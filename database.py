from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from privacy_cleanup import purge_retired_collection
from appeal_privacy import AppealPrivacyStore, AUTOMATED_EVENTS
from admin_credentials import admin_login_subject_hash
from applications import ApplicationStore
from reaction_roles import ReactionRoleStore
from join_limits import JoinLimitStore
from moderation_policy import (
    CATEGORY_LABELS, LEGACY_CATEGORY_ALIASES, MIN_MODERATION_THRESHOLD,
    SUPPORT_ONLY_CATEGORIES, SUPPORTED_MODERATION_CATEGORIES,
    PROTECTED_MODERATION_CATEGORY_PREFIXES,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


CASE_REFERENCE_LETTERS = "ABCDEFGHJKLMNPQRSTUVWXYZ"
CASE_REFERENCE_DIGITS = "23456789"
CASE_REFERENCE_LENGTH = 8
REPORT_REFERENCE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
REPORT_REFERENCE_LENGTH = 8
DASHBOARD_ANNOUNCEMENT_LIFETIME = timedelta(days=3)
LEGACY_ZERO_TOLERANCE_REASON_PREFIX = (
    "Automatic global ban: zero-tolerance slur detected in "
)
DEFAULT_SPAM_SETTINGS: dict[str, int | float] = {
    "repeat_count": 3,
    "repeat_window_seconds": 30.0,
    "rapid_count": 5,
    "rapid_window_seconds": 10.0,
    "score_threshold": 7.0,
    "score_half_life_seconds": 30.0,
    "mass_mention_limit": 5,
    "timeout_seconds": 3600,
}
SPAM_SETTING_LIMITS: dict[str, tuple[float, float]] = {
    "repeat_count": (2, 100),
    "repeat_window_seconds": (1, 3600),
    "rapid_count": (2, 250),
    "rapid_window_seconds": (1, 600),
    "score_threshold": (1, 100),
    "score_half_life_seconds": (1, 3600),
    "mass_mention_limit": (2, 100),
    "timeout_seconds": (60, 28 * 24 * 60 * 60),
}
SPAM_INTEGER_SETTINGS = frozenset(
    {"repeat_count", "rapid_count", "mass_mention_limit", "timeout_seconds"}
)
PRIVACY_ENFORCEMENT_RETENTION_REASONS = {
    "server_blacklist": (
        "Active server-blacklist enforcement must remain intact so the bot cannot "
        "be re-added to a blocked server."
    ),
    "global_bans": (
        "Active global-ban enforcement must remain intact until the ban is reviewed "
        "and removed through the global-ban workflow."
    ),
    "global_warnings": (
        "Service-wide safety warnings are retained for a case-by-case necessity and "
        "proportionality review."
    ),
    "warning_policy_actions": (
        "This enforcement-state record prevents warning penalties from being applied twice."
    ),
}
PRIVACY_ACTIVE_QUEUE_STATUSES = {"pending", "processing"}
_IPV4_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
@dataclass(frozen=True)
class WarningRecord:
    id: int
    server_id: str
    user_id: str
    moderator_id: str | None
    source: str
    reason: str
    message_id: str | None
    channel_id: str | None
    categories: dict[str, bool]
    scores: dict[str, float]
    original_content: str | None
    created_at: str


@dataclass(frozen=True)
class ModerationCaseRecord:
    id: int
    reference_id: str
    server_id: str
    user_id: str
    action: str
    moderator_id: str | None
    reason: str
    source_type: str
    source_id: int
    status: str
    created_at: str


@dataclass(frozen=True)
class WarningPolicy:
    timeout_count: int = 3
    kick_count: int = 5
    ban_count: int = 7


@dataclass(frozen=True)
class PenaltyRule:
    threshold: int
    action: str
    duration_seconds: int | None = None


@dataclass(frozen=True)
class GlobalBanRecord:
    reference_id: str
    user_id: str
    reason: str
    created_by: str
    created_at: str


@dataclass(frozen=True)
class GlobalWarningRecord:
    reference_id: str
    user_id: str
    reason: str
    created_by: str
    created_at: str


@dataclass(frozen=True)
class CaptchaChallenge:
    server_id: str
    user_id: str
    answer_hash: str
    salt: str
    expires_at: str
    created_at: str
    failure_count: int = 0


class ModerationDatabase:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, timeout=30.0)
        try:
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA busy_timeout=30000")
            for attempt in range(100):
                try:
                    self.connection.execute("PRAGMA journal_mode=WAL")
                    break
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).casefold() or attempt == 99:
                        raise
                    time.sleep(0.1)
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA secure_delete=ON")
            self._initialize()
            self.applications = ApplicationStore(self)
            self.reaction_roles = ReactionRoleStore(self)
            self.join_limits = JoinLimitStore(self)
            self.appeal_privacy = AppealPrivacyStore(self)
        except Exception:
            self.connection.rollback()
            self.connection.close()
            raise

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            BEGIN IMMEDIATE;

            CREATE TABLE IF NOT EXISTS server_settings (
                server_id TEXT PRIMARY KEY,
                locale TEXT NOT NULL DEFAULT 'en',
                log_channel_id TEXT,
                warning_timeout_count INTEGER NOT NULL DEFAULT 3,
                warning_kick_count INTEGER NOT NULL DEFAULT 5,
                warning_ban_count INTEGER NOT NULL DEFAULT 7,
                join_protection_enabled INTEGER NOT NULL DEFAULT 0,
                captcha_all_members_enabled INTEGER NOT NULL DEFAULT 0,
                warning_expiry_days INTEGER,
                nickname_protection_enabled INTEGER NOT NULL DEFAULT 1,
                link_protection_enabled INTEGER NOT NULL DEFAULT 0,
                allow_gifs_enabled INTEGER NOT NULL DEFAULT 0,
                spam_detection_enabled INTEGER NOT NULL DEFAULT 1,
                spam_repeat_count INTEGER,
                spam_repeat_window_seconds REAL,
                spam_rapid_count INTEGER,
                spam_rapid_window_seconds REAL,
                spam_score_threshold REAL,
                spam_score_half_life_seconds REAL,
                spam_mass_mention_limit INTEGER,
                spam_timeout_seconds INTEGER,
                image_scanning_enabled INTEGER NOT NULL DEFAULT 0,
                ai_thinking_enabled INTEGER NOT NULL DEFAULT 0,
                moderator_exemption_enabled INTEGER NOT NULL DEFAULT 1,
                alt_detection_enabled INTEGER NOT NULL DEFAULT 0,
                public_stats_enabled INTEGER NOT NULL DEFAULT 1,
                moderation_threshold REAL,
                retention_days INTEGER,
                moderation_mode TEXT NOT NULL DEFAULT 'enforce'
                    CHECK (moderation_mode IN ('observe', 'review', 'enforce'))
            );

            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS warning_policy_actions (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('timeout', 'kick', 'ban')),
                threshold INTEGER NOT NULL,
                trigger_warning_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id, action, threshold)
            );

            CREATE TABLE IF NOT EXISTS warning_penalty_rules (
                server_id TEXT NOT NULL,
                threshold INTEGER NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('timeout', 'kick', 'ban')),
                duration_seconds INTEGER,
                position INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, threshold)
            );

            CREATE TABLE IF NOT EXISTS automation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                name TEXT NOT NULL,
                trigger_type TEXT NOT NULL CHECK (
                    trigger_type IN ('every_message', 'keyword', 'contains_link', 'has_attachment')
                ),
                trigger_value TEXT,
                action_type TEXT NOT NULL CHECK (
                    action_type IN ('delete_message', 'warn', 'timeout', 'send_reply', 'send_log')
                ),
                action_config_json TEXT NOT NULL DEFAULT '{}',
                actions_json TEXT NOT NULL DEFAULT '[]',
                conditions_json TEXT NOT NULL DEFAULT '[]',
                condition_mode TEXT NOT NULL DEFAULT 'all' CHECK (condition_mode IN ('all', 'any')),
                priority INTEGER NOT NULL DEFAULT 100,
                enabled INTEGER NOT NULL DEFAULT 1,
                execution_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                last_executed_at TEXT,
                last_error TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_automation_rules_server
                ON automation_rules(server_id, enabled, id);

            CREATE TABLE IF NOT EXISTS server_polls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                message_id TEXT UNIQUE,
                question TEXT NOT NULL,
                options_json TEXT NOT NULL,
                votes_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
                multiple_choice INTEGER NOT NULL DEFAULT 0,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                scheduled_for TEXT,
                published_at TEXT,
                closes_at TEXT,
                anonymous INTEGER NOT NULL DEFAULT 0,
                required_role_id TEXT,
                quorum INTEGER NOT NULL DEFAULT 0,
                reminder_minutes INTEGER,
                reminder_sent_at TEXT
            );

            CREATE TABLE IF NOT EXISTS poll_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                name TEXT NOT NULL,
                question TEXT NOT NULL,
                options_json TEXT NOT NULL,
                multiple_choice INTEGER NOT NULL DEFAULT 0,
                anonymous INTEGER NOT NULL DEFAULT 0,
                required_role_id TEXT,
                quorum INTEGER NOT NULL DEFAULT 0,
                reminder_minutes INTEGER,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(server_id, name)
            );

            CREATE INDEX IF NOT EXISTS idx_poll_templates_server
                ON poll_templates(server_id, name COLLATE NOCASE);

            CREATE TABLE IF NOT EXISTS moderation_category_policies (
                server_id TEXT NOT NULL,
                category TEXT NOT NULL,
                threshold REAL,
                action TEXT NOT NULL DEFAULT 'warn'
                    CHECK (action IN ('observe', 'review', 'delete', 'warn', 'timeout')),
                timeout_seconds INTEGER,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (server_id, category)
            );

            CREATE TABLE IF NOT EXISTS dashboard_onboarding (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                current_step INTEGER NOT NULL DEFAULT 0,
                completed_at TEXT,
                dismissed_at TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS local_report_settings (
                server_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                channel_id TEXT,
                message_id TEXT,
                anonymous_allowed INTEGER NOT NULL DEFAULT 1,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS global_bans (
                reference_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS server_blacklist (
                server_id TEXT PRIMARY KEY,
                server_name TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                blacklisted_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS global_ban_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied')),
                requested_at TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT,
                review_note TEXT NOT NULL DEFAULT '',
                global_reference_id TEXT,
                enforcement_action_id INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_global_ban_requests_status
                ON global_ban_requests(status, requested_at DESC);

            CREATE UNIQUE INDEX IF NOT EXISTS idx_global_ban_requests_pending_user
                ON global_ban_requests(user_id) WHERE status='pending';

            CREATE TABLE IF NOT EXISTS global_warnings (
                reference_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS global_warnings_user_idx
                ON global_warnings(user_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS captcha_challenges (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                answer_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_captcha_web_token
                ON captcha_challenges(answer_hash)
                WHERE salt='web';

            CREATE TABLE IF NOT EXISTS server_announcements (
                server_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                announced_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dashboard_announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_dashboard_announcements_server
                ON dashboard_announcements(server_id, id DESC);

            CREATE TABLE IF NOT EXISTS dashboard_announcement_dismissals (
                announcement_id INTEGER NOT NULL,
                user_id TEXT NOT NULL,
                dismissed_at TEXT NOT NULL,
                PRIMARY KEY (announcement_id, user_id),
                FOREIGN KEY (announcement_id) REFERENCES dashboard_announcements(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS server_permission_notices (
                server_id TEXT NOT NULL,
                permission_name TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                notified_at TEXT NOT NULL,
                PRIMARY KEY (server_id, permission_name)
            );

            CREATE TABLE IF NOT EXISTS email_webhook_deliveries (
                message_key TEXT PRIMARY KEY,
                message_id TEXT,
                recipient TEXT NOT NULL,
                delivered_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_messages (
                message_key TEXT PRIMARY KEY,
                thread_key TEXT NOT NULL,
                mailbox_address TEXT NOT NULL DEFAULT 'admin@modstoat.site',
                message_id TEXT,
                direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                cc_json TEXT NOT NULL DEFAULT '[]',
                bcc_json TEXT NOT NULL DEFAULT '[]',
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                in_reply_to TEXT,
                references_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'received'
                    CHECK (status IN ('received', 'queued', 'sent', 'failed')),
                read_at TEXT,
                deleted_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_email_messages_thread_sent
                ON email_messages(thread_key, sent_at DESC);

            CREATE TABLE IF NOT EXISTS email_reply_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_key TEXT NOT NULL,
                mailbox_address TEXT NOT NULL DEFAULT 'admin@modstoat.site',
                from_address TEXT NOT NULL DEFAULT 'admin@modstoat.site',
                to_address TEXT NOT NULL,
                cc_json TEXT NOT NULL DEFAULT '[]',
                bcc_json TEXT NOT NULL DEFAULT '[]',
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                in_reply_to TEXT,
                references_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'sent', 'failed')),
                error TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                processed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_email_reply_queue_status
                ON email_reply_queue(status, id);

            CREATE TABLE IF NOT EXISTS email_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reply_id INTEGER,
                message_key TEXT,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                content BLOB NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_email_attachments_reply
                ON email_attachments(reply_id);

            CREATE INDEX IF NOT EXISTS idx_email_attachments_message
                ON email_attachments(message_key);

            CREATE TABLE IF NOT EXISTS auto_roles (
                server_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                added_by TEXT NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (server_id, role_id)
            );

            CREATE TABLE IF NOT EXISTS dashboard_login_codes (
                code_hash TEXT PRIMARY KEY,
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                used_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_dashboard_codes_server_user
                ON dashboard_login_codes(server_id, user_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS appeals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE,
                server_id TEXT,
                user_id TEXT NOT NULL,
                case_kind TEXT NOT NULL CHECK (case_kind IN ('moderation', 'global_ban')),
                case_reference TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'eligible'
                    CHECK (status IN ('eligible', 'submitted', 'approved', 'denied')),
                statement TEXT,
                created_at TEXT NOT NULL,
                submitted_at TEXT,
                reviewed_at TEXT,
                reviewer_id TEXT,
                reviewer_response TEXT,
                UNIQUE(case_kind, case_reference)
            );

            CREATE INDEX IF NOT EXISTS idx_appeals_server_status
                ON appeals(server_id, status, id DESC);

            CREATE TABLE IF NOT EXISTS dashboard_sessions (
                token_hash TEXT PRIMARY KEY,
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_dashboard_sessions_expiry
                ON dashboard_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS dashboard_access_grants (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                granted_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_dashboard_access_grants_user
                ON dashboard_access_grants(user_id, server_id);

            CREATE TABLE IF NOT EXISTS dashboard_access_denials (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                revoked_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS owner_dashboard_sessions (
                token_hash TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_owner_dashboard_sessions_expiry
                ON owner_dashboard_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS admin_dashboard_sessions (
                token_hash TEXT PRIMARY KEY,
                admin_email TEXT NOT NULL,
                password_version INTEGER NOT NULL DEFAULT 1,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_admin_dashboard_sessions_expiry
                ON admin_dashboard_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS admin_dashboard_accounts (
                user_id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                password_version INTEGER NOT NULL DEFAULT 1,
                password_expires_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_password_change_at TEXT NOT NULL,
                last_login_at TEXT,
                delivery_action_id INTEGER,
                revoked_by TEXT,
                revoked_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_admin_dashboard_accounts_active
                ON admin_dashboard_accounts(active, updated_at DESC);

            CREATE TABLE IF NOT EXISTS admin_password_change_sessions (
                token_hash TEXT PRIMARY KEY,
                admin_user_id TEXT NOT NULL,
                password_version INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_admin_password_change_sessions_expiry
                ON admin_password_change_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS admin_login_failures (
                scope TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                subject_hash TEXT,
                failure_count INTEGER NOT NULL DEFAULT 0,
                window_started_at TEXT NOT NULL,
                locked_until TEXT,
                PRIMARY KEY (scope, key_hash)
            );

            CREATE TABLE IF NOT EXISTS dashboard_notification_reads (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                section TEXT NOT NULL
                    CHECK (section IN ('activity', 'appeals', 'reports')),
                last_event_id INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id, section)
            );

            CREATE TABLE IF NOT EXISTS appeal_notification_preferences (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
                    CHECK (enabled IN (0, 1)),
                updated_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_appeal_notification_preferences_server
                ON appeal_notification_preferences(server_id, enabled);

            CREATE TABLE IF NOT EXISTS server_daily_stats (
                server_id TEXT NOT NULL,
                stat_date TEXT NOT NULL,
                message_count INTEGER NOT NULL DEFAULT 0,
                new_joins INTEGER NOT NULL DEFAULT 0,
                new_leaves INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, stat_date)
            );

            CREATE TABLE IF NOT EXISTS server_daily_active_users (
                server_id TEXT NOT NULL,
                stat_date TEXT NOT NULL,
                user_id TEXT NOT NULL,
                PRIMARY KEY (server_id, stat_date, user_id)
            );

            CREATE TABLE IF NOT EXISTS server_daily_user_stats (
                server_id TEXT NOT NULL,
                stat_date TEXT NOT NULL,
                user_id TEXT NOT NULL,
                message_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, stat_date, user_id)
            );

            CREATE TABLE IF NOT EXISTS server_daily_channel_stats (
                server_id TEXT NOT NULL,
                stat_date TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                message_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, stat_date, channel_id)
            );

            CREATE TABLE IF NOT EXISTS server_daily_word_stats (
                server_id TEXT NOT NULL,
                stat_date TEXT NOT NULL,
                word TEXT NOT NULL,
                use_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, stat_date, word)
            );

            CREATE INDEX IF NOT EXISTS idx_daily_channel_stats_date
                ON server_daily_channel_stats(server_id, stat_date);

            CREATE INDEX IF NOT EXISTS idx_daily_word_stats_date
                ON server_daily_word_stats(server_id, stat_date);

            CREATE TABLE IF NOT EXISTS dashboard_server_snapshots (
                server_id TEXT PRIMARY KEY,
                server_name TEXT NOT NULL,
                owner_id TEXT NOT NULL DEFAULT '',
                server_icon_url TEXT,
                bot_joined_at TEXT,
                member_count INTEGER NOT NULL,
                previous_member_count INTEGER NOT NULL DEFAULT 0,
                permission_audit_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS discovery_applications (
                server_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                information TEXT NOT NULL DEFAULT '',
                invite_url TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                last_bumped_at TEXT,
                last_bumped_by TEXT,
                is_revoked INTEGER NOT NULL DEFAULT 0,
                revoked_by TEXT,
                revoked_at TEXT,
                revocation_note TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied')),
                submitted_by TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT,
                review_note TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_discovery_applications_status
                ON discovery_applications(status, submitted_at DESC);

            CREATE TABLE IF NOT EXISTS dashboard_channels (
                server_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                channel_name TEXT NOT NULL,
                category_id TEXT,
                PRIMARY KEY (server_id, channel_id)
            );

            CREATE TABLE IF NOT EXISTS dashboard_categories (
                server_id TEXT NOT NULL,
                category_id TEXT NOT NULL,
                category_name TEXT NOT NULL,
                category_position INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (server_id, category_id)
            );

            CREATE TABLE IF NOT EXISTS dashboard_roles (
                server_id TEXT NOT NULL,
                role_id TEXT NOT NULL,
                role_name TEXT NOT NULL,
                assignable INTEGER,
                PRIMARY KEY (server_id, role_id)
            );

            CREATE TABLE IF NOT EXISTS dashboard_members (
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                display_name TEXT,
                discriminator TEXT,
                avatar_url TEXT,
                banner_url TEXT,
                joined_at TEXT,
                account_created_at TEXT,
                roles_json TEXT NOT NULL DEFAULT '[]',
                manage_server INTEGER NOT NULL DEFAULT 0,
                is_bot INTEGER NOT NULL DEFAULT 0,
                online INTEGER NOT NULL DEFAULT 0,
                timed_out_until TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (server_id, user_id)
            );

            CREATE INDEX IF NOT EXISTS idx_dashboard_members_server_name
                ON dashboard_members(server_id, username COLLATE NOCASE);

            CREATE TABLE IF NOT EXISTS user_identities (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                discriminator TEXT,
                full_username TEXT NOT NULL,
                display_name TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_user_identities_full_username
                ON user_identities(full_username COLLATE NOCASE);

            CREATE TABLE IF NOT EXISTS dashboard_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
                result_json TEXT,
                created_at TEXT NOT NULL,
                not_before TEXT,
                claimed_at TEXT,
                claim_token TEXT,
                processed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_dashboard_actions_pending
                ON dashboard_actions(status, id);

            DROP TABLE IF EXISTS dev_webhook_events;

            CREATE TABLE IF NOT EXISTS report_tokens (
                token_hash TEXT PRIMARY KEY,
                server_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                report_scope TEXT NOT NULL DEFAULT 'global',
                captcha_hash TEXT,
                captcha_salt TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference_id TEXT,
                server_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                target_user_id TEXT NOT NULL,
                subject_type TEXT NOT NULL DEFAULT 'user',
                subject_text TEXT,
                reported_channel_id TEXT,
                reported_message_id TEXT,
                reason TEXT NOT NULL,
                evidence TEXT,
                network_risk_json TEXT NOT NULL DEFAULT '{}',
                report_scope TEXT NOT NULL DEFAULT 'global',
                anonymous INTEGER NOT NULL DEFAULT 0,
                receipt_token_hash TEXT,
                receipt_expires_at TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'resolved', 'dismissed')),
                review_note TEXT NOT NULL DEFAULT '',
                reviewed_by TEXT,
                reviewed_at TEXT,
                reporter_notification_status TEXT NOT NULL DEFAULT 'not_requested'
                    CHECK (reporter_notification_status IN (
                        'not_requested', 'pending', 'sent', 'failed'
                    )),
                reporter_notification_error TEXT,
                reporter_notified_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_report_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL REFERENCES user_reports(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                data BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL REFERENCES user_reports(id) ON DELETE CASCADE,
                sender_type TEXT NOT NULL CHECK (sender_type IN ('reporter', 'moderator', 'system')),
                sender_id TEXT,
                message TEXT NOT NULL,
                request_info INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_report_messages_report
                ON report_messages(report_id, id);

            CREATE TABLE IF NOT EXISTS appeal_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appeal_id INTEGER NOT NULL REFERENCES appeals(id) ON DELETE CASCADE,
                sender_type TEXT NOT NULL CHECK (sender_type IN ('appellant', 'moderator', 'system')),
                sender_id TEXT,
                message TEXT NOT NULL,
                request_info INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_appeal_messages_appeal
                ON appeal_messages(appeal_id, id);

            CREATE TABLE IF NOT EXISTS appeal_message_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL REFERENCES appeal_messages(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                data BLOB NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_ip_fingerprints (
                fingerprint TEXT NOT NULL,
                user_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                source TEXT NOT NULL CHECK (source IN ('report', 'verification')),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (fingerprint, user_id)
            );

            CREATE TABLE IF NOT EXISTS user_ip_addresses (
                ip_address TEXT NOT NULL,
                user_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                source TEXT NOT NULL CHECK (source IN ('report', 'verification')),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (ip_address, user_id, server_id, source)
            );

            CREATE INDEX IF NOT EXISTS idx_user_ip_addresses_user
                ON user_ip_addresses(user_id, last_seen_at DESC);

            CREATE INDEX IF NOT EXISTS idx_user_ip_fingerprints_user
                ON user_ip_fingerprints(user_id, last_seen_at DESC);

            CREATE TABLE IF NOT EXISTS scope_exclusions (
                server_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL CHECK (target_type IN ('channel', 'category')),
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (server_id, target_id)
            );

            CREATE TABLE IF NOT EXISTS channel_image_scanning_settings (
                server_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (server_id, channel_id)
            );

            CREATE TABLE IF NOT EXISTS disabled_moderation_categories (
                server_id TEXT NOT NULL,
                category TEXT NOT NULL,
                disabled_by TEXT NOT NULL,
                disabled_at TEXT NOT NULL,
                PRIMARY KEY (server_id, category)
            );

            CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                moderator_id TEXT,
                source TEXT NOT NULL CHECK (source IN ('automatic', 'manual')),
                reason TEXT NOT NULL,
                message_id TEXT,
                channel_id TEXT,
                categories_json TEXT NOT NULL DEFAULT '{}',
                scores_json TEXT NOT NULL DEFAULT '{}',
                original_content TEXT,
                ai_thinking_json TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS warnings_server_user_idx
                ON warnings(server_id, user_id, id DESC);

            CREATE TABLE IF NOT EXISTS moderation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user_id TEXT,
                actor_id TEXT,
                message_id TEXT,
                channel_id TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS moderation_events_server_idx
                ON moderation_events(server_id, id DESC);

            CREATE INDEX IF NOT EXISTS moderation_events_server_type_idx
                ON moderation_events(server_id, event_type, id DESC);

            CREATE TABLE IF NOT EXISTS moderation_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reference_id TEXT UNIQUE,
                server_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                moderator_id TEXT,
                reason TEXT NOT NULL,
                source_type TEXT NOT NULL CHECK (source_type IN ('warning', 'event')),
                source_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'removed')),
                created_at TEXT NOT NULL,
                UNIQUE(source_type, source_id)
            );

            CREATE INDEX IF NOT EXISTS moderation_cases_server_user_idx
                ON moderation_cases(server_id, user_id, id DESC);

            CREATE TABLE IF NOT EXISTS moderation_case_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                case_reference TEXT NOT NULL,
                entry_type TEXT NOT NULL CHECK (entry_type IN ('note', 'evidence')),
                content TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_case_entries_server_reference
                ON moderation_case_entries(server_id, case_reference, id);

            CREATE TABLE IF NOT EXISTS moderation_case_entry_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL
                    REFERENCES moderation_case_entries(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                data BLOB NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_case_entry_attachments_entry
                ON moderation_case_entry_attachments(entry_id, id);
            """
        )
        notification_table = self.connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='dashboard_notification_reads'"
        ).fetchone()
        notification_sql = str(notification_table["sql"] or "") if notification_table else ""
        if "'reports'" not in notification_sql:
            self.connection.execute(
                "DROP TABLE IF EXISTS dashboard_notification_reads_v2"
            )
            self.connection.execute(
                """
                CREATE TABLE dashboard_notification_reads_v2 (
                    server_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    section TEXT NOT NULL
                        CHECK (section IN ('activity', 'appeals', 'reports')),
                    last_event_id INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (server_id, user_id, section)
                )
                """
            )
            self.connection.execute(
                """
                INSERT INTO dashboard_notification_reads_v2(
                    server_id, user_id, section, last_event_id, updated_at
                )
                SELECT server_id, user_id, section, last_event_id, updated_at
                FROM dashboard_notification_reads
                """
            )
            self.connection.execute("DROP TABLE dashboard_notification_reads")
            self.connection.execute(
                "ALTER TABLE dashboard_notification_reads_v2 "
                "RENAME TO dashboard_notification_reads"
            )
        warning_columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(warnings)").fetchall()
        }
        if "original_content" not in warning_columns:
            self.connection.execute(
                "ALTER TABLE warnings ADD COLUMN original_content TEXT"
            )
        # The AI's reasoning ("thinking") is message-derived content: it is purged
        # together with original_content under the 30-day retention rule.
        if "ai_thinking_json" not in warning_columns:
            self.connection.execute(
                "ALTER TABLE warnings ADD COLUMN ai_thinking_json TEXT"
            )
        email_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(email_messages)"
            ).fetchall()
        }
        if "deleted_at" not in email_columns:
            self.connection.execute(
                "ALTER TABLE email_messages ADD COLUMN deleted_at TEXT"
            )
        if "mailbox_address" not in email_columns:
            self.connection.execute(
                "ALTER TABLE email_messages ADD COLUMN mailbox_address TEXT "
                "NOT NULL DEFAULT 'admin@modstoat.site'"
            )
        if "cc_json" not in email_columns:
            self.connection.execute(
                "ALTER TABLE email_messages ADD COLUMN cc_json TEXT "
                "NOT NULL DEFAULT '[]'"
            )
        if "bcc_json" not in email_columns:
            self.connection.execute(
                "ALTER TABLE email_messages ADD COLUMN bcc_json TEXT "
                "NOT NULL DEFAULT '[]'"
            )
        # Older databases enforced Message-ID uniqueness across every inbox.
        # A single email can legitimately target both owner and support aliases,
        # so deduplication must be mailbox-scoped.
        self.connection.execute("DROP INDEX IF EXISTS idx_email_messages_message_id")
        self.connection.execute(
            "CREATE UNIQUE INDEX idx_email_messages_message_id "
            "ON email_messages(mailbox_address, message_id) "
            "WHERE message_id IS NOT NULL"
        )
        reply_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(email_reply_queue)"
            ).fetchall()
        }
        if "mailbox_address" not in reply_columns:
            self.connection.execute(
                "ALTER TABLE email_reply_queue ADD COLUMN mailbox_address TEXT "
                "NOT NULL DEFAULT 'admin@modstoat.site'"
            )
        if "from_address" not in reply_columns:
            self.connection.execute(
                "ALTER TABLE email_reply_queue ADD COLUMN from_address TEXT "
                "NOT NULL DEFAULT 'admin@modstoat.site'"
            )
        if "cc_json" not in reply_columns:
            self.connection.execute(
                "ALTER TABLE email_reply_queue ADD COLUMN cc_json TEXT "
                "NOT NULL DEFAULT '[]'"
            )
        if "bcc_json" not in reply_columns:
            self.connection.execute(
                "ALTER TABLE email_reply_queue ADD COLUMN bcc_json TEXT "
                "NOT NULL DEFAULT '[]'"
            )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_messages_mailbox_thread "
            "ON email_messages(mailbox_address, thread_key, sent_at DESC)"
        )
        snapshot_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(dashboard_server_snapshots)"
            ).fetchall()
        }
        if "server_icon_url" not in snapshot_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_server_snapshots ADD COLUMN server_icon_url TEXT"
            )
        if "server_banner_url" not in snapshot_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_server_snapshots ADD COLUMN server_banner_url TEXT"
            )
        if "owner_id" not in snapshot_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_server_snapshots "
                "ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''"
            )
        if "bot_joined_at" not in snapshot_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_server_snapshots "
                "ADD COLUMN bot_joined_at TEXT"
            )
        if "permission_audit_json" not in snapshot_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_server_snapshots "
                "ADD COLUMN permission_audit_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "previous_member_count" not in snapshot_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_server_snapshots "
                "ADD COLUMN previous_member_count INTEGER NOT NULL DEFAULT 0"
            )
            self.connection.execute(
                "UPDATE dashboard_server_snapshots "
                "SET previous_member_count=member_count"
            )
        discovery_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(discovery_applications)"
            ).fetchall()
        }
        if "invite_url" not in discovery_columns:
            self.connection.execute(
                "ALTER TABLE discovery_applications "
                "ADD COLUMN invite_url TEXT NOT NULL DEFAULT ''"
            )
        for name, definition in (
            ("tags_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("last_bumped_at", "TEXT"),
            ("last_bumped_by", "TEXT"),
            ("is_revoked", "INTEGER NOT NULL DEFAULT 0"),
            ("revoked_by", "TEXT"),
            ("revoked_at", "TEXT"),
            ("revocation_note", "TEXT"),
        ):
            if name not in discovery_columns:
                self.connection.execute(
                    f"ALTER TABLE discovery_applications ADD COLUMN {name} {definition}"
                )
        settings_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(server_settings)"
            ).fetchall()
        }
        for name, default in (
            ("warning_timeout_count", 3),
            ("warning_kick_count", 5),
            ("warning_ban_count", 7),
            ("join_protection_enabled", 0),
            ("captcha_all_members_enabled", 0),
            ("nickname_protection_enabled", 1),
            ("link_protection_enabled", 0),
            ("allow_gifs_enabled", 0),
            # Current link policy: links are removed by default and only GifBox links are allowed.
            ("link_filter_enabled", 1),
            ("gifbox_links_allowed", 1),
            ("spam_detection_enabled", 1),
            ("image_scanning_enabled", 0),
            # Image scanning is on by default (2026-10-19); servers that turned it off keep their choice.
            ("image_scanning_on", 1),
            ("ai_thinking_enabled", 0),
            ("moderator_exemption_enabled", 1),
            ("alt_detection_enabled", 0),
            ("public_stats_enabled", 1),
        ):
            if name not in settings_columns:
                self.connection.execute(
                    f"ALTER TABLE server_settings ADD COLUMN {name} "
                    f"INTEGER NOT NULL DEFAULT {default}"
                )
        if "locale" not in settings_columns:
            self.connection.execute(
                "ALTER TABLE server_settings "
                "ADD COLUMN locale TEXT NOT NULL DEFAULT 'en'"
            )
        if "moderation_threshold" not in settings_columns:
            self.connection.execute(
                "ALTER TABLE server_settings ADD COLUMN moderation_threshold REAL"
            )
        if "retention_days" not in settings_columns:
            self.connection.execute(
                "ALTER TABLE server_settings ADD COLUMN retention_days INTEGER"
            )
        # Retired setting: keep the legacy column for database compatibility only.
        self.connection.execute("UPDATE server_settings SET retention_days=NULL WHERE retention_days IS NOT NULL")
        if "warning_expiry_days" not in settings_columns:
            self.connection.execute(
                "ALTER TABLE server_settings ADD COLUMN warning_expiry_days INTEGER"
            )
        if "moderation_mode" not in settings_columns:
            self.connection.execute(
                "ALTER TABLE server_settings ADD COLUMN moderation_mode TEXT "
                "NOT NULL DEFAULT 'enforce'"
            )
        for name, definition in (
            ("spam_repeat_count", "INTEGER"),
            ("spam_repeat_window_seconds", "REAL"),
            ("spam_rapid_count", "INTEGER"),
            ("spam_rapid_window_seconds", "REAL"),
            ("spam_score_threshold", "REAL"),
            ("spam_score_half_life_seconds", "REAL"),
            ("spam_mass_mention_limit", "INTEGER"),
            ("spam_timeout_seconds", "INTEGER"),
        ):
            if name not in settings_columns:
                self.connection.execute(
                    f"ALTER TABLE server_settings ADD COLUMN {name} {definition}"
                )
        spam_score_default_migrated = self.connection.execute(
            """
            SELECT 1 FROM app_metadata
            WHERE key='spam_score_threshold_default_7_v1'
            """
        ).fetchone()
        if spam_score_default_migrated is None:
            # Dashboard saves made the former default explicit. Move those servers
            # to the new default without changing any other custom threshold.
            self.connection.execute(
                """
                UPDATE server_settings SET spam_score_threshold=7
                WHERE spam_score_threshold=5
                """
            )
            self.connection.execute(
                """
                INSERT INTO app_metadata(key, value)
                VALUES ('spam_score_threshold_default_7_v1', '1')
                """
            )
        report_token_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(report_tokens)"
            ).fetchall()
        }
        if "report_scope" not in report_token_columns:
            self.connection.execute(
                "ALTER TABLE report_tokens ADD COLUMN report_scope TEXT "
                "NOT NULL DEFAULT 'global'"
            )
        onboarding_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(dashboard_onboarding)"
            ).fetchall()
        }
        if "dismissed_at" not in onboarding_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_onboarding ADD COLUMN dismissed_at TEXT"
            )
        report_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(user_reports)"
            ).fetchall()
        }
        if "network_risk_json" not in report_columns:
            self.connection.execute(
                "ALTER TABLE user_reports ADD COLUMN network_risk_json TEXT NOT NULL DEFAULT '{}'"
            )
        for name, definition in (
            ("reference_id", "TEXT"),
            ("report_scope", "TEXT NOT NULL DEFAULT 'global'"),
            ("anonymous", "INTEGER NOT NULL DEFAULT 0"),
            ("receipt_token_hash", "TEXT"),
            ("receipt_expires_at", "TEXT"),
            ("subject_type", "TEXT NOT NULL DEFAULT 'user'"),
            ("subject_text", "TEXT"),
            ("reported_channel_id", "TEXT"),
            ("reported_message_id", "TEXT"),
            ("review_note", "TEXT NOT NULL DEFAULT ''"),
            ("reviewed_by", "TEXT"),
            ("reviewed_at", "TEXT"),
            (
                "reporter_notification_status",
                "TEXT NOT NULL DEFAULT 'not_requested' CHECK ("
                "reporter_notification_status IN ("
                "'not_requested', 'pending', 'sent', 'failed'))",
            ),
            ("reporter_notification_error", "TEXT"),
            ("reporter_notified_at", "TEXT"),
        ):
            if name not in report_columns:
                self.connection.execute(
                    f"ALTER TABLE user_reports ADD COLUMN {name} {definition}"
                )
        receipt_compatibility_expiry = (
            datetime.now(timezone.utc) + timedelta(days=30)
        ).isoformat(timespec="seconds")
        self.connection.execute(
            """
            UPDATE user_reports SET receipt_expires_at=?
            WHERE receipt_token_hash IS NOT NULL AND receipt_expires_at IS NULL
            """,
            (receipt_compatibility_expiry,),
        )
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_reports_receipt "
            "ON user_reports(receipt_token_hash) WHERE receipt_token_hash IS NOT NULL"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_user_reports_server_scope_status "
            "ON user_reports(server_id, report_scope, status, id DESC)"
        )
        dashboard_channel_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(dashboard_channels)"
            ).fetchall()
        }
        if "category_id" not in dashboard_channel_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_channels ADD COLUMN category_id TEXT"
            )
        dashboard_role_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(dashboard_roles)"
            ).fetchall()
        }
        if "assignable" not in dashboard_role_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_roles ADD COLUMN assignable INTEGER"
            )
        dashboard_member_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(dashboard_members)"
            ).fetchall()
        }
        if "manage_server" not in dashboard_member_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_members "
                "ADD COLUMN manage_server INTEGER NOT NULL DEFAULT 0"
            )
        captcha_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(captcha_challenges)"
            ).fetchall()
        }
        if "failure_count" not in captcha_columns:
            self.connection.execute(
                "ALTER TABLE captcha_challenges ADD COLUMN failure_count "
                "INTEGER NOT NULL DEFAULT 0"
            )
        case_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(moderation_cases)"
            ).fetchall()
        }
        if "reference_id" not in case_columns:
            self.connection.execute(
                "ALTER TABLE moderation_cases ADD COLUMN reference_id TEXT"
            )
        automation_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(automation_rules)"
            ).fetchall()
        }
        if "conditions_json" not in automation_columns:
            self.connection.execute(
                "ALTER TABLE automation_rules ADD COLUMN conditions_json "
                "TEXT NOT NULL DEFAULT '[]'"
            )
        if "condition_mode" not in automation_columns:
            self.connection.execute(
                "ALTER TABLE automation_rules ADD COLUMN condition_mode "
                "TEXT NOT NULL DEFAULT 'all'"
            )
        for name, definition in (
            ("actions_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("priority", "INTEGER NOT NULL DEFAULT 100"),
            ("execution_count", "INTEGER NOT NULL DEFAULT 0"),
            ("failure_count", "INTEGER NOT NULL DEFAULT 0"),
            ("last_executed_at", "TEXT"),
            ("last_error", "TEXT"),
        ):
            if name not in automation_columns:
                self.connection.execute(
                    f"ALTER TABLE automation_rules ADD COLUMN {name} {definition}"
                )
        poll_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(server_polls)"
            ).fetchall()
        }
        for name, definition in (
            ("multiple_choice", "INTEGER NOT NULL DEFAULT 0"),
            ("scheduled_for", "TEXT"),
            ("published_at", "TEXT"),
            ("anonymous", "INTEGER NOT NULL DEFAULT 0"),
            ("required_role_id", "TEXT"),
            ("quorum", "INTEGER NOT NULL DEFAULT 0"),
            ("reminder_minutes", "INTEGER"),
            ("reminder_sent_at", "TEXT"),
        ):
            if name not in poll_columns:
                self.connection.execute(
                    f"ALTER TABLE server_polls ADD COLUMN {name} {definition}"
                )
        dashboard_action_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(dashboard_actions)"
            ).fetchall()
        }
        if "not_before" not in dashboard_action_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_actions ADD COLUMN not_before TEXT"
            )
        if "claimed_at" not in dashboard_action_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_actions ADD COLUMN claimed_at TEXT"
            )
        if "claim_token" not in dashboard_action_columns:
            self.connection.execute(
                "ALTER TABLE dashboard_actions ADD COLUMN claim_token TEXT"
            )
        admin_failure_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(admin_login_failures)"
            ).fetchall()
        }
        if "subject_hash" not in admin_failure_columns:
            self.connection.execute(
                "ALTER TABLE admin_login_failures ADD COLUMN subject_hash TEXT"
            )
        self.connection.execute(
            "DELETE FROM admin_login_failures WHERE scope='user'"
        )
        admin_session_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(admin_dashboard_sessions)"
            ).fetchall()
        }
        if "password_version" not in admin_session_columns:
            self.connection.execute(
                "ALTER TABLE admin_dashboard_sessions ADD COLUMN password_version "
                "INTEGER NOT NULL DEFAULT 1"
            )
        self.connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS moderation_cases_reference_idx
            ON moderation_cases(reference_id)
            """
        )
        # Separate opt-in preferences also override DEFAULT 1 in older SQLite schemas.
        self.connection.execute("""CREATE TABLE IF NOT EXISTS join_verification_settings (
            server_id TEXT PRIMARY KEY, young_accounts_enabled INTEGER NOT NULL DEFAULT 0,
            all_members_enabled INTEGER NOT NULL DEFAULT 0)""")
        self.connection.execute("""CREATE TABLE IF NOT EXISTS verification_consents (
            challenge_hash TEXT PRIMARY KEY, server_id TEXT NOT NULL, user_id TEXT NOT NULL,
            policy_version TEXT NOT NULL, accepted_at TEXT NOT NULL, expires_at TEXT NOT NULL)""")
        retired = self.connection.execute(
            "SELECT 1 FROM app_metadata WHERE key='privacy_retired_collection_20261001_v1'"
        ).fetchone()
        if retired is None:
            purge_retired_collection(self.connection)
            self.connection.execute("UPDATE server_settings SET join_protection_enabled=0, captcha_all_members_enabled=0")
            self.connection.execute("INSERT INTO app_metadata(key,value) VALUES ('privacy_retired_collection_20261001_v1','1')")
        # Anonymous statistics retain no individual, channel or extracted-word rows.
        # Clear legacy records on every startup so restored copies cannot revive them.
        for table in ("server_daily_active_users", "server_daily_user_stats", "server_daily_word_stats", "server_daily_channel_stats"):
            self.connection.execute(f"DELETE FROM {table}")
        if not self.connection.execute("SELECT 1 FROM app_metadata WHERE key='retired_message_archives_and_sharing_v1'").fetchone():
            self.connection.execute("""DELETE FROM moderation_events WHERE event_type IN
                ('message_edited','external_message_deletion','external_message_deletion_bulk','cross_server_ban')""")
            self.connection.execute("""UPDATE moderation_events SET details_json=json_remove(details_json,'$.cross_server_notification')
                WHERE json_valid(details_json) AND json_type(details_json,'$.cross_server_notification') IS NOT NULL""")
            self.connection.execute("DELETE FROM server_daily_word_stats")
            self.connection.execute("INSERT INTO app_metadata(key,value) VALUES('retired_message_archives_and_sharing_v1','1')")
        link_protection_default_migrated = self.connection.execute(
            """
            SELECT 1 FROM app_metadata
            WHERE key='link_protection_disabled_by_default_v1'
            """
        ).fetchone()
        if link_protection_default_migrated is None:
            self.connection.execute(
                """
                UPDATE server_settings SET link_protection_enabled=0
                WHERE server_id NOT IN (
                    SELECT DISTINCT server_id FROM moderation_events
                    WHERE event_type IN ('link_protection_enabled', 'link_protection_disabled')
                )
                """
            )
            self.connection.execute(
                """
                INSERT INTO app_metadata(key, value)
                VALUES ('link_protection_disabled_by_default_v1', '1')
                """
            )
        if self.connection.execute(
            "SELECT 1 FROM app_metadata WHERE key='link_policy_gifbox_default_v2'"
        ).fetchone() is None:
            # The new columns default to on. Keep each server's earlier choice only
            # where a moderator changed that setting themselves.
            for column, legacy, setting in (
                ("link_filter_enabled", "link_protection_enabled", "link_protection"),
                ("gifbox_links_allowed", "allow_gifs_enabled", "allow_gifs"),
            ):
                self.connection.execute(
                    f"""
                    UPDATE server_settings SET {column}={legacy}
                    WHERE server_id IN (
                        SELECT server_id FROM moderation_events
                        WHERE event_type IN ('{setting}_enabled', '{setting}_disabled')
                        OR (event_type='dashboard_settings_updated' AND json_valid(details_json)
                            AND json_type(details_json, '$.changed.{setting}') IS NOT NULL)
                    )
                    """
                )
            self.connection.execute(
                "INSERT INTO app_metadata(key, value) VALUES ('link_policy_gifbox_default_v2', '1')"
            )
        if self.connection.execute(
            "SELECT 1 FROM app_metadata WHERE key='image_scanning_default_on_v1'"
        ).fetchone() is None:
            # The new column defaults to on. A server stays off only if its latest
            # server-wide choice (command or dashboard) was to turn scanning off.
            latest: dict[str, bool] = {}
            for row in self.connection.execute(
                """
                SELECT server_id, event_type, details_json FROM moderation_events
                WHERE event_type IN ('image_scanning_enabled', 'image_scanning_disabled')
                   OR (event_type='dashboard_settings_updated' AND json_valid(details_json)
                       AND json_type(details_json, '$.changed.image_scanning') IS NOT NULL)
                ORDER BY id
                """
            ):
                details = json.loads(row["details_json"] or "{}") if row["details_json"] else {}
                if row["event_type"] == "dashboard_settings_updated":
                    latest[row["server_id"]] = bool(details["changed"]["image_scanning"])
                elif not details.get("target_channel_id"):
                    latest[row["server_id"]] = row["event_type"] == "image_scanning_enabled"
            self.connection.execute("UPDATE server_settings SET image_scanning_on=1")
            self.connection.executemany(
                "UPDATE server_settings SET image_scanning_on=0 WHERE server_id=?",
                [(server_id,) for server_id, enabled in latest.items() if not enabled],
            )
            self.connection.execute(
                "INSERT INTO app_metadata(key, value) VALUES ('image_scanning_default_on_v1', '1')"
            )
        onboarding_redesign_reset = self.connection.execute(
            """
            SELECT 1 FROM app_metadata
            WHERE key='dashboard_onboarding_redesign_v2_reset'
            """
        ).fetchone()
        if onboarding_redesign_reset is None:
            # The redesigned guide changes the meaning and order of every step.
            # Start each dashboard user at the beginning exactly once so nobody
            # resumes at a stale percentage or remains dismissed/completed.
            self.connection.execute("DELETE FROM dashboard_onboarding")
            self.connection.execute(
                """
                INSERT INTO app_metadata(key, value)
                VALUES ('dashboard_onboarding_redesign_v2_reset', '1')
                """
            )
        delivery_cache_miss_requeue = self.connection.execute(
            """
            SELECT 1 FROM app_metadata
            WHERE key='dashboard_delivery_cache_miss_requeue_v1'
            """
        ).fetchone()
        if delivery_cache_miss_requeue is None:
            # Older workers treated a cold Stoat cache as a permanent delivery
            # failure. Give only those known-safe, pre-send failures another try.
            self.connection.execute(
                """
                UPDATE dashboard_actions
                SET status='pending', result_json=NULL, processed_at=NULL,
                    claimed_at=NULL, claim_token=NULL, not_before=NULL
                WHERE status='failed'
                  AND action IN ('publish_poll', 'post_local_report_instructions')
                  AND result_json LIKE '%Server is unavailable%'
                """
            )
            self.connection.execute(
                """
                INSERT INTO app_metadata(key, value)
                VALUES ('dashboard_delivery_cache_miss_requeue_v1', '1')
                """
            )
        self._remove_legacy_zero_tolerance_history()
        self._backfill_moderation_cases()
        self._backfill_case_references()
        self._backfill_report_references()
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_reports_server_reference "
            "ON user_reports(server_id, reference_id) WHERE reference_id IS NOT NULL"
        )
        self._backfill_user_identities()
        self.connection.execute(
            """
            UPDATE dashboard_actions
            SET status='pending', claimed_at=NULL, claim_token=NULL
            WHERE status='processing'
              AND (
                  claimed_at IS NULL
                  OR datetime(claimed_at) <= datetime('now', '-5 minutes')
              )
            """
        )
        self.connection.execute(
            """
            UPDATE email_reply_queue SET status='pending'
            WHERE status='processing'
            """
        )
        self._migrate_local_moderation_categories()
        self._migrate_stoatguard_production_categories_v2()
        self._migrate_image_scanning_experimental_opt_in_v1()
        self.connection.execute("PRAGMA optimize")
        self.connection.commit()

    def _migrate_local_moderation_categories(self) -> None:
        key = "local_moderation_categories_v1"
        if self.connection.execute("SELECT 1 FROM app_metadata WHERE key=?", (key,)).fetchone():
            return
        for old, new in LEGACY_CATEGORY_ALIASES.items():
            self.connection.execute(
                "INSERT OR IGNORE INTO moderation_category_policies "
                "(server_id, category, threshold, action, timeout_seconds, updated_by, updated_at) "
                "SELECT server_id, ?, threshold, action, timeout_seconds, updated_by, updated_at "
                "FROM moderation_category_policies WHERE category=?", (new, old),
            )
            if new not in SUPPORT_ONLY_CATEGORIES:
                self.connection.execute(
                    "INSERT OR IGNORE INTO disabled_moderation_categories "
                    "(server_id, category, disabled_by, disabled_at) "
                    "SELECT server_id, ?, disabled_by, disabled_at "
                    "FROM disabled_moderation_categories WHERE category=?", (new, old),
                )
        # Retire old active rules, while retaining all historical scores and cases.
        placeholders = ",".join("?" for _ in SUPPORTED_MODERATION_CATEGORIES)
        for table in ("moderation_category_policies", "disabled_moderation_categories"):
            self.connection.execute(f"DELETE FROM {table} WHERE category NOT IN ({placeholders})", SUPPORTED_MODERATION_CATEGORIES)
        self.connection.execute("INSERT INTO app_metadata(key,value) VALUES (?, '1')", (key,))

    def _migrate_stoatguard_production_categories_v2(self) -> None:
        """Move stored policy choices to the final StoatGuard vocabulary."""
        key = "stoatguard_production_categories_v2"
        if self.connection.execute(
            "SELECT 1 FROM app_metadata WHERE key=?", (key,)
        ).fetchone():
            return
        for old, new in LEGACY_CATEGORY_ALIASES.items():
            self.connection.execute(
                "INSERT OR IGNORE INTO moderation_category_policies "
                "(server_id, category, threshold, action, timeout_seconds, updated_by, updated_at) "
                "SELECT server_id, ?, threshold, action, timeout_seconds, updated_by, updated_at "
                "FROM moderation_category_policies WHERE category=?",
                (new, old),
            )
            if new not in SUPPORT_ONLY_CATEGORIES:
                self.connection.execute(
                    "INSERT OR IGNORE INTO disabled_moderation_categories "
                    "(server_id, category, disabled_by, disabled_at) "
                    "SELECT server_id, ?, disabled_by, disabled_at "
                    "FROM disabled_moderation_categories WHERE category=?",
                    (new, old),
                )
        placeholders = ",".join("?" for _ in SUPPORTED_MODERATION_CATEGORIES)
        for table in (
            "moderation_category_policies",
            "disabled_moderation_categories",
        ):
            self.connection.execute(
                f"DELETE FROM {table} WHERE category NOT IN ({placeholders})",
                SUPPORTED_MODERATION_CATEGORIES,
            )
        self.connection.execute(
            "INSERT INTO app_metadata(key,value) VALUES (?, '1')", (key,)
        )

    def _migrate_image_scanning_experimental_opt_in_v1(self) -> None:
        """Disable experimental vision everywhere once, including overrides."""
        key = "image_scanning_experimental_opt_in_v1"
        if self.connection.execute(
            "SELECT 1 FROM app_metadata WHERE key=?", (key,)
        ).fetchone():
            return
        self.connection.execute(
            "UPDATE server_settings SET image_scanning_enabled=0"
        )
        self.connection.execute("DELETE FROM channel_image_scanning_settings")
        self.connection.execute(
            "INSERT INTO app_metadata(key,value) VALUES (?, '1')", (key,)
        )

    @staticmethod
    def _full_username(username: object, discriminator: object = None) -> str | None:
        name = str(username or "").strip()
        if not name:
            return None
        discriminator_text = str(discriminator or "").strip()
        if discriminator_text and not name.endswith(f"#{discriminator_text}"):
            return f"{name}#{discriminator_text}"
        return name

    def _record_user_identity(
        self,
        user_id: object,
        username: object,
        discriminator: object = None,
        display_name: object = None,
    ) -> bool:
        identifier = str(user_id or "").strip()
        name = str(username or "").strip()
        if (
            not identifier
            or not name
            or name == identifier
            or name.casefold() in {"unknown user", "unknown username", "unknown member"}
        ):
            return False
        discriminator_text = str(discriminator or "").strip() or None
        if discriminator_text and name.endswith(f"#{discriminator_text}"):
            name = name[: -(len(discriminator_text) + 1)]
        elif discriminator_text is None:
            tagged_name = re.fullmatch(r"(.+)#(\d{4})", name)
            if tagged_name is not None:
                name, discriminator_text = tagged_name.groups()
        full_username = self._full_username(name, discriminator_text)
        if full_username is None:
            return False
        self.connection.execute(
            """
            INSERT INTO user_identities(
                user_id, username, discriminator, full_username, display_name, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username=excluded.username,
                discriminator=excluded.discriminator,
                full_username=excluded.full_username,
                display_name=COALESCE(excluded.display_name, user_identities.display_name),
                updated_at=excluded.updated_at
            """,
            (
                identifier,
                name,
                discriminator_text,
                full_username,
                str(display_name).strip() if display_name else None,
                _utc_now(),
            ),
        )
        return True

    def record_user_identity(
        self,
        user_id: object,
        username: object,
        discriminator: object = None,
        display_name: object = None,
    ) -> bool:
        recorded = self._record_user_identity(
            user_id, username, discriminator, display_name
        )
        if recorded:
            self.connection.commit()
        return recorded

    @staticmethod
    def _payload_identity_for_user(
        value: object, user_id: str
    ) -> tuple[object, object, object] | None:
        if isinstance(value, list):
            for item in value:
                found = ModerationDatabase._payload_identity_for_user(item, user_id)
                if found is not None:
                    return found
            return None
        if not isinstance(value, dict):
            return None
        for key, identifier in value.items():
            if not key.endswith("_id") or str(identifier or "") != user_id:
                continue
            stem = key[:-3]
            name_stem = stem[:-5] if stem.endswith("_user") else stem
            username_key = "username" if name_stem == "user" else f"{name_stem}_username"
            discriminator_key = (
                "discriminator"
                if name_stem == "user"
                else f"{name_stem}_discriminator"
            )
            display_key = (
                "display_name" if name_stem == "user" else f"{name_stem}_display_name"
            )
            username = value.get(username_key)
            if username:
                return username, value.get(discriminator_key), value.get(display_key)
        for child in value.values():
            found = ModerationDatabase._payload_identity_for_user(child, user_id)
            if found is not None:
                return found
        return None

    def _record_payload_identities(self, value: object) -> None:
        if isinstance(value, list):
            for item in value:
                self._record_payload_identities(item)
            return
        if not isinstance(value, dict):
            return
        for key, identifier in list(value.items()):
            if not key.endswith("_id") or identifier in {None, ""}:
                continue
            found = self._payload_identity_for_user(value, str(identifier))
            if found is not None:
                self._record_user_identity(identifier, *found)
        for child in value.values():
            self._record_payload_identities(child)

    def _backfill_user_identities(self) -> None:
        rows = self.connection.execute(
            """
            SELECT user_id, username, discriminator, display_name
            FROM dashboard_members
            WHERE username != user_id
            ORDER BY updated_at
            """
        ).fetchall()
        for row in rows:
            self._record_user_identity(
                row["user_id"], row["username"], row["discriminator"], row["display_name"]
            )

    def get_recorded_user_identity(
        self, user_id: str, server_id: str | None = None
    ) -> dict[str, Any] | None:
        identifier = str(user_id or "").strip()
        if not identifier:
            return None
        already_in_transaction = self.connection.in_transaction
        member = None
        if server_id:
            member = self.connection.execute(
                """
                SELECT username, discriminator, display_name, updated_at
                FROM dashboard_members WHERE server_id=? AND user_id=?
                """,
                (server_id, identifier),
            ).fetchone()
        if member is None:
            member = self.connection.execute(
                """
                SELECT username, discriminator, display_name, updated_at
                FROM dashboard_members WHERE user_id=?
                ORDER BY updated_at DESC LIMIT 1
                """,
                (identifier,),
            ).fetchone()
        identity = self.connection.execute(
            """
            SELECT user_id, username, discriminator, full_username,
                   display_name, updated_at
            FROM user_identities WHERE user_id=?
            """,
            (identifier,),
        ).fetchone()
        member_full_username = (
            self._full_username(member["username"], member["discriminator"])
            if member is not None and member["username"] != identifier
            else None
        )
        if member_full_username is not None and (
            identity is None
            or identity["full_username"] != member_full_username
            or (member["display_name"] and identity["display_name"] != member["display_name"])
        ):
            self._record_user_identity(
                identifier,
                member["username"],
                member["discriminator"],
                member["display_name"],
            )
            identity = self.connection.execute(
                """
                SELECT user_id, username, discriminator, full_username,
                       display_name, updated_at
                FROM user_identities WHERE user_id=?
                """,
                (identifier,),
            ).fetchone()
        if identity is not None:
            if not already_in_transaction and self.connection.in_transaction:
                self.connection.commit()
            return dict(identity)

        return None

    def _new_case_reference_id(self) -> str:
        alphabet = CASE_REFERENCE_LETTERS + CASE_REFERENCE_DIGITS
        generator = secrets.SystemRandom()
        while True:
            characters = [
                secrets.choice(CASE_REFERENCE_LETTERS),
                secrets.choice(CASE_REFERENCE_DIGITS),
                *(
                    secrets.choice(alphabet)
                    for _ in range(CASE_REFERENCE_LENGTH - 2)
                ),
            ]
            generator.shuffle(characters)
            reference_id = "".join(characters)
            exists = self.connection.execute(
                "SELECT 1 FROM moderation_cases WHERE reference_id=?",
                (reference_id,),
            ).fetchone()
            if exists is None:
                return reference_id

    def _backfill_case_references(self) -> None:
        rows = self.connection.execute(
            "SELECT id FROM moderation_cases WHERE reference_id IS NULL ORDER BY id"
        ).fetchall()
        for row in rows:
            self.connection.execute(
                "UPDATE moderation_cases SET reference_id=? WHERE id=?",
                (self._new_case_reference_id(), row["id"]),
            )

    def _new_report_reference_id(self, server_id: str) -> str:
        for _attempt in range(100):
            reference_id = "".join(
                secrets.choice(REPORT_REFERENCE_ALPHABET)
                for _ in range(REPORT_REFERENCE_LENGTH)
            )
            exists = self.connection.execute(
                "SELECT 1 FROM user_reports WHERE server_id=? AND reference_id=?",
                (server_id, reference_id),
            ).fetchone()
            if exists is None:
                return reference_id
        raise RuntimeError("Unable to allocate a report reference ID")

    def _backfill_report_references(self) -> None:
        rows = self.connection.execute(
            "SELECT id, server_id FROM user_reports "
            "WHERE reference_id IS NULL ORDER BY id"
        ).fetchall()
        for row in rows:
            self.connection.execute(
                "UPDATE user_reports SET reference_id=? WHERE id=?",
                (self._new_report_reference_id(row["server_id"]), row["id"]),
            )

    @staticmethod
    def _event_case_details(
        event_type: str, details: dict[str, Any]
    ) -> tuple[str, str] | None:
        if event_type == "member_ban":
            return "ban", str(details.get("reason") or "Member banned")
        if event_type == "member_kick":
            # Stoat emits the same removal event for kicks performed outside
            # Stoatmod, but does not include the external moderator or reason.
            # Keep those events in the audit log without presenting them as
            # moderation cases created by Stoatmod.
            if details.get("stoatmod_initiated") is False:
                return None
            return "kick", str(details.get("reason") or "Member kicked")
        if event_type == "warning_policy_timeout":
            count = details.get("warning_count")
            reason = (
                f"Automatic warning policy: {count} warnings"
                if count is not None
                else "Automatic warning policy timeout"
            )
            return "timeout", reason
        if event_type == "warning_policy_ban":
            count = details.get("warning_count")
            reason = (
                f"Automatic warning policy: {count} warnings"
                if count is not None
                else "Automatic warning policy ban"
            )
            return "ban", reason
        if event_type == "manual_mute":
            duration = details.get("duration_seconds")
            reason = str(details.get("reason") or (
                f"Manual mute for {duration} seconds"
                if duration is not None
                else "Manual mute"
            ))
            return "mute", reason
        if event_type == "automatic_spam_timeout":
            return "timeout", str(
                details.get("reason") or "Automatic spam timeout"
            )
        return None

    def _linked_warning_case(
        self, server_id: str, user_id: str | None, details: dict[str, Any]
    ) -> ModerationCaseRecord | None:
        reference = details.get("combined_warning_case")
        if not isinstance(reference, str) or not user_id:
            return None
        case = self.get_moderation_case(server_id, reference)
        if (
            case is not None
            and case.user_id == user_id
            and case.source_type == "warning"
            and case.source_id == details.get("warning_id")
        ):
            return case
        return None

    def _backfill_moderation_cases(self) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO moderation_cases(
                server_id, user_id, action, moderator_id, reason,
                source_type, source_id, status, created_at
            )
            SELECT server_id, user_id, 'warning', moderator_id, reason,
                   'warning', id, 'active', created_at
            FROM warnings
            """
        )
        rows = self.connection.execute(
            """
            SELECT id, server_id, event_type, user_id, actor_id,
                   details_json, created_at
            FROM moderation_events
            WHERE user_id IS NOT NULL
            ORDER BY id
            """
        ).fetchall()
        for row in rows:
            details = json.loads(row["details_json"])
            if self._linked_warning_case(row["server_id"], row["user_id"], details):
                continue
            case_details = self._event_case_details(row["event_type"], details)
            if case_details is None:
                continue
            action, reason = case_details
            self.connection.execute(
                """
                INSERT OR IGNORE INTO moderation_cases(
                    server_id, user_id, action, moderator_id, reason,
                    source_type, source_id, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'event', ?, 'active', ?)
                """,
                (
                    row["server_id"],
                    row["user_id"],
                    action,
                    row["actor_id"],
                    reason,
                    row["id"],
                    row["created_at"],
                ),
            )

    def _remove_legacy_zero_tolerance_history(self) -> int:
        candidate_rows = self.connection.execute(
            """
            SELECT id, event_type, details_json
            FROM moderation_events
            WHERE event_type IN (
                'zero_tolerance_global_ban',
                'global_ban_enforced',
                'global_ban_synchronized',
                'global_ban_enforced_on_join'
            )
            """
        ).fetchall()
        event_ids: list[int] = []
        for row in candidate_rows:
            try:
                details = json.loads(row["details_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                details = {}
            reason = str(details.get("reason") or "")
            if (
                row["event_type"] == "zero_tolerance_global_ban"
                or reason.startswith(LEGACY_ZERO_TOLERANCE_REASON_PREFIX)
            ):
                event_ids.append(int(row["id"]))
        if not event_ids:
            return 0

        placeholders = ",".join("?" for _event_id in event_ids)
        case_rows = self.connection.execute(
            f"""
            SELECT id, server_id, reference_id
            FROM moderation_cases
            WHERE source_type='event' AND source_id IN ({placeholders})
            """,
            event_ids,
        ).fetchall()
        for case in case_rows:
            reference_id = case["reference_id"]
            if reference_id:
                entry_rows = self.connection.execute(
                    """
                    SELECT id FROM moderation_case_entries
                    WHERE server_id=? AND case_reference=?
                    """,
                    (case["server_id"], reference_id),
                ).fetchall()
                entry_ids = [int(entry["id"]) for entry in entry_rows]
                if entry_ids:
                    entry_placeholders = ",".join("?" for _entry in entry_ids)
                    self.connection.execute(
                        "DELETE FROM moderation_case_entry_attachments "
                        f"WHERE entry_id IN ({entry_placeholders})",
                        entry_ids,
                    )
                self.connection.execute(
                    """
                    DELETE FROM moderation_case_entries
                    WHERE server_id=? AND case_reference=?
                    """,
                    (case["server_id"], reference_id),
                )
        self.connection.execute(
            f"""
            DELETE FROM moderation_cases
            WHERE source_type='event' AND source_id IN ({placeholders})
            """,
            event_ids,
        )

        self.connection.execute(
            f"DELETE FROM moderation_events WHERE id IN ({placeholders})",
            event_ids,
        )
        return len(event_ids)

    def close(self) -> None:
        self.connection.close()

    def set_log_channel(self, server_id: str, channel_id: str) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, log_channel_id)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET log_channel_id=excluded.log_channel_id
            """,
            (server_id, channel_id),
        )
        self.connection.commit()

    def set_moderation_threshold(self, server_id: str, threshold: float) -> None:
        if not MIN_MODERATION_THRESHOLD <= threshold <= 1:
            raise ValueError("Moderation threshold must be between 0 and 1")
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, moderation_threshold)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                moderation_threshold=excluded.moderation_threshold
            """,
            (server_id, threshold),
        )
        self.connection.commit()

    def get_moderation_threshold(
        self, server_id: str, default: float
    ) -> float:
        row = self.connection.execute(
            """
            SELECT moderation_threshold FROM server_settings WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        if row is None or row["moderation_threshold"] is None:
            return max(MIN_MODERATION_THRESHOLD, default)
        return max(MIN_MODERATION_THRESHOLD, float(row["moderation_threshold"]))

    def reset_moderation_threshold(self, server_id: str) -> bool:
        cursor = self.connection.execute(
            """
            UPDATE server_settings SET moderation_threshold=NULL
            WHERE server_id=? AND moderation_threshold IS NOT NULL
            """,
            (server_id,),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def get_log_channel(self, server_id: str) -> str | None:
        row = self.connection.execute(
            "SELECT log_channel_id FROM server_settings WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return None if row is None else row["log_channel_id"]

    def list_global_announcement_targets(self) -> list[dict[str, Any]]:
        """Return every installed server and its current announcement route.

        Dashboard snapshots are the durable record of servers that still have the
        bot installed.  Using them here avoids silently skipping a server when the
        live client cache is incomplete during a reconnect.
        """
        rows = self.connection.execute(
            """
            SELECT snapshot.server_id, snapshot.server_name, snapshot.owner_id,
                   settings.log_channel_id
            FROM dashboard_server_snapshots AS snapshot
            LEFT JOIN server_settings AS settings
              ON settings.server_id=snapshot.server_id
            ORDER BY LOWER(snapshot.server_name), snapshot.server_id
            """
        ).fetchall()
        return [
            {
                "server_id": str(row["server_id"]),
                "server_name": str(row["server_name"]),
                "owner_id": str(row["owner_id"] or "").strip() or None,
                "log_channel_id": (
                    str(row["log_channel_id"]).strip()
                    if row["log_channel_id"]
                    else None
                ),
            }
            for row in rows
        ]

    def add_auto_role(
        self, server_id: str, role_id: str, added_by: str
    ) -> bool:
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO auto_roles(
                server_id, role_id, added_by, added_at
            ) VALUES (?, ?, ?, ?)
            """,
            (server_id, role_id, added_by, _utc_now()),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def remove_auto_role(self, server_id: str, role_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM auto_roles WHERE server_id=? AND role_id=?",
            (server_id, role_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def clear_auto_roles(self, server_id: str) -> int:
        cursor = self.connection.execute(
            "DELETE FROM auto_roles WHERE server_id=?", (server_id,)
        )
        self.connection.commit()
        return cursor.rowcount

    def list_auto_roles(self, server_id: str) -> list[str]:
        rows = self.connection.execute(
            """
            SELECT role_id FROM auto_roles
            WHERE server_id=? ORDER BY added_at, role_id
            """,
            (server_id,),
        ).fetchall()
        return [row["role_id"] for row in rows]

    def create_dashboard_login_code(
        self,
        code_hash: str,
        server_id: str,
        user_id: str,
        expires_at: str,
    ) -> None:
        self.connection.execute(
            """
            DELETE FROM dashboard_login_codes
            WHERE server_id=? AND user_id=? AND used_at IS NULL
            """,
            (server_id, user_id),
        )
        self.connection.execute(
            """
            INSERT INTO dashboard_login_codes(
                code_hash, server_id, user_id, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (code_hash, server_id, user_id, expires_at, _utc_now()),
        )
        self.connection.commit()

    def consume_dashboard_login_code(
        self, code_hash: str
    ) -> tuple[str, str] | None:
        now = _utc_now()
        cursor = self.connection.execute(
            """
            UPDATE dashboard_login_codes SET used_at=?
            WHERE code_hash=? AND used_at IS NULL AND expires_at>?
            """,
            (now, code_hash, now),
        )
        if cursor.rowcount == 0:
            self.connection.commit()
            return None
        row = self.connection.execute(
            """
            SELECT server_id, user_id FROM dashboard_login_codes
            WHERE code_hash=?
            """,
            (code_hash,),
        ).fetchone()
        self.connection.commit()
        return (row["server_id"], row["user_id"])

    def create_dashboard_session(
        self,
        token_hash: str,
        server_id: str,
        user_id: str,
        expires_at: str,
    ) -> None:
        now = _utc_now()
        self.connection.execute(
            "DELETE FROM dashboard_sessions WHERE expires_at<=?", (now,)
        )
        self.connection.execute(
            """
            INSERT INTO dashboard_sessions(
                token_hash, server_id, user_id, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (token_hash, server_id, user_id, expires_at, now),
        )
        self.connection.commit()

    def get_dashboard_session(
        self, token_hash: str
    ) -> tuple[str, str] | None:
        row = self.connection.execute(
            """
            SELECT server_id, user_id FROM dashboard_sessions
            WHERE token_hash=? AND expires_at>?
            """,
            (token_hash, _utc_now()),
        ).fetchone()
        return None if row is None else (row["server_id"], row["user_id"])

    def remove_dashboard_session(self, token_hash: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM dashboard_sessions WHERE token_hash=?", (token_hash,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def get_dashboard_server_owner(self, server_id: str) -> str | None:
        row = self.connection.execute(
            "SELECT owner_id FROM dashboard_server_snapshots WHERE server_id=?",
            (server_id,),
        ).fetchone()
        if row is None:
            return None
        owner_id = str(row["owner_id"] or "").strip()
        return owner_id or None

    def get_dashboard_server_name(self, server_id: str) -> str | None:
        row = self.connection.execute(
            "SELECT server_name FROM dashboard_server_snapshots WHERE server_id=?",
            (server_id,),
        ).fetchone()
        if row is None:
            return None
        server_name = str(row["server_name"] or "").strip()
        return server_name or None

    def dashboard_user_has_access(
        self,
        server_id: str,
        user_id: str,
        *,
        owner_id: str | None = None,
        manage_server: bool | None = None,
    ) -> bool:
        effective_owner_id = (
            str(owner_id).strip()
            if owner_id is not None
            else self.get_dashboard_server_owner(server_id)
        )
        if effective_owner_id and str(user_id) == effective_owner_id:
            return True
        denied = self.connection.execute(
            "SELECT 1 FROM dashboard_access_denials WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        ).fetchone()
        if denied is not None:
            return False
        row = self.connection.execute(
            "SELECT 1 FROM dashboard_access_grants WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        ).fetchone()
        if row is not None:
            return True
        if manage_server is not None:
            return bool(manage_server)
        member = self.connection.execute(
            """
            SELECT manage_server FROM dashboard_members
            WHERE server_id=? AND user_id=? AND is_bot=0
            """,
            (server_id, user_id),
        ).fetchone()
        return bool(member and member["manage_server"])

    def grant_dashboard_access(
        self, server_id: str, user_id: str, granted_by: str
    ) -> bool:
        if str(user_id) == str(self.get_dashboard_server_owner(server_id) or ""):
            return False
        restored = self.connection.execute(
            "DELETE FROM dashboard_access_denials WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        ).rowcount
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO dashboard_access_grants(
                server_id, user_id, granted_by, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (server_id, user_id, granted_by, _utc_now()),
        )
        self.connection.commit()
        return bool(restored or cursor.rowcount > 0)

    def revoke_dashboard_access(
        self, server_id: str, user_id: str, revoked_by: str
    ) -> bool:
        if str(user_id) == str(self.get_dashboard_server_owner(server_id) or ""):
            return False
        had_access = self.dashboard_user_has_access(server_id, user_id)
        self.connection.execute(
            "DELETE FROM dashboard_access_grants WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        )
        self.connection.execute(
            """
            INSERT INTO dashboard_access_denials(
                server_id, user_id, revoked_by, created_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(server_id, user_id) DO UPDATE SET
                revoked_by=excluded.revoked_by,
                created_at=excluded.created_at
            """,
            (server_id, user_id, revoked_by, _utc_now()),
        )
        self.connection.execute(
            "DELETE FROM dashboard_sessions WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        )
        self.connection.execute(
            "DELETE FROM appeal_notification_preferences "
            "WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        )
        self.connection.execute(
            """
            DELETE FROM dashboard_login_codes
            WHERE server_id=? AND user_id=? AND used_at IS NULL
            """,
            (server_id, user_id),
        )
        self.connection.commit()
        return had_access

    def restore_dashboard_access(self, server_id: str, user_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM dashboard_access_denials WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def revoke_dashboard_sessions(
        self, server_id: str, user_id: str | None = None
    ) -> int:
        if user_id is None:
            cursor = self.connection.execute(
                "DELETE FROM dashboard_sessions WHERE server_id=?", (server_id,)
            )
            self.connection.execute(
                """
                DELETE FROM dashboard_login_codes
                WHERE server_id=? AND used_at IS NULL
                """,
                (server_id,),
            )
        else:
            cursor = self.connection.execute(
                "DELETE FROM dashboard_sessions WHERE server_id=? AND user_id=?",
                (server_id, user_id),
            )
            self.connection.execute(
                """
                DELETE FROM dashboard_login_codes
                WHERE server_id=? AND user_id=? AND used_at IS NULL
                """,
                (server_id, user_id),
            )
        self.connection.commit()
        return cursor.rowcount

    def list_dashboard_access(self, server_id: str) -> dict[str, Any]:
        owner_id = self.get_dashboard_server_owner(server_id)
        rows = self.connection.execute(
            """
            WITH candidates AS (
                SELECT user_id FROM dashboard_members
                WHERE server_id=? AND manage_server=1 AND is_bot=0
                UNION
                SELECT user_id FROM dashboard_access_grants WHERE server_id=?
                UNION
                SELECT user_id FROM dashboard_access_denials WHERE server_id=?
            )
            SELECT candidates.user_id,
                   grants.granted_by, grants.created_at AS granted_at,
                   denials.revoked_by, denials.created_at AS revoked_at,
                   members.username, members.discriminator, members.display_name,
                   members.avatar_url, COALESCE(members.manage_server, 0) AS manage_server,
                   (SELECT COUNT(*) FROM dashboard_sessions AS sessions
                    WHERE sessions.server_id=?
                      AND sessions.user_id=candidates.user_id
                      AND sessions.expires_at>?) AS active_sessions
            FROM candidates
            LEFT JOIN dashboard_members AS members
              ON members.server_id=? AND members.user_id=candidates.user_id
            LEFT JOIN dashboard_access_grants AS grants
              ON grants.server_id=? AND grants.user_id=candidates.user_id
            LEFT JOIN dashboard_access_denials AS denials
              ON denials.server_id=? AND denials.user_id=candidates.user_id
            ORDER BY COALESCE(members.display_name, members.username, candidates.user_id)
                     COLLATE NOCASE
            """,
            (
                server_id,
                server_id,
                server_id,
                server_id,
                _utc_now(),
                server_id,
                server_id,
                server_id,
            ),
        ).fetchall()

        def access_user(
            user_id: str,
            *,
            is_owner: bool,
            granted_by: str | None,
            granted_at: str | None,
            manage_server: bool = False,
            revoked_by: str | None = None,
            revoked_at: str | None = None,
            row: sqlite3.Row | None = None,
        ) -> dict[str, Any]:
            identity = self.get_recorded_user_identity(user_id, server_id) or {}
            username = (
                (row["username"] if row is not None else None)
                or identity.get("username")
                or user_id
            )
            discriminator = (
                (row["discriminator"] if row is not None else None)
                or identity.get("discriminator")
            )
            full_username = identity.get("full_username") or self._full_username(
                username, discriminator
            )
            active_sessions = (
                int(row["active_sessions"])
                if row is not None
                else int(self.connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM dashboard_sessions
                    WHERE server_id=? AND user_id=? AND expires_at>?
                    """,
                    (server_id, user_id, _utc_now()),
                ).fetchone()["count"])
            )
            return {
                "user_id": user_id,
                "username": username,
                "full_username": full_username,
                "display_name": (
                    (row["display_name"] if row is not None else None)
                    or identity.get("display_name")
                ),
                "avatar_url": row["avatar_url"] if row is not None else None,
                "is_owner": is_owner,
                "manage_server": manage_server,
                "access_source": (
                    "owner" if is_owner else "grant" if granted_by else "manage_server"
                ),
                "granted_by": granted_by,
                "granted_at": granted_at,
                "revoked_by": revoked_by,
                "revoked_at": revoked_at,
                "is_revoked": revoked_at is not None,
                "active_sessions": active_sessions,
            }

        users: list[dict[str, Any]] = []
        if owner_id:
            owner_member = self.connection.execute(
                """
                SELECT username, discriminator, display_name, avatar_url,
                       (SELECT COUNT(*) FROM dashboard_sessions
                        WHERE server_id=? AND user_id=? AND expires_at>?)
                       AS active_sessions
                FROM dashboard_members WHERE server_id=? AND user_id=?
                """,
                (server_id, owner_id, _utc_now(), server_id, owner_id),
            ).fetchone()
            users.append(access_user(
                owner_id,
                is_owner=True,
                granted_by=None,
                granted_at=None,
                manage_server=True,
                row=owner_member,
            ))
        revoked_users: list[dict[str, Any]] = []
        for row in rows:
            if str(row["user_id"]) == str(owner_id or ""):
                continue
            user = access_user(
                str(row["user_id"]),
                is_owner=False,
                granted_by=(str(row["granted_by"]) if row["granted_by"] else None),
                granted_at=(str(row["granted_at"]) if row["granted_at"] else None),
                manage_server=bool(row["manage_server"]),
                revoked_by=(str(row["revoked_by"]) if row["revoked_by"] else None),
                revoked_at=(str(row["revoked_at"]) if row["revoked_at"] else None),
                row=row,
            )
            if user["is_revoked"]:
                revoked_users.append(user)
            elif user["manage_server"] or user["granted_by"]:
                users.append(user)
        return {
            "owner_id": owner_id,
            "users": users,
            "revoked_users": revoked_users,
            "active_session_count": sum(user["active_sessions"] for user in users),
        }

    def create_owner_dashboard_session(
        self, token_hash: str, expires_at: str
    ) -> None:
        now = _utc_now()
        self.connection.execute(
            "DELETE FROM owner_dashboard_sessions WHERE expires_at<=?", (now,)
        )
        self.connection.execute(
            """
            INSERT INTO owner_dashboard_sessions(token_hash, expires_at, created_at)
            VALUES (?, ?, ?)
            """,
            (token_hash, expires_at, now),
        )
        self.connection.commit()

    def get_owner_dashboard_session(self, token_hash: str) -> bool:
        row = self.connection.execute(
            """
            SELECT 1 FROM owner_dashboard_sessions
            WHERE token_hash=? AND expires_at>?
            """,
            (token_hash, _utc_now()),
        ).fetchone()
        return row is not None

    def remove_owner_dashboard_session(self, token_hash: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM owner_dashboard_sessions WHERE token_hash=?", (token_hash,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def provision_admin_dashboard_account(
        self,
        user_id: str,
        created_by: str,
        *,
        replace: bool = False,
    ) -> dict[str, Any]:
        identifier = user_id.strip().upper()
        now = _utc_now()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            current = self.connection.execute(
                "SELECT password_version, revoked_at, delivery_action_id "
                "FROM admin_dashboard_accounts "
                "WHERE user_id=?",
                (identifier,),
            ).fetchone()
            if current is not None and current["revoked_at"] is None and not replace:
                self.connection.rollback()
                raise ValueError(
                    "That user already has an admin account or credential delivery in progress."
                )
            password_version = int(current["password_version"] or 0) + 1 if current else 1
            if current is not None and current["delivery_action_id"]:
                self.connection.execute(
                    """
                    UPDATE dashboard_actions
                    SET status='failed', result_json=?, processed_at=?,
                        claimed_at=NULL, claim_token=NULL
                    WHERE id=? AND status IN ('pending', 'processing')
                    """,
                    (
                        json.dumps(
                            {"error": "Credential delivery was replaced by the owner."},
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        now,
                        int(current["delivery_action_id"]),
                    ),
                )
            self.connection.execute(
                """
                INSERT INTO admin_dashboard_accounts(
                    user_id, password_hash, password_version,
                    password_expires_at, active, created_by, created_at,
                    updated_at, last_password_change_at, delivery_action_id,
                    revoked_by, revoked_at
                ) VALUES (?, '', ?, ?, 0, ?, ?, ?, ?, NULL, NULL, NULL)
                ON CONFLICT(user_id) DO UPDATE SET
                    password_hash='',
                    password_version=excluded.password_version,
                    password_expires_at=excluded.password_expires_at,
                    active=0,
                    updated_at=excluded.updated_at,
                    last_password_change_at=excluded.last_password_change_at,
                    delivery_action_id=NULL,
                    revoked_by=NULL,
                    revoked_at=NULL
                """,
                (
                    identifier,
                    password_version,
                    now,
                    created_by,
                    now,
                    now,
                    now,
                ),
            )
            self.connection.execute(
                "DELETE FROM admin_dashboard_sessions WHERE admin_email=?",
                (identifier,),
            )
            self.connection.execute(
                "DELETE FROM admin_password_change_sessions WHERE admin_user_id=?",
                (identifier,),
            )
            payload = {
                "user_id": identifier,
                "password_version": password_version,
            }
            action_cursor = self.connection.execute(
                """
                INSERT INTO dashboard_actions(
                    server_id, action, actor_id, payload_json, created_at
                ) VALUES ('global', 'deliver_admin_credentials', ?, ?, ?)
                """,
                (
                    created_by,
                    json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    now,
                ),
            )
            action_id = int(action_cursor.lastrowid)
            self.connection.execute(
                "UPDATE admin_dashboard_accounts SET delivery_action_id=? WHERE user_id=?",
                (action_id, identifier),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        account = self.get_admin_dashboard_account(identifier)
        if account is None:
            raise RuntimeError("The admin account could not be loaded after creation.")
        return account

    def queue_due_admin_password_rotations(self, *, now: datetime | None = None) -> int:
        """Expire access and queue weekly DMs atomically, including after downtime."""
        timestamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            accounts = self.connection.execute(
                """
                SELECT user_id, password_version, delivery_action_id
                FROM admin_dashboard_accounts
                WHERE active=1 AND revoked_at IS NULL
                  AND (datetime(password_expires_at) <= datetime(?)
                       OR datetime(password_expires_at) IS NULL)
                """,
                (timestamp,),
            ).fetchall()
            for account in accounts:
                user_id = account["user_id"]
                version = int(account["password_version"]) + 1
                self.connection.execute(
                    """
                    UPDATE dashboard_actions
                    SET status='failed', result_json=?, processed_at=?,
                        claimed_at=NULL, claim_token=NULL
                    WHERE id=? AND status IN ('pending', 'processing')
                    """,
                    (json.dumps({"error": "Replaced by scheduled password rotation."}),
                     timestamp, account["delivery_action_id"]),
                )
                cursor = self.connection.execute(
                    """
                    INSERT INTO dashboard_actions(server_id, action, actor_id, payload_json, created_at)
                    VALUES ('global', 'deliver_admin_credentials', 'system:weekly-password-rotation', ?, ?)
                    """,
                    (json.dumps({"user_id": user_id, "password_version": version,
                                 "reason": "scheduled_rotation"}, sort_keys=True), timestamp),
                )
                self.connection.execute(
                    """
                    UPDATE admin_dashboard_accounts
                    SET password_hash='', password_version=?, active=0,
                        delivery_action_id=?, updated_at=?
                    WHERE user_id=?
                    """,
                    (version, cursor.lastrowid, timestamp, user_id),
                )
                self.connection.execute(
                    "DELETE FROM admin_dashboard_sessions WHERE admin_email=?", (user_id,)
                )
                self.connection.execute(
                    "DELETE FROM admin_password_change_sessions WHERE admin_user_id=?", (user_id,)
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return len(accounts)

    def defer_admin_credential_delivery(
        self, action_id: int, *, claim_token: str, retry_count: int, delay_seconds: int
    ) -> bool:
        """Retry only the current, unrevoked credential delivery; never store a secret."""
        retry_at = (datetime.now(timezone.utc) + timedelta(seconds=max(1, delay_seconds))).isoformat(timespec="seconds")
        cursor = self.connection.execute(
            """
            UPDATE dashboard_actions
            SET status='pending', payload_json=json_set(payload_json, '$.retry_count', ?),
                result_json=?, not_before=?, claimed_at=NULL, claim_token=NULL, processed_at=NULL
            WHERE id=? AND action='deliver_admin_credentials'
              AND status='processing' AND claim_token=?
              AND EXISTS (
                  SELECT 1 FROM admin_dashboard_accounts AS account
                  WHERE account.delivery_action_id=dashboard_actions.id
                    AND account.password_version=json_extract(dashboard_actions.payload_json, '$.password_version')
                    AND account.active=0 AND account.revoked_at IS NULL
              )
            """,
            (retry_count, json.dumps({"error": "Credential DM could not be delivered. Automatic retry scheduled.",
                                     "retry_scheduled": True}), retry_at, action_id, claim_token),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def activate_admin_dashboard_account_credentials(
        self,
        user_id: str,
        password_version: int,
        delivery_action_id: int,
        password_hash: str,
        password_expires_at: str,
        *,
        claim_token: str | None = None,
    ) -> bool:
        claim_clause = ""
        claim_values: tuple[Any, ...] = ()
        if claim_token:
            claim_clause = (
                " AND EXISTS (SELECT 1 FROM dashboard_actions AS action "
                "WHERE action.id=? AND action.status='processing' "
                "AND action.claim_token=?)"
            )
            claim_values = (int(delivery_action_id), claim_token)
        cursor = self.connection.execute(
            f"""
            UPDATE admin_dashboard_accounts
            SET password_hash=?, password_expires_at=?, active=1,
                updated_at=?, last_password_change_at=?
            WHERE user_id=? AND password_version=?
              AND delivery_action_id=? AND active=0 AND revoked_at IS NULL
              {claim_clause}
            """,
            (*(
                password_hash,
                password_expires_at,
                _utc_now(),
                _utc_now(),
                user_id.strip().upper(),
                int(password_version),
                int(delivery_action_id),
            ), *claim_values),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def admin_dashboard_delivery_is_current(
        self,
        user_id: str,
        password_version: int,
        delivery_action_id: int,
        *,
        claim_token: str | None = None,
        renew_claim: bool = False,
    ) -> bool:
        if claim_token and renew_claim:
            renewed = self.connection.execute(
                """
                UPDATE dashboard_actions SET claimed_at=?
                WHERE id=? AND status='processing' AND claim_token=?
                """,
                (_utc_now(), int(delivery_action_id), claim_token),
            )
            self.connection.commit()
            if not renewed.rowcount:
                return False
        claim_clause = ""
        claim_values: tuple[Any, ...] = ()
        if claim_token:
            claim_clause = (
                " AND EXISTS (SELECT 1 FROM dashboard_actions AS action "
                "WHERE action.id=? AND action.status='processing' "
                "AND action.claim_token=?)"
            )
            claim_values = (int(delivery_action_id), claim_token)
        row = self.connection.execute(
            f"""
            SELECT 1 FROM admin_dashboard_accounts
            WHERE user_id=? AND password_version=? AND delivery_action_id=?
              AND active=0 AND revoked_at IS NULL
              {claim_clause}
            """,
            (*(
                user_id.strip().upper(),
                int(password_version),
                int(delivery_action_id),
            ), *claim_values),
        ).fetchone()
        return row is not None

    def get_admin_dashboard_account(
        self, user_id: str, *, include_password_hash: bool = False
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT accounts.*, identities.full_username, identities.display_name
            FROM admin_dashboard_accounts AS accounts
            LEFT JOIN user_identities AS identities
              ON identities.user_id=accounts.user_id
            WHERE accounts.user_id=?
            """,
            (user_id.strip().upper(),),
        ).fetchone()
        if row is None:
            return None
        account = dict(row)
        if not include_password_hash:
            account.pop("password_hash", None)
        account["active"] = bool(account["active"])
        action_id = account.get("delivery_action_id")
        action = self.get_dashboard_action(int(action_id)) if action_id else None
        result = action.get("result", {}) if action else {}
        account["delivery"] = {
            "action_id": int(action_id) if action_id else None,
            "status": action.get("status", "not_requested") if action else "not_requested",
            "error": str(result.get("error") or "") or None,
            "delivered_at": action.get("processed_at") if action else None,
            "next_attempt_at": action.get("not_before") if action else None,
        }
        return account

    def list_admin_dashboard_accounts(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT user_id FROM admin_dashboard_accounts
            ORDER BY active DESC, updated_at DESC, user_id
            """
        ).fetchall()
        return [
            account
            for row in rows
            if (
                account := self.get_admin_dashboard_account(str(row["user_id"]))
            ) is not None
        ]

    def revoke_admin_dashboard_account(
        self, user_id: str, revoked_by: str
    ) -> dict[str, Any] | None:
        identifier = user_id.strip().upper()
        now = _utc_now()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            account = self.connection.execute(
                "SELECT delivery_action_id, revoked_at FROM admin_dashboard_accounts "
                "WHERE user_id=?",
                (identifier,),
            ).fetchone()
            if account is None or account["revoked_at"] is not None:
                self.connection.rollback()
                return None
            cursor = self.connection.execute(
                """
                UPDATE admin_dashboard_accounts
                SET active=0, password_version=password_version+1,
                    updated_at=?, revoked_by=?, revoked_at=?
                WHERE user_id=? AND revoked_at IS NULL
                """,
                (now, revoked_by, now, identifier),
            )
            if not cursor.rowcount:
                self.connection.rollback()
                return None
            self.connection.execute(
                "DELETE FROM admin_dashboard_sessions WHERE admin_email=?",
                (identifier,),
            )
            self.connection.execute(
                "DELETE FROM admin_password_change_sessions WHERE admin_user_id=?",
                (identifier,),
            )
            if account["delivery_action_id"]:
                self.connection.execute(
                    """
                    UPDATE dashboard_actions
                    SET status='failed', result_json=?, processed_at=?,
                        claimed_at=NULL, claim_token=NULL
                    WHERE id=? AND status IN ('pending', 'processing')
                    """,
                    (
                        json.dumps({"error": "Admin access was revoked before delivery."}),
                        now,
                        int(account["delivery_action_id"]),
                    ),
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return self.get_admin_dashboard_account(identifier)

    def create_admin_dashboard_session(
        self,
        token_hash: str,
        admin_user_id: str,
        password_version: int,
        expires_at: str,
    ) -> bool:
        identifier = admin_user_id.strip().upper()
        now = _utc_now()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                "DELETE FROM admin_dashboard_sessions WHERE expires_at<=?", (now,)
            )
            cursor = self.connection.execute(
                """
                INSERT INTO admin_dashboard_sessions(
                    token_hash, admin_email, password_version, expires_at, created_at
                )
                SELECT ?, accounts.user_id, ?, ?, ?
                FROM admin_dashboard_accounts AS accounts
                WHERE accounts.user_id=? AND accounts.active=1
                  AND accounts.password_version=?
                  AND accounts.password_expires_at>?
                """,
                (
                    token_hash,
                    int(password_version),
                    expires_at,
                    now,
                    identifier,
                    int(password_version),
                    now,
                ),
            )
            if cursor.rowcount:
                self.connection.execute(
                    "UPDATE admin_dashboard_accounts "
                    "SET last_login_at=?, updated_at=? "
                    "WHERE user_id=? AND active=1 AND password_version=?",
                    (now, now, identifier, int(password_version)),
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return cursor.rowcount > 0

    def get_admin_dashboard_session(self, token_hash: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT sessions.admin_email AS user_id,
                   sessions.password_version,
                   accounts.password_expires_at,
                   accounts.full_username
            FROM admin_dashboard_sessions AS sessions
            INNER JOIN (
                SELECT accounts.*,
                       identities.full_username AS full_username
                FROM admin_dashboard_accounts AS accounts
                LEFT JOIN user_identities AS identities
                  ON identities.user_id=accounts.user_id
            ) AS accounts ON accounts.user_id=sessions.admin_email
            WHERE sessions.token_hash=?
              AND sessions.expires_at>?
              AND accounts.active=1
              AND accounts.password_version=sessions.password_version
              AND accounts.password_expires_at>?
            """,
            (token_hash, _utc_now(), _utc_now()),
        ).fetchone()
        return dict(row) if row else None

    def remove_admin_dashboard_session(self, token_hash: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM admin_dashboard_sessions WHERE token_hash=?", (token_hash,)
        )
        self.connection.commit()
        return cursor.rowcount > 0


    def admin_login_is_rate_limited(
        self, scope: str, key_hash: str
    ) -> bool:
        now = datetime.now(timezone.utc)
        now_text = now.isoformat(timespec="seconds")
        inactive_cutoff = (now - timedelta(minutes=15)).isoformat(
            timespec="seconds"
        )
        self.connection.execute(
            """
            DELETE FROM admin_login_failures
            WHERE (locked_until IS NOT NULL AND locked_until<=?)
               OR (locked_until IS NULL AND window_started_at<=?)
            """,
            (now_text, inactive_cutoff),
        )
        self.connection.commit()
        row = self.connection.execute(
            """
            SELECT 1 FROM admin_login_failures
            WHERE scope=? AND key_hash=? AND locked_until>?
            """,
            (scope, key_hash, _utc_now()),
        ).fetchone()
        return row is not None

    def record_admin_login_failure(
        self,
        scope: str,
        key_hash: str,
        *,
        max_attempts: int,
        window_seconds: int = 900,
        subject_hash: str | None = None,
    ) -> bool:
        now = datetime.now(timezone.utc)
        now_text = now.isoformat(timespec="seconds")
        window_start = now - timedelta(seconds=max(60, window_seconds))
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                """
                SELECT failure_count, window_started_at, locked_until
                FROM admin_login_failures WHERE scope=? AND key_hash=?
                """,
                (scope, key_hash),
            ).fetchone()
            if row is None:
                failure_count = 1
                started_at = now_text
            else:
                try:
                    started = datetime.fromisoformat(str(row["window_started_at"]))
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=timezone.utc)
                except (TypeError, ValueError):
                    started = window_start
                if started <= window_start:
                    failure_count = 1
                    started_at = now_text
                else:
                    failure_count = int(row["failure_count"] or 0) + 1
                    started_at = str(row["window_started_at"])
            locked_until = (
                (now + timedelta(seconds=max(60, window_seconds))).isoformat(
                    timespec="seconds"
                )
                if failure_count >= max(1, max_attempts)
                else None
            )
            self.connection.execute(
                """
                INSERT INTO admin_login_failures(
                    scope, key_hash, subject_hash, failure_count,
                    window_started_at, locked_until
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope, key_hash) DO UPDATE SET
                    subject_hash=excluded.subject_hash,
                    failure_count=excluded.failure_count,
                    window_started_at=excluded.window_started_at,
                    locked_until=excluded.locked_until
                """,
                (
                    scope,
                    key_hash,
                    subject_hash,
                    failure_count,
                    started_at,
                    locked_until,
                ),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return locked_until is not None

    def clear_admin_login_failures(self, scope: str, key_hash: str) -> None:
        self.connection.execute(
            "DELETE FROM admin_login_failures WHERE scope=? AND key_hash=?",
            (scope, key_hash),
        )
        self.connection.commit()

    def appeal_notification_preference(
        self,
        server_id: str,
        user_id: str,
        enabled: bool | None = None,
    ) -> bool:
        """Read or update a moderator's per-server appeal DM preference."""
        if enabled is not None:
            with self.connection:
                if enabled:
                    self.connection.execute(
                        """
                        INSERT INTO appeal_notification_preferences(
                            server_id, user_id, enabled, updated_at
                        ) VALUES (?, ?, 1, ?)
                        ON CONFLICT(server_id, user_id) DO UPDATE SET
                            enabled=1,
                            updated_at=excluded.updated_at
                        """,
                        (server_id, user_id, _utc_now()),
                    )
                else:
                    self.connection.execute(
                        """
                        DELETE FROM appeal_notification_preferences
                        WHERE server_id=? AND user_id=?
                        """,
                        (server_id, user_id),
                    )
        row = self.connection.execute(
            """
            SELECT enabled FROM appeal_notification_preferences
            WHERE server_id=? AND user_id=?
            """,
            (server_id, user_id),
        ).fetchone()
        return bool(row and row["enabled"])

    def appeal_notification_recipients(self, server_id: str) -> list[str]:
        """Return opted-in moderators who still have dashboard access."""
        rows = self.connection.execute(
            """
            SELECT user_id FROM appeal_notification_preferences
            WHERE server_id=? AND enabled=1
            ORDER BY user_id
            """,
            (server_id,),
        ).fetchall()
        return [
            str(row["user_id"])
            for row in rows
            if self.dashboard_user_has_access(server_id, str(row["user_id"]))
        ]

    @staticmethod
    def _dashboard_notification_filter(section: str) -> tuple[str, tuple[Any, ...]]:
        if section == "activity":
            return "", ()
        if section == "appeals":
            return " AND event_type=?", ("moderation_appeal_submitted",)
        if section == "reports":
            return (
                " AND event_type IN (?, ?, ?, ?)",
                (
                    "server_report_submitted",
                    "server_report_response",
                    "local_report_submitted",
                    "local_report_response",
                ),
            )
        raise ValueError("Notification section must be activity, appeals, or reports.")

    def get_dashboard_notification_snapshot(
        self, server_id: str, user_id: str
    ) -> dict[str, dict[str, int]]:
        sections = ("activity", "appeals", "reports")
        markers = {
            str(row["section"]): int(row["last_event_id"] or 0)
            for row in self.connection.execute(
                "SELECT section, last_event_id FROM dashboard_notification_reads "
                "WHERE server_id=? AND user_id=?",
                (server_id, user_id),
            ).fetchall()
        }
        if any(section not in markers for section in sections):
            now = _utc_now()
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                for section in sections:
                    filter_sql, filter_values = self._dashboard_notification_filter(section)
                    latest_row = self.connection.execute(
                        "SELECT COALESCE(MAX(id), 0) AS latest_event_id "
                        "FROM moderation_events WHERE server_id=?" + filter_sql,
                        (server_id, *filter_values),
                    ).fetchone()
                    self.connection.execute(
                        """
                        INSERT OR IGNORE INTO dashboard_notification_reads(
                            server_id, user_id, section, last_event_id, updated_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            server_id,
                            user_id,
                            section,
                            int(latest_row["latest_event_id"] or 0),
                            now,
                        ),
                    )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

        result: dict[str, dict[str, int]] = {}
        for section in sections:
            filter_sql, filter_values = self._dashboard_notification_filter(section)
            marker = self.connection.execute(
                """
                SELECT last_event_id FROM dashboard_notification_reads
                WHERE server_id=? AND user_id=? AND section=?
                """,
                (server_id, user_id, section),
            ).fetchone()
            last_event_id = int(marker["last_event_id"] or 0) if marker else 0
            snapshot_row = self.connection.execute(
                "SELECT COALESCE(MAX(id), 0) AS latest_event_id, "
                "COALESCE(SUM(CASE WHEN id>? THEN 1 ELSE 0 END), 0) AS unread_count "
                "FROM moderation_events WHERE server_id=?" + filter_sql,
                (last_event_id, server_id, *filter_values),
            ).fetchone()
            result[section] = {
                "unread_count": int(snapshot_row["unread_count"] or 0),
                "latest_event_id": int(snapshot_row["latest_event_id"] or 0),
            }
        return result

    def mark_dashboard_notification_read(
        self,
        server_id: str,
        user_id: str,
        section: str,
        through_event_id: int,
    ) -> dict[str, int]:
        filter_sql, filter_values = self._dashboard_notification_filter(section)
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            latest_row = self.connection.execute(
                "SELECT COALESCE(MAX(id), 0) AS latest_event_id "
                "FROM moderation_events WHERE server_id=?" + filter_sql,
                (server_id, *filter_values),
            ).fetchone()
            latest_event_id = int(latest_row["latest_event_id"] or 0)
            clamped = min(max(0, int(through_event_id)), latest_event_id)
            self.connection.execute(
                """
                INSERT INTO dashboard_notification_reads(
                    server_id, user_id, section, last_event_id, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(server_id, user_id, section) DO UPDATE SET
                    last_event_id=MAX(last_event_id, excluded.last_event_id),
                    updated_at=excluded.updated_at
                """,
                (server_id, user_id, section, clamped, _utc_now()),
            )
            marker = self.connection.execute(
                """
                SELECT last_event_id FROM dashboard_notification_reads
                WHERE server_id=? AND user_id=? AND section=?
                """,
                (server_id, user_id, section),
            ).fetchone()
            unread_row = self.connection.execute(
                "SELECT COUNT(*) AS count FROM moderation_events "
                "WHERE server_id=? AND id>?" + filter_sql,
                (server_id, int(marker["last_event_id"]), *filter_values),
            ).fetchone()
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {
            "unread_count": int(unread_row["count"] or 0),
            "latest_event_id": latest_event_id,
        }

    def get_moderation_policy_studio(
        self, server_id: str, default_threshold: float = 0.9
    ) -> dict[str, Any]:
        settings = self.connection.execute(
            "SELECT moderation_mode, moderation_threshold FROM server_settings WHERE server_id=?",
            (server_id,),
        ).fetchone()
        mode = str(settings["moderation_mode"] if settings else "enforce")
        if mode not in {"observe", "review", "enforce"}:
            mode = "enforce"
        default = (
            float(settings["moderation_threshold"])
            if settings and settings["moderation_threshold"] is not None
            else float(default_threshold)
        )
        default = max(MIN_MODERATION_THRESHOLD, default)
        rows = self.connection.execute(
            """
            SELECT category, threshold, action, timeout_seconds, updated_by, updated_at
            FROM moderation_category_policies WHERE server_id=? ORDER BY category
            """,
            (server_id,),
        ).fetchall()
        configured = {str(row["category"]): dict(row) for row in rows}
        disabled = set(self.list_disabled_moderation_categories(server_id))
        policies: list[dict[str, Any]] = []
        for category in SUPPORTED_MODERATION_CATEGORIES:
            override = configured.get(category, {})
            policies.append(
                {
                    "category": category,
                    "label": CATEGORY_LABELS[category],
                    "enabled": category not in disabled or any(
                        category == prefix or category.startswith(f"{prefix}/")
                        for prefix in PROTECTED_MODERATION_CATEGORY_PREFIXES
                    ),
                    "protected": any(
                        category == prefix or category.startswith(f"{prefix}/")
                        for prefix in PROTECTED_MODERATION_CATEGORY_PREFIXES
                    ),
                    "threshold": override.get("threshold"),
                    "effective_threshold": max(MIN_MODERATION_THRESHOLD, float(
                        override["threshold"] if override.get("threshold") is not None else default
                    )),
                    "action": (
                        "observe"
                        if category in SUPPORT_ONLY_CATEGORIES
                        else str(override.get("action") or "warn")
                    ),
                    "timeout_seconds": override.get("timeout_seconds"),
                }
            )
        return {"mode": mode, "default_threshold": default, "policies": policies,
                "score_kind": "label_probability_uncalibrated", "minimum_threshold": MIN_MODERATION_THRESHOLD}

    def save_moderation_policy_studio(
        self,
        server_id: str,
        mode: str,
        default_threshold: float,
        policies: list[dict[str, Any]],
        updated_by: str,
    ) -> dict[str, Any]:
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode not in {"observe", "review", "enforce"}:
            raise ValueError("moderation mode must be observe, review, or enforce")
        threshold = float(default_threshold)
        if not MIN_MODERATION_THRESHOLD <= threshold <= 1:
            raise ValueError("default threshold must be between 0 and 1")
        normalized: dict[str, tuple[float | None, str, int | None, bool]] = {}
        for raw in policies:
            category = str(raw.get("category") or "").strip()
            if category not in SUPPORTED_MODERATION_CATEGORIES:
                raise ValueError(f"unsupported moderation category: {category}")
            category_threshold = raw.get("threshold")
            if category_threshold in {None, ""}:
                parsed_threshold = None
            else:
                parsed_threshold = float(category_threshold)
                if not MIN_MODERATION_THRESHOLD <= parsed_threshold <= 1:
                    raise ValueError("category thresholds must be between 0 and 1")
            action = str(raw.get("action") or "warn").strip().lower()
            if action not in {"observe", "review", "delete", "warn", "timeout"}:
                raise ValueError("unsupported moderation policy action")
            timeout_seconds = raw.get("timeout_seconds")
            parsed_timeout = None if timeout_seconds in {None, ""} else int(timeout_seconds)
            if action == "timeout" and (parsed_timeout is None or not 60 <= parsed_timeout <= 2419200):
                raise ValueError("policy timeouts must be between 60 seconds and 28 days")
            if action != "timeout":
                parsed_timeout = None
            protected = any(
                category == prefix or category.startswith(f"{prefix}/")
                for prefix in PROTECTED_MODERATION_CATEGORY_PREFIXES
            )
            if protected:
                action = "observe"
                parsed_timeout = None
            normalized[category] = (
                parsed_threshold,
                action,
                parsed_timeout,
                True if protected else bool(raw.get("enabled", True)),
            )
        now = _utc_now()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                """
                INSERT INTO server_settings(server_id, moderation_mode, moderation_threshold)
                VALUES (?, ?, ?)
                ON CONFLICT(server_id) DO UPDATE SET
                    moderation_mode=excluded.moderation_mode,
                    moderation_threshold=excluded.moderation_threshold
                """,
                (server_id, normalized_mode, threshold),
            )
            self.connection.execute(
                "DELETE FROM moderation_category_policies WHERE server_id=?", (server_id,)
            )
            self.connection.execute(
                "DELETE FROM disabled_moderation_categories WHERE server_id=?", (server_id,)
            )
            self.connection.executemany(
                """
                INSERT INTO moderation_category_policies(
                    server_id, category, threshold, action, timeout_seconds,
                    updated_by, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (server_id, category, values[0], values[1], values[2], updated_by, now)
                    for category, values in normalized.items()
                ),
            )
            self.connection.executemany(
                """
                INSERT INTO disabled_moderation_categories(
                    server_id, category, disabled_by, disabled_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    (server_id, category, updated_by, now)
                    for category, values in normalized.items()
                    if not values[3]
                ),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return self.get_moderation_policy_studio(server_id, threshold)

    def get_onboarding_state(self, server_id: str, user_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            """
            SELECT current_step, completed_at, dismissed_at, updated_at
            FROM dashboard_onboarding WHERE server_id=? AND user_id=?
            """,
            (server_id, user_id),
        ).fetchone()
        if row is None:
            return {
                "current_step": 0,
                "completed": False,
                "completed_at": None,
                "dismissed": False,
                "dismissed_at": None,
            }
        return {
            "current_step": int(row["current_step"]),
            "completed": row["completed_at"] is not None,
            "completed_at": row["completed_at"],
            "dismissed": row["dismissed_at"] is not None,
            "dismissed_at": row["dismissed_at"],
        }

    def save_onboarding_state(
        self,
        server_id: str,
        user_id: str,
        current_step: int,
        *,
        complete: bool = False,
        dismissed: bool = False,
        reopen: bool = False,
    ) -> dict[str, Any]:
        step = max(0, min(int(current_step), 4))
        now = _utc_now()
        self.connection.execute(
            """
            INSERT INTO dashboard_onboarding(
                server_id, user_id, current_step, completed_at, dismissed_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id, user_id) DO UPDATE SET
                current_step=excluded.current_step,
                completed_at=CASE
                    WHEN ?=1 THEN NULL
                    WHEN excluded.completed_at IS NOT NULL THEN excluded.completed_at
                    ELSE dashboard_onboarding.completed_at
                END,
                dismissed_at=CASE
                    WHEN excluded.completed_at IS NOT NULL OR ?=1 THEN NULL
                    WHEN excluded.dismissed_at IS NOT NULL THEN excluded.dismissed_at
                    ELSE dashboard_onboarding.dismissed_at
                END,
                updated_at=excluded.updated_at
            """,
            (
                server_id,
                user_id,
                step,
                now if complete else None,
                now if dismissed and not complete else None,
                now,
                int(reopen),
                int(reopen),
            ),
        )
        self.connection.commit()
        return self.get_onboarding_state(server_id, user_id)

    def get_local_report_settings(self, server_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM local_report_settings WHERE server_id=?", (server_id,)
        ).fetchone()
        if row is None:
            return {
                "enabled": False,
                "channel_id": None,
                "message_id": None,
                "anonymous_allowed": True,
                "dm_reporting_available": True,
            }
        item = dict(row)
        item["enabled"] = bool(item["enabled"])
        item["anonymous_allowed"] = bool(item["anonymous_allowed"])
        item["dm_reporting_available"] = True
        return item

    def save_local_report_settings(
        self,
        server_id: str,
        *,
        enabled: bool,
        channel_id: str | None,
        anonymous_allowed: bool,
        updated_by: str,
    ) -> dict[str, Any]:
        now = _utc_now()
        self.connection.execute(
            """
            INSERT INTO local_report_settings(
                server_id, enabled, channel_id, anonymous_allowed, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                enabled=excluded.enabled,
                channel_id=excluded.channel_id,
                message_id=CASE
                    WHEN excluded.enabled=1
                     AND local_report_settings.channel_id IS excluded.channel_id
                    THEN local_report_settings.message_id
                    ELSE NULL
                END,
                anonymous_allowed=excluded.anonymous_allowed,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (server_id, int(enabled), channel_id, int(anonymous_allowed), updated_by, now),
        )
        self.connection.commit()
        return self.get_local_report_settings(server_id)

    def set_local_report_instruction_message(
        self, server_id: str, channel_id: str, message_id: str
    ) -> bool:
        cursor = self.connection.execute(
            """
            UPDATE local_report_settings SET message_id=?, updated_at=?
            WHERE server_id=? AND enabled=1 AND channel_id=?
            """,
            (message_id, _utc_now(), server_id, channel_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def list_local_report_servers_for_user(self, user_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT settings.server_id, snapshots.server_name, settings.channel_id
            FROM local_report_settings AS settings
            JOIN dashboard_members AS members
              ON members.server_id=settings.server_id AND members.user_id=?
            LEFT JOIN dashboard_server_snapshots AS snapshots
              ON snapshots.server_id=settings.server_id
            WHERE settings.enabled=1
            ORDER BY COALESCE(snapshots.server_name, settings.server_id) COLLATE NOCASE
            """,
            (user_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def create_report_token(
        self,
        token_hash: str,
        server_id: str,
        reporter_id: str,
        expires_at: str,
        *,
        report_scope: str = "global",
    ) -> None:
        if report_scope not in {"global", "local"}:
            raise ValueError("invalid report scope")
        now = _utc_now()
        self.connection.execute(
            "DELETE FROM report_tokens WHERE expires_at<=?", (now,)
        )
        self.connection.execute(
            """
            INSERT INTO report_tokens(
                token_hash, server_id, reporter_id, report_scope, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (token_hash, server_id, reporter_id, report_scope, expires_at, now),
        )
        self.connection.commit()

    def get_report_token(
        self, token_hash: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT server_id, reporter_id, report_scope, captcha_hash, captcha_salt 
            FROM report_tokens
            WHERE token_hash=? AND expires_at>?
            """,
            (token_hash, _utc_now()),
        ).fetchone()
        return dict(row) if row else None

    def claim_report_token(self, token_hash: str) -> dict[str, Any] | None:
        """Atomically claim a live one-use report token for submission."""
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT * FROM report_tokens WHERE token_hash=? AND expires_at>?",
                (token_hash, _utc_now()),
            ).fetchone()
            if row is None:
                self.connection.rollback()
                return None
            cursor = self.connection.execute(
                "DELETE FROM report_tokens WHERE token_hash=? AND expires_at>?",
                (token_hash, _utc_now()),
            )
            if not cursor.rowcount:
                self.connection.rollback()
                return None
            self.connection.commit()
            return dict(row)
        except Exception:
            self.connection.rollback()
            raise

    def restore_report_token(self, token: dict[str, Any]) -> bool:
        """Restore an exact claimed token after a failed report delivery."""
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO report_tokens(
                token_hash, server_id, reporter_id, report_scope,
                captcha_hash, captcha_salt, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token["token_hash"],
                token["server_id"],
                token["reporter_id"],
                token.get("report_scope") or "global",
                token.get("captcha_hash"),
                token.get("captcha_salt"),
                token["expires_at"],
                token["created_at"],
            ),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def get_report_delivery_context(
        self, server_id: str, reporter_id: str, target_user_id: str
    ) -> dict[str, str | None]:
        """Return human-readable identities for a report webhook."""
        server = self.connection.execute(
            "SELECT server_name FROM dashboard_server_snapshots WHERE server_id=?",
            (server_id,),
        ).fetchone()
        reporter = self.get_recorded_user_identity(reporter_id, server_id)
        target = self.get_recorded_user_identity(target_user_id, server_id)
        return {
            "server_name": server["server_name"] if server else None,
            "reporter_username": reporter["full_username"] if reporter else None,
            "target_username": target["full_username"] if target else None,
        }


    def consume_report_token(self, token_hash: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM report_tokens WHERE token_hash=?", (token_hash,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def create_user_report(
        self,
        server_id: str,
        reporter_id: str,
        target_user_id: str,
        reason: str,
        evidence: str | None,
        network_risk: dict[str, Any] | None = None,
        *,
        report_scope: str = "global",
        anonymous: bool = False,
        receipt_token_hash: str | None = None,
        subject_type: str = "user",
        subject_text: str | None = None,
        reported_channel_id: str | None = None,
        reported_message_id: str | None = None,
    ) -> int:
        if report_scope not in {"global", "local"}:
            raise ValueError("invalid report scope")
        if subject_type not in {"user", "message", "channel", "server", "other"}:
            raise ValueError("invalid report subject type")
        created_at = _utc_now()
        reference_id = self._new_report_reference_id(server_id)
        receipt_expires_at = (
            datetime.now(timezone.utc) + timedelta(days=90)
        ).isoformat(timespec="seconds") if receipt_token_hash else None
        cursor = self.connection.execute(
            """
            INSERT INTO user_reports(
                reference_id, server_id, reporter_id, target_user_id, reason, evidence,
                network_risk_json, report_scope, anonymous, receipt_token_hash,
                receipt_expires_at, subject_type, subject_text,
                reported_channel_id, reported_message_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reference_id, server_id, reporter_id, target_user_id, reason, evidence,
                json.dumps(network_risk or {}, separators=(",", ":"), sort_keys=True),
                report_scope, int(anonymous), receipt_token_hash,
                receipt_expires_at, subject_type, subject_text,
                reported_channel_id, reported_message_id, created_at,
            ),
        )
        report_id = int(cursor.lastrowid)
        if report_scope == "local":
            self.connection.execute(
                """
                INSERT INTO moderation_events(
                    server_id, event_type, user_id, actor_id, details_json, created_at
                ) VALUES (?, 'server_report_submitted', ?, ?, ?, ?)
                """,
                (
                    server_id,
                    target_user_id,
                    None if anonymous else reporter_id,
                    json.dumps(
                        {
                            "report_id": report_id,
                            "report_reference": reference_id,
                            "anonymous": bool(anonymous),
                        },
                        separators=(",", ":"), sort_keys=True,
                    ),
                    _utc_now(),
                ),
            )
        self.connection.commit()
        return report_id

    def add_report_attachment(
        self,
        report_id: int,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO user_report_attachments(
                report_id, filename, content_type, data
            ) VALUES (?, ?, ?, ?)
            """,
            (report_id, filename, content_type, data),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def delete_user_report(self, report_id: int) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM user_reports WHERE id=?", (report_id,)
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def list_owner_reports(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT reports.id, reports.server_id, reports.reporter_id,
                   reports.reference_id,
                   reporter.username AS reporter_username,
                   reports.target_user_id,
                   target.username AS target_username,
                   reports.subject_type, reports.subject_text,
                   reports.reason, reports.evidence, reports.status, reports.review_note,
                   reports.reviewed_by, reports.reviewed_at,
                   reports.reporter_notification_status,
                   reports.reporter_notification_error,
                   reports.reporter_notified_at, reports.created_at
            FROM user_reports AS reports
            LEFT JOIN dashboard_members AS reporter
              ON reporter.server_id=reports.server_id
             AND reporter.user_id=reports.reporter_id
            LEFT JOIN dashboard_members AS target
              ON target.server_id=reports.server_id
             AND target.user_id=reports.target_user_id
            WHERE reports.report_scope='global'
            ORDER BY id DESC
            """
        ).fetchall()
        reports = [dict(row) for row in rows]
        for report in reports:
            context = self.get_report_delivery_context(
                report["server_id"], report["reporter_id"], report["target_user_id"]
            )
            report["reporter_username"] = (
                context["reporter_username"] or report.get("reporter_username")
            )
            report["target_username"] = (
                context["target_username"] or report.get("target_username")
            )
        return reports

    def get_owner_report(self, report_id: int) -> dict[str, Any] | None:
        report = self.connection.execute(
            "SELECT * FROM user_reports WHERE id=? AND report_scope='global'", (report_id,)
        ).fetchone()
        if not report:
            return None
        attachments = self.connection.execute(
            """
            SELECT id, filename, content_type, LENGTH(data) AS size
            FROM user_report_attachments WHERE report_id=?
            """,
            (report_id,)
        ).fetchall()
        
        result = dict(report)
        result["network_risk"] = json.loads(result.pop("network_risk_json") or "{}")
        context = self.get_report_delivery_context(
            result["server_id"], result["reporter_id"], result["target_user_id"]
        )
        result.update(context)
        result["attachments"] = [dict(att) for att in attachments]
        result["messages"] = self.list_report_messages(report_id)
        return result

    def list_local_reports(
        self, server_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT reports.id, reports.reference_id, reports.target_user_id,
                   reports.subject_type, reports.subject_text,
                   target.username AS target_username,
                   reports.reason, reports.status, reports.anonymous,
                   reports.review_note, reports.reviewed_by, reports.reviewed_at,
                   reports.reporter_notification_status,
                   reports.reporter_notification_error,
                   reports.reporter_notified_at,
                   reports.created_at,
                   CASE WHEN reports.anonymous=1 THEN NULL ELSE reports.reporter_id END
                       AS reporter_id,
                   CASE WHEN reports.anonymous=1 THEN NULL ELSE reporter.username END
                       AS reporter_username,
                   EXISTS(
                       SELECT 1 FROM report_messages messages
                       WHERE messages.report_id=reports.id AND messages.request_info=1
                   ) AS information_requested
            FROM user_reports AS reports
            LEFT JOIN dashboard_members AS reporter
              ON reporter.server_id=reports.server_id
             AND reporter.user_id=reports.reporter_id
            LEFT JOIN dashboard_members AS target
              ON target.server_id=reports.server_id
             AND target.user_id=reports.target_user_id
            WHERE reports.server_id=? AND reports.report_scope='local'
            ORDER BY reports.id DESC LIMIT ?
            """,
            (server_id, max(1, min(int(limit), 250))),
        ).fetchall()
        return [
            {
                **dict(row),
                "anonymous": bool(row["anonymous"]),
                "information_requested": bool(row["information_requested"]),
            }
            for row in rows
        ]

    def get_local_report(self, server_id: str, report_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM user_reports
            WHERE server_id=? AND id=? AND report_scope='local'
            """,
            (server_id, report_id),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["anonymous"] = bool(result["anonymous"])
        result["network_risk"] = json.loads(result.pop("network_risk_json") or "{}")
        context = self.get_report_delivery_context(
            result["server_id"], result["reporter_id"], result["target_user_id"]
        )
        if result["anonymous"]:
            result["reporter_id"] = None
            context["reporter_username"] = None
            result["network_risk"] = {}
        result.update(context)
        result["attachments"] = [
            dict(attachment)
            for attachment in self.connection.execute(
                """
                SELECT id, filename, content_type, LENGTH(data) AS size
                FROM user_report_attachments
                WHERE report_id=? ORDER BY id
                """,
                (report_id,),
            ).fetchall()
        ]
        result["messages"] = self.list_report_messages(report_id)
        if result["anonymous"]:
            for message in result["messages"]:
                if message["sender_type"] == "reporter":
                    message["sender_id"] = None
        result.pop("receipt_token_hash", None)
        return result

    def list_report_messages(self, report_id: int) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT id, sender_type, sender_id, message, request_info, created_at
            FROM report_messages WHERE report_id=? ORDER BY id
            """,
            (report_id,),
        ).fetchall()
        return [
            {**dict(row), "request_info": bool(row["request_info"])} for row in rows
        ]

    def add_report_message(
        self,
        report_id: int,
        sender_type: str,
        sender_id: str | None,
        message: str,
        *,
        request_info: bool = False,
    ) -> int:
        if sender_type not in {"reporter", "moderator", "system"}:
            raise ValueError("invalid report message sender")
        body = str(message or "").strip()
        if not body or len(body) > 4000:
            raise ValueError("report messages must be between 1 and 4000 characters")
        cursor = self.connection.execute(
            """
            INSERT INTO report_messages(
                report_id, sender_type, sender_id, message, request_info, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (report_id, sender_type, sender_id, body, int(request_info), _utc_now()),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def get_report_by_receipt(self, receipt_token_hash: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM user_reports
            WHERE receipt_token_hash=? AND receipt_expires_at>?
            """,
            (receipt_token_hash, _utc_now()),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["anonymous"] = bool(result["anonymous"])
        result["messages"] = self.list_report_messages(int(result["id"]))
        for message in result["messages"]:
            message["sender_id"] = None
        result["attachments"] = [
            dict(attachment)
            for attachment in self.connection.execute(
                """
                SELECT id, filename, content_type, LENGTH(data) AS size
                FROM user_report_attachments
                WHERE report_id=? ORDER BY id
                """,
                (result["id"],),
            ).fetchall()
        ]
        result.pop("network_risk_json", None)
        result.pop("receipt_token_hash", None)
        result.pop("reporter_id", None)
        result.pop("reviewed_by", None)
        return result

    def get_report_for_notification(self, report_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM user_reports WHERE id=?", (report_id,)
        ).fetchone()
        return None if row is None else dict(row)

    def get_report_followup_usage(self, report_id: int) -> dict[str, int]:
        row = self.connection.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM report_messages
               WHERE report_id=? AND sender_type='reporter') AS message_count,
              (SELECT COUNT(*) FROM user_report_attachments
               WHERE report_id=?) AS attachment_count,
              (SELECT COALESCE(SUM(LENGTH(data)), 0) FROM user_report_attachments
               WHERE report_id=?) AS attachment_bytes
            """,
            (report_id, report_id, report_id),
        ).fetchone()
        return {
            "message_count": int(row["message_count"] or 0),
            "attachment_count": int(row["attachment_count"] or 0),
            "attachment_bytes": int(row["attachment_bytes"] or 0),
        }


    def review_local_report(
        self,
        server_id: str,
        report_id: int,
        status: str,
        review_note: str,
        reviewed_by: str,
    ) -> int | None:
        if status not in {"resolved", "dismissed"}:
            raise ValueError("invalid report status")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                """
                SELECT reporter_id FROM user_reports
                WHERE id=? AND server_id=? AND report_scope='local' AND status='pending'
                """,
                (report_id, server_id),
            ).fetchone()
            if row is None:
                self.connection.rollback()
                return None
            receipt_extension = (
                datetime.now(timezone.utc) + timedelta(days=30)
            ).isoformat(timespec="seconds")
            cursor = self.connection.execute(
                """
                UPDATE user_reports SET status=?, review_note=?, reviewed_by=?, reviewed_at=?,
                    reporter_notification_status='pending',
                    reporter_notification_error=NULL, reporter_notified_at=NULL,
                    receipt_expires_at=CASE
                        WHEN receipt_token_hash IS NOT NULL
                         AND (receipt_expires_at IS NULL OR receipt_expires_at<?)
                        THEN ? ELSE receipt_expires_at END
                WHERE id=? AND server_id=? AND report_scope='local' AND status='pending'
                """,
                (
                    status,
                    review_note,
                    reviewed_by,
                    _utc_now(),
                    receipt_extension,
                    receipt_extension,
                    report_id,
                    server_id,
                ),
            )
            if not cursor.rowcount:
                self.connection.rollback()
                return None
            action_id = self.enqueue_dashboard_action(
                server_id,
                "notify_report_outcome",
                reviewed_by,
                {"report_id": report_id},
            )
        except Exception:
            self.connection.rollback()
            raise
        return action_id

    def request_local_report_information(
        self,
        server_id: str,
        report_id: int,
        reviewer_id: str,
        prompt: str,
    ) -> int | None:
        return self._request_report_information(
            report_id,
            reviewer_id,
            prompt,
            report_scope="local",
            server_id=server_id,
        )

    def request_global_report_information(
        self,
        report_id: int,
        reviewer_id: str,
        prompt: str,
    ) -> int | None:
        return self._request_report_information(
            report_id,
            reviewer_id,
            prompt,
            report_scope="global",
        )

    def _request_report_information(
        self,
        report_id: int,
        reviewer_id: str,
        prompt: str,
        *,
        report_scope: str,
        server_id: str | None = None,
    ) -> int | None:
        body = str(prompt or "").strip()
        if not body or len(body) > 4000:
            raise ValueError("report messages must be between 1 and 4000 characters")
        where_server = " AND server_id=?" if server_id is not None else ""
        parameters: tuple[Any, ...] = (
            (report_id, report_scope, server_id)
            if server_id is not None
            else (report_id, report_scope)
        )
        row = self.connection.execute(
            f"""
            SELECT server_id FROM user_reports
            WHERE id=? AND report_scope=? AND status='pending'{where_server}
            """,
            parameters,
        ).fetchone()
        if row is None:
            return None
        now = _utc_now()
        try:
            self.connection.execute(
                """
                INSERT INTO report_messages(
                    report_id, sender_type, sender_id, message, request_info, created_at
                ) VALUES (?, 'moderator', ?, ?, 1, ?)
                """,
                (report_id, reviewer_id, body, now),
            )
            action_cursor = self.connection.execute(
                """
                INSERT INTO dashboard_actions(
                    server_id, action, actor_id, payload_json, created_at, not_before
                ) VALUES (?, 'notify_report_update', ?, ?, ?, NULL)
                """,
                (
                    str(row["server_id"]),
                    reviewer_id,
                    json.dumps(
                        {"report_id": report_id},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return int(action_cursor.lastrowid)

    def get_report_attachment(
        self, attachment_id: int, *, report_id: int | None = None
    ) -> dict[str, Any] | None:
        if report_id is None:
            row = self.connection.execute(
                "SELECT filename, content_type, data FROM user_report_attachments WHERE id=?",
                (attachment_id,),
            ).fetchone()
        else:
            row = self.connection.execute(
                """
                SELECT filename, content_type, data FROM user_report_attachments
                WHERE id=? AND report_id=?
                """,
                (attachment_id, report_id),
            ).fetchone()
        return dict(row) if row else None


    def review_user_report(
        self,
        report_id: int,
        status: str,
        review_note: str,
        reviewed_by: str,
    ) -> int | None:
        """Close a pending report and atomically queue its reporter notification."""
        if status not in {"resolved", "dismissed"}:
            raise ValueError("Invalid report status")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            report = self.connection.execute(
                """
                SELECT server_id, status FROM user_reports
                WHERE id=? AND report_scope='global'
                """,
                (report_id,),
            ).fetchone()
            if report is None:
                self.connection.rollback()
                return None
            if report["status"] != "pending":
                self.connection.rollback()
                raise ValueError(f"This report is already {report['status']}.")
            reviewed_at = _utc_now()
            receipt_extension = (
                datetime.now(timezone.utc) + timedelta(days=30)
            ).isoformat(timespec="seconds")
            cursor = self.connection.execute(
                """
                UPDATE user_reports
                SET status=?, review_note=?, reviewed_by=?, reviewed_at=?,
                    reporter_notification_status='pending',
                    reporter_notification_error=NULL,
                    reporter_notified_at=NULL,
                    receipt_expires_at=CASE
                        WHEN receipt_token_hash IS NOT NULL
                         AND (receipt_expires_at IS NULL OR receipt_expires_at<?)
                        THEN ? ELSE receipt_expires_at END
                WHERE id=? AND report_scope='global' AND status='pending'
                """,
                (
                    status,
                    review_note,
                    reviewed_by,
                    reviewed_at,
                    receipt_extension,
                    receipt_extension,
                    report_id,
                ),
            )
            if not cursor.rowcount:
                self.connection.rollback()
                raise ValueError("This report has already been reviewed.")
            action_id = self.enqueue_dashboard_action(
                report["server_id"],
                "notify_report_outcome",
                reviewed_by,
                {"report_id": report_id},
            )
        except Exception:
            self.connection.rollback()
            raise
        return action_id

    def retry_reporter_notification(
        self, report_id: int, requested_by: str
    ) -> int | None:
        """Atomically queue another DM attempt for a closed, undelivered report."""
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            report = self.connection.execute(
                """
                SELECT server_id, status, reporter_notification_status
                FROM user_reports WHERE id=? AND report_scope='global'
                """,
                (report_id,),
            ).fetchone()
            if report is None:
                self.connection.rollback()
                return None
            if report["status"] not in {"resolved", "dismissed"}:
                self.connection.rollback()
                raise ValueError("This report has not been reviewed.")
            notification_status = str(report["reporter_notification_status"])
            if notification_status == "sent":
                self.connection.rollback()
                raise ValueError("The reporter has already been notified.")
            if notification_status == "pending":
                self.connection.rollback()
                raise ValueError("A reporter notification is already queued.")
            cursor = self.connection.execute(
                """
                UPDATE user_reports
                SET reporter_notification_status='pending',
                    reporter_notification_error=NULL,
                    reporter_notified_at=NULL
                WHERE id=? AND report_scope='global'
                  AND reporter_notification_status IN ('failed', 'not_requested')
                """,
                (report_id,),
            )
            if not cursor.rowcount:
                self.connection.rollback()
                raise ValueError("The reporter notification could not be retried.")
            action_id = self.enqueue_dashboard_action(
                report["server_id"],
                "notify_report_outcome",
                requested_by,
                {"report_id": report_id},
            )
        except Exception:
            self.connection.rollback()
            raise
        return action_id

    def mark_reporter_notification(
        self,
        report_id: int,
        *,
        success: bool,
        error: str | None = None,
    ) -> bool:
        cursor = self.connection.execute(
            """
            UPDATE user_reports
            SET reporter_notification_status=?, reporter_notification_error=?,
                reporter_notified_at=?
            WHERE id=?
            """,
            (
                "sent" if success else "failed",
                None if success else (error or "Direct message could not be delivered."),
                _utc_now() if success else None,
                report_id,
            ),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def record_daily_message(
        self, server_id: str, user_id: str | None = None, stat_date: str | None = None,
        *, channel_id: str | None = None, content: str | None = None,
    ) -> None:
        """Increment a daily community total; legacy identifying arguments are ignored."""
        stat_date = stat_date or datetime.now(timezone.utc).date().isoformat()
        self.connection.execute(
            """INSERT INTO server_daily_stats(server_id, stat_date, message_count)
            VALUES (?, ?, 1) ON CONFLICT(server_id, stat_date) DO UPDATE SET
            message_count=message_count+1""", (server_id, stat_date),
        )
        self.connection.commit()

    def get_activity_insights(
        self, server_id: str | None = None, *, days: int = 7, limit: int = 8
    ) -> dict[str, Any]:
        safe_days = max(1, min(int(days), 30))
        parameters = (f"-{safe_days - 1} days", server_id) if server_id else (f"-{safe_days - 1} days",)
        server_filter = "AND server_id=?" if server_id else ""
        totals = self.connection.execute(
            f"""SELECT COALESCE(SUM(message_count),0) AS messages,
            COALESCE(SUM(new_joins),0) AS joins, COALESCE(SUM(new_leaves),0) AS leaves
            FROM server_daily_stats WHERE date(stat_date)>=date('now', ?) {server_filter}""",
            parameters,
        ).fetchone()
        return {"period_days": safe_days, "messages": int(totals["messages"]),
                "joins": int(totals["joins"]), "leaves": int(totals["leaves"]),
                "net_growth": int(totals["joins"]) - int(totals["leaves"])}


    def get_global_leaderboard(
        self, metric: str = "activity", period: str = "day", *, limit: int = 25
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        if metric == "members":
            rows = self.connection.execute(
                """
                SELECT snapshot.server_id, snapshot.server_name,
                       snapshot.server_icon_url, snapshot.member_count AS value,
                       snapshot.previous_member_count AS previous_value
                FROM dashboard_server_snapshots AS snapshot
                LEFT JOIN server_settings AS settings
                  ON settings.server_id=snapshot.server_id
                WHERE COALESCE(settings.public_stats_enabled, 1)=1
                ORDER BY member_count DESC, server_name COLLATE NOCASE
                """,
            ).fetchall()
            entries = [dict(row) for row in rows]
            previous_order = sorted(
                entries,
                key=lambda item: (-item["previous_value"], item["server_name"].casefold()),
            )
            previous_ranks = {
                item["server_id"]: index + 1 for index, item in enumerate(previous_order)
            }
            for index, item in enumerate(entries):
                item["rank_change"] = previous_ranks[item["server_id"]] - (index + 1)
                item.pop("previous_value", None)
            return entries[:safe_limit]
        days = {"day": 1, "week": 7, "month": 30}.get(period)
        if metric != "activity" or days is None:
            raise ValueError("invalid global leaderboard filter")
        current_rows = self.connection.execute(
            """
            SELECT stats.server_id,
                   COALESCE(snapshot.server_name, stats.server_id) AS server_name,
                   snapshot.server_icon_url,
                   SUM(stats.message_count) AS value
            FROM server_daily_stats AS stats
            LEFT JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=stats.server_id
            LEFT JOIN server_settings AS settings
              ON settings.server_id=stats.server_id
            WHERE date(stats.stat_date) >= date('now', ?)
              AND COALESCE(settings.public_stats_enabled, 1)=1
            GROUP BY stats.server_id
            ORDER BY value DESC, server_name COLLATE NOCASE
            """,
            (f"-{days - 1} days",),
        ).fetchall()
        previous_rows = self.connection.execute(
            """
            SELECT stats.server_id, SUM(stats.message_count) AS value
            FROM server_daily_stats AS stats
            LEFT JOIN server_settings AS settings
              ON settings.server_id=stats.server_id
            WHERE date(stats.stat_date) BETWEEN date('now', ?) AND date('now', ?)
              AND COALESCE(settings.public_stats_enabled, 1)=1
            GROUP BY stats.server_id
            ORDER BY value DESC, stats.server_id
            """,
            (f"-{days * 2 - 1} days", f"-{days} days"),
        ).fetchall()
        previous_ranks = {
            row["server_id"]: index + 1 for index, row in enumerate(previous_rows)
        }
        entries = [dict(row) for row in current_rows]
        for index, item in enumerate(entries):
            old_rank = previous_ranks.get(item["server_id"])
            item["rank_change"] = 0 if old_rank is None else old_rank - (index + 1)
        return entries[:safe_limit]

    def record_daily_member_change(
        self, server_id: str, change: str, stat_date: str | None = None
    ) -> None:
        if change not in {"join", "leave"}:
            raise ValueError("change must be join or leave")
        stat_date = stat_date or datetime.now(timezone.utc).date().isoformat()
        column = "new_joins" if change == "join" else "new_leaves"
        self.connection.execute(
            f"""
            INSERT INTO server_daily_stats(server_id, stat_date, {column})
            VALUES (?, ?, 1)
            ON CONFLICT(server_id, stat_date) DO UPDATE SET
                {column}={column}+1
            """,
            (server_id, stat_date),
        )
        self.connection.commit()

    def update_dashboard_server_identity(
        self,
        server_id: str,
        server_name: str,
        server_icon_url: str | None,
        server_banner_url: str | None,
    ) -> None:
        """Refresh branding without resetting permissions, members or channels."""
        self.connection.execute(
            """
            UPDATE dashboard_server_snapshots
            SET server_name=?, server_icon_url=?, server_banner_url=?, updated_at=?
            WHERE server_id=? AND (
                server_name IS NOT ? OR server_icon_url IS NOT ?
                OR server_banner_url IS NOT ?
            )
            """,
            (server_name, server_icon_url, server_banner_url, _utc_now(),
             server_id, server_name, server_icon_url, server_banner_url),
        )
        self.connection.commit()

    def update_dashboard_server_snapshot(
        self,
        server_id: str,
        server_name: str,
        member_count: int,
        channels: list[tuple[str, str] | tuple[str, str, str | None]],
        roles: list[tuple[str, str] | tuple[str, str, bool | None]] | None = None,
        categories: list[tuple[str, str]] | None = None,
        server_icon_url: str | None = None,
        permission_audit: dict[str, Any] | None = None,
        owner_id: str | None = None,
        bot_joined_at: str | None = None,
        server_banner_url: str | None = None,
    ) -> None:
        effective_permission_audit = permission_audit or {}
        if permission_audit and not permission_audit.get("available", False):
            previous = self.connection.execute(
                "SELECT permission_audit_json FROM dashboard_server_snapshots WHERE server_id=?",
                (server_id,),
            ).fetchone()
            if previous is not None:
                try:
                    previous_audit = json.loads(
                        previous["permission_audit_json"] or "{}"
                    )
                except (TypeError, ValueError):
                    previous_audit = {}
                if previous_audit.get("available", False):
                    effective_permission_audit = previous_audit
        self.connection.execute(
            """
            INSERT INTO dashboard_server_snapshots(
                server_id, server_name, owner_id, server_icon_url, server_banner_url, bot_joined_at,
                member_count, previous_member_count,
                permission_audit_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                server_name=excluded.server_name,
                owner_id=CASE WHEN excluded.owner_id<>'' THEN excluded.owner_id
                              ELSE dashboard_server_snapshots.owner_id END,
                server_icon_url=excluded.server_icon_url,
                server_banner_url=excluded.server_banner_url,
                bot_joined_at=COALESCE(
                    NULLIF(excluded.bot_joined_at, ''),
                    dashboard_server_snapshots.bot_joined_at
                ),
                previous_member_count=dashboard_server_snapshots.member_count,
                member_count=excluded.member_count,
                permission_audit_json=excluded.permission_audit_json,
                updated_at=excluded.updated_at
            """,
            (
                server_id,
                server_name,
                str(owner_id or "").strip(),
                server_icon_url,
                server_banner_url,
                str(bot_joined_at or "").strip() or None,
                member_count,
                member_count,
                json.dumps(effective_permission_audit, separators=(",", ":")),
                _utc_now(),
            ),
        )
        self.connection.execute(
            "DELETE FROM dashboard_channels WHERE server_id=?", (server_id,)
        )
        self.connection.executemany(
            """
            INSERT INTO dashboard_channels(
                server_id, channel_id, channel_name, category_id
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (
                    server_id,
                    channel[0],
                    channel[1],
                    channel[2] if len(channel) == 3 else None,
                )
                for channel in channels
            ),
        )
        self.connection.execute(
            "DELETE FROM dashboard_categories WHERE server_id=?", (server_id,)
        )
        self.connection.executemany(
            """
            INSERT INTO dashboard_categories(
                server_id, category_id, category_name, category_position
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (server_id, category_id, name, position)
                for position, (category_id, name) in enumerate(categories or [])
            ),
        )
        self.connection.execute(
            "DELETE FROM dashboard_roles WHERE server_id=?", (server_id,)
        )
        self.connection.executemany(
            """
            INSERT INTO dashboard_roles(server_id, role_id, role_name, assignable)
            VALUES (?, ?, ?, ?)
            """,
            (
                (
                    server_id,
                    role[0],
                    role[1],
                    None if len(role) < 3 or role[2] is None else int(bool(role[2])),
                )
                for role in (roles or [])
            ),
        )
        self.connection.commit()

    def replace_dashboard_members(
        self, server_id: str, members: list[dict[str, Any]]
    ) -> None:
        """Replace the server member directory while preserving cached banners."""
        members = list(
            {
                str(member["user_id"]): member
                for member in members
                if str(member.get("user_id") or "").strip()
            }.values()
        )
        known_banners = {
            row["user_id"]: row["banner_url"]
            for row in self.connection.execute(
                "SELECT user_id, banner_url FROM dashboard_members WHERE server_id=?",
                (server_id,),
            ).fetchall()
        }
        self.connection.execute(
            "DELETE FROM dashboard_members WHERE server_id=?", (server_id,)
        )
        updated_at = _utc_now()
        self.connection.executemany(
            """
            INSERT INTO dashboard_members(
                server_id, user_id, username, display_name, discriminator,
                avatar_url, banner_url, joined_at, account_created_at,
                roles_json, manage_server, is_bot, online, timed_out_until, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    server_id,
                    member["user_id"],
                    member.get("username") or member["user_id"],
                    member.get("display_name"),
                    member.get("discriminator"),
                    member.get("avatar_url"),
                    member.get("banner_url") or known_banners.get(member["user_id"]),
                    member.get("joined_at"),
                    member.get("account_created_at"),
                    json.dumps(member.get("role_ids") or []),
                    int(bool(member.get("manage_server"))),
                    int(bool(member.get("is_bot"))),
                    int(bool(member.get("online"))),
                    member.get("timed_out_until"),
                    updated_at,
                )
                for member in members
            ),
        )
        for member in members:
            self._record_user_identity(
                member.get("user_id"),
                member.get("username"),
                member.get("discriminator"),
                member.get("display_name"),
            )
        self.connection.commit()

    def update_dashboard_member_banner(
        self, server_id: str, user_id: str, banner_url: str | None
    ) -> None:
        self.connection.execute(
            """
            UPDATE dashboard_members SET banner_url=?, updated_at=?
            WHERE server_id=? AND user_id=?
            """,
            (banner_url, _utc_now(), server_id, user_id),
        )
        self.connection.commit()

    def upsert_dashboard_member(
        self,
        server_id: str,
        member: dict[str, Any],
        *,
        adjust_count_on_insert: bool = False,
    ) -> None:
        existed = None
        if adjust_count_on_insert:
            existed = self.connection.execute(
                """
                SELECT 1 FROM dashboard_members
                WHERE server_id=? AND user_id=?
                """,
                (server_id, member["user_id"]),
            ).fetchone()
        self.connection.execute(
            """
            INSERT INTO dashboard_members(
                server_id, user_id, username, display_name, discriminator,
                avatar_url, banner_url, joined_at, account_created_at,
                roles_json, manage_server, is_bot, online, timed_out_until, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id, user_id) DO UPDATE SET
                username=excluded.username, display_name=excluded.display_name,
                discriminator=excluded.discriminator, avatar_url=excluded.avatar_url,
                joined_at=excluded.joined_at,
                account_created_at=excluded.account_created_at,
                roles_json=excluded.roles_json, manage_server=excluded.manage_server,
                is_bot=excluded.is_bot,
                online=excluded.online, timed_out_until=excluded.timed_out_until,
                updated_at=excluded.updated_at
            """,
            (
                server_id, member["user_id"], member.get("username") or member["user_id"],
                member.get("display_name"), member.get("discriminator"),
                member.get("avatar_url"), member.get("banner_url"), member.get("joined_at"),
                member.get("account_created_at"), json.dumps(member.get("role_ids") or []),
                int(bool(member.get("manage_server"))),
                int(bool(member.get("is_bot"))), int(bool(member.get("online"))),
                member.get("timed_out_until"), _utc_now(),
            ),
        )
        self._record_user_identity(
            member.get("user_id"),
            member.get("username"),
            member.get("discriminator"),
            member.get("display_name"),
        )
        if adjust_count_on_insert and existed is None:
            self.connection.execute(
                """
                UPDATE dashboard_server_snapshots
                SET member_count=member_count + 1, updated_at=?
                WHERE server_id=?
                """,
                (_utc_now(), server_id),
            )
        self.connection.commit()

    def remove_dashboard_member(
        self,
        server_id: str,
        user_id: str,
        *,
        adjust_count_on_delete: bool = False,
    ) -> None:
        cursor = self.connection.execute(
            "DELETE FROM dashboard_members WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        )
        if adjust_count_on_delete and cursor.rowcount == 1:
            self.connection.execute(
                """
                UPDATE dashboard_server_snapshots
                SET member_count=MAX(0, member_count - 1), updated_at=?
                WHERE server_id=?
                """,
                (_utc_now(), server_id),
            )
        self.connection.commit()

    def list_dashboard_members(
        self, server_id: str, *, limit: int | None = None
    ) -> list[dict[str, Any]]:
        query = """
            SELECT m.*,
                   (SELECT COUNT(*) FROM moderation_cases c
                    WHERE c.server_id=m.server_id AND c.user_id=m.user_id) AS case_count
            FROM dashboard_members m
            WHERE m.server_id=? AND m.is_bot=0
            ORDER BY COALESCE(m.display_name, m.username) COLLATE NOCASE
        """
        parameters: tuple[Any, ...] = (server_id,)
        if limit is not None:
            query += " LIMIT ?"
            parameters = (server_id, max(0, limit))
        rows = self.connection.execute(query, parameters).fetchall()
        members: list[dict[str, Any]] = []
        for row in rows:
            member = dict(row)
            member["role_ids"] = json.loads(member.pop("roles_json"))
            member["is_bot"] = bool(member["is_bot"])
            member["online"] = bool(member["online"])
            members.append(member)
        return members

    def get_dashboard_member(
        self, server_id: str, user_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT m.*,
                   (SELECT COUNT(*) FROM moderation_cases c
                    WHERE c.server_id=m.server_id AND c.user_id=m.user_id) AS case_count
            FROM dashboard_members m WHERE m.server_id=? AND m.user_id=?
            """,
            (server_id, user_id),
        ).fetchone()
        if row is None:
            return None
        member = dict(row)
        member["role_ids"] = json.loads(member.pop("roles_json"))
        member["is_bot"] = bool(member["is_bot"])
        member["online"] = bool(member["online"])
        member["cases"] = self.list_dashboard_cases_for_user(
            server_id, user_id, limit=50
        )
        member["active_warning_count"] = self.count_warnings(server_id, user_id)
        # Server moderators receive only their own cases; network history sharing is retired.
        member["server_history"] = []
        return member


    def purge_server_data(self, server_id: str) -> dict[str, int]:
        """Permanently remove every record owned by a departed server.

        Discovering tables by their ``server_id`` column keeps this purge complete
        when new server-scoped features are added. Network-level enforcement records,
        including the server blacklist, are intentionally preserved.
        """
        server_id = str(server_id).strip()
        if not server_id:
            raise ValueError("server_id is required")
        deleted: dict[str, int] = {}
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            tables = self.connection.execute(
                """
                SELECT name FROM sqlite_schema
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
            for table_row in tables:
                table = str(table_row["name"])
                if table == "server_blacklist":
                    continue
                quoted_table = self._privacy_identifier(table)
                columns = {
                    str(row["name"])
                    for row in self.connection.execute(
                        f"PRAGMA table_info({quoted_table})"
                    ).fetchall()
                }
                if "server_id" not in columns:
                    continue
                if table == "dashboard_actions":
                    # The blacklist action is a network-level enforcement audit
                    # record and is also the source polled by the protected owner
                    # and admin dashboards. Preserve it after the server-owned
                    # snapshot and moderation data have been removed.
                    cursor = self.connection.execute(
                        """
                        DELETE FROM dashboard_actions
                        WHERE server_id=? AND action!='blacklist_server'
                        """,
                        (server_id,),
                    )
                else:
                    cursor = self.connection.execute(
                        f"DELETE FROM {quoted_table} WHERE server_id=?", (server_id,)
                    )
                if cursor.rowcount:
                    deleted[table] = cursor.rowcount

            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return deleted


    def reconcile_dashboard_server_snapshots(
        self, active_server_ids: set[str]
    ) -> list[str]:
        """Purge stale servers not present in the bot's Ready payload."""
        known_server_ids = {
            str(row["server_id"])
            for row in self.connection.execute(
                "SELECT server_id FROM dashboard_server_snapshots"
            ).fetchall()
        }
        removed = sorted(known_server_ids - active_server_ids)
        for server_id in removed:
            self.purge_server_data(server_id)
        return removed


    def get_dashboard_server_member_count(self, server_id: str) -> int | None:
        row = self.connection.execute(
            "SELECT member_count FROM dashboard_server_snapshots WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return int(row["member_count"]) if row is not None else None

    def update_dashboard_server_member_count(
        self, server_id: str, member_count: int
    ) -> bool:
        cursor = self.connection.execute(
            """
            UPDATE dashboard_server_snapshots
            SET previous_member_count=member_count,
                member_count=?, updated_at=?
            WHERE server_id=?
            """,
            (max(0, int(member_count)), _utc_now(), server_id),
        )
        self.connection.commit()
        return cursor.rowcount == 1

    def get_dashboard_overview(self, server_id: str) -> dict[str, Any]:
        daily_rows = self.connection.execute(
            """
            SELECT s.stat_date, s.message_count, s.new_joins, s.new_leaves
            FROM server_daily_stats AS s
            WHERE s.server_id=?
              AND s.stat_date>=date('now', '-13 days')
            GROUP BY s.server_id, s.stat_date
            ORDER BY s.stat_date
            """,
            (server_id,),
        ).fetchall()
        snapshot = self.connection.execute(
            """
            SELECT server_name, server_icon_url, member_count,
                   permission_audit_json, updated_at
            FROM dashboard_server_snapshots WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        today = datetime.now(timezone.utc).date().isoformat()
        today_data = next(
            (row for row in daily_rows if row["stat_date"] == today), None
        )
        return {
            "server": {
                "id": server_id,
                "name": snapshot["server_name"] if snapshot else "Stoat server",
                "icon_url": snapshot["server_icon_url"] if snapshot else None,
                "member_count": snapshot["member_count"] if snapshot else 0,
                "updated_at": snapshot["updated_at"] if snapshot else None,
            },
            "permission_audit": (
                json.loads(snapshot["permission_audit_json"] or "{}")
                if snapshot else {}
            ),
            "today": {
                "messages": today_data["message_count"] if today_data else 0,
                "joins": today_data["new_joins"] if today_data else 0,
                "leaves": today_data["new_leaves"] if today_data else 0,
            },
            "daily": [dict(row) for row in daily_rows],
            "insights": self.get_activity_insights(server_id, days=7, limit=8),
        }

    def get_public_dashboard_stats(self) -> dict[str, Any]:
        """Return non-sensitive, aggregate figures for the public website."""
        snapshot = self.connection.execute(
            """
            SELECT COUNT(*) AS server_count,
                   COALESCE(SUM(member_count), 0) AS member_count,
                   MAX(updated_at) AS updated_at
            FROM dashboard_server_snapshots AS snapshot
            LEFT JOIN server_settings AS settings
              ON settings.server_id=snapshot.server_id
            WHERE COALESCE(settings.public_stats_enabled, 1)=1
            """
        ).fetchone()
        cases = self.connection.execute(
            """
            SELECT COUNT(*) AS case_count
            FROM moderation_cases AS cases
            LEFT JOIN server_settings AS settings
              ON settings.server_id=cases.server_id
            WHERE COALESCE(settings.public_stats_enabled, 1)=1
            """
        ).fetchone()
        return {
            "server_count": int(snapshot["server_count"]),
            "member_count": int(snapshot["member_count"]),
            "case_count": int(cases["case_count"]),
            "updated_at": snapshot["updated_at"],
            "top_servers": self.get_public_top_servers(limit=3),
        }

    def get_public_top_servers(self, *, limit: int = 3) -> list[dict[str, Any]]:
        """Rank servers that explicitly passed Discovery review."""
        rows = self.connection.execute(
            """
            SELECT snapshot.server_id, snapshot.server_name,
                   snapshot.server_icon_url, snapshot.member_count AS value,
                   snapshot.permission_audit_json
            FROM dashboard_server_snapshots AS snapshot
            JOIN discovery_applications AS discovery
              ON discovery.server_id=snapshot.server_id
            LEFT JOIN server_settings AS settings
              ON settings.server_id=snapshot.server_id
            WHERE COALESCE(settings.public_stats_enabled, 1)=1
              AND NULLIF(TRIM(snapshot.server_icon_url), '') IS NOT NULL
              AND discovery.status='approved'
              AND COALESCE(discovery.is_revoked, 0)=0
              AND NULLIF(TRIM(discovery.invite_url), '') IS NOT NULL
            ORDER BY snapshot.member_count DESC,
                     snapshot.server_name COLLATE NOCASE
            """
        ).fetchall()
        ranked: list[dict[str, Any]] = []
        for row in rows:
            try:
                permission_audit = json.loads(row["permission_audit_json"] or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(permission_audit, dict):
                continue
            role_permissions = permission_audit.get("permissions", [])
            if not (
                permission_audit.get("available")
                and isinstance(role_permissions, list)
                and role_permissions
                and all(
                    isinstance(permission, dict)
                    and bool(permission.get("granted"))
                    for permission in role_permissions
                )
            ):
                continue
            ranked.append(
                {
                    "server_id": row["server_id"],
                    "server_name": row["server_name"],
                    "server_icon_url": row["server_icon_url"],
                    "value": row["value"],
                    "rank_change": 0,
                }
            )
            if len(ranked) >= max(1, min(limit, 100)):
                break
        return ranked

    @staticmethod
    def _permission_audit_is_complete(permission_audit_json: str | None) -> bool:
        try:
            audit = json.loads(permission_audit_json or "{}")
        except (TypeError, ValueError):
            return False
        permissions = audit.get("permissions", []) if isinstance(audit, dict) else []
        return bool(
            isinstance(audit, dict)
            and audit.get("available")
            and isinstance(permissions, list)
            and permissions
            and all(
                isinstance(permission, dict) and bool(permission.get("granted"))
                for permission in permissions
            )
        )

    @staticmethod
    def validate_discovery_invite(invite_url: str) -> str:
        """Validate public listings against known Stoat invite hosts."""
        invite_url = invite_url.strip()
        if len(invite_url) > 500:
            raise ValueError("The server invite URL must be 500 characters or fewer.")
        parsed = urlparse(invite_url)
        hostname = (parsed.hostname or "").lower()
        valid_host = hostname == "stt.gg" or hostname == "stoat.chat" or hostname.endswith(".stoat.chat")
        if (
            parsed.scheme != "https"
            or not valid_host
            or parsed.username
            or parsed.password
            or not parsed.path.strip("/")
        ):
            raise ValueError("Enter a valid HTTPS Stoat server invite URL.")
        return invite_url

    @staticmethod
    def validate_discovery_tags(tags: list[Any] | None) -> list[str]:
        if tags is None:
            return []
        if not isinstance(tags, list):
            raise ValueError("Discovery tags must be provided as a list.")
        normalized: list[str] = []
        seen: set[str] = set()
        for raw_tag in tags:
            tag = " ".join(str(raw_tag).strip().split())
            if not 2 <= len(tag) <= 24:
                raise ValueError("Each Discovery tag must be between 2 and 24 characters.")
            if not all(character.isalnum() or character in " -&+" for character in tag):
                raise ValueError("Discovery tags may only contain letters, numbers, spaces, &, + and -.")
            key = tag.casefold()
            if key not in seen:
                seen.add(key)
                normalized.append(tag)
        if len(normalized) > 5:
            raise ValueError("A Discovery listing can have a maximum of five tags.")
        return normalized

    def get_discovery_eligibility(self, server_id: str) -> dict[str, Any]:
        """Return the live requirements used for applying and public listing."""
        snapshot = self.connection.execute(
            """
            SELECT server_icon_url, permission_audit_json
            FROM dashboard_server_snapshots WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        requirements = {
            "stoatmod": snapshot is not None,
            "full_permissions": bool(
                snapshot
                and self._permission_audit_is_complete(
                    snapshot["permission_audit_json"]
                )
            ),
            "server_icon": bool(
                snapshot and str(snapshot["server_icon_url"] or "").strip()
            ),
            "global_statistics": bool(
                snapshot and self.get_public_stats_enabled(server_id)
            ),
        }
        return {"eligible": all(requirements.values()), "requirements": requirements}

    def get_discovery_application(self, server_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM discovery_applications WHERE server_id=?",
            (server_id,),
        ).fetchone()
        application = dict(row) if row else None
        if application:
            try:
                application["tags"] = json.loads(
                    application.pop("tags_json", "[]") or "[]"
                )
            except (TypeError, ValueError):
                application["tags"] = []
        if application and application.get("is_revoked"):
            application["status"] = "revoked"
        cooldown_until = None
        if application and application["status"] == "denied" and application["reviewed_at"]:
            reviewed_at = datetime.fromisoformat(application["reviewed_at"])
            cooldown_until = (reviewed_at + timedelta(days=7)).isoformat(timespec="seconds")
        now = datetime.now(timezone.utc)
        cooldown_active = bool(
            cooldown_until and datetime.fromisoformat(cooldown_until) > now
        )
        eligibility = self.get_discovery_eligibility(server_id)
        bump_cooldown_until = None
        if (
            application
            and application["status"] == "approved"
            and application.get("last_bumped_at")
        ):
            next_bump = datetime.fromisoformat(
                str(application["last_bumped_at"])
            ) + timedelta(hours=2)
            if next_bump > now:
                bump_cooldown_until = next_bump.isoformat(timespec="seconds")
        return {
            "application": application,
            "eligibility": eligibility,
            "cooldown_until": cooldown_until,
            "can_apply": bool(
                eligibility["eligible"]
                and not cooldown_active
                and (
                    not application
                    or application["status"] in {"denied", "revoked"}
                )
            ),
            "bump_cooldown_until": bump_cooldown_until,
            "can_bump": bool(
                application
                and application["status"] == "approved"
                and not application.get("is_revoked")
                and eligibility["eligible"]
                and not bump_cooldown_until
            ),
        }

    def submit_discovery_application(
        self, server_id: str, submitted_by: str, description: str,
        information: str, invite_url: str, tags: list[Any] | None = None
    ) -> dict[str, Any]:
        invite_url = self.validate_discovery_invite(invite_url)
        tags = self.validate_discovery_tags(tags)
        state = self.get_discovery_application(server_id)
        if not state["eligibility"]["eligible"]:
            raise ValueError("This server does not currently meet every discovery requirement.")
        current = state["application"]
        if current and current["status"] in {"pending", "approved"}:
            raise ValueError(
                "This server already has a pending or approved discovery application."
            )
        if not state["can_apply"]:
            raise ValueError("This server cannot reapply until its seven-day cooldown ends.")
        now = _utc_now()
        self.connection.execute(
            """
            INSERT INTO discovery_applications(
                server_id, description, information, invite_url, tags_json,
                status, submitted_by,
                submitted_at, reviewed_by, reviewed_at, review_note, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, NULL, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                description=excluded.description,
                information=excluded.information,
                invite_url=excluded.invite_url,
                tags_json=excluded.tags_json,
                status='pending',
                is_revoked=0,
                revoked_by=NULL,
                revoked_at=NULL,
                revocation_note=NULL,
                last_bumped_at=NULL,
                last_bumped_by=NULL,
                submitted_by=excluded.submitted_by,
                submitted_at=excluded.submitted_at,
                reviewed_by=NULL,
                reviewed_at=NULL,
                review_note=NULL,
                updated_at=excluded.updated_at
            """,
            (
                server_id, description, information, invite_url,
                json.dumps(tags, separators=(",", ":")), submitted_by, now, now,
            ),
        )
        self.connection.commit()
        return self.get_discovery_application(server_id)

    def update_discovery_listing(
        self, server_id: str, description: str, information: str,
        invite_url: str, tags: list[Any] | None = None,
        submitted_by: str | None = None,
    ) -> dict[str, Any]:
        invite_url = self.validate_discovery_invite(invite_url)
        tags = self.validate_discovery_tags(tags)
        current = self.connection.execute(
            """
            SELECT description, information, invite_url, tags_json, status
            FROM discovery_applications
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        if current is None:
            raise ValueError("Apply for discovery before saving listing details.")
        tags_json = json.dumps(tags, separators=(",", ":"))
        try:
            current_tags = json.loads(current["tags_json"] or "[]")
        except (TypeError, json.JSONDecodeError):
            current_tags = []
        changed = (
            current["description"] != description
            or current["information"] != information
            or current["invite_url"] != invite_url
            or current_tags != tags
        )
        if not changed:
            return self.get_discovery_application(server_id)
        now = _utc_now()
        if current["status"] == "approved":
            self.connection.execute(
                """
                UPDATE discovery_applications
                SET description=?, information=?, invite_url=?, tags_json=?,
                    status='pending',
                    submitted_by=COALESCE(?, submitted_by),
                    submitted_at=?,
                    reviewed_by=NULL,
                    reviewed_at=NULL,
                    review_note=NULL,
                    last_bumped_at=NULL,
                    last_bumped_by=NULL,
                    updated_at=?
                WHERE server_id=?
                """,
                (
                    description, information, invite_url, tags_json,
                    submitted_by, now, now, server_id,
                ),
            )
        else:
            self.connection.execute(
                """
                UPDATE discovery_applications
                SET description=?, information=?, invite_url=?, tags_json=?,
                    submitted_by=COALESCE(?, submitted_by), updated_at=?
                WHERE server_id=?
                """,
                (
                    description, information, invite_url, tags_json,
                    submitted_by, now, server_id,
                ),
            )
        self.connection.commit()
        return self.get_discovery_application(server_id)

    def review_discovery_application(
        self, server_id: str, decision: str, reviewed_by: str, note: str = ""
    ) -> dict[str, Any]:
        if decision not in {"approved", "denied"}:
            raise ValueError("Decision must be approved or denied.")
        current = self.connection.execute(
            "SELECT status, invite_url, is_revoked FROM discovery_applications WHERE server_id=?",
            (server_id,),
        ).fetchone()
        if current is None:
            raise ValueError("Discovery application not found.")
        if current["status"] != "pending" or current["is_revoked"]:
            raise ValueError("Only pending discovery applications can be reviewed.")
        if decision == "approved":
            self.validate_discovery_invite(current["invite_url"])
            if not self.get_discovery_eligibility(server_id)["eligible"]:
                raise ValueError("This server no longer meets every discovery requirement.")
        now = _utc_now()
        self.connection.execute(
            """
            UPDATE discovery_applications
            SET status=?, reviewed_by=?, reviewed_at=?, review_note=?, updated_at=?
            WHERE server_id=?
            """,
            (decision, reviewed_by, now, note or None, now, server_id),
        )
        self.connection.commit()
        return self.get_discovery_application(server_id)

    def revoke_discovery_server(
        self, server_id: str, revoked_by: str, note: str = ""
    ) -> dict[str, Any]:
        current = self.connection.execute(
            """
            SELECT status, is_revoked FROM discovery_applications
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        if current is None or current["status"] != "approved" or current["is_revoked"]:
            raise ValueError("Only an active approved Discovery listing can be revoked.")
        now = _utc_now()
        self.connection.execute(
            """
            UPDATE discovery_applications
            SET is_revoked=1, revoked_by=?, revoked_at=?, revocation_note=?,
                updated_at=?
            WHERE server_id=?
            """,
            (revoked_by, now, note or None, now, server_id),
        )
        self.connection.commit()
        return self.get_discovery_application(server_id)

    def bump_discovery_server(
        self, server_id: str, bumped_by: str
    ) -> dict[str, Any]:
        application = self.connection.execute(
            """
            SELECT status, invite_url, is_revoked, last_bumped_at
            FROM discovery_applications WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        if (
            application is None
            or application["status"] != "approved"
            or application["is_revoked"]
        ):
            raise ValueError("This server does not have an active approved Discovery listing.")
        self.validate_discovery_invite(application["invite_url"])
        if not self.get_discovery_eligibility(server_id)["eligible"]:
            raise ValueError("This server no longer meets every Discovery requirement.")
        now = datetime.now(timezone.utc)
        last_bumped_at = application["last_bumped_at"]
        if last_bumped_at:
            next_bump = datetime.fromisoformat(last_bumped_at) + timedelta(hours=2)
            if next_bump > now:
                return {
                    "bumped": False,
                    "last_bumped_at": last_bumped_at,
                    "next_bump_at": next_bump.isoformat(timespec="seconds"),
                }
        bumped_at = now.isoformat(timespec="seconds")
        next_bump_at = (now + timedelta(hours=2)).isoformat(timespec="seconds")
        cursor = self.connection.execute(
            """
            UPDATE discovery_applications
            SET last_bumped_at=?, last_bumped_by=?
            WHERE server_id=? AND status='approved' AND is_revoked=0
              AND (last_bumped_at IS NULL OR datetime(last_bumped_at) <= datetime('now', '-2 hours'))
            """,
            (bumped_at, bumped_by, server_id),
        )
        if cursor.rowcount == 0:
            refreshed = self.connection.execute(
                "SELECT last_bumped_at FROM discovery_applications WHERE server_id=?",
                (server_id,),
            ).fetchone()
            last = refreshed["last_bumped_at"] if refreshed else bumped_at
            next_bump = datetime.fromisoformat(last) + timedelta(hours=2)
            self.connection.rollback()
            return {
                "bumped": False,
                "last_bumped_at": last,
                "next_bump_at": next_bump.isoformat(timespec="seconds"),
            }
        self.connection.commit()
        return {
            "bumped": True,
            "last_bumped_at": bumped_at,
            "next_bump_at": next_bump_at,
        }

    def list_owner_discovery_applications(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT application.*, snapshot.server_name, snapshot.server_icon_url,
                   snapshot.member_count
            FROM discovery_applications AS application
            LEFT JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=application.server_id
            ORDER BY CASE application.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
                     application.submitted_at DESC
            """
        ).fetchall()
        applications = []
        for row in rows:
            item = dict(row)
            try:
                item["tags"] = json.loads(item.pop("tags_json", "[]") or "[]")
            except (TypeError, ValueError):
                item["tags"] = []
            if item.get("is_revoked"):
                item["status"] = "revoked"
            item["eligibility"] = self.get_discovery_eligibility(item["server_id"])
            applications.append(item)
        return applications

    def list_public_discovery_servers(self) -> list[dict[str, Any]]:
        activity_rows = self.connection.execute(
            """
            SELECT stats.server_id, SUM(stats.message_count) AS value,
                   COALESCE(snapshot.server_name, stats.server_id) AS server_name
            FROM server_daily_stats AS stats
            LEFT JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=stats.server_id
            LEFT JOIN server_settings AS settings
              ON settings.server_id=stats.server_id
            WHERE date(stats.stat_date)=date('now')
              AND COALESCE(settings.public_stats_enabled, 1)=1
            GROUP BY stats.server_id
            ORDER BY value DESC, server_name COLLATE NOCASE
            """
        ).fetchall()
        activity_ranks = {
            row["server_id"]: index + 1
            for index, row in enumerate(activity_rows)
        }
        rows = self.connection.execute(
            """
            SELECT application.server_id, snapshot.server_name,
                   snapshot.server_icon_url, snapshot.server_banner_url, snapshot.member_count,
                   application.description, application.information,
                   application.invite_url,
                   application.tags_json,
                   application.reviewed_at AS approved_at,
                   application.last_bumped_at,
                   application.updated_at,
                   COALESCE((
                       SELECT daily.message_count FROM server_daily_stats AS daily
                       WHERE daily.server_id=application.server_id
                         AND date(daily.stat_date)=date('now')
                   ), 0) AS daily_messages
            FROM discovery_applications AS application
            JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=application.server_id
            WHERE application.status='approved'
              AND application.is_revoked=0
              AND application.invite_url<>''
            ORDER BY application.last_bumped_at IS NULL,
                     application.last_bumped_at DESC,
                     snapshot.member_count DESC,
                     snapshot.server_name COLLATE NOCASE
            """
        ).fetchall()
        servers = []
        for row in rows:
            if not self.get_discovery_eligibility(row["server_id"])["eligible"]:
                continue
            server = dict(row)
            try:
                server["tags"] = json.loads(server.pop("tags_json", "[]") or "[]")
            except (TypeError, ValueError):
                server["tags"] = []
            server["global_rank"] = activity_ranks.get(row["server_id"])
            servers.append(server)
        return servers

    def update_system_heartbeat(
        self, service: str, details: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Record a small public-safe liveness heartbeat for a local service."""
        heartbeat = {
            "service": service,
            "updated_at": _utc_now(),
            "details": details or {},
        }
        self.connection.execute(
            """
            INSERT INTO app_metadata(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (f"system_heartbeat:{service}", json.dumps(heartbeat)),
        )
        self.connection.commit()
        return heartbeat

    def get_system_heartbeat(self, service: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT value FROM app_metadata WHERE key=?",
            (f"system_heartbeat:{service}",),
        ).fetchone()
        if row is None:
            return None
        try:
            heartbeat = json.loads(row["value"])
        except (TypeError, json.JSONDecodeError):
            return None
        return heartbeat if isinstance(heartbeat, dict) else None

    def get_owner_dashboard_summary(self) -> dict[str, Any]:
        network = self.connection.execute(
            """
            SELECT COUNT(*) AS server_count,
                   COALESCE(SUM(member_count), 0) AS member_count,
                   MAX(updated_at) AS updated_at
            FROM dashboard_server_snapshots
            """
        ).fetchone()
        cases = self.connection.execute(
            "SELECT COUNT(*) AS case_count FROM moderation_cases"
        ).fetchone()
        appeal_counts = self.connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='submitted' THEN 1 ELSE 0 END) AS pending
            FROM appeals
            WHERE case_kind='moderation'
            """
        ).fetchone()
        global_bans = self.connection.execute(
            "SELECT COUNT(*) AS count FROM global_bans"
        ).fetchone()
        today_activity = self.connection.execute(
            """
            SELECT COALESCE(SUM(message_count), 0) AS messages
            FROM server_daily_stats WHERE date(stat_date)=date('now')
            """
        ).fetchone()
        return {
            "server_count": int(network["server_count"]),
            "member_count": int(network["member_count"]),
            "case_count": int(cases["case_count"]),
            "updated_at": network["updated_at"],
            "appeal_count": int(appeal_counts["total"] or 0),
            "pending_appeals": int(appeal_counts["pending"] or 0),
            "global_bans": int(global_bans["count"] or 0),
            "messages_today": int(today_activity["messages"] or 0),
        }

    def get_owner_notification_counts(
        self, mailbox_address: str = "admin@modstoat.site"
    ) -> dict[str, int]:
        unread = self.connection.execute(
            """
            SELECT COUNT(*) AS count FROM email_messages
            WHERE mailbox_address=? AND direction='inbound'
              AND read_at IS NULL AND deleted_at IS NULL
            """,
            (mailbox_address.casefold(),),
        ).fetchone()
        reports = self.connection.execute(
            "SELECT COUNT(*) AS count FROM user_reports WHERE status='pending'"
        ).fetchone()
        discovery = self.connection.execute(
            """
            SELECT COUNT(*) AS count FROM discovery_applications
            WHERE status='pending' AND is_revoked=0
            """
        ).fetchone()
        ban_requests = self.connection.execute(
            """
            SELECT COUNT(*) AS count FROM global_ban_requests
            WHERE status='pending'
            """
        ).fetchone()
        return {
            "unread_email": int(unread["count"] or 0),
            "pending_reports": int(reports["count"] or 0),
            "pending_discovery": int(discovery["count"] or 0),
            "pending_global_ban_requests": int(ban_requests["count"] or 0),
        }

    @staticmethod
    def _privacy_identifier(name: str) -> str:
        return '"' + name.replace('"', '""') + '"'

    def _privacy_matches(
        self, identifier: str
    ) -> list[tuple[str, list[dict[str, Any]]]]:
        tables = self.connection.execute(
            """
            SELECT name FROM sqlite_schema
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        matches: list[tuple[str, list[dict[str, Any]]]] = []
        seen_rows: dict[str, set[int]] = {}
        for table_row in tables:
            table = str(table_row["name"])
            quoted_table = self._privacy_identifier(table)
            columns = [
                str(row["name"])
                for row in self.connection.execute(
                    f"PRAGMA table_info({quoted_table})"
                ).fetchall()
            ]
            if not columns:
                continue
            predicate = " OR ".join(
                f"instr(COALESCE(CAST({self._privacy_identifier(column)} AS TEXT), ''), ?) > 0"
                for column in columns
            )
            rows = self.connection.execute(
                f"SELECT rowid AS __privacy_rowid__, * FROM {quoted_table} "
                f"WHERE {predicate}",
                (identifier,) * len(columns),
            ).fetchall()
            if rows:
                records = [dict(row) for row in rows]
                matches.append((table, records))
                seen_rows[table] = {
                    int(record["__privacy_rowid__"]) for record in records
                }

        # A case note or evidence row belongs to the data subject's case even
        # when the note itself does not repeat the subject's user ID.
        case_rows = next(
            (records for table, records in matches if table == "moderation_cases"),
            [],
        )
        case_keys = {
            (str(row.get("server_id", "")), str(row.get("reference_id", "")))
            for row in case_rows
            if row.get("reference_id")
        }
        if case_keys:
            related: list[dict[str, Any]] = []
            known = seen_rows.setdefault("moderation_case_entries", set())
            for server_id, reference in case_keys:
                rows = self.connection.execute(
                    """
                    SELECT rowid AS __privacy_rowid__, *
                    FROM moderation_case_entries
                    WHERE server_id=? AND case_reference=?
                    """,
                    (server_id, reference),
                ).fetchall()
                for row in rows:
                    record = dict(row)
                    rowid = int(record["__privacy_rowid__"])
                    if rowid not in known:
                        known.add(rowid)
                        related.append(record)
            if related:
                existing = next(
                    (
                        records
                        for table, records in matches
                        if table == "moderation_case_entries"
                    ),
                    None,
                )
                if existing is None:
                    matches.append(("moderation_case_entries", related))
                else:
                    existing.extend(related)

        def append_related(table: str, rows: list[sqlite3.Row]) -> None:
            if not rows:
                return
            known = seen_rows.setdefault(table, set())
            related_records: list[dict[str, Any]] = []
            for row in rows:
                record = dict(row)
                rowid = int(record["__privacy_rowid__"])
                if rowid in known:
                    continue
                known.add(rowid)
                related_records.append(record)
            if not related_records:
                return
            existing = next(
                (records for name, records in matches if name == table), None
            )
            if existing is None:
                matches.append((table, related_records))
            else:
                existing.extend(related_records)

        application_rows = next((records for table, records in matches if table == "join_applications"), [])
        application_ids = [row["id"] for row in application_rows]
        if application_ids:
            placeholders = ",".join("?" for _ in application_ids)
            append_related("join_application_answers", self.connection.execute(
                "SELECT rowid AS __privacy_rowid__, * FROM join_application_answers "
                f"WHERE application_id IN ({placeholders})", application_ids).fetchall())

        # Attachments often contain no copy of the subject ID, so include them
        # through their parent case entry, report, email, or queued reply.
        case_entry_rows = next(
            (
                records
                for table, records in matches
                if table == "moderation_case_entries"
            ),
            [],
        )
        case_entry_ids = sorted({int(row["id"]) for row in case_entry_rows})
        if case_entry_ids:
            placeholders = ",".join("?" for _ in case_entry_ids)
            append_related(
                "moderation_case_entry_attachments",
                self.connection.execute(
                    "SELECT rowid AS __privacy_rowid__, * "
                    "FROM moderation_case_entry_attachments "
                    f"WHERE entry_id IN ({placeholders})",
                    case_entry_ids,
                ).fetchall(),
            )

        report_rows = next(
            (records for table, records in matches if table == "user_reports"), []
        )
        report_ids = sorted({int(row["id"]) for row in report_rows})
        if report_ids:
            placeholders = ",".join("?" for _ in report_ids)
            append_related(
                "user_report_attachments",
                self.connection.execute(
                    "SELECT rowid AS __privacy_rowid__, * "
                    "FROM user_report_attachments "
                    f"WHERE report_id IN ({placeholders})",
                    report_ids,
                ).fetchall(),
            )

        message_rows = next(
            (records for table, records in matches if table == "email_messages"), []
        )
        message_keys = sorted(
            {str(row["message_key"]) for row in message_rows if row.get("message_key")}
        )
        if message_keys:
            placeholders = ",".join("?" for _ in message_keys)
            append_related(
                "email_attachments",
                self.connection.execute(
                    "SELECT rowid AS __privacy_rowid__, * FROM email_attachments "
                    f"WHERE message_key IN ({placeholders})",
                    message_keys,
                ).fetchall(),
            )
            append_related(
                "email_webhook_deliveries",
                self.connection.execute(
                    "SELECT rowid AS __privacy_rowid__, * FROM email_webhook_deliveries "
                    f"WHERE message_key IN ({placeholders})",
                    message_keys,
                ).fetchall(),
            )

        reply_rows = next(
            (records for table, records in matches if table == "email_reply_queue"), []
        )
        reply_ids = sorted({int(row["id"]) for row in reply_rows})
        if reply_ids:
            placeholders = ",".join("?" for _ in reply_ids)
            append_related(
                "email_attachments",
                self.connection.execute(
                    "SELECT rowid AS __privacy_rowid__, * FROM email_attachments "
                    f"WHERE reply_id IN ({placeholders})",
                    reply_ids,
                ).fetchall(),
            )
        append_related(
            "admin_login_failures",
            self.connection.execute(
                "SELECT rowid AS __privacy_rowid__, * "
                "FROM admin_login_failures WHERE subject_hash=?",
                (admin_login_subject_hash(identifier),),
            ).fetchall(),
        )
        return sorted(matches, key=lambda item: item[0])

    @staticmethod
    def _privacy_export_value(value: Any) -> Any:
        if not isinstance(value, bytes):
            return value
        return {
            "encoding": "base64",
            "size": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
            "content": base64.b64encode(value).decode("ascii"),
        }

    @staticmethod
    def _privacy_retention_reason(table: str, row: dict[str, Any]) -> str | None:
        protected_reason = PRIVACY_ENFORCEMENT_RETENTION_REASONS.get(table)
        if protected_reason:
            return protected_reason
        if table == "dashboard_actions" and row.get("action") == "blacklist_server":
            return (
                "This action documents a network-level server blacklist decision and "
                "its departure result."
            )
        if table == "appeals" and row.get("case_kind") == "global_ban":
            return (
                "This appeal is part of the active global-ban review and must be handled "
                "with that enforcement record."
            )
        if table in {"dashboard_actions", "email_reply_queue"}:
            if str(row.get("status", "")).lower() in PRIVACY_ACTIVE_QUEUE_STATUSES:
                return (
                    "This queued operation is still active; deleting it could interrupt or "
                    "duplicate an in-progress action."
                )
        if table == "global_ban_requests":
            status = str(row.get("status", "")).lower()
            if status == "pending":
                return (
                    "This global-ban request is awaiting an owner decision and must remain "
                    "available in the approval queue."
                )
            if status == "approved":
                return (
                    "This request documents an owner-approved global enforcement decision "
                    "and is retained with its global-ban audit trail."
                )
        return None

    @staticmethod
    def _privacy_ip_addresses(value: Any) -> set[str]:
        found: set[str] = set()

        def inspect(item: Any, key: str = "") -> None:
            if isinstance(item, dict):
                for child_key, child_value in item.items():
                    inspect(child_value, str(child_key))
                return
            if isinstance(item, (list, tuple)):
                for child in item:
                    inspect(child, key)
                return
            if not isinstance(item, str) or "fingerprint" in key.casefold():
                return
            candidates = list(_IPV4_PATTERN.findall(item))
            candidates.extend(_IPV6_CANDIDATE_PATTERN.findall(item))
            if key.casefold() in {"ip", "ip_address", "remote_ip", "client_ip"}:
                candidates.append(item.strip())
            for candidate in candidates:
                try:
                    found.add(str(ipaddress.ip_address(candidate)))
                except ValueError:
                    continue

        inspect(value)
        return found

    def _privacy_identity(self, identifier: str, subject_type: str) -> dict[str, Any]:
        if subject_type == "server":
            row = self.connection.execute(
                "SELECT server_id, server_name, server_icon_url, updated_at "
                "FROM dashboard_server_snapshots WHERE server_id=?",
                (identifier,),
            ).fetchone()
            return {
                "server_id": identifier,
                "name": row["server_name"] if row else None,
                "profile_picture": row["server_icon_url"] if row else None,
                "updated_at": row["updated_at"] if row else None,
            }

        rows = self.connection.execute(
            """
            SELECT server_id, user_id, username, display_name, discriminator,
                   avatar_url, banner_url, joined_at, account_created_at, updated_at
            FROM dashboard_members WHERE user_id=?
            ORDER BY updated_at DESC, server_id
            """,
            (identifier,),
        ).fetchall()
        profiles = []
        for row in rows:
            profile = dict(row)
            username = str(profile.get("username") or "")
            discriminator = str(profile.get("discriminator") or "")
            profile["full_username"] = (
                f"{username}#{discriminator}" if discriminator else username or None
            )
            profile["profile_picture"] = profile.get("avatar_url")
            profiles.append(profile)
        current = profiles[0] if profiles else {}
        recorded = self.connection.execute(
            """
            SELECT username, discriminator, full_username, display_name, updated_at
            FROM user_identities WHERE user_id=?
            """,
            (identifier,),
        ).fetchone()
        return {
            "user_id": identifier,
            "username": current.get("username") or (recorded["username"] if recorded else None),
            "discriminator": current.get("discriminator") or (recorded["discriminator"] if recorded else None),
            "full_username": current.get("full_username") or (recorded["full_username"] if recorded else None),
            "display_name": current.get("display_name") or (recorded["display_name"] if recorded else None),
            "profile_picture": current.get("profile_picture"),
            "banner_url": current.get("banner_url"),
            "updated_at": current.get("updated_at") or (recorded["updated_at"] if recorded else None),
            "profiles": profiles,
        }

    def search_privacy_subjects(
        self, query: str, limit: int = 25
    ) -> list[dict[str, Any]]:
        """Resolve owner privacy searches to exact user or server subjects."""
        search = str(query or "").strip()
        if len(search) < 2:
            return []
        escaped = (
            search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        results: dict[tuple[str, str], dict[str, Any]] = {}

        def add_result(
            subject_type: str,
            identifier: str,
            *,
            matched_on: str,
            rank: int,
            case_reference: str | None = None,
            server_id: str | None = None,
        ) -> None:
            key = (subject_type, identifier)
            existing = results.get(key)
            if existing is None:
                identity = self._privacy_identity(identifier, subject_type)
                if subject_type == "server":
                    title = str(identity.get("name") or "Unknown server")
                    subtitle = identifier
                else:
                    title = str(
                        identity.get("full_username")
                        or identity.get("display_name")
                        or "Unknown username"
                    )
                    subtitle = identifier
                existing = {
                    "subject_type": subject_type,
                    "identifier": identifier,
                    "title": title,
                    "subtitle": subtitle,
                    "profile_picture": identity.get("profile_picture"),
                    "display_name": identity.get("display_name"),
                    "matched_on": [],
                    "case_references": [],
                    "server_ids": [],
                    "_rank": rank,
                }
                results[key] = existing
            existing["_rank"] = min(int(existing["_rank"]), rank)
            if matched_on not in existing["matched_on"]:
                existing["matched_on"].append(matched_on)
            if case_reference and case_reference not in existing["case_references"]:
                existing["case_references"].append(case_reference)
            if server_id and server_id not in existing["server_ids"]:
                existing["server_ids"].append(server_id)

        exact_identifier = search.upper()
        if exact_identifier.isalnum() and 10 <= len(exact_identifier) <= 64:
            server = self.connection.execute(
                "SELECT 1 FROM dashboard_server_snapshots WHERE server_id=?",
                (exact_identifier,),
            ).fetchone()
            add_result(
                "server" if server else "user",
                exact_identifier,
                matched_on="Exact Stoat ID",
                rank=0,
            )

        user_rows = self.connection.execute(
            """
            SELECT user_id FROM user_identities
            WHERE user_id LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR username LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR full_username LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR display_name LIKE ? ESCAPE '\\' COLLATE NOCASE
            UNION
            SELECT user_id FROM dashboard_members
            WHERE user_id LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR username LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR (username || CASE WHEN discriminator IS NOT NULL AND discriminator<>''
                   THEN '#' || discriminator ELSE '' END)
                    LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR display_name LIKE ? ESCAPE '\\' COLLATE NOCASE
            LIMIT ?
            """,
            (pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern, limit),
        ).fetchall()
        for row in user_rows:
            identifier = str(row["user_id"])
            identity = self._privacy_identity(identifier, "user")
            searchable = " ".join(
                str(identity.get(key) or "")
                for key in ("username", "full_username", "display_name")
            ).casefold()
            add_result(
                "user",
                identifier,
                matched_on=(
                    "Username or display name"
                    if search.casefold() in searchable
                    else "Stoat user ID"
                ),
                rank=1,
            )

        case_needle = search.upper()
        if case_needle.startswith("CASE-"):
            case_needle = case_needle[5:]
        case_rows = self.connection.execute(
            """
            SELECT cases.reference_id, cases.user_id, cases.server_id,
                   COALESCE(snapshot.server_name, 'Unknown server') AS server_name
            FROM moderation_cases AS cases
            LEFT JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=cases.server_id
            WHERE cases.reference_id LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR ('CASE-' || cases.reference_id) LIKE ? ESCAPE '\\' COLLATE NOCASE
            ORDER BY CASE WHEN cases.reference_id=? THEN 0 ELSE 1 END, cases.id DESC
            LIMIT ?
            """,
            (f"%{case_needle}%", f"%{search}%", case_needle, limit),
        ).fetchall()
        for row in case_rows:
            reference = f"CASE-{row['reference_id']}"
            add_result(
                "user",
                str(row["user_id"]),
                matched_on=f"{reference} in {row['server_name']}",
                rank=0 if str(row["reference_id"]).upper() == case_needle else 2,
                case_reference=reference,
                server_id=str(row["server_id"]),
            )

        server_rows = self.connection.execute(
            """
            SELECT server_id FROM dashboard_server_snapshots
            WHERE server_id LIKE ? ESCAPE '\\' COLLATE NOCASE
               OR server_name LIKE ? ESCAPE '\\' COLLATE NOCASE
            ORDER BY server_name COLLATE NOCASE LIMIT ?
            """,
            (pattern, pattern, limit),
        ).fetchall()
        for row in server_rows:
            add_result(
                "server",
                str(row["server_id"]),
                matched_on="Server name or ID",
                rank=1,
            )

        ordered = sorted(
            results.values(),
            key=lambda item: (
                int(item["_rank"]),
                str(item["title"]).casefold(),
                str(item["identifier"]),
            ),
        )[: max(1, min(int(limit), 100))]
        for item in ordered:
            item.pop("_rank", None)
        return ordered

    def export_privacy_data(
        self,
        identifier: str,
        subject_type: str,
        *,
        file_matches: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        matches = self._privacy_matches(identifier)
        tables = []
        total_records = 0
        deletable_records = 0
        retained_records = 0
        ip_sources: dict[str, set[str]] = {}
        for table, rows in matches:
            records = []
            table_deletable = 0
            table_retained = 0
            retention_reasons: set[str] = set()
            for row in rows:
                record = {
                    key: self._privacy_export_value(value)
                    for key, value in row.items()
                    if key != "__privacy_rowid__"
                }
                reason = self._privacy_retention_reason(table, row)
                record["_privacy_deletion"] = {
                    "status": "retained" if reason else "eligible",
                    "reason": reason,
                }
                if reason:
                    table_retained += 1
                    retention_reasons.add(reason)
                else:
                    table_deletable += 1
                for address in self._privacy_ip_addresses(record):
                    ip_sources.setdefault(address, set()).add(f"database:{table}")
                records.append(record)
            total_records += len(records)
            deletable_records += table_deletable
            retained_records += table_retained
            tables.append(
                {
                    "table": table,
                    "record_count": len(records),
                    "deletable_count": table_deletable,
                    "retained_count": table_retained,
                    "retention_reasons": sorted(retention_reasons),
                    "records": records,
                }
            )
        files = list(file_matches or [])
        for match in files:
            for address in self._privacy_ip_addresses(match):
                ip_sources.setdefault(address, set()).add(
                    f"file:{match.get('path', 'unknown')}"
                )
        return {
            "export_version": 2,
            "generated_at": _utc_now(),
            "subject_type": subject_type,
            "identifier": identifier,
            "identity": self._privacy_identity(identifier, subject_type),
            "ip_addresses": [
                {"address": address, "sources": sorted(sources)}
                for address, sources in sorted(ip_sources.items())
            ],
            "total_records": total_records,
            "deletable_records": deletable_records,
            "retained_records": retained_records,
            "table_count": len(tables),
            "tables": tables,
            "file_count": len(files),
            "files": files,
            "coverage": {
                "database": "All application tables plus related case, report, and email attachments",
                "files": "Configured logs, text exports, and backup indicators",
                "limitations": [
                    "Raw IP addresses are persistently stored for restricted owner lookup and shown when present in a stored record or searched file.",
                    "Keyed IP fingerprints are non-reversible and are not displayed as IP addresses.",
                    "Backup matches require review under the service backup-retention procedure.",
                ],
            },
        }

    def delete_privacy_data(self, identifier: str) -> dict[str, Any]:
        matches = self._privacy_matches(identifier)
        deleted_tables: list[dict[str, Any]] = []
        retained_tables: list[dict[str, Any]] = []
        credential_action_ids = {
            int(row["delivery_action_id"])
            for table, rows in matches
            if table == "admin_dashboard_accounts"
            for row in rows
            if row.get("delivery_action_id")
        }

        def retention_reason(table: str, row: dict[str, Any]) -> str | None:
            if (
                table == "dashboard_actions"
                and int(row.get("id") or 0) in credential_action_ids
                and row.get("action") == "deliver_admin_credentials"
            ):
                return None
            return self._privacy_retention_reason(table, row)

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            if credential_action_ids:
                placeholders = ",".join("?" for _ in credential_action_ids)
                self.connection.execute(
                    "UPDATE dashboard_actions "
                    "SET status='failed', result_json=?, processed_at=?, "
                    "claimed_at=NULL, claim_token=NULL "
                    f"WHERE id IN ({placeholders}) "
                    "AND action='deliver_admin_credentials' "
                    "AND status IN ('pending', 'processing')",
                    (
                        json.dumps(
                            {"error": "Admin account data was deleted."},
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        _utc_now(),
                        *sorted(credential_action_ids),
                    ),
                )
            for table, rows in matches:
                retained = [
                    row for row in rows
                    if retention_reason(table, row) is not None
                ]
                rows = [
                    row for row in rows
                    if retention_reason(table, row) is None
                ]
                if retained:
                    reasons = sorted(
                        {
                            str(retention_reason(table, row))
                            for row in retained
                        }
                    )
                    retained_tables.append(
                        {
                            "table": table,
                            "record_count": len(retained),
                            "reasons": reasons,
                        }
                    )
                rowids = sorted(
                    {int(row["__privacy_rowid__"]) for row in rows}
                )
                if not rowids:
                    continue
                quoted_table = self._privacy_identifier(table)
                placeholders = ",".join("?" for _ in rowids)
                cursor = self.connection.execute(
                    f"DELETE FROM {quoted_table} WHERE rowid IN ({placeholders})",
                    rowids,
                )
                if cursor.rowcount:
                    deleted_tables.append(
                        {"table": table, "record_count": cursor.rowcount}
                    )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {
            "deleted_records": sum(
                item["record_count"] for item in deleted_tables
            ),
            "tables": deleted_tables,
            "deleted_tables": deleted_tables,
            "retained_records": sum(
                item["record_count"] for item in retained_tables
            ),
            "retained_tables": retained_tables,
            "requires_review": bool(retained_tables),
        }

    def list_owner_servers(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT snapshot.server_id, snapshot.server_name, snapshot.server_icon_url,
                   snapshot.owner_id, snapshot.bot_joined_at, snapshot.member_count,
                   snapshot.permission_audit_json,
                   snapshot.updated_at,
                   (SELECT COUNT(*) FROM dashboard_channels
                    WHERE server_id=snapshot.server_id) AS channel_count,
                   (SELECT COUNT(*) FROM dashboard_roles
                    WHERE server_id=snapshot.server_id) AS role_count,
                   (SELECT COUNT(*) FROM moderation_cases
                    WHERE server_id=snapshot.server_id) AS case_count,
                   (SELECT COUNT(*) FROM appeals
                    WHERE server_id=snapshot.server_id) AS appeal_count
            FROM dashboard_server_snapshots AS snapshot
            ORDER BY snapshot.server_name COLLATE NOCASE
            """
        ).fetchall()
        servers: list[dict[str, Any]] = []
        for row in rows:
            server = dict(row)
            try:
                permission_audit = json.loads(
                    server.pop("permission_audit_json") or "{}"
                )
            except (TypeError, ValueError):
                permission_audit = {}
            role_permissions = [
                permission
                for permission in permission_audit.get("permissions", [])
                if isinstance(permission, dict)
            ]
            server["permission_audit_available"] = bool(
                permission_audit.get("available")
            )
            server["missing_permissions"] = [
                {
                    "name": str(permission.get("name") or ""),
                    "label": str(
                        permission.get("label")
                        or permission.get("name")
                        or "Unknown permission"
                    ),
                    "impact": str(permission.get("impact") or ""),
                }
                for permission in role_permissions
                if not bool(permission.get("granted"))
            ]
            server["has_permissions"] = bool(
                server["permission_audit_available"]
                and role_permissions
                and not server["missing_permissions"]
            )
            owner_identity = self.get_recorded_user_identity(
                str(server.get("owner_id") or ""), row["server_id"]
            )
            server["owner_username"] = (
                owner_identity.get("full_username") if owner_identity else None
            )
            server["owner_display_name"] = (
                owner_identity.get("display_name") if owner_identity else None
            )
            server["settings"] = self.get_dashboard_settings(row["server_id"])
            server["today"] = self.get_dashboard_overview(row["server_id"])["today"]
            servers.append(server)
        return servers

    def list_owner_cases(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT cases.reference_id, cases.server_id,
                   COALESCE(snapshot.server_name, 'Unknown server') AS server_name,
                   snapshot.server_icon_url,
                   cases.user_id, member.username, member.display_name,
                   cases.action, cases.moderator_id, moderator.username AS moderator_username,
                   moderator.display_name AS moderator_display_name, cases.reason,
                   cases.status, cases.created_at,
                   event.details_json AS event_details_json
            FROM moderation_cases AS cases
            LEFT JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=cases.server_id
            LEFT JOIN dashboard_members AS member
              ON member.server_id=cases.server_id AND member.user_id=cases.user_id
            LEFT JOIN dashboard_members AS moderator
              ON moderator.server_id=cases.server_id
             AND moderator.user_id=cases.moderator_id
            LEFT JOIN moderation_events AS event
              ON cases.source_type='event' AND event.id=cases.source_id
             AND event.server_id=cases.server_id
            ORDER BY cases.id DESC
            """
        ).fetchall()
        cases = []
        for row in rows:
            case = dict(row)
            user_identity = self.get_recorded_user_identity(
                case["user_id"], case["server_id"]
            )
            if user_identity is not None:
                case["username"] = user_identity["full_username"]
                case["display_name"] = (
                    case.get("display_name") or user_identity["display_name"]
                )
            if case.get("moderator_id"):
                moderator_identity = self.get_recorded_user_identity(
                    case["moderator_id"], case["server_id"]
                )
                if moderator_identity is not None:
                    case["moderator_username"] = moderator_identity["full_username"]
                    case["moderator_display_name"] = (
                        case.get("moderator_display_name")
                        or moderator_identity["display_name"]
                    )
            event_details_json = case.pop("event_details_json", None)
            event_details = json.loads(event_details_json) if event_details_json else {}
            case["stoatmod_initiated"] = (
                event_details.get("actor_attribution") == "known_bot_action"
                if case["action"] == "kick" else None
            )
            cases.append(case)
        return cases

    def list_owner_appeals(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM appeals WHERE case_kind='moderation' ORDER BY id DESC"
        ).fetchall()
        appeals = []
        for row in rows:
            appeal = self._appeal_details(row)
            snapshot = self.connection.execute(
                """
                SELECT server_name FROM dashboard_server_snapshots
                WHERE server_id=?
                """,
                (row["server_id"],),
            ).fetchone()
            appeal["server_name"] = (
                snapshot["server_name"] if snapshot else "Unknown server"
            )
            appeals.append(appeal)
        return appeals

    def list_owner_global_bans(self) -> list[dict[str, Any]]:
        bans = []
        for record in self.list_global_bans():
            identity = self._privacy_identity(record.user_id, "user")
            bans.append({
                "reference_id": record.reference_id,
                "user_id": record.user_id,
                "reason": record.reason,
                "created_by": record.created_by,
                "created_at": record.created_at,
                "username": identity.get("full_username"),
                "display_name": identity.get("display_name"),
                "profile_picture": identity.get("profile_picture"),
            })
        return bans

    def create_global_ban_request(
        self, user_id: str, reason: str, requested_by: str
    ) -> dict[str, Any]:
        if self.get_global_ban(user_id) is not None:
            raise ValueError("That user is already globally banned.")
        requested_at = _utc_now()
        requester = requested_by.strip()
        requester = requester.casefold() if "@" in requester else requester.upper()
        try:
            cursor = self.connection.execute(
                """
                INSERT INTO global_ban_requests(
                    user_id, reason, requested_by, requested_at
                ) VALUES (?, ?, ?, ?)
                """,
                (user_id, reason, requester, requested_at),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            self.connection.rollback()
            raise ValueError(
                "A global-ban request for that user is already awaiting review."
            ) from exc
        return self.get_global_ban_request(int(cursor.lastrowid)) or {}

    def get_global_ban_request(self, request_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT requests.*, actions.status AS enforcement_status,
                   actions.result_json AS enforcement_result_json,
                   actions.processed_at AS enforcement_processed_at
            FROM global_ban_requests AS requests
            LEFT JOIN dashboard_actions AS actions
              ON actions.id=requests.enforcement_action_id
            WHERE requests.id=?
            """,
            (request_id,),
        ).fetchone()
        return self._global_ban_request_details(row) if row else None

    @staticmethod
    def _global_ban_request_details(row: sqlite3.Row) -> dict[str, Any]:
        request = dict(row)
        raw_result = request.pop("enforcement_result_json", None)
        try:
            result = json.loads(raw_result) if raw_result else {}
        except (TypeError, json.JSONDecodeError):
            result = {}
        request["enforcement_result"] = result if isinstance(result, dict) else {}
        if request["status"] == "pending":
            request["enforcement_status"] = "awaiting_owner"
        elif request["status"] == "denied":
            request["enforcement_status"] = "not_approved"
        elif not request.get("enforcement_status"):
            request["enforcement_status"] = "unavailable"
        return request

    def list_global_ban_requests(
        self, *, requested_by: str | None = None, limit: int = 250
    ) -> list[dict[str, Any]]:
        if requested_by is None:
            rows = self.connection.execute(
                """
                SELECT requests.*, actions.status AS enforcement_status,
                       actions.result_json AS enforcement_result_json,
                       actions.processed_at AS enforcement_processed_at
                FROM global_ban_requests AS requests
                LEFT JOIN dashboard_actions AS actions
                  ON actions.id=requests.enforcement_action_id
                ORDER BY CASE requests.status WHEN 'pending' THEN 0 ELSE 1 END,
                         requests.id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            requester = requested_by.strip()
            requester = requester.casefold() if "@" in requester else requester.upper()
            rows = self.connection.execute(
                """
                SELECT requests.*, actions.status AS enforcement_status,
                       actions.result_json AS enforcement_result_json,
                       actions.processed_at AS enforcement_processed_at
                FROM global_ban_requests AS requests
                LEFT JOIN dashboard_actions AS actions
                  ON actions.id=requests.enforcement_action_id
                WHERE requests.requested_by=?
                ORDER BY CASE requests.status WHEN 'pending' THEN 0 ELSE 1 END,
                         requests.id DESC LIMIT ?
                """,
                (requester, limit),
            ).fetchall()
        return [self._global_ban_request_details(row) for row in rows]

    def retry_global_ban_request_enforcement(
        self, request_id: int
    ) -> dict[str, Any] | None:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            request = self.connection.execute(
                """
                SELECT requests.*, actions.status AS action_status
                FROM global_ban_requests AS requests
                LEFT JOIN dashboard_actions AS actions
                  ON actions.id=requests.enforcement_action_id
                WHERE requests.id=?
                """,
                (request_id,),
            ).fetchone()
            if request is None:
                self.connection.rollback()
                return None
            if request["status"] != "approved" or not request["enforcement_action_id"]:
                self.connection.rollback()
                raise ValueError("Only approved global-ban requests can be retried.")
            if request["action_status"] != "failed":
                self.connection.rollback()
                raise ValueError("Only failed global-ban enforcement can be retried.")
            if self.get_global_ban(str(request["user_id"])) is None:
                self.connection.rollback()
                raise ValueError(
                    "The global-ban record no longer exists and cannot be retried."
                )
            cursor = self.connection.execute(
                """
                UPDATE dashboard_actions
                SET status='pending', result_json=NULL, processed_at=NULL,
                    not_before=NULL, claimed_at=NULL, claim_token=NULL
                WHERE id=? AND action='owner_global_ban' AND status='failed'
                """,
                (request["enforcement_action_id"],),
            )
            if cursor.rowcount != 1:
                self.connection.rollback()
                raise ValueError("Global-ban enforcement is already being retried.")
            self.connection.commit()
        except Exception:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        return self.get_global_ban_request(request_id)

    def review_global_ban_request(
        self,
        request_id: int,
        decision: str,
        reviewed_by: str,
        review_note: str,
        *,
        reference_id: str | None,
        action_server_id: str,
        action_actor_id: str,
    ) -> dict[str, Any] | None:
        if decision not in {"approved", "denied"}:
            raise ValueError("Decision must be approved or denied.")
        if decision == "approved" and not reference_id:
            raise ValueError("A global reference is required for approval.")
        reviewed_at = _utc_now()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            request_row = self.connection.execute(
                "SELECT * FROM global_ban_requests WHERE id=?", (request_id,)
            ).fetchone()
            if request_row is None:
                self.connection.rollback()
                return None
            if request_row["status"] != "pending":
                self.connection.rollback()
                raise ValueError("This global-ban request has already been reviewed.")

            action_id: int | None = None
            resulting_reference: str | None = None
            if decision == "approved":
                existing = self.connection.execute(
                    "SELECT 1 FROM global_bans WHERE user_id=?",
                    (request_row["user_id"],),
                ).fetchone()
                if existing is not None:
                    self.connection.rollback()
                    raise ValueError("That user is already globally banned.")
                created_at = _utc_now()
                self.connection.execute(
                    """
                    INSERT INTO global_bans(
                        reference_id, user_id, reason, created_by, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        reference_id,
                        request_row["user_id"],
                        request_row["reason"],
                        action_actor_id,
                        created_at,
                    ),
                )
                action = self.connection.execute(
                    """
                    INSERT INTO dashboard_actions(
                        server_id, action, actor_id, payload_json, created_at
                    ) VALUES (?, 'owner_global_ban', ?, ?, ?)
                    """,
                    (
                        action_server_id,
                        action_actor_id,
                        json.dumps(
                            {
                                "user_id": request_row["user_id"],
                                "reason": request_row["reason"],
                                "reference_id": reference_id,
                                "requested_by": request_row["requested_by"],
                                "request_id": request_id,
                            },
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        created_at,
                    ),
                )
                action_id = int(action.lastrowid)
                resulting_reference = reference_id

            cursor = self.connection.execute(
                """
                UPDATE global_ban_requests
                SET status=?, reviewed_by=?, reviewed_at=?, review_note=?,
                    global_reference_id=?, enforcement_action_id=?
                WHERE id=? AND status='pending'
                """,
                (
                    decision,
                    reviewed_by,
                    reviewed_at,
                    review_note,
                    resulting_reference,
                    action_id,
                    request_id,
                ),
            )
            if cursor.rowcount != 1:
                self.connection.rollback()
                raise ValueError("This global-ban request has already been reviewed.")
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            self.connection.rollback()
            raise ValueError("The global ban could not be created safely.") from exc
        except Exception:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        return self.get_global_ban_request(request_id)

    def get_owner_global_ban_detail(self, user_id: str) -> dict[str, Any] | None:
        record = self.get_global_ban(user_id)
        if record is None:
            return None
        identity = self._privacy_identity(record.user_id, "user")
        case_rows = self.connection.execute(
            """
            SELECT server_id, reference_id FROM moderation_cases
            WHERE user_id=? ORDER BY id DESC
            """,
            (record.user_id,),
        ).fetchall()
        cases = []
        for case_row in case_rows:
            detail = self.get_moderation_case_detail(
                str(case_row["server_id"]), str(case_row["reference_id"])
            )
            if detail is None:
                continue
            snapshot = self.connection.execute(
                "SELECT server_name, server_icon_url FROM dashboard_server_snapshots WHERE server_id=?",
                (case_row["server_id"],),
            ).fetchone()
            detail["server_name"] = (
                snapshot["server_name"] if snapshot else "Unknown server"
            )
            detail["server_icon_url"] = (
                snapshot["server_icon_url"] if snapshot else None
            )
            cases.append(detail)

        event_rows = self.connection.execute(
            """
            SELECT event.id, event.server_id,
                   COALESCE(snapshot.server_name, 'Unknown server') AS server_name,
                   event.event_type, event.actor_id, event.channel_id,
                   event.message_id, event.details_json, event.created_at
            FROM moderation_events AS event
            LEFT JOIN dashboard_server_snapshots AS snapshot
              ON snapshot.server_id=event.server_id
            WHERE event.user_id=?
              AND (
                lower(event.event_type) LIKE '%global_ban%'
                OR event.event_type IN ('cross_server_ban', 'member_ban')
              )
            ORDER BY event.id DESC LIMIT 250
            """,
            (record.user_id,),
        ).fetchall()
        enforcement_events = []
        for row in event_rows:
            event = dict(row)
            try:
                event["details"] = json.loads(event.pop("details_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                event["details"] = {}
            enforcement_events.append(event)

        warning_records = [
            {
                "reference_id": warning.reference_id,
                "reason": warning.reason,
                "created_by": warning.created_by,
                "created_at": warning.created_at,
            }
            for warning in self.list_global_warnings(record.user_id, limit=250)
        ]
        appeal_rows = self.connection.execute(
            """
            SELECT * FROM appeals
            WHERE user_id=? AND case_kind='global_ban'
            ORDER BY id DESC
            """,
            (record.user_id,),
        ).fetchall()
        return {
            "reference_id": record.reference_id,
            "user_id": record.user_id,
            "reason": record.reason,
            "created_by": record.created_by,
            "created_at": record.created_at,
            "identity": identity,
            "cases": cases,
            "global_warnings": warning_records,
            "enforcement_events": enforcement_events,
            "appeals": [self._appeal_details(row) for row in appeal_rows],
        }

    def get_dashboard_settings(
        self,
        server_id: str,
        default_threshold: float = 0.9,
        spam_defaults: dict[str, int | float] | None = None,
    ) -> dict[str, Any]:
        policy = self.get_warning_policy(server_id)
        channels = self.connection.execute(
            """
            SELECT channel_id, channel_name, category_id FROM dashboard_channels
            WHERE server_id=? ORDER BY channel_name COLLATE NOCASE
            """,
            (server_id,),
        ).fetchall()
        categories = self.connection.execute(
            """
            SELECT category_id, category_name FROM dashboard_categories
            WHERE server_id=? ORDER BY category_position, category_name COLLATE NOCASE
            """,
            (server_id,),
        ).fetchall()
        roles = self.connection.execute(
            """
            SELECT role_id, role_name, assignable FROM dashboard_roles
            WHERE server_id=? ORDER BY role_name COLLATE NOCASE
            """,
            (server_id,),
        ).fetchall()
        exempt_channels = {
            exclusion["target_id"]
            for exclusion in self.list_scope_exclusions(server_id)
            if exclusion["target_type"] == "channel"
        }
        exempt_categories = {
            exclusion["target_id"]
            for exclusion in self.list_scope_exclusions(server_id)
            if exclusion["target_type"] == "category"
        }
        return {
            "locale": self.get_server_locale(server_id),
            "join_protection": self.get_join_protection(server_id),
            "captcha_all_members": self.get_captcha_all_members(server_id),
            "nickname_protection": self.get_nickname_protection(server_id),
            "link_protection": self.get_link_protection(server_id),
            "allow_gifs": self.get_allow_gifs(server_id),
            "join_limits": self.join_limits.settings(server_id),
            "spam_detection": self.get_spam_detection(server_id),
            "spam_settings": self.get_spam_settings(server_id, spam_defaults),
            "spam_defaults": dict(spam_defaults or DEFAULT_SPAM_SETTINGS),
            "image_scanning": self.get_image_scanning(server_id),
            "ai_thinking": self.get_ai_thinking(server_id),
            "moderator_exemption": self.get_moderator_exemption(server_id),
            "public_stats": self.get_public_stats_enabled(server_id),
            "moderation_threshold": self.get_moderation_threshold(
                server_id, default_threshold
            ),
            "moderation_policy": self.get_moderation_policy_studio(
                server_id, default_threshold
            ),
            "warning_expiry_days": self.get_warning_expiry_days(server_id),
            "log_channel_id": self.get_log_channel(server_id),
            "warning_policy": {
                "timeout": policy.timeout_count,
                "kick": policy.kick_count,
                "ban": policy.ban_count,
            },
            "penalty_rules": [
                {
                    "threshold": rule.threshold,
                    "action": rule.action,
                    "duration_seconds": rule.duration_seconds,
                }
                for rule in self.list_penalty_rules(server_id)
            ],
            "auto_roles": self.list_auto_roles(server_id),
            "exempt_channels": sorted(exempt_channels),
            "exempt_categories": sorted(exempt_categories),
            "moderation_categories": list(SUPPORTED_MODERATION_CATEGORIES),
            "disabled_moderation_categories": self.list_disabled_moderation_categories(
                server_id
            ),
            "protected_moderation_categories": [
                category
                for category in SUPPORTED_MODERATION_CATEGORIES
                if any(
                    category == prefix or category.startswith(f"{prefix}/")
                    for prefix in PROTECTED_MODERATION_CATEGORY_PREFIXES
                )
            ],
            "channels": [dict(row) for row in channels],
            "categories": [dict(row) for row in categories],
            "roles": [
                {
                    **dict(row),
                    "assignable": (
                        None if row["assignable"] is None else bool(row["assignable"])
                    ),
                }
                for row in roles
            ],
        }

    def set_server_locale(self, server_id: str, locale: str) -> None:
        if locale not in {"en", "fr", "pt", "es"}:
            raise ValueError("language must be English, French, Portuguese, or Spanish")
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, locale)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET locale=excluded.locale
            """,
            (server_id, locale),
        )
        self.connection.commit()

    def get_server_locale(self, server_id: str) -> str:
        row = self.connection.execute(
            "SELECT locale FROM server_settings WHERE server_id=?", (server_id,)
        ).fetchone()
        if row is None or row["locale"] not in {"en", "fr", "pt", "es"}:
            return "en"
        return str(row["locale"])

    def set_warning_expiry_days(self, server_id: str, days: int | None) -> None:
        if days is not None and days not in {7, 30, 90, 180, 365}:
            raise ValueError("warning expiry must be never, 7, 30, 90, 180, or 365 days")
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, warning_expiry_days)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET warning_expiry_days=excluded.warning_expiry_days
            """,
            (server_id, days),
        )
        self.connection.commit()

    def get_warning_expiry_days(self, server_id: str) -> int | None:
        row = self.connection.execute(
            "SELECT warning_expiry_days FROM server_settings WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return None if row is None else row["warning_expiry_days"]

    def create_appeal_access(
        self,
        code_hash: str,
        user_id: str,
        case_kind: str,
        case_reference: str,
        server_id: str | None = None,
    ) -> int:
        if case_kind != "moderation":
            raise ValueError("only server moderation cases are eligible for appeals")
        now = _utc_now()
        self.connection.execute(
            """
            INSERT INTO appeals(
                code_hash, server_id, user_id, case_kind, case_reference,
                status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'eligible', ?)
            ON CONFLICT(case_kind, case_reference) DO UPDATE SET
                code_hash=excluded.code_hash,
                server_id=excluded.server_id,
                user_id=excluded.user_id
            """,
            (code_hash, server_id, user_id, case_kind, case_reference.upper(), now),
        )
        row = self.connection.execute(
            "SELECT id FROM appeals WHERE case_kind=? AND case_reference=?",
            (case_kind, case_reference.upper()),
        ).fetchone()
        self.connection.commit()
        return int(row["id"])

    def get_appeal_by_credentials(
        self, code_hash: str, user_id: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM appeals
            WHERE code_hash=? AND user_id=? AND case_kind='moderation'
            """,
            (code_hash, user_id),
        ).fetchone()
        return None if row is None else self._appeal_details(row)

    def get_appeal(self, appeal_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM appeals WHERE id=?", (appeal_id,)
        ).fetchone()
        return None if row is None else self._appeal_details(row)

    def get_server_appeal_by_case(
        self, server_id: str, case_reference: str
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM appeals
            WHERE server_id=? AND case_kind='moderation' AND case_reference=?
            """,
            (server_id, case_reference.upper()),
        ).fetchone()
        return None if row is None else self._appeal_details(row)

    def _appeal_details(self, row: sqlite3.Row) -> dict[str, Any]:
        appeal = dict(row)
        appeal.pop("code_hash", None)
        evidence: dict[str, Any] = {}
        if row["case_kind"] == "global_ban":
            record = self.get_global_ban(row["case_reference"])
            if record is not None:
                evidence = {
                    "case_id": record.reference_id,
                    "action": "global_ban",
                    "moderator_reason": record.reason,
                    "moderator_id": record.created_by,
                    "created_at": record.created_at,
                    "original_message": None,
                    "detected_thresholds": {},
                }
        else:
            case_row = self.connection.execute(
                "SELECT * FROM moderation_cases WHERE server_id=? AND reference_id=?",
                (row["server_id"], row["case_reference"]),
            ).fetchone()
            if case_row is not None:
                evidence = {
                    "case_id": case_row["reference_id"],
                    "action": case_row["action"],
                    "moderator_reason": case_row["reason"],
                    "moderator_id": case_row["moderator_id"],
                    "created_at": case_row["created_at"],
                    "original_message": None,
                    "detected_thresholds": {},
                    "entries": self._appeal_case_evidence_entries(
                        str(row["server_id"]), str(row["case_reference"])
                    ),
                }
                if case_row["source_type"] == "warning":
                    warning = self.connection.execute(
                        "SELECT * FROM warnings WHERE id=?", (case_row["source_id"],)
                    ).fetchone()
                    if warning is not None:
                        evidence["original_message"] = warning["original_content"]
                        evidence["detected_thresholds"] = {
                            "categories": json.loads(warning["categories_json"]),
                            "scores": json.loads(warning["scores_json"]),
                        }
                else:
                    event = self.connection.execute(
                        "SELECT details_json FROM moderation_events WHERE id=?",
                        (case_row["source_id"],),
                    ).fetchone()
                    if event is not None:
                        details = json.loads(event["details_json"])
                        evidence["original_message"] = details.get("original_content")
                        evidence["detected_thresholds"] = {
                            "categories": details.get("categories", []),
                            "scores": details.get("scores", {}),
                        }
                        warning_id = details.get("warning_id")
                        if warning_id is not None:
                            warning = self.connection.execute(
                                "SELECT original_content FROM warnings WHERE id=?",
                                (warning_id,),
                            ).fetchone()
                            if warning is not None:
                                evidence["original_message"] = warning["original_content"]
        appeal["evidence"] = evidence
        appeal["privacy"] = self.appeal_privacy.public_status(appeal)
        message_rows = self.connection.execute(
            """
            SELECT id, sender_type, sender_id, message, request_info, created_at
            FROM appeal_messages WHERE appeal_id=? ORDER BY id
            """,
            (row["id"],),
        ).fetchall()
        messages: list[dict[str, Any]] = []
        for message_row in message_rows:
            message = dict(message_row)
            message["request_info"] = bool(message["request_info"])
            message["attachments"] = [
                dict(attachment)
                for attachment in self.connection.execute(
                    """
                    SELECT id, filename, content_type, size, created_at
                    FROM appeal_message_attachments WHERE message_id=? ORDER BY id
                    """,
                    (message["id"],),
                ).fetchall()
            ]
            messages.append(message)
        appeal["messages"] = messages
        last_request = next(
            (
                index for index in range(len(messages) - 1, -1, -1)
                if messages[index]["sender_type"] == "moderator"
                and messages[index]["request_info"]
            ),
            -1,
        )
        appeal["needs_info"] = bool(
            appeal["status"] == "submitted"
            and last_request >= 0
            and not any(
                message["sender_type"] == "appellant"
                for message in messages[last_request + 1 :]
            )
        )
        return appeal

    def _appeal_case_evidence_entries(
        self, server_id: str, case_reference: str
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT id, content, created_at
            FROM moderation_case_entries
            WHERE server_id=? AND case_reference=? AND entry_type='evidence'
            ORDER BY id
            """,
            (server_id, case_reference.upper()),
        ).fetchall()
        entries = [dict(row) for row in rows]
        attachments_by_entry: dict[int, list[dict[str, Any]]] = {
            int(entry["id"]): [] for entry in entries
        }
        if attachments_by_entry:
            placeholders = ",".join("?" for _ in attachments_by_entry)
            attachments = self.connection.execute(
                f"""
                SELECT id, entry_id, filename, content_type, size, created_at
                FROM moderation_case_entry_attachments
                WHERE entry_id IN ({placeholders}) ORDER BY id
                """,
                tuple(attachments_by_entry),
            ).fetchall()
            for attachment in attachments:
                item = dict(attachment)
                entry_id = int(item.pop("entry_id"))
                attachments_by_entry[entry_id].append(item)
        for entry in entries:
            entry["attachments"] = attachments_by_entry[int(entry["id"])]
        return entries

    def get_appeal_evidence_attachment(
        self, code_hash: str, user_id: str, attachment_id: int
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        row = self.connection.execute(
            """
            SELECT attachment.filename, attachment.content_type,
                   attachment.data, attachment.size
            FROM appeals AS appeal
            JOIN moderation_case_entries AS entry
              ON entry.server_id=appeal.server_id
             AND entry.case_reference=appeal.case_reference
             AND entry.entry_type='evidence'
            JOIN moderation_case_entry_attachments AS attachment
              ON attachment.entry_id=entry.id
            WHERE appeal.code_hash=? AND appeal.user_id=?
              AND appeal.case_kind='moderation' AND attachment.id=?
            """,
            (code_hash, user_id, attachment_id),
        ).fetchone()
        return None if row is None else dict(row)

    def submit_appeal(
        self, appeal_id: int, user_id: str, statement: str, *,
        privacy_version: str | None = None, ai_improvement_opt_in: bool = False,
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        self.connection.execute("BEGIN IMMEDIATE")
        if privacy_version is not None:
            current = self.get_appeal(appeal_id)
            if current is None or current['user_id'] != user_id or current['status'] != 'eligible':
                self.connection.rollback()
                return None
            try:
                self.appeal_privacy.record(current, privacy_version, ai_improvement_opt_in)
            except ValueError:
                self.connection.rollback()
                raise
        cursor = self.connection.execute(
            """
            UPDATE appeals SET status='submitted', statement=?, submitted_at=?
            WHERE id=? AND user_id=? AND case_kind='moderation'
              AND status='eligible'
            """,
            (statement, _utc_now(), appeal_id, user_id),
        )
        if cursor.rowcount:
            self.connection.execute(
                """
                INSERT INTO appeal_messages(
                    appeal_id, sender_type, sender_id, message, request_info, created_at
                ) VALUES (?, 'appellant', ?, ?, 0, ?)
                """,
                (appeal_id, user_id, statement, _utc_now()),
            )
        if not cursor.rowcount:
            self.connection.rollback()
            return None
        self.connection.commit()
        return self.get_appeal(appeal_id) if cursor.rowcount else None

    def add_appeal_message(
        self,
        appeal_id: int,
        sender_type: str,
        sender_id: str | None,
        message: str,
        *,
        request_info: bool = False,
        privacy_version: str | None = None,
        ai_improvement_opt_in: bool | None = None,
    ) -> int:
        if sender_type not in {"appellant", "moderator", "system"}:
            raise ValueError("invalid appeal message sender")
        body = str(message or "").strip()
        if not body or len(body) > 4000:
            raise ValueError("appeal messages must be between 1 and 4000 characters")
        self.appeal_privacy.prune()
        self.connection.execute("BEGIN IMMEDIATE")
        current = self.get_appeal(appeal_id)
        if current is None or current['status'] != 'submitted':
            self.connection.rollback()
            raise ValueError('Only an open appeal accepts a response.')
        if privacy_version is not None:
            if current is None or current['user_id'] != sender_id or current['status'] != 'submitted' or sender_type != 'appellant':
                self.connection.rollback()
                raise ValueError('Only an open appeal accepts a response from its appellant.')
            try:
                self.appeal_privacy.record(current, privacy_version, ai_improvement_opt_in)
            except ValueError:
                self.connection.rollback()
                raise
        cursor = self.connection.execute(
            """
            INSERT INTO appeal_messages(
                appeal_id, sender_type, sender_id, message, request_info, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (appeal_id, sender_type, sender_id, body, int(request_info), _utc_now()),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def add_appeal_message_attachment(
        self,
        message_id: int,
        filename: str,
        content_type: str,
        data: bytes,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO appeal_message_attachments(
                message_id, filename, content_type, data, size, created_at
            ) SELECT ?, ?, ?, ?, ?, ?
              WHERE EXISTS (
                SELECT 1 FROM appeal_messages m JOIN appeals a ON a.id=m.appeal_id
                WHERE m.id=? AND a.status='submitted'
              )
            """,
            (message_id, filename, content_type, data, len(data), _utc_now(), message_id),
        )
        self.connection.commit()
        if not cursor.rowcount:
            raise ValueError("Only open appeals accept attachments.")
        return int(cursor.lastrowid)

    def get_latest_appeal_message_id(
        self, appeal_id: int, sender_type: str
    ) -> int | None:
        row = self.connection.execute(
            """
            SELECT id FROM appeal_messages
            WHERE appeal_id=? AND sender_type=? ORDER BY id DESC LIMIT 1
            """,
            (appeal_id, sender_type),
        ).fetchone()
        return None if row is None else int(row["id"])

    def get_appeal_message_attachment(
        self,
        attachment_id: int,
        *,
        appeal_id: int | None = None,
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        query = """
            SELECT attachment.filename, attachment.content_type,
                   attachment.data, attachment.size
            FROM appeal_message_attachments AS attachment
            JOIN appeal_messages AS message ON message.id=attachment.message_id
            WHERE attachment.id=?
        """
        values: list[Any] = [attachment_id]
        if appeal_id is not None:
            query += " AND message.appeal_id=?"
            values.append(appeal_id)
        row = self.connection.execute(query, values).fetchone()
        return None if row is None else dict(row)

    def request_appeal_information(
        self,
        server_id: str,
        appeal_id: int,
        reviewer_id: str,
        prompt: str,
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        row = self.connection.execute(
            """
            SELECT id FROM appeals WHERE id=? AND server_id=?
              AND case_kind='moderation' AND status='submitted'
            """,
            (appeal_id, server_id),
        ).fetchone()
        if row is None:
            return None
        self.add_appeal_message(
            appeal_id, "moderator", reviewer_id, prompt, request_info=True
        )
        self.enqueue_dashboard_action(
            server_id,
            "notify_appeal_update",
            reviewer_id,
            {"appeal_id": appeal_id},
        )
        return self.get_appeal(appeal_id)

    def list_dashboard_appeals(
        self, server_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        self.appeal_privacy.prune()
        rows = self.connection.execute(
            """
            SELECT * FROM appeals
            WHERE server_id=? AND case_kind='moderation'
            ORDER BY CASE status WHEN 'submitted' THEN 0 ELSE 1 END,
                     CASE WHEN status='submitted' THEN submitted_at END DESC,
                     id DESC LIMIT ?
            """,
            (server_id, limit),
        ).fetchall()
        return [self._appeal_details(row) for row in rows]

    def review_appeal(
        self,
        appeal_id: int,
        reviewer_id: str,
        decision: str,
        response: str,
    ) -> dict[str, Any] | None:
        if decision not in {"approved", "denied"}:
            raise ValueError("decision must be approved or denied")
        self.appeal_privacy.prune()
        self.connection.execute("BEGIN IMMEDIATE")
        cursor = self.connection.execute(
            """
            UPDATE appeals SET status=?, reviewer_id=?, reviewer_response=?, reviewed_at=?
            WHERE id=? AND case_kind='moderation' AND status='submitted'
            """,
            (decision, reviewer_id, response, _utc_now(), appeal_id),
        )
        if cursor.rowcount:
            self.connection.execute(
                """
                INSERT INTO appeal_messages(
                    appeal_id, sender_type, sender_id, message, request_info, created_at
                ) VALUES (?, 'moderator', ?, ?, 0, ?)
                """,
                (appeal_id, reviewer_id, response, _utc_now()),
            )
            closed = self.get_appeal(appeal_id)
            assert closed is not None
            self.appeal_privacy.purge_case_content(closed, now=datetime.now(timezone.utc))
        self.connection.commit()
        self.appeal_privacy.checkpoint()
        return self.get_appeal(appeal_id) if cursor.rowcount else None

    def list_dashboard_cases(
        self, server_id: str, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT c.reference_id, c.user_id, c.action, c.moderator_id, c.reason,
                   c.status, c.created_at,
                   m.username, m.display_name,
                   mod.username AS moderator_username, mod.display_name AS moderator_display_name,
                   w.scores_json, e.details_json AS event_details_json
            FROM moderation_cases c
            LEFT JOIN dashboard_members m ON m.server_id = c.server_id AND m.user_id = c.user_id
            LEFT JOIN dashboard_members mod ON mod.server_id = c.server_id AND mod.user_id = c.moderator_id
            LEFT JOIN warnings w ON c.source_type = 'warning' AND w.id = c.source_id AND w.server_id = c.server_id
            LEFT JOIN moderation_events e ON c.source_type = 'event' AND e.id = c.source_id AND e.server_id = c.server_id
            WHERE c.server_id=?
            ORDER BY c.id DESC LIMIT ?
            """,
            (server_id, limit),
        ).fetchall()
        
        result = []
        for row in rows:
            d = dict(row)
            user_identity = self.get_recorded_user_identity(d["user_id"], server_id)
            if user_identity is not None:
                d["username"] = user_identity["full_username"]
                d["display_name"] = d.get("display_name") or user_identity["display_name"]
            if d.get("moderator_id"):
                moderator_identity = self.get_recorded_user_identity(
                    d["moderator_id"], server_id
                )
                if moderator_identity is not None:
                    d["moderator_username"] = moderator_identity["full_username"]
                    d["moderator_display_name"] = (
                        d.get("moderator_display_name")
                        or moderator_identity["display_name"]
                    )
            scores_json = d.pop("scores_json", None)
            event_details_json = d.pop("event_details_json", None)
            d["scores"] = json.loads(scores_json) if scores_json else None
            event_details = json.loads(event_details_json) if event_details_json else {}
            d["stoatmod_initiated"] = (
                event_details.get("actor_attribution") == "known_bot_action"
                if d["action"] == "kick" else None
            )
            result.append(d)
        return result

    def list_dashboard_cases_for_user(
        self, server_id: str, user_id: str, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT c.reference_id, c.user_id, c.action, c.moderator_id, c.reason,
                   c.status, c.created_at,
                   m.username, m.display_name,
                   mod.username AS moderator_username, mod.display_name AS moderator_display_name,
                   w.scores_json, e.details_json AS event_details_json
            FROM moderation_cases c
            LEFT JOIN dashboard_members m ON m.server_id = c.server_id AND m.user_id = c.user_id
            LEFT JOIN dashboard_members mod ON mod.server_id = c.server_id AND mod.user_id = c.moderator_id
            LEFT JOIN warnings w ON c.source_type = 'warning' AND w.id = c.source_id AND w.server_id = c.server_id
            LEFT JOIN moderation_events e ON c.source_type = 'event' AND e.id = c.source_id AND e.server_id = c.server_id
            WHERE c.server_id=? AND c.user_id=?
            ORDER BY c.id DESC LIMIT ?
            """,
            (server_id, user_id, limit),
        ).fetchall()
        
        result = []
        for row in rows:
            d = dict(row)
            user_identity = self.get_recorded_user_identity(d["user_id"], server_id)
            if user_identity is not None:
                d["username"] = user_identity["full_username"]
                d["display_name"] = d.get("display_name") or user_identity["display_name"]
            if d.get("moderator_id"):
                moderator_identity = self.get_recorded_user_identity(
                    d["moderator_id"], server_id
                )
                if moderator_identity is not None:
                    d["moderator_username"] = moderator_identity["full_username"]
                    d["moderator_display_name"] = (
                        d.get("moderator_display_name")
                        or moderator_identity["display_name"]
                    )
            scores_json = d.pop("scores_json", None)
            event_details_json = d.pop("event_details_json", None)
            d["scores"] = json.loads(scores_json) if scores_json else None
            event_details = json.loads(event_details_json) if event_details_json else {}
            d["stoatmod_initiated"] = (
                event_details.get("actor_attribution") == "known_bot_action"
                if d["action"] == "kick" else None
            )
            result.append(d)
        return result

    def list_dashboard_events(
        self, server_id: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT id, event_type, user_id, actor_id, message_id, channel_id,
                   details_json, created_at
            FROM moderation_events WHERE server_id=?
            ORDER BY id DESC LIMIT ?
            """,
            (server_id, limit),
        ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["details"] = json.loads(event.pop("details_json"))
            user_identity = self.get_recorded_user_identity(
                event.get("user_id") or "", server_id
            )
            actor_identity = self.get_recorded_user_identity(
                event.get("actor_id") or "", server_id
            )
            event["username"] = (
                user_identity["full_username"] if user_identity else None
            )
            event["display_name"] = (
                user_identity["display_name"] if user_identity else None
            )
            event["actor_username"] = (
                actor_identity["full_username"] if actor_identity else None
            )
            event["actor_display_name"] = (
                actor_identity["display_name"] if actor_identity else None
            )
            events.append(event)
        return events

    def backfill_captcha_kick_reasons(self, bot_user_id: str) -> int:
        """Repair legacy generic kick cases that can be tied to a CAPTCHA event."""
        kicks = self.connection.execute(
            """
            SELECT cases.id AS case_id, event.id AS event_id,
                   event.server_id, event.user_id, event.created_at,
                   event.details_json
            FROM moderation_cases AS cases
            JOIN moderation_events AS event
              ON cases.source_type='event' AND cases.source_id=event.id
            WHERE cases.action='kick'
              AND lower(cases.reason) IN ('kick', 'member kicked')
              AND event.event_type='member_kick'
            """
        ).fetchall()
        repaired = 0
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            for kick in kicks:
                captcha = self.connection.execute(
                    """
                    SELECT event_type, details_json
                    FROM moderation_events
                    WHERE server_id=? AND user_id=?
                      AND event_type IN ('join_captcha_kicked', 'join_captcha_failed')
                      AND ABS((julianday(created_at)-julianday(?))*86400) <= 30
                    ORDER BY ABS((julianday(created_at)-julianday(?))*86400), id DESC
                    LIMIT 1
                    """,
                    (
                        kick["server_id"], kick["user_id"], kick["created_at"],
                        kick["created_at"],
                    ),
                ).fetchone()
                if captcha is None:
                    continue
                captcha_details = json.loads(captcha["details_json"] or "{}")
                reason = str(captcha_details.get("reason") or "").strip()
                if not reason:
                    reason = (
                        "CAPTCHA timed out"
                        if captcha["event_type"] == "join_captcha_failed"
                        and captcha_details.get("result") == "kicked_after_30_minutes"
                        else "Failed CAPTCHA"
                    )
                event_details = json.loads(kick["details_json"] or "{}")
                event_details.update({
                    "reason": reason,
                    "actor_attribution": "known_bot_action",
                    "stoatmod_initiated": True,
                    "attribution_note": None,
                })
                self.connection.execute(
                    "UPDATE moderation_cases SET reason=?, moderator_id=? WHERE id=?",
                    (reason, bot_user_id, kick["case_id"]),
                )
                self.connection.execute(
                    "UPDATE moderation_events SET actor_id=?, details_json=? WHERE id=?",
                    (
                        bot_user_id,
                        json.dumps(event_details, separators=(",", ":"), sort_keys=True),
                        kick["event_id"],
                    ),
                )
                repaired += 1
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return repaired

    def remove_external_kick_cases(self) -> int:
        """Remove erroneous cases for kicks explicitly marked as external.

        The underlying moderation event remains available in the audit log.
        This cleanup runs after legacy CAPTCHA kick attribution is repaired so
        genuine Stoatmod kicks are not discarded.
        """
        rows = self.connection.execute(
            """
            SELECT cases.id, cases.server_id, cases.reference_id
            FROM moderation_cases AS cases
            INNER JOIN moderation_events AS event
              ON cases.source_type='event' AND cases.source_id=event.id
            WHERE event.event_type='member_kick'
              AND json_extract(event.details_json, '$.stoatmod_initiated') = 0
            """
        ).fetchall()
        if not rows:
            return 0

        try:
            self.connection.execute("BEGIN IMMEDIATE")
            for row in rows:
                self.connection.execute(
                    """
                    DELETE FROM moderation_case_entries
                    WHERE server_id=? AND case_reference=?
                    """,
                    (row["server_id"], row["reference_id"]),
                )
                self.connection.execute(
                    "DELETE FROM moderation_cases WHERE id=?", (row["id"],)
                )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return len(rows)

    def blacklist_server(
        self, server_id: str, reason: str, blacklisted_by: str
    ) -> tuple[dict[str, Any], int]:
        """Persist a server blacklist and atomically queue or resume departure.

        A request by the same actor is idempotent while its action is active. Failed
        actions can be safely requeued without deleting the network blacklist row.
        """
        server_id = str(server_id or "").strip()
        reason = str(reason or "").strip()
        blacklisted_by = str(blacklisted_by or "").strip()
        if not server_id:
            raise ValueError("Server ID is required.")
        if not 3 <= len(reason) <= 1000:
            raise ValueError("The blacklist reason must be between 3 and 1,000 characters.")
        if not blacklisted_by:
            raise ValueError("The admin account is required.")

        created_at = _utc_now()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            snapshot = self.connection.execute(
                """
                SELECT server_name, owner_id FROM dashboard_server_snapshots
                WHERE server_id=?
                """,
                (server_id,),
            ).fetchone()
            if snapshot is None:
                raise ValueError("Server not found in the current bot snapshot.")
            existing_blacklist = self.connection.execute(
                "SELECT 1 FROM server_blacklist WHERE server_id=?", (server_id,)
            ).fetchone()
            latest_action = self.connection.execute(
                """
                SELECT id, actor_id, status, result_json
                FROM dashboard_actions
                WHERE server_id=? AND action='blacklist_server'
                ORDER BY id DESC LIMIT 1
                """,
                (server_id,),
            ).fetchone()
            if existing_blacklist is not None and latest_action is not None and str(
                latest_action["status"]
            ) in {"pending", "processing"}:
                if str(latest_action["actor_id"]) != blacklisted_by:
                    raise ValueError(
                        "This server is already blacklisted and removal is in progress."
                    )
                action_id = int(latest_action["id"])
            else:
                completed_departure = False
                if latest_action is not None and latest_action["status"] == "completed":
                    try:
                        latest_result = json.loads(latest_action["result_json"] or "{}")
                    except (TypeError, ValueError):
                        latest_result = {}
                    completed_departure = (
                        latest_result.get("left") is True
                        or latest_result.get("already_departed") is True
                    )
                if existing_blacklist is not None and completed_departure:
                    raise ValueError("This server is already blacklisted.")
                if existing_blacklist is None:
                    self.connection.execute(
                        """
                        INSERT INTO server_blacklist(
                            server_id, server_name, owner_id, reason, blacklisted_by,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            server_id,
                            str(snapshot["server_name"]),
                            str(snapshot["owner_id"] or ""),
                            reason,
                            blacklisted_by,
                            created_at,
                        ),
                    )
                else:
                    self.connection.execute(
                        """
                        UPDATE server_blacklist
                        SET reason=?, blacklisted_by=?
                        WHERE server_id=?
                        """,
                        (reason, blacklisted_by, server_id),
                    )
                action_cursor = self.connection.execute(
                    """
                    INSERT INTO dashboard_actions(
                        server_id, action, actor_id, payload_json, created_at
                    ) VALUES (?, 'blacklist_server', ?, ?, ?)
                    """,
                    (
                        server_id,
                        blacklisted_by,
                        json.dumps(
                            {"reason": reason, "requested_by": blacklisted_by},
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                        created_at,
                    ),
                )
                action_id = int(action_cursor.lastrowid)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

        record = self.get_server_blacklist(server_id)
        assert record is not None
        return record, action_id

    def get_server_blacklist(self, server_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT server_id, server_name, owner_id, reason, blacklisted_by, created_at
            FROM server_blacklist WHERE server_id=?
            """,
            (str(server_id or "").strip(),),
        ).fetchone()
        return dict(row) if row is not None else None

    def enqueue_dashboard_action(
        self,
        server_id: str,
        action: str,
        actor_id: str,
        payload: dict[str, Any] | None = None,
        *,
        not_before: str | None = None,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO dashboard_actions(
                server_id, action, actor_id, payload_json, created_at, not_before
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                action,
                actor_id,
                json.dumps(payload or {}, separators=(",", ":"), sort_keys=True),
                _utc_now(),
                not_before,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)


    def has_pending_dashboard_action(self, action: str) -> bool:
        """Cheap read-only check so frequent pollers do not take the write lock."""
        return self.connection.execute(
            """
            SELECT 1 FROM dashboard_actions
            WHERE status='pending' AND action=?
              AND (not_before IS NULL OR datetime(not_before) <= datetime('now'))
            LIMIT 1
            """,
            (action,),
        ).fetchone() is not None

    def claim_dashboard_actions(
        self, *, limit: int = 10, only: str | None = None,
        exclude: tuple[str, ...] = ()
    ) -> list[dict[str, Any]]:
        claimed: list[dict[str, Any]] = []
        filters = ""
        parameters: list[Any] = []
        if only is not None:
            filters += " AND action=?"
            parameters.append(only)
        if exclude:
            filters += f" AND action NOT IN ({','.join('?' for _ in exclude)})"
            parameters.extend(exclude)
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(
                """
                UPDATE dashboard_actions
                SET status='pending', claimed_at=NULL, claim_token=NULL
                WHERE status='processing'
                  AND datetime(claimed_at) <= datetime('now', '-5 minutes')
                """
            )
            rows = self.connection.execute(
                f"""
                SELECT id, server_id, action, actor_id, payload_json
                FROM dashboard_actions
                WHERE status='pending'
                  AND (not_before IS NULL OR datetime(not_before) <= datetime('now'))
                  {filters}
                ORDER BY id LIMIT ?
                """,
                (*parameters, limit),
            ).fetchall()
            for row in rows:
                claim_token = secrets.token_urlsafe(24)
                cursor = self.connection.execute(
                    """
                    UPDATE dashboard_actions
                    SET status='processing', claimed_at=?, claim_token=?
                    WHERE id=? AND status='pending'
                    """,
                    (_utc_now(), claim_token, row["id"]),
                )
                if cursor.rowcount:
                    action = dict(row)
                    action["payload"] = json.loads(action.pop("payload_json"))
                    action["claim_token"] = claim_token
                    claimed.append(action)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return claimed

    def defer_report_notification_action(
        self,
        action_id: int,
        report_id: int,
        *,
        payload: dict[str, Any],
        delay_seconds: int,
        error: str,
        claim_token: str | None = None,
    ) -> bool:
        """Reschedule a transiently failed report DM and keep both rows in sync."""
        not_before = (
            datetime.now(timezone.utc) + timedelta(seconds=max(1, delay_seconds))
        ).isoformat(timespec="seconds")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            claim_clause = " AND claim_token=?" if claim_token else ""
            action_cursor = self.connection.execute(
                f"""
                UPDATE dashboard_actions
                SET status='pending', payload_json=?, result_json=?,
                    not_before=?, claimed_at=NULL, claim_token=NULL, processed_at=NULL
                WHERE id=? AND status='processing'
                {claim_clause}
                """,
                (*(
                    json.dumps(payload, separators=(",", ":"), sort_keys=True),
                    json.dumps(
                        {"error": error, "retry_scheduled": True},
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    not_before,
                    action_id,
                ), *((claim_token,) if claim_token else ())),
            )
            report_cursor = self.connection.execute(
                """
                UPDATE user_reports
                SET reporter_notification_status='pending',
                    reporter_notification_error=?, reporter_notified_at=NULL
                WHERE id=? AND status IN ('resolved', 'dismissed')
                """,
                (error, report_id),
            )
            if not action_cursor.rowcount or not report_cursor.rowcount:
                self.connection.rollback()
                return False
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return True

    def defer_dashboard_action(
        self,
        action_id: int,
        *,
        payload: dict[str, Any],
        delay_seconds: int,
        error: str,
        claim_token: str | None = None,
    ) -> bool:
        """Return a claimed delivery action to the queue after a bounded delay."""
        not_before = (
            datetime.now(timezone.utc) + timedelta(seconds=max(1, delay_seconds))
        ).isoformat(timespec="seconds")
        claim_clause = " AND claim_token=?" if claim_token else ""
        cursor = self.connection.execute(
            f"""
            UPDATE dashboard_actions
            SET status='pending', payload_json=?, result_json=?,
                not_before=?, claimed_at=NULL, claim_token=NULL, processed_at=NULL
            WHERE id=? AND status='processing'
            {claim_clause}
            """,
            (*(
                json.dumps(payload, separators=(",", ":"), sort_keys=True),
                json.dumps(
                    {"error": error, "retry_scheduled": True},
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                not_before,
                action_id,
            ), *((claim_token,) if claim_token else ())),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def finish_dashboard_action(
        self,
        action_id: int,
        *,
        success: bool,
        result: dict[str, Any] | None = None,
        claim_token: str | None = None,
    ) -> bool:
        claim_clause = " AND claim_token=?" if claim_token else ""
        cursor = self.connection.execute(
            f"""
            UPDATE dashboard_actions
            SET status=?, result_json=?, processed_at=?,
                claimed_at=NULL, claim_token=NULL
            WHERE id=? AND status='processing'
            {claim_clause}
            """,
            (*(
                "completed" if success else "failed",
                json.dumps(result or {}, separators=(",", ":"), sort_keys=True),
                _utc_now(),
                action_id,
            ), *((claim_token,) if claim_token else ())),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def get_dashboard_action(self, action_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT id, server_id, action, actor_id, payload_json, status, result_json,
                   created_at, processed_at, not_before
            FROM dashboard_actions WHERE id=?
            """,
            (action_id,),
        ).fetchone()
        if row is None:
            return None
        action = dict(row)
        try:
            action["payload"] = json.loads(action.pop("payload_json") or "{}")
        except (TypeError, ValueError):
            action["payload"] = {}
        try:
            action["result"] = json.loads(action.pop("result_json") or "{}")
        except (TypeError, ValueError):
            action["result"] = {}
        return action

    def record_verification_consent(self, challenge_hash: str, server_id: str, user_id: str, policy_version: str) -> None:
        now = datetime.now(timezone.utc)
        self.connection.execute("""INSERT INTO verification_consents
            (challenge_hash,server_id,user_id,policy_version,accepted_at,expires_at)
            VALUES (?,?,?,?,?,?) ON CONFLICT(challenge_hash) DO NOTHING""",
            (challenge_hash,server_id,user_id,policy_version,now.isoformat(),(now+timedelta(days=30)).isoformat()))
        self.connection.commit()

    def prune_verification_privacy_data(self) -> None:
        now = datetime.now(timezone.utc)
        cutoff = (now-timedelta(days=30)).isoformat()
        self.connection.execute("DELETE FROM verification_consents WHERE expires_at<=?", (now.isoformat(),))
        self.connection.execute("DELETE FROM moderation_events WHERE (event_type LIKE 'join_web_verification_%' OR event_type LIKE 'join_captcha_%') AND created_at<?", (cutoff,))
        self.connection.execute("DELETE FROM dashboard_actions WHERE action IN ('complete_join_verification','handle_join_verification_failure') AND created_at<?", (cutoff,))
        self.connection.commit()

    def set_join_protection(self, server_id: str, enabled: bool) -> None:
        self.connection.execute("""INSERT INTO join_verification_settings(server_id, young_accounts_enabled)
            VALUES (?, ?) ON CONFLICT(server_id) DO UPDATE SET young_accounts_enabled=excluded.young_accounts_enabled""",
            (server_id, int(enabled)))
        self.connection.commit()

    def get_join_protection(self, server_id: str) -> bool:
        row = self.connection.execute("SELECT young_accounts_enabled FROM join_verification_settings WHERE server_id=?", (server_id,)).fetchone()
        return bool(row and row[0])

    def set_captcha_all_members(self, server_id: str, enabled: bool) -> None:
        self.connection.execute("""INSERT INTO join_verification_settings(server_id, all_members_enabled)
            VALUES (?, ?) ON CONFLICT(server_id) DO UPDATE SET all_members_enabled=excluded.all_members_enabled""",
            (server_id, int(enabled)))
        self.connection.commit()

    def get_captcha_all_members(self, server_id: str) -> bool:
        row = self.connection.execute("SELECT all_members_enabled FROM join_verification_settings WHERE server_id=?", (server_id,)).fetchone()
        return bool(row and row[0])

    def set_nickname_protection(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, nickname_protection_enabled)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                nickname_protection_enabled=excluded.nickname_protection_enabled
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_nickname_protection(self, server_id: str) -> bool:
        row = self.connection.execute(
            """
            SELECT nickname_protection_enabled FROM server_settings
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["nickname_protection_enabled"])

    def set_link_protection(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, link_filter_enabled)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                link_filter_enabled=excluded.link_filter_enabled
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_link_protection(self, server_id: str) -> bool:
        row = self.connection.execute(
            """
            SELECT link_filter_enabled FROM server_settings
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["link_filter_enabled"])

    def set_allow_gifs(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, gifbox_links_allowed)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                gifbox_links_allowed=excluded.gifbox_links_allowed
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_allow_gifs(self, server_id: str) -> bool:
        row = self.connection.execute(
            """
            SELECT gifbox_links_allowed FROM server_settings
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["gifbox_links_allowed"])

    def set_spam_detection(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, spam_detection_enabled)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                spam_detection_enabled=excluded.spam_detection_enabled
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_spam_detection(self, server_id: str) -> bool:
        row = self.connection.execute(
            """
            SELECT spam_detection_enabled FROM server_settings
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["spam_detection_enabled"])

    def get_spam_settings(
        self,
        server_id: str,
        defaults: dict[str, int | float] | None = None,
    ) -> dict[str, int | float]:
        effective_defaults = {**DEFAULT_SPAM_SETTINGS, **(defaults or {})}
        row = self.connection.execute(
            """
            SELECT spam_repeat_count, spam_repeat_window_seconds,
                   spam_rapid_count, spam_rapid_window_seconds,
                   spam_score_threshold, spam_score_half_life_seconds,
                   spam_mass_mention_limit, spam_timeout_seconds
            FROM server_settings WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        columns = {
            "repeat_count": "spam_repeat_count",
            "repeat_window_seconds": "spam_repeat_window_seconds",
            "rapid_count": "spam_rapid_count",
            "rapid_window_seconds": "spam_rapid_window_seconds",
            "score_threshold": "spam_score_threshold",
            "score_half_life_seconds": "spam_score_half_life_seconds",
            "mass_mention_limit": "spam_mass_mention_limit",
            "timeout_seconds": "spam_timeout_seconds",
        }
        result: dict[str, int | float] = {}
        for key, column in columns.items():
            value = row[column] if row is not None and row[column] is not None else effective_defaults[key]
            result[key] = int(value) if key in SPAM_INTEGER_SETTINGS else float(value)
        return result

    def set_spam_settings(
        self, server_id: str, settings: dict[str, int | float]
    ) -> None:
        if set(settings) != set(DEFAULT_SPAM_SETTINGS):
            raise ValueError("all spam settings are required")
        normalized: dict[str, int | float] = {}
        for key, value in settings.items():
            numeric = float(value)
            minimum, maximum = SPAM_SETTING_LIMITS[key]
            if not minimum <= numeric <= maximum:
                raise ValueError(f"{key} must be between {minimum:g} and {maximum:g}")
            if key in SPAM_INTEGER_SETTINGS and not numeric.is_integer():
                raise ValueError(f"{key} must be a whole number")
            normalized[key] = int(numeric) if key in SPAM_INTEGER_SETTINGS else numeric
        self.connection.execute(
            """
            INSERT INTO server_settings(
                server_id, spam_repeat_count, spam_repeat_window_seconds,
                spam_rapid_count, spam_rapid_window_seconds,
                spam_score_threshold, spam_score_half_life_seconds,
                spam_mass_mention_limit, spam_timeout_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                spam_repeat_count=excluded.spam_repeat_count,
                spam_repeat_window_seconds=excluded.spam_repeat_window_seconds,
                spam_rapid_count=excluded.spam_rapid_count,
                spam_rapid_window_seconds=excluded.spam_rapid_window_seconds,
                spam_score_threshold=excluded.spam_score_threshold,
                spam_score_half_life_seconds=excluded.spam_score_half_life_seconds,
                spam_mass_mention_limit=excluded.spam_mass_mention_limit,
                spam_timeout_seconds=excluded.spam_timeout_seconds
            """,
            (
                server_id,
                normalized["repeat_count"],
                normalized["repeat_window_seconds"],
                normalized["rapid_count"],
                normalized["rapid_window_seconds"],
                normalized["score_threshold"],
                normalized["score_half_life_seconds"],
                normalized["mass_mention_limit"],
                normalized["timeout_seconds"],
            ),
        )
        self.connection.commit()

    def set_ai_thinking(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, ai_thinking_enabled)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                ai_thinking_enabled=excluded.ai_thinking_enabled
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_ai_thinking(self, server_id: str) -> bool:
        row = self.connection.execute(
            "SELECT ai_thinking_enabled FROM server_settings WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return False if row is None else bool(row["ai_thinking_enabled"])

    def set_image_scanning(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, image_scanning_on)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                image_scanning_on=excluded.image_scanning_on
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def set_channel_image_scanning(
        self,
        server_id: str,
        channel_id: str,
        enabled: bool,
        updated_by: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO channel_image_scanning_settings(
                server_id, channel_id, enabled, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(server_id, channel_id) DO UPDATE SET
                enabled=excluded.enabled,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at
            """,
            (server_id, channel_id, int(enabled), updated_by, _utc_now()),
        )
        self.connection.commit()

    def get_channel_image_scanning_override(
        self, server_id: str, channel_id: str
    ) -> bool | None:
        row = self.connection.execute(
            """
            SELECT enabled FROM channel_image_scanning_settings
            WHERE server_id=? AND channel_id=?
            """,
            (server_id, channel_id),
        ).fetchone()
        return None if row is None else bool(row["enabled"])

    def get_image_scanning(
        self, server_id: str, channel_id: str | None = None
    ) -> bool:
        if channel_id is not None:
            override = self.get_channel_image_scanning_override(
                server_id, channel_id
            )
            if override is not None:
                return override
        row = self.connection.execute(
            """
            SELECT image_scanning_on FROM server_settings
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["image_scanning_on"])

    def set_moderator_exemption(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, moderator_exemption_enabled)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                moderator_exemption_enabled=excluded.moderator_exemption_enabled
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_moderator_exemption(self, server_id: str) -> bool:
        row = self.connection.execute(
            """
            SELECT moderator_exemption_enabled FROM server_settings
            WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["moderator_exemption_enabled"])


    def set_public_stats_enabled(self, server_id: str, enabled: bool) -> None:
        self.connection.execute(
            """
            INSERT INTO server_settings(server_id, public_stats_enabled)
            VALUES (?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                public_stats_enabled=excluded.public_stats_enabled
            """,
            (server_id, int(enabled)),
        )
        self.connection.commit()

    def get_public_stats_enabled(self, server_id: str) -> bool:
        row = self.connection.execute(
            "SELECT public_stats_enabled FROM server_settings WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return True if row is None else bool(row["public_stats_enabled"])


    def has_server_announcement(self, server_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM server_announcements WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return row is not None

    def record_server_announcement(self, server_id: str, channel_id: str) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO server_announcements(
                server_id, channel_id, announced_at
            ) VALUES (?, ?, ?)
            """,
            (server_id, channel_id, _utc_now()),
        )
        self.connection.commit()

    def create_dashboard_announcement(
        self,
        server_id: str,
        title: str,
        message: str,
        created_by: str,
    ) -> dict[str, Any]:
        created_at = _utc_now()
        cursor = self.connection.execute(
            """
            INSERT INTO dashboard_announcements(
                server_id, title, message, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (server_id, title, message, created_by, created_at),
        )
        self.connection.commit()
        return {
            "id": int(cursor.lastrowid),
            "title": title,
            "message": message,
            "created_at": created_at,
            "expires_at": (
                datetime.fromisoformat(created_at)
                + DASHBOARD_ANNOUNCEMENT_LIFETIME
            ).isoformat(timespec="seconds"),
        }

    def list_dashboard_announcements(
        self, server_id: str, user_id: str, *, limit: int = 10
    ) -> list[dict[str, Any]]:
        cutoff = (
            datetime.now(timezone.utc) - DASHBOARD_ANNOUNCEMENT_LIFETIME
        ).isoformat(timespec="seconds")
        rows = self.connection.execute(
            """
            SELECT announcement.id, announcement.title, announcement.message,
                   announcement.created_at
            FROM dashboard_announcements AS announcement
            WHERE announcement.server_id=?
              AND announcement.created_at>?
              AND NOT EXISTS (
                  SELECT 1 FROM dashboard_announcement_dismissals AS dismissal
                  WHERE dismissal.announcement_id=announcement.id
                    AND dismissal.user_id=?
              )
            ORDER BY announcement.id DESC LIMIT ?
            """,
            (server_id, cutoff, user_id, max(0, limit)),
        ).fetchall()
        announcements: list[dict[str, Any]] = []
        for row in rows:
            announcement = dict(row)
            announcement["expires_at"] = (
                datetime.fromisoformat(announcement["created_at"])
                + DASHBOARD_ANNOUNCEMENT_LIFETIME
            ).isoformat(timespec="seconds")
            announcements.append(announcement)
        return announcements

    def dismiss_dashboard_announcement(
        self, server_id: str, user_id: str, announcement_id: int
    ) -> bool:
        announcement = self.connection.execute(
            """
            SELECT 1 FROM dashboard_announcements WHERE id=? AND server_id=?
            """,
            (announcement_id, server_id),
        ).fetchone()
        if announcement is None:
            return False
        self.connection.execute(
            """
            INSERT OR IGNORE INTO dashboard_announcement_dismissals(
                announcement_id, user_id, dismissed_at
            ) VALUES (?, ?, ?)
            """,
            (announcement_id, user_id, _utc_now()),
        )
        self.connection.commit()
        return True

    def list_server_permission_notices(
        self, server_id: str, *, within_seconds: int | None = None
    ) -> set[str]:
        if within_seconds is None:
            rows = self.connection.execute(
                """
                SELECT permission_name FROM server_permission_notices
                WHERE server_id=?
                """,
                (server_id,),
            ).fetchall()
        else:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(seconds=within_seconds)
            ).isoformat(timespec="seconds")
            rows = self.connection.execute(
                """
                SELECT permission_name FROM server_permission_notices
                WHERE server_id=? AND notified_at>=?
                """,
                (server_id, cutoff),
            ).fetchall()
        return {str(row["permission_name"]) for row in rows}

    def record_server_permission_notices(
        self,
        server_id: str,
        permission_names: list[str],
        channel_id: str,
        *,
        refresh_existing: bool = False,
    ) -> None:
        now = _utc_now()
        statement = (
            """
            INSERT INTO server_permission_notices(
                server_id, permission_name, channel_id, notified_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(server_id, permission_name) DO UPDATE SET
                channel_id=excluded.channel_id,
                notified_at=excluded.notified_at
            """
            if refresh_existing
            else """
            INSERT OR IGNORE INTO server_permission_notices(
                server_id, permission_name, channel_id, notified_at
            ) VALUES (?, ?, ?, ?)
            """
        )
        self.connection.executemany(
            statement,
            ((server_id, name, channel_id, now) for name in permission_names),
        )
        self.connection.commit()

    def has_email_webhook_delivery(self, message_key: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM email_webhook_deliveries WHERE message_key=?",
            (message_key,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _email_relay_marker(recipient: str, mailbox: str | None = None) -> str:
        base = f"email_relay_initialized:{recipient.lower()}"
        return f"{base}:{mailbox.casefold()}" if mailbox else base

    def is_email_relay_initialized(
        self, recipient: str, mailbox: str | None = None
    ) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM app_metadata WHERE key=?",
            (self._email_relay_marker(recipient, mailbox),),
        ).fetchone()
        return row is not None

    def initialize_email_relay(
        self,
        recipient: str,
        existing_messages: list[tuple[str, str | None]],
        mailbox: str | None = None,
    ) -> None:
        now = _utc_now()
        self.connection.executemany(
            """
            INSERT OR IGNORE INTO email_webhook_deliveries(
                message_key, message_id, recipient, delivered_at
            ) VALUES (?, ?, ?, ?)
            """,
            (
                (message_key, message_id, recipient, now)
                for message_key, message_id in existing_messages
            ),
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO app_metadata(key, value) VALUES (?, ?)",
            (self._email_relay_marker(recipient, mailbox), now),
        )
        self.connection.commit()

    def record_email_message(
        self,
        *,
        message_key: str,
        thread_key: str,
        message_id: str | None,
        direction: str,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        sent_at: str,
        in_reply_to: str | None,
        references: list[str],
        status: str,
        mailbox_address: str | None = None,
        cc_addresses: list[str] | None = None,
        bcc_addresses: list[str] | None = None,
    ) -> bool:
        mailbox = (mailbox_address or recipient).strip().casefold()
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO email_messages(
                message_key, thread_key, mailbox_address, message_id, direction, sender,
                recipient, cc_json, bcc_json, subject, body, sent_at, in_reply_to,
                references_json, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_key,
                thread_key,
                mailbox,
                message_id,
                direction,
                sender,
                recipient,
                json.dumps(cc_addresses or []),
                json.dumps(bcc_addresses or []),
                subject,
                body,
                sent_at,
                in_reply_to,
                json.dumps(references),
                status,
                _utc_now(),
            ),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def list_owner_email_threads(
        self,
        limit: int = 100,
        *,
        mailbox_address: str = "admin@modstoat.site",
    ) -> list[dict[str, Any]]:
        mailbox = mailbox_address.strip().casefold()
        rows = self.connection.execute(
            """
            SELECT messages.thread_key,
                   COUNT(*) AS message_count,
                   MAX(messages.sent_at) AS last_message_at,
                   SUM(CASE WHEN messages.direction='inbound'
                                 AND messages.read_at IS NULL THEN 1 ELSE 0 END)
                       AS unread_count,
                   (SELECT subject FROM email_messages AS first_message
                    WHERE first_message.thread_key=messages.thread_key
                      AND first_message.mailbox_address=messages.mailbox_address
                      AND first_message.deleted_at IS NULL
                    ORDER BY first_message.sent_at, first_message.rowid LIMIT 1) AS subject,
                   (SELECT CASE WHEN latest.direction='inbound'
                                THEN latest.sender ELSE latest.recipient END
                    FROM email_messages AS latest
                    WHERE latest.thread_key=messages.thread_key
                      AND latest.mailbox_address=messages.mailbox_address
                      AND latest.deleted_at IS NULL
                    ORDER BY latest.sent_at DESC, latest.rowid DESC LIMIT 1) AS participant,
                   (SELECT body FROM email_messages AS latest
                    WHERE latest.thread_key=messages.thread_key
                      AND latest.mailbox_address=messages.mailbox_address
                      AND latest.deleted_at IS NULL
                    ORDER BY latest.sent_at DESC, latest.rowid DESC LIMIT 1) AS preview,
                   (SELECT direction FROM email_messages AS latest
                    WHERE latest.thread_key=messages.thread_key
                      AND latest.mailbox_address=messages.mailbox_address
                      AND latest.deleted_at IS NULL
                    ORDER BY latest.sent_at DESC, latest.rowid DESC LIMIT 1) AS last_direction
            FROM email_messages AS messages
            WHERE messages.mailbox_address=? AND messages.deleted_at IS NULL
            GROUP BY messages.mailbox_address, messages.thread_key
            ORDER BY last_message_at DESC
            LIMIT ?
            """,
            (mailbox, limit),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_owner_email_thread(
        self,
        thread_key: str,
        *,
        mailbox_address: str = "admin@modstoat.site",
    ) -> dict[str, Any] | None:
        mailbox = mailbox_address.strip().casefold()
        rows = self.connection.execute(
            """
            SELECT message_key, thread_key, message_id, direction, sender,
                   recipient, cc_json, bcc_json, subject, body, sent_at, in_reply_to,
                   references_json, status
            FROM email_messages
            WHERE thread_key=? AND mailbox_address=? AND deleted_at IS NULL
            ORDER BY sent_at, rowid
            """,
            (thread_key, mailbox),
        ).fetchall()
        if not rows:
            return None
        now = _utc_now()
        self.connection.execute(
            """
            UPDATE email_messages SET read_at=?
            WHERE thread_key=? AND mailbox_address=?
              AND direction='inbound' AND read_at IS NULL
            """,
            (now, thread_key, mailbox),
        )
        self.connection.commit()
        messages = []
        for row in rows:
            message = dict(row)
            try:
                message["references"] = json.loads(message.pop("references_json"))
            except (TypeError, json.JSONDecodeError):
                message["references"] = []
            for field in ("cc", "bcc"):
                try:
                    value = json.loads(message.pop(f"{field}_json"))
                    message[field] = value if isinstance(value, list) else []
                except (TypeError, json.JSONDecodeError):
                    message[field] = []
            message["attachments"] = [
                {
                    "filename": attachment["filename"],
                    "content_type": attachment["content_type"],
                    "size": int(attachment["size"]),
                }
                for attachment in self.connection.execute(
                    """
                    SELECT filename, content_type, size
                    FROM email_attachments WHERE message_key=? ORDER BY id
                    """,
                    (message["message_key"],),
                ).fetchall()
            ]
            messages.append(message)
        latest = messages[-1]
        participant = next(
            (
                message["sender"]
                for message in reversed(messages)
                if message["direction"] == "inbound"
            ),
            latest["recipient"],
        )
        return {
            "thread_key": thread_key,
            "subject": messages[0]["subject"],
            "participant": participant,
            "messages": messages,
        }

    def queue_owner_email_reply(
        self,
        thread_key: str,
        body: str,
        created_by: str,
        attachments: list[tuple[str, str, bytes]] | None = None,
        *,
        cc_addresses: list[str] | None = None,
        bcc_addresses: list[str] | None = None,
        mailbox_address: str = "admin@modstoat.site",
    ) -> dict[str, Any] | None:
        mailbox = mailbox_address.strip().casefold()
        thread = self.get_owner_email_thread(
            thread_key, mailbox_address=mailbox
        )
        if thread is None:
            return None
        latest = thread["messages"][-1]
        # Keep the root conversation subject byte-for-byte. Threading is
        # carried by In-Reply-To and References, so changing the subject is
        # unnecessary and can split replies in some inboxes.
        subject = str(thread["subject"]).strip()
        references = list(latest.get("references", []))
        if latest.get("message_id") and latest["message_id"] not in references:
            references.append(latest["message_id"])
        now = _utc_now()
        cursor = self.connection.execute(
            """
            INSERT INTO email_reply_queue(
                thread_key, mailbox_address, from_address, to_address,
                cc_json, bcc_json, subject, body, in_reply_to,
                references_json, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                thread_key,
                mailbox,
                mailbox,
                thread["participant"],
                json.dumps(cc_addresses or []),
                json.dumps(bcc_addresses or []),
                subject,
                body,
                latest.get("message_id"),
                json.dumps(references),
                created_by,
                now,
            ),
        )
        reply_id = int(cursor.lastrowid)
        self._store_email_attachments(reply_id, attachments or [])
        self.connection.commit()
        return {
            "id": reply_id,
            "thread_key": thread_key,
            "status": "pending",
            "created_at": now,
        }

    def queue_owner_new_email(
        self,
        to_address: str,
        subject: str,
        body: str,
        created_by: str,
        attachments: list[tuple[str, str, bytes]] | None = None,
        *,
        cc_addresses: list[str] | None = None,
        bcc_addresses: list[str] | None = None,
        mailbox_address: str = "admin@modstoat.site",
    ) -> dict[str, Any]:
        now = _utc_now()
        mailbox = mailbox_address.strip().casefold()
        thread_key = secrets.token_hex(32)
        cursor = self.connection.execute(
            """
            INSERT INTO email_reply_queue(
                thread_key, mailbox_address, from_address, to_address,
                cc_json, bcc_json, subject, body, in_reply_to,
                references_json, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, '[]', ?, ?)
            """,
            (
                thread_key,
                mailbox,
                mailbox,
                to_address,
                json.dumps(cc_addresses or []),
                json.dumps(bcc_addresses or []),
                subject,
                body,
                created_by,
                now,
            ),
        )
        reply_id = int(cursor.lastrowid)
        self._store_email_attachments(reply_id, attachments or [])
        self.connection.commit()
        return {
            "id": reply_id,
            "thread_key": thread_key,
            "status": "pending",
            "created_at": now,
        }

    def _store_email_attachments(
        self,
        reply_id: int,
        attachments: list[tuple[str, str, bytes]],
    ) -> None:
        now = _utc_now()
        self.connection.executemany(
            """
            INSERT INTO email_attachments(
                reply_id, filename, content_type, content, size, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                (reply_id, filename, content_type, content, len(content), now)
                for filename, content_type, content in attachments
            ),
        )

    def claim_email_replies(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT * FROM email_reply_queue
            WHERE status='pending' ORDER BY id LIMIT ?
            """,
            (limit,),
        ).fetchall()
        if not rows:
            return []
        ids = [int(row["id"]) for row in rows]
        self.connection.executemany(
            "UPDATE email_reply_queue SET status='processing' WHERE id=?",
            ((reply_id,) for reply_id in ids),
        )
        self.connection.commit()
        replies = []
        for row in rows:
            reply = dict(row)
            try:
                reply["references"] = json.loads(reply.pop("references_json"))
            except (TypeError, json.JSONDecodeError):
                reply["references"] = []
            for field in ("cc", "bcc"):
                try:
                    value = json.loads(reply.pop(f"{field}_json"))
                    reply[field] = value if isinstance(value, list) else []
                except (TypeError, json.JSONDecodeError):
                    reply[field] = []
            reply["attachments"] = [
                dict(attachment)
                for attachment in self.connection.execute(
                    """
                    SELECT filename, content_type, content, size
                    FROM email_attachments WHERE reply_id=? ORDER BY id
                    """,
                    (reply["id"],),
                ).fetchall()
            ]
            replies.append(reply)
        return replies

    def complete_email_reply(
        self,
        reply_id: int,
        *,
        message_key: str | None = None,
        message_id: str | None = None,
        sender: str | None = None,
        thread_key: str | None = None,
        error: str | None = None,
    ) -> None:
        row = self.connection.execute(
            "SELECT * FROM email_reply_queue WHERE id=?", (reply_id,)
        ).fetchone()
        if row is None:
            return
        now = _utc_now()
        if error is not None:
            self.connection.execute(
                """
                UPDATE email_reply_queue
                SET status='failed', error=?, processed_at=? WHERE id=?
                """,
                (error[:1000], now, reply_id),
            )
        else:
            final_thread_key = thread_key or str(row["thread_key"])
            self.connection.execute(
                """
                UPDATE email_reply_queue
                SET status='sent', thread_key=?, error=NULL, processed_at=? WHERE id=?
                """,
                (final_thread_key, now, reply_id),
            )
            references = json.loads(row["references_json"] or "[]")
            final_message_key = message_key or f"outbound:{reply_id}"
            self.record_email_message(
                message_key=final_message_key,
                thread_key=final_thread_key,
                message_id=message_id,
                direction="outbound",
                sender=sender or row["from_address"],
                recipient=row["to_address"],
                subject=row["subject"],
                body=row["body"],
                sent_at=now,
                in_reply_to=row["in_reply_to"],
                references=references,
                status="sent",
                mailbox_address=row["mailbox_address"],
                cc_addresses=json.loads(row["cc_json"] or "[]"),
                bcc_addresses=json.loads(row["bcc_json"] or "[]"),
            )
            self.connection.execute(
                """
                UPDATE email_attachments SET message_key=? WHERE reply_id=?
                """,
                (final_message_key, reply_id),
            )
        self.connection.commit()

    def delete_owner_email_message(
        self,
        message_key: str,
        *,
        mailbox_address: str = "admin@modstoat.site",
    ) -> bool:
        mailbox = mailbox_address.strip().casefold()
        now = _utc_now()
        cursor = self.connection.execute(
            """
            UPDATE email_messages
            SET sender='[deleted]', recipient='[deleted]',
                subject='Deleted message', body='', message_id=NULL,
                in_reply_to=NULL, references_json='[]', read_at=?, deleted_at=?
            WHERE message_key=? AND mailbox_address=? AND deleted_at IS NULL
            """,
            (now, now, message_key, mailbox),
        )
        if cursor.rowcount:
            self.connection.execute(
                "DELETE FROM email_attachments WHERE message_key=?",
                (message_key,),
            )
        self.connection.commit()
        return cursor.rowcount > 0

    def delete_owner_email_thread(
        self,
        thread_key: str,
        *,
        mailbox_address: str = "admin@modstoat.site",
    ) -> int:
        mailbox = mailbox_address.strip().casefold()
        message_keys = [
            str(row["message_key"])
            for row in self.connection.execute(
                """
                SELECT message_key FROM email_messages
                WHERE thread_key=? AND mailbox_address=? AND deleted_at IS NULL
                """,
                (thread_key, mailbox),
            ).fetchall()
        ]
        if not message_keys:
            return 0
        now = _utc_now()
        cursor = self.connection.execute(
            """
            UPDATE email_messages
            SET sender='[deleted]', recipient='[deleted]',
                subject='Deleted message', body='', message_id=NULL,
                in_reply_to=NULL, references_json='[]', read_at=?, deleted_at=?
            WHERE thread_key=? AND mailbox_address=? AND deleted_at IS NULL
            """,
            (now, now, thread_key, mailbox),
        )
        placeholders = ",".join("?" for _ in message_keys)
        self.connection.execute(
            f"DELETE FROM email_attachments WHERE message_key IN ({placeholders})",
            message_keys,
        )
        self.connection.execute(
            """
            DELETE FROM email_attachments
            WHERE reply_id IN (
                SELECT id FROM email_reply_queue
                WHERE thread_key=? AND mailbox_address=? AND status='pending'
            )
            """,
            (thread_key, mailbox),
        )
        self.connection.execute(
            "DELETE FROM email_reply_queue WHERE thread_key=? "
            "AND mailbox_address=? AND status='pending'",
            (thread_key, mailbox),
        )
        self.connection.commit()
        return cursor.rowcount

    def record_email_webhook_delivery(
        self, message_key: str, message_id: str | None, recipient: str
    ) -> None:
        self.connection.execute(
            """
            INSERT OR IGNORE INTO email_webhook_deliveries(
                message_key, message_id, recipient, delivered_at
            ) VALUES (?, ?, ?, ?)
            """,
            (message_key, message_id, recipient, _utc_now()),
        )
        self.connection.commit()

    def set_captcha_challenge(
        self,
        server_id: str,
        user_id: str,
        answer_hash: str,
        salt: str,
        expires_at: str,
    ) -> CaptchaChallenge:
        created_at = _utc_now()
        self.connection.execute(
            """
            INSERT INTO captcha_challenges(
                server_id, user_id, answer_hash, salt, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id, user_id) DO UPDATE SET
                answer_hash=excluded.answer_hash,
                salt=excluded.salt,
                expires_at=excluded.expires_at,
                created_at=excluded.created_at,
                failure_count=0
            """,
            (server_id, user_id, answer_hash, salt, expires_at, created_at),
        )
        self.connection.commit()
        return CaptchaChallenge(
            server_id, user_id, answer_hash, salt, expires_at, created_at, 0
        )

    def set_web_verification_challenge(
        self,
        server_id: str,
        user_id: str,
        token_hash: str,
        expires_at: str,
    ) -> CaptchaChallenge:
        return self.set_captcha_challenge(
            server_id, user_id, token_hash, "web", expires_at
        )

    def get_web_verification_challenge(
        self, token_hash: str
    ) -> CaptchaChallenge | None:
        row = self.connection.execute(
            """
            SELECT * FROM captcha_challenges
            WHERE answer_hash=? AND salt='web' AND expires_at>?
            """,
            (token_hash, _utc_now()),
        ).fetchone()
        if row is None:
            return None
        return CaptchaChallenge(
            row["server_id"], row["user_id"], row["answer_hash"],
            row["salt"], row["expires_at"], row["created_at"],
            row["failure_count"]
        )

    def consume_web_verification_challenge(
        self, token_hash: str
    ) -> tuple[str, str] | None:
        row = self.connection.execute(
            """
            SELECT server_id, user_id FROM captcha_challenges
            WHERE answer_hash=? AND salt='web' AND expires_at>?
            """,
            (token_hash, _utc_now()),
        ).fetchone()
        if row is None:
            return None
        cursor = self.connection.execute(
            """
            DELETE FROM captcha_challenges
            WHERE answer_hash=? AND salt='web' AND expires_at>?
            """,
            (token_hash, _utc_now()),
        )
        self.connection.commit()
        if cursor.rowcount != 1:
            return None
        return row["server_id"], row["user_id"]

    def list_captcha_challenges(
        self, user_id: str | None = None
    ) -> list[CaptchaChallenge]:
        if user_id is None:
            rows = self.connection.execute(
                "SELECT * FROM captcha_challenges ORDER BY expires_at"
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT * FROM captcha_challenges
                WHERE user_id=? ORDER BY expires_at
                """,
                (user_id,),
            ).fetchall()
        return [
            CaptchaChallenge(
                row["server_id"], row["user_id"], row["answer_hash"],
                row["salt"], row["expires_at"], row["created_at"],
                row["failure_count"]
            )
            for row in rows
        ]

    def get_captcha_challenge(
        self, server_id: str, user_id: str
    ) -> CaptchaChallenge | None:
        row = self.connection.execute(
            """
            SELECT * FROM captcha_challenges
            WHERE server_id=? AND user_id=?
            """,
            (server_id, user_id),
        ).fetchone()
        if row is None:
            return None
        return CaptchaChallenge(
            row["server_id"], row["user_id"], row["answer_hash"],
            row["salt"], row["expires_at"], row["created_at"],
            row["failure_count"]
        )

    def increment_captcha_failure(self, server_id: str, user_id: str) -> int | None:
        cursor = self.connection.execute(
            """
            UPDATE captcha_challenges
            SET failure_count=failure_count+1
            WHERE server_id=? AND user_id=? AND expires_at>?
            """,
            (server_id, user_id, _utc_now()),
        )
        if cursor.rowcount != 1:
            self.connection.commit()
            return None
        row = self.connection.execute(
            """
            SELECT failure_count FROM captcha_challenges
            WHERE server_id=? AND user_id=?
            """,
            (server_id, user_id),
        ).fetchone()
        self.connection.commit()
        return int(row["failure_count"])

    def get_latest_captcha_failure_reason(
        self, server_id: str, user_id: str, since: str | None = None
    ) -> str | None:
        row = self.connection.execute(
            """
            SELECT details_json FROM moderation_events
            WHERE server_id=? AND user_id=?
              AND event_type='join_web_verification_failed'
              AND (? IS NULL OR created_at>=?)
            ORDER BY id DESC LIMIT 1
            """,
            (server_id, user_id, since, since),
        ).fetchone()
        if row is None:
            return None
        try:
            reason = json.loads(row["details_json"] or "{}").get("reason")
        except (TypeError, ValueError):
            return None
        return str(reason) if reason else None

    def captcha_challenge_was_issued(
        self, server_id: str, user_id: str, *, since: str
    ) -> bool:
        row = self.connection.execute(
            """
            SELECT 1 FROM moderation_events
            WHERE server_id=? AND user_id=?
              AND event_type='join_captcha_issued'
              AND created_at>=?
            LIMIT 1
            """,
            (server_id, user_id, since),
        ).fetchone()
        return row is not None

    def remove_captcha_challenge(self, server_id: str, user_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM captcha_challenges WHERE server_id=? AND user_id=?",
            (server_id, user_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def get_warning_policy(self, server_id: str) -> WarningPolicy:
        row = self.connection.execute(
            """
            SELECT warning_timeout_count, warning_kick_count, warning_ban_count
            FROM server_settings WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        if row is None:
            return WarningPolicy()
        return WarningPolicy(
            timeout_count=row["warning_timeout_count"],
            kick_count=row["warning_kick_count"],
            ban_count=row["warning_ban_count"],
        )

    def list_penalty_rules(self, server_id: str) -> list[PenaltyRule]:
        rows = self.connection.execute(
            """
            SELECT threshold, action, duration_seconds
            FROM warning_penalty_rules
            WHERE server_id=? ORDER BY threshold, position
            """,
            (server_id,),
        ).fetchall()
        if rows:
            return [
                PenaltyRule(
                    int(row["threshold"]),
                    str(row["action"]),
                    int(row["duration_seconds"])
                    if row["duration_seconds"] is not None else None,
                )
                for row in rows
            ]
        policy = self.get_warning_policy(server_id)
        return [
            PenaltyRule(policy.timeout_count, "timeout", 3600),
            PenaltyRule(policy.kick_count, "kick"),
            PenaltyRule(policy.ban_count, "ban"),
        ]

    def set_penalty_rules(
        self, server_id: str, rules: list[dict[str, Any]]
    ) -> list[PenaltyRule]:
        normalized: list[PenaltyRule] = []
        seen: set[int] = set()
        if not 1 <= len(rules) <= 12:
            raise ValueError("configure between 1 and 12 penalty rules")
        for raw in rules:
            threshold = int(raw.get("threshold", 0))
            action = str(raw.get("action", ""))
            duration = raw.get("duration_seconds")
            duration_seconds = int(duration) if duration is not None else None
            if threshold < 1 or threshold > 100 or threshold in seen:
                raise ValueError("penalty thresholds must be unique from 1 to 100")
            if action not in {"timeout", "kick", "ban"}:
                raise ValueError("unsupported penalty action")
            if action == "timeout":
                if duration_seconds is None or not 60 <= duration_seconds <= 2419200:
                    raise ValueError("timeout duration must be between 60 and 2419200 seconds")
            elif duration_seconds is not None:
                raise ValueError("only timeout penalties accept a duration")
            seen.add(threshold)
            normalized.append(PenaltyRule(threshold, action, duration_seconds))
        normalized.sort(key=lambda rule: rule.threshold)
        self.connection.execute(
            "DELETE FROM warning_penalty_rules WHERE server_id=?", (server_id,)
        )
        self.connection.executemany(
            """
            INSERT INTO warning_penalty_rules(
                server_id, threshold, action, duration_seconds, position
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                (server_id, rule.threshold, rule.action, rule.duration_seconds, index)
                for index, rule in enumerate(normalized)
            ),
        )
        self.connection.commit()
        return normalized


    def list_automation_rules(self, server_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT * FROM automation_rules WHERE server_id=? ORDER BY priority, id
            """,
            (server_id,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["enabled"] = bool(item["enabled"])
            item["action_config"] = json.loads(item.pop("action_config_json") or "{}")
            item["actions"] = json.loads(item.pop("actions_json") or "[]")
            if not item["actions"]:
                item["actions"] = [
                    {"type": item["action_type"], "config": item["action_config"]}
                ]
            item["conditions"] = json.loads(item.pop("conditions_json") or "[]")
            result.append(item)
        return result

    def create_automation_rule(
        self,
        server_id: str,
        name: str,
        trigger_type: str,
        trigger_value: str | None,
        action_type: str,
        action_config: dict[str, Any],
        created_by: str,
        conditions: list[dict[str, Any]] | None = None,
        condition_mode: str = "all",
        actions: list[dict[str, Any]] | None = None,
        priority: int = 100,
    ) -> dict[str, Any]:
        now = _utc_now()
        cursor = self.connection.execute(
            """
            INSERT INTO automation_rules(
                server_id, name, trigger_type, trigger_value, action_type,
                action_config_json, actions_json, conditions_json, condition_mode,
                priority, enabled,
                created_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                server_id, name, trigger_type, trigger_value, action_type,
                json.dumps(action_config, separators=(",", ":"), sort_keys=True),
                json.dumps(actions or [], separators=(",", ":"), sort_keys=True),
                json.dumps(conditions or [], separators=(",", ":"), sort_keys=True),
                condition_mode,
                max(1, min(int(priority), 1000)),
                created_by, now, now,
            ),
        )
        self.connection.commit()
        return next(
            rule for rule in self.list_automation_rules(server_id)
            if rule["id"] == int(cursor.lastrowid)
        )

    def update_automation_rule(
        self, server_id: str, rule_id: int, updates: dict[str, Any]
    ) -> bool:
        allowed = {
            "name": "name", "trigger_type": "trigger_type",
            "trigger_value": "trigger_value", "action_type": "action_type",
            "enabled": "enabled", "condition_mode": "condition_mode",
            "priority": "priority",
        }
        assignments: list[str] = []
        values: list[Any] = []
        for key, column in allowed.items():
            if key in updates:
                assignments.append(f"{column}=?")
                values.append(int(bool(updates[key])) if key == "enabled" else updates[key])
        if "action_config" in updates:
            assignments.append("action_config_json=?")
            values.append(json.dumps(updates["action_config"], separators=(",", ":"), sort_keys=True))
        if "conditions" in updates:
            assignments.append("conditions_json=?")
            values.append(json.dumps(updates["conditions"], separators=(",", ":"), sort_keys=True))
        if "actions" in updates:
            assignments.append("actions_json=?")
            values.append(json.dumps(updates["actions"], separators=(",", ":"), sort_keys=True))
        if not assignments:
            return False
        assignments.append("updated_at=?")
        values.extend([_utc_now(), server_id, rule_id])
        cursor = self.connection.execute(
            f"UPDATE automation_rules SET {', '.join(assignments)} WHERE server_id=? AND id=?",
            values,
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def delete_automation_rule(self, server_id: str, rule_id: int) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM automation_rules WHERE server_id=? AND id=?",
            (server_id, rule_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def record_automation_execution(
        self, rule_id: int, *, success: bool, error: str | None = None
    ) -> None:
        self.connection.execute(
            """
            UPDATE automation_rules SET
                execution_count=execution_count+1,
                failure_count=failure_count+?,
                last_executed_at=?,
                last_error=?
            WHERE id=?
            """,
            (0 if success else 1, _utc_now(), None if success else str(error or "Unknown error")[:1000], rule_id),
        )
        self.connection.commit()

    def create_poll(
        self, server_id: str, channel_id: str, question: str,
        options: list[dict[str, str]], created_by: str,
        closes_at: str | None = None, *, multiple_choice: bool = False,
        scheduled_for: str | None = None,
        anonymous: bool = False,
        required_role_id: str | None = None,
        quorum: int = 0,
        reminder_minutes: int | None = None,
    ) -> int:
        if int(quorum) < 0 or int(quorum) > 100000:
            raise ValueError("poll quorum must be between 0 and 100000")
        if reminder_minutes is not None and int(reminder_minutes) not in {5, 15, 30, 60, 1440}:
            raise ValueError("unsupported poll reminder interval")
        cursor = self.connection.execute(
            """
            INSERT INTO server_polls(
                server_id, channel_id, question, options_json, created_by,
                created_at, closes_at, multiple_choice, scheduled_for,
                anonymous, required_role_id, quorum, reminder_minutes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id, channel_id, question, json.dumps(options), created_by,
                _utc_now(), closes_at, int(multiple_choice), scheduled_for,
                int(anonymous), required_role_id, int(quorum), reminder_minutes,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def set_poll_message(self, poll_id: int, message_id: str) -> None:
        self.connection.execute(
            "UPDATE server_polls SET message_id=?, published_at=? WHERE id=?",
            (message_id, _utc_now(), poll_id),
        )
        self.connection.commit()

    def get_poll(self, poll_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM server_polls WHERE id=?", (poll_id,)
        ).fetchone()
        return self._poll_from_row(row) if row is not None else None

    def get_poll_by_message(self, message_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM server_polls WHERE message_id=?", (message_id,)
        ).fetchone()
        return self._poll_from_row(row) if row is not None else None

    def _poll_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["options"] = json.loads(item.pop("options_json"))
        raw_votes = json.loads(item.pop("votes_json") or "{}")
        item["votes"] = {
            str(user_id): ([str(value)] if isinstance(value, str) else [str(v) for v in value])
            for user_id, value in raw_votes.items()
        }
        item["multiple_choice"] = bool(item["multiple_choice"])
        item["anonymous"] = bool(item.get("anonymous"))
        vote_counts = {str(option.get("emoji")): 0 for option in item["options"]}
        for selected in item["votes"].values():
            for emoji in selected:
                if emoji in vote_counts:
                    vote_counts[emoji] += 1
        item["vote_counts"] = vote_counts
        item["total_voters"] = len(item["votes"])
        item["quorum_met"] = int(item.get("quorum") or 0) <= len(item["votes"])
        if item["status"] == "open" and not item["message_id"] and item["scheduled_for"]:
            item["status"] = "scheduled"
        return item

    def list_polls(
        self, server_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM server_polls WHERE server_id=? "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (server_id, max(1, min(limit, 100)), max(0, int(offset))),
        ).fetchall()
        result = []
        for row in rows:
            result.append(self._poll_from_row(row))
        return result

    def count_polls(self, server_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS total FROM server_polls WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return int(row["total"] if row is not None else 0)

    def list_poll_templates(self, server_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM poll_templates WHERE server_id=? ORDER BY name COLLATE NOCASE",
            (server_id,),
        ).fetchall()
        templates: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["options"] = json.loads(item.pop("options_json") or "[]")
            item["multiple_choice"] = bool(item["multiple_choice"])
            item["anonymous"] = bool(item["anonymous"])
            templates.append(item)
        return templates

    def save_poll_template(
        self,
        server_id: str,
        name: str,
        question: str,
        options: list[dict[str, str]],
        created_by: str,
        *,
        multiple_choice: bool = False,
        anonymous: bool = False,
        required_role_id: str | None = None,
        quorum: int = 0,
        reminder_minutes: int | None = None,
    ) -> dict[str, Any]:
        template_name = str(name or "").strip()
        if not template_name or len(template_name) > 80:
            raise ValueError("template names must be between 1 and 80 characters")
        self.connection.execute(
            """
            INSERT INTO poll_templates(
                server_id, name, question, options_json, multiple_choice,
                anonymous, required_role_id, quorum, reminder_minutes,
                created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(server_id, name) DO UPDATE SET
                question=excluded.question,
                options_json=excluded.options_json,
                multiple_choice=excluded.multiple_choice,
                anonymous=excluded.anonymous,
                required_role_id=excluded.required_role_id,
                quorum=excluded.quorum,
                reminder_minutes=excluded.reminder_minutes,
                created_by=excluded.created_by,
                created_at=excluded.created_at
            """,
            (
                server_id, template_name, question, json.dumps(options),
                int(multiple_choice), int(anonymous), required_role_id, int(quorum),
                reminder_minutes, created_by, _utc_now(),
            ),
        )
        self.connection.commit()
        return next(
            template for template in self.list_poll_templates(server_id)
            if template["name"].casefold() == template_name.casefold()
        )

    def delete_poll_template(self, server_id: str, template_id: int) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM poll_templates WHERE server_id=? AND id=?",
            (server_id, template_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def delete_poll(self, server_id: str, poll_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM server_polls WHERE server_id=? AND id=?",
            (server_id, poll_id),
        ).fetchone()
        if row is None:
            return None
        poll = self._poll_from_row(row)
        queued = self.connection.execute(
            """
            SELECT id, payload_json FROM dashboard_actions
            WHERE server_id=? AND status='pending'
              AND action IN ('publish_poll', 'close_poll')
            """,
            (server_id,),
        ).fetchall()
        action_ids = [
            int(action["id"])
            for action in queued
            if int(json.loads(action["payload_json"] or "{}").get("poll_id") or 0) == poll_id
        ]
        if action_ids:
            self.connection.executemany(
                "DELETE FROM dashboard_actions WHERE id=?",
                ((action_id,) for action_id in action_ids),
            )
        self.connection.execute(
            "DELETE FROM server_polls WHERE server_id=? AND id=?",
            (server_id, poll_id),
        )
        self.connection.commit()
        return poll

    def close_poll(self, poll_id: int) -> bool:
        cursor = self.connection.execute(
            "UPDATE server_polls SET status='closed' WHERE id=? AND status='open'",
            (poll_id,),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def record_poll_vote(
        self, message_id: str, user_id: str, emoji: str, *, remove: bool = False
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT id, options_json, votes_json, status, multiple_choice, closes_at "
            "FROM server_polls WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if row is None:
            return None
        if row["status"] != "open":
            return {"accepted": False, "remove_emoji": emoji, "reason": "closed"}
        if row["closes_at"] and datetime.fromisoformat(row["closes_at"]) <= datetime.now(timezone.utc):
            self.close_poll(int(row["id"]))
            return {"accepted": False, "remove_emoji": emoji, "reason": "closed"}
        options = json.loads(row["options_json"])
        emojis = [str(option.get("emoji")) for option in options]
        if emoji not in emojis:
            return {"accepted": False, "remove_emoji": emoji, "reason": "invalid_option"}
        raw_votes = json.loads(row["votes_json"] or "{}")
        votes = {
            str(voter): ([str(value)] if isinstance(value, str) else [str(v) for v in value])
            for voter, value in raw_votes.items()
        }
        current = votes.get(user_id, [])
        if remove:
            if emoji not in current:
                return None
            current = [value for value in current if value != emoji]
            if current:
                votes[user_id] = current
            else:
                votes.pop(user_id, None)
        else:
            if emoji in current:
                return {"accepted": True}
            if not bool(row["multiple_choice"]) and current:
                return {
                    "accepted": False, "remove_emoji": emoji,
                    "reason": "single_choice_limit",
                }
            votes[user_id] = [*current, emoji]
        self.connection.execute(
            "UPDATE server_polls SET votes_json=? WHERE id=?",
            (json.dumps(votes, separators=(",", ":"), sort_keys=True), row["id"]),
        )
        self.connection.commit()
        return {"accepted": True}

    def set_warning_policy(
        self, server_id: str, timeout_count: int, kick_count: int, ban_count: int
    ) -> WarningPolicy:
        policy = WarningPolicy(timeout_count, kick_count, ban_count)
        self.connection.execute(
            """
            INSERT INTO server_settings(
                server_id, warning_timeout_count, warning_kick_count,
                warning_ban_count
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(server_id) DO UPDATE SET
                warning_timeout_count=excluded.warning_timeout_count,
                warning_kick_count=excluded.warning_kick_count,
                warning_ban_count=excluded.warning_ban_count
            """,
            (server_id, timeout_count, kick_count, ban_count),
        )
        # The legacy command becomes the complete policy again when used.
        self.connection.execute(
            "DELETE FROM warning_penalty_rules WHERE server_id=?", (server_id,)
        )
        self.connection.commit()
        return policy

    def reset_warning_policy(self, server_id: str) -> WarningPolicy:
        return self.set_warning_policy(server_id, 3, 5, 7)

    def claim_warning_policy_action(
        self,
        server_id: str,
        user_id: str,
        action: str,
        threshold: int,
        warning_id: int,
    ) -> bool:
        expiry_days = self.get_warning_expiry_days(server_id)
        if expiry_days is not None:
            self.connection.execute(
                """
                DELETE FROM warning_policy_actions
                WHERE server_id=? AND user_id=?
                  AND datetime(created_at) < datetime('now', ?)
                """,
                (server_id, user_id, f"-{expiry_days} days"),
            )
        cursor = self.connection.execute(
            """
            INSERT OR IGNORE INTO warning_policy_actions(
                server_id, user_id, action, threshold,
                trigger_warning_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (server_id, user_id, action, threshold, warning_id, _utc_now()),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def release_warning_policy_action(
        self, server_id: str, user_id: str, action: str, threshold: int
    ) -> None:
        self.connection.execute(
            """
            DELETE FROM warning_policy_actions
            WHERE server_id=? AND user_id=? AND action=? AND threshold=?
            """,
            (server_id, user_id, action, threshold),
        )
        self.connection.commit()

    def global_reference_exists(self, reference_id: str) -> bool:
        row = self.connection.execute(
            """
            SELECT 1 FROM global_bans WHERE reference_id=?
            UNION ALL
            SELECT 1 FROM global_warnings WHERE reference_id=?
            LIMIT 1
            """,
            (reference_id, reference_id),
        ).fetchone()
        return row is not None

    def add_global_ban(
        self,
        reference_id: str,
        user_id: str,
        reason: str,
        created_by: str,
    ) -> GlobalBanRecord:
        created_at = _utc_now()
        self.connection.execute(
            """
            INSERT INTO global_bans(
                reference_id, user_id, reason, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (reference_id, user_id, reason, created_by, created_at),
        )
        self.connection.commit()
        return GlobalBanRecord(reference_id, user_id, reason, created_by, created_at)

    def get_global_ban(self, value: str) -> GlobalBanRecord | None:
        row = self.connection.execute(
            """
            SELECT * FROM global_bans
            WHERE user_id=? OR reference_id=? LIMIT 1
            """,
            (value, value.upper()),
        ).fetchone()
        if row is None:
            return None
        return GlobalBanRecord(
            row["reference_id"], row["user_id"], row["reason"],
            row["created_by"], row["created_at"]
        )

    def list_global_bans(self) -> list[GlobalBanRecord]:
        rows = self.connection.execute(
            "SELECT * FROM global_bans ORDER BY created_at"
        ).fetchall()
        return [
            GlobalBanRecord(
                row["reference_id"], row["user_id"], row["reason"],
                row["created_by"], row["created_at"]
            )
            for row in rows
        ]

    def remove_global_ban(self, user_id: str) -> GlobalBanRecord | None:
        record = self.get_global_ban(user_id)
        if record is None or record.user_id != user_id:
            return None
        self.connection.execute(
            "DELETE FROM global_bans WHERE user_id=?", (user_id,)
        )
        self.connection.commit()
        return record

    def add_global_warning(
        self,
        reference_id: str,
        user_id: str,
        reason: str,
        created_by: str,
    ) -> GlobalWarningRecord:
        created_at = _utc_now()
        self.connection.execute(
            """
            INSERT INTO global_warnings(
                reference_id, user_id, reason, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (reference_id, user_id, reason, created_by, created_at),
        )
        self.connection.commit()
        return GlobalWarningRecord(reference_id, user_id, reason, created_by, created_at)

    def list_global_warnings(self, value: str, *, limit: int = 10) -> list[GlobalWarningRecord]:
        rows = self.connection.execute(
            """
            SELECT * FROM global_warnings
            WHERE user_id=? OR reference_id=?
            ORDER BY created_at DESC LIMIT ?
            """,
            (value, value.upper(), limit),
        ).fetchall()
        return [
            GlobalWarningRecord(
                row["reference_id"], row["user_id"], row["reason"],
                row["created_by"], row["created_at"]
            )
            for row in rows
        ]

    def remove_global_warning(
        self, reference_id: str
    ) -> GlobalWarningRecord | None:
        warnings = self.list_global_warnings(reference_id, limit=1)
        if not warnings or warnings[0].reference_id != reference_id.upper():
            return None
        record = warnings[0]
        self.connection.execute(
            "DELETE FROM global_warnings WHERE reference_id=?",
            (record.reference_id,),
        )
        self.connection.commit()
        return record

    def exclude_scope(
        self,
        server_id: str,
        target_id: str,
        target_type: str,
        created_by: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO scope_exclusions(
                server_id, target_id, target_type, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(server_id, target_id) DO UPDATE SET
                target_type=excluded.target_type,
                created_by=excluded.created_by,
                created_at=excluded.created_at
            """,
            (server_id, target_id, target_type, created_by, _utc_now()),
        )
        self.connection.commit()

    def include_scope(self, server_id: str, target_id: str) -> bool:
        cursor = self.connection.execute(
            "DELETE FROM scope_exclusions WHERE server_id=? AND target_id=?",
            (server_id, target_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def remove_deleted_channel_reference(
        self, server_id: str, channel_id: str
    ) -> bool:
        """Remove a confirmed-deleted channel from dashboard state and scope."""
        cursor = self.connection.execute(
            """
            DELETE FROM scope_exclusions
            WHERE server_id=? AND target_id=? AND target_type='channel'
            """,
            (server_id, channel_id),
        )
        self.connection.execute(
            "DELETE FROM dashboard_channels WHERE server_id=? AND channel_id=?",
            (server_id, channel_id),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def is_scope_excluded(
        self,
        server_id: str,
        channel_id: str,
        category_id: str | None,
    ) -> bool:
        targets = [channel_id]
        if category_id:
            targets.append(category_id)
        placeholders = ",".join("?" for _ in targets)
        row = self.connection.execute(
            f"""
            SELECT 1 FROM scope_exclusions
            WHERE server_id=? AND target_id IN ({placeholders}) LIMIT 1
            """,
            (server_id, *targets),
        ).fetchone()
        return row is not None

    def count_scope_exclusions(self, server_id: str) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM scope_exclusions WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return int(row["count"])

    def list_scope_exclusions(self, server_id: str) -> list[dict[str, str]]:
        rows = self.connection.execute(
            """
            SELECT target_id, target_type FROM scope_exclusions
            WHERE server_id=? ORDER BY target_type, target_id
            """,
            (server_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def disable_moderation_category(
        self, server_id: str, category: str, disabled_by: str
    ) -> None:
        self.connection.execute(
            """
            DELETE FROM disabled_moderation_categories
            WHERE server_id=? AND category LIKE ?
            """,
            (server_id, f"{category}/%"),
        )
        self.connection.execute(
            """
            INSERT INTO disabled_moderation_categories(
                server_id, category, disabled_by, disabled_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(server_id, category) DO UPDATE SET
                disabled_by=excluded.disabled_by,
                disabled_at=excluded.disabled_at
            """,
            (server_id, category, disabled_by, _utc_now()),
        )
        self.connection.commit()

    def enable_moderation_category(self, server_id: str, category: str) -> int:
        cursor = self.connection.execute(
            """
            DELETE FROM disabled_moderation_categories
            WHERE server_id=? AND (category=? OR category LIKE ?)
            """,
            (server_id, category, f"{category}/%"),
        )
        self.connection.commit()
        return cursor.rowcount

    def reset_moderation_categories(self, server_id: str) -> int:
        cursor = self.connection.execute(
            "DELETE FROM disabled_moderation_categories WHERE server_id=?",
            (server_id,),
        )
        self.connection.commit()
        return cursor.rowcount

    def list_disabled_moderation_categories(self, server_id: str) -> list[str]:
        rows = self.connection.execute(
            """
            SELECT category FROM disabled_moderation_categories
            WHERE server_id=? ORDER BY category
            """,
            (server_id,),
        ).fetchall()
        return [row["category"] for row in rows]

    def is_moderation_category_disabled(
        self, server_id: str, category: str
    ) -> bool:
        return any(
            category == disabled or category.startswith(f"{disabled}/")
            for disabled in self.list_disabled_moderation_categories(server_id)
        )

    def add_warning(
        self,
        *,
        server_id: str,
        user_id: str,
        moderator_id: str | None,
        source: str,
        reason: str,
        message_id: str | None = None,
        channel_id: str | None = None,
        categories: dict[str, bool] | None = None,
        scores: dict[str, float] | None = None,
        original_content: str | None = None,
        ai_thinking: dict[str, Any] | None = None,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO warnings(
                server_id, user_id, moderator_id, source, reason,
                message_id, channel_id, categories_json, scores_json, created_at
                , original_content, ai_thinking_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                user_id,
                moderator_id,
                source,
                reason,
                message_id,
                channel_id,
                json.dumps(categories or {}, separators=(",", ":"), sort_keys=True),
                json.dumps(scores or {}, separators=(",", ":"), sort_keys=True),
                _utc_now(),
                original_content,
                (
                    json.dumps(ai_thinking, separators=(",", ":"), sort_keys=True)
                    if ai_thinking else None
                ),
            ),
        )
        warning_id = int(cursor.lastrowid)
        created_at = self.connection.execute(
            "SELECT created_at FROM warnings WHERE id=?", (warning_id,)
        ).fetchone()["created_at"]
        self.connection.execute(
            """
            INSERT INTO moderation_cases(
                reference_id, server_id, user_id, action, moderator_id, reason,
                source_type, source_id, status, created_at
            ) VALUES (?, ?, ?, 'warning', ?, ?, 'warning', ?, 'active', ?)
            """,
            (
                self._new_case_reference_id(),
                server_id,
                user_id,
                moderator_id,
                reason,
                warning_id,
                created_at,
            ),
        )
        case_row = self.connection.execute(
            "SELECT reference_id FROM moderation_cases WHERE source_type='warning' AND source_id=?",
            (warning_id,),
        ).fetchone()
        if source == "automatic" and hasattr(self, "appeal_privacy"):
            self.appeal_privacy.register(server_id, user_id, message_id, created_at)
        if hasattr(self, "appeal_privacy") and self.appeal_privacy.message_was_purged(server_id, message_id):
            self.appeal_privacy.purge_message(server_id, message_id, now=datetime.now(timezone.utc))
        self.connection.commit()
        return warning_id

    def count_active_warnings(self, server_id: str, user_id: str) -> int:
        """Count warnings whose case is active and whose expiry has not elapsed."""
        expiry_days = self.get_warning_expiry_days(server_id)
        if expiry_days is None:
            row = self.connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM warnings AS warning
                INNER JOIN moderation_cases AS moderation_case
                  ON moderation_case.server_id=warning.server_id
                 AND moderation_case.source_type='warning'
                 AND moderation_case.source_id=warning.id
                 AND moderation_case.status='active'
                WHERE warning.server_id=? AND warning.user_id=?
                """,
                (server_id, user_id),
            ).fetchone()
        else:
            row = self.connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM warnings AS warning
                INNER JOIN moderation_cases AS moderation_case
                  ON moderation_case.server_id=warning.server_id
                 AND moderation_case.source_type='warning'
                 AND moderation_case.source_id=warning.id
                 AND moderation_case.status='active'
                WHERE warning.server_id=? AND warning.user_id=?
                  AND datetime(warning.created_at) >= datetime('now', ?)
                """,
                (server_id, user_id, f"-{expiry_days} days"),
            ).fetchone()
        return int(row["count"])

    def count_warnings(self, server_id: str, user_id: str) -> int:
        """Backward-compatible alias for the active warning count."""
        return self.count_active_warnings(server_id, user_id)

    def list_warnings(
        self, server_id: str, user_id: str, *, limit: int = 10
    ) -> list[WarningRecord]:
        rows = self.connection.execute(
            """
            SELECT warning.* FROM warnings AS warning
            INNER JOIN moderation_cases AS moderation_case
              ON moderation_case.server_id=warning.server_id
             AND moderation_case.source_type='warning'
             AND moderation_case.source_id=warning.id
             AND moderation_case.status='active'
            WHERE warning.server_id=? AND warning.user_id=?
            ORDER BY warning.id DESC LIMIT ?
            """,
            (server_id, user_id, limit),
        ).fetchall()
        return [
            self._warning_from_row(row)
            for row in rows
        ]


    @staticmethod
    def _safe_member_history_details(details: dict[str, Any]) -> dict[str, Any]:
        safe_keys = {
            "action",
            "action_type",
            "actor_attribution",
            "attempt",
            "attempts",
            "case_reference",
            "categories",
            "decision",
            "duration_seconds",
            "global_reference",
            "method",
            "nickname_reset_succeeded",
            "remaining_warnings",
            "source",
            "source_server_id",
            "source_server_name",
            "source_warning_count",
            "threshold",
            "timeout_seconds",
            "total",
            "total_warnings",
            "warning_count",
            "warning_id",
        }
        return {
            key: value
            for key, value in details.items()
            if key in safe_keys and isinstance(value, (str, int, float, bool, list, dict))
        }

    @staticmethod
    def _warning_from_row(row: sqlite3.Row) -> WarningRecord:
        return WarningRecord(
            id=row["id"],
            server_id=row["server_id"],
            user_id=row["user_id"],
            moderator_id=row["moderator_id"],
            source=row["source"],
            reason=row["reason"],
            message_id=row["message_id"],
            channel_id=row["channel_id"],
            categories=json.loads(row["categories_json"]),
            scores=json.loads(row["scores_json"]),
            original_content=row["original_content"],
            created_at=row["created_at"],
        )


    def remove_moderation_case(
        self, server_id: str, reference_id: str
    ) -> tuple[ModerationCaseRecord, WarningRecord | None] | None:
        case = self.get_moderation_case(server_id, reference_id)
        if case is None or case.status == "removed":
            return None
        warning: WarningRecord | None = None
        if case.source_type == "warning":
            row = self.connection.execute(
                "SELECT * FROM warnings WHERE server_id=? AND id=?",
                (server_id, case.source_id),
            ).fetchone()
            if row is not None:
                warning = self._warning_from_row(row)
        self.connection.execute(
            """
            UPDATE moderation_cases SET status='removed'
            WHERE server_id=? AND reference_id=?
            """,
            (server_id, reference_id.upper()),
        )
        self.connection.commit()
        return case, warning

    @staticmethod
    def _case_from_row(row: sqlite3.Row) -> ModerationCaseRecord:
        return ModerationCaseRecord(
            id=row["id"],
            reference_id=row["reference_id"],
            server_id=row["server_id"],
            user_id=row["user_id"],
            action=row["action"],
            moderator_id=row["moderator_id"],
            reason=row["reason"],
            source_type=row["source_type"],
            source_id=row["source_id"],
            status=row["status"],
            created_at=row["created_at"],
        )

    def get_moderation_case(
        self, server_id: str, reference_id: str
    ) -> ModerationCaseRecord | None:
        row = self.connection.execute(
            "SELECT * FROM moderation_cases WHERE server_id=? AND reference_id=?",
            (server_id, reference_id.upper()),
        ).fetchone()
        return None if row is None else self._case_from_row(row)

    def get_moderation_case_by_id(
        self, server_id: str, case_id: int
    ) -> ModerationCaseRecord | None:
        row = self.connection.execute(
            "SELECT * FROM moderation_cases WHERE server_id=? AND id=?",
            (server_id, case_id),
        ).fetchone()
        return None if row is None else self._case_from_row(row)

    @staticmethod
    def _load_ai_thinking(value: Any) -> dict[str, Any] | None:
        if not value:
            return None
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def get_moderation_case_detail(
        self, server_id: str, reference_id: str
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        case = self.get_moderation_case(server_id, reference_id)
        if case is None:
            return None
        detail: dict[str, Any] = {
            "reference_id": case.reference_id,
            "server_id": case.server_id,
            "user_id": case.user_id,
            "action": case.action,
            "moderator_id": case.moderator_id,
            "reason": case.reason,
            "status": case.status,
            "created_at": case.created_at,
            "source_type": case.source_type,
            "source": {},
        }
        
        member = self.get_recorded_user_identity(case.user_id, server_id)
        if member is not None:
            detail["username"] = member["full_username"]
            detail["display_name"] = member["display_name"]
        else:
            detail["username"] = None
            detail["display_name"] = None

        if case.moderator_id is not None:
            mod = self.get_recorded_user_identity(case.moderator_id, server_id)
            if mod is not None:
                detail["moderator_username"] = mod["full_username"]
                detail["moderator_display_name"] = mod["display_name"]
            else:
                detail["moderator_username"] = None
                detail["moderator_display_name"] = None
        else:
            detail["moderator_username"] = None
            detail["moderator_display_name"] = None

        if case.source_type == "warning":
            warning = self.connection.execute(
                "SELECT * FROM warnings WHERE id=? AND server_id=?",
                (case.source_id, server_id),
            ).fetchone()
            if warning is not None:
                detail["source"] = {
                    "type": "warning",
                    "source": warning["source"],
                    "message_id": warning["message_id"],
                    "channel_id": warning["channel_id"],
                    "original_content": warning["original_content"],
                    "categories": json.loads(warning["categories_json"]),
                    "scores": json.loads(warning["scores_json"]),
                    "ai_thinking": self._load_ai_thinking(warning["ai_thinking_json"]),
                    "content_retention_ended": self.appeal_privacy.message_was_purged(
                        server_id, warning["message_id"]
                    ),
                }
            else:
                # Older case removals deleted the warning row even though the case
                # promised to preserve its audit trail. Automatic moderation events
                # still contain the evidence, so recover it for those legacy cases.
                event_rows = self.connection.execute(
                    """
                    SELECT message_id, channel_id, details_json
                    FROM moderation_events
                    WHERE server_id=? ORDER BY id DESC
                    """,
                    (server_id,),
                ).fetchall()
                for event in event_rows:
                    try:
                        event_details = json.loads(event["details_json"])
                    except (TypeError, ValueError):
                        continue
                    if event_details.get("warning_id") != case.source_id:
                        continue
                    detail["source"] = {
                        "type": "warning",
                        "source": "automatic",
                        "message_id": event["message_id"],
                        "channel_id": event["channel_id"],
                        "original_content": event_details.get("original_content"),
                        "categories": event_details.get("categories", {}),
                        "scores": event_details.get("scores", {}),
                        "ai_thinking": event_details.get("ai_thinking"),
                        "recovered_from_audit_event": True,
                    }
                    break
        else:
            event = self.connection.execute(
                "SELECT * FROM moderation_events WHERE id=? AND server_id=?",
                (case.source_id, server_id),
            ).fetchone()
            if event is not None:
                detail["source"] = {
                    "type": "event",
                    "event_type": event["event_type"],
                    "message_id": event["message_id"],
                    "channel_id": event["channel_id"],
                    "details": json.loads(event["details_json"]),
                }
        entries = self.connection.execute(
            """
            SELECT id, entry_type, content, created_by, created_at
            FROM moderation_case_entries
            WHERE server_id=? AND case_reference=? ORDER BY id
            """,
            (server_id, case.reference_id),
        ).fetchall()
        entry_records = [dict(row) for row in entries]
        attachments_by_entry: dict[int, list[dict[str, Any]]] = {
            int(entry["id"]): [] for entry in entry_records
        }
        if attachments_by_entry:
            placeholders = ",".join("?" for _ in attachments_by_entry)
            attachment_query = f"""
                SELECT id, entry_id, filename, content_type, size, created_at
                FROM moderation_case_entry_attachments
                WHERE entry_id IN ({placeholders}) ORDER BY id
            """
            attachments = self.connection.execute(
                attachment_query,
                tuple(attachments_by_entry),
            ).fetchall()
            for attachment in attachments:
                item = dict(attachment)
                entry_id = int(item.pop("entry_id"))
                attachments_by_entry[entry_id].append(item)
        for entry in entry_records:
            entry["attachments"] = attachments_by_entry[int(entry["id"])]
        detail["entries"] = entry_records
        return detail

    def add_moderation_case_entry(
        self,
        server_id: str,
        reference_id: str,
        entry_type: str,
        content: str,
        created_by: str,
        attachments: list[tuple[str, str, bytes]] | None = None,
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        case = self.get_moderation_case(server_id, reference_id)
        if case is None:
            return None
        if self.appeal_privacy.case_content_closed(server_id, case.reference_id, case.user_id):
            raise ValueError("Content storage for this case has ended under the retention policy.")
        if entry_type not in {"note", "evidence"}:
            raise ValueError("entry type must be note or evidence")
        created_at = _utc_now()
        cursor = self.connection.execute(
            """
            INSERT INTO moderation_case_entries(
                server_id, case_reference, entry_type, content, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                case.reference_id,
                entry_type,
                content,
                created_by,
                created_at,
            ),
        )
        entry_id = int(cursor.lastrowid)
        attachment_records: list[dict[str, Any]] = []
        for filename, content_type, data in attachments or []:
            attachment_cursor = self.connection.execute(
                """
                INSERT INTO moderation_case_entry_attachments(
                    entry_id, filename, content_type, data, size, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (entry_id, filename, content_type, data, len(data), created_at),
            )
            attachment_records.append(
                {
                    "id": int(attachment_cursor.lastrowid),
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(data),
                    "created_at": created_at,
                }
            )
        self.connection.commit()
        return {
            "id": entry_id,
            "entry_type": entry_type,
            "content": content,
            "created_by": created_by,
            "created_at": created_at,
            "attachments": attachment_records,
        }

    def get_moderation_case_attachment(
        self,
        server_id: str,
        reference_id: str,
        attachment_id: int,
    ) -> dict[str, Any] | None:
        self.appeal_privacy.prune()
        row = self.connection.execute(
            """
            SELECT a.filename, a.content_type, a.data, a.size
            FROM moderation_case_entry_attachments a
            JOIN moderation_case_entries e ON e.id=a.entry_id
            WHERE a.id=? AND e.server_id=? AND e.case_reference=?
            """,
            (attachment_id, server_id, reference_id.upper()),
        ).fetchone()
        return None if row is None else dict(row)

    def get_warning_case(
        self, server_id: str, warning_id: int
    ) -> ModerationCaseRecord | None:
        row = self.connection.execute(
            """
            SELECT * FROM moderation_cases
            WHERE server_id=? AND source_type='warning' AND source_id=?
            """,
            (server_id, warning_id),
        ).fetchone()
        return None if row is None else self._case_from_row(row)

    def get_event_case(
        self, server_id: str, event_id: int
    ) -> ModerationCaseRecord | None:
        row = self.connection.execute(
            """
            SELECT * FROM moderation_cases
            WHERE server_id=? AND source_type='event' AND source_id=?
            """,
            (server_id, event_id),
        ).fetchone()
        if row is not None:
            return self._case_from_row(row)
        event = self.connection.execute(
            "SELECT user_id, details_json FROM moderation_events WHERE server_id=? AND id=?",
            (server_id, event_id),
        ).fetchone()
        if event is None:
            return None
        return self._linked_warning_case(
            server_id, event["user_id"], json.loads(event["details_json"])
        )

    def list_moderation_cases(
        self, server_id: str, user_id: str, *, limit: int = 10
    ) -> list[ModerationCaseRecord]:
        rows = self.connection.execute(
            """
            SELECT * FROM moderation_cases
            WHERE server_id=? AND user_id=?
            ORDER BY id DESC LIMIT ?
            """,
            (server_id, user_id, limit),
        ).fetchall()
        return [self._case_from_row(row) for row in rows]

    def add_event(
        self,
        *,
        server_id: str,
        event_type: str,
        user_id: str | None = None,
        actor_id: str | None = None,
        message_id: str | None = None,
        channel_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> int:
        if event_type in {"message_edited", "external_message_deletion", "external_message_deletion_bulk", "cross_server_ban"}:
            return 0  # Retired collection paths cannot repopulate an archive.
        event_details = dict(details or {})
        # Only the timeout explicitly caused by this warning belongs to its case.
        # Never combine unrelated incidents just because the user is the same.
        event_details.pop("combined_warning_case", None)
        combined_case = None
        if event_type in {"automatic_spam_timeout", "warning_policy_timeout"}:
            warning_id = event_details.get("warning_id")
            if isinstance(warning_id, int) and not isinstance(warning_id, bool):
                candidate = self.get_warning_case(server_id, warning_id)
                if candidate is not None and candidate.user_id == user_id and candidate.status == "active":
                    warning = self.connection.execute(
                        "SELECT message_id FROM warnings WHERE server_id=? AND id=?",
                        (server_id, warning_id),
                    ).fetchone()
                    if warning is not None and (
                        not message_id or warning["message_id"] == message_id
                    ):
                        combined_case = candidate
                        event_details["combined_warning_case"] = candidate.reference_id
        self._record_payload_identities(
            {
                "user_id": user_id,
                "username": event_details.get("username")
                or event_details.get("user_username"),
                "discriminator": event_details.get("discriminator")
                or event_details.get("user_discriminator"),
                "display_name": event_details.get("display_name")
                or event_details.get("user_display_name"),
                "actor_id": actor_id,
                "actor_username": event_details.get("actor_username"),
                "actor_discriminator": event_details.get("actor_discriminator"),
                "actor_display_name": event_details.get("actor_display_name"),
                "details": event_details,
            }
        )
        cursor = self.connection.execute(
            """
            INSERT INTO moderation_events(
                server_id, event_type, user_id, actor_id,
                message_id, channel_id, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                event_type,
                user_id,
                actor_id,
                message_id,
                channel_id,
                json.dumps(event_details, separators=(",", ":"), sort_keys=True),
                _utc_now(),
            ),
        )
        event_id = int(cursor.lastrowid)
        case_reference: str | None = None
        if combined_case is not None:
            case_reference = combined_case.reference_id
            duration = event_details.get("timeout_seconds", event_details.get("duration_seconds"))
            timeout_reason = self._event_case_details(event_type, event_details)[1]
            explanation = "Timeout applied"
            if duration is not None:
                explanation += f" for {duration} seconds"
            explanation += f": {timeout_reason}. The warning and timeout share this case and appeal."
            self.connection.execute(
                "UPDATE moderation_cases SET action='warning_and_timeout', reason=? WHERE id=?",
                (f"{combined_case.reason} | {explanation}", combined_case.id),
            )
            self.connection.execute(
                """INSERT INTO moderation_case_entries(
                    server_id, case_reference, entry_type, content, created_by, created_at
                ) VALUES (?, ?, 'note', ?, ?, ?)""",
                (server_id, case_reference, explanation, actor_id or "Stoatmod", _utc_now()),
            )
        elif user_id is not None:
            case_details = self._event_case_details(event_type, event_details)
            if case_details is not None:
                action, case_reason = case_details
                created_at = self.connection.execute(
                    "SELECT created_at FROM moderation_events WHERE id=?",
                    (event_id,),
                ).fetchone()["created_at"]
                case_cursor = self.connection.execute(
                    """
                    INSERT INTO moderation_cases(
                        reference_id, server_id, user_id, action, moderator_id, reason,
                        source_type, source_id, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 'event', ?, 'active', ?)
                    """,
                    (
                        self._new_case_reference_id(),
                        server_id,
                        user_id,
                        action,
                        actor_id,
                        case_reason,
                        event_id,
                        created_at,
                    ),
                )
                case_reference = self.connection.execute(
                    "SELECT reference_id FROM moderation_cases WHERE id=?",
                    (int(case_cursor.lastrowid),),
                ).fetchone()["reference_id"]
        if event_type in AUTOMATED_EVENTS and user_id and hasattr(self, "appeal_privacy"):
            event_created = self.connection.execute("SELECT created_at FROM moderation_events WHERE id=?", (event_id,)).fetchone()[0]
            self.appeal_privacy.register(server_id, user_id, message_id, event_created)
        if hasattr(self, "appeal_privacy") and self.appeal_privacy.message_was_purged(server_id, message_id):
            self.appeal_privacy.purge_message(server_id, message_id, now=datetime.now(timezone.utc))
        self.connection.commit()
        return event_id
