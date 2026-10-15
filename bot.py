from __future__ import annotations

import asyncio
from difflib import SequenceMatcher
import hashlib
import hmac
import ipaddress
import io
import json
import os
import logging
import re
import secrets
import time
import unicodedata
from collections import deque
from datetime import datetime, timedelta, timezone

import stoat
import tldextract
from PIL import Image, ImageDraw, ImageFont
from urllib.parse import urlparse

from config import Settings, load_env_file
from database import (
    CaptchaChallenge,
    ModerationDatabase,
    ModerationCaseRecord,
    PROTECTED_MODERATION_CATEGORY_PREFIXES,
    SUPPORTED_MODERATION_CATEGORIES,
    WarningPolicy,
    WarningRecord,
)
from email_relay import EmailRelayConfig, ProtonEmailRelay
from localization import (
    SUPPORTED_LANGUAGES,
    help_description,
    localize_delivery,
    normalize_language,
    translate,
)
from moderation import ModerationError, ModerationResult, StoatGuardModerator
from moderation_policy import MIN_ACTION_SCORE, SUPPORT_CATEGORY, SUPPORT_ONLY_CATEGORIES

from case_notice import CASE_NOTICE_GRACE_SECONDS, CaseNotice
from admin_credentials import ADMIN_PASSWORD_LIFETIME_DAYS, generate_temporary_password, hash_password
from application_flow import ApplicationFlow
from reaction_role_flow import ReactionRoleFlow
from join_limits import JoinLimitFlow, format_duration as format_join_limit_duration


logger = logging.getLogger("stoat_moderator")
GLOBAL_COMMAND_OWNER_ID = os.getenv("GLOBAL_COMMAND_OWNER_ID", "").strip() or "00000000000000000000000000"
SUPPORT_EMAIL = "admin@modstoat.site"
SUPPORT_SERVER_URL = "https://stt.gg/PCaYw69F"
COMMAND_MESSAGE_PREFIXES = ("~", "/", "!")
CAPTCHA_FAILED_ATTEMPTS_KICK_REASON = "Failed CAPTCHA"
CAPTCHA_EXPIRED_KICK_REASON = "CAPTCHA timed out"
CAPTCHA_DELIVERY_TIMEOUT_SECONDS = 20
ADMIN_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS = 20
ADMIN_CREDENTIAL_DM_TIMEOUT_SECONDS = 30
SERVER_COMMAND_USAGES: dict[str, str] = {
    "~approve": "~approve USER_ID REASON",
    "~deny": "~deny USER_ID REASON",
    "~warnings": "~warnings USER_ID",
    "~setup": "~setup",
    "~warn": "~warn USER_ID REASON",
    "~remove": "~remove CASE_ID",
    "~case": "~case CASE_ID",
    "~cases": "~cases USER_ID",
    "~appeal": "~appeal CASE_ID accept|deny REASON",
    "~mute": "~mute USER_ID [DURATION] REASON",
    "~unmute": "~unmute USER_ID REASON",
    "~kick": "~kick USER_ID REASON",
    "~ban": "~ban USER_ID REASON",
    "~unban": "~unban USER_ID REASON",
    "~policy": "~policy [show|set TIMEOUT_COUNT KICK_COUNT BAN_COUNT|reset]",
    "~join-protection": "~join-protection [enable|disable|status]",
    "~auto-role": "~auto-role [ROLE_ID|add ROLE_ID|remove ROLE_ID|clear|list|status]",
    "~bypass": "~bypass USER_ID REASON",
    "~dashboard": "~dashboard",
    "~bump": "~bump",
    "~nickname-protection": "~nickname-protection [enable|disable|status]",
    "~link-protection": "~link-protection [enable|disable|status]",
    "~spam-detection": "~spam-detection [enable|disable|status]",
    "~image-scanning": "~image-scanning [enable [CHANNEL_ID]|disable [CHANNEL_ID]|status [CHANNEL_ID]]",
    "~moderator-exemption": "~moderator-exemption [enable|disable|status]",
    "~mod-exemption": "~mod-exemption [enable|disable|status]",
    "~threshold": "~threshold [status|set PERCENT|confirm PERCENT|reset]",
    "~categories": "~categories [status|enable CATEGORY|disable CATEGORY|reset]",
    "~log": "~log CHANNEL_ID",
    "~log-channel": "~log-channel CHANNEL_ID",
    "~exclude": "~exclude CHANNEL_OR_CATEGORY_ID",
    "~include": "~include CHANNEL_OR_CATEGORY_ID",
}
PUBLIC_COMMAND_USAGES: dict[str, str] = {
    "~help": "~help",
    "~language": "~language [English|French|Portuguese|Spanish]",
    "~support": "~support",
    "~information": "~information",
    "~info": "~info",
    "~report": "~report",
    "~global_report": "~global_report",
    **SERVER_COMMAND_USAGES,
}
GLOBAL_COMMAND_USAGES: dict[str, str] = {
    "~global_ban": "~global_ban USER_ID REASON",
    "~global_unban": "~global_unban USER_ID REASON",
    "~global_warn": "~global_warn USER_ID REASON",
    "~global_remove": "~global_remove WARNING_ID",
    "~global_lookup": "~global_lookup USER_OR_REFERENCE_ID",
    "~global_announce": "~global_announce MESSAGE",
    "~global_help": "~global_help",
}
GLOBAL_COMMANDS = set(GLOBAL_COMMAND_USAGES)
GLOBAL_REFERENCE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
GLOBAL_BAN_PERMISSION_NOTICE_SECONDS = 24 * 60 * 60
ZERO_TOLERANCE_USERNAME_SLURS = ("nigger", "faggot", "fag", "kike")
ZERO_TOLERANCE_USERNAME_BAN_REASON = (
    "Automatic account-username global ban: literal zero-tolerance slur match"
)
CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DASHBOARD_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SERVER_PERMISSION_REQUIREMENTS = (
    (
        "view_channel",
        "View Channels",
        "inspect and moderate channels Stoatmod cannot see",
    ),
    (
        "read_message_history",
        "Read Message History",
        "review message history and moderation context",
    ),
    (
        "send_messages",
        "Send Messages",
        "answer commands or post notices in affected channels",
    ),
    (
        "send_embeds",
        "Send Embeds",
        "send dashboard codes and formatted moderation logs",
    ),
    (
        "manage_messages",
        "Manage Messages",
        "remove messages caught by moderation, link, or spam protection",
    ),
    (
        "react",
        "React",
        "publish polls and remove invalid extra poll reactions",
    ),
    (
        "timeout_members",
        "Timeout Members",
        "apply mutes, spam timeouts, or join-verification restrictions",
    ),
    (
        "kick_members",
        "Kick Members",
        "kick members after verification or warning-policy failures",
    ),
    (
        "ban_members",
        "Ban Members",
        "apply server or global bans to members in this server",
    ),
    (
        "assign_roles",
        "Assign Roles",
        "give configured automatic roles to new members",
    ),
    (
        "manage_roles",
        "Manage Roles",
        "manage configured role-based protection features",
    ),
    (
        "manage_nicknames",
        "Manage Nicknames",
        "reset nicknames caught by nickname protection",
    ),
)
EMBED_DESCRIPTION_LIMIT = 1800
EMBED_TITLE_EMOJIS = (
    "🧪",
    "📚",
    "💡",
    "📊",
    "🚨",
    "❌",
    "✅",
    "🔐",
    "📝",
    "🧹",
    "🔗",
    "🔰",
    "🔧",
    "🌐",
    "👤",
    "📨",
    "📣",
    "✨",
)


def counts_towards_message_statistics(content: str) -> bool:
    """Exclude command-like messages from daily messages and active users."""
    return not content.lstrip().startswith(COMMAND_MESSAGE_PREFIXES)


URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)
LINK_PATTERN = re.compile(
    r"(?ix)(?:https?|ftp)://[^\s<>]+|(?:www\.)[^\s<>]+|"
    r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,62})\.)+"
    r"[a-z]{2,63}(?::\d+)?(?:/[^\s<>]*)?|"
    r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s<>]*)?"
)
PUBLIC_SUFFIX_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
)
AUTOMATIC_LINK_DELETION_ALLOWED_HOSTS = frozenset({"gifbox.me"})
FLOOD_PATTERN = re.compile(r"(.)\1{7,}")
EVERYONE_MENTION_PATTERN = re.compile(r"(?<![\w@])@(?:everyone|online)\b", re.IGNORECASE)
# Stoat sets these message flags only when the author may mention everyone/online.
EVERYONE_MENTION_FLAGS = (1 << 1) | (1 << 2)
STATUS_ROTATION_SECONDS = 60
STATUS_UPDATE_TIMEOUT_SECONDS = 30
STATUS_RESTART_DELAY_SECONDS = 5
DASHBOARD_ACTION_RESTART_DELAY_SECONDS = 5
DASHBOARD_MEMBER_REFRESH_SECONDS = 60 * 60
REPORT_NOTIFICATION_RETRY_DELAYS = (15, 60, 300)
DASHBOARD_DELIVERY_RETRY_DELAYS = (5, 30, 120)
DASHBOARD_DELIVERY_ACTIONS = frozenset(
    {
        "publish_poll",
        "post_local_report_instructions",
        "send_local_report_log",
        "log_automatic_appeal_decision",
        "configure_applications",
        "resolve_application",
        "application_submitted",
        "resume_application",
        "notify_application_decision",
    }
)
# Stoat permits two PATCH /users/:id calls per fixed 10-second window. Status
# changes use the self-user edit route, so keep our own attempts at least one
# full window apart. This remains safe if the task is cancelled and restarted.
STOAT_USER_EDIT_WINDOW_SECONDS = 10
STATUS_MIN_UPDATE_INTERVAL_SECONDS = STOAT_USER_EDIT_WINDOW_SECONDS


class ReportNotificationDeliveryError(RuntimeError):
    """Raised when Stoat could not deliver a report outcome direct message."""


def configure_logging(path: str) -> None:
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    handlers: list[logging.Handler] = [stream]
    if path:
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    logging.basicConfig(level=logging.INFO, handlers=handlers)


class ModerationBot(stoat.Client):
    def __init__(self, settings: Settings) -> None:
        super().__init__(cache=stoat.MapCache(messages_max_size=0))
        # ``stoat.Client`` exposes a read-only ``settings`` property, so keep
        # this application's configuration under a distinct attribute.
        self.moderation_settings = settings
        self.database = ModerationDatabase(settings.database_path)
        self.limiter = asyncio.Semaphore(settings.concurrency)
        self.moderator = StoatGuardModerator(
            api_key=settings.local_ai_api_key,
            expected_version=settings.local_ai_expected_version,
            base_url=settings.local_ai_base_url,
            timeout_seconds=settings.timeout_seconds,
            max_image_bytes=settings.max_image_bytes,
        )
        self._tasks: set[asyncio.Task[None]] = set()
        self._status_task: asyncio.Task[None] | None = None
        self._dashboard_action_task: asyncio.Task[None] | None = None
        self._email_relay_task: asyncio.Task[None] | None = None
        self._ready_reconciliation_task: asyncio.Task[None] | None = None
        self._global_ban_sync_task: asyncio.Task[None] | None = None
        self._dashboard_member_refresh_task: asyncio.Task[None] | None = None
        self._email_relay = (
            ProtonEmailRelay(
                self.database,
                EmailRelayConfig(
                    webhook_url=settings.email_relay_webhook_url,
                    recipient=settings.email_relay_recipient,
                    imap_host=settings.proton_bridge_imap_host,
                    imap_port=settings.proton_bridge_imap_port,
                    imap_username=settings.proton_bridge_imap_username,
                    imap_password=settings.proton_bridge_imap_password,
                    imap_mailbox=settings.proton_bridge_imap_mailbox,
                    imap_ca_file=settings.proton_bridge_ca_file,
                    smtp_host=settings.proton_bridge_smtp_host,
                    smtp_port=settings.proton_bridge_smtp_port,
                    smtp_username=settings.proton_bridge_smtp_username,
                    smtp_password=settings.proton_bridge_smtp_password,
                    poll_seconds=settings.email_relay_poll_seconds,
                    additional_recipients=tuple(
                        sorted(settings.email_relay_additional_recipients)
                    ),
                ),
            )
            if settings.email_relay_enabled
            else None
        )
        self._status_user: stoat.OwnUser | None = None
        self._status_index = 0
        # Delay the first edit too, so a quick process restart cannot
        # immediately follow an edit made by the previous process.
        self._last_status_update_attempt: float | None = time.monotonic()
        self._last_heartbeat_write = 0.0
        self._closing = False
        # Stoat populates ``self.servers`` after Ready handlers return. Keep the
        # accepted Ready servers available while startup reconciliation runs so
        # durable dashboard actions can still resolve their server targets.
        self._ready_event_servers: dict[str, stoat.Server] | None = None
        self._bot_deleted_ids: set[str] = set()
        self._spam_history: dict[tuple[str, str], deque[tuple[float, str]]] = {}
        self._spam_scores: dict[tuple[str, str], tuple[float, float]] = {}
        self._spam_timeout_until: dict[tuple[str, str], float] = {}
        self._support_dm_times: dict[tuple[str, str], float] = {}
        self._captcha_tasks: dict[tuple[str, str], asyncio.Task[None]] = {}
        self._global_ban_removal_suppressions: set[tuple[str, str]] = set()
        self._nickname_reset_suppressions: set[tuple[str, str]] = set()
        self._zero_tolerance_username_locks: dict[str, asyncio.Lock] = {}
        self._announcement_locks: dict[str, asyncio.Lock] = {}
        self._pending_ban_attribution: dict[
            tuple[str, str], tuple[str, str]
        ] = {}
        self._pending_kick_attribution: dict[
            tuple[str, str], tuple[str, str]
        ] = {}
        self._pending_threshold_changes: dict[
            tuple[str, str], tuple[float, float]
        ] = {}
        self.application_flow = ApplicationFlow(self)
        self.reaction_role_flow = ReactionRoleFlow(self)
        self.join_limit_flow = JoinLimitFlow(self)

    def _active_warning_count(self, server_id: str, user_id: str) -> int:
        """Use the explicit active counter, with compatibility for test doubles."""
        counter = getattr(self.database, "count_active_warnings", None)
        if counter is None:
            counter = self.database.count_warnings
        return int(counter(server_id, user_id))

    async def setup_hook(self) -> None:
        await self.moderator.__aenter__()
        if self._email_relay is not None:
            self._email_relay_task = asyncio.create_task(
                self._email_relay.run(), name="proton-email-relay"
            )
            logger.info(
                "email_relay_started recipients=%s mailbox=%s",
                ",".join((
                    self.moderation_settings.email_relay_recipient,
                    *sorted(self.moderation_settings.email_relay_additional_recipients),
                )),
                self.moderation_settings.proton_bridge_imap_mailbox,
            )

    async def close(self) -> None:
        self._closing = True
        if self._ready_reconciliation_task is not None:
            self._ready_reconciliation_task.cancel()
            await asyncio.gather(
                self._ready_reconciliation_task, return_exceptions=True
            )
            self._ready_reconciliation_task = None
        if self._status_task is not None:
            self._status_task.cancel()
            await asyncio.gather(self._status_task, return_exceptions=True)
            self._status_task = None
        if self._dashboard_action_task is not None:
            self._dashboard_action_task.cancel()
            await asyncio.gather(
                self._dashboard_action_task, return_exceptions=True
            )
            self._dashboard_action_task = None
        if self._email_relay_task is not None:
            self._email_relay_task.cancel()
            await asyncio.gather(
                self._email_relay_task, return_exceptions=True
            )
            self._email_relay_task = None
        if self._global_ban_sync_task is not None:
            self._global_ban_sync_task.cancel()
            await asyncio.gather(
                self._global_ban_sync_task, return_exceptions=True
            )
            self._global_ban_sync_task = None
        if self._dashboard_member_refresh_task is not None:
            self._dashboard_member_refresh_task.cancel()
            await asyncio.gather(
                self._dashboard_member_refresh_task, return_exceptions=True
            )
            self._dashboard_member_refresh_task = None
        captcha_tasks = list(self._captcha_tasks.values())
        for task in captcha_tasks:
            task.cancel()
        if captcha_tasks:
            await asyncio.gather(*captcha_tasks, return_exceptions=True)
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.moderator.__aexit__(None, None, None)
        self.database.close()
        await super().close()

    def rotating_statuses(self) -> tuple[str, str, str]:
        server_ids = getattr(self, "_status_server_ids", None)
        server_count = len(server_ids) if server_ids is not None else len(self.servers)
        return (
            "~help for commands",
            "monitoring..",
            f"watching over {server_count} servers",
        )

    def _track_status_server(self, server_id: str, *, connected: bool) -> None:
        server_ids = getattr(self, "_status_server_ids", None)
        if server_ids is not None:
            if connected:
                server_ids.add(server_id)
            else:
                server_ids.discard(server_id)

    def start_status_rotation(self, user: stoat.OwnUser) -> None:
        # Ready can fire again after a reconnect. Always replace the stale user
        # object even when the existing rotation task is still healthy.
        self._status_user = user
        if self._status_task is not None and not self._status_task.done():
            return
        self._status_task = asyncio.create_task(self._rotate_status())
        self._status_task.add_done_callback(self._status_rotation_stopped)

    def start_dashboard_action_worker(self) -> None:
        if (
            self._dashboard_action_task is not None
            and not self._dashboard_action_task.done()
        ):
            return
        self._dashboard_action_task = asyncio.create_task(
            self._run_dashboard_actions(), name="dashboard-actions"
        )
        self._dashboard_action_task.add_done_callback(
            self._dashboard_action_worker_stopped
        )

    def start_global_ban_sync_worker(self) -> None:
        if (
            self._global_ban_sync_task is not None
            and not self._global_ban_sync_task.done()
        ):
            return
        self._global_ban_sync_task = asyncio.create_task(
            self._run_global_ban_sync(), name="global-ban-sync"
        )

    def start_dashboard_member_refresh_worker(self) -> None:
        if (
            self._dashboard_member_refresh_task is not None
            and not self._dashboard_member_refresh_task.done()
        ):
            return
        self._dashboard_member_refresh_task = asyncio.create_task(
            self._run_dashboard_member_refresh(),
            name="dashboard-member-refresh",
        )

    async def handle_ready(self, event: stoat.ReadyEvent) -> None:
        """Return promptly so the gateway can dispatch message events."""
        previous = self._ready_reconciliation_task
        if previous is not None and not previous.done():
            previous.cancel()
            await asyncio.gather(previous, return_exceptions=True)
        self._ready_reconciliation_task = asyncio.create_task(
            self._run_ready_reconciliation(event),
            name="ready-reconciliation",
        )

    async def _run_ready_reconciliation(self, event: stoat.ReadyEvent) -> None:
        """Reject blacklisted servers, then run best-effort Ready reconciliation."""
        self._ready_event_servers = None
        server_summary = ", ".join(
            f"{server.name} ({server.id})" for server in event.servers
        )
        logger.info(
            "logged_in_as=%s model=%s servers=%d channels=%d",
            event.me.tag,
            self.moderation_settings.local_ai_expected_version,
            len(event.servers),
            len(event.channels),
        )
        if server_summary:
            logger.info("visible_servers=%s", server_summary)
        else:
            logger.warning(
                "bot_is_not_in_any_server invite_the_bot_before_testing_moderation"
            )

        # Ready is authoritative even before the SDK populates its own cache.
        # Replace the set on reconnect to drop servers left while offline.
        self._status_server_ids = {server.id for server in event.servers}
        # Ready can run again after reconnects; every starter is idempotent.
        self.start_status_rotation(event.me)

        # Complete the blacklist scan before the dashboard worker can claim a
        # persisted blacklist action. This prevents duplicate owner DMs and leave
        # requests when the process restarts with an action still pending.
        connected_servers: list[stoat.Server] = []
        for server in event.servers:
            try:
                if await self.reject_blacklisted_server(server, source="ready"):
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                # Fail closed for this startup pass when blacklist enforcement
                # cannot be determined. A reconnect or ServerCreate event can
                # retry it without treating the server as safe in the meantime.
                logger.exception(
                    "ready_server_blacklist_check_failed server_id=%s",
                    server.id,
                )
                continue
            connected_servers.append(server)

        # While this mapping is non-None it is the authoritative connected set:
        # excluded and unresolved blacklist entries must not be fetched back in.
        self._ready_event_servers = {
            server.id: server for server in connected_servers
        }

        # Start durable workers before any optional maintenance work. The
        # periodic workers repair dashboard/global-ban drift without flooding
        # Stoat's API during every reconnect.
        self.start_dashboard_action_worker()
        self.start_global_ban_sync_worker()
        self.start_dashboard_member_refresh_worker()
        join_limit_flow = getattr(self, "join_limit_flow", None)
        if join_limit_flow is not None:
            join_limit_flow.start()
        reaction_role_flow = getattr(self, "reaction_role_flow", None)
        if reaction_role_flow is not None:
            reaction_role_flow.start()

        try:
            await self.resume_captcha_challenges()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("ready_captcha_challenge_resume_failed")

        try:
            repaired_kicks = self.database.backfill_captcha_kick_reasons(event.me.id)
            if repaired_kicks:
                logger.info("captcha_kick_reasons_backfilled cases=%d", repaired_kicks)
        except Exception:
            logger.exception("ready_captcha_kick_reason_backfill_failed")

        try:
            removed_external_kick_cases = self.database.remove_external_kick_cases()
            if removed_external_kick_cases:
                logger.info(
                    "external_kick_cases_removed cases=%d",
                    removed_external_kick_cases,
                )
        except Exception:
            logger.exception("ready_external_kick_case_cleanup_failed")

        try:
            active_server_ids = {server.id for server in event.servers}
            removed_server_ids = self.database.reconcile_dashboard_server_snapshots(
                active_server_ids
            )
            if removed_server_ids:
                logger.info(
                    "stale_dashboard_servers_removed server_ids=%s",
                    ",".join(removed_server_ids),
                )
        except Exception:
            logger.exception("ready_dashboard_server_reconciliation_failed")

        try:
            self.update_bot_heartbeat(len(connected_servers))
        except Exception:
            logger.exception("ready_bot_heartbeat_update_failed")

        # Ready includes current branding even when a change happened offline.
        # Update only identity fields; do not replace full counts or permissions
        # with Ready's partial member/channel cache or make extra API requests.
        for server in connected_servers:
            try:
                self.sync_dashboard_server_identity(server)
            except Exception:
                logger.exception("ready_server_identity_refresh_failed server_id=%s", server.id)

        # Existing snapshots are durable, while ServerCreate and member events
        # maintain current state incrementally. Avoid full per-server refresh,
        # announcement, and global-ban fetch sweeps here: with many servers they
        # consume Stoat API buckets needed by live moderation and reaction roles.

        # Stoat processes and caches the Ready payload synchronously after this
        # handler returns, before worker tasks receive another scheduling turn.
        self._ready_event_servers = None

    async def handle_server_create(self, event: stoat.ServerCreateEvent) -> None:
        """Reject persistent blacklist entries before initializing a new server."""
        self._track_status_server(event.server.id, connected=True)
        if await self.reject_blacklisted_server(
            event.server, source="server_create"
        ):
            return
        await self.refresh_dashboard_server(event.server)
        self.update_bot_heartbeat(
            self.database.get_public_dashboard_stats()["server_count"]
        )
        await self.announce_server(event.server)

    async def _run_dashboard_member_refresh(self) -> None:
        while not self._closing:
            await asyncio.sleep(DASHBOARD_MEMBER_REFRESH_SECONDS)
            if self._closing:
                return
            try:
                refreshed = await self.refresh_all_dashboard_member_counts()
                logger.info(
                    "periodic_dashboard_member_refresh_complete refreshed=%d servers=%d",
                    refreshed,
                    len(self.servers),
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("periodic_dashboard_member_refresh_failed")

    async def _run_global_ban_sync(self) -> None:
        while not self._closing:
            await asyncio.sleep(
                self.moderation_settings.global_ban_sync_seconds
            )
            if self._closing:
                return
            try:
                servers = self._global_ban_servers()
                await self.sync_global_bans(servers)
                logger.info(
                    "periodic_global_ban_sync_complete servers=%d interval_seconds=%d",
                    len(servers),
                    self.moderation_settings.global_ban_sync_seconds,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("periodic_global_ban_sync_failed")

    def update_bot_heartbeat(self, server_count: int | None = None) -> None:
        ready_event_servers = getattr(self, "_ready_event_servers", None)
        self.database.update_system_heartbeat(
            "bot",
            {
                "connected": self._status_user is not None,
                "server_count": (
                    (
                        len(ready_event_servers)
                        if ready_event_servers is not None
                        else len(self.servers)
                    )
                    if server_count is None
                    else max(0, server_count)
                ),
            },
        )
        self._last_heartbeat_write = time.monotonic()

    async def _run_dashboard_actions(self) -> None:
        last_password_maintenance = float("-inf")
        while not self._closing:
            now = time.monotonic()
            if now - last_password_maintenance >= 60:
                try:
                    self.database.queue_due_admin_password_rotations()
                    last_password_maintenance = now
                except Exception:
                    logger.exception("admin_password_rotation_maintenance_failed")
            if now - self._last_heartbeat_write >= 15:
                self.update_bot_heartbeat()
            application_flow = getattr(self, "application_flow", None)
            if application_flow is not None:
                try:
                    await application_flow.maintenance()
                except Exception:
                    logger.exception("application_maintenance_failed")
            reaction_role_flow = getattr(self, "reaction_role_flow", None)
            actions = (
                self.database.claim_dashboard_actions(exclude=("reaction_roles",))
                if reaction_role_flow is not None and reaction_role_flow.runs_actions
                else self.database.claim_dashboard_actions()
            )
            for action in actions:
                success = False
                result: dict[str, object] = {}
                purge_server_after_finish: str | None = None
                try:
                    if action["action"] in {"configure_applications", "resolve_application", "application_submitted", "resume_application", "notify_application_decision"}:
                        result = await self.application_flow.action(action)
                        success = True
                    elif action["action"] == "reaction_roles":
                        result = await self.reaction_role_flow.action(action)
                        success = True
                    elif action["action"] == "release_join_challenges":
                        server = self.get_server(action["server_id"])
                        if server is None:
                            raise LookupError("Server is unavailable")
                        released = await self.disable_join_protection(server)
                        result = {"released_challenges": released}
                        self.database.add_event(
                            server_id=action["server_id"],
                            event_type="dashboard_join_challenges_released",
                            actor_id=action["actor_id"],
                            details=result,
                        )
                        await self.send_log(
                            action["server_id"],
                            "Join protection disabled from dashboard",
                            f"**Pending users released:** {released}",
                            color="#747F8D",
                        )
                        success = True
                    elif action["action"] == "refresh_member_profile":
                        user_id = str(action["payload"].get("user_id") or "")
                        user = self.get_user(user_id) or await self.fetch_user(user_id)
                        profile = await user.fetch_profile()
                        banner_url = self._asset_url(
                            getattr(profile, "background", None)
                        )
                        self.database.update_dashboard_member_banner(
                            action["server_id"], user_id, banner_url
                        )
                        result = {"user_id": user_id, "banner_url": banner_url}
                        success = True
                    elif action["action"] in {
                        "create_server_invite",
                        "get_random_server_invite",
                    }:
                        server = await self._resolve_dashboard_server(
                            action["server_id"]
                        )
                        if server is None:
                            raise LookupError(
                                "Stoatmod is no longer connected to this server."
                            )
                        result = await self._get_owner_server_invite(server)
                        success = True
                    elif action["action"] == "blacklist_server":
                        blacklist = self.database.get_server_blacklist(
                            action["server_id"]
                        )
                        if blacklist is None:
                            raise LookupError("The server blacklist entry is unavailable.")
                        server = await self._resolve_dashboard_server(
                            action["server_id"]
                        )
                        result = await self._enforce_server_blacklist(
                            server,
                            blacklist,
                            source="admin_dashboard",
                        )
                        if (
                            result.get("left") is not True
                            and result.get("already_departed") is not True
                        ):
                            raise RuntimeError(
                                "Stoat did not confirm that Stoatmod left or was "
                                "already absent from the server."
                            )
                        purge_server_after_finish = action["server_id"]
                        success = True
                    elif action["action"] == "deliver_admin_credentials":
                        user_id = str(action["payload"].get("user_id") or "").upper()
                        password_version = int(
                            action["payload"].get("password_version") or 0
                        )
                        account = self.database.get_admin_dashboard_account(user_id)
                        if account is None:
                            raise LookupError("The admin account no longer exists.")
                        if (
                            int(account.get("delivery_action_id") or 0) != action["id"]
                            or int(account.get("password_version") or 0)
                            != password_version
                            or account.get("revoked_at") is not None
                        ):
                            raise RuntimeError(
                                "This credential delivery was replaced or revoked."
                            )
                        if account.get("active"):
                            result = {
                                "user_id": user_id,
                                "username": account.get("full_username"),
                                "password_expires_at": account.get(
                                    "password_expires_at"
                                ),
                                "delivery_confirmed": True,
                            }
                            success = True
                        else:
                            if not self.database.admin_dashboard_delivery_is_current(
                                user_id,
                                password_version,
                                action["id"],
                                claim_token=action.get("claim_token"),
                            ):
                                raise RuntimeError(
                                    "This credential delivery is no longer current."
                                )
                            user = self.get_user(user_id)
                            if user is None:
                                user = await asyncio.wait_for(
                                    self.fetch_user(user_id),
                                    timeout=ADMIN_CREDENTIAL_LOOKUP_TIMEOUT_SECONDS,
                                )
                            if user_id == self.state.my_id or self._user_is_bot(user):
                                raise ValueError(
                                    "Bot accounts cannot access the admin dashboard."
                                )
                            username = await self._resolve_user_tag(user_id, user)
                            generated_password = generate_temporary_password()
                            generated_password_hash = await asyncio.to_thread(
                                hash_password, generated_password
                            )
                            password_expires_at = datetime.now(
                                timezone.utc
                            ) + timedelta(days=ADMIN_PASSWORD_LIFETIME_DAYS)
                            if not self.database.admin_dashboard_delivery_is_current(
                                user_id,
                                password_version,
                                action["id"],
                                claim_token=action.get("claim_token"),
                                renew_claim=True,
                            ):
                                raise RuntimeError(
                                    "This credential delivery changed before the direct message was sent."
                                )
                            delivered = await asyncio.wait_for(
                                self._send_user_dm(
                                    user_id,
                                    "Your ModStoat admin dashboard password",
                                    ("Your admin password has been automatically reset after 7 days.\n\n"
                                     if action["payload"].get("reason") == "scheduled_rotation"
                                     else "A new password has been issued for your ModStoat staff account.\n\n")
                                    +
                                    f"**Login:** {self.moderation_settings.dashboard_url}/admin/login\n"
                                    f"**User ID:** `{user_id}`\n"
                                    f"**Credential version:** `{password_version}`\n"
                                    f"**Generated password:** `{generated_password}`\n"
                                    f"**Next automatic reset:** {password_expires_at.isoformat(timespec='seconds')}\n\n"
                                    "Your password resets automatically every 7 days. The bot will DM "
                                    "your new password here. Previous passwords and sessions stop working at reset.\n\n"
                                    "If you ever receive more than one credential message, use the "
                                    "newest message with the highest credential version.\n\n"
                                    "Do not share this password. ModStoat staff will never ask you "
                                    "to send it in a message.",
                                    user=user,
                                    color="#5865F2",
                                    sensitive=True,
                                ),
                                timeout=ADMIN_CREDENTIAL_DM_TIMEOUT_SECONDS,
                            )
                            if not delivered:
                                raise RuntimeError(
                                    "The login details could not be delivered by direct message."
                                )
                            if not self.database.activate_admin_dashboard_account_credentials(
                                user_id,
                                password_version,
                                action["id"],
                                generated_password_hash,
                                password_expires_at.isoformat(timespec="seconds"),
                                claim_token=action.get("claim_token"),
                            ):
                                raise RuntimeError(
                                    "Admin access changed before credential delivery completed."
                                )
                            result = {
                                "user_id": user_id,
                                "username": username,
                                "password_expires_at": password_expires_at.isoformat(
                                    timespec="seconds"
                                ),
                                "delivery_confirmed": True,
                            }
                            success = True
                    elif action["action"] == "discovery_status_log":
                        status = str(action["payload"].get("status") or "updated")
                        title = str(
                            action["payload"].get("title")
                            or "StoatMod Discovery status updated"
                        )
                        description = str(
                            action["payload"].get("description")
                            or "This server's Discovery status has changed."
                        )
                        await self.send_log(
                            action["server_id"],
                            title,
                            description,
                            color="#3BA55D" if status == "approved" else "#ED4245",
                        )
                        result = {
                            "status": status,
                            "log_channel_id": self.database.get_log_channel(
                                action["server_id"]
                            ),
                        }
                        success = True
                    elif action["action"] == "moderate_member":
                        server = await self._resolve_dashboard_server(
                            action["server_id"]
                        )
                        if server is None:
                            raise LookupError("Server is unavailable")
                        user_id = str(action["payload"].get("user_id") or "")
                        moderation_action = str(action["payload"].get("action") or "")
                        reason = str(action["payload"].get("reason") or "No reason provided")
                        if action["payload"].get("source") == "alt_detection":
                            raise ValueError("Alt-account detection has been removed")
                        moderation_actor_id = action["actor_id"]
                        if moderation_action == "warn":
                            member = server.get_member(user_id) or await server.fetch_member(user_id)
                            if self._moderator_is_exempt(server.id, server, member):
                                raise PermissionError("Elevated members cannot be warned")
                            warning_id = self.database.add_warning(
                                server_id=server.id,
                                user_id=user_id,
                                moderator_id=moderation_actor_id,
                                source="dashboard",
                                reason=reason,
                            )
                            warning_case = self.database.get_warning_case(
                                server.id, warning_id
                            )
                            public_case_id = (
                                self._case_reference(warning_case.reference_id)
                                if warning_case is not None
                                else "Unavailable"
                            )
                            total = self._active_warning_count(server.id, user_id)
                            appeal = self._appeal_instructions(
                                user_id,
                                "moderation",
                                warning_case.reference_id if warning_case is not None else "",
                                server_id=server.id,
                            )
                            await self._send_case_dm(
                                user_id,
                                "You received a warning",
                                f"You received a warning in **{server.name}**.\n\n"
                                f"**Case ID:** `{public_case_id}`\n"
                                f"**Reason:** {reason}\n"
                                f"**Warnings in this server:** {total}"
                                f"{appeal}",
                                warning_id=warning_id,
                                server_id=server.id,
                            )
                            await self._enforce_warning_policy_and_notify(
                                server, server.id, user_id, warning_id, total
                            )
                            event_type = "manual_warning"
                            details = {
                                "reason": reason,
                                "warning_id": warning_id,
                                "case_reference": public_case_id,
                                "total": total,
                            }
                        elif moderation_action == "mute":
                            member = server.get_member(user_id) or await server.fetch_member(user_id)
                            if self._member_is_moderator(server, member):
                                raise PermissionError("Elevated members cannot be muted")
                            if not await self.require_action_permissions(server, "timeout_members"):
                                raise PermissionError("Missing Timeout Members permission")
                            duration_seconds = int(action["payload"].get("duration_seconds") or 3600)
                            await member.timeout(timedelta(seconds=duration_seconds))
                            event_type = "manual_mute"
                            details = {"reason": reason, "duration_seconds": duration_seconds}
                        elif moderation_action == "kick":
                            member = server.get_member(user_id) or await server.fetch_member(user_id)
                            if not await self.require_action_permissions(server, "kick_members"):
                                raise PermissionError("Missing Kick Members permission")
                            await self._kick_member_with_reason(
                                member,
                                server.id,
                                user_id,
                                reason,
                                actor_id=moderation_actor_id,
                            )
                            event_type = "dashboard_member_kick_requested"
                            details = {"reason": reason}
                        elif moderation_action == "ban":
                            if not await self.require_action_permissions(server, "ban_members"):
                                raise PermissionError("Missing Ban Members permission")
                            self._pending_ban_attribution[(server.id, user_id)] = (
                                moderation_actor_id, reason
                            )
                            await server.ban(user_id, reason=reason[:1024])
                            event_type = "dashboard_member_ban_requested"
                            details = {"reason": reason}
                        else:
                            raise ValueError("Unsupported moderation action")
                        self.database.add_event(
                            server_id=server.id,
                            event_type=event_type,
                            user_id=user_id,
                            actor_id=moderation_actor_id,
                            details=details,
                        )
                        warning_log_details = (
                            f"\n**Case ID:** `{details['case_reference']}`"
                            f"\n**Total warnings:** {details['total']}"
                            if moderation_action == "warn"
                            else ""
                        )
                        log_title = f"Member {moderation_action} from dashboard"
                        actor_label = "Moderator"
                        await self.send_log(
                            server.id,
                            log_title,
                            f"**User:** `{await self._resolve_user_tag(user_id)}`\n"
                            f"**{actor_label}:** `{await self._resolve_user_tag(moderation_actor_id)}`\n"
                            f"**Reason:** {reason}{warning_log_details}",
                            color="#F59E0B" if moderation_action == "warn" else "#ED4245",
                        )
                        result = {
                            "user_id": user_id,
                            "action": moderation_action,
                            **details,
                        }
                        success = True
                    elif action["action"] == "publish_poll":
                        poll_id = int(action["payload"].get("poll_id") or 0)
                        poll = self.database.get_poll(poll_id)
                        if poll is None or poll["status"] == "closed":
                            raise LookupError("Poll is unavailable or already closed")
                        if poll.get("message_id"):
                            result = {
                                "poll_id": poll_id,
                                "message_id": str(poll["message_id"]),
                                "already_published": True,
                            }
                            success = True
                            self.database.finish_dashboard_action(
                                action["id"],
                                success=True,
                                result=result,
                                **(
                                    {"claim_token": action["claim_token"]}
                                    if action.get("claim_token")
                                    else {}
                                ),
                            )
                            continue
                        server = await self._resolve_dashboard_server(
                            action["server_id"]
                        )
                        if server is None:
                            raise LookupError("Server is unavailable")
                        channel_id = str(poll["channel_id"])
                        channel = self.get_channel(channel_id) or await self.fetch_channel(channel_id)
                        if str(
                            getattr(channel, "server_id", action["server_id"])
                        ) != action["server_id"]:
                            raise PermissionError(
                                "Poll channel belongs to another server"
                            )
                        question = str(poll["question"])
                        options = poll["options"]
                        emojis = [str(item["emoji"]) for item in options]
                        choice_text = "Choose one option." if not poll["multiple_choice"] else "Choose one or more options."
                        audience_text = (
                            f" Voting requires role <@&{poll['required_role_id']}>."
                            if poll.get("required_role_id") else ""
                        )
                        quorum_text = (
                            f" Minimum voters: **{int(poll.get('quorum') or 0)}**."
                            if int(poll.get("quorum") or 0) else ""
                        )
                        poll_message = await channel.send(
                            embeds=[self._embed(
                                "Server poll",
                                f"**{question}**\n\n" + "\n".join(
                                    f"{item['emoji']} {item['label']}" for item in options
                                ) + f"\n\n{choice_text}{audience_text}{quorum_text} Reactions are monitored."
                                + (" Voter IDs are hidden in dashboard results, but reactions are visible in Stoat." if poll.get("anonymous") else ""),
                                "#5865F2",
                            )],
                            interactions=stoat.MessageInteractions(
                                emojis, restrict_reactions=True
                            ),
                        )
                        self.database.set_poll_message(poll_id, poll_message.id)
                        self.database.add_event(
                            server_id=server.id, event_type="poll_created",
                            actor_id=action["actor_id"], message_id=poll_message.id,
                            channel_id=channel_id,
                            details={"poll_id": poll_id, "question": question, "options": options},
                        )
                        result = {"poll_id": poll_id, "message_id": poll_message.id}
                        success = True
                    elif action["action"] == "close_poll":
                        poll_id = int(action["payload"].get("poll_id") or 0)
                        poll = self.database.get_poll(poll_id)
                        if poll is None:
                            raise LookupError("Poll is unavailable")
                        self.database.close_poll(poll_id)
                        poll = self.database.get_poll(poll_id) or poll
                        counts = {
                            option["emoji"]: sum(
                                option["emoji"] in choices
                                for choices in poll["votes"].values()
                            )
                            for option in poll["options"]
                        }
                        total = len(poll["votes"])
                        quorum = int(poll.get("quorum") or 0)
                        quorum_met = total >= quorum
                        lines = []
                        for option in poll["options"]:
                            count = counts[option["emoji"]]
                            percent = round((count / total) * 100) if total else 0
                            bars = "█" * round(percent / 10) + "░" * (10 - round(percent / 10))
                            lines.append(
                                f"{option['emoji']} **{option['label']}** — {count} ({percent}%)\n`{bars}`"
                            )
                        if poll.get("message_id"):
                            channel = self.get_channel(poll["channel_id"]) or await self.fetch_channel(poll["channel_id"])
                            poll_message = await channel.fetch_message(poll["message_id"])
                            await poll_message.edit(embeds=[self._embed(
                                "Poll closed", f"**{poll['question']}**\n\n" + "\n".join(lines)
                                + f"\n\n**Voters:** {total}"
                                + (f" / **Quorum:** {quorum} ({'met' if quorum_met else 'not met'})" if quorum else "")
                                + ("\n**Voter identities:** Hidden from dashboard results; Stoat reactions remain visible." if poll.get("anonymous") else ""),
                                "#747F8D"
                            )])
                        self.database.add_event(
                            server_id=poll["server_id"], event_type="poll_closed",
                            actor_id=action["actor_id"], message_id=poll.get("message_id"),
                            channel_id=poll["channel_id"],
                            details={"poll_id": poll_id, "responses": total, "results": counts, "quorum": quorum, "quorum_met": quorum_met},
                        )
                        result = {"poll_id": poll_id, "responses": total, "quorum_met": quorum_met}
                        success = True
                    elif action["action"] == "delete_poll_message":
                        channel_id = str(action["payload"].get("channel_id") or "")
                        message_id = str(action["payload"].get("message_id") or "")
                        if not channel_id or not message_id:
                            raise ValueError("Poll message details are missing")
                        channel = self.get_channel(channel_id) or await self.fetch_channel(channel_id)
                        poll_message = await channel.fetch_message(message_id)
                        await poll_message.delete()
                        result = {
                            "poll_id": int(action["payload"].get("poll_id") or 0),
                            "message_id": message_id,
                        }
                        success = True
                    elif action["action"] == "send_poll_reminder":
                        poll_id = int(action["payload"].get("poll_id") or 0)
                        poll = self.database.get_poll(poll_id)
                        if poll is None or poll["status"] != "open":
                            raise LookupError("Poll is unavailable or already closed")
                        channel = self.get_channel(poll["channel_id"]) or await self.fetch_channel(poll["channel_id"])
                        closes_at = str(poll.get("closes_at") or "soon")
                        await channel.send(
                            embeds=[self._embed(
                                "Poll closing soon",
                                f"**{poll['question']}**\n\nVote on the poll above before **{closes_at}**.",
                                "#F59E0B",
                            )]
                        )
                        self.database.add_event(
                            server_id=poll["server_id"], event_type="poll_reminder_sent",
                            actor_id=action["actor_id"], message_id=poll.get("message_id"),
                            channel_id=poll["channel_id"], details={"poll_id": poll_id},
                        )
                        result = {"poll_id": poll_id, "reminded": True}
                        success = True
                    elif action["action"] == "post_local_report_instructions":
                        server = await self._resolve_dashboard_server(
                            action["server_id"]
                        )
                        if server is None:
                            raise LookupError("Server is unavailable")
                        channel_id = str(action["payload"].get("channel_id") or "")
                        report_settings = self.database.get_local_report_settings(
                            action["server_id"]
                        )
                        if (
                            not report_settings.get("enabled")
                            or str(report_settings.get("channel_id") or "")
                            != channel_id
                        ):
                            raise LookupError(
                                "Server reporting setup changed before delivery"
                            )
                        channel = self.get_channel(channel_id) or await self.fetch_channel(channel_id)
                        if str(getattr(channel, "server_id", action["server_id"])) != action["server_id"]:
                            raise PermissionError(
                                "Instruction embed channel belongs to another server"
                            )
                        prompt = await channel.send(
                            embeds=[self._embed(
                                "Report a server violation",
                                "Keep evidence private. You can:\n\n"
                                "• DM me `~report`. If we share several reporting-enabled servers, I will ask which one.\n"
                                "• Send `~report` in any channel in this server. I will best-effort remove the command and send your private link by DM.\n\n"
                                "The secure form supports member, message, channel, server, and other reports. "
                                "Anonymous reports hide your identity from server staff when this server permits them.",
                                "#5865F2",
                            )]
                        )
                        if not self.database.set_local_report_instruction_message(
                            action["server_id"], channel_id, prompt.id
                        ):
                            try:
                                await prompt.delete()
                            except Exception:
                                logger.warning(
                                    "stale_local_report_instructions_delete_failed "
                                    "message_id=%s",
                                    prompt.id,
                                    exc_info=True,
                                )
                            raise RuntimeError(
                                "Server reporting setup changed during delivery"
                            )
                        result = {"channel_id": channel_id, "message_id": prompt.id}
                        success = True
                    elif action["action"] == "send_local_report_log":
                        report_id = int(action["payload"].get("report_id") or 0)
                        report = self.database.get_local_report(
                            action["server_id"], report_id
                        )
                        if report is None:
                            raise LookupError("Server report is unavailable")
                        reporter = (
                            "Anonymous"
                            if report.get("anonymous")
                            else str(report.get("reporter_username") or report.get("reporter_id") or "Unknown")
                        )
                        subject = str(
                            report.get("target_username")
                            or report.get("subject_text")
                            or report.get("target_user_id")
                            or report.get("subject_type")
                            or "Other"
                        )
                        report_reference = str(
                            report.get("reference_id") or report_id
                        )
                        await self.send_log(
                            action["server_id"],
                            f"New server report {report_reference}",
                            f"**Reporter:** {reporter}\n"
                            f"**Subject:** {subject}\n"
                            f"**Type:** {str(report.get('subject_type') or 'user').title()}\n"
                            f"**Reason:** {str(report.get('reason') or '')[:300]}\n\n"
                            "Open the server dashboard's report inbox for evidence and review.",
                            color="#F59E0B",
                            raise_on_error=True,
                        )
                        result = {
                            "report_id": report_id,
                            "report_reference": report_reference,
                            "logged": True,
                        }
                        success = True
                    elif action["action"] == "notify_report_update":
                        report_id = int(action["payload"].get("report_id") or 0)
                        report = self.database.get_report_for_notification(report_id)
                        if report is None:
                            raise LookupError("Report is unavailable")
                        report_reference = str(
                            report.get("reference_id") or report_id
                        )
                        destination = (
                            "The Stoatmod team"
                            if report.get("report_scope") == "global"
                            else "Server moderators"
                        )
                        delivered = await self._send_user_dm(
                            str(report["reporter_id"]),
                            "More information is needed for your report",
                            f"{destination} asked for more information about report "
                            f"`{report_reference}`.\n\n"
                            "Open the private receipt link you saved after submitting the report to read the request and respond.",
                            server_id=str(report["server_id"]),
                            color="#F59E0B",
                        )
                        if not delivered:
                            raise RuntimeError("The reporter could not be reached")
                        result = {"report_id": report_id, "notified": True}
                        success = True
                    elif action["action"] == "notify_appeal_update":
                        appeal_id = int(action["payload"].get("appeal_id") or 0)
                        appeal = self.database.get_appeal(appeal_id)
                        if appeal is None or appeal.get("server_id") != action["server_id"]:
                            raise LookupError("Appeal is unavailable")
                        delivered = await self._send_user_dm(
                            str(appeal["user_id"]),
                            "More information is needed for your appeal",
                            f"Moderators requested more information for case `{appeal['case_reference']}`.\n\n"
                            "Open the appeal portal with your original appeal code to read the request and respond.",
                            server_id=action["server_id"],
                            color="#F59E0B",
                        )
                        if not delivered:
                            raise RuntimeError("The appellant could not be reached")
                        result = {"appeal_id": appeal_id, "notified": True}
                        success = True
                    elif action["action"] == "send_settings_log":
                        changed = action["payload"].get("changed", {})
                        if "spam_settings" in changed or changed.get("spam_detection") is False:
                            self._clear_spam_state(action["server_id"])
                        labels = {
                            "locale": "Server language",
                            "join_protection": "Join protection",
                            "captcha_all_members": "CAPTCHA every member",
                            "warning_expiry_days": "Warning expiry",
                            "nickname_protection": "Nickname protection",
                            "link_protection": "Link protection",
                            "allow_gifs": "Allow GifBox links",
                            "join_limits": "Join protection options",
                            "spam_detection": "Spam detection",
                            "spam_settings": "Spam protection",
                            "image_scanning": "Image scanning",
                            "moderator_exemption": "Moderator exemption",
                            "moderation_threshold": "Moderation sensitivity",
                            "log_channel_id": "Moderation log channel",
                            "warning_policy": "Warning escalation",
                            "penalty_rules": "Penalty ladder",
                            "disabled_moderation_categories": "Moderation categories",
                            "auto_roles": "Automatic roles",
                            "exempt_channels": "Exempt channels",
                            "exempt_categories": "Exempt categories",
                        }
                        lines: list[str] = []
                        for key, value in changed.items():
                            if key == "retention_days":
                                continue  # Ignore queued updates for the retired setting.
                            label = labels.get(key, key.replace("_", " ").title())
                            if isinstance(value, bool):
                                display = "Enabled" if value else "Disabled"
                            elif key == "moderation_threshold":
                                display = f"{float(value):.0%}"
                            elif key == "log_channel_id":
                                display = f"<#{value}>"
                            elif key == "warning_policy" and isinstance(value, dict):
                                display = (
                                    f"timeout {value.get('timeout')}, "
                                    f"kick {value.get('kick')}, ban {value.get('ban')}"
                                )
                            elif key == "spam_settings" and isinstance(value, dict):
                                display = (
                                    f"repeat {value.get('repeat_count')} in "
                                    f"{value.get('repeat_window_seconds'):g}s; rapid "
                                    f"{value.get('rapid_count')} in "
                                    f"{value.get('rapid_window_seconds'):g}s; score "
                                    f"{value.get('score_threshold'):g}; mentions "
                                    f"{value.get('mass_mention_limit')}; timeout "
                                    f"{self._format_duration(int(value.get('timeout_seconds') or 0))}"
                                )
                            elif key == "join_limits" and isinstance(value, dict):
                                limited = [
                                    label
                                    for label, name in (("links", "links"), ("attachments", "attachments"))
                                    if value.get(name)
                                ]
                                display = (
                                    f"Enabled for {format_join_limit_duration(int(value.get('duration_seconds') or 0))}; "
                                    f"limits {' and '.join(limited) or 'nothing'}"
                                    if value.get("enabled")
                                    else "Disabled"
                                )
                            elif key == "disabled_moderation_categories" and isinstance(value, list):
                                display = (
                                    "Excluded: " + ", ".join(value)
                                    if value
                                    else "All configurable categories included"
                                )
                            elif key == "exempt_channels" and isinstance(value, list):
                                display = (
                                    ", ".join(f"<#{channel_id}>" for channel_id in value)
                                    or "None"
                                )
                            elif key == "exempt_categories" and isinstance(value, list):
                                display = (
                                    ", ".join(f"`{category_id}`" for category_id in value)
                                    or "None"
                                )
                            else:
                                display = str(value)
                            lines.append(f"**{label}:** {display}")
                        await self.send_log(
                            action["server_id"],
                            "Dashboard settings updated",
                            (
                                f"**Changed by:** <@{action['actor_id']}>\n"
                                + "\n".join(lines)
                            ),
                            color="#747F8D",
                        )
                        success = True
                    elif action["action"] == "send_dashboard_login_log":
                        await self.send_log(
                            action["server_id"],
                            "Moderator signed in to dashboard",
                            (
                                f"**Moderator:** <@{action['actor_id']}>\n"
                                f"**Session expires:** {action['payload'].get('expires_at')}"
                            ),
                            color="#747F8D",
                        )
                        success = True
                    elif action["action"] == "complete_join_verification":
                        # Legacy queued CAPTCHA actions must never remove an
                        # application restriction (including after a rejoin).
                        application_store = getattr(self.database, "applications", None)
                        if application_store is not None:
                            application_user = str(action["payload"].get("user_id") or action["actor_id"])
                            application = application_store.pending(action["server_id"], application_user)
                            if application is not None:
                                self.database.finish_dashboard_action(action["id"], success=True, result={"application": True},
                                    **({"claim_token": action["claim_token"]} if action.get("claim_token") else {}))
                                continue
                        server = self.get_server(action["server_id"])
                        if server is None:
                            raise LookupError("Server is unavailable")
                        user_id = str(action["payload"].get("user_id") or action["actor_id"])
                        member = server.get_member(user_id)
                        if member is None:
                            member = await server.fetch_member(user_id)
                        if not await self.require_action_permissions(
                            server, "timeout_members"
                        ):
                            raise PermissionError("Missing Timeout Members permission")
                        await member.timeout(None)
                        self.database.add_event(
                            server_id=action["server_id"],
                            event_type="join_captcha_passed",
                            user_id=user_id,
                            details={"method": "website"},
                        )
                        await self._send_user_dm(
                            user_id,
                            "Verification complete",
                            f"Your verification for **{server.name}** passed and your timeout was removed.",
                            server_id=action["server_id"],
                            user=member,
                            color="#3BA55D",
                        )
                        await self.send_log(
                            action["server_id"],
                            "Website join verification passed",
                            (
                                f"**User:** `{await self._resolve_user_tag(user_id, member)}`\n"
                                "**Checks:** Browser CAPTCHA and network risk scan\n"
                                "**Action:** One-day timeout removed"
                            ),
                            color="#3BA55D",
                        )
                        success = True
                    elif action["action"] == "handle_join_verification_failure":
                        application_store = getattr(self.database, "applications", None)
                        if application_store is not None:
                            application_user = str(action["payload"].get("user_id") or action["actor_id"])
                            application = application_store.pending(action["server_id"], application_user)
                            if application is not None and (
                                application["id"] != action["payload"].get("application_id")
                                or application["status"] != "screening"
                            ):
                                self.database.finish_dashboard_action(action["id"], success=True, result={"skipped": "Stale application check"},
                                    **({"claim_token": action["claim_token"]} if action.get("claim_token") else {}))
                                continue
                        server = self.get_server(action["server_id"])
                        if server is None:
                            raise LookupError("Server is unavailable")
                        user_id = str(action["payload"].get("user_id") or action["actor_id"])
                        attempt = int(action["payload"].get("attempt") or 1)
                        reason = str(action["payload"].get("reason") or "Verification failed")
                        member = server.get_member(user_id)
                        if member is None:
                            member = await server.fetch_member(user_id)
                        user_tag = await self._resolve_user_tag(user_id, member)
                        await self.send_log(
                            action["server_id"],
                            "Website join verification failed",
                            f"**User:** `{user_tag}`\n"
                            f"**Attempt:** {attempt}/3\n"
                            f"**Reason:** {reason}",
                            color="#F59E0B" if attempt < 3 else "#ED4245",
                        )
                        if bool(action["payload"].get("kick")):
                            kick_reason = str(
                                action["payload"].get("kick_reason")
                                or CAPTCHA_FAILED_ATTEMPTS_KICK_REASON
                            )
                            if not await self.require_action_permissions(
                                server, "kick_members"
                            ):
                                raise PermissionError("Missing Kick Members permission")
                            await self._send_user_dm(
                                user_id,
                                "Removed after failed verification",
                                f"You were removed from **{server.name}**.\n\n"
                                f"**Reason:** {kick_reason}.\n\n"
                                "You may rejoin and try again.",
                                server_id=action["server_id"],
                                user=member,
                                color="#ED4245",
                            )
                            await self._kick_member_with_reason(
                                member,
                                action["server_id"],
                                user_id,
                                kick_reason,
                            )
                            task = self._captcha_tasks.pop(
                                (action["server_id"], user_id), None
                            )
                            if task is not None:
                                task.cancel()
                            self.database.add_event(
                                server_id=action["server_id"],
                                event_type="join_captcha_kicked",
                                user_id=user_id,
                                details={
                                    "reason": kick_reason,
                                    "attempts": attempt,
                                },
                            )
                            await self.send_log(
                                action["server_id"],
                                "Member kicked after failed verification",
                                f"**User:** `{user_tag}`\n"
                                f"**Reason:** {kick_reason}\n"
                                "**Case created:** No",
                                color="#ED4245",
                            )
                        success = True
                    elif action["action"] == "send_case_entry_log":
                        await self.send_log(
                            action["server_id"],
                            "Case information updated",
                            f"**Case:** `CASE-{action['payload'].get('case_reference')}`\n"
                            f"**Added by:** <@{action['actor_id']}>\n"
                            f"**Type:** {str(action['payload'].get('entry_type')).title()}",
                            color="#747F8D",
                        )
                        success = True
                    elif action["action"] == "send_case_removed_log":
                        user_id = str(action["payload"].get("user_id") or "")
                        remaining = int(
                            action["payload"].get("remaining_warnings") or 0
                        )
                        await self.send_log(
                            action["server_id"],
                            "Moderation case removed from dashboard",
                            f"**Case:** `CASE-{action['payload'].get('case_reference')}`\n"
                            f"**User:** `{await self._resolve_user_tag(user_id)}`\n"
                            f"**Removed by:** <@{action['actor_id']}>\n"
                            f"**Original action:** {str(action['payload'].get('action')).replace('_', ' ').title()}\n"
                            f"**Original reason:** {action['payload'].get('reason')}\n"
                            f"**Remaining warnings:** {remaining}",
                            color="#3BA55D",
                        )
                        success = True
                    elif action["action"] == "send_appeal_submitted_log":
                        appeal = self.database.get_appeal(
                            int(action["payload"]["appeal_id"])
                        )
                        if (
                            appeal is None
                            or appeal["case_kind"] != "moderation"
                            or appeal["server_id"] != action["server_id"]
                        ):
                            raise LookupError("Appeal is unavailable")
                        evidence = appeal.get("evidence", {})
                        await self.send_log(
                            action["server_id"],
                            "New moderation appeal submitted",
                            f"**Case:** `CASE-{appeal['case_reference']}`\n"
                            f"**User:** <@{appeal['user_id']}>\n"
                            f"**Original action:** "
                            f"{str(evidence.get('action') or 'Unknown').replace('_', ' ').title()}\n"
                            f"**Original reason:** "
                            f"{evidence.get('moderator_reason') or 'No reason supplied'}\n"
                            f"**Appeal statement:**\n{appeal.get('statement') or 'No statement supplied'}\n\n"
                            "Review it in the moderator dashboard or use "
                            f"`~appeal CASE-{appeal['case_reference']} accept REASON` "
                            f"or `~appeal CASE-{appeal['case_reference']} deny REASON`.",
                            color="#F59E0B",
                        )
                        server_name = (
                            self.database.get_dashboard_server_name(
                                action["server_id"]
                            )
                            or "your server"
                        )
                        dashboard_base = str(
                            getattr(self.moderation_settings, "dashboard_url", "")
                        ).rstrip("/")
                        review_instruction = (
                            f"[Open Appeals in the moderator dashboard]({dashboard_base}/dashboard?view=appeals)."
                            if dashboard_base
                            else "Open Appeals in the moderator dashboard to review it."
                        )
                        notification = (
                            f"A member submitted a moderation appeal in **{server_name}**.\n\n"
                            f"**Case:** `CASE-{appeal['case_reference']}`\n"
                            f"**Member:** <@{appeal['user_id']}> (`{appeal['user_id']}`)\n"
                            f"**Original action:** "
                            f"{str(evidence.get('action') or 'Unknown').replace('_', ' ').title()}\n\n"
                            f"{review_instruction}"
                        )
                        notified = 0
                        failed = 0
                        for moderator_id in (
                            self.database.appeal_notification_recipients(
                                action["server_id"]
                            )
                        ):
                            try:
                                delivered = await self._send_user_dm(
                                    moderator_id,
                                    f"New moderation appeal · {server_name}",
                                    notification,
                                    server_id=action["server_id"],
                                    color="#F59E0B",
                                    sensitive=True,
                                )
                            except Exception:
                                logger.warning(
                                    "appeal_moderator_dm_failed appeal_id=%s",
                                    appeal["id"],
                                )
                                delivered = False
                            if delivered:
                                notified += 1
                            else:
                                failed += 1
                        result = {
                            "moderator_dms_sent": notified,
                            "moderator_dms_failed": failed,
                        }
                        success = True
                    elif action["action"] == "owner_global_ban":
                        user_id = str(action["payload"]["user_id"])
                        reference_id = str(action["payload"]["reference_id"])
                        reason = str(action["payload"]["reason"])
                        if user_id == self.state.my_id:
                            self.database.remove_global_ban(user_id)
                            raise ValueError("The bot cannot be globally banned")
                        await self._send_user_dm(
                            user_id,
                            "You have been globally banned",
                            "You have been banned from all servers containing this bot.\n\n"
                            f"**Reference ID:** `{reference_id}`\n**Reason:** {reason}"
                            f"{self._global_ban_contact_instructions()}",
                            server_id=action["server_id"],
                        )
                        succeeded, failed = await self._apply_global_ban_to_servers(
                            user_id,
                            reason,
                            reference_id=reference_id,
                            actor_id=action["actor_id"],
                            source="owner_dashboard",
                        )
                        result = {"servers_updated": len(succeeded), "servers_failed": len(failed)}
                        success = True
                    elif action["action"] == "owner_global_unban":
                        user_id = str(action["payload"]["user_id"])
                        reference_id = str(action["payload"]["reference_id"])
                        succeeded, failed = await self._apply_global_ban_to_servers(
                            user_id, "", unban=True, reference_id=reference_id
                        )
                        await self._send_user_dm(
                            user_id,
                            "Your global ban was removed",
                            f"Global ban `{reference_id}` was removed from your record.",
                            server_id=action["server_id"],
                            color="#3BA55D",
                        )
                        result = {"servers_updated": len(succeeded), "servers_failed": len(failed)}
                        success = True
                    elif action["action"] == "notify_report_outcome":
                        report_id = int(action["payload"]["report_id"])
                        try:
                            result = await self._notify_report_outcome(report_id)
                            success = True
                        except ReportNotificationDeliveryError as exc:
                            try:
                                retries_used = max(
                                    0, int(action["payload"].get("retry_count") or 0)
                                )
                            except (TypeError, ValueError):
                                retries_used = 0
                            if retries_used >= len(REPORT_NOTIFICATION_RETRY_DELAYS):
                                self.database.mark_reporter_notification(
                                    report_id, success=False, error=str(exc)
                                )
                                raise
                            retry_number = retries_used + 1
                            delay_seconds = REPORT_NOTIFICATION_RETRY_DELAYS[
                                retries_used
                            ]
                            retry_payload = {
                                **action["payload"],
                                "retry_count": retry_number,
                            }
                            retry_message = (
                                f"Delivery attempt {retry_number} failed. "
                                f"Automatic retry {retry_number} of "
                                f"{len(REPORT_NOTIFICATION_RETRY_DELAYS)} is scheduled."
                            )
                            if not self.database.defer_report_notification_action(
                                action["id"],
                                report_id,
                                payload=retry_payload,
                                delay_seconds=delay_seconds,
                                error=retry_message,
                                **(
                                    {"claim_token": action["claim_token"]}
                                    if action.get("claim_token")
                                    else {}
                                ),
                            ):
                                self.database.mark_reporter_notification(
                                    report_id, success=False, error=str(exc)
                                )
                                raise RuntimeError(
                                    "The report notification retry could not be queued."
                                ) from exc
                            logger.warning(
                                "report_outcome_notification_retry_scheduled "
                                "report_id=%s retry=%s delay_seconds=%s",
                                report_id,
                                retry_number,
                                delay_seconds,
                            )
                            continue
                    elif action["action"] == "log_automatic_appeal_decision":
                        appeal_id = int(action["payload"]["appeal_id"])
                        appeal = self.database.get_appeal(appeal_id)
                        if (
                            appeal is None
                            or appeal["case_kind"] != "moderation"
                            or appeal["server_id"] != action["server_id"]
                            or appeal["status"] != "denied"
                            or appeal.get("reviewer_id") != "STOATMOD_APPEAL_TIMEOUT"
                        ):
                            raise LookupError("Automatic appeal decision is unavailable")
                        if self.database.get_log_channel(action["server_id"]):
                            await self.send_log(
                                action["server_id"],
                                "Appeal automatically rejected",
                                f"**Case:** `CASE-{appeal['case_reference']}`\n"
                                f"**User:** <@{appeal['user_id']}>\n"
                                "**Decided by:** Stoatmod (automatic)\n"
                                "**Reason:** No decision was made within 10 days of submission.\n"
                                "**Outcome:** The original moderation decision remains in place.\n"
                                "**Content:** The moderated message and appeal content have been "
                                "deleted from Stoatmod's database and files.",
                                color="#ED4245",
                                raise_on_error=True,
                            )
                            result = {"appeal_id": appeal_id, "logged": True}
                        else:
                            result = {"appeal_id": appeal_id, "skipped": "No moderation log channel is configured"}
                        success = True
                    elif action["action"] == "resolve_appeal":
                        appeal_id = int(action["payload"]["appeal_id"])
                        appeal = self.database.get_appeal(appeal_id)
                        if appeal is None:
                            raise LookupError("Appeal is unavailable")
                        if appeal["case_kind"] != "moderation":
                            raise LookupError("Global bans are not eligible for appeals")
                        if appeal["server_id"] != action["server_id"]:
                            raise LookupError("Appeal is unavailable in this server")
                        decision = str(action["payload"]["decision"])
                        automatic = appeal.get("reviewer_id") == "STOATMOD_APPEAL_TIMEOUT"
                        evidence = appeal.get("evidence", {})
                        user_id = str(appeal["user_id"])
                        reversed_action = "No moderation record was changed"
                        if decision == "approved":
                            appeal_server_id = str(appeal["server_id"])
                            server = self.get_server(appeal_server_id)
                            case_action = str(evidence.get("action") or "")
                            if case_action == "warning":
                                self.database.remove_moderation_case(
                                    appeal_server_id,
                                    str(appeal["case_reference"]),
                                )
                                reversed_action = "Warning removed"
                            elif case_action in {"timeout", "warning_and_timeout"}:
                                if server is None:
                                    raise LookupError("Server is unavailable")
                                if not await self.require_action_permissions(
                                    server, "timeout_members"
                                ):
                                    raise PermissionError(
                                        "Missing Timeout Members permission"
                                    )
                                member = server.get_member(user_id)
                                if member is None:
                                    member = await server.fetch_member(user_id)
                                await member.timeout(None)
                                reversed_action = "Timeout removed"
                                if case_action == "warning_and_timeout":
                                    self.database.remove_moderation_case(
                                        appeal_server_id, str(appeal["case_reference"])
                                    )
                                    reversed_action = "Warning and timeout removed"
                            elif case_action == "ban":
                                if server is None:
                                    raise LookupError("Server is unavailable")
                                if not await self.require_action_permissions(
                                    server, "ban_members"
                                ):
                                    raise PermissionError(
                                        "Missing Ban Members permission"
                                    )
                                await server.unban(user_id)
                                reversed_action = "Server ban removed"
                        response = str(appeal.get("reviewer_response") or "")
                        title = "Appeal automatically rejected" if automatic else f"Appeal {decision}"
                        response_label = "Reason" if automatic else "Moderator response"
                        await self._send_user_dm(
                            user_id,
                            title,
                            f"**Case:** `{appeal['case_reference']}`\n"
                            f"**Decision:** {decision.title()}\n"
                            f"**{response_label}:** {response}\n"
                            f"**Outcome:** {reversed_action}",
                            server_id=(
                                str(appeal["server_id"])
                                if appeal.get("server_id")
                                else None
                            ),
                            color="#3BA55D" if decision == "approved" else "#ED4245",
                        )
                        # New automatic decisions have a separate, retryable log
                        # action. Keep the inline path for manual and older jobs.
                        if not (automatic and action["payload"].get("automatic_log_queued")):
                            reviewer = "Stoatmod (automatic)" if automatic else f"<@{action['actor_id']}>"
                            await self.send_log(
                                str(appeal["server_id"]),
                                title,
                                f"**Case:** `{appeal['case_reference']}`\n"
                                f"**User:** <@{user_id}>\n"
                                f"**Reviewed by:** {reviewer}\n"
                                f"**Reason:** {response}\n"
                                f"**Outcome:** {reversed_action}",
                                color="#3BA55D" if decision == "approved" else "#ED4245",
                            )
                        result = {"outcome": reversed_action}
                        success = True
                    else:
                        result = {"error": "Unknown dashboard action"}
                except Exception as exc:
                    result = {"error": str(exc)}
                    if action["action"] == "deliver_admin_credentials":
                        # Transport errors can contain the outgoing DM. Never persist
                        # or log their text, since this message includes a password.
                        result = {"error": "Credential delivery failed or was replaced. Access remains disabled."}
                        retries = min(12, max(0, int(action["payload"].get("retry_count") or 0)))
                        delay = min(3600, 300 * (2 ** retries))
                        if action.get("claim_token") and self.database.defer_admin_credential_delivery(
                            action["id"], claim_token=action["claim_token"],
                            retry_count=retries + 1, delay_seconds=delay,
                        ):
                            logger.warning("admin_credential_retry_scheduled action_id=%s delay_seconds=%s", action["id"], delay)
                            continue
                    if action["action"] in DASHBOARD_DELIVERY_ACTIONS:
                        try:
                            retries_used = max(
                                0, int(action["payload"].get("retry_count") or 0)
                            )
                        except (TypeError, ValueError):
                            retries_used = 0
                        if retries_used < len(DASHBOARD_DELIVERY_RETRY_DELAYS):
                            retry_number = retries_used + 1
                            delay_seconds = DASHBOARD_DELIVERY_RETRY_DELAYS[
                                retries_used
                            ]
                            retry_payload = {
                                **action["payload"],
                                "retry_count": retry_number,
                            }
                            retry_message = (
                                f"Delivery attempt {retry_number} failed. "
                                f"Automatic retry {retry_number} of "
                                f"{len(DASHBOARD_DELIVERY_RETRY_DELAYS)} is scheduled: "
                                f"{exc}"
                            )
                            if self.database.defer_dashboard_action(
                                action["id"],
                                payload=retry_payload,
                                delay_seconds=delay_seconds,
                                error=retry_message,
                                **(
                                    {"claim_token": action["claim_token"]}
                                    if action.get("claim_token")
                                    else {}
                                ),
                            ):
                                logger.warning(
                                    "dashboard_delivery_retry_scheduled "
                                    "action_id=%s action=%s retry=%s delay_seconds=%s",
                                    action["id"],
                                    action["action"],
                                    retry_number,
                                    delay_seconds,
                                )
                                continue
                    # Support invites are private global-owner operations. Their result
                    # is returned only through the protected owner dashboard and must
                    # not announce the attempt to server logs, admins, DMs, or bot logs.
                    if action["action"] not in {
                        "create_server_invite",
                        "get_random_server_invite",
                        "deliver_admin_credentials",
                    }:
                        logger.exception(
                            "dashboard_action_failed action_id=%s action=%s",
                            action["id"],
                            action["action"],
                        )
                finished = self.database.finish_dashboard_action(
                    action["id"],
                    success=success,
                    result=result,
                    **(
                        {"claim_token": action["claim_token"]}
                        if action.get("claim_token")
                        else {}
                    ),
                )
                if success and finished and purge_server_after_finish:
                    try:
                        deleted = self.database.purge_server_data(
                            purge_server_after_finish
                        )
                        self.update_bot_heartbeat(
                            self.database.get_public_dashboard_stats()["server_count"]
                        )
                        logger.info(
                            "blacklisted_server_data_purged server_id=%s records=%d tables=%d",
                            purge_server_after_finish,
                            sum(deleted.values()),
                            len(deleted),
                        )
                    except Exception:
                        logger.exception(
                            "blacklisted_server_data_purge_failed server_id=%s",
                            purge_server_after_finish,
                        )
            await asyncio.sleep(5)

    async def _get_owner_server_invite(
        self, server: stoat.Server
    ) -> dict[str, str]:
        """Return one random active invite without notifying the target server."""
        fetch_invites = getattr(server, "fetch_invites", None)
        if not callable(fetch_invites):
            raise RuntimeError("Stoat cannot retrieve invites for this server.")
        try:
            invites = await fetch_invites()
        except Exception as exc:
            error_type = str(getattr(exc, "type", "") or "")
            error_text = str(exc)
            if error_type == "MissingPermission" or error_text.startswith(
                "MissingPermission"
            ):
                raise RuntimeError(
                    "Stoatmod cannot view this server's active invites because it "
                    "does not have Manage Server permission."
                ) from None
            raise RuntimeError(
                "Stoat could not retrieve this server's active invites."
                + (f" {error_text}" if error_text else "")
            ) from None
        active_invites = [
            invite
            for invite in invites
            if str(getattr(invite, "code", "") or "").strip()
        ]
        if not active_invites:
            raise RuntimeError("This server has no active invites.")
        invite = secrets.choice(active_invites)
        code = str(getattr(invite, "code", "") or "").strip()
        return {
            "invite_url": f"https://stt.gg/{code}",
            "channel_id": str(getattr(invite, "channel_id", "") or ""),
        }

    async def _resolve_dashboard_server(
        self, server_id: str
    ) -> stoat.Server | None:
        """Resolve a dashboard target from Ready state, cache, or Stoat's API."""
        ready_event_servers = getattr(self, "_ready_event_servers", None)
        if ready_event_servers is not None:
            return ready_event_servers.get(server_id)
        server = self.get_server(server_id)
        if server is not None:
            return server
        try:
            return await self.fetch_server(server_id)
        except stoat.NotFound:
            # A NotFound response confirms that the bot is no longer able to
            # resolve the server as a member. Other API failures must propagate
            # so callers do not mistake an outage for a completed departure.
            return None

    async def _enforce_server_blacklist(
        self,
        server: stoat.Server | None,
        blacklist: dict[str, object],
        *,
        source: str,
    ) -> dict[str, object]:
        """Notify the stored owner and leave a persistently blacklisted server."""
        server_id = str(blacklist.get("server_id") or getattr(server, "id", ""))
        server_name = str(
            getattr(server, "name", "")
            or blacklist.get("server_name")
            or "this server"
        )
        owner_id = str(
            getattr(server, "owner_id", "") or blacklist.get("owner_id") or ""
        )
        reason = str(blacklist.get("reason") or "No reason was provided.")
        if server is not None and owner_id == self.state.my_id:
            raise RuntimeError(
                "Stoatmod owns this server and cannot leave without deleting it."
            )

        owner_notified = False
        if owner_id:
            owner_notified = await self._send_user_dm(
                owner_id,
                "Your server has been blacklisted",
                f"Stoatmod cannot remain in **{server_name}** because the server "
                "has been blacklisted. It will leave immediately, or is already "
                "absent.\n\n"
                f"**Reason:** {reason}\n\n"
                f"If you have any questions, contact `{SUPPORT_EMAIL}`.",
                server_id=server_id or None,
                color="#ED4245",
            )

        left = False
        already_departed = server is None
        if server is not None:
            try:
                await server.leave(silent=True)
                left = True
            except stoat.NotFound:
                # The server or the bot's membership disappeared between the
                # live lookup and the DELETE request. The desired state is
                # already satisfied, so this is a confirmed idempotent success.
                already_departed = True
        self._track_status_server(server_id, connected=False)
        logger.warning(
            "server_blacklist_enforced server_id=%s source=%s "
            "owner_notified=%s left=%s already_departed=%s",
            server_id,
            source,
            owner_notified,
            left,
            already_departed,
        )
        return {
            "server_id": server_id,
            "owner_id": owner_id,
            "owner_notified": owner_notified,
            "left": left,
            "already_departed": already_departed,
        }

    async def reject_blacklisted_server(
        self, server: stoat.Server, *, source: str
    ) -> bool:
        """Immediately reject a blacklisted connection before any setup runs."""
        blacklist = self.database.get_server_blacklist(server.id)
        if blacklist is None:
            return False
        try:
            await self._enforce_server_blacklist(server, blacklist, source=source)
            deleted = self.database.purge_server_data(server.id)
            self.update_bot_heartbeat(
                self.database.get_public_dashboard_stats()["server_count"]
            )
            logger.info(
                "blacklisted_server_rejoin_purged server_id=%s records=%d tables=%d",
                server.id,
                sum(deleted.values()),
                len(deleted),
            )
        except Exception:
            logger.exception(
                "server_blacklist_enforcement_failed server_id=%s source=%s",
                server.id,
                source,
            )
        return True


    async def _automation_conditions_match(
        self, message: stoat.Message, server: stoat.Server, rule: dict[str, object]
    ) -> bool:
        conditions = rule.get("conditions") or []
        if not conditions:
            return True
        user = message.get_author_as_user()
        if user is None:
            try:
                user = self.get_user(message.author_id) or await self.fetch_user(message.author_id)
            except Exception:
                user = None
        member = server.get_member(message.author_id)
        if member is None:
            try:
                member = await server.fetch_member(message.author_id)
            except Exception:
                member = None
        username = str(getattr(user, "name", "") or "")
        raw_nickname = getattr(member, "nick", None)
        nickname = "" if raw_nickname is None or raw_nickname is stoat.UNDEFINED else str(raw_nickname)
        content = message.content or ""
        role_ids = {str(value) for value in (getattr(member, "role_ids", None) or [])}
        mentions = getattr(message, "mentions", None) or []
        account_created = getattr(user, "created_at", None)

        def matches(condition: dict[str, object]) -> bool:
            condition_type = str(condition.get("type") or "")
            value = str(condition.get("value") or "")
            folded = value.casefold()
            if condition_type == "username_contains": return folded in username.casefold()
            if condition_type == "username_equals": return folded == username.casefold()
            if condition_type == "nickname_contains": return folded in nickname.casefold()
            if condition_type == "nickname_equals": return folded == nickname.casefold()
            if condition_type == "channel_is": return value == message.channel_id
            if condition_type == "role_has": return value in role_ids
            if condition_type == "message_contains": return folded in content.casefold()
            if condition_type == "message_starts_with": return content.casefold().startswith(folded)
            if condition_type == "message_ends_with": return content.casefold().endswith(folded)
            if condition_type == "message_length_min": return len(content) >= int(value)
            if condition_type == "message_length_max": return len(content) <= int(value)
            if condition_type == "mention_count_min": return len(mentions) >= int(value)
            if condition_type == "has_embed": return bool(message.embeds)
            if condition_type == "account_age_days_max":
                return bool(account_created) and (
                    datetime.now(timezone.utc) - account_created
                ) <= timedelta(days=int(value))
            return False

        results = [matches(condition) for condition in conditions]
        return any(results) if rule.get("condition_mode") == "any" else all(results)

    async def handle_dashboard_automations(self, message: stoat.Message) -> bool:
        """Run rules configured exclusively through the server dashboard."""
        server, server_id = message.get_server()
        if server is None or not server_id:
            return False
        list_rules = getattr(self.database, "list_automation_rules", None)
        if not callable(list_rules):
            return False
        deleted = False
        content = message.content or ""
        for rule in list_rules(server_id):
            if not rule.get("enabled"):
                continue
            trigger = rule.get("trigger_type")
            trigger_value = str(rule.get("trigger_value") or "")
            matched = (
                trigger == "every_message"
                or (trigger == "keyword" and trigger_value.casefold() in content.casefold())
                or (
                    trigger == "contains_link"
                    and self._contains_filterable_link(
                        content,
                        allow_gifs=self._server_allows_gifs(server_id),
                    )
                )
                or (trigger == "has_attachment" and bool(message.attachments))
            )
            if not matched:
                continue
            if not await self._automation_conditions_match(message, server, rule):
                continue
            actions = rule.get("actions") or [
                {
                    "type": str(rule.get("action_type") or ""),
                    "config": rule.get("action_config") or {},
                }
            ]
            applied_actions: list[str] = []
            try:
                for configured_action in actions:
                    action = str(configured_action.get("type") or "")
                    config = configured_action.get("config") or {}
                    reason = str(config.get("message") or f"Dashboard automation: {rule['name']}")
                    if action == "delete_message":
                        if deleted:
                            continue
                        if not await self.require_action_permissions(server, "manage_messages"):
                            raise PermissionError("Missing Manage Messages permission")
                        await message.delete()
                        deleted = True
                    elif action == "warn":
                        member = server.get_member(message.author_id)
                        if member is None:
                            member = await server.fetch_member(message.author_id)
                        if self._moderator_is_exempt(server_id, server, member):
                            raise PermissionError("Elevated members are exempt from automation warnings")
                        warning_id = self.database.add_warning(
                            server_id=server_id, user_id=message.author_id,
                            moderator_id=self.state.my_id, source="automation",
                            reason=reason, message_id=message.id,
                            channel_id=message.channel_id, original_content=content,
                        )
                        await self.enforce_warning_policy(
                            server, server_id, message.author_id, warning_id,
                            self._active_warning_count(server_id, message.author_id),
                        )
                    elif action == "timeout":
                        member = server.get_member(message.author_id) or await server.fetch_member(message.author_id)
                        if self._moderator_is_exempt(server_id, server, member):
                            raise PermissionError("Elevated members are exempt from automation timeouts")
                        if not await self.require_action_permissions(server, "timeout_members"):
                            raise PermissionError("Missing Timeout Members permission")
                        await member.timeout(
                            timedelta(seconds=int(config.get("duration_seconds") or 3600))
                        )
                    elif action == "send_reply":
                        await message.channel.send(content=reason)
                    elif action == "send_log":
                        await self.send_log(
                            server_id, f"Automation: {rule['name']}",
                            f"**User:** `{await self._resolve_user_tag(message.author_id)}`\n"
                            f"**Channel:** <#{message.channel_id}>\n**Message:** {reason}",
                            color="#F59E0B",
                        )
                    else:
                        raise ValueError(f"Unsupported automation action: {action}")
                    applied_actions.append(action)
                record_execution = getattr(
                    self.database, "record_automation_execution", None
                )
                if callable(record_execution):
                    record_execution(int(rule["id"]), success=True)
                self.database.add_event(
                    server_id=server_id, event_type="automation_executed",
                    user_id=message.author_id,
                    actor_id=getattr(getattr(self, "_state", None), "my_id", None),
                    message_id=message.id, channel_id=message.channel_id,
                    details={
                        "automation_id": rule["id"], "name": rule["name"],
                        "trigger_type": trigger, "actions": applied_actions,
                        "condition_mode": rule.get("condition_mode", "all"),
                        "conditions": rule.get("conditions", []),
                        "original_content": content,
                    },
                )
            except Exception as exc:
                record_execution = getattr(
                    self.database, "record_automation_execution", None
                )
                if callable(record_execution):
                    record_execution(
                        int(rule["id"]), success=False, error=str(exc)
                    )
                self.database.add_event(
                    server_id=server_id, event_type="automation_failed",
                    user_id=message.author_id,
                    actor_id=getattr(getattr(self, "_state", None), "my_id", None),
                    message_id=message.id, channel_id=message.channel_id,
                    details={
                        "automation_id": rule["id"], "name": rule["name"],
                        "error": str(exc)[:500], "applied_actions": applied_actions,
                    },
                )
                logger.exception(
                    "automation_execution_failed server_id=%s rule_id=%s",
                    server_id, rule.get("id"),
                )
        return deleted

    def _status_rotation_stopped(self, task: asyncio.Task[None]) -> None:
        if task is not self._status_task:
            return
        self._status_task = None
        if self._closing:
            return
        if not task.cancelled():
            error = task.exception()
            if error is not None:
                logger.error(
                    "status_rotation_task_crashed", exc_info=error
                )
        logger.warning(
            "status_rotation_restarting delay_seconds=%s",
            STATUS_RESTART_DELAY_SECONDS,
        )
        asyncio.get_running_loop().call_later(
            STATUS_RESTART_DELAY_SECONDS, self._restart_status_rotation
        )

    def _dashboard_action_worker_stopped(
        self, task: asyncio.Task[None]
    ) -> None:
        if task is not self._dashboard_action_task:
            return
        self._dashboard_action_task = None
        if self._closing:
            return
        if not task.cancelled():
            error = task.exception()
            if error is not None:
                logger.error(
                    "dashboard_action_worker_crashed", exc_info=error
                )
        logger.warning(
            "dashboard_action_worker_restarting delay_seconds=%s",
            DASHBOARD_ACTION_RESTART_DELAY_SECONDS,
        )
        asyncio.get_running_loop().call_later(
            DASHBOARD_ACTION_RESTART_DELAY_SECONDS,
            self._restart_dashboard_action_worker,
        )

    def _restart_dashboard_action_worker(self) -> None:
        if self._closing:
            return
        self.start_dashboard_action_worker()

    def _restart_status_rotation(self) -> None:
        if self._closing or self._status_user is None:
            return
        self.start_status_rotation(self._status_user)

    @staticmethod
    def _status_clock() -> float:
        return time.monotonic()

    async def _wait_for_status_edit_slot(self) -> None:
        now = self._status_clock()
        last_attempt = getattr(self, "_last_status_update_attempt", None)
        if last_attempt is not None:
            remaining = (
                STATUS_MIN_UPDATE_INTERVAL_SECONDS - (now - last_attempt)
            )
            if remaining > 0:
                logger.info(
                    "status_rotation_local_ratelimit delay_seconds=%.3f",
                    remaining,
                )
                await asyncio.sleep(remaining)
                now = self._status_clock()
        # Count attempts rather than successes because rejected HTTP calls also
        # consume Stoat's user-edit bucket.
        self._last_status_update_attempt = now

    async def _update_rotating_status(self) -> str:
        user = self._status_user
        if user is None:
            raise RuntimeError("Status rotation started without a current user")
        statuses = self.rotating_statuses()
        if not statuses:
            raise RuntimeError("Status rotation has no configured statuses")
        status_text = statuses[self._status_index % len(statuses)]
        await self._wait_for_status_edit_slot()
        await asyncio.wait_for(
            user.edit(
                status=stoat.UserStatusEdit(
                    text=status_text,
                    presence=stoat.Presence.online,
                )
            ),
            timeout=STATUS_UPDATE_TIMEOUT_SECONDS,
        )
        self._status_index = (self._status_index + 1) % len(statuses)
        return status_text

    async def _rotate_status(self) -> None:
        while True:
            try:
                await self._update_rotating_status()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("status_rotation_update_failed")
            await asyncio.sleep(STATUS_ROTATION_SECONDS)

    def dispatch_scan(self, message: stoat.Message) -> None:
        task = asyncio.create_task(self.scan_message(message))
        self._tasks.add(task)
        task.add_done_callback(self._scan_task_stopped)

    def _scan_task_stopped(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            logger.error("scan_task_crashed", exc_info=error)

    def message_is_in_scope(self, message: stoat.Message) -> bool:
        if message.author_id == self.state.my_id or message.webhook is not None:
            return False
        if self.moderation_settings.channel_ids and message.channel_id not in self.moderation_settings.channel_ids:
            return False
        server, server_id = message.get_server()
        if server is None or not server_id:
            return False
        if self.moderation_settings.server_ids and server_id not in self.moderation_settings.server_ids:
            return False
        channel = self.get_channel(message.channel_id)
        if self._channel_is_nsfw(channel):
            return False
        category_id = self._category_id_for_channel(
            server, message.channel_id, channel
        )
        if self.database.is_scope_excluded(
            server_id, message.channel_id, category_id
        ):
            return False
        return True

    @staticmethod
    def _channel_is_nsfw(channel: object | None) -> bool:
        return bool(getattr(channel, "nsfw", False))

    @staticmethod
    def _category_id_for_channel(
        server: stoat.Server, channel_id: str, channel: object | None
    ) -> str | None:
        category_id = getattr(channel, "category_id", None)
        if category_id:
            return category_id

        for category in server.categories or ():
            if channel_id in category.channels:
                return category.id
        return None

    @staticmethod
    def _parse_user_id(raw: str) -> str:
        value = raw.strip()
        if value.startswith("<@") and value.endswith(">"):
            value = value[2:-1]
        return value

    @staticmethod
    def _user_is_bot(user: object | None) -> bool:
        return user is not None and getattr(user, "bot", None) is not None

    @staticmethod
    def _parse_channel_id(raw: str) -> str:
        value = raw.strip()
        if value.startswith("<#") and value.endswith(">"):
            value = value[2:-1]
        return value

    @staticmethod
    def _parse_role_id(raw: str) -> str:
        value = raw.strip()
        if value.startswith("<@&") and value.endswith(">"):
            value = value[3:-1]
        return value

    @staticmethod
    def _parse_duration(raw: str) -> int | None:
        pattern = r"(\d{1,8})\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w)"
        value = raw.strip().lower()
        if not re.fullmatch(rf"(?:{pattern}\s*)+", value):
            return None
        multipliers = {
            "s": 1,
            "m": 60,
            "h": 60 * 60,
            "d": 24 * 60 * 60,
            "w": 7 * 24 * 60 * 60,
        }
        seconds = sum(
            int(amount) * multipliers[unit[0]]
            for amount, unit in re.findall(pattern, value)
        )
        return seconds if 0 < seconds <= 28 * 24 * 60 * 60 else None

    @classmethod
    def _parse_mute_arguments(cls, raw: str) -> tuple[int, str]:
        """Accept an optional duration at either end, preserving the reason."""
        words = raw.split()
        duration_pattern = (
            r"(?:\d+\s*(?:seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w)\s*)+"
        )

        def edge_duration(tokens: list[str]) -> tuple[int, int, str] | None:
            for size in range(len(tokens), 0, -1):
                for start in (0, len(tokens) - size):
                    value = " ".join(tokens[start:start + size])
                    if re.fullmatch(duration_pattern, value, re.I):
                        return start, size, value
            return None

        duration = 3600
        match = edge_duration(words)
        if match is not None:
            start, size, value = match
            parsed = cls._parse_duration(value)
            if parsed is None:
                raise ValueError("Mute duration must be greater than zero and at most 4 weeks.")
            duration = parsed
            words = words[:start] + words[start + size:]
            if edge_duration(words) is not None:
                raise ValueError("Put one duration before or after the reason, not at both ends.")
        elif words and any(
            re.fullmatch(r"[+-]?\d[\da-z.]*[a-z]", word, re.I)
            for word in (words[0], words[-1])
        ):
            raise ValueError("Use a duration such as 25m, 2h, 1h30m, or 25 minutes (maximum 4 weeks).")
        reason = " ".join(words).strip()
        if not reason or not reason.strip("`\"' \t\r\n"):
            raise ValueError("A reason is required. Add it before or after the duration.")
        return duration, reason

    async def _require_command_reason(self, message: stoat.Message, command: str, parts: list[str]) -> str | None:
        reason = " ".join(parts[2:]).strip()
        if reason and reason.strip("`\"' \t\r\n"):
            return reason
        usage = SERVER_COMMAND_USAGES.get(command) or GLOBAL_COMMAND_USAGES[command]
        await self.send_command_response(
            message, "Reason required", f"A reason is required.\n\nUsage: `{usage}`",
            color="#F59E0B",
        )
        return None

    @staticmethod
    def _format_duration(seconds: int) -> str:
        for unit_seconds, label in (
            (7 * 24 * 60 * 60, "week"),
            (24 * 60 * 60, "day"),
            (60 * 60, "hour"),
            (60, "minute"),
        ):
            if seconds % unit_seconds == 0:
                amount = seconds // unit_seconds
                return f"{amount} {label}{'' if amount == 1 else 's'}"
        return f"{seconds} second{'' if seconds == 1 else 's'}"

    @staticmethod
    def _parse_policy_counts(raw: str) -> tuple[int, int, int] | None:
        values = raw.split()
        if len(values) != 3:
            return None
        try:
            timeout_count, kick_count, ban_count = map(int, values)
        except ValueError:
            return None
        if not 1 <= timeout_count < kick_count < ban_count:
            return None
        return timeout_count, kick_count, ban_count

    @staticmethod
    def _parse_threshold_percentage(raw: str) -> float | None:
        value = raw.strip().removesuffix("%").strip()
        try:
            percentage = float(value)
        except ValueError:
            return None
        if not 0 <= percentage <= 100:
            return None
        return percentage / 100

    @staticmethod
    def _format_threshold_percentage(threshold: float) -> str:
        return f"{threshold * 100:g}%"

    @staticmethod
    def _policy_description(policy: WarningPolicy) -> str:
        return (
            f"**{policy.timeout_count} warnings:** one-hour timeout\n"
            f"**{policy.kick_count} warnings:** kick\n"
            f"**{policy.ban_count} warnings:** ban"
        )

    @staticmethod
    def _normalize_moderation_category(value: str) -> str:
        return value.strip().casefold().replace("_", "-")

    @staticmethod
    def _category_is_always_protected(category: str) -> bool:
        normalized = ModerationBot._normalize_moderation_category(category)
        return any(
            normalized == prefix or normalized.startswith(f"{prefix}/")
            for prefix in PROTECTED_MODERATION_CATEGORY_PREFIXES
        )

    @staticmethod
    def _protected_category_action(category: str) -> str:
        normalized = ModerationBot._normalize_moderation_category(category)
        return "self_harm" if normalized == SUPPORT_CATEGORY else "observe"

    def _category_is_enabled(self, server_id: str, category: str) -> bool:
        normalized = self._normalize_moderation_category(category)
        return self._category_is_always_protected(normalized) or not (
            self.database.is_moderation_category_disabled(server_id, normalized)
        )

    def _moderation_threshold(self, server_id: str) -> float:
        getter = getattr(self.database, "get_moderation_threshold", None)
        if getter is None:
            return self.moderation_settings.threshold
        return getter(server_id, self.moderation_settings.threshold)


    def _moderation_policy_matches(
        self, server_id: str, result: ModerationResult
    ) -> list[dict[str, object]]:
        if result.action_exempt:
            return []
        getter = getattr(self.database, "get_moderation_policy_studio", None)
        if not callable(getter):
            threshold = self._moderation_threshold(server_id)
            return [
                {
                    "category": category,
                    "score": float(result.scores.get(category, 0)),
                    "threshold": threshold,
                    "action": (
                        self._protected_category_action(category)
                        if self._category_is_always_protected(category)
                        else "warn"
                    ),
                    "timeout_seconds": None,
                    "protected": self._category_is_always_protected(category),
                    "mode": "enforce",
                }
                for category in result.blocked_categories(threshold)
                if self._category_is_enabled(server_id, category)
            ]
        studio = getter(server_id, self.moderation_settings.threshold)
        configured = {
            str(policy["category"]): policy for policy in studio["policies"]
        }
        matches: list[dict[str, object]] = []
        for category, score in result.scores.items():
            policy = configured.get(category)
            if policy is None or not policy.get("enabled"):
                continue
            effective_threshold = policy.get("effective_threshold")
            threshold = float(
                studio["default_threshold"] if effective_threshold is None else effective_threshold
            )
            if float(score) < threshold:
                continue
            protected = self._category_is_always_protected(category)
            matches.append({
                "category": category,
                "score": float(score),
                "threshold": threshold,
                "action": (
                    self._protected_category_action(category)
                    if protected
                    else str(policy.get("action") or "warn")
                ),
                "timeout_seconds": policy.get("timeout_seconds"),
                "protected": protected,
                "mode": studio["mode"],
            })
        return sorted(matches, key=lambda item: str(item["category"]))

    def _enforced_display_name_categories(
        self, server_id: str, result: ModerationResult
    ) -> list[str]:
        return [
            str(match["category"])
            for match in self._moderation_policy_matches(server_id, result)
            if not match.get("protected")
            and (
                match.get("mode") == "enforce"
                and match.get("action") in {"delete", "warn", "timeout"}
            )
        ]

    def _moderation_category_status(self, server_id: str) -> str:
        disabled = self.database.list_disabled_moderation_categories(server_id)
        enabled = [
            category
            for category in SUPPORTED_MODERATION_CATEGORIES
            if self._category_is_enabled(server_id, category)
            and not self._category_is_always_protected(category)
        ]
        return (
            "**Enabled**\n"
            + ("\n".join(f"• `{category}`" for category in enabled) or "• None")
            + "\n\n**Disabled**\n"
            + ("\n".join(f"• `{category}`" for category in disabled) or "• None")
            + "\n\n**Always protected**\n"
            + "\n".join(
                f"• `{category}`"
                for category in SUPPORTED_MODERATION_CATEGORIES
                if self._category_is_always_protected(category)
            )
        )

    def _join_limit_summary(self, server_id: str) -> str:
        store = getattr(self.database, "join_limits", None)
        if store is None or not store.active(server_id):
            return "Disabled"
        config = store.settings(server_id)
        limited = " and ".join(
            name for name in ("links", "attachments") if config[name]
        )
        return f"{limited.capitalize()} for {format_join_limit_duration(config['duration_seconds'])}"

    async def _server_information_description(
        self, server: stoat.Server, server_id: str
    ) -> str:
        policy = self.database.get_warning_policy(server_id)
        join_enabled = self.database.get_join_protection(server_id)
        nickname_enabled = self.database.get_nickname_protection(server_id)
        link_enabled = self.database.get_link_protection(server_id)
        spam_enabled = self._spam_detection_enabled(server_id)
        spam_settings = self._spam_settings(server_id)
        image_scanning_enabled = self.database.get_image_scanning(server_id)
        moderator_exemption_enabled = self._moderator_exemption_enabled(server_id)
        pending = sum(
            challenge.server_id == server_id
            for challenge in self.database.list_captcha_challenges()
        )

        log_channel_id = self.database.get_log_channel(server_id)
        exclusions = self.database.count_scope_exclusions(server_id)
        disabled_categories = self.database.list_disabled_moderation_categories(
            server_id
        )
        owner_tag = await self._resolve_user_tag(server.owner_id)
        categories = server.categories or ()
        return (
            f"**Name:** {server.name}\n"
            f"**Server ID:** `{server_id}`\n"
            f"**Language:** {SUPPORTED_LANGUAGES[self._server_locale(server_id)]}\n"
            f"**Owner:** `{owner_tag}`\n"
            f"**Description:** {server.description or 'Not set'}\n"
            f"**Cached members:** {len(server.members)}\n"
            f"**Channels:** {len(server.channels)}\n"
            f"**Categories:** {len(categories)}\n"
            f"**Server marked NSFW:** {'Yes' if server.nsfw else 'No'}\n\n"
            "**Warning policy**\n"
            f"{self._policy_description(policy)}\n\n"
            "**Protection status**\n"
            f"**Join protection:** {'Enabled' if join_enabled else 'Disabled'}\n"
            f"**Pending CAPTCHAs:** {pending}\n"
            f"**New member limits:** {self._join_limit_summary(server_id)}\n"
            f"**Nickname protection:** {'Enabled' if nickname_enabled else 'Disabled'}\n"
            f"**Link protection:** {'Enabled' if link_enabled else 'Disabled'}\n"
            f"**Spam detection:** {'Enabled' if spam_enabled else 'Disabled'}\n"
            f"**Image scanning:** {'Enabled' if image_scanning_enabled else 'Disabled'}\n"
            f"**Moderator exemption:** {'Enabled' if moderator_exemption_enabled else 'Disabled'}\n"
            "**Automatic NSFW-channel exclusion:** Enabled\n"
            f"**Configured exclusions:** {exclusions}\n"
            f"**Disabled AI categories:** {', '.join(disabled_categories) if disabled_categories else 'None'}\n"
            f"**Repeated-message rule:** {spam_settings['repeat_count']} in "
            f"{spam_settings['repeat_window_seconds']:g} seconds\n"
            f"**Rapid-message rule:** {spam_settings['rapid_count']} in "
            f"{spam_settings['rapid_window_seconds']:g} seconds\n"
            f"**Mass-mention limit:** {spam_settings['mass_mention_limit']}\n"
            f"**Spam-score threshold:** {spam_settings['score_threshold']:g}\n"
            f"**Spam-score memory:** {spam_settings['score_half_life_seconds']:g} seconds\n"
            f"**Spam timeout:** {self._format_duration(int(spam_settings['timeout_seconds']))}\n\n"
            "**Moderation configuration**\n"
            f"**AI threshold:** {self._moderation_threshold(server_id):.2%}\n"
            f"**Log channel:** {f'<#{log_channel_id}>' if log_channel_id else 'Not configured'}"
        )

    @staticmethod
    def _dashboard_channel_snapshot(
        server: stoat.Server,
        additional_channels: list[object] | None = None,
    ) -> tuple[list[tuple[str, str, str | None]], list[tuple[str, str]]]:
        raw_categories = getattr(server, "categories", None) or []
        categories = (
            raw_categories.values()
            if isinstance(raw_categories, dict)
            else raw_categories
        )
        category_list = list(categories)
        category_by_channel = {
            channel_id: category.id
            for category in category_list
            for channel_id in category.channels
        }
        raw_channels = getattr(server, "channels", None) or {}
        channels = (
            raw_channels.values()
            if isinstance(raw_channels, dict)
            else raw_channels
        )
        text_channels: list[tuple[str, str, str | None]] = []
        seen_channel_ids: set[str] = set()
        for channel in [*channels, *(additional_channels or [])]:
            if not isinstance(channel, stoat.TextChannel):
                continue
            if channel.id in seen_channel_ids:
                continue
            seen_channel_ids.add(channel.id)
            text_channels.append(
                (
                    channel.id,
                    channel.name,
                    getattr(channel, "category_id", None)
                    or category_by_channel.get(channel.id),
                )
            )
        dashboard_categories = [
            (category.id, category.title) for category in category_list
        ]
        return text_channels, dashboard_categories

    @staticmethod
    def _role_is_assignable(bot_member: object | None, role: object) -> bool | None:
        """Return whether Stoatmod's highest role is above the target role."""
        if bot_member is None:
            return None
        bot_top_role = getattr(bot_member, "top_role", None)
        bot_rank = getattr(bot_top_role, "rank", None)
        role_rank = getattr(role, "rank", None)
        if bot_rank is None or role_rank is None:
            return None
        return int(bot_rank) < int(role_rank)

    def _cached_bot_member(self, server: stoat.Server) -> object | None:
        bot_id = getattr(getattr(self, "_state", None), "my_id", None)
        get_member = getattr(server, "get_member", None)
        return get_member(bot_id) if bot_id and callable(get_member) else None

    @staticmethod
    def _role_ids_after_member_edit(
        updated_member: object,
    ) -> list[str] | None:
        returned_role_ids = getattr(updated_member, "role_ids", None)
        if isinstance(returned_role_ids, (list, tuple, set)):
            return list(dict.fromkeys(str(role_id) for role_id in returned_role_ids))
        # A successful HTTP response is not proof that every requested role is
        # present. Partial responses must be confirmed with a fresh member fetch.
        return None

    async def _assign_auto_roles_on_join(
        self, server: stoat.Server, member: stoat.Member
    ) -> tuple[list[str], list[str]]:
        server_id = str(getattr(server, "id", member.server_id))
        configured_role_ids = list(
            dict.fromkeys(self.database.list_auto_roles(server_id))
        )
        if not configured_role_ids:
            return [], []

        raw_roles = getattr(server, "roles", None) or {}
        available_roles = (
            raw_roles
            if isinstance(raw_roles, dict)
            else {str(role.id): role for role in raw_roles}
        )
        fetch_member = getattr(server, "fetch_member", None)
        bot_member = self._cached_bot_member(server)
        bot_id = getattr(getattr(self, "_state", None), "my_id", None)
        if bot_member is None and bot_id:
            try:
                if callable(fetch_member):
                    bot_member = await fetch_member(bot_id)
            except Exception:
                logger.warning(
                    "auto_role_bot_member_unavailable server_id=%s",
                    server_id,
                    exc_info=True,
                )

        assignable_role_ids: list[str] = []
        unavailable_role_ids: list[str] = []
        hierarchy_blocked_role_ids: list[str] = []
        for role_id in configured_role_ids:
            role = available_roles.get(role_id)
            if role is None:
                fetch_role = getattr(server, "fetch_role", None)
                if callable(fetch_role):
                    try:
                        role = await fetch_role(role_id)
                    except Exception:
                        role = None
            if role is None:
                unavailable_role_ids.append(role_id)
                continue
            if self._role_is_assignable(bot_member, role) is False:
                hierarchy_blocked_role_ids.append(role_id)
                continue
            assignable_role_ids.append(role_id)

        current_role_ids = list(
            dict.fromkeys(
                str(role_id)
                for role_id in (getattr(member, "role_ids", None) or [])
            )
        )
        confirmed_current_role_ids: list[str] | None = None
        latest_confirmed_member: object | None = None
        if callable(fetch_member):
            try:
                confirmed_member = await fetch_member(member.id)
            except Exception:
                logger.warning(
                    "auto_role_initial_confirmation_failed server_id=%s user_id=%s",
                    server_id,
                    member.id,
                    exc_info=True,
                )
            else:
                confirmed_current_role_ids = self._role_ids_after_member_edit(
                    confirmed_member
                )
                if confirmed_current_role_ids is not None:
                    current_role_ids = confirmed_current_role_ids
                    latest_confirmed_member = confirmed_member
                    if hasattr(member, "role_ids"):
                        member.role_ids = list(current_role_ids)
        member_confirmation_unavailable = confirmed_current_role_ids is None
        retry_edit_budget = 8
        retry_edit_attempts = 0
        retry_edit_budget_exhausted = False
        pending_role_ids = [
            role_id
            for role_id in assignable_role_ids
            if role_id not in current_role_ids
        ]
        permission_blocked = False
        if pending_role_ids and member_confirmation_unavailable:
            logger.warning(
                "auto_role_assignment_skipped_unconfirmed_member server_id=%s user_id=%s role_ids=%s",
                server_id,
                member.id,
                pending_role_ids,
            )
        elif pending_role_ids and not await self.require_action_permissions(
            server, "assign_roles"
        ):
            permission_blocked = True
        elif pending_role_ids:
            requested_role_ids = list(
                dict.fromkeys([*current_role_ids, *pending_role_ids])
            )
            try:
                await latest_confirmed_member.edit(roles=requested_role_ids)
            except Exception:
                latest_confirmed_member = None
                logger.warning(
                    "auto_role_batch_assignment_failed server_id=%s user_id=%s role_ids=%s; retrying_missing_roles",
                    server_id,
                    member.id,
                    pending_role_ids,
                    exc_info=True,
                )
            else:
                latest_confirmed_member = None
                confirmed_role_ids: list[str] | None = None
                try:
                    confirmed_member = await fetch_member(member.id)
                except Exception:
                    logger.warning(
                        "auto_role_batch_confirmation_failed server_id=%s user_id=%s role_ids=%s",
                        server_id,
                        member.id,
                        pending_role_ids,
                        exc_info=True,
                    )
                else:
                    confirmed_role_ids = self._role_ids_after_member_edit(
                        confirmed_member
                    )
                if confirmed_role_ids is not None:
                    current_role_ids = confirmed_role_ids
                    confirmed_current_role_ids = list(current_role_ids)
                    latest_confirmed_member = confirmed_member
                    if hasattr(member, "role_ids"):
                        member.role_ids = list(current_role_ids)

            pending_role_ids = [
                role_id
                for role_id in assignable_role_ids
                if role_id not in current_role_ids
            ]
            for role_id in list(pending_role_ids):
                for attempt in range(2):
                    if role_id in current_role_ids:
                        break
                    if retry_edit_budget <= 0:
                        retry_edit_budget_exhausted = True
                        break
                    if attempt:
                        await asyncio.sleep(0.5 * attempt)
                    if latest_confirmed_member is None:
                        try:
                            confirmed_member = await fetch_member(member.id)
                        except Exception:
                            logger.warning(
                                "auto_role_member_refresh_failed server_id=%s user_id=%s role_id=%s attempt=%s",
                                server_id,
                                member.id,
                                role_id,
                                attempt + 1,
                                exc_info=True,
                            )
                            continue
                        confirmed_role_ids = self._role_ids_after_member_edit(
                            confirmed_member
                        )
                        if confirmed_role_ids is None:
                            continue
                        current_role_ids = confirmed_role_ids
                        confirmed_current_role_ids = list(current_role_ids)
                        latest_confirmed_member = confirmed_member
                        if hasattr(member, "role_ids"):
                            member.role_ids = list(current_role_ids)
                        if role_id in current_role_ids:
                            break
                    requested_role_ids = list(
                        dict.fromkeys(
                            [*(str(value) for value in current_role_ids), role_id]
                        )
                    )
                    retry_edit_budget -= 1
                    retry_edit_attempts += 1
                    try:
                        await latest_confirmed_member.edit(
                            roles=requested_role_ids
                        )
                    except Exception:
                        latest_confirmed_member = None
                        logger.warning(
                            "auto_role_assignment_retry_failed server_id=%s user_id=%s role_id=%s attempt=%s",
                            server_id,
                            member.id,
                            role_id,
                            attempt + 1,
                            exc_info=True,
                        )
                        continue
                    latest_confirmed_member = None
                    for confirmation_attempt in range(2):
                        if confirmation_attempt:
                            await asyncio.sleep(0.5)
                        try:
                            confirmed_member = await fetch_member(member.id)
                        except Exception:
                            logger.warning(
                                "auto_role_assignment_confirmation_failed server_id=%s user_id=%s role_id=%s attempt=%s confirmation=%s",
                                server_id,
                                member.id,
                                role_id,
                                attempt + 1,
                                confirmation_attempt + 1,
                                exc_info=True,
                            )
                            continue
                        confirmed_role_ids = self._role_ids_after_member_edit(
                            confirmed_member
                        )
                        if confirmed_role_ids is None:
                            continue
                        current_role_ids = confirmed_role_ids
                        confirmed_current_role_ids = list(current_role_ids)
                        latest_confirmed_member = confirmed_member
                        if hasattr(member, "role_ids"):
                            member.role_ids = list(current_role_ids)
                        if role_id in current_role_ids:
                            break
                    if role_id in current_role_ids:
                        break

        if retry_edit_budget <= 0 and any(
            role_id not in current_role_ids for role_id in pending_role_ids
        ):
            retry_edit_budget_exhausted = True
        role_ids_for_audit = (
            confirmed_current_role_ids
            if confirmed_current_role_ids is not None
            else []
        )
        granted_role_ids = [
            role_id
            for role_id in configured_role_ids
            if role_id in role_ids_for_audit
        ]
        failed_role_ids = [
            role_id
            for role_id in configured_role_ids
            if role_id not in granted_role_ids
        ]
        add_event = getattr(self.database, "add_event", None)
        if callable(add_event):
            add_event(
                server_id=server_id,
                event_type="auto_roles_processed_on_join",
                user_id=member.id,
                actor_id=bot_id,
                details={
                    "configured_role_ids": configured_role_ids,
                    "granted_role_ids": granted_role_ids,
                    "failed_role_ids": failed_role_ids,
                    "unavailable_role_ids": unavailable_role_ids,
                    "hierarchy_blocked_role_ids": hierarchy_blocked_role_ids,
                    "permission_blocked": permission_blocked,
                    "member_confirmation_unavailable": (
                        member_confirmation_unavailable
                    ),
                    "retry_edit_attempts": retry_edit_attempts,
                    "retry_edit_budget_exhausted": retry_edit_budget_exhausted,
                },
            )
        if failed_role_ids:
            await self.send_log(
                server_id,
                "Automatic role assignment failed",
                f"**User:** `{await self._resolve_user_tag(member.id, member)}`\n"
                f"**User ID:** `{member.id}`\n"
                f"**Roles not assigned:** "
                + ", ".join(f"<@&{role_id}> (`{role_id}`)" for role_id in failed_role_ids)
                + "\n**Cause:** Check Stoatmod's Assign Roles permission and role hierarchy.",
                color="#ED4245",
            )
        return granted_role_ids, failed_role_ids

    def sync_dashboard_server_identity(self, server: stoat.Server) -> None:
        self.database.update_dashboard_server_identity(
            server.id,
            server.name,
            self._server_icon_url(server),
            self._asset_url(getattr(server, "banner", None)),
        )

    async def handle_server_update(self, event: stoat.ServerUpdateEvent) -> None:
        # The SDK writes its cache after handlers run. `after` already contains
        # the merged update, including explicit icon/banner removals.
        server = event.after
        try:
            if server is None:
                server = await self.fetch_server(event.server.id)
            self.sync_dashboard_server_identity(server)
        except Exception:
            # Preserve the last snapshot on transient failures. Ready and the
            # periodic refresh repair it from the current gateway state.
            logger.exception("server_identity_refresh_failed server_id=%s", event.server.id)


    async def handle_channel_delete(self, event: stoat.ChannelDeleteEvent) -> None:
        """Remove an exemption only when Stoat confirms the channel was deleted."""
        channel = event.channel
        server_id = str(getattr(channel, "server_id", "") or "")
        if not server_id:
            return
        try:
            await self.fetch_channel(event.channel_id)
        except stoat.NotFound:
            removed = self.database.remove_deleted_channel_reference(
                server_id, event.channel_id
            )
            if removed:
                logger.info(
                    "deleted_channel_exemption_removed server_id=%s channel_id=%s source=event",
                    server_id,
                    event.channel_id,
                )
        except stoat.Forbidden:
            # ChannelDelete is also emitted when the bot loses View Channel.
            # Preserve the exemption unless Stoat confirms the channel is gone.
            return
        except Exception:
            logger.warning(
                "deleted_channel_verification_failed server_id=%s channel_id=%s source=event",
                server_id,
                event.channel_id,
                exc_info=True,
            )

    @staticmethod
    def _complete_dashboard_member_count(
        members: list[object], users: list[object] | None = None
    ) -> int:
        """Reconcile both collections returned by Stoat's member endpoint."""
        return max(len(members), len(users or []))

    async def _fetch_complete_dashboard_members(
        self, server: stoat.Server
    ) -> tuple[list[object], list[object] | None] | None:
        try:
            member_list = await server.fetch_member_list(exclude_offline=False)
            fetched_members = list(member_list.members)
            fetched_users = list(member_list.users)
            if len(fetched_members) != len(fetched_users):
                logger.warning(
                    "dashboard_member_response_mismatch server_id=%s members=%d users=%d",
                    server.id,
                    len(fetched_members),
                    len(fetched_users),
                )
            return fetched_members, fetched_users
        except Exception:
            logger.exception(
                "dashboard_member_count_refresh_failed server_id=%s", server.id
            )
        try:
            return list(
                await server.fetch_members(exclude_offline=False)
            ), None
        except Exception:
            logger.exception(
                "dashboard_member_count_fallback_failed server_id=%s", server.id
            )
            return None

    async def refresh_all_dashboard_member_counts(self) -> int:
        """Periodically repair counts if a gateway join/leave event was missed."""
        refreshed = 0
        update_count = getattr(
            self.database, "update_dashboard_server_member_count", None
        )
        replace_members = getattr(self.database, "replace_dashboard_members", None)
        for server in list(self.servers.values()):
            try:
                try:
                    self.sync_dashboard_server_identity(server)
                except Exception:
                    logger.exception("periodic_server_identity_refresh_failed server_id=%s", server.id)
                result = await self._fetch_complete_dashboard_members(server)
                if result is None:
                    continue
                fetched_members, fetched_users = result
                member_count = self._complete_dashboard_member_count(
                    fetched_members, fetched_users
                )
                if callable(update_count):
                    update_count(server.id, member_count)
                if callable(replace_members):
                    replace_members(
                        server.id,
                        self._dashboard_member_snapshot(
                            fetched_members, fetched_users, server=server
                        ),
                    )
                refreshed += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "periodic_dashboard_server_member_refresh_failed server_id=%s",
                    server.id,
                )
        return refreshed

    async def refresh_dashboard_server(self, server: stoat.Server) -> None:
        """Refresh a dashboard snapshot with the server's complete member count."""
        raw_members = getattr(server, "members", None) or {}
        cached_member_count = len(raw_members)
        complete_members = await self._fetch_complete_dashboard_members(server)
        if complete_members is not None:
            fetched_members, fetched_users = complete_members
            member_count = self._complete_dashboard_member_count(
                fetched_members, fetched_users
            )
        else:
            fetched_users = None
            fetched_members = list(
                raw_members.values()
                if isinstance(raw_members, dict)
                else raw_members
            )
            get_stored_count = getattr(
                self.database, "get_dashboard_server_member_count", None
            )
            stored_count = (
                get_stored_count(server.id) if callable(get_stored_count) else None
            )
            # Ready only contains members related to the bot, not the whole
            # server. Never replace a known full count with that partial cache.
            member_count = (
                int(stored_count)
                if stored_count is not None
                else cached_member_count
            )

        raw_cached_channels = getattr(server, "channels", None) or []
        cached_channels = list(
            raw_cached_channels.values()
            if isinstance(raw_cached_channels, dict)
            else raw_cached_channels
        )
        known_channel_ids = {
            channel.id for channel in cached_channels if hasattr(channel, "id")
        }
        channel_ids = list(getattr(server, "channel_ids", None) or [])
        get_log_channel = getattr(self.database, "get_log_channel", None)
        configured_log_channel_id = (
            get_log_channel(server.id) if callable(get_log_channel) else None
        )
        if (
            configured_log_channel_id
            and configured_log_channel_id not in known_channel_ids
            and configured_log_channel_id not in channel_ids
        ):
            channel_ids.append(configured_log_channel_id)
        raw_categories = getattr(server, "categories", None) or []
        categories = (
            raw_categories.values()
            if isinstance(raw_categories, dict)
            else raw_categories
        )
        for category in categories:
            for channel_id in getattr(category, "channels", None) or []:
                if channel_id not in channel_ids:
                    channel_ids.append(channel_id)

        list_scope_exclusions = getattr(
            self.database, "list_scope_exclusions", None
        )
        if callable(list_scope_exclusions):
            for exclusion in list_scope_exclusions(server.id):
                excluded_channel_id = str(exclusion.get("target_id", ""))
                if (
                    exclusion.get("target_type") == "channel"
                    and excluded_channel_id
                    and excluded_channel_id not in known_channel_ids
                    and excluded_channel_id not in channel_ids
                ):
                    # A deletion may have happened while the bot was offline.
                    # Fetch the saved exemption directly so a 404 can clean it.
                    channel_ids.append(excluded_channel_id)

        fetched_channels: list[object] = []
        inaccessible_channel_ids: list[str] = []
        for channel_id in channel_ids:
            if channel_id in known_channel_ids:
                continue
            try:
                channel = await self.fetch_channel(channel_id)
            except stoat.NotFound:
                remove_deleted_reference = getattr(
                    self.database, "remove_deleted_channel_reference", None
                )
                if callable(remove_deleted_reference) and remove_deleted_reference(
                    server.id, channel_id
                ):
                    logger.info(
                        "deleted_channel_exemption_removed server_id=%s channel_id=%s source=refresh",
                        server.id,
                        channel_id,
                    )
                continue
            except stoat.Forbidden as exc:
                inaccessible_channel_ids.append(channel_id)
                logger.warning(
                    "dashboard_channel_inaccessible server_id=%s channel_id=%s permission=%s",
                    server.id,
                    channel_id,
                    getattr(exc, "permission", "ViewChannel"),
                )
                continue
            except Exception:
                logger.warning(
                    "dashboard_channel_refresh_failed server_id=%s channel_id=%s",
                    server.id,
                    channel_id,
                    exc_info=True,
                )
                continue
            if getattr(channel, "server_id", server.id) != server.id:
                continue
            fetched_channels.append(channel)
            known_channel_ids.add(channel_id)

        text_channels, dashboard_categories = self._dashboard_channel_snapshot(
            server, fetched_channels
        )
        raw_roles = getattr(server, "roles", None) or {}
        roles = list(raw_roles.values() if isinstance(raw_roles, dict) else raw_roles)
        bot_id = getattr(getattr(self, "_state", None), "my_id", None)
        bot_member = next(
            (
                member
                for member in fetched_members
                if bot_id and str(getattr(member, "id", "")) == str(bot_id)
            ),
            None,
        )
        if bot_member is None and bot_id:
            fetch_member = getattr(server, "fetch_member", None)
            if callable(fetch_member):
                try:
                    bot_member = await fetch_member(bot_id)
                except Exception:
                    logger.warning(
                        "dashboard_bot_member_refresh_failed server_id=%s",
                        server.id,
                        exc_info=True,
                    )
        dashboard_roles = [
            (role.id, role.name, self._role_is_assignable(bot_member, role))
            for role in roles
        ]
        self.database.update_dashboard_server_snapshot(
            server.id,
            server.name,
            member_count,
            text_channels,
            dashboard_roles,
            dashboard_categories,
            self._server_icon_url(server),
            self._dashboard_permission_audit(
                server, inaccessible_channel_ids, bot_member, fetched_channels
            ),
            server_banner_url=self._asset_url(getattr(server, "banner", None)),
            owner_id=str(getattr(server, "owner_id", "") or ""),
            bot_joined_at=self._iso_datetime(
                getattr(bot_member, "joined_at", None)
            ),
        )
        replace_members = getattr(self.database, "replace_dashboard_members", None)
        if replace_members is not None:
            replace_members(
                server.id,
                self._dashboard_member_snapshot(
                    fetched_members, fetched_users, server=server
                ),
            )
        users_for_zero_tolerance_scan = list(fetched_users or [])
        known_scan_user_ids = {
            str(getattr(user, "id", "") or "")
            for user in users_for_zero_tolerance_scan
        }
        for member in fetched_members:
            member_user_id = str(getattr(member, "id", "") or "")
            if not member_user_id or member_user_id in known_scan_user_ids:
                continue
            get_user = getattr(member, "get_user", None)
            if not callable(get_user):
                continue
            try:
                user = get_user()
            except Exception:
                continue
            if user is None:
                continue
            users_for_zero_tolerance_scan.append(user)
            known_scan_user_ids.add(member_user_id)
        await self._scan_zero_tolerance_usernames(
            users_for_zero_tolerance_scan,
            source_server_id=server.id,
        )

    @classmethod
    def _dashboard_member_snapshot(
        cls,
        members: list[object],
        users: list[object] | None = None,
        *,
        server: object | None = None,
    ) -> list[dict[str, object]]:
        users_by_id = {
            str(getattr(user, "id", "")): user
            for user in users or []
            if getattr(user, "id", None)
        }
        snapshot: list[dict[str, object]] = []
        for member in members:
            user_id = str(getattr(member, "id", ""))
            if not user_id:
                continue
            user = users_by_id.get(user_id)
            if user is None and hasattr(member, "get_user"):
                user = member.get_user()
            manage_server = False
            permissions_for = getattr(server, "permissions_for", None)
            if callable(permissions_for):
                try:
                    manage_server = bool(
                        getattr(permissions_for(member), "manage_server", False)
                    )
                except Exception:
                    logger.warning(
                        "dashboard_member_permissions_failed server_id=%s user_id=%s",
                        getattr(server, "id", "unknown"),
                        user_id,
                        exc_info=True,
                    )
            snapshot.append(
                {
                    "user_id": user_id,
                    "username": str(getattr(user, "name", None) or user_id),
                    "display_name": getattr(user, "display_name", None),
                    "discriminator": getattr(user, "discriminator", None),
                    "avatar_url": cls._asset_url(
                        getattr(member, "server_avatar", None)
                        or getattr(user, "avatar", None)
                    ),
                    "joined_at": cls._iso_datetime(getattr(member, "joined_at", None)),
                    "account_created_at": cls._iso_datetime(
                        getattr(user, "created_at", None)
                    ),
                    "role_ids": list(getattr(member, "role_ids", None) or []),
                    "manage_server": manage_server,
                    "is_bot": getattr(user, "bot", None) is not None,
                    "online": bool(getattr(user, "online", False)),
                    "timed_out_until": cls._iso_datetime(
                        getattr(member, "timed_out_until", None)
                    ),
                }
            )
        return snapshot

    @staticmethod
    def _iso_datetime(value: object | None) -> str | None:
        return value.isoformat() if hasattr(value, "isoformat") else None

    @staticmethod
    def _asset_url(asset: object | None) -> str | None:
        if asset is None:
            return None
        try:
            return str(asset.url())
        except Exception:
            return None

    @staticmethod
    def _server_icon_url(server: stoat.Server) -> str | None:
        icon = getattr(server, "icon", None)
        if icon is None:
            return None
        try:
            return str(icon.url())
        except Exception:
            logger.warning("server_icon_url_failed server_id=%s", server.id)
            return None

    @staticmethod
    def _dashboard_code_hash(code: str) -> str:
        return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()

    def _appeal_instructions(
        self,
        user_id: str,
        case_kind: str,
        case_reference: str,
        *,
        server_id: str | None = None,
        reuse_existing: bool = False,
    ) -> str:
        if case_kind != "moderation":
            return ""
        creator = getattr(self.database, "create_appeal_access", None)
        if creator is None or not case_reference or case_reference == "Unavailable":
            return ""
        existing_getter = getattr(self.database, "get_server_appeal_by_case", None)
        if reuse_existing and server_id and callable(existing_getter):
            existing = existing_getter(server_id, case_reference.replace("CASE-", ""))
            if existing is not None and existing["user_id"] == user_id:
                return (
                    "\n\n**Appeal this decision**\n"
                    f"Case: `CASE-{case_reference.replace('CASE-', '')}`\n"
                    "Use the appeal code already sent for this case. "
                    "That appeal covers the warning and its timeout."
                )
        code = "".join(
            secrets.choice(DASHBOARD_CODE_ALPHABET) for _ in range(10)
        )
        creator(
            self._dashboard_code_hash(code),
            user_id,
            case_kind,
            case_reference.replace("CASE-", ""),
            server_id,
        )
        appeal_url = (
            f"{self.moderation_settings.dashboard_url.rstrip('/')}/appeal"
        )
        return (
            "\n\n**Appeal this decision**\n"
            f"Case: `{case_reference}`\n"
            f"Appeal code: `{code}`\n"
            f"Open: {appeal_url}\n"
            "Enter the code with your Stoat user ID."
        )

    @staticmethod
    def _global_ban_contact_instructions() -> str:
        return (
            "\n\n**Contact the administrator by email only**\n"
            f"The server and its dashboard cannot review global bans. Email "
            f"`{SUPPORT_EMAIL}` and include the reference ID above."
        )

    def _detect_spam(
        self,
        server_id: str,
        user_id: str,
        content: str,
        *,
        mention_count: int = 0,
        now: float | None = None,
        spam_settings: dict[str, int | float] | None = None,
    ) -> str | None:
        current = time.monotonic() if now is None else now
        key = (server_id, user_id)
        if self._spam_timeout_until.get(key, 0) > current:
            return None

        settings = spam_settings or self._spam_settings(server_id)

        window = max(
            settings["repeat_window_seconds"],
            settings["rapid_window_seconds"],
        )
        history = self._spam_history.setdefault(key, deque())
        while history and current - history[0][0] > window:
            history.popleft()

        normalized = " ".join(content.casefold().split())
        comparison_text = URL_PATTERN.sub("<url>", normalized)
        previous_text = history[-1][1] if history else ""
        history.append((current, normalized))

        previous_score, previous_at = self._spam_scores.get(key, (0.0, current))
        half_life = settings["score_half_life_seconds"]
        decayed_score = previous_score * (0.5 ** ((current - previous_at) / half_life))
        points = 0.5
        signals: list[str] = []
        if previous_at != current and current - previous_at <= 2:
            points += 1
            signals.append("rapid posting")
        if comparison_text and previous_text:
            previous_comparison = URL_PATTERN.sub("<url>", previous_text)
            if comparison_text == previous_comparison:
                points += 2
                signals.append("duplicate content")
            elif min(len(comparison_text), len(previous_comparison)) >= 8:
                similarity = SequenceMatcher(
                    None, comparison_text, previous_comparison, autojunk=False
                ).ratio()
                if similarity >= 0.86:
                    points += 1.5
                    signals.append("near-duplicate content")
        link_count = len(URL_PATTERN.findall(content))
        if link_count >= 2:
            points += min(3.0, float(link_count))
            signals.append("repeated links")
        if FLOOD_PATTERN.search(normalized):
            points += 2
            signals.append("character flooding")
        if mention_count >= 2:
            points += min(3.0, mention_count * 0.75)
            signals.append("multiple mentions")
        score = decayed_score + points
        self._spam_scores[key] = (score, current)

        if normalized:
            repeated = 0
            for timestamp, previous in reversed(history):
                if current - timestamp > settings["repeat_window_seconds"]:
                    break
                if previous != normalized:
                    break
                repeated += 1
            if repeated >= settings["repeat_count"]:
                history.clear()
                self._spam_scores.pop(key, None)
                return (
                    f"repeated the same message {repeated} times within "
                    f"{settings['repeat_window_seconds']:g} seconds"
                )

        rapid = sum(
            current - timestamp <= settings["rapid_window_seconds"]
            for timestamp, _content in history
        )
        if rapid >= settings["rapid_count"]:
            history.clear()
            self._spam_scores.pop(key, None)
            return (
                f"sent {rapid} messages within "
                f"{settings['rapid_window_seconds']:g} seconds"
            )
        threshold = settings["score_threshold"]
        if score >= threshold:
            history.clear()
            self._spam_scores.pop(key, None)
            signal_text = ", ".join(dict.fromkeys(signals)) or "sustained activity"
            return f"reached a spam score of {score:.1f} ({signal_text})"
        return None

    def _mass_mention_reason(
        self, message: stoat.Message, *, limit: int | None = None
    ) -> str | None:
        user_mentions = set(getattr(message, "mention_ids", ()) or ())
        role_mentions = set(getattr(message, "role_mention_ids", ()) or ())
        mention_count = len(user_mentions) + len(role_mentions)
        # One @everyone/@online that the author is allowed to use is fine; using
        # it more than once in a message is not. Repeats across messages are
        # handled by _repeated_everyone_reason().
        if self._everyone_mention_uses(message) >= 2:
            return "used @everyone or @online more than once in one message"
        effective_limit = (
            limit
            if limit is not None
            else int(getattr(self.moderation_settings, "mass_mention_limit", 5))
        )
        if mention_count >= effective_limit:
            return f"mentioned {mention_count} users or roles in one message"
        return None

    @staticmethod
    def _everyone_mention_uses(message: stoat.Message) -> int:
        """How many @everyone/@online mentions in this message actually ping.

        Stoat only flags a message when the author has permission to mention
        everyone, so a message without the flag counts as zero."""
        if not int(getattr(message, "raw_flags", 0) or 0) & EVERYONE_MENTION_FLAGS:
            return 0
        content = str(getattr(message, "content", "") or "")
        return max(1, len(EVERYONE_MENTION_PATTERN.findall(content)))

    def _repeated_everyone_reason(
        self,
        message: stoat.Message,
        server_id: str,
        spam_settings: dict[str, int | float],
        *,
        now: float | None = None,
    ) -> str | None:
        """Spam only when a member uses @everyone/@online again within the repeat window."""
        if self._everyone_mention_uses(message) < 1:
            return None
        current = time.monotonic() if now is None else now
        histories = self.__dict__.setdefault("_everyone_history", {})
        history = histories.setdefault((server_id, message.author_id), deque())
        window = float(spam_settings["repeat_window_seconds"])
        while history and current - history[0] > window:
            history.popleft()
        history.append(current)
        if len(history) < 2:
            return None
        history.clear()
        return f"used @everyone or @online more than once within {window:g} seconds"

    async def _delete_automatic_message(self, message: stoat.Message) -> bool:
        self._bot_deleted_ids.add(message.id)
        try:
            await message.delete()
        except Exception:
            self._bot_deleted_ids.discard(message.id)
            logger.exception("automatic_message_delete_failed message_id=%s", message.id)
            return False
        asyncio.get_running_loop().call_later(
            60, self._bot_deleted_ids.discard, message.id
        )
        return True

    @staticmethod
    def _link_candidate_is_valid(link: str) -> bool:
        candidate = link.strip().rstrip(".,;:!?)]}")
        if re.match(r"(?i)^(?:https?|ftp)://|^www\.", candidate):
            return True
        parsed = urlparse(f"//{candidate}")
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        if not hostname:
            return False
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass
        extracted = PUBLIC_SUFFIX_EXTRACTOR(hostname)
        return bool(extracted.domain and extracted.suffix)

    @classmethod
    def _contains_link(cls, content: str) -> bool:
        return any(
            cls._link_candidate_is_valid(match.group(0))
            for match in LINK_PATTERN.finditer(content)
        )

    @staticmethod
    def _link_is_allowed_for_automatic_deletion(link: str) -> bool:
        candidate = link.strip().rstrip(".,;:!?)]}")
        parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
        hostname = (parsed.hostname or "").casefold().rstrip(".")
        return any(
            hostname == allowed_host or hostname.endswith(f".{allowed_host}")
            for allowed_host in AUTOMATIC_LINK_DELETION_ALLOWED_HOSTS
        )

    def _server_allows_gifs(self, server_id: str) -> bool:
        getter = getattr(self.database, "get_allow_gifs", None)
        return bool(getter(server_id)) if callable(getter) else False

    @classmethod
    def _contains_filterable_link(
        cls, content: str, *, allow_gifs: bool = False
    ) -> bool:
        if not allow_gifs:
            return cls._contains_link(content)
        return any(
            not cls._link_is_allowed_for_automatic_deletion(match.group(0))
            for match in LINK_PATTERN.finditer(content)
            if cls._link_candidate_is_valid(match.group(0))
        )

    async def handle_link_filter(self, message: stoat.Message) -> bool:
        server, server_id = message.get_server()
        if server is None or not server_id:
            return False
        if not self.database.get_link_protection(server_id):
            return False
        if not self._contains_filterable_link(
            message.content,
            allow_gifs=self._server_allows_gifs(server_id),
        ):
            return False
        if not await self.require_action_permissions(server, "manage_messages"):
            return True
        deleted = await self._delete_automatic_message(message)
        user_tag = await self._resolve_user_tag(
            message.author_id, message.get_author_as_user()
        )
        self.database.add_event(
            server_id=server_id,
            event_type="automatic_link_deletion",
            user_id=message.author_id,
            actor_id=self.state.my_id,
            message_id=message.id,
            channel_id=message.channel_id,
            details={
                "message_deleted": deleted,
                "warning_added": False,
                "original_content": message.content,
            },
        )
        await self.send_log(
            server_id,
            "Link filtered" if deleted else "Link filter — deletion failed",
            f"**User:** `{user_tag}`\n"
            f"**Channel:** <#{message.channel_id}>\n"
            f"**Message:** `{message.id}`\n"
            "**Warning added:** No\n\n"
            f"**Original message:**\n{self._original_message_text(message.content)}",
            color="#F59E0B" if deleted else "#ED4245",
        )
        return True

    async def handle_join_limits(self, message: stoat.Message) -> bool:
        """Remove links and attachments from members still under join protection."""
        join_limit_flow = getattr(self, "join_limit_flow", None)
        if join_limit_flow is None:
            return False
        try:
            return await join_limit_flow.handle_message(message)
        except Exception:
            logger.exception("join_limit_check_failed message_id=%s", message.id)
            return False

    async def handle_spam(self, message: stoat.Message) -> bool:
        server, server_id = message.get_server()
        if server is None or not server_id:
            return False
        if not self._spam_detection_enabled(server_id):
            return False
        spam_settings = self._spam_settings(server_id)
        timeout_seconds = int(spam_settings["timeout_seconds"])
        mass_mention_reason = self._mass_mention_reason(
            message, limit=int(spam_settings["mass_mention_limit"])
        )
        if mass_mention_reason is None:
            mass_mention_reason = self._repeated_everyone_reason(
                message, server_id, spam_settings
            )
        mention_count = len(set(getattr(message, "mention_ids", ()) or ())) + len(
            set(getattr(message, "role_mention_ids", ()) or ())
        )
        reason = mass_mention_reason or self._detect_spam(
            server_id,
            message.author_id,
            message.content,
            mention_count=mention_count,
            spam_settings=spam_settings,
        )
        if reason is None:
            return False

        if not await self.require_action_permissions(server, "timeout_members"):
            return True

        member = message.get_author_as_member() or server.get_member(message.author_id)
        message_deleted = False
        try:
            if member is None:
                member = await server.fetch_member(message.author_id)
            if self._moderator_is_exempt(server_id, server, member):
                logger.info(
                    "spam_timeout_skipped_elevated_member server_id=%s user_id=%s",
                    server_id,
                    message.author_id,
                )
                return message_deleted
            if mass_mention_reason is not None and await self.require_action_permissions(
                server, "manage_messages"
            ):
                message_deleted = await self._delete_automatic_message(message)
            await member.timeout(
                timedelta(seconds=timeout_seconds)
            )
        except stoat.Forbidden as exc:
            if exc.type == "IsElevated":
                logger.info(
                    "spam_timeout_skipped_elevated_member server_id=%s user_id=%s",
                    server_id,
                    message.author_id,
                )
                return message_deleted
            logger.exception(
                "spam_timeout_failed server_id=%s user_id=%s message_id=%s",
                server_id,
                message.author_id,
                message.id,
            )
            return message_deleted
        except Exception:
            logger.exception(
                "spam_timeout_failed server_id=%s user_id=%s message_id=%s",
                server_id,
                message.author_id,
                message.id,
            )
            return message_deleted

        self._spam_timeout_until[(server_id, message.author_id)] = (
            time.monotonic() + timeout_seconds
        )
        warning_reason = f"Automatic spam detection: {reason}"
        warning_id = self.database.add_warning(
            server_id=server_id,
            user_id=message.author_id,
            moderator_id=self.state.my_id,
            source="automatic",
            reason=warning_reason,
            message_id=message.id,
            channel_id=message.channel_id,
            original_content=message.content,
        )
        warning_case_reference = self._warning_case_reference(
            server_id, warning_id
        )
        total = self._active_warning_count(server_id, message.author_id)
        user_tag = await self._resolve_user_tag(
            message.author_id, message.get_author_as_user()
        )
        timeout_event_id = self.database.add_event(
            server_id=server_id,
            event_type="automatic_spam_timeout",
            user_id=message.author_id,
            actor_id=self.state.my_id,
            message_id=message.id,
            channel_id=message.channel_id,
            details={
                "reason": reason,
                "timeout_seconds": timeout_seconds,
                "warning_id": warning_id,
                "total_warnings": total,
                "mass_mention": mass_mention_reason is not None,
                "message_deleted": message_deleted,
            },
        )
        spam_appeal = self._appeal_instructions(
            message.author_id,
            "moderation",
            warning_case_reference,
            server_id=server_id,
        )
        if spam_appeal:
            await self._send_case_dm(
                message.author_id,
                "You were warned and timed out",
                f"Automatic spam protection acted in **{getattr(server, 'name', 'this server')}**.\n\n"
                f"**Reason:** {reason}\n"
                f"**Actions:** 1 warning and a timeout of {self._format_duration(timeout_seconds)}\n"
                f"**Warnings in this server:** {total}\n"
                "The warning and timeout are part of the same case. One appeal covers both actions."
                f"{spam_appeal}",
                warning_id=warning_id,
                server_id=server_id,
                user=member,
            )
        await self.send_log(
            server_id,
            "Spam detected — user timed out",
            f"{self._event_case_line(server_id, timeout_event_id)}"
            f"**User:** `{user_tag}`\n**Channel:** <#{message.channel_id}>\n"
            f"**Reason:** {reason}\n**Timeout:** "
            f"{self._format_duration(timeout_seconds)}\n"
            + (
                f"**Message blocked:** {'Yes' if message_deleted else 'No — deletion failed'}\n"
                if mass_mention_reason is not None
                else ""
            )
            + f"**Warning case:** `{warning_case_reference}`\n"
            f"**Total warnings:** {total}",
            color="#ED4245",
        )

        policy = self.database.get_warning_policy(server_id)
        if (
            timeout_seconds >= 3600
            and policy.timeout_count <= total < policy.kick_count
        ):
            self.database.claim_warning_policy_action(
                server_id,
                message.author_id,
                "timeout",
                policy.timeout_count,
                warning_id,
            )
        await self._enforce_warning_policy_and_notify(
            server,
            server_id,
            message.author_id,
            warning_id,
            total,
        )
        return True

    async def enforce_warning_policy(
        self,
        server: stoat.Server,
        server_id: str,
        user_id: str,
        warning_id: int,
        warning_count: int,
    ) -> None:
        if user_id == self.state.my_id:
            return

        rule_getter = getattr(self.database, "list_penalty_rules", None)
        if callable(rule_getter):
            rules = rule_getter(server_id)
            eligible = tuple(
                (rule.action, rule.threshold, rule.duration_seconds)
                for rule in sorted(rules, key=lambda item: item.threshold, reverse=True)
            )
        else:
            policy = self.database.get_warning_policy(server_id)
            eligible = (
                ("ban", policy.ban_count, None),
                ("kick", policy.kick_count, None),
                ("timeout", policy.timeout_count, 3600),
            )
        selected = next(
            (
                (action, threshold, duration_seconds)
                for action, threshold, duration_seconds in eligible
                if warning_count >= threshold
            ),
            None,
        )
        if selected is None:
            return
        action, threshold, duration_seconds = selected

        member = server.get_member(user_id)
        if member is None and action != "ban":
            try:
                member = await server.fetch_member(user_id)
            except Exception:
                logger.exception(
                    "warning_policy_member_fetch_failed server_id=%s user_id=%s action=%s",
                    server_id,
                    user_id,
                    action,
                )
                return
        if member is not None:
            if self._moderator_is_exempt(server_id, server, member):
                logger.info(
                    "warning_policy_exempt_moderator server_id=%s user_id=%s",
                    server_id,
                    user_id,
                )
                return

        required_permission = {
            "timeout": "timeout_members",
            "kick": "kick_members",
            "ban": "ban_members",
        }[action]
        if not await self.require_action_permissions(server, required_permission):
            return

        if not self.database.claim_warning_policy_action(
            server_id, user_id, action, threshold, warning_id
        ):
            return

        try:
            if action == "timeout":
                assert member is not None
                timeout_seconds = int(duration_seconds or 3600)
                await member.timeout(timedelta(seconds=timeout_seconds))
                action_label = f"Timed out for {self._format_duration(timeout_seconds)}"
            elif action == "kick":
                assert member is not None
                await self._kick_member_with_reason(
                    member,
                    server_id,
                    user_id,
                    f"Automatic warning policy: {warning_count} warnings",
                )
                action_label = "Kicked"
            else:
                ban_reason = f"Automatic warning policy: {warning_count} warnings"
                attribution_key = (server_id, user_id)
                self._pending_ban_attribution[attribution_key] = (
                    self.state.my_id,
                    ban_reason,
                )
                await server.ban(
                    user_id,
                    reason=ban_reason,
                )
                asyncio.get_running_loop().call_later(
                    60, self._pending_ban_attribution.pop, attribution_key, None
                )
                action_label = "Banned"
        except Exception:
            if action == "ban":
                self._pending_ban_attribution.pop((server_id, user_id), None)
            self.database.release_warning_policy_action(
                server_id, user_id, action, threshold
            )
            logger.exception(
                "warning_policy_action_failed server_id=%s user_id=%s action=%s",
                server_id,
                user_id,
                action,
            )
            return

        user_tag = await self._resolve_user_tag(user_id, member)
        warning_case_reference = self._warning_case_reference(
            server_id, warning_id
        )
        action_event_id = self.database.add_event(
            server_id=server_id,
            event_type=f"warning_policy_{action}",
            user_id=user_id,
            actor_id=self.state.my_id,
            details={
                "warning_id": warning_id,
                "warning_count": warning_count,
                "threshold": threshold,
                "duration_seconds": duration_seconds,
            },
        )
        event_case_getter = getattr(self.database, "get_event_case", None)
        action_case = (
            event_case_getter(server_id, action_event_id)
            if event_case_getter is not None
            else None
        )
        notice = self._case_notices().get((server_id, user_id, warning_id))
        action_appeal = (
            self._appeal_instructions(
                user_id,
                "moderation",
                action_case.reference_id if action_case is not None else "",
                server_id=server_id,
                # A case has one appeal: reuse the code its message already carries.
                reuse_existing=action == "timeout" or notice is not None,
            )
            if action in {"timeout", "ban"}
            else ""
        )
        await self.send_log(
            server_id,
            f"Warning policy — {action_label.lower()}",
            f"{self._event_case_line(server_id, action_event_id)}"
            f"**User:** `{user_tag}`\n**Action:** {action_label}\n"
            f"**Warning count:** {warning_count}\n"
            f"**Triggering case:** `{warning_case_reference}`",
            color="#ED4245",
        )
        if notice is not None:
            # One case is one message: fold this action into the warning's message.
            notice.add_escalation(
                action, warning_count, action_label, server.name, action_appeal
            )
            return
        dm_title = {
            "timeout": "You have been timed out",
            "kick": "You have been kicked",
            "ban": "You have been banned",
        }[action]
        await self._send_user_dm(
            user_id,
            dm_title,
            f"A moderation action was applied to you in **{server.name}** "
            f"because you reached {warning_count} warnings.\n\n"
            f"**Action:** {action_label}\n"
            f"**Triggering case:** `{warning_case_reference}`"
            f"{action_appeal}",
            server_id=server_id,
            user=member,
        )

    def _case_notices(self) -> dict[tuple[str | None, str, int], CaseNotice]:
        notices = self.__dict__.get("_case_notice_store")
        if notices is None:
            notices = self.__dict__["_case_notice_store"] = {}
        return notices

    async def _send_case_dm(
        self,
        user_id: str,
        title: str,
        description: str,
        *,
        warning_id: int | None,
        server_id: str | None = None,
        user: object | None = None,
        color: str = "#ED4245",
    ) -> None:
        """Send a warning's message once, with any escalation of that warning folded in.

        The message is held until _enforce_warning_policy_and_notify() has decided
        whether the warning also triggers a timeout, kick or ban; a timer sends it
        anyway if that never happens."""
        if warning_id is None:
            await self._send_user_dm(
                user_id, title, description, server_id=server_id, user=user, color=color
            )
            return
        key = (server_id, user_id, warning_id)
        notices = self._case_notices()
        previous = notices.pop(key, None)
        if previous is not None and previous.timer is not None:
            previous.timer.cancel()
        notice = CaseNotice(
            user_id, title, description, server_id=server_id, user=user, color=color
        )
        flushes = self.__dict__.setdefault("_case_notice_flushes", set())

        def flush_later() -> None:
            task = asyncio.ensure_future(self._flush_case_notice(key))
            flushes.add(task)
            task.add_done_callback(flushes.discard)

        notice.timer = asyncio.get_running_loop().call_later(
            CASE_NOTICE_GRACE_SECONDS, flush_later
        )
        notices[key] = notice

    async def _flush_case_notice(self, key: tuple[str | None, str, int]) -> bool:
        notice = self._case_notices().pop(key, None)
        if notice is None:
            return False
        if notice.timer is not None:
            notice.timer.cancel()
        title, description = notice.compose()
        return await self._send_user_dm(
            notice.user_id, title, description,
            server_id=notice.server_id, user=notice.user, color=notice.color,
        )

    async def _enforce_warning_policy_and_notify(
        self,
        server: stoat.Server,
        server_id: str,
        user_id: str,
        warning_id: int,
        warning_count: int,
    ) -> None:
        try:
            await self.enforce_warning_policy(
                server, server_id, user_id, warning_id, warning_count
            )
        finally:
            await self._flush_case_notice((server_id, user_id, warning_id))

    async def _send_user_dm(
        self,
        user_id: str,
        title: str,
        description: str,
        *,
        server_id: str | None = None,
        user: object | None = None,
        color: str = "#ED4245",
        sensitive: bool = False,
    ) -> bool:
        if server_id:
            title, description = localize_delivery(
                self._server_locale(server_id), title, description
            )
        target = user
        try:
            if target is None or not hasattr(target, "open_dm"):
                target = self.get_user(user_id) or await self.fetch_user(user_id)
            dm = await target.open_dm()
            await self._send_embed_pages(dm, title, description, color)
            return True
        except Exception:
            if sensitive:
                logger.warning("sensitive_user_dm_failed user_id=%s", user_id)
            else:
                logger.exception("user_dm_failed user_id=%s title=%s", user_id, title)
            return False

    async def _notify_report_outcome(self, report_id: int) -> dict[str, object]:
        report_getter = getattr(
            self.database, "get_report_for_notification", None
        )
        if callable(report_getter):
            report = report_getter(report_id)
        else:
            report = self.database.get_owner_report(report_id)
        if report is None:
            raise LookupError("Report is unavailable")
        context_getter = getattr(
            self.database, "get_report_delivery_context", None
        )
        if callable(context_getter):
            report.update(context_getter(
                str(report["server_id"]),
                str(report["reporter_id"]),
                str(report.get("target_user_id") or ""),
            ))
        status = str(report.get("status") or "")
        if status not in {"resolved", "dismissed"}:
            raise ValueError("Report has not been reviewed")
        reporter_id = str(report["reporter_id"])
        if report.get("reporter_notification_status") == "sent":
            return {
                "report_id": report_id,
                "user_id": None if bool(report.get("anonymous")) else reporter_id,
                "status": status,
                "notified": True,
                "already_notified": True,
            }
        server_name = str(report.get("server_name") or "the reported server")
        report_reference = str(report.get("reference_id") or report_id)
        is_global = report.get("report_scope") == "global"
        target_name = str(
            report.get("target_username") or report.get("subject_text")
            or report.get("target_user_id") or report.get("subject_type") or "Unknown subject"
        )
        note = str(report.get("review_note") or "").strip()
        outcome = status.title()
        note_text = note or "No additional notes were provided."
        subject_label = (
            "Reported user"
            if is_global or str(report.get("subject_type") or "user") == "user"
            else "Subject"
        )
        delivered = await self._send_user_dm(
            reporter_id,
            f"Your {'global ' if is_global else ''}report was {status}",
            (
                "Your report to the **Stoatmod global team** has been "
                f"{status}.\n\n"
                if is_global
                else f"Your report in **{server_name}** has been {status}.\n\n"
            )
            + f"**Report ID:** `{report_reference}`\n"
            f"**{subject_label}:** `{target_name}`\n"
            f"**Outcome:** {outcome}\n"
            f"**Moderator notes:** {note_text}",
            server_id=str(report["server_id"]),
            color="#3BA55D" if status == "resolved" else "#747F8D",
        )
        if not delivered:
            error = "The reporter could not be reached by direct message."
            raise ReportNotificationDeliveryError(error)
        self.database.mark_reporter_notification(report_id, success=True)
        self.database.add_event(
            server_id=str(report["server_id"]),
            event_type="report_outcome_notified",
            user_id=None if bool(report.get("anonymous")) else reporter_id,
            actor_id=str(report.get("reviewed_by") or GLOBAL_COMMAND_OWNER_ID),
            details={
                "report_id": report_id,
                "report_reference": report_reference,
                "status": status,
                "has_review_note": bool(note),
            },
        )
        return {
            "report_id": report_id,
            "user_id": None if bool(report.get("anonymous")) else reporter_id,
            "status": status,
            "notified": True,
        }

    async def handle_timeout_command(
        self,
        message: stoat.Message,
        server: stoat.Server,
        server_id: str,
        command: str,
        parts: list[str],
    ) -> None:
        if len(parts) < 2:
            await self.send_command_response(
                message, "Mute command", f"Usage: `{SERVER_COMMAND_USAGES[command]}`", color="#F59E0B"
            )
            return

        user_id = self._parse_user_id(parts[1])
        duration_seconds: int | None = None
        if command == "~mute":
            try:
                duration_seconds, reason = self._parse_mute_arguments(" ".join(parts[2:]))
            except ValueError as exc:
                await self.send_command_response(
                    message,
                    "Mute command",
                    f"{exc}\n\n"
                    "Usage: `~mute @user 25m REASON` or `~mute @user REASON 25m`.\n"
                    "Use `~mute @user REASON` for the default 1 hour. A reason is always required.",
                    color="#F59E0B",
                )
                return
        else:
            reason = await self._require_command_reason(message, command, parts)
            if reason is None:
                return

        member = server.get_member(user_id)
        try:
            if member is None:
                member = await server.fetch_member(user_id)
        except Exception:
            logger.exception(
                "mute_member_fetch_failed server_id=%s user_id=%s",
                server_id,
                user_id,
            )
            await self.send_command_response(
                message,
                "Member not found",
                "That user is not a member of this server.",
                color="#ED4245",
            )
            return

        if command == "~mute" and self._member_is_moderator(server, member):
            await self.send_command_response(
                message,
                "Cannot mute member",
                "Stoat does not allow elevated members with moderation permissions "
                "to be timed out.",
                color="#ED4245",
            )
            return

        if not await self.require_action_permissions(server, "timeout_members"):
            return

        try:
            await member.timeout(
                timedelta(seconds=duration_seconds)
                if duration_seconds is not None
                else None
            )
        except stoat.Forbidden as exc:
            detail = (
                "Stoat does not allow elevated members to be timed out."
                if exc.type == "IsElevated"
                else "The bot does not have permission to change this member's timeout."
            )
            await self.send_command_response(
                message,
                "Mute action failed",
                detail,
                color="#ED4245",
            )
            return
        except Exception:
            logger.exception(
                "mute_action_failed server_id=%s user_id=%s command=%s",
                server_id,
                user_id,
                command,
            )
            await self.send_command_response(
                message,
                "Mute action failed",
                "Stoat could not update that member's timeout.",
                color="#ED4245",
            )
            return

        user_tag = await self._resolve_user_tag(user_id, member)
        moderator_tag = await self._resolve_user_tag(
            message.author_id, message.get_author_as_user()
        )
        muted = command == "~mute"
        action = "Muted" if muted else "Unmuted"
        details = {"reason": reason}
        if muted:
            details["duration_seconds"] = duration_seconds
        mute_event_id = self.database.add_event(
            server_id=server_id,
            event_type="manual_mute" if muted else "manual_unmute",
            user_id=user_id,
            actor_id=message.author_id,
            channel_id=message.channel_id,
            details=details,
        )
        duration_line = (
            f"\n**Duration:** {self._format_duration(duration_seconds)}"
            if duration_seconds is not None
            else ""
        )
        description = (
            f"{self._event_case_line(server_id, mute_event_id)}"
            f"**User:** `{user_tag}`{duration_line}\n**Reason:** {reason}"
        )
        await self.send_command_response(
            message, f"Member {action.lower()}", description, color="#3BA55D"
        )
        await self.send_log(
            server_id,
            f"Member {action.lower()}",
            f"**Moderator:** `{moderator_tag}`\n{description}",
            color="#F59E0B" if muted else "#3BA55D",
        )
        if muted:
            getter = getattr(self.database, "get_event_case", None)
            case = getter(server_id, mute_event_id) if getter else None
            appeal = (
                self._appeal_instructions(user_id, "moderation", case.reference_id, server_id=server_id)
                if case is not None else ""
            )
            await self._send_user_dm(
                user_id,
                "You have been muted",
                f"You were muted in **{server.name}**.\n\n{description}{appeal}",
                server_id=server_id,
                user=member,
            )
        else:
            await self._send_user_dm(
                user_id,
                "You have been unmuted",
                f"Your mute in **{server.name}** was removed by a moderator.\n\n**Reason:** {reason}",
                server_id=server_id,
                user=member,
            )

    async def handle_kick_ban_command(
        self,
        message: stoat.Message,
        server: stoat.Server,
        server_id: str,
        command: str,
        parts: list[str],
    ) -> None:
        reason = await self._require_command_reason(message, command, parts)
        if reason is None:
            return
        user_id = self._parse_user_id(parts[1])
        try:
            if command == "~kick":
                if not await self.require_action_permissions(server, "kick_members"):
                    return
                member = server.get_member(user_id) or await server.fetch_member(user_id)
                await self._kick_member_with_reason(
                    member,
                    server_id,
                    user_id,
                    reason,
                    actor_id=message.author_id,
                )
            else:
                if not await self.require_action_permissions(server, "ban_members"):
                    return
                self._pending_ban_attribution[(server_id, user_id)] = (
                    message.author_id, reason
                )
                await server.ban(user_id, reason=reason[:1024])
        except Exception:
            if command == "~kick":
                self._pending_kick_attribution.pop((server_id, user_id), None)
            else:
                self._pending_ban_attribution.pop((server_id, user_id), None)
            logger.exception(
                "manual_member_action_failed server_id=%s user_id=%s action=%s",
                server_id, user_id, command[1:],
            )
            await self.send_command_response(
                message,
                f"{command[1:].title()} failed",
                "Stoat could not apply that action. Check the member and role hierarchy.",
                color="#ED4245",
            )
            return
        await self.send_command_response(
            message,
            f"Member {'kicked' if command == '~kick' else 'banned'}",
            f"**User:** `{await self._resolve_user_tag(user_id)}`\n**Reason:** {reason}",
            color="#ED4245",
        )

    async def handle_unban_command(
        self, message: stoat.Message, server: stoat.Server, server_id: str, parts: list[str]
    ) -> None:
        reason = await self._require_command_reason(message, "~unban", parts)
        if reason is None:
            return
        user_id = self._parse_user_id(parts[1])
        if not await self.require_action_permissions(server, "ban_members"):
            return
        if self.database.get_global_ban(user_id) is not None:
            await self.send_command_response(
                message, "User is globally banned",
                "This user has an active global ban. The global owner must remove it with "
                "`~global_unban USER_ID REASON` before a server unban can take effect.", color="#F59E0B",
            )
            return
        try:
            bans = await server.fetch_bans()
            if not any(ban.user_id == user_id for ban in bans):
                await self.send_command_response(
                    message, "User is not banned", "That user has no ban in this server.", color="#F59E0B",
                )
                return
            await server.unban(user_id)
        except Exception:
            logger.exception("manual_unban_failed server_id=%s user_id=%s", server_id, user_id)
            await self.send_command_response(
                message, "Unban failed", "Stoat could not remove that ban. Check the user ID and my ban permissions.",
                color="#ED4245",
            )
            return
        self.database.add_event(
            server_id=server_id, event_type="manual_unban", user_id=user_id,
            actor_id=message.author_id, channel_id=message.channel_id, details={"reason": reason},
        )
        description = f"**User:** `{await self._resolve_user_tag(user_id)}`\n**Reason:** {reason}"
        await self.send_command_response(message, "Member unbanned", description, color="#3BA55D")
        await self.send_log(
            server_id, "Member unbanned", f"**Moderator:** <@{message.author_id}>\n{description}", color="#3BA55D",
        )
        await self._send_user_dm(
            user_id, "You have been unbanned",
            f"Your ban in **{server.name}** was removed.\n\n**Reason:** {reason}",
            server_id=server_id, color="#3BA55D",
        )

    @staticmethod
    def _format_user_tag(user: object | None) -> str | None:
        if user is None:
            return None
        name = getattr(user, "name", None)
        discriminator = getattr(user, "discriminator", None)
        if not name:
            return None
        return f"{name}#{discriminator}" if discriminator else str(name)

    async def _resolve_user_tag(
        self, user_id: str, user: object | None = None
    ) -> str:
        def remember(candidate: object | None) -> str | None:
            tag = self._format_user_tag(candidate)
            if tag is None:
                return None
            recorder = getattr(
                getattr(self, "database", None), "record_user_identity", None
            )
            if callable(recorder):
                recorder(
                    user_id,
                    getattr(candidate, "name", None),
                    getattr(candidate, "discriminator", None),
                    getattr(candidate, "display_name", None),
                )
            return tag

        tag = remember(user)
        if tag is not None:
            return tag

        tag = remember(self.get_user(user_id))
        if tag is not None:
            return tag

        try:
            tag = remember(await self.fetch_user(user_id))
            if tag is not None:
                return tag
        except Exception:
            logger.warning("user_tag_resolution_failed user_id=%s", user_id)
        identity_getter = getattr(
            getattr(self, "database", None), "get_recorded_user_identity", None
        )
        if callable(identity_getter):
            identity = identity_getter(user_id)
            if identity and identity.get("full_username"):
                return str(identity["full_username"])
        return "Unknown user"

    async def _classify_display_name(
        self, value: str
    ) -> ModerationResult | None:
        try:
            async with self.limiter:
                return await self.moderator.classify_text(value)
        except ModerationError:
            logger.exception("display_name_scan_failed value_length=%s", len(value))
            return None

    @staticmethod
    def _contains_zero_tolerance_slur(value: str) -> bool:
        """Return true only for a configured literal slur inside the name."""
        normalized = unicodedata.normalize("NFKC", value).casefold()
        return any(slur in normalized for slur in ZERO_TOLERANCE_USERNAME_SLURS)

    @staticmethod
    def _literal_slur_moderation_result() -> ModerationResult:
        return ModerationResult(
            flagged=True,
            categories={"hate": True},
            scores={"hate": 1.0},
        )

    async def _enforce_zero_tolerance_username_global_ban(
        self,
        user_id: str,
        username: str,
        *,
        user: object | None = None,
        source_server_id: str | None = None,
    ) -> bool:
        """Create the sole automatic global ban for a literal account-name match."""
        if not self._contains_zero_tolerance_slur(username):
            return False
        bot_marker = getattr(user, "bot", None) if user is not None else None
        if (
            user_id in {GLOBAL_COMMAND_OWNER_ID, self.state.my_id}
            or bot_marker not in (None, False, stoat.UNDEFINED)
        ):
            return False

        locks = getattr(self, "_zero_tolerance_username_locks", None)
        if locks is None:
            locks = {}
            self._zero_tolerance_username_locks = locks
        lock = locks.setdefault(user_id, asyncio.Lock())
        async with lock:
            try:
                if self.database.get_global_ban(user_id) is not None:
                    return True
                reference_id = self._new_global_reference()
                self.database.add_global_ban(
                    reference_id,
                    user_id,
                    ZERO_TOLERANCE_USERNAME_BAN_REASON,
                    self.state.my_id,
                )
            except Exception:
                try:
                    if self.database.get_global_ban(user_id) is not None:
                        return True
                except Exception:
                    pass
                logger.exception(
                    "automatic_username_global_ban_record_failed user_id=%s",
                    user_id,
                )
                return False

        try:
            await self._send_user_dm(
                user_id,
                "You have been automatically globally banned",
                "Your Stoat account username matched Stoatmod's literal "
                "zero-tolerance slur rule. This deterministic account-username "
                "rule is the only automatic global-ban path.\n\n"
                f"**Reference ID:** `{reference_id}`\n"
                f"**Reason:** {ZERO_TOLERANCE_USERNAME_BAN_REASON}"
                f"{self._global_ban_contact_instructions()}",
                server_id=source_server_id,
                user=user,
            )
        except Exception:
            logger.exception(
                "automatic_username_global_ban_dm_failed user_id=%s "
                "reference_id=%s",
                user_id,
                reference_id,
            )
        try:
            await self._apply_global_ban_to_servers(
                user_id,
                ZERO_TOLERANCE_USERNAME_BAN_REASON,
                reference_id=reference_id,
                actor_id=self.state.my_id,
                source="automatic_account_username_slur",
            )
        except Exception:
            logger.exception(
                "automatic_username_global_ban_enforcement_failed user_id=%s "
                "reference_id=%s",
                user_id,
                reference_id,
            )
        return True

    async def _scan_zero_tolerance_usernames(
        self,
        users: list[object],
        *,
        source_server_id: str,
    ) -> int:
        """Apply the literal account-username rule to an existing member list."""
        enforced = 0
        seen_user_ids: set[str] = set()
        for user in users:
            user_id = str(getattr(user, "id", "") or "")
            username = getattr(user, "name", "")
            if (
                not user_id
                or user_id in seen_user_ids
                or username is stoat.UNDEFINED
                or not self._contains_zero_tolerance_slur(str(username))
            ):
                continue
            seen_user_ids.add(user_id)
            try:
                if await self._enforce_zero_tolerance_username_global_ban(
                    user_id,
                    str(username),
                    user=user,
                    source_server_id=source_server_id,
                ):
                    enforced += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(
                    "existing_username_zero_tolerance_scan_failed "
                    "server_id=%s user_id=%s",
                    source_server_id,
                    user_id,
                )
        return enforced

    async def _enforce_display_name_violation(
        self,
        server: stoat.Server,
        member: stoat.Member,
        *,
        name_kind: str,
        previous_value: str | None,
        new_value: str,
        restore_nick: str | None,
        restore_available: bool,
        result: ModerationResult,
        active_categories: list[str],
    ) -> None:
        server_id = server.id
        user_id = member.id
        categories = active_categories
        category_text = ", ".join(categories) or "unsafe content"
        reset_succeeded = False
        reset_error = "The previous name was unavailable."
        suppression_key = (server_id, user_id)
        if restore_available:
            if not await self.require_action_permissions(
                server, "manage_nicknames"
            ):
                restore_available = False
                reset_error = "Stoatmod is missing Manage Nicknames permission."
        if restore_available:
            self._nickname_reset_suppressions.add(suppression_key)
            try:
                await member.edit(nick=restore_nick)
                reset_succeeded = True
                reset_error = ""
                asyncio.get_running_loop().call_later(
                    60, self._nickname_reset_suppressions.discard, suppression_key
                )
            except Exception:
                self._nickname_reset_suppressions.discard(suppression_key)
                reset_error = "The bot could not restore the previous nickname."
                logger.exception(
                    "nickname_reset_failed server_id=%s user_id=%s",
                    server_id,
                    user_id,
                )

        reason = f"Automatic {name_kind} moderation: {category_text}"
        warning_id = self.database.add_warning(
            server_id=server_id,
            user_id=user_id,
            moderator_id=self.state.my_id,
            source="automatic",
            reason=reason,
            categories=result.categories,
            scores=result.scores,
            original_content=new_value,
        )
        warning_case_reference = self._warning_case_reference(
            server_id, warning_id
        )
        total = self._active_warning_count(server_id, user_id)
        user = member.get_user()
        user_tag = await self._resolve_user_tag(user_id, user)
        self.database.add_event(
            server_id=server_id,
            event_type=f"automatic_{name_kind}_moderation",
            user_id=user_id,
            actor_id=self.state.my_id,
            details={
                "warning_id": warning_id,
                "total_warnings": total,
                "previous_value": previous_value,
                "new_value": new_value,
                "nickname_reset_succeeded": reset_succeeded,
                "categories": result.categories,
                "scores": result.scores,
            },
        )
        reset_status = "Restored" if reset_succeeded else f"Failed — {reset_error}"
        await self.send_log(
            server_id,
            f"Unsafe {name_kind} detected",
            f"**User:** `{user_tag}`\n"
            f"**Previous value:** {self._original_message_text(previous_value)}\n"
            f"**New value:** {new_value}\n"
            f"**Nickname reset:** {reset_status}\n"
            f"**Categories:** {category_text}\n"
            f"**Warning case:** `{warning_case_reference}`\n"
            f"**Total warnings:** {total}",
            color="#ED4245",
        )
        await self._send_case_dm(
            user_id,
            f"Your {name_kind} violated server rules",
            f"Your new {name_kind} in **{server.name}** was detected as violating "
            f"the moderation policy.\n\n**Categories:** {category_text}\n"
            f"**Nickname reset:** {reset_status}\n"
            f"**Warning case:** `{warning_case_reference}`\n"
            f"**Warnings in this server:** {total}",
            warning_id=warning_id,
            server_id=server_id,
            user=user,
        )
        await self._enforce_warning_policy_and_notify(
            server, server_id, user_id, warning_id, total
        )

    async def handle_member_nickname_update(
        self, event: stoat.ServerMemberUpdateEvent
    ) -> None:
        nickname_changed = event.member.nick is not stoat.UNDEFINED
        if nickname_changed:
            key = (event.member.server_id, event.member.id)
            if key in self._nickname_reset_suppressions:
                self._nickname_reset_suppressions.discard(key)
                return
            if event.member.id == self.state.my_id:
                return
        server = self.get_server(event.member.server_id)
        if server is None:
            return
        member = event.after or server.get_member(event.member.id)
        if member is None:
            try:
                member = await server.fetch_member(event.member.id)
            except Exception:
                logger.exception(
                    "member_update_fetch_failed server_id=%s user_id=%s",
                    event.member.server_id,
                    event.member.id,
                )
                return
        upsert_member = getattr(self.database, "upsert_dashboard_member", None)
        if upsert_member is not None:
            member_snapshot = self._dashboard_member_snapshot(
                [member], server=server
            )
            if member_snapshot:
                upsert_member(event.member.server_id, member_snapshot[0])
        if not nickname_changed:
            return

        new_nick = event.member.nick
        previous_nick = event.before.nick if event.before is not None else None
        if event.before is not None and previous_nick == new_nick:
            return
        literal_slur_match = (
            new_nick is not None
            and new_nick is not stoat.UNDEFINED
            and self._contains_zero_tolerance_slur(str(new_nick))
        )
        if literal_slur_match:
            new_value = str(new_nick)
            result = self._literal_slur_moderation_result()
            active_categories = ["hate"]
        else:
            if not self.database.get_nickname_protection(event.member.server_id):
                return
            if self._moderator_is_exempt(event.member.server_id, server, member):
                return
            user = member.get_user()
            if user is None:
                try:
                    user = await self.fetch_user(event.member.id)
                except Exception:
                    logger.exception(
                        "nickname_user_fetch_failed user_id=%s", event.member.id
                    )
                    return
            new_value = new_nick if new_nick is not None else user.name
            result = await self._classify_display_name(new_value)
            if result is None:
                return
            active_categories = self._enforced_display_name_categories(
                event.member.server_id, result
            )
            if not active_categories:
                return
        restore_nick = previous_nick
        if restore_nick is stoat.UNDEFINED or (
            restore_nick is not None
            and self._contains_zero_tolerance_slur(str(restore_nick))
        ):
            restore_nick = None
        await self._enforce_display_name_violation(
            server,
            member,
            name_kind="nickname",
            previous_value=previous_nick,
            new_value=new_value,
            restore_nick=restore_nick,
            restore_available=event.before is not None,
            result=result,
            active_categories=active_categories,
        )

    async def handle_username_update(self, event: stoat.UserUpdateEvent) -> None:
        if event.user.name is stoat.UNDEFINED or event.user.id == self.state.my_id:
            return
        new_name = str(event.user.name)
        recorder = getattr(self.database, "record_user_identity", None)
        if callable(recorder):
            recorder(
                event.user.id,
                new_name,
                getattr(event.user, "discriminator", None),
                getattr(event.user, "display_name", None),
            )
        previous_name = event.before.name if event.before is not None else None
        if previous_name == new_name:
            return
        memberships: list[tuple[stoat.Server, stoat.Member]] = []
        for server in self.servers.values():
            member = server.get_member(event.user.id)
            if member is None:
                continue
            memberships.append((server, member))
        source_server_id = memberships[0][0].id if memberships else None
        if await self._enforce_zero_tolerance_username_global_ban(
            event.user.id,
            new_name,
            user=event.user,
            source_server_id=source_server_id,
        ):
            return
        eligible_members = [
            (server, member)
            for server, member in memberships
            if self.database.get_nickname_protection(server.id)
            and not self._moderator_is_exempt(server.id, server, member)
        ]
        if not eligible_members:
            return
        result = await self._classify_display_name(new_name)
        if result is None:
            return
        for server, member in eligible_members:
            active_categories = self._enforced_display_name_categories(server.id, result)
            if not active_categories:
                continue
            await self._enforce_display_name_violation(
                server,
                member,
                name_kind="username",
                previous_value=previous_name,
                new_value=new_name,
                restore_nick=previous_name,
                restore_available=previous_name is not None,
                result=result,
                active_categories=active_categories,
            )

    @staticmethod
    def _aggregate_results(
        results: list[tuple[str, ModerationResult]],
    ) -> tuple[dict[str, bool], dict[str, float]]:
        categories: dict[str, bool] = {}
        scores: dict[str, float] = {}
        for _content_id, result in results:
            for name, value in result.categories.items():
                categories[name] = categories.get(name, False) or value
            for name, value in result.scores.items():
                scores[name] = max(scores.get(name, 0.0), value)
        return categories, scores

    @staticmethod
    def _triggered_category_names(policy_matches: list[dict[str, object]]) -> list[str]:
        """Categories that actually triggered: a policy match scoring at least the action minimum (90%), excluding support-only categories."""
        candidates = [
            match for match in policy_matches
            if str(match["category"]) not in SUPPORT_ONLY_CATEGORIES
        ]
        strict = {
            str(match["category"]) for match in candidates
            if float(match.get("score") or 0.0) >= MIN_ACTION_SCORE
        }
        # A match always passed its own threshold; fall back to the matched names if a score were ever missing.
        return sorted(strict or {str(match["category"]) for match in candidates})

    @staticmethod
    def _format_scores(scores: dict[str, float]) -> str:
        if not scores:
            return "• No category scores available"
        return "\n".join(
            f"• `{name}` — **{score:.2%}**"
            for name, score in sorted(
                scores.items(), key=lambda item: item[1], reverse=True
            )
        )

    @staticmethod
    def _log_channel_from_parts(command: str, parts: list[str]) -> str | None:
        if command == "~log-channel":
            return parts[1] if len(parts) >= 2 else None
        if len(parts) >= 3 and parts[1].lower() == "channel":
            return parts[2]
        if len(parts) == 2:
            return parts[1]
        return None


    async def _send_suicidal_thoughts_support(
        self,
        message: stoat.Message,
        server_id: str,
        score: float,
    ) -> None:
        support_dm_times = getattr(self, "_support_dm_times", None)
        if support_dm_times is None:
            support_dm_times = {}
            self._support_dm_times = support_dm_times
        key = (server_id, message.author_id)
        now = time.monotonic()
        last_sent = support_dm_times.get(key)
        if last_sent is not None and now - last_sent < 3600:
            return
        support_dm_times[key] = now
        delivered = await self._send_user_dm(
            message.author_id,
            "We hope you're okay",
            "Something you wrote suggested that you may be thinking about suicide "
            "or hurting yourself. **You are not in trouble for sharing how you "
            "feel. This is a support message, not a warning.**\n\n"
            "If you may be in immediate danger, contact your local emergency "
            "services now. If you can, consider reaching out to someone you trust.\n\n"
            "**Support resources**\n"
            "• **UK & ROI:** Samaritans — call **116 123** free, any time\n"
            "  https://www.samaritans.org/how-we-can-help/contact-samaritan/\n"
            "• **United States:** call or text **988**\n"
            "  https://988lifeline.org/\n"
            "• **Canada:** call or text **9-8-8**\n"
            "  https://988.ca/\n"
            "• **Other countries:** find a verified local helpline\n"
            "  https://findahelpline.com/",
            server_id=server_id,
            user=message.get_author_as_user(),
            color="#5865F2",
        )
        self.database.add_event(
            server_id=server_id,
            event_type="self_harm_support",
            user_id=message.author_id,
            actor_id=self.state.my_id,
            message_id=message.id,
            channel_id=message.channel_id,
            details={
                "category": SUPPORT_CATEGORY,
                "score": float(score),
                "delivered": delivered,
            },
        )
        if not delivered:
            logger.error(
                "self_harm_support_dm_failed server_id=%s user_id=%s",
                server_id,
                message.author_id,
            )

    def _is_moderator(self, message: stoat.Message, server: stoat.Server) -> bool:
        member = message.get_author_as_member()
        if member is None:
            return False
        return self._member_is_moderator(server, member)

    async def _message_author_is_moderator(self, message: stoat.Message) -> bool:
        server, server_id = message.get_server()
        if server is None or not server_id:
            return False
        if not self._moderator_exemption_enabled(server_id):
            return False
        member = message.get_author_as_member()
        if member is None:
            member = server.get_member(message.author_id)
        if member is None:
            try:
                member = await server.fetch_member(message.author_id)
            except Exception:
                logger.warning(
                    "message_member_fetch_failed server_id=%s user_id=%s",
                    server_id,
                    message.author_id,
                )
                return False
        return self._member_is_moderator(server, member)

    def _moderator_exemption_enabled(self, server_id: str) -> bool:
        getter = getattr(self.database, "get_moderator_exemption", None)
        return True if getter is None else bool(getter(server_id))

    def _spam_detection_enabled(self, server_id: str) -> bool:
        getter = getattr(self.database, "get_spam_detection", None)
        return True if getter is None else bool(getter(server_id))

    def _spam_settings(self, server_id: str) -> dict[str, int | float]:
        defaults: dict[str, int | float] = {
            "repeat_count": int(getattr(self.moderation_settings, "spam_repeat_count", 3)),
            "repeat_window_seconds": float(
                getattr(self.moderation_settings, "spam_repeat_window_seconds", 30)
            ),
            "rapid_count": int(getattr(self.moderation_settings, "spam_rapid_count", 5)),
            "rapid_window_seconds": float(
                getattr(self.moderation_settings, "spam_rapid_window_seconds", 10)
            ),
            "score_threshold": float(
                getattr(self.moderation_settings, "spam_score_threshold", 7)
            ),
            "score_half_life_seconds": float(
                getattr(self.moderation_settings, "spam_score_half_life_seconds", 30)
            ),
            "mass_mention_limit": int(
                getattr(self.moderation_settings, "mass_mention_limit", 5)
            ),
            "timeout_seconds": int(
                getattr(self.moderation_settings, "spam_timeout_seconds", 3600)
            ),
        }
        getter = getattr(getattr(self, "database", None), "get_spam_settings", None)
        if not callable(getter):
            return defaults
        return {**defaults, **getter(server_id, defaults)}

    def _clear_spam_state(self, server_id: str) -> None:
        for collection in (
            self._spam_history,
            self._spam_scores,
            self._spam_timeout_until,
            self.__dict__.get("_everyone_history", {}),
        ):
            for key in [key for key in collection if key[0] == server_id]:
                collection.pop(key, None)

    def _moderator_is_exempt(
        self,
        server_id: str,
        server: stoat.Server,
        member: stoat.Member,
    ) -> bool:
        return self._moderator_exemption_enabled(
            server_id
        ) and self._member_is_moderator(server, member)

    @staticmethod
    def _member_is_moderator(server: stoat.Server, member: stoat.Member) -> bool:
        permissions = server.permissions_for(member)
        return bool(
            getattr(permissions, "manage_messages", False)
            or getattr(permissions, "timeout_members", False)
            or getattr(permissions, "kick_members", False)
            or getattr(permissions, "ban_members", False)
            or getattr(permissions, "manage_nicknames", False)
            or getattr(permissions, "manage_server", False)
        )

    @staticmethod
    def _resolve_scope_target(
        server: stoat.Server, target_id: str
    ) -> tuple[str, str] | None:
        channel = server.get_channel(target_id)
        if channel is not None:
            return "channel", getattr(channel, "name", target_id)
        category = server.get_category(target_id)
        if category is not None:
            return "category", category.title
        return None

    @staticmethod
    def _embed_title_with_emoji(title: str) -> str:
        if title.startswith(EMBED_TITLE_EMOJIS):
            return title
        normalized = title.casefold()
        rules = (
            (("help", "command list"), "📚"),
            (("information", "server information"), "💡"),
            (("status", "lookup", "history"), "📊"),
            (("warning", "warn"), "🚨"),
            (("failed", "failure", "denied", "invalid", "cannot", "unsafe"), "❌"),
            (("complete", "passed", "accepted", "enabled", "included", "success"), "✅"),
            (("captcha", "verification", "join protection"), "🔐"),
            (("edited", "nickname", "username"), "📝"),
            (("deleted", "deletion", "removed"), "🧹"),
            (("link",), "🔗"),
            (("spam", "mass mention"), "🚨"),
            (("moderation", "protection", "exemption", "policy", "categories"), "🔰"),
            (("configuration", "updated", "scope", "log channel"), "🔧"),
            (("global", "server"), "🌐"),
            (("member", "user"), "👤"),
            (("message", "announcement"), "📨"),
        )
        emoji = next(
            (
                candidate
                for keywords, candidate in rules
                if any(keyword in normalized for keyword in keywords)
            ),
            "✨",
        )
        return f"{emoji} {title}"

    @classmethod
    def _embed(cls, title: str, description: str, color: str) -> stoat.SendableEmbed:
        return stoat.SendableEmbed(
            title=cls._embed_title_with_emoji(title),
            description=description,
            color=color,
        )

    @staticmethod
    def _split_embed_description(
        description: str, limit: int = EMBED_DESCRIPTION_LIMIT
    ) -> list[str]:
        if len(description.encode("utf-8")) <= limit:
            return [description]
        chunks: list[str] = []
        remaining = description
        while len(remaining.encode("utf-8")) > limit:
            low = 1
            high = min(len(remaining), limit)
            while low < high:
                midpoint = (low + high + 1) // 2
                if len(remaining[:midpoint].encode("utf-8")) <= limit:
                    low = midpoint
                else:
                    high = midpoint - 1
            max_characters = low
            split_at = remaining.rfind("\n", 0, max_characters)
            if split_at < max_characters // 2:
                split_at = max_characters
            else:
                split_at += 1
            chunks.append(remaining[:split_at])
            remaining = remaining[split_at:]
        if remaining:
            chunks.append(remaining)
        return chunks

    async def _send_embed_pages(
        self,
        channel: object,
        title: str,
        description: str,
        color: str,
    ) -> None:
        pages = self._split_embed_description(description)
        total = len(pages)
        for index, page in enumerate(pages, start=1):
            page_title = title if total == 1 else f"{title} ({index}/{total})"
            await channel.send(embeds=[self._embed(page_title, page, color)])

    @staticmethod
    def _original_message_text(content: str | None) -> str:
        if content is None:
            return "*(Not available for this warning.)*"
        if not content:
            return "*(The deleted message contained no text.)*"
        return content


    @staticmethod
    def _warning_reason(record: WarningRecord) -> str:
        if not record.scores:
            return record.reason
        scored_categories = [
            (category, score)
            for category, score in record.scores.items()
            if record.categories.get(category, False)
        ] or list(record.scores.items())
        category, score = max(scored_categories, key=lambda item: item[1])
        return f"{category.replace('_', ' ')} — {score:.2%}"

    @classmethod
    def _warning_history(
        cls,
        records: list[WarningRecord],
        case_ids: dict[int, str] | None = None,
    ) -> str:
        return "\n\n".join(
            (
                f"**Case ID:** `{cls._case_reference(case_ids[record.id])}`\n"
                if case_ids is not None and record.id in case_ids
                else ""
            )
            + f"**Reason:** {cls._warning_reason(record)}\n"
            f"**Original message:**\n{cls._original_message_text(record.original_content)}\n"
            f"**Date & time:** {record.created_at}"
            for record in records
        )

    @staticmethod
    def _case_reference(reference_id: str) -> str:
        return f"CASE-{reference_id.upper()}"

    @staticmethod
    def _parse_case_id(value: str) -> str | None:
        normalized = value.strip().strip("`\"'")
        normalized = normalized.replace("–", "-").replace("—", "-")
        match = re.fullmatch(
            r"(?:case[\s_:#-]*)?#?[\[(]?([A-Z0-9]+)[\])]?[.,:]?",
            normalized,
            re.I,
        )
        if match is None:
            return None
        reference_id = match.group(1).upper()
        if reference_id.isdigit():
            return reference_id if 1 <= len(reference_id) <= 18 else None
        if len(reference_id) != 8:
            return None
        if not any(character.isalpha() for character in reference_id):
            return None
        if not any(character.isdigit() for character in reference_id):
            return None
        return reference_id

    @staticmethod
    def _appeal_decision(value: str) -> str | None:
        operation = value.strip().strip("[](){}:,.!").lower()
        if operation in {
            "accept",
            "accepted",
            "approve",
            "approved",
            "grant",
            "granted",
            "yes",
        }:
            return "approved"
        if operation in {
            "deny",
            "denied",
            "reject",
            "rejected",
            "decline",
            "declined",
            "no",
        }:
            return "denied"
        return None

    @classmethod
    def _case_history(cls, records: list[ModerationCaseRecord]) -> str:
        return "\n\n".join(
            f"**Case ID:** `{cls._case_reference(record.reference_id)}`\n"
            f"**Action:** {record.action.replace('_', ' ').title()}\n"
            f"**Reason:** {record.reason}\n"
            f"**Status:** {record.status.title()}\n"
            f"**Date & time:** {record.created_at}"
            for record in records
        )

    def _event_case_line(self, server_id: str, event_id: int) -> str:
        getter = getattr(self.database, "get_event_case", None)
        if getter is None:
            return ""
        record = getter(server_id, event_id)
        if record is None:
            return ""
        return f"**Case ID:** `{self._case_reference(record.reference_id)}`\n"

    def _warning_case_reference(
        self, server_id: str, warning_id: int
    ) -> str:
        getter = getattr(self.database, "get_warning_case", None)
        if getter is None:
            return "Unavailable"
        record = getter(server_id, warning_id)
        if record is None:
            return "Unavailable"
        return self._case_reference(record.reference_id)


    @staticmethod
    async def _server_has_member(server: stoat.Server, user_id: str) -> bool:
        if server.get_member(user_id) is not None:
            return True
        try:
            return await server.fetch_member(user_id) is not None
        except Exception:
            return False

    async def send_log(
        self,
        server_id: str,
        title: str,
        description: str,
        *,
        color: str = "#5865F2",
        raise_on_error: bool = False,
    ) -> None:
        channel_id = self.database.get_log_channel(server_id)
        if not channel_id:
            if raise_on_error:
                raise LookupError("No moderation log channel is configured")
            return
        title, description = localize_delivery(
            self._server_locale(server_id), title, description
        )
        channel = self.get_channel(channel_id, partial=True)
        try:
            await self._send_embed_pages(channel, title, description, color)
        except Exception:
            logger.exception(
                "log_channel_send_failed server_id=%s channel_id=%s",
                server_id,
                channel_id,
            )
            if raise_on_error:
                raise

    async def send_command_response(
        self,
        message: stoat.Message,
        title: str,
        description: str,
        *,
        color: str = "#5865F2",
    ) -> None:
        try:
            await self._send_embed_pages(message.channel, title, description, color)
        except Exception:
            logger.warning(
                "command_embed_send_failed channel_id=%s; retrying_as_text",
                getattr(message, "channel_id", None),
                exc_info=True,
            )
            pages = self._split_embed_description(description)
            total = len(pages)
            for index, page in enumerate(pages, start=1):
                page_title = title if total == 1 else f"{title} ({index}/{total})"
                await message.channel.send(content=f"**{page_title}**\n\n{page}")

    async def announce_server(self, server: stoat.Server) -> bool:
        lock = self._announcement_locks.setdefault(server.id, asyncio.Lock())
        async with lock:
            if self.database.has_server_announcement(server.id):
                return False
            description = (
                f"Thanks for adding **Stoatmod** to **{server.name}**.\n\n"
                "Stoatmod provides automated moderation, spam and link protection, CAPTCHA "
                "join checks, moderation cases, appeals, statistics, and server Discovery.\n\n"
                "**1 — Permissions come first**\n"
                "Grant every permission reported by `~setup` and place the Stoatmod role "
                "above the members and automatic roles it manages. Permissions are essential: "
                "missing access can stop the bot deleting unsafe content, assigning roles, "
                "managing nicknames, timing out, kicking or banning members, completing "
                "verification, or writing logs. Full permissions are also required to "
                "advertise in Discovery. Run `~setup` now to find and fix anything missing.\n\n"
                "**2 — Choose your server language**\n"
                "Run `~language` to view it, or use `~language English`, `~language French`, "
                "`~language Portuguese`, or `~language Spanish` to change member DMs, join "
                "verification, help, and moderation logs.\n\n"
                "**3 — Open the dashboard**\n"
                "Run `~dashboard` for a private one-time login code. Configure protections, "
                "review cases and appeals, see statistics, and manage Discovery there.\n\n"
                "**4 — Advertise your server with Discovery**\n"
                "Our public Discovery page helps people find servers using Stoatmod. To apply, "
                "keep the bot installed, grant all permissions, add a server icon, and enable "
                "global statistics. Open **Dashboard → Discovery**, add a description, Stoat "
                "invite and tags, then submit for review. Once approved, run `~bump` every two "
                "hours to return to the top.\n\n"
                "Use `~help` for every command. Join and nickname protection are enabled by "
                "default, and eligible moderation actions include a secure appeal code."
            )
            for channel in server.channels:
                if not isinstance(channel, stoat.TextChannel) or self._channel_is_nsfw(channel):
                    continue
                try:
                    await self._send_embed_pages(
                        channel,
                        "Stoatmod setup and information",
                        description,
                        "#5865F2",
                    )
                except Exception:
                    logger.info(
                        "server_announcement_channel_failed server_id=%s channel_id=%s",
                        server.id,
                        channel.id,
                    )
                    continue
                self.database.record_server_announcement(server.id, channel.id)
                logger.info(
                    "server_announcement_sent server_id=%s channel_id=%s",
                    server.id,
                    channel.id,
                )
                return True
            logger.warning("server_announcement_no_channel server_id=%s", server.id)
            return False

    async def require_action_permissions(
        self,
        server: stoat.Server,
        *permission_names: str,
        renotify_after_seconds: int | None = None,
    ) -> bool:
        state = getattr(self, "_state", None)
        bot_id = getattr(state, "my_id", None)
        if bot_id is None or not hasattr(server, "get_member"):
            return True
        bot_member = server.get_member(bot_id)
        if bot_member is None:
            try:
                bot_member = await server.fetch_member(bot_id)
            except Exception:
                logger.warning(
                    "permission_notice_bot_member_unavailable server_id=%s", server.id
                )
                return False
        permissions = server.permissions_for(bot_member)
        missing_for_action = [
            requirement
            for requirement in SERVER_PERMISSION_REQUIREMENTS
            if requirement[0] in permission_names
            and getattr(permissions, requirement[0], None) is False
        ]
        if not missing_for_action:
            return True
        already_notified = (
            self.database.list_server_permission_notices(
                server.id, within_seconds=renotify_after_seconds
            )
            if renotify_after_seconds is not None
            else self.database.list_server_permission_notices(server.id)
        )
        missing = [
            (name, label, impact)
            for name, label, impact in missing_for_action
            if name not in already_notified
        ]
        if not missing:
            return False

        description = (
            f"Stoatmod is missing permission{'s' if len(missing) != 1 else ''} "
            f"in **{server.name}**. Until fixed:\n\n"
            + "\n".join(
                f"• **{label}** — Stoatmod cannot {impact}."
                for _name, label, impact in missing
            )
            + "\n\nRun `~setup` after updating the bot role to check the full setup. "
            + (
                f"This notice repeats at most once every {renotify_after_seconds // 3600} hours while the permission is still missing."
                if renotify_after_seconds is not None
                else "Each missing permission is reported only once."
            )
        )
        log_channel_id = self.database.get_log_channel(server.id)
        if not log_channel_id:
            delivered_to = await self._send_permission_notice_to_owner(
                server, description
            )
        else:
            channel = self.get_channel(log_channel_id, partial=True)
            try:
                await self._send_embed_pages(
                    channel,
                    "Stoatmod is missing permissions",
                    description,
                    "#F59E0B",
                )
            except Exception:
                try:
                    await channel.send(
                        content="Stoatmod is missing permissions\n\n" + description
                    )
                except Exception:
                    logger.info(
                        "permission_notice_log_channel_failed server_id=%s channel_id=%s",
                        server.id,
                        log_channel_id,
                    )
                    delivered_to = await self._send_permission_notice_to_owner(
                        server, description
                    )
                else:
                    delivered_to = log_channel_id
            else:
                delivered_to = log_channel_id
        if delivered_to is None:
            return False
        names = [name for name, _label, _impact in missing]
        if renotify_after_seconds is None:
            self.database.record_server_permission_notices(
                server.id, names, delivered_to
            )
        else:
            self.database.record_server_permission_notices(
                server.id, names, delivered_to, refresh_existing=True
            )
        logger.warning(
            "permission_notice_sent server_id=%s permissions=%s destination=%s",
            server.id,
            ",".join(name for name, _label, _impact in missing),
            delivered_to,
        )
        return False

    async def _send_permission_notice_to_owner(
        self, server: stoat.Server, description: str
    ) -> str | None:
        owner_id = str(getattr(server, "owner_id", "") or "")
        if not owner_id:
            logger.warning(
                "permission_notice_owner_unavailable server_id=%s", server.id
            )
            return None
        get_owner = getattr(server, "get_owner", None)
        owner = get_owner() if callable(get_owner) else None
        delivered = await self._send_user_dm(
            owner_id,
            "Stoatmod cannot complete a server action",
            description
            + "\n\nThe configured moderation log channel is unavailable, so this "
            "one-time notice was sent privately to you as the server owner.",
            server_id=server.id,
            user=owner,
            color="#F59E0B",
        )
        return f"dm:{owner_id}" if delivered else None

    def _dashboard_permission_audit(
        self,
        server: stoat.Server,
        inaccessible_channel_ids: list[str] | None = None,
        bot_member: object | None = None,
        resolved_channels: list[object] | None = None,
    ) -> dict[str, object]:
        """Return the same permission checks used by ``~setup`` for the dashboard."""
        state = getattr(self, "_state", None)
        bot_id = getattr(state, "my_id", None)
        get_member = getattr(server, "get_member", None)
        if bot_member is None:
            bot_member = (
                get_member(bot_id) if bot_id and callable(get_member) else None
            )
        checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        get_log_channel = getattr(self.database, "get_log_channel", None)
        log_channel_id = (
            get_log_channel(server.id) if callable(get_log_channel) else None
        )
        if bot_member is None:
            return {
                "available": False,
                "checked_at": checked_at,
                "permissions": [],
                "missing_count": 0,
                "inaccessible_channels": list(inaccessible_channel_ids or []),
                "log_channel": {
                    "configured": bool(log_channel_id),
                    "accessible": False,
                    "channel_id": log_channel_id,
                    "missing": ["Unable to resolve Stoatmod's server member record"],
                },
            }

        permissions = server.permissions_for(bot_member)
        inaccessible_channels = set(inaccessible_channel_ids or [])
        raw_channels = getattr(server, "channels", None) or []
        cached_channels = (
            list(raw_channels.values())
            if isinstance(raw_channels, dict)
            else list(raw_channels)
        )
        channels = [*cached_channels, *(resolved_channels or [])]
        for channel in channels:
            channel_id = str(getattr(channel, "id", "") or "")
            channel_permissions_for = getattr(channel, "permissions_for", None)
            if not channel_id or not callable(channel_permissions_for):
                continue
            try:
                channel_permissions = channel_permissions_for(bot_member)
            except Exception:
                continue
            if getattr(channel_permissions, "view_channel", None) is False:
                inaccessible_channels.add(channel_id)
        permission_results = [
            {
                "name": name,
                "label": label,
                "impact": impact,
                "granted": bool(getattr(permissions, name, False)),
            }
            for name, label, impact in SERVER_PERMISSION_REQUIREMENTS
        ]
        log_missing: list[str] = []
        if not log_channel_id:
            log_missing.append("No moderation log channel is configured")
        else:
            get_channel = getattr(server, "get_channel", None)
            log_channel = get_channel(log_channel_id) if callable(get_channel) else None
            if log_channel is None:
                log_channel = next(
                    (
                        channel
                        for channel in resolved_channels or []
                        if str(getattr(channel, "id", "")) == str(log_channel_id)
                    ),
                    None,
                )
            if log_channel is None:
                get_cached_channel = getattr(self, "get_channel", None)
                if callable(get_cached_channel):
                    log_channel = get_cached_channel(log_channel_id)
            if log_channel is None:
                log_missing.append("The configured moderation log channel no longer exists")
            else:
                try:
                    channel_permissions = log_channel.permissions_for(bot_member)
                except stoat.NoData:
                    # A freshly fetched channel can arrive before its server is
                    # hydrated into Stoat's global cache. Keep the dashboard
                    # snapshot usable, but do not guess around channel overrides.
                    log_missing.append(
                        "Unable to verify moderation log channel permissions"
                    )
                else:
                    for name, label in (
                        ("view_channel", "View Channel"),
                        ("send_messages", "Send Messages"),
                        ("send_embeds", "Send Embeds"),
                    ):
                        if not bool(getattr(channel_permissions, name, False)):
                            log_missing.append(label)

        return {
            "available": True,
            "checked_at": checked_at,
            "permissions": permission_results,
            "missing_count": sum(
                not bool(item["granted"]) for item in permission_results
            ),
            "inaccessible_channels": sorted(inaccessible_channels),
            "log_channel": {
                "configured": bool(log_channel_id),
                "accessible": bool(log_channel_id) and not log_missing,
                "channel_id": log_channel_id,
                "missing": log_missing,
            },
        }

    async def _setup_audit_description(self, server: stoat.Server) -> str:
        bot_member = server.get_member(self.state.my_id)
        if bot_member is None:
            try:
                bot_member = await server.fetch_member(self.state.my_id)
            except Exception:
                return "❌ Stoatmod could not resolve its own server member record."
        permissions = server.permissions_for(bot_member)
        required_permissions = tuple(
            (label, name) for name, label, _impact in SERVER_PERMISSION_REQUIREMENTS
        )
        permission_lines = [
            f"{'✅' if getattr(permissions, name, False) else '❌'} {label}"
            for label, name in required_permissions
        ]
        issues = sum(
            not bool(getattr(permissions, name, False))
            for _label, name in required_permissions
        )
        inaccessible_channels: list[str] = []
        get_overview = getattr(self.database, "get_dashboard_overview", None)
        if callable(get_overview):
            try:
                stored_audit = get_overview(server.id).get("permission_audit", {})
                inaccessible_channels = list(
                    stored_audit.get("inaccessible_channels", [])
                )
            except Exception:
                logger.debug(
                    "setup_permission_snapshot_unavailable server_id=%s",
                    server.id,
                    exc_info=True,
                )
        channel_access_line = (
            f"❌ {len(inaccessible_channels)} channel override"
            f"{'s' if len(inaccessible_channels) != 1 else ''} block Stoatmod access"
            if inaccessible_channels
            else "✅ No inaccessible channels detected"
        )
        issues += len(inaccessible_channels)

        log_channel_id = self.database.get_log_channel(server.id)
        if not log_channel_id:
            log_line = "❌ No moderation log channel is configured"
            issues += 1
        else:
            log_channel = server.get_channel(log_channel_id)
            if log_channel is None:
                log_line = "❌ The configured moderation log channel no longer exists"
                issues += 1
            else:
                try:
                    channel_permissions = log_channel.permissions_for(bot_member)
                except stoat.NoData:
                    log_line = (
                        f"❌ Log channel <#{log_channel_id}> permissions could not "
                        "be verified yet"
                    )
                    issues += 1
                else:
                    log_ok = all(
                        bool(getattr(channel_permissions, name, False))
                        for name in ("view_channel", "send_messages", "send_embeds")
                    )
                    log_line = (
                        f"{'✅' if log_ok else '❌'} Log channel <#{log_channel_id}> "
                        f"is {'accessible' if log_ok else 'missing view/send/embed access'}"
                    )
                    issues += int(not log_ok)

        auto_role_lines: list[str] = []
        bot_top_role = getattr(bot_member, "top_role", None)
        raw_roles = getattr(server, "roles", {}) or {}
        roles = raw_roles if isinstance(raw_roles, dict) else {
            role.id: role for role in raw_roles
        }
        for role_id in self.database.list_auto_roles(server.id):
            role = roles.get(role_id)
            if role is None:
                auto_role_lines.append(f"❌ `{role_id}` no longer exists")
                issues += 1
                continue
            hierarchy_ok = (
                bot_top_role is not None
                and getattr(bot_top_role, "rank", 10**9) < getattr(role, "rank", -1)
            )
            auto_role_lines.append(
                f"{'✅' if hierarchy_ok else '❌'} {role.name} — "
                f"{'assignable' if hierarchy_ok else 'move the Stoatmod role above it'}"
            )
            issues += int(not hierarchy_ok)
        if not auto_role_lines:
            auto_role_lines.append("ℹ️ No automatic roles are configured")

        dashboard_ready = bool(self.moderation_settings.dashboard_url)
        issues += int(not dashboard_ready)
        summary = (
            "✅ Setup looks ready."
            if issues == 0
            else f"⚠️ Found **{issues}** setup issue{'s' if issues != 1 else ''}."
        )
        return (
            f"{summary}\n\n**Bot permissions**\n"
            + "\n".join(permission_lines)
            + f"\n\n**Channel access overrides**\n{channel_access_line}"
            + f"\n\n**Moderation logging**\n{log_line}"
            + "\n\n**Automatic roles & hierarchy**\n"
            + "\n".join(auto_role_lines)
            + "\n\n**Website dashboard**\n"
            + ("✅ Dashboard URL is configured" if dashboard_ready else "❌ Dashboard URL is missing")
            + "\n\nUse `~dashboard` for a one-time website login code."
        )

    def _new_global_reference(self) -> str:
        for _attempt in range(100):
            reference_id = "".join(
                secrets.choice(GLOBAL_REFERENCE_ALPHABET) for _ in range(6)
            )
            if not self.database.global_reference_exists(reference_id):
                return reference_id
        raise RuntimeError("Unable to allocate a unique global reference ID")

    def _global_ban_servers(self) -> list[stoat.Server]:
        # Ready initialization performs network work before Stoat fills its
        # cache. Its filtered server set remains authoritative during that time.
        ready_servers = getattr(self, "_ready_event_servers", None)
        return list((ready_servers if ready_servers is not None else self.servers).values())

    async def _apply_global_ban_to_servers(
        self,
        user_id: str,
        reason: str,
        *,
        unban: bool = False,
        reference_id: str | None = None,
        actor_id: str | None = None,
        source: str = "global_moderation",
    ) -> tuple[list[str], list[str]]:
        succeeded: list[str] = []
        failed: list[str] = []
        enforcement_reason = (
            f"Global ban {reference_id}: {reason}" if reference_id else reason
        )
        for server in self._global_ban_servers():
            try:
                if unban:
                    if not await self.require_action_permissions(
                        server, "ban_members"
                    ):
                        failed.append(server.name)
                        continue
                    existing = next(
                        (ban for ban in await server.fetch_bans() if ban.user_id == user_id),
                        None,
                    )
                    # Only undo this global ban. A local ban (including one
                    # predating global enforcement) belongs to the server.
                    if existing is not None:
                        if not reference_id or not (existing.reason or "").startswith(
                            f"Global ban {reference_id}: "
                        ):
                            continue
                        try:
                            await server.unban(user_id)
                        except stoat.errors.NotFound:
                            # Another moderator may already have removed it.
                            pass
                    succeeded.append(server.name)
                    continue
                if not await self._server_has_member(server, user_id):
                    continue
                if not await self.require_action_permissions(server, "ban_members"):
                    failed.append(server.name)
                    continue
                # Never overwrite a pre-existing server ban with our reason,
                # even if membership is still present in the cache.
                if any(ban.user_id == user_id for ban in await server.fetch_bans()):
                    continue
                self._suppress_global_ban_removal(server.id, user_id)
                await server.ban(user_id, reason=enforcement_reason[:1024])
                succeeded.append(server.name)
                add_event = getattr(getattr(self, "database", None), "add_event", None)
                if callable(add_event):
                    add_event(
                        server_id=server.id,
                        event_type="global_ban_enforced",
                        user_id=user_id,
                        actor_id=actor_id,
                        details={
                            "reason": reason,
                            "global_reference": reference_id,
                            "enforcement_source": source,
                        },
                    )
                reference_line = (
                    f"**Reference ID:** `{reference_id}`\n" if reference_id else ""
                )
                await self.send_log(
                    server.id,
                    "Global ban enforced",
                    f"{reference_line}**User:** <@{user_id}>\n**Reason:** {reason}",
                    color="#ED4245",
                )
            except Exception:
                self._global_ban_removal_suppressions.discard(
                    (server.id, user_id)
                )
                failed.append(server.name)
                logger.exception(
                    "global_%s_failed server_id=%s user_id=%s",
                    "unban" if unban else "ban",
                    server.id,
                    user_id,
                )
        return succeeded, failed

    def _suppress_global_ban_removal(self, server_id: str, user_id: str) -> None:
        key = (server_id, user_id)
        self._global_ban_removal_suppressions.add(key)
        asyncio.get_running_loop().call_later(
            60, self._global_ban_removal_suppressions.discard, key
        )

    async def _send_global_warning_log(
        self, title: str, description: str, *, color: str
    ) -> None:
        for server_id in self.servers:
            await self.send_log(server_id, title, description, color=color)

    async def _send_global_announcement(
        self, announcement: str
    ) -> tuple[int, list[str], list[str]]:
        configured = 0
        succeeded: list[str] = []
        failed: list[str] = []
        description = (
            "━━━━━━━━━━━━━━━━━━━━\n"
            "**A message from the Stoatmod team**\n\n"
            f"{announcement}\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "*Official service-wide announcement*\n\n"
            "**Need help?**\n"
            f"**Support server:** {SUPPORT_SERVER_URL}\n"
            f"**Email:** `{SUPPORT_EMAIL}`"
        )
        embed = self._embed(
            "📣 OFFICIAL STOATMOD ANNOUNCEMENT",
            description,
            "#F2C94C",
        )
        target_getter = getattr(
            self.database, "list_global_announcement_targets", None
        )
        if callable(target_getter):
            targets = target_getter()
        else:
            targets = [
                {
                    "server_id": server.id,
                    "server_name": server.name,
                    "owner_id": getattr(server, "owner_id", None),
                    "log_channel_id": self.database.get_log_channel(server.id),
                }
                for server in self.servers.values()
            ]
        cached_servers = self.servers
        for target in targets:
            server_id = str(target["server_id"])
            live_server = cached_servers.get(server_id)
            server_name = str(
                getattr(live_server, "name", None)
                or target.get("server_name")
                or server_id
            )
            owner_id = str(
                getattr(live_server, "owner_id", None)
                or target.get("owner_id")
                or ""
            ).strip()
            create_announcement = getattr(
                self.database, "create_dashboard_announcement", None
            )
            if callable(create_announcement):
                try:
                    create_announcement(
                        server_id,
                        "Official Stoatmod announcement",
                        announcement,
                        GLOBAL_COMMAND_OWNER_ID,
                    )
                except Exception:
                    logger.exception(
                        "global_announcement_dashboard_failed server_id=%s",
                        server_id,
                    )
            add_event = getattr(self.database, "add_event", None)
            if callable(add_event):
                try:
                    add_event(
                        server_id=server_id,
                        event_type="global_announcement",
                        actor_id=GLOBAL_COMMAND_OWNER_ID,
                        details={"message": announcement},
                    )
                except Exception:
                    logger.exception(
                        "global_announcement_event_failed server_id=%s", server_id
                    )
            channel_id = target.get("log_channel_id")
            if not channel_id:
                continue
            configured += 1
            try:
                if not owner_id:
                    raise LookupError("Server owner is unavailable")
                channel = self.get_channel(channel_id)
                if channel is None:
                    channel = await self.fetch_channel(channel_id)
                if channel is None:
                    raise LookupError("Moderation log channel is unavailable")
                await channel.send(
                    content=(
                        f"📣 <@{owner_id}> — an official Stoatmod announcement "
                        f"for **{server_name}**"
                    ),
                    embeds=[embed],
                    silent=False,
                    mention_everyone=False,
                    mention_online=False,
                )
                succeeded.append(server_name)
            except stoat.errors.NotFound:
                failed.append(server_name)
                logger.warning(
                    "global_announcement_stale_log_channel "
                    "server_id=%s channel_id=%s",
                    server_id,
                    channel_id,
                )
            except Exception:
                failed.append(server_name)
                logger.exception(
                    "global_announcement_send_failed server_id=%s channel_id=%s",
                    server_id,
                    channel_id,
                )
        return configured, succeeded, failed

    async def sync_global_bans(self, servers: list[stoat.Server]) -> None:
        records = self.database.list_global_bans()
        if not records:
            return
        for server in servers:
            try:
                existing = {ban.user_id for ban in await server.fetch_bans()}
            except stoat.errors.Forbidden:
                logger.warning(
                    "global_ban_sync_fetch_forbidden server_id=%s name=%r missing_permission=BanMembers",
                    server.id,
                    server.name,
                )
                await self.require_action_permissions(
                    server,
                    "ban_members",
                    renotify_after_seconds=GLOBAL_BAN_PERMISSION_NOTICE_SECONDS,
                )
                continue
            except Exception:
                logger.exception(
                    "global_ban_sync_fetch_failed server_id=%s", server.id
                )
                continue
            for record in records:
                if record.user_id in existing:
                    continue
                if not await self._server_has_member(server, record.user_id):
                    continue
                if not await self.require_action_permissions(
                    server,
                    "ban_members",
                    renotify_after_seconds=GLOBAL_BAN_PERMISSION_NOTICE_SECONDS,
                ):
                    continue
                try:
                    self._suppress_global_ban_removal(server.id, record.user_id)
                    await server.ban(
                        record.user_id,
                        reason=(
                            f"Global ban {record.reference_id}: {record.reason}"
                        )[:1024],
                    )
                    self.database.add_event(
                        server_id=server.id,
                        event_type="global_ban_synchronized",
                        user_id=record.user_id,
                        actor_id=record.created_by,
                        details={
                            "reason": record.reason,
                            "global_reference": record.reference_id,
                            "enforcement_source": "periodic_sync",
                        },
                    )
                    await self.send_log(
                        server.id,
                        "Global ban synchronized",
                        f"**Reference ID:** `{record.reference_id}`\n"
                        f"**User:** `{await self._resolve_user_tag(record.user_id)}`\n"
                        f"**Server:** `{server.name}`\n"
                        f"**Reason:** {record.reason}",
                        color="#ED4245",
                    )
                except Exception:
                    self._global_ban_removal_suppressions.discard(
                        (server.id, record.user_id)
                    )
                    logger.exception(
                        "global_ban_sync_failed server_id=%s user_id=%s",
                        server.id,
                        record.user_id,
                    )

    @staticmethod
    def _global_result_summary(succeeded: list[str], failed: list[str]) -> str:
        lines = [f"**Servers updated:** {len(succeeded)}"]
        if failed:
            lines.append(f"**Servers failed:** {len(failed)} ({', '.join(failed)})")
        return "\n".join(lines)

    async def handle_global_command(
        self, message: stoat.Message, command: str, parts: list[str]
    ) -> None:
        try:
            _command_server, command_server_id = message.get_server()
        except (AttributeError, TypeError):
            command_server_id = None
        if command == "~global_help":
            await self.send_command_response(
                message,
                "Global moderation commands",
                "• `~global_ban USER_ID REASON` — Ban a user from every server\n"
                "• `~global_unban USER_ID REASON` — Remove a global ban everywhere\n"
                "• `~global_warn USER_ID REASON` — Send a global warning\n"
                "• `~global_remove WARNING_ID` — Remove a global warning\n"
                "• `~global_lookup USER_OR_REFERENCE_ID` — Look up global records\n"
                "• `~global_announce MESSAGE` — Announce to every configured log channel",
                color="#5865F2",
            )
            return

        if command == "~global_announce":
            announcement = message.content[len(command):].strip()
            if not announcement:
                await self.send_command_response(
                    message,
                    "Global announcement",
                    "Usage: `~global_announce MESSAGE`",
                    color="#F59E0B",
                )
                return
            if len(announcement.encode("utf-8")) > 1400:
                await self.send_command_response(
                    message,
                    "Global announcement too long",
                    "The announcement must be 1,400 UTF-8 bytes or fewer.",
                    color="#F59E0B",
                )
                return
            configured, succeeded, failed = await self._send_global_announcement(
                announcement
            )
            await self.send_command_response(
                message,
                "Global announcement completed",
                f"**Configured log channels:** {configured}\n"
                f"**Delivered:** {len(succeeded)}\n"
                f"**Failed:** {len(failed)}",
                color="#3BA55D" if not failed else "#F59E0B",
            )
            return

        if command in {"~global_ban", "~global_warn"}:
            reason = await self._require_command_reason(message, command, parts)
            if reason is None:
                return
            user_id = self._parse_user_id(parts[1])
            if len(reason) > 1000:
                await self.send_command_response(
                    message,
                    "Reason too long",
                    "Global moderation reasons must be 1,000 characters or fewer.",
                    color="#F59E0B",
                )
                return
            if user_id in {GLOBAL_COMMAND_OWNER_ID, self.state.my_id}:
                await self.send_command_response(
                    message,
                    "Global command rejected",
                    "The global command owner and this bot cannot be targeted.",
                    color="#ED4245",
                )
                return
            user_tag = await self._resolve_user_tag(user_id)

            if command == "~global_ban":
                existing = self.database.get_global_ban(user_id)
                if existing is not None:
                    await self.send_command_response(
                        message,
                        "Already globally banned",
                        f"`{user_tag}` is already globally banned under reference "
                        f"`{existing.reference_id}`.",
                        color="#ED4245",
                    )
                    return
                reference_id = self._new_global_reference()
                self.database.add_global_ban(
                    reference_id, user_id, reason, message.author_id
                )
                await self._send_user_dm(
                    user_id,
                    "You have been globally banned",
                    "You have been banned from all servers containing this bot.\n\n"
                    f"**Reference ID:** `{reference_id}`\n**Reason:** {reason}"
                    f"{self._global_ban_contact_instructions()}",
                    server_id=command_server_id,
                )
                succeeded, failed = await self._apply_global_ban_to_servers(
                    user_id,
                    reason,
                    reference_id=reference_id,
                    actor_id=message.author_id,
                    source="global_command",
                )
                description = (
                    f"**Reference ID:** `{reference_id}`\n**User:** `{user_tag}`\n"
                    f"**Reason:** {reason}\n"
                    f"{self._global_result_summary(succeeded, failed)}"
                )
                await self.send_command_response(
                    message, "Global ban added", description, color="#ED4245"
                )
                return

            reference_id = self._new_global_reference()
            self.database.add_global_warning(
                reference_id, user_id, reason, message.author_id
            )
            await self._send_user_dm(
                user_id,
                "You received a global warning",
                f"**Reference ID:** `{reference_id}`\n**Reason:** {reason}\n\n"
                "If this behavior continues, you may be globally banned from all "
                "servers containing this bot.",
                server_id=command_server_id,
            )
            description = (
                f"**Reference ID:** `{reference_id}`\n**User:** `{user_tag}`\n"
                f"**Reason:** {reason}"
            )
            await self.send_command_response(
                message, "Global warning added", description, color="#F59E0B"
            )
            await self._send_global_warning_log(
                "Global warning added", description, color="#F59E0B"
            )
            return

        if command == "~global_unban":
            reason = await self._require_command_reason(message, command, parts)
            if reason is None:
                return
        elif len(parts) != 2:
            await self.send_command_response(
                message,
                "Global command",
                f"Usage: `{command} ID`",
                color="#F59E0B",
            )
            return
        value = parts[1].strip()

        if command == "~global_unban":
            user_id = self._parse_user_id(value)
            record = self.database.remove_global_ban(user_id)
            succeeded, failed = await self._apply_global_ban_to_servers(
                user_id, reason, unban=True,
                reference_id=record.reference_id if record else None,
                actor_id=message.author_id, source="global_command",
            )
            self.database.add_event(
                server_id="stoatmod-global", event_type="manual_global_unban",
                user_id=user_id, actor_id=message.author_id,
                details={
                    "reason": reason, "reference_id": record.reference_id if record else None,
                    "servers_updated": succeeded, "servers_failed": failed,
                },
            )
            user_tag = await self._resolve_user_tag(user_id)
            description = (
                f"**User:** `{user_tag}`\n"
                f"**Removed reference:** `{record.reference_id if record else 'not listed'}`\n"
                f"**Reason:** {reason}\n"
                f"{self._global_result_summary(succeeded, failed)}"
            )
            await self.send_command_response(
                message, "Global unban completed", description, color="#3BA55D"
            )
            return

        if command == "~global_remove":
            record = self.database.remove_global_warning(value.upper())
            if record is None:
                await self.send_command_response(
                    message,
                    "Global warning not found",
                    f"No global warning has reference `{value.upper()}`.",
                    color="#ED4245",
                )
                return
            user_tag = await self._resolve_user_tag(record.user_id)
            description = (
                f"**Reference ID:** `{record.reference_id}`\n"
                f"**User:** `{user_tag}`\n**Reason:** {record.reason}"
            )
            await self._send_user_dm(
                record.user_id,
                "A global warning was removed",
                f"Global warning `{record.reference_id}` was removed from your record.\n\n"
                f"**Reason:** {record.reason}",
                server_id=command_server_id,
            )
            await self.send_command_response(
                message, "Global warning removed", description, color="#3BA55D"
            )
            await self._send_global_warning_log(
                "Global warning removed", description, color="#3BA55D"
            )
            return

        ban = self.database.get_global_ban(value)
        warnings = self.database.list_global_warnings(value, limit=10)
        if ban is None and not warnings:
            await self.send_command_response(
                message,
                "Global lookup",
                f"No global records were found for `{value}`.",
                color="#3BA55D",
            )
            return
        user_id = ban.user_id if ban is not None else warnings[0].user_id
        user_tag = await self._resolve_user_tag(user_id)
        sections = [f"**User:** `{user_tag}`"]
        if ban is not None:
            sections.append(
                f"**Global ban:** `{ban.reference_id}`\n"
                f"**Reason:** {ban.reason}\n**Date:** {ban.created_at}"
            )
        sections.extend(
            f"**Global warning:** `{warning.reference_id}`\n"
            f"**Reason:** {warning.reason}\n**Date:** {warning.created_at}"
            for warning in warnings
        )
        await self.send_command_response(
            message,
            "Global lookup",
            "\n\n".join(sections),
            color="#5865F2",
        )

    @staticmethod
    def _captcha_hash(answer: str, salt: str) -> str:
        return hashlib.sha256(
            f"{salt}:{answer.strip().upper()}".encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _generate_captcha_image() -> tuple[str, bytes]:
        answer = "".join(secrets.choice(CAPTCHA_ALPHABET) for _ in range(7))
        width, height = 360, 120
        image = Image.new("RGB", (width, height), (242, 245, 250))
        draw = ImageDraw.Draw(image)
        for _ in range(18):
            color = tuple(60 + secrets.randbelow(150) for _ in range(3))
            points = [
                (secrets.randbelow(width), secrets.randbelow(height))
                for _point in range(4)
            ]
            draw.line(points, fill=color, width=1 + secrets.randbelow(3))
        for _ in range(450):
            x, y = secrets.randbelow(width), secrets.randbelow(height)
            shade = 80 + secrets.randbelow(160)
            draw.point((x, y), fill=(shade, shade, shade))

        try:
            font = ImageFont.truetype("DejaVuSans-Bold.ttf", 54)
        except OSError:
            font = ImageFont.load_default(size=48)
        x = 24
        for character in answer:
            tile = Image.new("RGBA", (58, 80), (0, 0, 0, 0))
            tile_draw = ImageDraw.Draw(tile)
            color = tuple(20 + secrets.randbelow(100) for _ in range(3)) + (255,)
            tile_draw.text((8, 7), character, font=font, fill=color)
            angle = secrets.randbelow(31) - 15
            tile = tile.rotate(
                angle, resample=Image.Resampling.BICUBIC, expand=False
            )
            image.paste(
                tile,
                (x, 18 + secrets.randbelow(17) - 8),
                tile,
            )
            x += 43 + secrets.randbelow(5)

        output = io.BytesIO()
        image.save(output, format="PNG", optimize=True)
        return answer, output.getvalue()

    def _schedule_captcha_expiry(self, challenge: CaptchaChallenge) -> None:
        key = (challenge.server_id, challenge.user_id)
        previous = self._captcha_tasks.pop(key, None)
        if previous is not None:
            previous.cancel()
        task = asyncio.create_task(self._expire_captcha(challenge))
        self._captcha_tasks[key] = task

    async def _kick_member_with_reason(
        self,
        member: stoat.Member,
        server_id: str,
        user_id: str,
        reason: str,
        *,
        actor_id: str | None = None,
    ) -> None:
        """Kick a member and attribute the subsequent removal event to the bot."""
        key = (server_id, user_id)
        attribution = (actor_id or self.state.my_id, reason)
        self._pending_kick_attribution[key] = attribution
        try:
            await member.kick()
        except Exception:
            self._pending_kick_attribution.pop(key, None)
            raise
        # Avoid retaining stale attribution if Stoat never delivers the removal event.
        def expire_attribution() -> None:
            if self._pending_kick_attribution.get(key) == attribution:
                self._pending_kick_attribution.pop(key, None)

        asyncio.get_running_loop().call_later(60, expire_attribution)

    async def _expire_captcha(self, challenge: CaptchaChallenge) -> None:
        key = (challenge.server_id, challenge.user_id)
        try:
            expires_at = datetime.fromisoformat(challenge.expires_at)
            delay = max(
                0.0, (expires_at - datetime.now(timezone.utc)).total_seconds()
            )
            await asyncio.sleep(delay)
            current = self.database.get_captcha_challenge(*key)
            if current is None or current.answer_hash != challenge.answer_hash:
                return
            application_store = getattr(self.database, "applications", None)
            if application_store is not None and application_store.pending(*key) is not None:
                application_store.expire()
                return
            failure_reason = None
            if current.failure_count > 0:
                failure_reason = self.database.get_latest_captcha_failure_reason(
                    *key, since=current.created_at
                )
            kick_reason = failure_reason or CAPTCHA_EXPIRED_KICK_REASON
            failed_verification = failure_reason is not None
            server = self.get_server(challenge.server_id)
            if server is None:
                return
            member = server.get_member(challenge.user_id)
            if member is None:
                try:
                    member = await server.fetch_member(challenge.user_id)
                except Exception:
                    self.database.remove_captcha_challenge(*key)
                    return
            await self._send_user_dm(
                challenge.user_id,
                "Verification failed" if failed_verification else "Verification expired",
                (
                    f"Your verification for **{server.name}** was rejected and you "
                    "have been removed from the server.\n\n"
                    if failed_verification
                    else f"You did not complete verification for **{server.name}** "
                    "within 30 minutes and have been removed from the server.\n\n"
                )
                + f"**Reason:** {kick_reason}.",
                server_id=challenge.server_id,
                user=member,
            )
            if not await self.require_action_permissions(server, "kick_members"):
                return
            try:
                await self._kick_member_with_reason(
                    member,
                    challenge.server_id,
                    challenge.user_id,
                    kick_reason,
                )
            except Exception:
                logger.exception(
                    "captcha_expiry_kick_failed server_id=%s user_id=%s",
                    *key,
                )
                return
            self.database.remove_captcha_challenge(*key)
            self.database.add_event(
                server_id=challenge.server_id,
                event_type="join_captcha_failed",
                user_id=challenge.user_id,
                details={
                    "result": (
                        "kicked_after_failed_verification"
                        if failed_verification
                        else "kicked_after_30_minutes"
                    ),
                    "reason": kick_reason,
                    "failure_count": current.failure_count,
                },
            )
            await self.send_log(
                challenge.server_id,
                "Join verification failed",
                f"**User:** `{await self._resolve_user_tag(challenge.user_id, member)}`\n"
                "**Action:** Kicked\n"
                f"**Reason:** {kick_reason}",
                color="#ED4245",
            )
        except asyncio.CancelledError:
            raise
        finally:
            if self._captcha_tasks.get(key) is asyncio.current_task():
                self._captcha_tasks.pop(key, None)

    async def resume_captcha_challenges(self) -> None:
        for challenge in self.database.list_captcha_challenges():
            application_store = getattr(self.database, "applications", None)
            if application_store is not None and application_store.pending(challenge.server_id, challenge.user_id):
                continue
            if not (self.database.get_join_protection(challenge.server_id)
                    or self.database.get_captcha_all_members(challenge.server_id)):
                await self._recover_unissued_captcha(challenge, disabled=True)
                continue
            if challenge.salt == "web" and not (
                self.database.captcha_challenge_was_issued(
                    challenge.server_id,
                    challenge.user_id,
                    since=challenge.created_at,
                )
            ):
                await self._recover_unissued_captcha(challenge)
                continue
            self._schedule_captcha_expiry(challenge)

    async def _recover_unissued_captcha(self, challenge: CaptchaChallenge, *, disabled: bool = False) -> None:
        application_store = getattr(self.database, "applications", None)
        if application_store is not None and application_store.pending(challenge.server_id, challenge.user_id):
            return
        challenge_removed = self.database.remove_captcha_challenge(
            challenge.server_id, challenge.user_id
        )
        restriction_removed = False
        server = self.get_server(challenge.server_id)
        if server is None:
            try:
                server = await self.fetch_server(challenge.server_id)
            except Exception:
                logger.exception(
                    "unissued_captcha_server_fetch_failed "
                    "server_id=%s user_id=%s",
                    challenge.server_id,
                    challenge.user_id,
                )
        member = None
        if server is not None:
            member = server.get_member(challenge.user_id)
            if member is None:
                try:
                    member = await server.fetch_member(challenge.user_id)
                except Exception:
                    logger.exception(
                        "unissued_captcha_member_fetch_failed "
                        "server_id=%s user_id=%s",
                        challenge.server_id,
                        challenge.user_id,
                    )
            if member is not None and await self.require_action_permissions(
                server, "timeout_members"
            ):
                try:
                    await member.timeout(None)
                    restriction_removed = True
                except Exception:
                    logger.exception(
                        "unissued_captcha_timeout_cleanup_failed "
                        "server_id=%s user_id=%s",
                        challenge.server_id,
                        challenge.user_id,
                    )

        self.database.add_event(
            server_id=challenge.server_id,
            event_type="join_captcha_disabled" if disabled else "join_captcha_recovered_unissued",
            user_id=challenge.user_id,
            details={
                "challenge_removed": challenge_removed,
                "restriction_removed": restriction_removed,
                "challenge_created_at": challenge.created_at,
            },
        )
        if server is not None:
            await self.send_log(
                challenge.server_id,
                "Join verification disabled" if disabled else "Incomplete join verification recovered",
                f"**User:** `{await self._resolve_user_tag(challenge.user_id, member)}`\n"
                + ("**CAPTCHA expiry:** Cancelled because join verification is disabled\n" if disabled
                   else "**CAPTCHA expiry:** Cancelled because delivery was never confirmed\n")
                +
                "**Temporary timeout removed:** "
                f"{'Yes' if restriction_removed else 'No — moderator action required'}",
                color="#F59E0B" if restriction_removed else "#ED4245",
            )

    async def replace_captcha(
        self, message: stoat.Message, challenge: CaptchaChallenge
    ) -> bool:
        answer, image_bytes = self._generate_captcha_image()
        salt = secrets.token_hex(16)
        replacement = self.database.set_captcha_challenge(
            challenge.server_id,
            challenge.user_id,
            self._captcha_hash(answer, salt),
            salt,
            challenge.expires_at,
        )
        self._schedule_captcha_expiry(replacement)
        server = self.get_server(challenge.server_id)
        server_name = getattr(server, "name", "the server")
        remaining_seconds = max(
            0,
            int(
                (
                    datetime.fromisoformat(challenge.expires_at)
                    - datetime.now(timezone.utc)
                ).total_seconds()
            ),
        )
        remaining_minutes = max(1, (remaining_seconds + 59) // 60)
        try:
            await message.channel.send(
                content=self._localized_text(
                    challenge.server_id,
                    "Reply with the seven characters shown in the new image.",
                ),
                attachments=[("replacement-captcha.png", image_bytes)],
                embeds=[
                    self._localized_embed(
                        challenge.server_id,
                        "Incorrect code — new CAPTCHA",
                        f"That answer was incorrect for **{server_name}**. A new, "
                        "unique CAPTCHA has been generated.\n\n"
                        f"**Time remaining:** approximately {remaining_minutes} minutes\n"
                        "The original 30-minute deadline has not been extended.",
                        "#F59E0B",
                    )
                ],
            )
            return True
        except Exception:
            logger.exception(
                "replacement_captcha_send_failed server_id=%s user_id=%s",
                challenge.server_id,
                challenge.user_id,
            )
            restored = self.database.set_captcha_challenge(
                challenge.server_id,
                challenge.user_id,
                challenge.answer_hash,
                challenge.salt,
                challenge.expires_at,
            )
            self._schedule_captcha_expiry(restored)
            return False

    async def handle_captcha_response(self, message: stoat.Message) -> bool:
        server, _server_id = message.get_server()
        if server is not None:
            return False
        challenges = self.database.list_captcha_challenges(message.author_id)
        if not challenges:
            return False

        web_challenges = [
            challenge for challenge in challenges
            if challenge.salt == "web"
            and datetime.fromisoformat(challenge.expires_at) > datetime.now(timezone.utc)
        ]
        if web_challenges:
            challenge = web_challenges[0]
            await message.channel.send(
                embeds=[
                    self._localized_embed(
                        challenge.server_id,
                        "Complete verification on the website",
                        "Use the secure verification link from my earlier message. "
                        "Text replies cannot complete browser verification.",
                        "#F59E0B",
                    )
                ]
            )
            return True

        response = message.content.strip().upper()
        matched = next(
            (
                challenge
                for challenge in challenges
                if hmac.compare_digest(
                    challenge.answer_hash,
                    self._captcha_hash(response, challenge.salt),
                )
            ),
            None,
        )
        if matched is None:
            active_challenges = [
                challenge
                for challenge in challenges
                if datetime.fromisoformat(challenge.expires_at)
                > datetime.now(timezone.utc)
            ]
            for challenge in active_challenges:
                await self.replace_captcha(message, challenge)
            if not active_challenges:
                expired = challenges[0]
                await message.channel.send(
                    embeds=[
                        self._localized_embed(
                            expired.server_id,
                            "Verification expired",
                            "The 30-minute verification window has expired.",
                            "#ED4245",
                        )
                    ]
                )
            return True

        if datetime.fromisoformat(matched.expires_at) <= datetime.now(timezone.utc):
            await message.channel.send(
                embeds=[
                    self._localized_embed(
                        matched.server_id,
                        "Verification expired",
                        "The 30-minute verification window has expired.",
                        "#ED4245",
                    )
                ]
            )
            return True

        target_server = self.get_server(matched.server_id)
        if target_server is None:
            return True
        if not await self.require_action_permissions(
            target_server, "timeout_members"
        ):
            return True
        member = target_server.get_member(matched.user_id)
        try:
            if member is None:
                member = await target_server.fetch_member(matched.user_id)
            await member.timeout(None)
        except Exception:
            logger.exception(
                "captcha_success_unmute_failed server_id=%s user_id=%s",
                matched.server_id,
                matched.user_id,
            )
            await message.channel.send(
                embeds=[
                    self._localized_embed(
                        matched.server_id,
                        "Verification accepted",
                        "Your code was correct, but I could not remove your timeout. "
                        "A moderator has been notified.",
                        "#F59E0B",
                    )
                ]
            )
            await self.send_log(
                matched.server_id,
                "Join verification needs moderator action",
                f"**User:** `{await self._resolve_user_tag(matched.user_id, member)}`\n"
                "**Result:** CAPTCHA passed\n"
                "**Problem:** The bot could not remove the timeout",
                color="#F59E0B",
            )
            return True

        self.database.remove_captcha_challenge(
            matched.server_id, matched.user_id
        )
        task = self._captcha_tasks.pop(
            (matched.server_id, matched.user_id), None
        )
        if task is not None:
            task.cancel()
        self.database.add_event(
            server_id=matched.server_id,
            event_type="join_captcha_passed",
            user_id=matched.user_id,
        )
        await message.channel.send(
            embeds=[
                self._localized_embed(
                    matched.server_id,
                    "Verification complete",
                    f"Your timeout in **{target_server.name}** has been removed.",
                    "#3BA55D",
                )
            ]
        )
        await self.send_log(
            matched.server_id,
            "Join verification passed",
            f"**User:** `{await self._resolve_user_tag(matched.user_id, member)}`\n"
            "**Action:** One-day timeout removed",
            color="#3BA55D",
        )
        return True

    async def issue_join_captcha(
        self, server: stoat.Server, member: stoat.Member
    ) -> bool:
        if self._moderator_is_exempt(server.id, server, member):
            return False
        if not await self.require_action_permissions(server, "timeout_members"):
            return False

        verification_token = secrets.token_urlsafe(32)
        verification_url = (
            f"{self.moderation_settings.dashboard_url.rstrip('/')}"
            f"/verify?token={verification_token}"
        )
        timeout_until = datetime.now(timezone.utc) + timedelta(days=1)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        challenge_created = False

        async def rollback_pending_verification() -> tuple[bool, bool]:
            task = self._captcha_tasks.pop((server.id, member.id), None)
            if task is not None:
                task.cancel()
            challenge_removed = True
            if challenge_created:
                try:
                    challenge_removed = self.database.remove_captcha_challenge(
                        server.id, member.id
                    )
                except Exception:
                    challenge_removed = False
                    logger.exception(
                        "join_captcha_challenge_cleanup_failed "
                        "server_id=%s user_id=%s",
                        server.id,
                        member.id,
                    )
            try:
                await member.timeout(None)
                restriction_removed = True
            except Exception:
                restriction_removed = False
                logger.exception(
                    "join_captcha_timeout_rollback_failed server_id=%s user_id=%s",
                    server.id,
                    member.id,
                )
            return challenge_removed, restriction_removed

        try:
            updated_member = await member.timeout(timeout_until)
            confirmed_until = getattr(updated_member, "timed_out_until", None)
            if not isinstance(confirmed_until, datetime):
                raise RuntimeError("Stoat did not confirm the member timeout")
            if confirmed_until.tzinfo is None:
                confirmed_until = confirmed_until.replace(tzinfo=timezone.utc)
            if confirmed_until < timeout_until - timedelta(seconds=5):
                raise RuntimeError("Stoat confirmed a shorter timeout than requested")
        except Exception:
            logger.exception(
                "join_protection_timeout_failed server_id=%s user_id=%s",
                server.id,
                member.id,
            )
            self.database.add_event(
                server_id=server.id,
                event_type="join_captcha_restriction_failed",
                user_id=member.id,
                details={
                    "reason": "timeout_error_or_unconfirmed",
                    "challenge_created": False,
                },
            )
            await self.send_log(
                server.id,
                "Join verification could not be enforced",
                f"**User:** `{await self._resolve_user_tag(member.id, member)}`\n"
                "**Action:** No CAPTCHA expiry was created\n"
                "**Reason:** Stoat did not confirm the temporary timeout",
                color="#ED4245",
            )
            return False

        try:
            challenge = self.database.set_web_verification_challenge(
                server.id,
                member.id,
                hashlib.sha256(verification_token.encode("utf-8")).hexdigest(),
                expires_at.isoformat(timespec="seconds"),
            )
            challenge_created = True
            self._schedule_captcha_expiry(challenge)
        except Exception:
            logger.exception(
                "join_captcha_setup_failed server_id=%s user_id=%s",
                server.id,
                member.id,
            )
            challenge_removed, restriction_removed = (
                await rollback_pending_verification()
            )
            self.database.add_event(
                server_id=server.id,
                event_type="join_captcha_setup_failed",
                user_id=member.id,
                details={
                    "challenge_removed": challenge_removed,
                    "restriction_removed": restriction_removed,
                },
            )
            await self.send_log(
                server.id,
                "Join verification setup failed",
                f"**User:** `{await self._resolve_user_tag(member.id, member)}`\n"
                "**CAPTCHA expiry:** "
                f"{'Cancelled' if challenge_removed else 'Cleanup requires moderator attention'}\n"
                "**Temporary timeout removed:** "
                f"{'Yes' if restriction_removed else 'No — moderator action required'}",
                color="#ED4245",
            )
            return False

        delivery_failure: tuple[str, str] | None = None
        try:
            async def deliver_verification_link() -> None:
                dm = await member.open_dm()
                content = self._localized_text(
                    server.id, f"Complete verification securely: {verification_url}"
                )
                verification_embed = self._localized_embed(
                    server.id,
                    "Complete verification",
                    f"**{server.name}** requires join verification. "
                    "You have been temporarily muted for one day while verification is "
                    "pending.\n\n"
                    "Open the secure website link above within **30 minutes**. The page "
                    "checks the browser CAPTCHA and network risk before releasing you. "
                    "If you do not complete it in time, you will be kicked.",
                    "#F59E0B",
                )
                await dm.send(content=content, embeds=[verification_embed])

            await asyncio.wait_for(
                deliver_verification_link(),
                timeout=CAPTCHA_DELIVERY_TIMEOUT_SECONDS,
            )
        except TimeoutError:
            logger.error(
                "join_captcha_dm_timed_out server_id=%s user_id=%s timeout_seconds=%s",
                server.id,
                member.id,
                CAPTCHA_DELIVERY_TIMEOUT_SECONDS,
            )
            delivery_failure = ("dm_timeout", "The verification DM timed out")
        except Exception:
            logger.exception(
                "join_captcha_dm_failed server_id=%s user_id=%s",
                server.id,
                member.id,
            )
            delivery_failure = ("dm_error", "The verification DM could not be sent")

        if delivery_failure is not None:
            failure_code, failure_text = delivery_failure
            challenge_removed, restriction_removed = (
                await rollback_pending_verification()
            )
            details = {
                "reason": failure_code,
                "restriction_applied": not restriction_removed,
                "restriction_removed": restriction_removed,
                "challenge_created": not challenge_removed,
                "challenge_removed": challenge_removed,
            }
            if failure_code == "dm_timeout":
                details["timeout_seconds"] = CAPTCHA_DELIVERY_TIMEOUT_SECONDS
            self.database.add_event(
                server_id=server.id,
                event_type="join_captcha_delivery_failed",
                user_id=member.id,
                details=details,
            )
            await self.send_log(
                server.id,
                "Join verification could not be delivered",
                f"**User:** `{await self._resolve_user_tag(member.id, member)}`\n"
                f"**Reason:** {failure_text}\n"
                "**CAPTCHA expiry:** "
                f"{'Cancelled' if challenge_removed else 'Cleanup requires moderator attention'}\n"
                "**Temporary timeout removed:** "
                f"{'Yes' if restriction_removed else 'No — moderator action required'}",
                color="#ED4245",
            )
            return False

        self.database.add_event(
            server_id=server.id,
            event_type="join_captcha_issued",
            user_id=member.id,
            details={
                "expires_at": challenge.expires_at,
                "initial_timeout_seconds": 86400,
                "method": "website",
            },
        )
        await self.send_log(
            server.id,
            "Join verification required",
            f"**User:** `{await self._resolve_user_tag(member.id, member)}`\n"
            "**Action:** Muted for one day pending website verification\n"
            f"**Deadline:** {challenge.expires_at}",
            color="#F59E0B",
        )
        return True

    async def disable_join_protection(
        self, server: stoat.Server
    ) -> int:
        if not await self.require_action_permissions(server, "timeout_members"):
            return 0
        released = 0
        for challenge in self.database.list_captcha_challenges():
            if challenge.server_id != server.id:
                continue
            application_store = getattr(self.database, "applications", None)
            if application_store is not None:
                application = application_store.pending(server.id, challenge.user_id)
                if application is not None:
                    if self.database.get_captcha_all_members(server.id):
                        continue
                    self.database.remove_captcha_challenge(server.id, challenge.user_id)
                    task = self._captcha_tasks.pop((server.id, challenge.user_id), None)
                    if task is not None:
                        task.cancel()
                    if application["status"] == "screening":
                        application_store.mark_screened(application["id"])
                        await self.application_flow.resume(application, force=True)
                    continue
            member = server.get_member(challenge.user_id)
            try:
                if member is None:
                    member = await server.fetch_member(challenge.user_id)
                await member.timeout(None)
                released += 1
            except Exception:
                logger.exception(
                    "join_protection_disable_unmute_failed server_id=%s user_id=%s",
                    server.id,
                    challenge.user_id,
                )
            self.database.remove_captcha_challenge(
                challenge.server_id, challenge.user_id
            )
            task = self._captcha_tasks.pop(
                (challenge.server_id, challenge.user_id), None
            )
            if task is not None:
                task.cancel()
        return released

    def _server_locale(self, server_id: str) -> str:
        getter = getattr(getattr(self, "database", None), "get_server_locale", None)
        return getter(server_id) if getter is not None else "en"

    def _localized_embed(
        self, server_id: str, title: str, description: str, color: str
    ) -> stoat.SendableEmbed:
        title, description = localize_delivery(
            self._server_locale(server_id), title, description
        )
        return self._embed(title, description, color)

    def _localized_text(self, server_id: str, content: str) -> str:
        return localize_delivery(self._server_locale(server_id), "", content)[1]

    def _message_locale(self, message: stoat.Message) -> str:
        try:
            _server, server_id = message.get_server()
        except (AttributeError, TypeError):
            return "en"
        if not server_id:
            return "en"
        return self._server_locale(server_id)

    @staticmethod
    def _closest_command_usage(
        command: str, *, include_global: bool = False
    ) -> str | None:
        candidates = tuple(PUBLIC_COMMAND_USAGES) + (
            tuple(GLOBAL_COMMAND_USAGES) if include_global else ()
        )
        entered_name = command.removeprefix("~")
        closest = max(
            candidates,
            key=lambda candidate: SequenceMatcher(
                None, entered_name, candidate.removeprefix("~")
            ).ratio(),
        )
        similarity = SequenceMatcher(
            None, entered_name, closest.removeprefix("~")
        ).ratio()
        if similarity < 0.65:
            return None
        return GLOBAL_COMMAND_USAGES.get(
            closest, PUBLIC_COMMAND_USAGES.get(closest)
        )

    async def handle_report_entry(self, message: stoat.Message) -> bool:
        """Issue a user-bound report link from either a server or direct message."""
        content = (message.content or "").strip()
        parts = content.split(maxsplit=1)
        command = parts[0].casefold() if parts else ""
        if command not in {"~report", "~global_report"}:
            return False
        is_global_report = command == "~global_report"
        current_server, current_server_id = message.get_server()
        selected_server = current_server
        selected_server_id = current_server_id
        if is_global_report and current_server is None:
            await self.send_command_response(
                message,
                "Global report",
                "Use `~global_report` inside a server, or start a global report "
                "from the Support section of that server's dashboard.",
                color="#F59E0B",
            )
            return True
        if current_server is None:
            candidates = self.database.list_local_report_servers_for_user(
                message.author_id
            )
            if len(parts) == 1:
                if not candidates:
                    await self.send_command_response(
                        message,
                        "Server reports",
                        "You do not currently share a server where reporting is enabled.",
                        color="#F59E0B",
                    )
                    return True
                if len(candidates) > 1:
                    choices = "\n".join(
                        f"• **{item.get('server_name') or item['server_id']}** — "
                        f"`~report {item['server_id']}`"
                        for item in candidates[:20]
                    )
                    await self.send_command_response(
                        message,
                        "Choose a server",
                        "You can report in more than one server. Send one of these commands here:\n\n"
                        + choices,
                        color="#5865F2",
                    )
                    return True
                selected_server_id = str(candidates[0]["server_id"])
            else:
                selected_server_id = parts[1].strip()
                if selected_server_id not in {
                    str(item["server_id"]) for item in candidates
                }:
                    await self.send_command_response(
                        message,
                        "Server reports",
                        "That server is not available for reports from this account.",
                        color="#ED4245",
                    )
                    return True
            selected_server = await self._resolve_dashboard_server(
                str(selected_server_id)
            )
            if selected_server is None:
                await self.send_command_response(
                    message, "Server reports", "That server is temporarily unavailable.",
                    color="#ED4245",
                )
                return True
            member = selected_server.get_member(message.author_id)
            if member is None:
                try:
                    member = await selected_server.fetch_member(message.author_id)
                except Exception:
                    member = None
            if member is None:
                await self.send_command_response(
                    message,
                    "Server reports",
                    "I could not verify that you are currently a member of that server.",
                    color="#ED4245",
                )
                return True
        elif len(parts) != 1:
            await self.send_command_response(
                message,
                "Report command",
                f"Use `{command}` without a server ID when running it inside a server.",
                color="#F59E0B",
            )
            return True
        if selected_server is None or not selected_server_id:
            return True
        report_scope = "global" if is_global_report else "local"
        if not is_global_report:
            report_settings = self.database.get_local_report_settings(
                str(selected_server_id)
            )
            if not report_settings.get("enabled"):
                await self.send_command_response(
                    message,
                    "Server reports",
                    "Reporting is not enabled for that server. Use `~global_report` "
                    "for a Stoatmod-wide safety report instead.",
                    color="#F59E0B",
                )
                return True
        user = message.get_author_as_user()
        if user is None:
            user = await self.fetch_user(message.author_id)
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=60)
        self.database.create_report_token(
            token_hash,
            str(selected_server_id),
            message.author_id,
            expires_at.isoformat(timespec="seconds"),
            report_scope=report_scope,
        )
        dashboard_url = self.moderation_settings.dashboard_url.rstrip("/")
        report_url = f"{dashboard_url}/report?token={token}"
        scope_label = "Stoatmod-wide" if is_global_report else "server"
        delivered = await self._send_user_dm(
            message.author_id,
            "Secure global report link" if is_global_report else "Secure server report link",
            f"Use this one-time link to file a **{scope_label}** report"
            + (" with the Stoatmod team." if is_global_report else f" for **{selected_server.name}**.")
            + "\n\n"
            f"**[Open report form]({report_url})**\n\n"
            "The link expires in one hour. Evidence should only be added in the private form.",
            server_id=str(selected_server_id),
            user=user,
            color="#5865F2",
        )
        if not delivered:
            self.database.consume_report_token(token_hash)
            await self.send_command_response(
                message,
                "Global report" if is_global_report else "Report server issue",
                "I could not send the secure link. Check your direct-message privacy settings.",
                color="#ED4245",
            )
            return True
        if current_server is not None:
            try:
                await message.delete()
            except Exception:
                logger.info(
                    "public_report_command_delete_failed message_id=%s", message.id
                )
            await self.send_command_response(
                message,
                "Global report" if is_global_report else "Report server issue",
                "The secure report link was sent by direct message.",
                color="#3BA55D",
            )
        return True

    async def _resolve_command_server(self, message: stoat.Message):
        """A missing SDK cache entry does not establish that a message is a DM."""
        server, server_id = message.get_server()
        if server is not None and server_id:
            return server, server_id
        if not server_id:
            get_channel = getattr(message, "get_channel", None)
            channel = get_channel() if callable(get_channel) else None
            if channel is None:
                channel = await self.fetch_channel(message.channel_id)
            server_id = getattr(channel, "server_id", None)
        if not server_id:
            return None, None
        server = await self._resolve_dashboard_server(server_id)
        if server is None:
            server = await self.fetch_server(server_id)
        return server, server_id

    async def handle_command(self, message: stoat.Message) -> bool:
        content = message.content.strip()
        # Markdown, spaced tildes and approximate quantities are ordinary text.
        # Commands use one tilde directly before a complete command-name token.
        if not re.match(r"~[A-Za-z][A-Za-z0-9_-]*(?:\s|$)", content):
            return False

        parts = content.split(maxsplit=2)
        command = parts[0].lower()
        if command in GLOBAL_COMMANDS:
            if message.author_id != GLOBAL_COMMAND_OWNER_ID:
                logger.warning(
                    "unauthorized_global_command user_id=%s command=%s",
                    message.author_id,
                    command,
                )
                return True
            await self.handle_global_command(message, command, parts)
            return True
        if command == "~language":
            server, server_id = message.get_server()
            if server is None or not server_id:
                await self.send_command_response(
                    message,
                    translate("en", "language.title"),
                    translate("en", "language.server_only"),
                    color="#F59E0B",
                )
                return True
            current_locale = self.database.get_server_locale(server_id)
            if len(parts) == 1:
                await self.send_command_response(
                    message,
                    translate(current_locale, "language.title"),
                    translate(
                        current_locale,
                        "language.current",
                        language=SUPPORTED_LANGUAGES[current_locale],
                    )
                    + "\n\n"
                    + translate(current_locale, "language.usage"),
                )
                return True
            if not self._is_moderator(message, server):
                await self.send_command_response(
                    message,
                    translate(current_locale, "language.title"),
                    translate(current_locale, "language.permission"),
                    color="#ED4245",
                )
                return True
            new_locale = normalize_language(" ".join(parts[1:]))
            if new_locale is None:
                await self.send_command_response(
                    message,
                    translate(current_locale, "language.title"),
                    translate(current_locale, "language.invalid")
                    + "\n\n"
                    + translate(current_locale, "language.usage"),
                    color="#F59E0B",
                )
                return True
            self.database.set_server_locale(server_id, new_locale)
            self.database.add_event(
                server_id=server_id,
                event_type="server_language_changed",
                actor_id=message.author_id,
                details={"locale": new_locale},
            )
            await self.send_command_response(
                message,
                translate(new_locale, "language.title"),
                translate(
                    new_locale,
                    "language.changed",
                    language=SUPPORTED_LANGUAGES[new_locale],
                ),
                color="#3BA55D",
            )
            return True
        if command == "~help":
            locale = self._message_locale(message)
            await self.send_command_response(
                message,
                translate(locale, "help.title"),
                help_description(locale),
            )
            return True
        if command == "~support":
            await self.send_command_response(
                message,
                "Stoatmod support",
                "Get help from the official Stoatmod support team:\n\n"
                f"**Support server:** {SUPPORT_SERVER_URL}\n"
                f"**Email:** `{SUPPORT_EMAIL}`",
                color="#5865F2",
            )
            return True
        if command in {"~information", "~info"}:
            server, server_id = message.get_server()
            if server is None or not server_id:
                await self.send_command_response(
                    message,
                    "Server information",
                    "This command can only be used inside a server.",
                    color="#F59E0B",
                )
                return True
            await self.send_command_response(
                message,
                "Server information",
                await self._server_information_description(server, server_id),
                color="#5865F2",
            )
            return True
        if command in {"~report", "~global_report"}:
            return await self.handle_report_entry(message)

        if command not in SERVER_COMMAND_USAGES:
            usage = self._closest_command_usage(
                command,
                include_global=(
                    getattr(message, "author_id", None) == GLOBAL_COMMAND_OWNER_ID
                ),
            )
            displayed_command = command[:80].replace("`", "'")
            description = f"I do not recognise `{displayed_command}`."
            if usage is not None:
                description += f"\n\n**Correct usage:** `{usage}`"
            description += (
                "\n\nUse `~help` to view every public command and its syntax."
            )
            await self.send_command_response(
                message,
                "Invalid command",
                description,
                color="#F59E0B",
            )
            return True

        server, server_id = message.get_server()
        if command in {"~dashboard", "~approve", "~deny"} and (server is None or not server_id):
            try:
                server, server_id = await self._resolve_command_server(message)
            except Exception:
                logger.warning("server_command_lookup_failed command=%s channel_id=%s", command, message.channel_id, exc_info=True)
                await self.send_command_response(
                    message, "Dashboard temporarily unavailable" if command == "~dashboard" else "Application review temporarily unavailable",
                    f"I could not check this channel’s server. Please try `{command}` again shortly.",
                    color="#F59E0B",
                )
                return True
        if server is None or not server_id:
            await self.send_command_response(
                message,
                "Server-only command",
                "This command must be used inside a Stoat server.\n\n"
                f"**Correct usage:** `{SERVER_COMMAND_USAGES[command]}`",
                color="#F59E0B",
            )
            return True
        if command in {"~approve", "~deny"}:
            member = await server.fetch_member(message.author_id)
            allowed = self.database.dashboard_user_has_access(server_id, message.author_id,
                owner_id=server.owner_id, manage_server=server.permissions_for(member, include_timeout=False).manage_server)
            if not allowed:
                await self.send_command_response(message, "Permission denied", "Server admin or delegated dashboard access is required.", color="#ED4245")
                return True
            reason = await self._require_command_reason(message, command, parts)
            if reason is None:
                return True
            user_id = self._parse_user_id(parts[1])
            application = self.database.applications.current(server_id, user_id)
            try:
                if application is None:
                    raise ValueError("That user has no application in this server.")
                self.database.applications.decide(server_id, application["id"], message.author_id,
                    "approved" if command == "~approve" else "denied", reason)
            except ValueError as exc:
                await self.send_command_response(message, "Application review unavailable", str(exc), color="#ED4245")
                return True
            await self.send_command_response(message, "Application decision saved",
                "The bot is applying the decision. It will confirm the outcome in the logs and notify the applicant.", color="#3BA55D")
            return True
        if command == "~dashboard":
            owner_id = str(getattr(server, "owner_id", "") or "")
            get_author_member = getattr(message, "get_author_as_member", None)
            member = get_author_member() if callable(get_author_member) else None
            if member is None and callable(getattr(server, "fetch_member", None)):
                try:
                    member = await server.fetch_member(message.author_id)
                except Exception:
                    logger.warning("dashboard_command_member_lookup_failed server_id=%s user_id=%s", server_id, message.author_id, exc_info=True)
                    await self.send_command_response(
                        message, "Dashboard temporarily unavailable",
                        "I could not verify your server permissions. Please try `~dashboard` again shortly.",
                        color="#F59E0B",
                    )
                    return True
            manage_server = False
            if member is not None:
                try:
                    manage_server = bool(
                        getattr(
                            server.permissions_for(member), "manage_server", False
                        )
                    )
                except Exception:
                    logger.warning(
                        "dashboard_author_permissions_failed server_id=%s user_id=%s",
                        server_id,
                        message.author_id,
                        exc_info=True,
                    )
            if not self.database.dashboard_user_has_access(
                server_id,
                message.author_id,
                owner_id=owner_id,
                manage_server=manage_server,
            ):
                await self.send_command_response(
                    message,
                    "Dashboard access denied",
                    "The server owner has not granted you access to this dashboard.",
                    color="#ED4245",
                )
                return True
        elif not self._is_moderator(message, server):
            await self.send_command_response(
                message,
                "Permission denied",
                "Moderator permissions are required for that command.",
                color="#ED4245",
            )
            return True

        if command == "~setup":
            if len(parts) != 1:
                await self.send_command_response(
                    message,
                    "Setup checker",
                    "Use `~setup` without any additional options.",
                    color="#F59E0B",
                )
                return True
            await self.refresh_dashboard_server(server)
            await self.send_command_response(
                message,
                "Stoatmod setup audit",
                await self._setup_audit_description(server),
                color="#5865F2",
            )
            return True

        if command == "~bump":
            if len(parts) != 1:
                await self.send_command_response(
                    message,
                    "Discovery bump",
                    "Use `~bump` without any additional options.",
                    color="#F59E0B",
                )
                return True
            try:
                bump = self.database.bump_discovery_server(
                    server_id, message.author_id
                )
            except ValueError as exc:
                await self.send_command_response(
                    message,
                    "Discovery bump unavailable",
                    str(exc),
                    color="#ED4245",
                )
                return True
            if not bump["bumped"]:
                next_bump = datetime.fromisoformat(str(bump["next_bump_at"]))
                remaining_seconds = max(
                    1,
                    int((next_bump - datetime.now(timezone.utc)).total_seconds()),
                )
                remaining_minutes = (remaining_seconds + 59) // 60
                hours, minutes = divmod(remaining_minutes, 60)
                wait_text = (
                    f"{hours}h {minutes}m" if hours else f"{minutes} minute(s)"
                )
                await self.send_command_response(
                    message,
                    "Discovery bump on cooldown",
                    f"This server was already bumped. Try again in **{wait_text}**.",
                    color="#F59E0B",
                )
                return True
            self.database.add_event(
                server_id=server_id,
                event_type="discovery_listing_bumped",
                actor_id=message.author_id,
                details={"next_bump_at": bump["next_bump_at"]},
            )
            await self.send_command_response(
                message,
                "Discovery listing bumped",
                "This server is now at the top of StoatMod Discovery. "
                "It can be bumped again in **2 hours**.",
                color="#3BA55D",
            )
            await self.send_log(
                server_id,
                "Discovery listing bumped",
                f"**Moderator:** `{await self._resolve_user_tag(message.author_id, message.get_author_as_user())}`\n"
                "**Next bump:** in 2 hours",
                color="#3BA55D",
            )
            return True

        if command == "~dashboard":
            if len(parts) != 1:
                await self.send_command_response(
                    message,
                    "Dashboard command",
                    "Use `~dashboard` without any additional options.",
                    color="#F59E0B",
                )
                return True
            await self.refresh_dashboard_server(server)
            code = "".join(
                secrets.choice(DASHBOARD_CODE_ALPHABET) for _ in range(8)
            )
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
            self.database.create_dashboard_login_code(
                self._dashboard_code_hash(code),
                server_id,
                message.author_id,
                expires_at.isoformat(timespec="seconds"),
            )
            try:
                user = message.get_author_as_user()
                if user is None:
                    user = await self.fetch_user(message.author_id)
                dashboard_url = self.moderation_settings.dashboard_url.rstrip("/")
                login_url = (
                    dashboard_url
                    if dashboard_url.endswith("/login")
                    else f"{dashboard_url}/login"
                )
                delivered = await self._send_user_dm(
                    message.author_id,
                    "Your Stoatmod dashboard code",
                    f"Use this one-time code to open the dashboard for "
                    f"**{server.name}**:\n\n"
                    f"# `{code}`\n\n"
                    f"Open {login_url}\n\n"
                    "The code expires in **10 minutes** and can only be used once. "
                    "Your dashboard session lasts for 12 hours.",
                    server_id=server_id,
                    user=user,
                    color="#5865F2",
                )
                if not delivered:
                    raise RuntimeError("dashboard code DM failed")
            except Exception:
                logger.exception(
                    "dashboard_code_dm_failed server_id=%s user_id=%s",
                    server_id,
                    message.author_id,
                )
                await self.send_command_response(
                    message,
                    "Dashboard code could not be delivered",
                    "I could not send you a DM. Enable direct messages for this "
                    "server and run `~dashboard` again.",
                    color="#ED4245",
                )
                return True
            self.database.add_event(
                server_id=server_id,
                event_type="dashboard_code_issued",
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={"expires_at": expires_at.isoformat(timespec="seconds")},
            )
            await self.send_command_response(
                message,
                "Dashboard code sent",
                "Check your DMs. The one-time code expires in 10 minutes.",
                color="#3BA55D",
            )
            return True

        if command == "~case":
            case_reference = (
                self._parse_case_id(" ".join(parts[1:])) if len(parts) >= 2 else None
            )
            if case_reference is None:
                await self.send_command_response(
                    message,
                    "Case command",
                    "Usage: `~case CASE_ID`",
                    color="#F59E0B",
                )
                return True
            record = self.database.get_moderation_case(
                server_id, case_reference
            )
            if record is None:
                await self.send_command_response(
                    message,
                    "Case not found",
                    f"Case `{self._case_reference(case_reference)}` does not exist in this server.",
                    color="#ED4245",
                )
                return True
            user_tag = await self._resolve_user_tag(record.user_id)
            moderator_tag = (
                await self._resolve_user_tag(record.moderator_id)
                if record.moderator_id is not None
                else "Unavailable"
            )
            await self.send_command_response(
                message,
                self._case_reference(record.reference_id),
                f"**User:** `{user_tag}`\n"
                f"**Action:** {record.action.replace('_', ' ').title()}\n"
                f"**Reason:** {record.reason}\n"
                f"**Moderator:** `{moderator_tag}`\n"
                f"**Status:** {record.status.title()}\n"
                f"**Date & time:** {record.created_at}",
                color="#F59E0B" if record.status == "active" else "#747F8D",
            )
            return True

        if command == "~appeal":
            appeal_arguments = content.split()[1:]
            decision_index = next(
                (
                    index
                    for index, value in enumerate(appeal_arguments)
                    if self._appeal_decision(value) is not None
                ),
                None,
            )
            raw_case_reference = (
                " ".join(appeal_arguments[:decision_index])
                if decision_index is not None
                else ""
            )
            case_reference = self._parse_case_id(raw_case_reference)
            decision = (
                self._appeal_decision(appeal_arguments[decision_index])
                if decision_index is not None
                else None
            )
            response = (
                " ".join(appeal_arguments[decision_index + 1 :]).strip()
                if decision_index is not None
                else ""
            )
            if decision_index == 0 and len(appeal_arguments) >= 2:
                case_end = 3 if appeal_arguments[1].lower() == "case" else 2
                case_reference = self._parse_case_id(" ".join(appeal_arguments[1:case_end]))
                response = " ".join(appeal_arguments[case_end:]).strip()
            if (
                case_reference is None
                or decision is None
                or not response.strip("`\"' \t\r\n")
            ):
                await self.send_command_response(
                    message,
                    "Appeal decision",
                    "A case, decision, and reason are required.\n"
                    "Usage: `~appeal CASE_ID accept|deny REASON` or `~appeal accept|deny CASE_ID REASON`.\n"
                    "Accepted case forms include `CASE-AB12CD34`, "
                    "`case_AB12CD34`, `case AB12CD34`, `AB12CD34`, and numeric IDs.",
                    color="#F59E0B",
                )
                return True
            appeal = self.database.get_server_appeal_by_case(
                server_id, case_reference
            )
            if appeal is None and case_reference.isdigit():
                numeric_lookup = getattr(
                    self.database, "get_moderation_case_by_id", None
                )
                numeric_case = (
                    numeric_lookup(server_id, int(case_reference))
                    if numeric_lookup is not None
                    else None
                )
                if numeric_case is not None:
                    case_reference = numeric_case.reference_id
                    appeal = self.database.get_server_appeal_by_case(
                        server_id, case_reference
                    )
            if appeal is None:
                await self.send_command_response(
                    message,
                    "Appeal not found",
                    f"No appeal exists for `{self._case_reference(case_reference)}` "
                    "in this server.",
                    color="#ED4245",
                )
                return True
            if appeal["status"] != "submitted":
                await self.send_command_response(
                    message,
                    "Appeal cannot be decided",
                    f"This appeal is currently **{str(appeal['status']).title()}**. "
                    "Only submitted, undecided appeals can be reviewed.",
                    color="#F59E0B",
                )
                return True
            reviewed = self.database.review_appeal(
                int(appeal["id"]), message.author_id, decision, response
            )
            if reviewed is None:
                await self.send_command_response(
                    message,
                    "Appeal already decided",
                    "Another moderator decided this appeal before this command completed.",
                    color="#F59E0B",
                )
                return True
            self.database.enqueue_dashboard_action(
                server_id,
                "resolve_appeal",
                message.author_id,
                {"appeal_id": appeal["id"], "decision": decision},
            )
            self.database.add_event(
                server_id=server_id,
                event_type="moderation_appeal_decided",
                user_id=appeal["user_id"],
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={
                    "case_reference": appeal["case_reference"],
                    "decision": decision,
                    "reason": response,
                },
            )
            await self.send_command_response(
                message,
                f"Appeal {decision}",
                f"Appeal for `{self._case_reference(case_reference)}` was "
                f"**{decision}**. The member will be notified and the outcome "
                "will be written to the moderation log.",
                color="#3BA55D" if decision == "approved" else "#ED4245",
            )
            return True

        if command == "~cases":
            if len(parts) < 2:
                await self.send_command_response(
                    message,
                    "Cases command",
                    "Usage: `~cases USER_ID`",
                    color="#F59E0B",
                )
                return True
            user_id = self._parse_user_id(parts[1])
            user_tag = await self._resolve_user_tag(user_id)
            records = self.database.list_moderation_cases(
                server_id, user_id, limit=10
            )
            if not records:
                await self.send_command_response(
                    message,
                    "Moderation cases",
                    f"No cases are recorded for `{user_tag}` in this server.",
                    color="#3BA55D",
                )
                return True
            await self.send_command_response(
                message,
                f"Cases for {user_tag}",
                self._case_history(records),
                color="#F59E0B",
            )
            return True

        if command in {"~mute", "~unmute"}:
            await self.handle_timeout_command(
                message, server, server_id, command, parts
            )
            return True

        if command in {"~kick", "~ban"}:
            await self.handle_kick_ban_command(
                message, server, server_id, command, parts
            )
            return True

        if command == "~unban":
            await self.handle_unban_command(message, server, server_id, parts)
            return True

        if command == "~auto-role":
            operation = parts[1].lower() if len(parts) >= 2 else "list"
            if operation in {"list", "status"} and len(parts) == 2 or len(parts) == 1:
                role_ids = self.database.list_auto_roles(server_id)
                roles = getattr(server, "roles", None) or {}
                role_lines = [
                    f"• **{roles[role_id].name}** (`{role_id}`)"
                    if role_id in roles
                    else f"• Deleted or unavailable role (`{role_id}`)"
                    for role_id in role_ids
                ]
                await self.send_command_response(
                    message,
                    "Automatic roles",
                    "New members will receive:\n" + "\n".join(role_lines)
                    if role_lines
                    else "No automatic roles are configured.",
                    color="#5865F2" if role_lines else "#747F8D",
                )
                return True

            if operation in {"clear", "disable"} and len(parts) == 2:
                removed = self.database.clear_auto_roles(server_id)
                description = (
                    f"Removed **{removed}** automatic role"
                    f"{'s' if removed != 1 else ''}."
                )
                self.database.add_event(
                    server_id=server_id,
                    event_type="auto_roles_cleared",
                    actor_id=message.author_id,
                    channel_id=message.channel_id,
                    details={"removed": removed},
                )
                await self.send_command_response(
                    message, "Automatic roles disabled", description,
                    color="#747F8D",
                )
                return True

            if operation in {"add", "remove"}:
                if len(parts) != 3:
                    role_id = ""
                else:
                    role_id = self._parse_role_id(parts[2])
            elif len(parts) == 2:
                operation = "add"
                role_id = self._parse_role_id(parts[1])
            else:
                role_id = ""

            if not role_id:
                await self.send_command_response(
                    message,
                    "Automatic role command",
                    "Use `~auto-role ROLE_ID`, `~auto-role remove ROLE_ID`, "
                    "`~auto-role clear`, or `~auto-role list`.",
                    color="#F59E0B",
                )
                return True

            roles = getattr(server, "roles", None) or {}
            role = roles.get(role_id)
            if role is None and operation == "add":
                try:
                    role = await server.fetch_role(role_id)
                except Exception:
                    await self.send_command_response(
                        message,
                        "Invalid automatic role",
                        "That role does not exist in this server.",
                        color="#ED4245",
                    )
                    return True

            if operation == "add":
                if not await self.require_action_permissions(server, "assign_roles"):
                    return True
                bot_member = self._cached_bot_member(server)
                bot_id = getattr(getattr(self, "_state", None), "my_id", None)
                if bot_member is None and bot_id:
                    try:
                        bot_member = await server.fetch_member(bot_id)
                    except Exception:
                        bot_member = None
                assignable = self._role_is_assignable(bot_member, role)
                if assignable is not True:
                    await self.send_command_response(
                        message,
                        "Automatic role hierarchy blocked",
                        (
                            "Move the Stoatmod role above that role, then try again."
                            if assignable is False
                            else "Stoatmod could not verify its role hierarchy. Run `~setup` and try again."
                        ),
                        color="#ED4245",
                    )
                    return True
                changed = self.database.add_auto_role(
                    server_id, role_id, message.author_id
                )
                action = "Added" if changed else "Already configured"
                event_type = "auto_role_added"
                color = "#3BA55D"
            else:
                changed = self.database.remove_auto_role(server_id, role_id)
                action = "Removed" if changed else "Was not configured"
                event_type = "auto_role_removed"
                color = "#747F8D"
            role_name = getattr(role, "name", "Unknown role")
            description = f"**Action:** {action}\n**Role:** {role_name} (`{role_id}`)"
            self.database.add_event(
                server_id=server_id,
                event_type=event_type,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={"role_id": role_id, "changed": changed},
            )
            await self.send_command_response(
                message, "Automatic role updated", description, color=color
            )
            await self.send_log(
                server_id, "Automatic role updated", description, color=color
            )
            return True

        if command == "~bypass":
            reason = await self._require_command_reason(message, command, parts)
            if reason is None:
                return True
            application_store = getattr(self.database, "applications", None)
            if len(parts) >= 2 and application_store is not None and application_store.pending(server_id, self._parse_user_id(parts[1])):
                await self.send_command_response(message, "Application approval required",
                    "Use `~approve USER_ID REASON` for a submitted application. CAPTCHA bypass cannot approve an application.", color="#F59E0B")
                return True
            user_id = self._parse_user_id(parts[1])
            if not user_id:
                await self.send_command_response(
                    message,
                    "Verification bypass command",
                    "Usage: `~bypass USER_ID REASON`",
                    color="#F59E0B",
                )
                return True
            challenge = self.database.get_captcha_challenge(server_id, user_id)
            if challenge is None:
                await self.send_command_response(
                    message,
                    "No pending verification",
                    "That user does not have an active verification restriction in this server.",
                    color="#ED4245",
                )
                return True
            if not await self.require_action_permissions(server, "timeout_members"):
                return True
            member = server.get_member(user_id)
            try:
                if member is None:
                    member = await server.fetch_member(user_id)
                await member.timeout(None)
            except Exception:
                logger.exception(
                    "captcha_bypass_unmute_failed server_id=%s user_id=%s",
                    server_id,
                    user_id,
                )
                await self.send_command_response(
                    message,
                    "Verification bypass failed",
                    "I could not remove that member's timeout. Check my permissions and role position.",
                    color="#ED4245",
                )
                return True
            self.database.remove_captcha_challenge(server_id, user_id)
            task = self._captcha_tasks.pop((server_id, user_id), None)
            if task is not None:
                task.cancel()
            user_tag = await self._resolve_user_tag(user_id, member)
            self.database.add_event(
                server_id=server_id,
                event_type="join_captcha_bypassed",
                user_id=user_id,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={"reason": reason},
            )
            await self._send_user_dm(
                user_id,
                "Verification bypassed",
                f"A moderator approved your verification for **{server.name}**. "
                f"Your temporary restriction has been removed.\n\n**Reason:** {reason}",
                server_id=server_id,
                user=member,
                color="#3BA55D",
            )
            description = (
                f"**User:** `{user_tag}`\n"
                f"**Moderator:** <@{message.author_id}>\n"
                f"**Action:** Verification restriction removed\n**Reason:** {reason}"
            )
            await self.send_command_response(
                message, "Verification bypassed", description, color="#3BA55D"
            )
            if self.database.get_log_channel(server_id) != message.channel_id:
                await self.send_log(
                    server_id,
                    "Join verification bypassed",
                    description,
                    color="#3BA55D",
                )
            return True

        if command == "~join-protection":
            operation = (
                parts[1].lower()
                if len(parts) == 2
                else ("status" if len(parts) == 1 else "")
            )
            if operation not in {"enable", "disable", "status"}:
                await self.send_command_response(
                    message,
                    "Join protection command",
                    "Use `~join-protection enable`, `~join-protection disable`, "
                    "or `~join-protection status`.",
                    color="#F59E0B",
                )
                return True
            if operation == "status":
                enabled = self.database.get_join_protection(server_id)
                pending = sum(
                    challenge.server_id == server_id
                    for challenge in self.database.list_captcha_challenges()
                )
                await self.send_command_response(
                    message,
                    "Join protection status",
                    f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                    f"**Pending CAPTCHA challenges:** {pending}",
                    color="#3BA55D" if enabled else "#747F8D",
                )
                return True

            enabled = operation == "enable"
            self.database.set_join_protection(server_id, enabled)
            released = 0
            if not enabled:
                released = await self.disable_join_protection(server)
            self.database.add_event(
                server_id=server_id,
                event_type=(
                    "join_protection_enabled"
                    if enabled
                    else "join_protection_disabled"
                ),
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={"released_challenges": released},
            )
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            if not enabled:
                description += f"\n**Pending users released:** {released}"
            await self.send_command_response(
                message,
                "Join protection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            await self.send_log(
                server_id,
                "Join protection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            return True

        if command == "~nickname-protection":
            operation = (
                parts[1].lower()
                if len(parts) == 2
                else ("status" if len(parts) == 1 else "")
            )
            if operation not in {"enable", "disable", "status"}:
                await self.send_command_response(
                    message,
                    "Nickname protection command",
                    "Use `~nickname-protection enable`, "
                    "`~nickname-protection disable`, or "
                    "`~nickname-protection status`.",
                    color="#F59E0B",
                )
                return True
            enabled = self.database.get_nickname_protection(server_id)
            if operation == "status":
                await self.send_command_response(
                    message,
                    "Nickname protection status",
                    f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                    "Usernames and server nicknames are checked when they change.",
                    color="#3BA55D" if enabled else "#747F8D",
                )
                return True

            enabled = operation == "enable"
            self.database.set_nickname_protection(server_id, enabled)
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            self.database.add_event(
                server_id=server_id,
                event_type=(
                    "nickname_protection_enabled"
                    if enabled
                    else "nickname_protection_disabled"
                ),
                actor_id=message.author_id,
                channel_id=message.channel_id,
            )
            await self.send_command_response(
                message,
                "Nickname protection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            await self.send_log(
                server_id,
                "Nickname protection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            return True

        if command == "~link-protection":
            operation = (
                parts[1].lower()
                if len(parts) == 2
                else ("status" if len(parts) == 1 else "")
            )
            if operation not in {"enable", "disable", "status"}:
                await self.send_command_response(
                    message,
                    "Link protection command",
                    "Use `~link-protection enable`, `~link-protection disable`, "
                    "or `~link-protection status`.",
                    color="#F59E0B",
                )
                return True
            enabled = self.database.get_link_protection(server_id)
            if operation == "status":
                allow_gifs = self._server_allows_gifs(server_id)
                await self.send_command_response(
                    message,
                    "Link protection status",
                    f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                    f"**GIF links:** {'Allowed' if allow_gifs else 'Blocked'}\n"
                    "When enabled, messages containing links are removed without a warning. "
                    "GIF links follow the server dashboard setting.",
                    color="#3BA55D" if enabled else "#747F8D",
                )
                return True

            enabled = operation == "enable"
            self.database.set_link_protection(server_id, enabled)
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            self.database.add_event(
                server_id=server_id,
                event_type=(
                    "link_protection_enabled"
                    if enabled
                    else "link_protection_disabled"
                ),
                actor_id=message.author_id,
                channel_id=message.channel_id,
            )
            await self.send_command_response(
                message,
                "Link protection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            await self.send_log(
                server_id,
                "Link protection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            return True

        if command == "~spam-detection":
            operation = (
                parts[1].lower()
                if len(parts) == 2
                else ("status" if len(parts) == 1 else "")
            )
            if operation not in {"enable", "disable", "status"}:
                await self.send_command_response(
                    message,
                    "Spam detection command",
                    "Use `~spam-detection enable`, `~spam-detection disable`, "
                    "or `~spam-detection status`.",
                    color="#F59E0B",
                )
                return True
            enabled = self._spam_detection_enabled(server_id)
            if operation == "status":
                spam_settings = self._spam_settings(server_id)
                await self.send_command_response(
                    message,
                    "Spam detection status",
                    f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                    f"**Repeated messages:** {spam_settings['repeat_count']} within "
                    f"{spam_settings['repeat_window_seconds']:g} seconds\n"
                    f"**Rapid messages:** {spam_settings['rapid_count']} within "
                    f"{spam_settings['rapid_window_seconds']:g} seconds\n"
                    f"**Mass mentions:** {spam_settings['mass_mention_limit']} users or roles\n"
                    f"**Spam score:** {spam_settings['score_threshold']:g} with a "
                    f"{spam_settings['score_half_life_seconds']:g}-second half-life\n"
                    f"**Timeout:** {self._format_duration(int(spam_settings['timeout_seconds']))}\n"
                    "Use the server dashboard’s Policy Studio to change these values.",
                    color="#3BA55D" if enabled else "#747F8D",
                )
                return True

            enabled = operation == "enable"
            self.database.set_spam_detection(server_id, enabled)
            if not enabled:
                self._clear_spam_state(server_id)
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            self.database.add_event(
                server_id=server_id,
                event_type=(
                    "spam_detection_enabled" if enabled else "spam_detection_disabled"
                ),
                actor_id=message.author_id,
                channel_id=message.channel_id,
            )
            await self.send_command_response(
                message,
                "Spam detection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            await self.send_log(
                server_id,
                "Spam detection updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            return True

        if command == "~image-scanning":
            operation = parts[1].lower() if len(parts) >= 2 else "status"
            if operation not in {"enable", "disable", "status"}:
                await self.send_command_response(
                    message,
                    "Image scanning command",
                    "Use `~image-scanning enable`, `~image-scanning disable`, or "
                    "`~image-scanning status`. Append a channel ID or mention to "
                    "manage one channel.",
                    color="#F59E0B",
                )
                return True

            channel_id: str | None = None
            if len(parts) == 3:
                channel_id = self._parse_channel_id(parts[2])
                if not isinstance(server.get_channel(channel_id), stoat.TextChannel):
                    await self.send_command_response(
                        message,
                        "Invalid image-scanning channel",
                        "That ID is not a text channel in this server.",
                        color="#ED4245",
                    )
                    return True

            if operation == "status":
                server_enabled = self.database.get_image_scanning(server_id)
                effective_enabled = self.database.get_image_scanning(
                    server_id, channel_id
                )
                description = (
                    f"**Server default:** {'Enabled' if server_enabled else 'Disabled'}"
                )
                if channel_id is not None:
                    override = self.database.get_channel_image_scanning_override(
                        server_id, channel_id
                    )
                    override_status = (
                        "None"
                        if override is None
                        else ("Enabled" if override else "Disabled")
                    )
                    description += (
                        f"\n**Channel:** <#{channel_id}>"
                        f"\n**Channel override:** {override_status}"
                        f"\n**Effective status:** "
                        f"{'Enabled' if effective_enabled else 'Disabled'}"
                    )
                await self.send_command_response(
                    message,
                    "Image scanning status",
                    description,
                    color="#3BA55D" if effective_enabled else "#747F8D",
                )
                return True

            enabled = operation == "enable"
            if channel_id is None:
                self.database.set_image_scanning(server_id, enabled)
                target = "Server default"
            else:
                self.database.set_channel_image_scanning(
                    server_id,
                    channel_id,
                    enabled,
                    message.author_id,
                )
                target = f"<#{channel_id}>"
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Target:** {target}\n"
                f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            self.database.add_event(
                server_id=server_id,
                event_type=(
                    "image_scanning_enabled"
                    if enabled
                    else "image_scanning_disabled"
                ),
                actor_id=message.author_id,
                channel_id=channel_id or message.channel_id,
                details={"target_channel_id": channel_id},
            )
            await self.send_command_response(
                message,
                "Image scanning updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            await self.send_log(
                server_id,
                "Image scanning updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            return True

        if command in {"~moderator-exemption", "~mod-exemption"}:
            operation = (
                parts[1].lower()
                if len(parts) == 2
                else ("status" if len(parts) == 1 else "")
            )
            if operation not in {"enable", "disable", "status"}:
                await self.send_command_response(
                    message,
                    "Moderator exemption command",
                    "Use `~moderator-exemption enable`, "
                    "`~moderator-exemption disable`, or "
                    "`~moderator-exemption status`.",
                    color="#F59E0B",
                )
                return True

            enabled = self._moderator_exemption_enabled(server_id)
            if operation == "status":
                await self.send_command_response(
                    message,
                    "Moderator exemption status",
                    f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                    "When enabled, members with moderation permissions are exempt "
                    "from automatic moderation.",
                    color="#3BA55D" if enabled else "#747F8D",
                )
                return True

            enabled = operation == "enable"
            self.database.set_moderator_exemption(server_id, enabled)
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Status:** {'Enabled' if enabled else 'Disabled'}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            if not enabled:
                description += (
                    "\n\nElevated members will be scanned and filtered, but Stoat may "
                    "still reject restricted actions such as timing them out."
                )
            self.database.add_event(
                server_id=server_id,
                event_type=(
                    "moderator_exemption_enabled"
                    if enabled
                    else "moderator_exemption_disabled"
                ),
                actor_id=message.author_id,
                channel_id=message.channel_id,
            )
            await self.send_command_response(
                message,
                "Moderator exemption updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            await self.send_log(
                server_id,
                "Moderator exemption updated",
                description,
                color="#3BA55D" if enabled else "#747F8D",
            )
            return True

        if command == "~threshold":
            operation = parts[1].lower() if len(parts) >= 2 else "status"
            current = self._moderation_threshold(server_id)
            confirmation_key = (server_id, message.author_id)
            pending_thresholds = getattr(
                self, "_pending_threshold_changes", None
            )
            if pending_thresholds is None:
                # Compatibility for lightweight test doubles created without
                # running the full client constructor.
                pending_thresholds = {}
                self._pending_threshold_changes = pending_thresholds
            if operation in {"status", "show"} and len(parts) <= 2:
                await self.send_command_response(
                    message,
                    "AI moderation threshold",
                    f"**Current threshold:** "
                    f"{self._format_threshold_percentage(current)}\n"
                    "Moderation action is taken when a category score meets or "
                    "exceeds this percentage.",
                    color="#5865F2",
                )
                return True

            if operation == "set" and len(parts) == 3:
                new_threshold = self._parse_threshold_percentage(parts[2])
                if new_threshold is None:
                    pending_thresholds.pop(confirmation_key, None)
                    await self.send_command_response(
                        message,
                        "Invalid AI threshold",
                        "Use a percentage from 0% to 100%, for example "
                        "`~threshold set 95%`.",
                        color="#F59E0B",
                    )
                    return True
                pending_thresholds.pop(confirmation_key, None)
                self.database.set_moderation_threshold(
                    server_id, new_threshold
                )
                event_type = "moderation_threshold_updated"
                action = "Set a server-specific threshold"
            elif operation == "confirm" and len(parts) == 3:
                pending_thresholds.pop(confirmation_key, None)
                await self.send_command_response(
                    message,
                    "Invalid AI threshold",
                    "Threshold confirmation is no longer supported. Use "
                    "`~threshold set PERCENT` with a value from 0% to 100%.",
                    color="#F59E0B",
                )
                return True
            elif operation == "reset" and len(parts) == 2:
                pending_thresholds.pop(confirmation_key, None)
                self.database.reset_moderation_threshold(server_id)
                new_threshold = self.moderation_settings.threshold
                event_type = "moderation_threshold_reset"
                action = "Reset to the environment default"
            else:
                await self.send_command_response(
                    message,
                    "AI moderation threshold command",
                    "Use `~threshold`, `~threshold set PERCENT`, or "
                    "`~threshold reset`. Thresholds must be from 0% to 100%.",
                    color="#F59E0B",
                )
                return True

            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            description = (
                f"**Action:** {action}\n"
                f"**Previous threshold:** "
                f"{self._format_threshold_percentage(current)}\n"
                f"**New threshold:** "
                f"{self._format_threshold_percentage(new_threshold)}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            self.database.add_event(
                server_id=server_id,
                event_type=event_type,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={
                    "previous_threshold": current,
                    "new_threshold": new_threshold,
                },
            )
            await self.send_command_response(
                message,
                "AI moderation threshold updated",
                description,
                color="#3BA55D",
            )
            await self.send_log(
                server_id,
                "AI moderation threshold updated",
                description,
                color="#3BA55D",
            )
            return True

        if command == "~categories":
            operation = parts[1].lower() if len(parts) >= 2 else "status"
            if operation in {"status", "show"} and len(parts) <= 2:
                await self.send_command_response(
                    message,
                    "Moderation categories",
                    self._moderation_category_status(server_id),
                    color="#5865F2",
                )
                return True

            if operation in {"reset", "enable-all"} and len(parts) == 2:
                changed = self.database.reset_moderation_categories(server_id)
                action = "enabled all configurable categories"
                event_type = "moderation_categories_reset"
                category = None
            elif operation in {"disable", "enable"} and len(parts) == 3:
                category = self._normalize_moderation_category(parts[2])
                if category not in SUPPORTED_MODERATION_CATEGORIES:
                    await self.send_command_response(
                        message,
                        "Unknown moderation category",
                        f"`{category}` is not supported. Use `~categories` to "
                        "view the available category names.",
                        color="#F59E0B",
                    )
                    return True
                if operation == "disable" and self._category_is_always_protected(
                    category
                ):
                    await self.send_command_response(
                        message,
                        "Category always protected",
                        f"`{category}` belongs to the self-harm safety family and "
                        "cannot be disabled.",
                        color="#F59E0B",
                    )
                    return True
                if operation == "disable":
                    self.database.disable_moderation_category(
                        server_id, category, message.author_id
                    )
                    changed = 1
                    action = f"disabled `{category}`"
                    event_type = "moderation_category_disabled"
                else:
                    changed = self.database.enable_moderation_category(
                        server_id, category
                    )
                    action = f"enabled `{category}`"
                    event_type = "moderation_category_enabled"
            else:
                await self.send_command_response(
                    message,
                    "Moderation categories command",
                    "Use `~categories`, `~categories disable CATEGORY`, "
                    "`~categories enable CATEGORY`, or `~categories reset`.",
                    color="#F59E0B",
                )
                return True

            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            still_disabled = (
                category is not None
                and not self._category_is_enabled(server_id, category)
            )
            description = (
                f"**Action:** {action}\n"
                f"**Changed entries:** {changed}\n"
                f"**Moderator:** `{moderator_tag}`"
            )
            if operation == "enable" and still_disabled:
                description += (
                    "\n**Effective status:** Still disabled by a parent category. "
                    "Enable the parent category to restore it."
                )
            self.database.add_event(
                server_id=server_id,
                event_type=event_type,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={"category": category, "changed_entries": changed},
            )
            await self.send_command_response(
                message,
                "Moderation categories updated",
                description,
                color="#3BA55D",
            )
            await self.send_log(
                server_id,
                "Moderation categories updated",
                description,
                color="#3BA55D",
            )
            return True

        if command == "~policy":
            operation = parts[1].lower() if len(parts) >= 2 else "show"
            if (operation == "show" and len(parts) == 2) or len(parts) == 1:
                policy = self.database.get_warning_policy(server_id)
                await self.send_command_response(
                    message,
                    "Warning escalation policy",
                    self._policy_description(policy),
                    color="#5865F2",
                )
                return True

            if operation == "set":
                counts = (
                    self._parse_policy_counts(parts[2])
                    if len(parts) >= 3
                    else None
                )
                if counts is None:
                    await self.send_command_response(
                        message,
                        "Policy command",
                        "Usage: `~policy set TIMEOUT_COUNT KICK_COUNT BAN_COUNT`\n"
                        "Thresholds must be positive and increase in that order.\n"
                        "Example: `~policy set 3 5 7`",
                        color="#F59E0B",
                    )
                    return True
                policy = self.database.set_warning_policy(server_id, *counts)
                event_type = "warning_policy_updated"
                title = "Warning escalation policy updated"
            elif operation == "reset" and len(parts) == 2:
                policy = self.database.reset_warning_policy(server_id)
                event_type = "warning_policy_reset"
                title = "Warning escalation policy reset"
            else:
                await self.send_command_response(
                    message,
                    "Policy command",
                    "Use `~policy show`, `~policy set 3 5 7`, or `~policy reset`.",
                    color="#F59E0B",
                )
                return True

            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            self.database.add_event(
                server_id=server_id,
                event_type=event_type,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={
                    "timeout_count": policy.timeout_count,
                    "kick_count": policy.kick_count,
                    "ban_count": policy.ban_count,
                },
            )
            description = self._policy_description(policy)
            await self.send_command_response(
                message, title, description, color="#3BA55D"
            )
            await self.send_log(
                server_id,
                title,
                f"**Moderator:** `{moderator_tag}`\n{description}",
                color="#3BA55D",
            )
            return True

        if command == "~warnings":
            if len(parts) < 2:
                await self.send_command_response(
                    message,
                    "Warnings command",
                    "Usage: `~warnings USER_ID`",
                    color="#F59E0B",
                )
                return True
            user_id = self._parse_user_id(parts[1])
            user_tag = await self._resolve_user_tag(user_id)
            records = self.database.list_warnings(server_id, user_id, limit=10)
            if not records:
                await self.send_command_response(
                    message,
                    "Warnings",
                    f"No warnings are recorded for `{user_tag}` in this server.",
                    color="#3BA55D",
                )
                return True
            await self.send_command_response(
                message,
                f"Warnings for {user_tag}",
                self._warning_history(
                    records,
                    {
                        record.id: case.reference_id
                        for record in records
                        if (
                            case := self.database.get_warning_case(
                                server_id, record.id
                            )
                        )
                        is not None
                    },
                ),
                color="#F59E0B",
            )
            return True

        if command == "~remove":
            case_reference = (
                self._parse_case_id(" ".join(parts[1:])) if len(parts) >= 2 else None
            )
            if case_reference is None:
                await self.send_command_response(
                    message,
                    "Remove moderation case command",
                    "Usage: `~remove CASE_ID`",
                    color="#F59E0B",
                )
                return True

            result = self.database.remove_moderation_case(
                server_id, case_reference
            )
            if result is None:
                await self.send_command_response(
                    message,
                    "Case not found",
                    f"Case `{self._case_reference(case_reference)}` does not "
                    "exist in this server or is already removed.",
                    color="#ED4245",
                )
                return True

            case, warning = result
            user_tag = await self._resolve_user_tag(case.user_id)
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            total = self._active_warning_count(server_id, case.user_id)
            self.database.add_event(
                server_id=server_id,
                event_type="moderation_case_removed",
                user_id=case.user_id,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={
                    "case_reference": case.reference_id,
                    "action": case.action,
                    "reason": case.reason,
                    "source_type": case.source_type,
                    "remaining_warnings": total,
                },
            )
            warning_line = (
                f"\n**Remaining warnings:** {total}" if warning is not None else ""
            )
            description = (
                f"**Case ID:** `{self._case_reference(case.reference_id)}`\n"
                f"**User:** `{user_tag}`\n"
                f"**Action:** {case.action.replace('_', ' ').title()}\n"
                f"**Reason:** {case.reason}{warning_line}"
            )
            await self.send_command_response(
                message,
                "Moderation case removed",
                description,
                color="#3BA55D",
            )
            # Only send log if the log channel is DIFFERENT from the command channel
            log_channel_id = self.database.get_log_channel(server_id)
            if log_channel_id != message.channel_id:
                await self.send_log(
                    server_id,
                    "Moderation case removed",
                    f"**Moderator:** `{moderator_tag}`\n{description}",
                    color="#3BA55D",
                )
            if warning is not None:
                await self._send_user_dm(
                    case.user_id,
                    "A warning was removed",
                    f"Case `{self._case_reference(case.reference_id)}` was "
                    f"removed from your record in **{server.name}**.\n\n"
                    f"**Reason:** {case.reason}\n"
                    f"**Remaining warnings:** {total}",
                    server_id=server_id,
                )
            return True

        if command == "~warn":
            reason = await self._require_command_reason(message, command, parts)
            if reason is None:
                return True
            user_id = self._parse_user_id(parts[1])
            target_member = server.get_member(user_id)
            if target_member is None:
                try:
                    target_member = await server.fetch_member(user_id)
                except Exception:
                    target_member = None
            if target_member is not None and self._moderator_is_exempt(
                server_id, server, target_member
            ):
                await self.send_command_response(
                    message,
                    "Moderator exempt",
                    "Moderators cannot receive moderation warnings or automatic actions.",
                    color="#F59E0B",
                )
                return True
            user_tag = await self._resolve_user_tag(user_id)
            moderator_tag = await self._resolve_user_tag(
                message.author_id, message.get_author_as_user()
            )
            warning_id = self.database.add_warning(
                server_id=server_id,
                user_id=user_id,
                moderator_id=message.author_id,
                source="manual",
                reason=reason,
                channel_id=message.channel_id,
            )
            warning_case = self.database.get_warning_case(server_id, warning_id)
            public_case_id = (
                self._case_reference(warning_case.reference_id)
                if warning_case is not None
                else "Unavailable"
            )
            case_line = (
                f"**Case ID:** `{public_case_id}`\n"
            )
            total = self._active_warning_count(server_id, user_id)
            appeal = self._appeal_instructions(
                user_id,
                "moderation",
                warning_case.reference_id if warning_case is not None else "",
                server_id=server_id,
            )
            self.database.add_event(
                server_id=server_id,
                event_type="manual_warning",
                user_id=user_id,
                actor_id=message.author_id,
                channel_id=message.channel_id,
                details={"warning_id": warning_id, "reason": reason, "total": total},
            )
            await self.send_command_response(
                message,
                f"Warning {public_case_id} added",
                f"{case_line}**User:** `{user_tag}`\n**Reason:** {reason}\n"
                f"**Total warnings:** {total}",
                color="#F59E0B",
            )
            await self.send_log(
                server_id,
                f"Manual warning {public_case_id}",
                f"{case_line}**User:** `{user_tag}`\n**Moderator:** `{moderator_tag}`\n"
                f"**Reason:** {reason}\n**Total warnings:** {total}",
                color="#F59E0B",
            )
            await self._send_case_dm(
                user_id,
                "You received a warning",
                f"You received a warning in **{server.name}**.\n\n"
                f"{case_line}"
                f"**Reason:** {reason}\n"
                f"**Warnings in this server:** {total}"
                f"{appeal}",
                warning_id=warning_id,
                server_id=server_id,
            )
            await self._enforce_warning_policy_and_notify(
                server, server_id, user_id, warning_id, total
            )
            return True

        if command in {"~exclude", "~include"}:
            if len(parts) < 2:
                await self.send_command_response(
                    message,
                    "Moderation scope command",
                    f"Usage: `{command} CHANNEL_OR_CATEGORY_ID`",
                    color="#F59E0B",
                )
                return True
            target_id = self._parse_channel_id(parts[1])
            resolved = self._resolve_scope_target(server, target_id)
            if resolved is None:
                await self.send_command_response(
                    message,
                    "Invalid scope target",
                    "That ID is not a channel or category in this server.",
                    color="#ED4245",
                )
                return True
            target_type, target_name = resolved
            if command == "~exclude":
                self.database.exclude_scope(
                    server_id, target_id, target_type, message.author_id
                )
                action = "excluded from"
                event_type = "moderation_scope_excluded"
            else:
                removed = self.database.include_scope(server_id, target_id)
                if not removed:
                    await self.send_command_response(
                        message,
                        "Already included",
                        f"`{target_name}` ({target_type}) is already included in moderation.",
                        color="#3BA55D",
                    )
                    return True
                action = "included in"
                event_type = "moderation_scope_included"
            self.database.add_event(
                server_id=server_id,
                event_type=event_type,
                actor_id=message.author_id,
                details={
                    "target_id": target_id,
                    "target_type": target_type,
                    "target_name": target_name,
                },
            )
            await self.send_command_response(
                message,
                "Moderation scope updated",
                f"**Target:** `{target_name}` (`{target_id}`)\n"
                f"**Type:** {target_type}\n**Status:** {action} moderation",
                color="#F59E0B" if command == "~exclude" else "#3BA55D",
            )
            await self.send_log(
                server_id,
                "Moderation scope updated",
                f"**Moderator:** `{await self._resolve_user_tag(message.author_id, message.get_author_as_user())}`\n"
                f"**Target:** `{target_name}` (`{target_id}`)\n"
                f"**Type:** {target_type}\n**Action:** {action} moderation",
                color="#F59E0B" if command == "~exclude" else "#3BA55D",
            )
            return True

        channel_id = self._log_channel_from_parts(command, parts)
        if not channel_id:
            await self.send_command_response(
                message,
                "Log-channel command",
                "Use `~log CHANNEL_ID`, `~log-channel CHANNEL_ID`, or "
                "`~log channel CHANNEL_ID`.",
                color="#F59E0B",
            )
            return True
        channel_id = self._parse_channel_id(channel_id)
        channel = server.get_channel(channel_id)
        if not isinstance(channel, stoat.TextChannel):
            await self.send_command_response(
                message,
                "Invalid log channel",
                "That ID is not a text channel in this server.",
                color="#ED4245",
            )
            return True
        self.database.set_log_channel(server_id, channel_id)
        self.database.add_event(
            server_id=server_id,
            event_type="log_channel_configured",
            actor_id=message.author_id,
            channel_id=channel_id,
        )
        await self.send_command_response(
            message,
            "Moderation log configured",
            f"Moderation logs will be sent to <#{channel_id}>.",
            color="#3BA55D",
        )
        await self.send_log(
            server_id,
            "Moderation log configured",
            f"**Moderator:** `{await self._resolve_user_tag(message.author_id, message.get_author_as_user())}`\n"
            f"**Channel:** <#{channel_id}>",
            color="#3BA55D",
        )
        return True

    async def handle_message_delete(self, event: stoat.MessageDeleteEvent) -> None:
        # Deletion alone is not a moderation decision. Do not archive its body.
        self._bot_deleted_ids.discard(event.message_id)

    async def handle_message_update(self, event: stoat.MessageUpdateEvent) -> None:
        if event.message.content is stoat.UNDEFINED:
            return

        message = event.after
        if message is None:
            try:
                message = await event.message.channel.fetch_message(event.message.id)
            except Exception:
                logger.warning(
                    "edited_message_fetch_failed channel_id=%s message_id=%s",
                    event.message.channel_id,
                    event.message.id,
                )

        channel = self.get_channel(event.message.channel_id)
        server_id = getattr(channel, "server_id", "")
        if message is not None:
            _server, message_server_id = message.get_server()
            server_id = message_server_id or server_id
        if not server_id:
            return

        if event.before is not None and event.before.content == event.message.content:
            return
        # Reassess only the current edited message. The normal moderation path
        # stores content only when it takes action; no before/after edit log.
        if message is None or not self.message_is_in_scope(message):
            return
        if await self._message_author_is_moderator(message):
            return
        if await self.handle_link_filter(message):
            return
        if await self.handle_join_limits(message):
            return
        if self._mass_mention_reason(message) is not None:
            await self.handle_spam(message)
            return
        self.dispatch_scan(message)

    async def handle_message_delete_bulk(self, event: stoat.MessageDeleteBulkEvent) -> None:
        self._bot_deleted_ids.difference_update(event.message_ids)

    async def handle_member_join(self, event: stoat.ServerMemberJoinEvent) -> None:
        self.database.record_daily_member_change(
            event.member.server_id, "join"
        )
        server = self.get_server(event.member.server_id)
        if server is None:
            member_get_server = getattr(event.member, "get_server", None)
            if callable(member_get_server):
                server = member_get_server()
        if server is None and getattr(self, "_state", None) is not None:
            try:
                server = await self.fetch_server(event.member.server_id)
            except Exception:
                logger.exception(
                    "join_server_resolution_failed server_id=%s user_id=%s",
                    event.member.server_id,
                    event.member.id,
                )
        # Persist the membership before any enforcement path returns.  The
        # database derives the displayed total from unique member records, so
        # duplicate gateway events cannot inflate the server count.
        upsert_member = getattr(self.database, "upsert_dashboard_member", None)
        if upsert_member is not None:
            joined_member_snapshot = self._dashboard_member_snapshot(
                [event.member], server=server
            )
            if joined_member_snapshot:
                upsert_member(
                    event.member.server_id,
                    joined_member_snapshot[0],
                    adjust_count_on_insert=True,
                )
        is_stoatmod_owner = event.member.id == GLOBAL_COMMAND_OWNER_ID
        global_ban = (
            None
            if is_stoatmod_owner
            else self.database.get_global_ban(event.member.id)
        )
        if global_ban is not None:
            if server is not None:
                if not await self.require_action_permissions(server, "ban_members"):
                    return
                try:
                    self._suppress_global_ban_removal(
                        event.member.server_id, event.member.id
                    )
                    await server.ban(
                        event.member.id,
                        reason=(
                            f"Global ban {global_ban.reference_id}: "
                            f"{global_ban.reason}"
                        )[:1024],
                    )
                    self.database.add_event(
                        server_id=event.member.server_id,
                        event_type="global_ban_enforced_on_join",
                        user_id=event.member.id,
                        actor_id=global_ban.created_by,
                        details={
                            "reason": global_ban.reason,
                            "global_reference": global_ban.reference_id,
                            "enforcement_source": "member_join",
                        },
                    )
                    await self.send_log(
                        event.member.server_id,
                        "Global ban enforced on join",
                        f"**Reference ID:** `{global_ban.reference_id}`\n"
                        f"**User:** `{await self._resolve_user_tag(event.member.id, event.member)}`\n"
                        f"**Server:** `{server.name}`\n"
                        f"**Reason:** {global_ban.reason}",
                        color="#ED4245",
                    )
                except Exception:
                    self._global_ban_removal_suppressions.discard(
                        (event.member.server_id, event.member.id)
                    )
                    logger.exception(
                        "global_ban_join_enforcement_failed server_id=%s user_id=%s",
                        event.member.server_id,
                        event.member.id,
                    )
            return
        user = event.member.get_user()
        if user is None:
            try:
                user = await self.fetch_user(event.member.id)
            except Exception:
                logger.exception(
                    "joining_user_fetch_failed server_id=%s user_id=%s",
                    event.member.server_id,
                    event.member.id,
                )
        username = getattr(user, "name", "") if user is not None else ""
        if (
            username is not stoat.UNDEFINED
            and await self._enforce_zero_tolerance_username_global_ban(
                event.member.id,
                str(username),
                user=user,
                source_server_id=event.member.server_id,
            )
        ):
            return
        account_age = (
            datetime.now(timezone.utc) - user.created_at
            if user is not None
            else None
        )
        application_pending = False
        application_flow = getattr(self, "application_flow", None)
        if application_flow is not None and server is not None and user is not None:
            application_pending = await application_flow.on_join(server, event.member,
                screening_required=bool(user.bot is None and (
                    (account_age < timedelta(days=14) and self.database.get_join_protection(server.id))
                    or self.database.get_captcha_all_members(server.id))),
                exempt=bool(user.bot is not None or self._moderator_is_exempt(server.id, server, event.member)), user=user)
        if (
            not application_pending
            and
            server is not None
            and user is not None
            and user.bot is None
            and (
                (
                    account_age < timedelta(days=14)
                    and self.database.get_join_protection(event.member.server_id)
                )
                or self.database.get_captcha_all_members(event.member.server_id)
            )
        ):
            await self.issue_join_captcha(server, event.member)

        granted_auto_role_ids: list[str] = []
        if server is not None and not application_pending:
            granted_auto_role_ids, _failed_auto_role_ids = (
                await self._assign_auto_roles_on_join(server, event.member)
            )
        join_limit_flow = getattr(self, "join_limit_flow", None)
        if join_limit_flow is not None and server is not None and not is_stoatmod_owner:
            try:
                await join_limit_flow.on_join(server, event.member, user)
            except Exception:
                logger.exception(
                    "join_limit_start_failed server_id=%s user_id=%s",
                    event.member.server_id,
                    event.member.id,
                )
        if user is not None:
            if upsert_member is not None:
                member_snapshot = self._dashboard_member_snapshot(
                    [event.member], [user], server=server
                )
                if member_snapshot:
                    upsert_member(
                        event.member.server_id,
                        member_snapshot[0],
                        adjust_count_on_insert=True,
                    )
            assert account_age is not None
            age_days = max(0.0, account_age.total_seconds() / 86400)
            if age_days < 7:
                await self.send_log(
                    event.member.server_id,
                    "Account less than one week old joined",
                    f"**User:** `{await self._resolve_user_tag(event.member.id, user)}`\n"
                    f"**Account age:** {age_days:.1f} days",
                    color="#F59E0B",
                )
        self.database.add_event(
            server_id=event.member.server_id,
            event_type="member_join",
            user_id=event.member.id,
        )
        history_section = "\n\n✅ **Verified Stoatmod owner**" if is_stoatmod_owner else ""
        auto_role_section = (
            "\n**Automatic roles:** "
            + ", ".join(f"<@&{role_id}>" for role_id in granted_auto_role_ids)
            if granted_auto_role_ids
            else ""
        )
        await self.send_log(
            event.member.server_id,
            "Member joined",
            f"**User:** `{await self._resolve_user_tag(event.member.id, event.member)}`\n"
            f"**User ID:** `{event.member.id}`"
            f"{auto_role_section}"
            f"{history_section}",
            color="#3BA55D",
        )

    async def _fetch_ban_record(
        self, server: stoat.Server, user_id: str
    ) -> object | None:
        for attempt in range(3):
            try:
                bans = await server.fetch_bans()
                record = next(
                    (ban for ban in bans if ban.user_id == user_id), None
                )
                if record is not None:
                    return record
            except Exception:
                logger.warning(
                    "ban_record_fetch_failed server_id=%s user_id=%s attempt=%s",
                    server.id,
                    user_id,
                    attempt + 1,
                )
            if attempt < 2:
                await asyncio.sleep(0.5 * (attempt + 1))
        return None

    async def handle_local_ban(
        self, event: stoat.ServerMemberRemoveEvent
    ) -> None:
        bot_id = getattr(getattr(self, "_state", None), "my_id", None)
        if bot_id and event.user_id == bot_id:
            self._pending_ban_attribution.pop(
                (event.server_id, event.user_id), None
            )
            logger.info(
                "local_ban_ignored_bot_removal server_id=%s",
                event.server_id,
            )
            return
        source_server = self.get_server(event.server_id)
        attribution = self._pending_ban_attribution.pop(
            (event.server_id, event.user_id), None
        )
        ban_record = (
            await self._fetch_ban_record(source_server, event.user_id)
            if source_server is not None
            else None
        )
        stored_reason = getattr(ban_record, "reason", None)
        reason = stored_reason or (attribution[1] if attribution else None)
        reason = reason or "No reason was provided."
        record_user = getattr(ban_record, "user", None)
        event_user = event.member.get_user() if event.member is not None else None
        user_tag = await self._resolve_user_tag(
            event.user_id, record_user or event_user
        )
        actor_id = attribution[0] if attribution else None
        actor_tag = (
            await self._resolve_user_tag(actor_id)
            if actor_id
            else "Unavailable — Stoat does not provide the moderator for this event"
        )
        warning_count = self._active_warning_count(
            event.server_id, event.user_id
        )
        source_name = source_server.name if source_server is not None else "Unknown server"
        description = (
            f"**Server:** {source_name}\n"
            f"**Server ID:** `{event.server_id}`\n"
            f"**Reason:** {reason}\n"
            f"**User:** `{user_tag}`\n"
            f"**User ID:** `{event.user_id}`\n"
            f"**Warnings in source server:** {warning_count}\n"
            f"**Moderator:** `{actor_tag}`"
        )
        ban_event_id = self.database.add_event(
            server_id=event.server_id,
            event_type="member_ban",
            user_id=event.user_id,
            actor_id=actor_id,
            details={
                "reason": reason,
                "warning_count": warning_count,
                "actor_attribution": (
                    "known_bot_action" if actor_id else "unavailable_from_stoat_event"
                ),
            },
        )
        await self.send_log(
            event.server_id,
            "Member banned",
            f"{self._event_case_line(event.server_id, ban_event_id)}{description}",
            color="#ED4245",
        )
    async def handle_member_remove(self, event: stoat.ServerMemberRemoveEvent) -> None:
        application_store = getattr(self.database, "applications", None)
        if application_store is not None:
            application_store.leave(event.server_id, event.user_id)
        join_limit_flow = getattr(self, "join_limit_flow", None)
        if join_limit_flow is not None:
            join_limit_flow.on_leave(event.server_id, event.user_id)
        bot_id = getattr(getattr(self, "_state", None), "my_id", None)
        if bot_id and event.user_id == bot_id:
            self._pending_ban_attribution.pop(
                (event.server_id, event.user_id), None
            )
            self._pending_kick_attribution.pop(
                (event.server_id, event.user_id), None
            )
            self._global_ban_removal_suppressions.discard(
                (event.server_id, event.user_id)
            )
            logger.info(
                "member_removal_ignored_for_stoatmod server_id=%s reason=%s",
                event.server_id,
                getattr(event.reason, "value", event.reason),
            )
            return
        self.database.record_daily_member_change(event.server_id, "leave")
        remove_member = getattr(self.database, "remove_dashboard_member", None)
        if remove_member is not None:
            remove_member(
                event.server_id,
                event.user_id,
                adjust_count_on_delete=True,
            )
        suppression_key = (event.server_id, event.user_id)
        if suppression_key in self._global_ban_removal_suppressions:
            self._global_ban_removal_suppressions.discard(suppression_key)
            return
        if event.reason is stoat.MemberRemovalIntention.ban:
            await self.handle_local_ban(event)
            return
        event_type = f"member_{event.reason.value.lower()}"
        attribution = (
            self._pending_kick_attribution.pop(
                (event.server_id, event.user_id), None
            )
            if event_type == "member_kick"
            else None
        )
        reason = attribution[1] if attribution else event.reason.value
        external_kick = event_type == "member_kick" and attribution is None
        removal_event_id = self.database.add_event(
            server_id=event.server_id,
            event_type=event_type,
            user_id=event.user_id,
            actor_id=attribution[0] if attribution else None,
            details={
                "reason": reason,
                "actor_attribution": (
                    "known_bot_action" if attribution else "unavailable_from_stoat_event"
                ),
                "stoatmod_initiated": not external_kick,
                "attribution_note": (
                    "ModStoat did not initiate this kick. Stoat does not provide "
                    "the external moderator or reason."
                    if external_kick else None
                ),
            },
        )
        actor_text = (
            await self._resolve_user_tag(attribution[0])
            if attribution
            else "unavailable (Stoat does not include the actor in this event)"
        )
        await self.send_log(
            event.server_id,
            f"Member {event.reason.value.lower()}",
            f"{self._event_case_line(event.server_id, removal_event_id)}"
            f"**User:** `{await self._resolve_user_tag(event.user_id)}`\n"
            f"**Actor:** {actor_text}\n**Reason:** {reason}"
            + (
                "\n**Note:** ModStoat did not initiate this kick. Stoat does not "
                "provide the external moderator or reason."
                if external_kick else ""
            ),
            color="#ED4245" if event.reason is not stoat.MemberRemovalIntention.leave else "#747F8D",
        )

    async def scan_message(self, message: stoat.Message) -> None:
        if await self._message_author_is_moderator(message):
            return
        server, server_id = message.get_server()
        if server is None or not server_id:
            return
        text_content = message.content.strip()
        images: list[tuple[str, str]] = []
        if self.database.get_image_scanning(server_id, message.channel_id):
            images = [
                (asset.id, asset.url())
                for asset in message.attachments
                if str(asset.content_type or "").lower().startswith("image/")
                and 0 < asset.size <= self.moderation_settings.max_image_bytes
                and not asset.deleted
            ]
            for index, embed in enumerate(message.embeds):
                if isinstance(embed, stoat.ImageEmbed):
                    images.append((f"embed:{index}", embed.url))
                elif isinstance(embed, stoat.TextEmbed):
                    media = embed.media
                    if (
                        media is not None
                        and str(media.content_type or "").lower().startswith("image/")
                        and 0 < media.size <= self.moderation_settings.max_image_bytes
                        and not media.deleted
                    ):
                        images.append((media.id, media.url()))
        if not text_content and not images:
            return

        results: list[tuple[str, ModerationResult]] = []
        if text_content:
            try:
                # Servers can opt into the classifier's "thinking" check, which
                # double-checks borderline categories and records its reasoning.
                thinking_enabled = getattr(self.database, "get_ai_thinking", None)
                thinking_kwargs = (
                    {"thinking": True}
                    if callable(thinking_enabled) and thinking_enabled(server_id) is True
                    else {}
                )
                async with self.limiter:
                    result = await self.moderator.classify_text(
                        text_content, **thinking_kwargs
                    )
                results.append(("text", result))
                self.log_result(message, "text", result)
            except ModerationError:
                logger.exception("scan_failed message_id=%s content_id=text", message.id)

        for image_id, image_url in images:
            try:
                async with self.limiter:
                    result = await self.moderator.classify_url(image_url)
                results.append((image_id, result))
                self.log_result(message, image_id, result)
            except ModerationError:
                logger.exception(
                    "scan_failed message_id=%s image_id=%s", message.id, image_id
                )

        blocked = [
            (image_id, result, self._moderation_policy_matches(server_id, result))
            for image_id, result in results
            if self._moderation_policy_matches(server_id, result)
        ]
        if not blocked:
            return

        matched_categories = sorted(
            {
                category
                for _image_id, _result, matches in blocked
                for category in (str(match["category"]) for match in matches)
            }
        )
        policy_matches = [
            match for _content_id, _result, matches in blocked for match in matches
        ]
        aggregate_categories, aggregate_scores = self._aggregate_results(results)
        if SUPPORT_CATEGORY in matched_categories:
            await self._send_suicidal_thoughts_support(
                message,
                server_id,
                aggregate_scores.get(SUPPORT_CATEGORY, 0.0),
            )
        # Protected detections must still remove the exposed content in enforce
        # mode. They deliberately do not create warnings or penalties: suicidal
        # thoughts use the support flow, while leaked credentials are removed to
        # protect the sender. Previously both matches were discarded here, so a
        # 99% detection could produce no moderation action at all.
        policy_matches = [
            (
                {**match, "action": "delete"}
                if match.get("protected")
                and str(match.get("category")) in SUPPORT_ONLY_CATEGORIES
                else match
            )
            for match in policy_matches
        ]
        if not policy_matches:
            return
        categories = sorted(
            {str(match["category"]) for match in policy_matches}
        )
        support_only = bool(categories) and all(
            category in SUPPORT_ONLY_CATEGORIES for category in categories
        )
        support_log_line = (
            "**Purpose:** Support only — no warning or penalty.\n"
            if support_only else ""
        )
        policy_mode = str(policy_matches[0].get("mode") or "enforce")
        non_protected_actions = [
            str(match.get("action") or "warn")
            for match in policy_matches
            if not match.get("protected")
        ]
        # Only categories that actually triggered (a policy match scoring at least the action minimum) are named in the
        # warning reason, the stored category flags and the DM. Previously every category name was listed.
        triggered_category_names = self._triggered_category_names(policy_matches)
        warning_categories = {
            name: name in triggered_category_names
            for name in aggregate_categories
            if name not in SUPPORT_ONLY_CATEGORIES
        }
        warning_scores = {
            name: score
            for name, score in aggregate_scores.items()
            if name not in SUPPORT_ONLY_CATEGORIES
        }
        triggered_scores = {
            name: score for name, score in warning_scores.items() if name in triggered_category_names
        }
        original_content = message.content
        # The AI's reasoning is message-derived content: it is stored only with the
        # case and is purged together with the original message after 30 days.
        ai_thinking = next(
            (
                getattr(result, "thinking", None)
                for content_id, result in results
                if content_id == "text" and getattr(result, "thinking", None)
            ),
            None,
        )
        ai_thinking_details = {"ai_thinking": ai_thinking} if ai_thinking else {}
        if policy_mode in {"observe", "review"}:
            event_type = (
                "moderation_policy_observed"
                if policy_mode == "observe"
                else "moderation_review_pending"
            )
            self.database.add_event(
                server_id=server_id,
                event_type=event_type,
                user_id=message.author_id,
                actor_id=self.state.my_id,
                message_id=message.id,
                channel_id=message.channel_id,
                details={
                    "mode": policy_mode,
                    "categories": categories,
                    "scores": aggregate_scores,
                    "policy_matches": policy_matches,
                    "original_content": original_content if policy_mode == "review" else None,
                    **(ai_thinking_details if policy_mode == "review" else {}),
                },
            )
            await self.send_log(
                server_id,
                "Moderation policy observation" if policy_mode == "observe" else "Moderation review requested",
                f"**User:** `{await self._resolve_user_tag(message.author_id)}`\n"
                f"**Channel:** <#{message.channel_id}>\n"
                f"**Message:** `{message.id}`\n"
                f"**Categories:** {', '.join(categories)}\n"
                f"**Mode:** {policy_mode.title()}\n\n"
                + ("No automatic action was taken." if policy_mode == "observe" else "Review this match in the dashboard before taking action."),
                color="#F59E0B" if policy_mode == "review" else "#747F8D",
            )
            return
        should_warn = any(
            action in {"warn", "timeout"} for action in non_protected_actions
        )
        should_delete = any(
            str(match.get("action") or "warn") in {"delete", "warn", "timeout"}
            for match in policy_matches
        )
        if not should_delete:
            self.database.add_event(
                server_id=server_id, event_type="moderation_policy_observed",
                user_id=message.author_id, actor_id=self.state.my_id,
                message_id=message.id, channel_id=message.channel_id,
                details={"mode": "enforce", "categories": categories, "policy_matches": policy_matches},
            )
            return
        warning_id: int | None = None
        if should_warn:
            reason = "Automatic content moderation: " + ", ".join(
                triggered_category_names
            )
            warning_id = self.database.add_warning(
                server_id=server_id,
                user_id=message.author_id,
                moderator_id=self.state.my_id,
                source="automatic",
                reason=reason,
                message_id=message.id,
                channel_id=message.channel_id,
                categories=warning_categories,
                scores=warning_scores,
                original_content=original_content,
                ai_thinking=ai_thinking,
            )
        warning_case_reference = (
            self._warning_case_reference(server_id, warning_id)
            if warning_id is not None
            else None
        )
        warning_case_line = (
            f"**Case ID:** `{warning_case_reference}`\n"
            if warning_case_reference is not None
            else ""
        )
        warning_appeal = (
            self._appeal_instructions(
                message.author_id,
                "moderation",
                warning_case_reference or "",
                server_id=server_id,
            )
            if warning_id is not None
            else ""
        )
        total = self._active_warning_count(server_id, message.author_id)
        user_tag = await self._resolve_user_tag(
            message.author_id, message.get_author_as_user()
        )
        if warning_id is not None:
            label = ", ".join(
                category.replace("_", " ")
                for category in triggered_category_names
            )
            await self._send_case_dm(
                message.author_id,
                "Your message violated the server moderation policy",
                f"A message you sent in **{server.name}** triggered the content "
                f"moderation policy.\n\n**Triggered categories:** {label}\n"
                f"**Case ID:** `{warning_case_reference}`\n"
                f"**Category scores:**\n{self._format_scores(triggered_scores)}\n"
                f"**Warnings in this server:** {total}\n\n"
                f"**Original message:**\n"
                f"{self._original_message_text(original_content)}"
                f"{warning_appeal}",
                warning_id=warning_id,
                server_id=server_id,
                user=message.get_author_as_user(),
            )
        timeout_seconds = max(
            (
                int(match.get("timeout_seconds") or 0)
                for match in policy_matches
                if match.get("action") == "timeout"
            ),
            default=0,
        )
        if timeout_seconds:
            member = server.get_member(message.author_id)
            if member is None:
                member = await server.fetch_member(message.author_id)
            if (
                not self._moderator_is_exempt(server_id, server, member)
                and await self.require_action_permissions(server, "timeout_members")
            ):
                await member.timeout(timedelta(seconds=timeout_seconds))
                self.database.add_event(
                    server_id=server_id,
                    event_type="moderation_policy_timeout",
                    user_id=message.author_id,
                    actor_id=self.state.my_id,
                    message_id=message.id,
                    channel_id=message.channel_id,
                    details={"duration_seconds": timeout_seconds, "categories": categories},
                )
        if not await self.require_action_permissions(server, "manage_messages"):
            self.database.add_event(
                server_id=server_id,
                event_type="automatic_deletion_failed",
                user_id=message.author_id,
                actor_id=self.state.my_id,
                message_id=message.id,
                channel_id=message.channel_id,
                details={
                    "warning_id": warning_id,
                    "reason": "missing_manage_messages_permission",
                    "support_only": support_only,
                    "matched_categories": categories,
                    "original_content": original_content,
                    **ai_thinking_details,
                    "categories": aggregate_categories,
                    "scores": aggregate_scores,
                    "total_warnings": total,
                },
            )
            await self.send_log(
                server_id,
                (
                    f"Automatic warning {warning_case_reference} — message not deleted"
                    if warning_id is not None else (
                        "Support — message not deleted" if support_only
                        else "Policy deletion — message not deleted"
                    )
                ),
                f"{warning_case_line}**User:** `{user_tag}`\n"
                f"**Channel:** <#{message.channel_id}>\n"
                f"**Message:** `{message.id}`\n"
                f"{support_log_line}"
                "**Deletion:** Failed because Stoatmod is missing Manage Messages.\n"
                f"**Category scores:**\n{self._format_scores(aggregate_scores)}\n"
                f"**Total warnings:** {total}\n\n"
                f"**Original message:**\n"
                f"{self._original_message_text(original_content)}",
                color="#3498DB" if support_only else "#ED4245",
            )
            if warning_id is not None:
                await self._enforce_warning_policy_and_notify(
                    server, server_id, message.author_id, warning_id, total
                )
            return
        self._bot_deleted_ids.add(message.id)
        deletion_error: Exception | None = None
        deleted = False
        for attempt in range(2):
            try:
                await message.delete()
                deleted = True
                break
            except stoat.NotFound:
                deleted = True
                break
            except Exception as exc:
                deletion_error = exc
                if attempt == 0:
                    await asyncio.sleep(0.5)
        if deleted:
            logger.warning(
                "message_deleted message_id=%s author_id=%s categories=%s",
                message.id,
                message.author_id,
                ",".join(categories),
            )
        else:
            self._bot_deleted_ids.discard(message.id)
            logger.error(
                "delete_failed message_id=%s error=%s",
                message.id,
                deletion_error,
                exc_info=(
                    type(deletion_error),
                    deletion_error,
                    deletion_error.__traceback__,
                ) if deletion_error is not None else None,
            )
            self.database.add_event(
                server_id=server_id,
                event_type="automatic_deletion_failed",
                user_id=message.author_id,
                actor_id=self.state.my_id,
                message_id=message.id,
                channel_id=message.channel_id,
                details={
                    "warning_id": warning_id,
                    "warning_added": warning_id is not None,
                    "support_only": support_only,
                    "matched_categories": categories,
                    "original_content": original_content,
                    **ai_thinking_details,
                    "categories": aggregate_categories,
                    "scores": aggregate_scores,
                    "total_warnings": total,
                },
            )
            await self.send_log(
                server_id,
                (
                    f"Automatic warning {warning_case_reference} — deletion failed"
                    if warning_id is not None else (
                        "Support — deletion failed" if support_only
                        else "Policy deletion failed"
                    )
                ),
                f"{warning_case_line}**User:** `{user_tag}`\n"
                f"**Channel:** <#{message.channel_id}>\n"
                f"**Message:** `{message.id}`\n{support_log_line}**Category scores:**\n"
                f"{self._format_scores(aggregate_scores)}\n"
                f"**Warning added:** {'Yes' if warning_id is not None else 'No'}\n"
                f"**Total warnings:** {total}\n\n"
                f"**Original message:**\n{self._original_message_text(original_content)}",
                color="#3498DB" if support_only else "#ED4245",
            )
            if warning_id is not None:
                await self._enforce_warning_policy_and_notify(
                    server, server_id, message.author_id, warning_id, total
                )
            return

        asyncio.get_running_loop().call_later(
            60, self._bot_deleted_ids.discard, message.id
        )

        self.database.add_event(
            server_id=server_id,
            event_type="automatic_deletion",
            user_id=message.author_id,
            actor_id=self.state.my_id,
            message_id=message.id,
            channel_id=message.channel_id,
            details={
                "warning_id": warning_id,
                "warning_added": warning_id is not None,
                "support_only": support_only,
                "matched_categories": categories,
                "original_content": original_content,
                **ai_thinking_details,
                "categories": aggregate_categories,
                "scores": aggregate_scores,
                "total_warnings": total,
            },
        )
        await self.send_log(
            server_id,
            (
                f"Automatic deletion and warning {warning_case_reference}"
                if warning_id is not None else (
                    "Deleted for support" if support_only else "Automatic policy deletion"
                )
            ),
            f"{warning_case_line}**User:** `{user_tag}`\n"
            f"**Channel:** <#{message.channel_id}>\n"
            f"**Message:** `{message.id}`\n{support_log_line}**Category scores:**\n"
            f"{self._format_scores(aggregate_scores)}\n"
            f"**Warning added:** {'Yes' if warning_id is not None else 'No'}\n"
            f"**Total warnings:** {total}\n\n"
            f"**Original message:**\n{self._original_message_text(original_content)}",
            color="#3498DB" if support_only else "#ED4245",
        )
        if warning_id is not None:
            await self._enforce_warning_policy_and_notify(
                server, server_id, message.author_id, warning_id, total
            )

    def log_result(self, message: stoat.Message, content_id: str, result: ModerationResult) -> None:
        _server, server_id = message.get_server()
        threshold = (
            self._moderation_threshold(server_id)
            if server_id
            else self.moderation_settings.threshold
        )
        raw_blocked = result.blocked_categories(threshold)
        ignored_categories = (
            [
                category
                for category in raw_blocked
                if not self._category_is_enabled(server_id, category)
            ]
            if server_id
            else []
        )
        record = {
            "event": "content_classified",
            "message_id": message.id,
            "content_id": content_id,
            "author_id": message.author_id,
            "channel_id": message.channel_id,
            "flagged": result.flagged,
            "threshold": threshold,
            "categories": result.categories,
            "scores": result.scores,
            "would_block": bool(raw_blocked) and not ignored_categories == raw_blocked,
            "ignored_disabled_categories": ignored_categories,
        }
        logger.info(json.dumps(record, separators=(",", ":"), sort_keys=True))


def main() -> None:
    global GLOBAL_COMMAND_OWNER_ID
    load_env_file()
    GLOBAL_COMMAND_OWNER_ID = os.getenv("GLOBAL_COMMAND_OWNER_ID", "").strip() or GLOBAL_COMMAND_OWNER_ID
    settings = Settings.from_env()
    configure_logging(settings.log_path)
    client = ModerationBot(settings)

    @client.on(stoat.ReadyEvent)
    async def on_ready(event: stoat.ReadyEvent, /) -> None:
        # Events may have been missed while disconnected: refetch members before
        # reaction roles trust the gateway cache again.
        client.reaction_role_flow.connection_reset()
        await client.handle_ready(event)

    @client.on(stoat.ServerCreateEvent)
    async def on_server_create(event: stoat.ServerCreateEvent, /) -> None:
        await client.handle_server_create(event)

    @client.on(stoat.ServerUpdateEvent)
    async def on_server_update(event: stoat.ServerUpdateEvent, /) -> None:
        await client.handle_server_update(event)

    @client.on(stoat.ServerDeleteEvent)
    async def on_server_delete(event: stoat.ServerDeleteEvent, /) -> None:
        client._track_status_server(event.server_id, connected=False)
        deleted = client.database.purge_server_data(event.server_id)
        # Use the persisted live directory because Stoat processes its cache
        # after user event handlers.
        client.update_bot_heartbeat(
            client.database.get_public_dashboard_stats()["server_count"]
        )
        logger.info(
            "server_data_purged server_id=%s records=%d tables=%d",
            event.server_id,
            sum(deleted.values()),
            len(deleted),
        )

    @client.on(stoat.ChannelDeleteEvent)
    async def on_channel_delete(event: stoat.ChannelDeleteEvent, /) -> None:
        await client.handle_channel_delete(event)

    @client.on(stoat.ChannelCreateEvent)
    async def on_channel_create(event: stoat.ChannelCreateEvent, /) -> None:
        try:
            await client.application_flow.on_channel_create(event.channel)
        except Exception:
            logger.exception("application_channel_protection_failed")

    @client.on(stoat.MessageCreateEvent)
    async def on_message(event: stoat.MessageCreateEvent, /) -> None:
        message = event.message
        if message.author_id == client.state.my_id or message.webhook is not None:
            return
        author = message.get_author_as_user()
        if author is None:
            try:
                author = await client.fetch_user(message.author_id)
            except Exception:
                logger.exception(
                    "message_author_fetch_failed user_id=%s", message.author_id
                )
        if client._user_is_bot(author):
            return
        _message_server, message_server_id = message.get_server()
        if (
            message_server_id
            and author is not None
            and counts_towards_message_statistics(message.content)
        ):
            client.database.record_daily_message(message_server_id)
        if await client.application_flow.handle_dm(message):
            return
        if await client.handle_report_entry(message):
            return
        if await client.handle_captcha_response(message):
            return
        if await client.handle_dashboard_automations(message):
            return
        if await client.handle_command(message):
            return
        if not client.message_is_in_scope(message):
            return
        if await client._message_author_is_moderator(message):
            return
        if await client.handle_link_filter(message):
            return
        if await client.handle_join_limits(message):
            return
        if await client.handle_spam(message):
            return
        if message.attachments or message.embeds:
            logger.info(
                "media_message_received message_id=%s channel_id=%s "
                "attachments=%d embeds=%d",
                message.id,
                message.channel_id,
                len(message.attachments),
                len(message.embeds),
            )
        client.dispatch_scan(message)

    @client.on(stoat.MessageDeleteEvent)
    async def on_message_delete(event: stoat.MessageDeleteEvent, /) -> None:
        await client.handle_message_delete(event)

    @client.on(stoat.MessageReactEvent)
    async def on_message_react(event: stoat.MessageReactEvent, /) -> None:
        if await client.reaction_role_flow.reaction(event, added=True):
            return
        if event.user_id != client.state.my_id:
            poll = client.database.get_poll_by_message(event.message_id)
            vote_result = None
            if poll is not None and poll.get("required_role_id"):
                server = await client._resolve_dashboard_server(
                    str(poll["server_id"])
                )
                member = server.get_member(event.user_id) if server is not None else None
                if member is None and server is not None:
                    try:
                        member = await server.fetch_member(event.user_id)
                    except Exception:
                        member = None
                role_ids = {str(role_id) for role_id in (getattr(member, "role_ids", None) or [])}
                if member is None or str(poll["required_role_id"]) not in role_ids:
                    vote_result = {
                        "accepted": False,
                        "remove_emoji": event.emoji,
                        "reason": "required_role",
                    }
            if vote_result is None:
                vote_result = client.database.record_poll_vote(
                    event.message_id, event.user_id, event.emoji
                )
            if vote_result and not vote_result.get("accepted"):
                try:
                    poll_message = event.message
                    if poll_message is None:
                        channel = client.get_channel(event.channel_id) or await client.fetch_channel(event.channel_id)
                        poll_message = await channel.fetch_message(event.message_id)
                    await poll_message.unreact(event.emoji, user=event.user_id)
                except Exception:
                    logger.exception(
                        "poll_extra_reaction_remove_failed message_id=%s user_id=%s emoji=%s",
                        event.message_id, event.user_id, event.emoji,
                    )

    @client.on(stoat.MessageUnreactEvent)
    async def on_message_unreact(event: stoat.MessageUnreactEvent, /) -> None:
        if await client.reaction_role_flow.reaction(event, added=False):
            return
        if event.user_id != client.state.my_id:
            client.database.record_poll_vote(
                event.message_id, event.user_id, event.emoji, remove=True
            )

    @client.on(stoat.MessageUpdateEvent)
    async def on_message_update(event: stoat.MessageUpdateEvent, /) -> None:
        await client.handle_message_update(event)

    @client.on(stoat.MessageClearReactionEvent)
    async def on_message_clear_reaction(event: stoat.MessageClearReactionEvent, /) -> None:
        await client.reaction_role_flow.cleared(event)

    @client.on(stoat.MessageDeleteBulkEvent)
    async def on_message_delete_bulk(event: stoat.MessageDeleteBulkEvent, /) -> None:
        await client.handle_message_delete_bulk(event)

    @client.on(stoat.ServerMemberJoinEvent)
    async def on_member_join(event: stoat.ServerMemberJoinEvent, /) -> None:
        # A join delivers the member's complete state; later role changes arrive as events.
        client.reaction_role_flow.trust_member(event.member.server_id, event.member.id)
        await client.handle_member_join(event)

    @client.on(stoat.ServerMemberRemoveEvent)
    async def on_member_remove(event: stoat.ServerMemberRemoveEvent, /) -> None:
        await client.handle_member_remove(event)

    @client.on(stoat.ServerMemberUpdateEvent)
    async def on_member_update(event: stoat.ServerMemberUpdateEvent, /) -> None:
        await client.handle_member_nickname_update(event)

    @client.on(stoat.UserUpdateEvent)
    async def on_user_update(event: stoat.UserUpdateEvent, /) -> None:
        await client.handle_username_update(event)

    client.run(settings.stoat_token)


if __name__ == "__main__":
    main()
