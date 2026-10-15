from __future__ import annotations

import os
import math
from dataclasses import dataclass
from pathlib import Path

from moderation import validate_model_base_url


def load_env_file(path: str | Path = ".env") -> None:
    """Load simple KEY=VALUE entries without replacing existing variables."""
    env_path = Path(path)
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if name:
            os.environ.setdefault(name, value)


def _csv_set(name: str) -> frozenset[str]:
    return frozenset(value.strip() for value in os.getenv(name, "").split(",") if value.strip())


def _integer(name: str, default: int, *, minimum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _number(name: str, default: float, *, minimum: float, maximum: float | None = None) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value < minimum or (maximum is not None and value > maximum):
        suffix = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be at least {minimum}{suffix}")
    return value


def _boolean(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True)
class Settings:
    stoat_token: str
    local_ai_api_key: str
    local_ai_expected_version: str
    local_ai_base_url: str
    threshold: float
    max_image_bytes: int
    concurrency: int
    timeout_seconds: float
    server_ids: frozenset[str]
    channel_ids: frozenset[str]
    notification: str
    spam_repeat_count: int
    spam_repeat_window_seconds: float
    spam_rapid_count: int
    spam_rapid_window_seconds: float
    spam_score_threshold: float
    spam_score_half_life_seconds: float
    mass_mention_limit: int
    spam_timeout_seconds: int
    log_path: str
    database_path: str
    dashboard_url: str
    global_ban_sync_seconds: int
    email_relay_enabled: bool
    email_relay_webhook_url: str
    email_relay_recipient: str
    email_relay_additional_recipients: frozenset[str]
    proton_bridge_imap_host: str
    proton_bridge_imap_port: int
    proton_bridge_imap_username: str
    proton_bridge_imap_password: str
    proton_bridge_imap_mailbox: str
    proton_bridge_ca_file: str
    proton_bridge_smtp_host: str
    proton_bridge_smtp_port: int
    proton_bridge_smtp_username: str
    proton_bridge_smtp_password: str
    email_relay_poll_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        stoat_token = os.getenv("STOAT_BOT_TOKEN", "").strip()
        if not stoat_token:
            raise ValueError("STOAT_BOT_TOKEN is required")
        local_ai_expected_version = os.getenv("LOCAL_AI_EXPECTED_VERSION", "").strip()
        if not local_ai_expected_version:
            raise ValueError("LOCAL_AI_EXPECTED_VERSION is required")

        email_relay_enabled = _boolean("EMAIL_RELAY_ENABLED")
        email_relay_webhook_url = os.getenv("EMAIL_RELAY_WEBHOOK_URL", "").strip()
        proton_bridge_imap_username = os.getenv(
            "PROTON_BRIDGE_IMAP_USERNAME", ""
        ).strip()
        proton_bridge_imap_password = os.getenv(
            "PROTON_BRIDGE_IMAP_PASSWORD", ""
        ).strip()
        proton_bridge_ca_file = os.getenv("PROTON_BRIDGE_CA_FILE", "").strip()
        if email_relay_enabled:
            missing = [
                name
                for name, value in (
                    ("PROTON_BRIDGE_IMAP_USERNAME", proton_bridge_imap_username),
                    ("PROTON_BRIDGE_IMAP_PASSWORD", proton_bridge_imap_password),
                    ("PROTON_BRIDGE_CA_FILE", proton_bridge_ca_file),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "Email relay is enabled but these settings are missing: "
                    + ", ".join(missing)
                )

        notification = os.getenv("MODERATION_NOTIFICATION", "warn").strip().lower()
        if notification not in {"warn", "silent"}:
            raise ValueError("MODERATION_NOTIFICATION must be warn or silent")

        return cls(
            stoat_token=stoat_token,
            local_ai_api_key=os.getenv("LOCAL_AI_API_KEY", "").strip(),
            local_ai_expected_version=local_ai_expected_version,
            local_ai_base_url=validate_model_base_url(
                os.getenv("LOCAL_AI_BASE_URL", "http://127.0.0.1:18006").strip()
            ),
            threshold=_number("MODERATION_THRESHOLD", 0.9, minimum=0, maximum=1),
            max_image_bytes=_integer(
                "MODERATION_MAX_IMAGE_BYTES", 10 * 1024 * 1024, minimum=1
            ),
            concurrency=_integer("MODERATION_CONCURRENCY", 3, minimum=1),
            timeout_seconds=_number("MODERATION_TIMEOUT_SECONDS", 45, minimum=1),
            server_ids=_csv_set("MODERATION_SERVER_IDS"),
            channel_ids=_csv_set("MODERATION_CHANNEL_IDS"),
            notification=notification,
            spam_repeat_count=_integer("SPAM_REPEAT_COUNT", 3, minimum=2),
            spam_repeat_window_seconds=_number(
                "SPAM_REPEAT_WINDOW_SECONDS", 30, minimum=1
            ),
            spam_rapid_count=_integer("SPAM_RAPID_COUNT", 5, minimum=2),
            spam_rapid_window_seconds=_number(
                "SPAM_RAPID_WINDOW_SECONDS", 10, minimum=1
            ),
            spam_score_threshold=_number(
                "SPAM_SCORE_THRESHOLD", 7, minimum=1
            ),
            spam_score_half_life_seconds=_number(
                "SPAM_SCORE_HALF_LIFE_SECONDS", 30, minimum=1
            ),
            mass_mention_limit=_integer("MASS_MENTION_LIMIT", 5, minimum=2),
            spam_timeout_seconds=_integer("SPAM_TIMEOUT_SECONDS", 3600, minimum=1),
            log_path=os.getenv("MODERATION_LOG_PATH", "moderation.log").strip(),
            database_path=os.getenv(
                "MODERATION_DATABASE_PATH", "moderation.db"
            ).strip(),
            dashboard_url=os.getenv(
                "DASHBOARD_URL", "http://localhost:3000"
            ).strip().rstrip("/"),
            global_ban_sync_seconds=_integer(
                "GLOBAL_BAN_SYNC_SECONDS", 300, minimum=30
            ),
            email_relay_enabled=email_relay_enabled,
            email_relay_webhook_url=email_relay_webhook_url,
            email_relay_recipient=os.getenv(
                "EMAIL_RELAY_RECIPIENT", "admin@modstoat.site"
            ).strip().lower(),
            email_relay_additional_recipients=frozenset(
                value.casefold()
                for value in _csv_set("EMAIL_RELAY_ADDITIONAL_RECIPIENTS")
            ),
            proton_bridge_imap_host=os.getenv(
                "PROTON_BRIDGE_IMAP_HOST", "127.0.0.1"
            ).strip(),
            proton_bridge_imap_port=_integer(
                "PROTON_BRIDGE_IMAP_PORT", 1143, minimum=1
            ),
            proton_bridge_imap_username=proton_bridge_imap_username,
            proton_bridge_imap_password=proton_bridge_imap_password,
            proton_bridge_imap_mailbox=os.getenv(
                "PROTON_BRIDGE_IMAP_MAILBOX", "stoatmod"
            ).strip(),
            proton_bridge_ca_file=proton_bridge_ca_file,
            proton_bridge_smtp_host=os.getenv(
                "PROTON_BRIDGE_SMTP_HOST", "127.0.0.1"
            ).strip(),
            proton_bridge_smtp_port=_integer(
                "PROTON_BRIDGE_SMTP_PORT", 1025, minimum=1
            ),
            proton_bridge_smtp_username=(
                os.getenv("PROTON_BRIDGE_SMTP_USERNAME", "").strip()
                or proton_bridge_imap_username
            ),
            proton_bridge_smtp_password=(
                os.getenv("PROTON_BRIDGE_SMTP_PASSWORD", "").strip()
                or proton_bridge_imap_password
            ),
            email_relay_poll_seconds=_integer(
                "EMAIL_RELAY_POLL_SECONDS", 30, minimum=10
            ),
        )
