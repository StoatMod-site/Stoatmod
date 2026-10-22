from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
import math
import os
import re
import secrets
import sys
import time
import io
import logging
from PIL import Image
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from aiohttp import ClientSession, ClientTimeout, web


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import load_env_file  # noqa: E402

load_env_file(PROJECT_ROOT / ".env")
load_env_file(Path(__file__).resolve().parent / ".env")

from appeal_privacy import APPEAL_PRIVACY_VERSION, AI_NOTICE_VERSION
from join_limits import normalize_settings as normalize_join_limits  # noqa: E402
from database import (  # noqa: E402
    DEFAULT_SPAM_SETTINGS,
    ModerationDatabase,
    PROTECTED_MODERATION_CATEGORY_PREFIXES,
    SPAM_INTEGER_SETTINGS,
    SPAM_SETTING_LIMITS,
    SUPPORTED_MODERATION_CATEGORIES,
)
from admin_credentials import hash_password
from api.status_history import read_history  # noqa: E402
from api.discovery_og import render_server_card  # noqa: E402
from api import discovery_extras  # noqa: E402


SESSION_COOKIE = "stoat_dashboard_session"
CSRF_COOKIE = "stoat_dashboard_csrf"
STOAT_REPORT_WEBHOOK = os.getenv("STOAT_REPORT_WEBHOOK", "").strip()
STOAT_BOT_TOKEN = os.getenv("STOAT_BOT_TOKEN", "").strip()
STOAT_API_BASE = os.getenv("STOAT_API_BASE", "https://api.stoat.chat/0.8").rstrip("/")
SESSION_HOURS = int(os.getenv("DASHBOARD_SESSION_HOURS", "12"))
DEFAULT_THRESHOLD = float(os.getenv("MODERATION_THRESHOLD", "0.9"))
SPAM_DEFAULTS: dict[str, int | float] = {
    "repeat_count": int(
        os.getenv("SPAM_REPEAT_COUNT", str(DEFAULT_SPAM_SETTINGS["repeat_count"]))
    ),
    "repeat_window_seconds": float(
        os.getenv(
            "SPAM_REPEAT_WINDOW_SECONDS",
            str(DEFAULT_SPAM_SETTINGS["repeat_window_seconds"]),
        )
    ),
    "rapid_count": int(
        os.getenv("SPAM_RAPID_COUNT", str(DEFAULT_SPAM_SETTINGS["rapid_count"]))
    ),
    "rapid_window_seconds": float(
        os.getenv(
            "SPAM_RAPID_WINDOW_SECONDS",
            str(DEFAULT_SPAM_SETTINGS["rapid_window_seconds"]),
        )
    ),
    "score_threshold": float(
        os.getenv(
            "SPAM_SCORE_THRESHOLD", str(DEFAULT_SPAM_SETTINGS["score_threshold"])
        )
    ),
    "score_half_life_seconds": float(
        os.getenv(
            "SPAM_SCORE_HALF_LIFE_SECONDS",
            str(DEFAULT_SPAM_SETTINGS["score_half_life_seconds"]),
        )
    ),
    "mass_mention_limit": int(
        os.getenv(
            "MASS_MENTION_LIMIT", str(DEFAULT_SPAM_SETTINGS["mass_mention_limit"])
        )
    ),
    "timeout_seconds": int(
        os.getenv(
            "SPAM_TIMEOUT_SECONDS", str(DEFAULT_SPAM_SETTINGS["timeout_seconds"])
        )
    ),
}
SECURE_COOKIES = os.getenv("DASHBOARD_SECURE_COOKIES", "false").lower() == "true"
ALLOWED_ORIGIN = os.getenv("DASHBOARD_ALLOWED_ORIGIN", "http://localhost:3000")
if urlparse(ALLOWED_ORIGIN).scheme.casefold() == "https" and not SECURE_COOKIES:
    raise RuntimeError(
        "DASHBOARD_SECURE_COOKIES must be true when DASHBOARD_ALLOWED_ORIGIN uses HTTPS."
    )
TRUSTED_PROXY_IPS = frozenset(
    value.strip()
    for value in os.getenv(
        "DASHBOARD_TRUSTED_PROXY_IPS", "127.0.0.1,::1"
    ).split(",")
    if value.strip()
)
TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")
VERIFICATION_PRIVACY_VERSION = "2026-10-01"
# Process-local keys support short-lived security limits and redacted exports only.
_ADMIN_RATE_LIMIT_KEY = secrets.token_bytes(32)
GLOBAL_COMMAND_OWNER_ID = os.getenv("GLOBAL_COMMAND_OWNER_ID", "").strip() or "00000000000000000000000000"
GLOBAL_REFERENCE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DATABASE_PATH = os.getenv(
    "MODERATION_DATABASE_PATH", str(PROJECT_ROOT / "moderation.db")
)
DATABASE_KEY = web.AppKey("database", ModerationDatabase)
LOGIN_ATTEMPTS_KEY = web.AppKey("login_attempts", dict)
MAX_EMAIL_ATTACHMENTS = 5
MAX_EMAIL_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_EMAIL_TOTAL_ATTACHMENT_BYTES = 8 * 1024 * 1024
MAX_EMAIL_COPY_RECIPIENTS = 20
MAX_EMAIL_RECIPIENT_FIELD_LENGTH = 4000
MAX_CASE_EVIDENCE_IMAGES = 3
MAX_CASE_EVIDENCE_IMAGE_BYTES = 4 * 1024 * 1024
MAX_CASE_EVIDENCE_TOTAL_BYTES = 8 * 1024 * 1024
CASE_EVIDENCE_IMAGE_TYPES = {
    "GIF": "image/gif",
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "WEBP": "image/webp",
}
PRIVACY_TEXT_FILE_SUFFIXES = {".log", ".txt", ".json", ".jsonl", ".ndjson", ".csv", ".tsv"}
PRIVACY_DATABASE_FILE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".bak"}
PRIVACY_MAX_FILE_BYTES = 50 * 1024 * 1024
PRIVACY_MAX_FILES_SCANNED = 500
PRIVACY_MAX_FILE_MATCHES = 500
_PRIVACY_IPV4_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)
_PRIVACY_IPV6_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
_STOAT_USER_ID_PATTERN = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
_DUMMY_ADMIN_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _code_hash(value: str) -> str:
    return hashlib.sha256(value.strip().upper().encode("utf-8")).hexdigest()


CAPTCHA_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _json_error(message: str, status: int) -> web.Response:
    return web.json_response({"error": message}, status=status)


def _client_ip(request: web.Request) -> str:
    remote = (request.remote or "unknown").strip()
    try:
        normalized_remote = str(ipaddress.ip_address(remote.split("%", 1)[0]))
    except ValueError:
        normalized_remote = remote
    if remote in TRUSTED_PROXY_IPS or normalized_remote in TRUSTED_PROXY_IPS:
        forwarded = (
            request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        )
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded.split("%", 1)[0]))
            except ValueError:
                pass
    return normalized_remote


@web.middleware
async def security_middleware(
    request: web.Request, handler: Any
) -> web.StreamResponse:
    if request.method == "OPTIONS":
        response: web.StreamResponse = web.Response(status=204)
    else:
        try:
            response = await handler(request)
        except web.HTTPException as exc:
            response = _json_error(exc.reason, exc.status)
    origin = request.headers.get("Origin")
    if origin and origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, X-CSRF-Token, X-Owner-CSRF-Token, X-Admin-CSRF-Token, "
            "X-Appeal-Code, X-Stoat-User-ID"
        )
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Vary"] = "Origin"
    if not response.headers.get("Cache-Control", "").lower().startswith("public"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


def _database(request: web.Request) -> ModerationDatabase:
    return request.app[DATABASE_KEY]


async def _prune_confirmed_deleted_exempt_channels(
    database: ModerationDatabase,
    server_id: str,
    current_settings: dict[str, Any] | None = None,
    additional_channel_ids: list[Any] | None = None,
) -> set[str]:
    """Remove stale exemptions that Stoat confirms no longer exist.

    The dashboard API runs separately from the gateway bot, so this check still
    works while the bot process is offline. Permission and network failures are
    deliberately preserved; only an authoritative 404 removes an exemption.
    """
    current_settings = current_settings or database.get_dashboard_settings(
        server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS
    )
    exempt_channel_ids = sorted({
        str(channel_id)
        for channel_id in [
            *current_settings.get("exempt_channels", []),
            *((additional_channel_ids or [])[:100]),
        ]
        if str(channel_id).strip()
    })
    if not exempt_channel_ids or not STOAT_BOT_TOKEN:
        return set()

    semaphore = asyncio.Semaphore(5)
    timeout = ClientTimeout(total=5, connect=2)
    headers = {"X-Bot-Token": STOAT_BOT_TOKEN}

    async with ClientSession(timeout=timeout) as session:
        async def confirmed_deleted(channel_id: str) -> str | None:
            url = f"{STOAT_API_BASE}/channels/{quote(channel_id, safe='')}"
            try:
                async with semaphore:
                    async with session.get(url, headers=headers) as response:
                        return channel_id if response.status == 404 else None
            except (asyncio.TimeoutError, OSError):
                return None
            except Exception:
                logging.warning(
                    "deleted_channel_verification_failed server_id=%s channel_id=%s source=dashboard",
                    server_id,
                    channel_id,
                    exc_info=True,
                )
                return None

        tasks = {
            asyncio.create_task(confirmed_deleted(channel_id))
            for channel_id in exempt_channel_ids
        }
        completed, pending = await asyncio.wait(tasks, timeout=5)
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        checks = [task.result() for task in completed if not task.cancelled()]

    deleted_channel_ids = {
        channel_id for channel_id in checks if channel_id is not None
    }
    for channel_id in deleted_channel_ids:
        removed = database.remove_deleted_channel_reference(server_id, channel_id)
        if removed:
            logging.info(
                "deleted_channel_exemption_removed server_id=%s channel_id=%s source=dashboard",
                server_id,
                channel_id,
            )
    return deleted_channel_ids


def _session(request: web.Request) -> tuple[str, str]:
    raw_token = request.cookies.get(SESSION_COOKIE, "")
    if not raw_token:
        raise web.HTTPUnauthorized(reason="Enter a fresh dashboard code to continue.")
    session = _database(request).get_dashboard_session(_token_hash(raw_token))
    if session is None:
        raise web.HTTPUnauthorized(reason="Your dashboard session has expired.")
    server_id, user_id = session
    if not _database(request).dashboard_user_has_access(server_id, user_id):
        _database(request).remove_dashboard_session(_token_hash(raw_token))
        raise web.HTTPForbidden(
            reason="The server owner has revoked your dashboard access."
        )
    return session


def _server_owner_session(request: web.Request) -> tuple[str, str]:
    server_id, user_id = _session(request)
    if user_id != _database(request).get_dashboard_server_owner(server_id):
        raise web.HTTPForbidden(
            reason="Only the server owner can manage dashboard access."
        )
    return server_id, user_id


def _require_csrf(request: web.Request) -> None:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get("X-CSRF-Token", "")
    if not cookie_token or not secrets.compare_digest(cookie_token, header_token):
        raise web.HTTPForbidden(reason="The security token is missing or invalid.")


def _normalize_stoat_user_id(value: object) -> str:
    user_id = str(value or "").strip().upper()
    if _STOAT_USER_ID_PATTERN.fullmatch(user_id) is None:
        raise ValueError("Enter a valid 26-character Stoat user ID.")
    return user_id


_ADMIN_PRIVACY_SECRET_FIELDS = {
    "access_token",
    "answer_hash",
    "api_key",
    "captcha_hash",
    "captcha_salt",
    "claim_token",
    "code_hash",
    "key_hash",
    "password_hash",
    "refresh_token",
    "salt",
    "secret",
    "subject_hash",
    "token_hash",
}


async def verify_code(request: web.Request) -> web.Response:
    ip = request.remote or "unknown"
    now = time.monotonic()
    attempts: deque[float] = request.app[LOGIN_ATTEMPTS_KEY][ip]
    while attempts and now - attempts[0] > 300:
        attempts.popleft()
    if len(attempts) >= 10:
        return _json_error("Too many attempts. Wait five minutes and try again.", 429)
    attempts.append(now)

    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    code = str(payload.get("code", "")).strip().upper()
    if len(code) != 8 or not code.isalnum():
        return _json_error("Enter the eight-character code sent by the bot.", 400)
    identity = _database(request).consume_dashboard_login_code(_code_hash(code))
    if identity is None:
        return _json_error("That code is invalid, expired, or already used.", 401)

    server_id, user_id = identity
    if not _database(request).dashboard_user_has_access(server_id, user_id):
        return _json_error(
            "The server owner has not granted you access to this dashboard.", 403
        )
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)
    _database(request).create_dashboard_session(
        _token_hash(session_token),
        server_id,
        user_id,
        expires_at.isoformat(timespec="seconds"),
    )
    _database(request).add_event(
        server_id=server_id,
        event_type="dashboard_login",
        actor_id=user_id,
        details={"expires_at": expires_at.isoformat(timespec="seconds")},
    )
    _database(request).enqueue_dashboard_action(
        server_id,
        "send_dashboard_login_log",
        user_id,
        {"expires_at": expires_at.isoformat(timespec="seconds")},
    )
    response = web.json_response(
        {"ok": True, "server_id": server_id, "expires_at": expires_at.isoformat()}
    )
    max_age = SESSION_HOURS * 3600
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=max_age,
        httponly=True,
        secure=SECURE_COOKIES,
        samesite="Strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=SECURE_COOKIES,
        samesite="Strict",
        path="/",
    )
    return response


async def session_status(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    database = _database(request)
    overview = database.get_dashboard_overview(server_id)
    return web.json_response(
        {
            "authenticated": True,
            "user_id": user_id,
            "is_owner": user_id == database.get_dashboard_server_owner(server_id),
            "server": overview["server"],
        }
    )


async def logout(request: web.Request) -> web.Response:
    _require_csrf(request)
    raw_token = request.cookies.get(SESSION_COOKIE, "")
    if raw_token:
        _database(request).remove_dashboard_session(_token_hash(raw_token))
    response = web.json_response({"ok": True})
    response.del_cookie(SESSION_COOKIE, path="/")
    response.del_cookie(CSRF_COOKIE, path="/")
    return response


async def dashboard(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    database = _database(request)
    await _prune_confirmed_deleted_exempt_channels(database, server_id)
    notifications = database.get_dashboard_notification_snapshot(server_id, user_id)
    polls = database.list_polls(server_id, limit=10)
    for poll in polls:
        poll.pop("votes", None)
    payload = {
            "overview": database.get_dashboard_overview(server_id),
            "settings": database.get_dashboard_settings(
                server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS
            ),
            "cases": database.list_dashboard_cases(server_id, limit=8),
            "events": database.list_dashboard_events(server_id, limit=10),
            "announcements": database.list_dashboard_announcements(
                server_id, user_id
            ),
            "appeals": database.list_dashboard_appeals(server_id, limit=8),
            "automations": database.list_automation_rules(server_id),
            "polls": polls,
            "poll_templates": database.list_poll_templates(server_id),
            "server_reports": database.list_local_reports(server_id, limit=25),
            "server_report_settings": database.get_local_report_settings(server_id),
            "onboarding": database.get_onboarding_state(server_id, user_id),
            "global_leaderboards": {
                "activity": {
                    period: database.get_global_leaderboard("activity", period, limit=10)
                    for period in ("day", "week", "month")
                },
                "members": database.get_global_leaderboard("members", limit=10),
            },
            "discovery": database.get_discovery_application(server_id),
            "notifications": notifications,
        }
    if user_id == database.get_dashboard_server_owner(server_id):
        payload["access_control"] = database.list_dashboard_access(server_id)
    return web.json_response(payload)


async def dashboard_notifications(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    database = _database(request)
    response = web.json_response({
        "notifications": database.get_dashboard_notification_snapshot(
            server_id, user_id
        ),
        "discovery": database.get_discovery_application(server_id),
        "announcements": database.list_dashboard_announcements(server_id, user_id),
    })
    response.headers["Cache-Control"] = "private, no-store"
    return response


async def mark_dashboard_notification_read(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    section = request.match_info.get("section", "").strip().lower()
    try:
        payload = await request.json()
        through_event_id = int(payload.get("through_event_id", -1))
        result = _database(request).mark_dashboard_notification_read(
            server_id, user_id, section, through_event_id
        )
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception:
        return _json_error("A valid notification cursor is required.", 400)
    return web.json_response({"section": section, **result})


async def dashboard_access(request: web.Request) -> web.Response:
    server_id, _owner_id = _server_owner_session(request)
    return web.json_response(
        {"access_control": _database(request).list_dashboard_access(server_id)}
    )


async def grant_dashboard_access(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, owner_id = _server_owner_session(request)
    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    user_id = str(payload.get("user_id", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9]{10,64}", user_id):
        return _json_error("Enter a valid Stoat user ID.", 400)
    if user_id == owner_id:
        return _json_error("The server owner always has dashboard access.", 400)
    database = _database(request)
    member = database.get_dashboard_member(server_id, user_id)
    if member is None or member.get("is_bot"):
        return _json_error("Choose a non-bot member of this server.", 404)
    created = database.grant_dashboard_access(server_id, user_id, owner_id)
    if created:
        database.add_event(
            server_id=server_id,
            event_type="dashboard_access_granted",
            user_id=user_id,
            actor_id=owner_id,
            details={"user_id": user_id},
        )
    return web.json_response(
        {
            "ok": True,
            "created": created,
            "access_control": database.list_dashboard_access(server_id),
        },
        status=201 if created else 200,
    )


async def revoke_dashboard_access(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, owner_id = _server_owner_session(request)
    user_id = request.match_info["user_id"].strip()
    if user_id == owner_id:
        return _json_error("The server owner cannot revoke their own access.", 400)
    database = _database(request)
    removed = database.revoke_dashboard_access(server_id, user_id, owner_id)
    if not removed:
        return _json_error("That user does not have dashboard access.", 404)
    database.add_event(
        server_id=server_id,
        event_type="dashboard_access_revoked",
        user_id=user_id,
        actor_id=owner_id,
        details={"user_id": user_id, "sessions_revoked": True},
    )
    return web.json_response(
        {
            "ok": True,
            "access_control": database.list_dashboard_access(server_id),
        }
    )


async def restore_dashboard_access(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, owner_id = _server_owner_session(request)
    user_id = request.match_info["user_id"].strip()
    if user_id == owner_id:
        return _json_error("The server owner always has dashboard access.", 400)
    database = _database(request)
    restored = database.restore_dashboard_access(server_id, user_id)
    if not restored:
        return _json_error("That user is not blocked from the dashboard.", 404)
    database.add_event(
        server_id=server_id,
        event_type="dashboard_access_restored",
        user_id=user_id,
        actor_id=owner_id,
        details={"user_id": user_id},
    )
    return web.json_response(
        {
            "ok": True,
            "access_control": database.list_dashboard_access(server_id),
        }
    )


async def revoke_all_dashboard_sessions(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, owner_id = _server_owner_session(request)
    database = _database(request)
    revoked = database.revoke_dashboard_sessions(server_id)
    database.add_event(
        server_id=server_id,
        event_type="dashboard_sessions_revoked",
        actor_id=owner_id,
        details={"revoked_sessions": revoked},
    )
    response = web.json_response({"ok": True, "revoked_sessions": revoked})
    response.del_cookie(SESSION_COOKIE, path="/")
    response.del_cookie(CSRF_COOKIE, path="/")
    return response


def _discovery_listing_fields(
    payload: dict[str, Any]
) -> tuple[str, str, str, list[str]]:
    description = str(payload.get("description", "")).strip()
    information = str(payload.get("information", "")).strip()
    invite_url = _database_invite_url(payload.get("invite_url", ""))
    tags = ModerationDatabase.validate_discovery_tags(payload.get("tags", []))
    if not 20 <= len(description) <= 500:
        raise ValueError("The server description must be between 20 and 500 characters.")
    if len(information) > 1500:
        raise ValueError("Server information must be 1,500 characters or fewer.")
    return description, information, invite_url, tags


def _database_invite_url(value: Any) -> str:
    return ModerationDatabase.validate_discovery_invite(str(value))


async def discovery_status(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    response = web.json_response(
        _database(request).get_discovery_application(server_id)
    )
    response.headers["Cache-Control"] = "no-store"
    return response


async def apply_for_discovery(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    _require_csrf(request)
    try:
        payload = await request.json()
        description, information, invite_url, tags = _discovery_listing_fields(payload)
        result = _database(request).submit_discovery_application(
            server_id, user_id, description, information, invite_url, tags
        )
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    return web.json_response(result, status=201)


async def update_discovery_listing(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    _require_csrf(request)
    try:
        payload = await request.json()
        description, information, invite_url, tags = _discovery_listing_fields(payload)
        result = _database(request).update_discovery_listing(
            server_id, description, information, invite_url, tags, user_id
        )
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    return web.json_response(result)


async def bump_discovery_listing(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    _require_csrf(request)
    database = _database(request)
    try:
        bump = database.bump_discovery_server(server_id, user_id)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    if bump["bumped"]:
        database.add_event(
            server_id=server_id,
            event_type="discovery_listing_bumped",
            actor_id=user_id,
            details={"next_bump_at": bump["next_bump_at"]},
        )
    return web.json_response({
        **database.get_discovery_application(server_id),
        "bump": bump,
    })


DISCOVERY_OG_TTL_SECONDS = 3 * 60 * 60
DISCOVERY_OG_MAX_MEDIA_BYTES = 8 * 1024 * 1024
_discovery_og_cache: dict[str, tuple[float, tuple[Any, ...], bytes]] = {}


async def _fetch_discovery_media(session: ClientSession, url: Any) -> bytes | None:
    """Server icons and banners only come from Stoat's media host."""
    parsed = urlparse(str(url or ""))
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (host == "stoatusercontent.com" or host.endswith(".stoatusercontent.com")):
        return None
    try:
        async with session.get(parsed.geturl(), allow_redirects=False) as response:
            if response.status != 200:
                return None
            data = await response.content.read(DISCOVERY_OG_MAX_MEDIA_BYTES + 1)
    except Exception:  # noqa: BLE001 - the card falls back to the plain design
        return None
    return data if 0 < len(data) <= DISCOVERY_OG_MAX_MEDIA_BYTES else None


async def public_discovery_og(request: web.Request) -> web.Response:
    """1200x630 social image for a public Discovery listing (og:image of its profile page)."""
    server_id = request.match_info["server_id"]
    if not server_id.isalnum() or len(server_id) > 64:
        raise web.HTTPNotFound()
    server = next(
        (item for item in _database(request).list_public_discovery_servers() if str(item.get("server_id", "")).lower() == server_id.lower()),
        None,
    )
    if server is None:
        raise web.HTTPNotFound()
    store = request.app[discovery_extras.STORE_KEY]
    store.enrich([server])
    key = tuple(str(server.get(name)) for name in ("server_name", "description", "server_icon_url", "server_banner_url", "member_count", "global_rank", "logo_url", "custom_banner_url", "verified"))
    cached = _discovery_og_cache.get(server["server_id"])
    now = time.monotonic()
    if cached and cached[1] == key and now - cached[0] < DISCOVERY_OG_TTL_SECONDS:
        body = cached[2]
    else:
        logo = store.get_media(server["server_id"], "logo")
        custom_banner = store.get_media(server["server_id"], "banner")
        async with ClientSession(timeout=ClientTimeout(total=8), headers={"User-Agent": "Stoatmod/1.0 (+https://modstoat.site)"}) as session:
            icon, banner = await asyncio.gather(
                _fetch_discovery_media(session, None if logo else server.get("server_icon_url")),
                _fetch_discovery_media(session, None if custom_banner else server.get("server_banner_url")),
            )
        icon = logo["data"] if logo else icon
        banner = custom_banner["data"] if custom_banner else banner
        body = await asyncio.get_running_loop().run_in_executor(
            None, lambda: render_server_card(server, icon=icon, banner=banner)
        )
        if len(_discovery_og_cache) > 500:
            _discovery_og_cache.clear()
        _discovery_og_cache[server["server_id"]] = (now, key, body)
    return web.Response(
        body=body,
        content_type="image/png",
        headers={"Cache-Control": "public, max-age=3600, stale-while-revalidate=86400"},
    )


async def public_discovery(request: web.Request) -> web.Response:
    store = request.app[discovery_extras.STORE_KEY]
    servers = store.enrich(_database(request).list_public_discovery_servers())
    response = web.json_response({
        "servers": servers,
        "spotlight": store.spotlight([str(server["server_id"]) for server in servers]),
    })
    response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=120"
    return response


async def stats(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    return web.json_response(_database(request).get_dashboard_overview(server_id))


async def cases(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    return web.json_response(
        {"cases": _database(request).list_dashboard_cases(server_id)}
    )


async def members(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    return web.json_response(
        {"members": _database(request).list_dashboard_members(server_id)}
    )


def _member_id(request: web.Request) -> str:
    user_id = request.match_info["user_id"].strip()
    if not user_id.isalnum() or not 10 <= len(user_id) <= 64:
        raise web.HTTPBadRequest(reason="Enter a valid Stoat user ID.")
    return user_id


async def member_detail(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    member = _database(request).get_dashboard_member(server_id, _member_id(request))
    if member is None:
        return _json_error("Member not found in this server snapshot.", 404)
    return web.json_response({"member": member})


async def refresh_member_profile(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    target_id = _member_id(request)
    database = _database(request)
    if database.get_dashboard_member(server_id, target_id) is None:
        return _json_error("Member not found in this server snapshot.", 404)
    database.enqueue_dashboard_action(
        server_id, "refresh_member_profile", user_id, {"user_id": target_id}
    )
    return web.json_response({"queued": True}, status=202)


async def moderate_member(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    target_id = _member_id(request)
    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    action = str(payload.get("action", "")).strip().lower()
    reason = str(payload.get("reason", "")).strip()
    if action not in {"warn", "mute", "kick", "ban"}:
        return _json_error("Choose warn, mute, kick, or ban.", 400)
    if not 3 <= len(reason) <= 1000:
        return _json_error("Enter a reason between 3 and 1,000 characters.", 400)
    database = _database(request)
    if database.get_dashboard_member(server_id, target_id) is None:
        return _json_error("Member not found in this server snapshot.", 404)
    action_payload: dict[str, Any] = {
        "user_id": target_id, "action": action, "reason": reason
    }
    if action == "mute":
        try:
            duration_seconds = int(payload.get("duration_seconds", 3600))
        except (TypeError, ValueError):
            return _json_error("Mute duration must be a whole number of seconds.", 400)
        if not 60 <= duration_seconds <= 28 * 24 * 60 * 60:
            return _json_error("Mute duration must be between one minute and four weeks.", 400)
        action_payload["duration_seconds"] = duration_seconds
    action_id = database.enqueue_dashboard_action(
        server_id, "moderate_member", user_id, action_payload
    )
    database.add_event(
        server_id=server_id,
        event_type="dashboard_member_action_queued",
        user_id=target_id,
        actor_id=user_id,
        details={"action": action, "reason": reason, "action_id": action_id},
    )
    return web.json_response({"queued": True, "action_id": action_id}, status=202)


def _case_reference(request: web.Request) -> str:
    reference = request.match_info["reference"].strip().upper()
    if len(reference) != 8 or not reference.isalnum():
        raise web.HTTPBadRequest(reason="Enter a valid eight-character case reference.")
    return reference


async def case_detail(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    detail = _database(request).get_moderation_case_detail(
        server_id, _case_reference(request)
    )
    if detail is None:
        return _json_error("Case not found in this server.", 404)
    return web.json_response({"case": detail})


async def _case_entry_form(
    request: web.Request,
) -> tuple[dict[str, Any], list[tuple[str, str, bytes]]]:
    if not request.content_type.startswith("multipart/"):
        try:
            payload = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(
                reason="A valid case entry form is required."
            ) from exc
        if not isinstance(payload, dict):
            raise web.HTTPBadRequest(reason="A JSON object is required.")
        return payload, []

    fields: dict[str, str] = {}
    images: list[tuple[str, str, bytes]] = []
    total_size = 0
    reader = await request.multipart()
    while part := await reader.next():
        if part.name != "images":
            fields[str(part.name)] = (await part.text()).strip()
            continue
        if not part.filename:
            continue
        if len(images) >= MAX_CASE_EVIDENCE_IMAGES:
            raise web.HTTPBadRequest(
                reason=f"Add no more than {MAX_CASE_EVIDENCE_IMAGES} evidence images."
            )
        data = await part.read(decode=False)
        if len(data) > MAX_CASE_EVIDENCE_IMAGE_BYTES:
            raise web.HTTPBadRequest(reason="Each evidence image must be 4 MB or smaller.")
        total_size += len(data)
        if total_size > MAX_CASE_EVIDENCE_TOTAL_BYTES:
            raise web.HTTPBadRequest(
                reason="Evidence images must be 8 MB or smaller in total."
            )
        filename = Path(part.filename).name.strip()[:180]
        if not filename or any(ord(character) < 32 for character in filename):
            raise web.HTTPBadRequest(reason="An evidence image filename is invalid.")
        try:
            with Image.open(io.BytesIO(data)) as image:
                content_type = CASE_EVIDENCE_IMAGE_TYPES.get(
                    str(image.format or "").upper()
                )
                width, height = image.size
                if content_type is None:
                    raise ValueError("unsupported image format")
                if width < 1 or height < 1 or width * height > 25_000_000:
                    raise ValueError("unsafe image dimensions")
                image.verify()
        except (OSError, SyntaxError, ValueError, Image.DecompressionBombError) as exc:
            raise web.HTTPBadRequest(
                reason="Evidence files must be valid PNG, JPEG, WebP, or GIF images."
            ) from exc
        images.append((filename, content_type, data))
    return fields, images


async def add_case_entry(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload, images = await _case_entry_form(request)
    except web.HTTPException:
        raise
    entry_type = str(payload.get("entry_type", "")).strip().lower()
    content = str(payload.get("content", "")).strip()
    if entry_type not in {"note", "evidence"}:
        return _json_error("Choose note or evidence.", 400)
    if images and entry_type != "evidence":
        return _json_error("Images can only be attached to evidence entries.", 400)
    if len(content) > 4000 or (len(content) < 2 and not images):
        return _json_error(
            "Add a short description or at least one evidence image. Text can be up to 4,000 characters.",
            400,
        )
    reference = _case_reference(request)
    database = _database(request)
    try:
        entry = database.add_moderation_case_entry(
            server_id, reference, entry_type, content, user_id, images
        )
    except ValueError as exc:
        return _json_error(str(exc), 409)
    if entry is None:
        return _json_error("Case not found in this server.", 404)
    database.add_event(
        server_id=server_id,
        event_type="dashboard_case_entry_added",
        actor_id=user_id,
        details={
            "case_reference": reference,
            "entry_type": entry_type,
            "attachment_count": len(images),
        },
    )
    database.enqueue_dashboard_action(
        server_id,
        "send_case_entry_log",
        user_id,
        {
            "case_reference": reference,
            "entry_type": entry_type,
            "attachment_count": len(images),
        },
    )
    return web.json_response({"entry": entry}, status=201)


def _case_attachment_id(request: web.Request) -> int:
    try:
        attachment_id = int(request.match_info["attachment_id"])
    except (KeyError, ValueError) as exc:
        raise web.HTTPBadRequest(reason="Enter a valid evidence image ID.") from exc
    if attachment_id < 1:
        raise web.HTTPBadRequest(reason="Enter a valid evidence image ID.")
    return attachment_id


def _case_attachment_response(attachment: dict[str, Any] | None) -> web.Response:
    if attachment is None:
        raise web.HTTPNotFound(reason="Evidence image not found.")
    encoded_filename = quote(str(attachment["filename"]), safe="")
    return web.Response(
        body=attachment["data"],
        content_type=str(attachment["content_type"]),
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": (
                "inline; filename=\"evidence-image\"; "
                f"filename*=UTF-8''{encoded_filename}"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


async def case_entry_attachment(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    attachment = _database(request).get_moderation_case_attachment(
        server_id,
        _case_reference(request),
        _case_attachment_id(request),
    )
    return _case_attachment_response(attachment)


def _remove_case_record(
    database: ModerationDatabase,
    *,
    server_id: str,
    reference: str,
    actor_id: str,
) -> dict[str, Any] | None:
    result = database.remove_moderation_case(server_id, reference)
    if result is None:
        return None
    case, warning = result
    remaining_warnings = database.count_active_warnings(server_id, case.user_id)
    details = {
        "case_reference": case.reference_id,
        "action": case.action,
        "reason": case.reason,
        "source_type": case.source_type,
        "warning_removed": warning is not None,
        "remaining_warnings": remaining_warnings,
    }
    database.add_event(
        server_id=server_id,
        event_type="dashboard_moderation_case_removed",
        user_id=case.user_id,
        actor_id=actor_id,
        details=details,
    )
    database.enqueue_dashboard_action(
        server_id,
        "send_case_removed_log",
        actor_id,
        {"user_id": case.user_id, **details},
    )
    return {
        "reference_id": case.reference_id,
        "user_id": case.user_id,
        "status": "removed",
        "remaining_warnings": remaining_warnings,
    }


async def remove_case(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    removed = _remove_case_record(
        _database(request),
        server_id=server_id,
        reference=_case_reference(request),
        actor_id=user_id,
    )
    if removed is None:
        return _json_error("Case not found in this server or already removed.", 404)
    return web.json_response({"case": removed})


async def events(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    return web.json_response(
        {"events": _database(request).list_dashboard_events(server_id)}
    )


async def dismiss_dashboard_announcement(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        announcement_id = int(request.match_info["announcement_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Announcement not found.", 404)
    if not _database(request).dismiss_dashboard_announcement(
        server_id, user_id, announcement_id
    ):
        return _json_error("Announcement not found.", 404)
    return web.json_response({"ok": True})


def _appeal_rate_limit(request: web.Request) -> web.Response | None:
    key = f"appeal:{_client_ip(request)}"
    now = time.monotonic()
    attempts: deque[float] = request.app[LOGIN_ATTEMPTS_KEY][key]
    while attempts and now - attempts[0] > 300:
        attempts.popleft()
    if len(attempts) >= 20:
        return _json_error("Too many appeal attempts. Wait five minutes and try again.", 429)
    attempts.append(now)
    return None


def _public_appeal(appeal: dict[str, Any]) -> dict[str, Any]:
    """Remove internal reviewer identities from a public appeal response."""
    result = dict(appeal)
    result.pop("reviewer_id", None)
    evidence = dict(result.get("evidence") or {})
    evidence.pop("moderator_id", None)
    result["evidence"] = evidence
    result["messages"] = [
        {**dict(message), "sender_id": None}
        for message in result.get("messages") or []
    ]
    return result


def _appeal_consent(request: web.Request, payload: dict[str, Any], *, follow_up: bool = False) -> tuple[str, bool | None]:
    multipart = request.content_type.startswith("multipart/")
    agreed = payload.get("privacy_policy_agreed")
    if not (agreed == "true" if multipart else agreed is True):
        raise web.HTTPBadRequest(reason="Agree to the privacy policy and appeal processing before submitting.")
    version = payload.get("privacy_policy_version")
    if version != APPEAL_PRIVACY_VERSION:
        raise web.HTTPConflict(reason="The appeal privacy notice has changed. Refresh and review it before agreeing.")
    choice = payload.get("ai_improvement_opt_in")
    if choice is None:
        selected = None if follow_up else False
    elif multipart and choice in ("true", "false"):
        selected = choice == "true"
    elif not multipart and type(choice) is bool:
        selected = choice
    else:
        raise web.HTTPBadRequest(reason="Choose whether to permit AI improvement using the separate checkbox.")
    if selected and payload.get("ai_notice_version") != AI_NOTICE_VERSION:
        raise web.HTTPConflict(reason="Review the current AI-improvement notice before opting in.")
    return str(version), selected


async def withdraw_appeal_ai_permission(request: web.Request) -> web.Response:
    limited = _appeal_rate_limit(request)
    if limited is not None:
        return limited
    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    if not isinstance(payload, dict):
        return _json_error("A JSON object is required.", 400)
    database = _database(request)
    database.appeal_privacy.prune()
    appeal = database.get_appeal_by_credentials(_code_hash(str(payload.get("code", "")).strip().upper()), str(payload.get("user_id", "")).strip())
    if appeal is None:
        return _json_error("The appeal credentials are invalid.", 404)
    database.appeal_privacy.withdraw(appeal["id"])
    return web.json_response({"appeal": _public_appeal(database.get_appeal(appeal["id"]))})


async def appeal_lookup(request: web.Request) -> web.Response:
    limited = _appeal_rate_limit(request)
    if limited is not None:
        return limited
    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    if not isinstance(payload, dict):
        return _json_error("A JSON object is required.", 400)
    code = str(payload.get("code", "")).strip().upper()
    user_id = str(payload.get("user_id", "")).strip()
    if len(code) != 10 or not code.isalnum():
        return _json_error("Enter the ten-character appeal code sent by the bot.", 400)
    if not user_id.isalnum() or not 10 <= len(user_id) <= 64:
        return _json_error("Enter your Stoat user ID.", 400)
    database = _database(request)
    database.appeal_privacy.prune()
    appeal = database.get_appeal_by_credentials(_code_hash(code), user_id)
    if appeal is None:
        return _json_error("The appeal code and user ID do not match an eligible case.", 404)
    return web.json_response({"appeal": _public_appeal(appeal)})


async def appeal_evidence_attachment(request: web.Request) -> web.Response:
    limited = _appeal_rate_limit(request)
    if limited is not None:
        return limited
    code = request.headers.get("X-Appeal-Code", "").strip().upper()
    user_id = request.headers.get("X-Stoat-User-ID", "").strip()
    if len(code) != 10 or not code.isalnum():
        return web.Response(status=404)
    if not user_id.isalnum() or not 10 <= len(user_id) <= 64:
        return web.Response(status=404)
    attachment = _database(request).get_appeal_evidence_attachment(
        _code_hash(code), user_id, _case_attachment_id(request)
    )
    return _case_attachment_response(attachment)


async def appeal_submit(request: web.Request) -> web.Response:
    limited = _appeal_rate_limit(request)
    if limited is not None:
        return limited
    try:
        payload, images = await _case_entry_form(request)
        privacy_version, ai_opt_in = _appeal_consent(request, payload)
    except web.HTTPException as exc:
        return _json_error(exc.reason, exc.status)
    code = str(payload.get("code", "")).strip().upper()
    user_id = str(payload.get("user_id", "")).strip()
    statement = str(payload.get("statement", "")).strip()
    if not 20 <= len(statement) <= 2000:
        return _json_error("Your appeal must be between 20 and 2,000 characters.", 400)
    database = _database(request)
    database.appeal_privacy.prune()
    appeal = database.get_appeal_by_credentials(_code_hash(code), user_id)
    if appeal is None:
        return _json_error("The appeal code and user ID do not match an eligible case.", 404)
    if appeal["status"] in {"approved", "denied"}:
        return _json_error("This appeal has already been decided.", 409)
    if appeal["status"] == "submitted":
        return _json_error(
            "This appeal is already submitted. Add follow-up information instead.",
            409,
        )
    database = _database(request)
    try:
        submitted = database.submit_appeal(appeal["id"], user_id, statement,
            privacy_version=privacy_version, ai_improvement_opt_in=bool(ai_opt_in))
    except ValueError as exc:
        return _json_error(str(exc), 400)
    if submitted is None:
        return _json_error("This appeal could not be submitted.", 409)
    message_id = database.get_latest_appeal_message_id(appeal["id"], "appellant")
    if message_id is not None:
        for filename, content_type, data in images:
            database.add_appeal_message_attachment(
                message_id, filename, content_type, data
            )
        submitted = database.get_appeal(appeal["id"])
    if appeal["status"] != "submitted" and submitted["case_kind"] == "moderation":
        server_id = str(submitted["server_id"])
        database.add_event(
            server_id=server_id,
            event_type="moderation_appeal_submitted",
            user_id=user_id,
            details={"case_reference": submitted["case_reference"]},
        )
        database.enqueue_dashboard_action(
            server_id,
            "send_appeal_submitted_log",
            user_id,
            {"appeal_id": submitted["id"]},
        )
    return web.json_response({"appeal": _public_appeal(submitted)})


async def appeal_respond(request: web.Request) -> web.Response:
    limited = _appeal_rate_limit(request)
    if limited is not None:
        return limited
    try:
        payload, images = await _case_entry_form(request)
        privacy_version, ai_opt_in = _appeal_consent(request, payload, follow_up=True)
    except web.HTTPException as exc:
        return _json_error(exc.reason, exc.status)
    code = str(payload.get("code", "")).strip().upper()
    user_id = str(payload.get("user_id", "")).strip()
    message = str(payload.get("message", payload.get("statement", ""))).strip()
    if not 3 <= len(message) <= 4000:
        return _json_error("Your response must be between 3 and 4,000 characters.", 400)
    database = _database(request)
    database.appeal_privacy.prune()
    appeal = database.get_appeal_by_credentials(_code_hash(code), user_id)
    if appeal is None:
        return _json_error("The appeal credentials are invalid.", 404)
    if appeal["status"] != "submitted":
        return _json_error("Only open appeals accept follow-up information.", 409)
    try:
        message_id = database.add_appeal_message(
            appeal["id"], "appellant", user_id, message,
            privacy_version=privacy_version, ai_improvement_opt_in=ai_opt_in,
        )
    except ValueError as exc:
        return _json_error(str(exc), 409)
    for filename, content_type, data in images:
        database.add_appeal_message_attachment(message_id, filename, content_type, data)
    database.add_event(
        server_id=str(appeal["server_id"]),
        event_type="moderation_appeal_response",
        user_id=user_id,
        details={"appeal_id": appeal["id"]},
    )
    updated = database.get_appeal(appeal["id"])
    return web.json_response({"appeal": _public_appeal(updated)})


async def appeal_message_attachment(request: web.Request) -> web.Response:
    limited = _appeal_rate_limit(request)
    if limited is not None:
        return limited
    code = request.headers.get("X-Appeal-Code", "").strip().upper()
    user_id = request.headers.get("X-Stoat-User-ID", "").strip()
    appeal = _database(request).get_appeal_by_credentials(_code_hash(code), user_id)
    if appeal is None:
        return web.Response(status=404)
    try:
        attachment_id = int(request.match_info["attachment_id"])
    except (KeyError, TypeError, ValueError):
        return web.Response(status=404)
    attachment = _database(request).get_appeal_message_attachment(
        attachment_id, appeal_id=int(appeal["id"])
    )
    return _case_attachment_response(attachment)


async def dashboard_appeal_message_attachment(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    try:
        appeal_id = int(request.match_info["appeal_id"])
        attachment_id = int(request.match_info["attachment_id"])
    except (KeyError, TypeError, ValueError):
        return web.Response(status=404)
    appeal = _database(request).get_appeal(appeal_id)
    if (
        appeal is None
        or appeal.get("case_kind") != "moderation"
        or str(appeal.get("server_id")) != server_id
    ):
        return web.Response(status=404)
    attachment = _database(request).get_appeal_message_attachment(
        attachment_id, appeal_id=appeal_id
    )
    return _case_attachment_response(attachment)


async def appeals(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    database = _database(request)
    return web.json_response({
        "appeals": database.list_dashboard_appeals(server_id),
        "dm_notifications": database.appeal_notification_preference(
            server_id, user_id
        ),
    })


async def appeal_notifications(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
    except ValueError:
        return _json_error("A JSON object is required.", 400)
    if not isinstance(payload, dict) or not isinstance(payload.get("enabled"), bool):
        return _json_error("Notification enabled must be true or false.", 400)
    enabled = _database(request).appeal_notification_preference(
        server_id, user_id, payload["enabled"]
    )
    return web.json_response({"dm_notifications": enabled})


async def review_appeal(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        appeal_id = int(request.match_info["appeal_id"])
        payload = await request.json()
    except (TypeError, ValueError, KeyError):
        return _json_error("A valid appeal and JSON request body are required.", 400)
    decision = str(payload.get("decision", "")).strip().lower()
    response = str(payload.get("response", "")).strip()
    if decision not in {"approved", "denied"}:
        return _json_error("Choose approved or denied.", 400)
    if not 3 <= len(response) <= 1000:
        return _json_error("The decision reason must be between 3 and 1,000 characters.", 400)
    database = _database(request)
    current = database.get_appeal(appeal_id)
    if (
        current is None
        or current["case_kind"] != "moderation"
        or current["server_id"] != server_id
    ):
        return _json_error("Appeal not found.", 404)
    reviewed = database.review_appeal(appeal_id, user_id, decision, response)
    if reviewed is None:
        return _json_error("Only submitted, undecided appeals can be reviewed.", 409)
    database.enqueue_dashboard_action(
        server_id,
        "resolve_appeal",
        user_id,
        {"appeal_id": appeal_id, "decision": decision},
    )
    return web.json_response({"appeal": reviewed})


async def request_appeal_information(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        appeal_id = int(request.match_info["appeal_id"])
        payload = await request.json()
    except (KeyError, TypeError, ValueError):
        return _json_error("A valid appeal and JSON request body are required.", 400)
    prompt = str(payload.get("prompt", "")).strip()
    if not 3 <= len(prompt) <= 2000:
        return _json_error("The information request must be between 3 and 2,000 characters.", 400)
    appeal = _database(request).request_appeal_information(
        server_id, appeal_id, user_id, prompt
    )
    if appeal is None:
        return _json_error("Open appeal not found.", 404)
    return web.json_response({"appeal": appeal}, status=202)


async def settings(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    database = _database(request)
    await _prune_confirmed_deleted_exempt_channels(database, server_id)
    return web.json_response(
        database.get_dashboard_settings(server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS)
    )


async def reaction_roles_api(request: web.Request) -> web.Response:
    from reaction_roles import panel_embed

    server_id, user_id = _session(request)
    store = _database(request).reaction_roles
    if request.method == "GET":
        directory = store.directory(server_id)
        if directory is None:
            store.refresh_directory(server_id, user_id)
        return web.json_response({"panels":store.panels(server_id), "directory":directory})
    _require_csrf(request)
    try:
        payload = await request.json()
        if not isinstance(payload,dict):
            raise ValueError("A JSON object is required.")
        operation = payload.get("operation", "save")
        if operation == "directory":
            store.refresh_directory(server_id,user_id)
            return web.json_response({"queued":True},status=202)
        if operation == "preview":
            config = store.validate(server_id,payload,draft=True)
            publish_error = None
            try:
                store.validate(server_id,payload)
            except ValueError as exc:
                publish_error = str(exc)
            return web.json_response({"embed":panel_embed(config),"publish_error":publish_error})
        panel_id = request.match_info.get("panel_id")
        if operation == "save":
            result=store.save(server_id,user_id,payload,panel_id)
        else:
            if not panel_id: raise ValueError("Choose a panel first.")
            cleanup=payload.get("cleanup",False)
            if not isinstance(cleanup,bool): raise ValueError("Choose whether to remove panel grants.")
            result=store.request(server_id,user_id,panel_id,operation,payload.get("revision"),cleanup)
        _database(request).add_event(server_id=server_id,event_type="reaction_role_panel_updated",actor_id=user_id,
            details={"panel_id":result["id"],"operation":operation})
        return web.json_response({"panel":result},status=202)
    except LookupError as exc:
        return _json_error(str(exc),404)
    except (ValueError,TypeError) as exc:
        return _json_error(str(exc),400)


async def application_settings(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    database = _database(request)
    store = database.applications
    if request.method == "POST":
        _require_csrf(request)
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                raise ValueError("A JSON object is required.")
            config = store.save_settings(server_id, user_id, payload)
        except (ValueError, TypeError) as exc:
            return _json_error(str(exc), 400)
    else:
        config = store.settings(server_id)
    config.pop("gate", None)
    directory = database.get_dashboard_settings(server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS)
    return web.json_response({"settings": config, "dm_notifications": store.notification_preference(server_id, user_id),
                              "channels": directory["channels"], "categories": directory["categories"]})


async def application_preview(request: web.Request) -> web.Response:
    from application_embeds import privacy_embed, question_embeds, submission_embed, validate_appearance
    from applications import ApplicationStore

    _require_csrf(request)
    server_id, _user_id = _session(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("A JSON object is required.")
        _enabled, intro, questions = ApplicationStore.validate_form(payload, draft=True)
        form = {"questions": questions, "introduction": intro,
                "appearance": validate_appearance(payload.get("appearance", {}))}
        position = payload.get("position", 0)
        if not isinstance(position, int) or isinstance(position, bool) or position < 0:
            raise ValueError("Choose a question to preview.")
        server_name = _database(request).get_dashboard_server_name(server_id) or "Your server"
        if payload.get("stage") == "privacy":
            embeds = [privacy_embed(form, server_name, "https://modstoat.site/privacy#applications")]
        elif payload.get("stage") == "submitted":
            embeds = [submission_embed(form, server_name, "14 days after submission")]
        elif questions and position < len(questions):
            embeds = question_embeds(form, server_name, position)
        else:
            embeds = []
        return web.json_response({"embeds": embeds, "server_name": server_name})
    except (ValueError, TypeError) as exc:
        return _json_error(str(exc), 400)


async def application_notifications(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
    except ValueError:
        return _json_error("A JSON object is required.", 400)
    if not isinstance(payload, dict) or not isinstance(payload.get("enabled"), bool):
        return _json_error("Notification enabled must be true or false.", 400)
    enabled = _database(request).applications.notification_preference(server_id, user_id, payload["enabled"])
    return web.json_response({"dm_notifications": enabled})


async def list_applications(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    store = _database(request).applications
    apps = store.list(server_id, before=request.query.get("before"))
    for app in apps:
        identity = _database(request).get_recorded_user_identity(app["user_id"], server_id) or {}
        app["username"] = identity.get("full_username") or app["user_id"]
    return web.json_response({"applications": apps, "next_cursor": apps[-1]["id"] if len(apps) == 100 else None})


async def application_detail(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    app = _database(request).applications.get(request.match_info["application_id"], server_id)
    if app is None:
        return _json_error("Application not found.", 404)
    return web.json_response({"application": app})


async def review_application(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("A JSON object is required.")
        reason = payload.get("reason", "")
        if not isinstance(reason, str):
            raise ValueError("The reason must be text.")
        app = _database(request).applications.decide(server_id, request.match_info["application_id"],
            user_id, str(payload.get("decision", "")), reason)
    except (ValueError, TypeError) as exc:
        return _json_error(str(exc), 409)
    return web.json_response({"application": app}, status=202)


async def retry_application(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        _database(request).applications.retry(server_id, request.match_info["application_id"], user_id)
    except ValueError as exc:
        return _json_error(str(exc), 409)
    return web.json_response({"queued": True}, status=202)


async def moderation_policy(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    return web.json_response(
        {"policy": _database(request).get_moderation_policy_studio(
            server_id, DEFAULT_THRESHOLD
        )}
    )


async def update_moderation_policy(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
        default_threshold = float(payload.get("default_threshold", DEFAULT_THRESHOLD))
        policies = payload.get("policies")
        if not isinstance(policies, list):
            raise ValueError("Per-category policies must be a list.")
        saved = _database(request).save_moderation_policy_studio(
            server_id,
            str(payload.get("mode", "enforce")),
            default_threshold,
            policies,
            user_id,
        )
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc), 400)
    _database(request).add_event(
        server_id=server_id,
        event_type="moderation_policy_updated",
        actor_id=user_id,
        details={"mode": saved["mode"]},
    )
    return web.json_response({"policy": saved})


async def onboarding_status(request: web.Request) -> web.Response:
    server_id, user_id = _session(request)
    return web.json_response(
        {"onboarding": _database(request).get_onboarding_state(server_id, user_id)}
    )


async def update_onboarding(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
        state = _database(request).save_onboarding_state(
            server_id,
            user_id,
            int(payload.get("current_step", 0)),
            complete=bool(payload.get("complete", False)),
            dismissed=bool(payload.get("dismissed", False)),
            reopen=bool(payload.get("reopen", False)),
        )
    except (TypeError, ValueError):
        return _json_error("A valid onboarding step is required.", 400)
    return web.json_response({"onboarding": state})


async def create_global_report_access(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise TypeError
        target_user_id = _normalize_stoat_user_id(payload.get("target_user_id"))
    except (TypeError, ValueError) as exc:
        return _json_error(
            str(exc) if isinstance(exc, ValueError) else "A JSON request body is required.",
            400,
        )
    if target_user_id == GLOBAL_COMMAND_OWNER_ID:
        return _json_error("The global owner cannot be reported for a global ban.", 400)
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=60)
    _database(request).create_report_token(
        _token_hash(token),
        server_id,
        user_id,
        expires_at.isoformat(timespec="seconds"),
        report_scope="global",
    )
    report_url = (
        f"{ALLOWED_ORIGIN.rstrip('/')}/report?token={quote(token, safe='')}"
        f"&target={quote(target_user_id, safe='')}"
    )
    return web.json_response(
        {
            "report_url": report_url,
            "expires_at": expires_at.isoformat(timespec="seconds"),
        },
        status=201,
    )


async def local_reports(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    database = _database(request)
    return web.json_response(
        {
            "reports": database.list_local_reports(server_id),
            "settings": database.get_local_report_settings(server_id),
        }
    )


async def local_report_detail(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    try:
        report_id = int(request.match_info["report_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Report not found.", 404)
    report = _database(request).get_local_report(server_id, report_id)
    if report is None:
        return _json_error("Report not found.", 404)
    return web.json_response({"report": report})


async def update_local_report_settings(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    database = _database(request)
    try:
        payload = await request.json()
        enabled = bool(payload.get("enabled", False))
        channel_id = str(payload.get("channel_id") or "").strip() or None
        valid_channels = {
            channel["channel_id"]
            for channel in database.get_dashboard_settings(
                server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS
            )["channels"]
        }
        if enabled and channel_id not in valid_channels:
            raise ValueError("Choose an instruction embed channel from this server.")
        saved = database.save_local_report_settings(
            server_id,
            enabled=enabled,
            channel_id=channel_id,
            anonymous_allowed=bool(payload.get("anonymous_allowed", True)),
            updated_by=user_id,
        )
        action_id = None
        if bool(payload.get("post_instructions")):
            if not enabled or channel_id is None:
                raise ValueError(
                    "Enable server reporting and choose an instruction embed channel first."
                )
            action_id = database.enqueue_dashboard_action(
                server_id,
                "post_local_report_instructions",
                user_id,
                {"channel_id": channel_id},
            )
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc), 400)
    database.add_event(
        server_id=server_id,
        event_type="server_reporting_updated",
        actor_id=user_id,
        channel_id=channel_id,
        details={"enabled": enabled, "anonymous_allowed": saved["anonymous_allowed"]},
    )
    return web.json_response({"settings": saved, "action_id": action_id})


async def update_local_report(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        report_id = int(request.match_info["report_id"])
        payload = await request.json()
    except (KeyError, TypeError, ValueError):
        return _json_error("A valid report and JSON request body are required.", 400)
    action = str(payload.get("action", "")).strip().lower()
    note = str(payload.get("note", "")).strip()
    if not 3 <= len(note) <= 4000:
        return _json_error("Add a note between 3 and 4,000 characters.", 400)
    database = _database(request)
    if action == "request_information":
        result = database.request_local_report_information(
            server_id, report_id, user_id, note
        )
        if result is None:
            return _json_error("Open report not found.", 404)
        status_code = 202
    elif action in {"resolved", "dismissed"}:
        result = database.review_local_report(
            server_id, report_id, action, note, user_id
        )
        if result is None:
            return _json_error("Open report not found.", 404)
        status_code = 202
    else:
        return _json_error("Choose request_information, resolved, or dismissed.", 400)
    return web.json_response(
        {"report": database.get_local_report(server_id, report_id), "action_id": result},
        status=status_code,
    )


async def local_report_attachment(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    try:
        report_id = int(request.match_info["report_id"])
        attachment_id = int(request.match_info["attachment_id"])
    except (KeyError, TypeError, ValueError):
        return web.Response(status=404)
    if _database(request).get_local_report(server_id, report_id) is None:
        return web.Response(status=404)
    attachment = _database(request).get_report_attachment(
        attachment_id, report_id=report_id
    )
    if attachment is None:
        return web.Response(status=404)
    return web.Response(
        body=attachment["data"],
        content_type=attachment["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{attachment["filename"]}"'},
    )


def _validate_automation_payload(payload: dict[str, Any]) -> tuple[str, str, str | None, str, dict[str, Any], list[dict[str, Any]], str, list[dict[str, Any]], int]:
    name = str(payload.get("name", "")).strip()[:80]
    trigger_type = str(payload.get("trigger_type", ""))
    trigger_value = str(payload.get("trigger_value", "")).strip()[:200] or None
    action_type = str(payload.get("action_type", ""))
    action_config = payload.get("action_config") or {}
    raw_conditions = payload.get("conditions") or []
    condition_mode = str(payload.get("condition_mode", "all"))
    raw_actions = payload.get("actions")
    priority = max(1, min(int(payload.get("priority", 100)), 1000))
    if len(name) < 2:
        raise ValueError("Automation name must be at least two characters.")
    if trigger_type not in {"every_message", "keyword", "contains_link", "has_attachment"}:
        raise ValueError("Choose a supported automation trigger.")
    if trigger_type == "keyword" and not trigger_value:
        raise ValueError("Keyword automations require a keyword.")
    supported_actions = {"delete_message", "warn", "timeout", "send_reply", "send_log"}
    if action_type not in supported_actions:
        raise ValueError("Choose a supported automation action.")
    if not isinstance(action_config, dict):
        raise ValueError("Automation action settings must be an object.")
    if condition_mode not in {"all", "any"}:
        raise ValueError("Condition mode must be all or any.")
    if not isinstance(raw_conditions, list) or len(raw_conditions) > 10:
        raise ValueError("Automations support up to ten additional conditions.")
    condition_types = {
        "username_contains", "username_equals", "nickname_contains", "nickname_equals",
        "channel_is", "role_has", "message_contains", "message_starts_with",
        "message_ends_with", "message_length_min", "message_length_max",
        "mention_count_min", "account_age_days_max", "has_embed",
    }
    conditions: list[dict[str, Any]] = []
    for raw in raw_conditions:
        if not isinstance(raw, dict) or str(raw.get("type", "")) not in condition_types:
            raise ValueError("Choose a supported automation condition.")
        condition_type = str(raw["type"])
        value = str(raw.get("value", "")).strip()[:200]
        if condition_type != "has_embed" and not value:
            raise ValueError("Every automation condition requires a value.")
        if condition_type in {"message_length_min", "message_length_max", "mention_count_min", "account_age_days_max"}:
            number = int(value)
            if number < 0 or number > 100000:
                raise ValueError("Numeric automation conditions are outside the supported range.")
            value = str(number)
        conditions.append({"type": condition_type, "value": value})
    if raw_actions is None:
        raw_actions = [{"type": action_type, "config": action_config}]
    if not isinstance(raw_actions, list) or not 1 <= len(raw_actions) <= 8:
        raise ValueError("Automations require between one and eight ordered actions.")
    actions: list[dict[str, Any]] = []
    for raw_action in raw_actions:
        if not isinstance(raw_action, dict):
            raise ValueError("Automation actions must be objects.")
        current_type = str(raw_action.get("type", ""))
        current_config = raw_action.get("config") or {}
        if current_type not in supported_actions or not isinstance(current_config, dict):
            raise ValueError("Choose a supported automation action.")
        if current_type == "timeout":
            duration = int(current_config.get("duration_seconds", 3600))
            if not 60 <= duration <= 2419200:
                raise ValueError("Timeout must be between one minute and four weeks.")
            current_config = {**current_config, "duration_seconds": duration}
        if current_type in {"warn", "send_reply", "send_log"}:
            message = str(current_config.get("message", "")).strip()[:1000]
            if len(message) < 2:
                raise ValueError("This automation action requires a message or reason.")
            current_config = {**current_config, "message": message}
        actions.append({"type": current_type, "config": current_config})
    action_type = str(actions[0]["type"])
    action_config = dict(actions[0]["config"])
    return name, trigger_type, trigger_value, action_type, action_config, conditions, condition_mode, actions, priority


async def automations(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    return web.json_response({"automations": _database(request).list_automation_rules(server_id)})


async def create_automation(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        values = _validate_automation_payload(await request.json())
    except (ValueError, TypeError) as exc:
        return _json_error(str(exc), 400)
    name, trigger_type, trigger_value, action_type, action_config, conditions, condition_mode, actions, priority = values
    rule = _database(request).create_automation_rule(
        server_id, name, trigger_type, trigger_value, action_type, action_config,
        user_id, conditions, condition_mode, actions, priority,
    )
    _database(request).add_event(
        server_id=server_id, event_type="automation_created", actor_id=user_id,
        details={"automation_id": rule["id"], "name": rule["name"]},
    )
    return web.json_response({"automation": rule}, status=201)


async def update_automation(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    rule_id = int(request.match_info["rule_id"])
    payload = await request.json()
    current = next((item for item in _database(request).list_automation_rules(server_id) if item["id"] == rule_id), None)
    if current is None:
        return _json_error("Automation not found.", 404)
    merged = {**current, **payload}
    try:
        name, trigger_type, trigger_value, action_type, action_config, conditions, condition_mode, actions, priority = _validate_automation_payload(merged)
    except (ValueError, TypeError) as exc:
        return _json_error(str(exc), 400)
    updates = {
        "name": name, "trigger_type": trigger_type, "trigger_value": trigger_value,
        "action_type": action_type, "action_config": action_config,
        "conditions": conditions, "condition_mode": condition_mode,
        "actions": actions, "priority": priority,
        "enabled": bool(payload.get("enabled", current["enabled"])),
    }
    _database(request).update_automation_rule(server_id, rule_id, updates)
    _database(request).add_event(
        server_id=server_id, event_type="automation_updated", actor_id=user_id,
        details={"automation_id": rule_id, "name": name},
    )
    return web.json_response({"automation": next(item for item in _database(request).list_automation_rules(server_id) if item["id"] == rule_id)})


async def delete_automation(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    rule_id = int(request.match_info["rule_id"])
    if not _database(request).delete_automation_rule(server_id, rule_id):
        return _json_error("Automation not found.", 404)
    _database(request).add_event(
        server_id=server_id, event_type="automation_deleted", actor_id=user_id,
        details={"automation_id": rule_id},
    )
    return web.json_response({"ok": True})


async def clone_automation(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        rule_id = int(request.match_info["rule_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Automation not found.", 404)
    database = _database(request)
    current = next(
        (rule for rule in database.list_automation_rules(server_id) if rule["id"] == rule_id),
        None,
    )
    if current is None:
        return _json_error("Automation not found.", 404)
    clone = database.create_automation_rule(
        server_id,
        f"Copy of {current['name']}"[:80],
        current["trigger_type"],
        current.get("trigger_value"),
        current["action_type"],
        current["action_config"],
        user_id,
        current["conditions"],
        current["condition_mode"],
        current["actions"],
        int(current.get("priority") or 100),
    )
    return web.json_response({"automation": clone}, status=201)


def _automation_simulation(payload: dict[str, Any], sample: dict[str, Any]) -> dict[str, Any]:
    content = str(sample.get("message", ""))
    lower = content.casefold()
    trigger_type = str(payload["trigger_type"])
    trigger_value = str(payload.get("trigger_value") or "").casefold()
    trigger_passed = {
        "every_message": True,
        "keyword": trigger_value in lower,
        "contains_link": bool(re.search(r"https?://|www\\.", content, re.IGNORECASE)),
        "has_attachment": bool(sample.get("has_attachment")),
    }.get(trigger_type, False)
    explanations: list[dict[str, Any]] = []
    roles = {str(role) for role in sample.get("role_ids", [])}
    for condition in payload.get("conditions", []):
        condition_type = str(condition.get("type"))
        value = str(condition.get("value", ""))
        folded = value.casefold()
        if condition_type == "username_contains":
            passed = folded in str(sample.get("username", "")).casefold()
        elif condition_type == "username_equals":
            passed = folded == str(sample.get("username", "")).casefold()
        elif condition_type == "nickname_contains":
            passed = folded in str(sample.get("nickname", "")).casefold()
        elif condition_type == "nickname_equals":
            passed = folded == str(sample.get("nickname", "")).casefold()
        elif condition_type == "channel_is":
            passed = value == str(sample.get("channel_id", ""))
        elif condition_type == "role_has":
            passed = value in roles
        elif condition_type == "message_contains":
            passed = folded in lower
        elif condition_type == "message_starts_with":
            passed = lower.startswith(folded)
        elif condition_type == "message_ends_with":
            passed = lower.endswith(folded)
        elif condition_type == "message_length_min":
            passed = len(content) >= int(value or 0)
        elif condition_type == "message_length_max":
            passed = len(content) <= int(value or 0)
        elif condition_type == "mention_count_min":
            passed = int(sample.get("mention_count", 0)) >= int(value or 0)
        elif condition_type == "account_age_days_max":
            passed = int(sample.get("account_age_days", 0)) <= int(value or 0)
        elif condition_type == "has_embed":
            passed = bool(sample.get("has_embed"))
        else:
            passed = False
        explanations.append(
            {"type": condition_type, "value": value, "passed": passed,
             "explanation": f"{condition_type.replace('_', ' ')} {'matched' if passed else 'did not match'}"}
        )
    mode = str(payload.get("condition_mode", "all"))
    conditions_passed = (all(item["passed"] for item in explanations) if mode == "all" else any(item["passed"] for item in explanations)) if explanations else True
    matched = trigger_passed and conditions_passed
    return {
        "matched": matched,
        "trigger": {"passed": trigger_passed, "type": trigger_type},
        "conditions": explanations,
        "planned_actions": payload.get("actions", []) if matched else [],
        "dry_run": True,
        "message": "No actions will be sent. This is a dry run.",
    }


async def simulate_automation(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    try:
        payload = await request.json()
        rule_payload = payload.get("automation") or payload
        sample = payload.get("sample") or {}
        values = _validate_automation_payload(rule_payload)
        normalized = {
            "name": values[0], "trigger_type": values[1], "trigger_value": values[2],
            "action_type": values[3], "action_config": values[4],
            "conditions": values[5], "condition_mode": values[6],
            "actions": values[7], "priority": values[8],
        }
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc), 400)
    _ = server_id
    return web.json_response({"simulation": _automation_simulation(normalized, sample)})


async def leaderboards(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    period = request.query.get("period", "day")
    scope = request.query.get("scope", "server")
    metric = request.query.get("metric", "activity")
    try:
        if scope == "server":
            return _json_error("Individual activity leaderboards have been removed.", 410)
        elif scope == "global":
            entries = _database(request).get_global_leaderboard(metric, period)
        else:
            raise ValueError("scope must be server or global")
    except ValueError as exc:
        return _json_error(str(exc), 400)
    return web.json_response({"scope": scope, "metric": metric, "period": period, "entries": entries})


def _normalize_poll_options(raw_options: Any) -> list[dict[str, str]]:
    if not isinstance(raw_options, list) or not 2 <= len(raw_options) <= 8:
        raise ValueError("Polls require between two and eight options.")
    default_emojis = ["🍎", "🍐", "🍊", "🍋", "🍉", "🍇", "🍓", "🥝"]
    options: list[dict[str, str]] = []
    for index, raw in enumerate(raw_options):
        if isinstance(raw, dict):
            label = str(raw.get("label", "")).strip()[:80]
            emoji = str(raw.get("emoji", "")).strip()[:80] or default_emojis[index]
        else:
            label = str(raw).strip()[:80]
            emoji = default_emojis[index]
        if not label or not emoji:
            raise ValueError("Every poll option needs a label and emoji.")
        options.append({"label": label, "emoji": emoji})
    if len({option["emoji"] for option in options}) != len(options):
        raise ValueError("Every poll option must use a different emoji.")
    return options


async def create_poll(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("A poll request must be an object.")
        question = str(payload.get("question", "")).strip()[:500]
        channel_id = str(payload.get("channel_id", "")).strip()
        options = _normalize_poll_options(payload.get("options"))
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc), 400)
    multiple_choice = bool(payload.get("multiple_choice", False))
    anonymous = bool(payload.get("anonymous", False))
    required_role_id = str(payload.get("required_role_id") or "").strip() or None
    try:
        quorum = int(payload.get("quorum", 0))
        reminder_minutes = (
            int(payload["reminder_minutes"])
            if payload.get("reminder_minutes") not in {None, ""}
            else None
        )
    except (TypeError, ValueError):
        return _json_error("Quorum and reminder values must be whole numbers.", 400)
    now = datetime.now(timezone.utc)
    try:
        scheduled_for = datetime.fromisoformat(str(payload["scheduled_for"])).astimezone(timezone.utc) if payload.get("scheduled_for") else now
        closes_at = datetime.fromisoformat(str(payload["closes_at"])).astimezone(timezone.utc) if payload.get("closes_at") else None
    except (ValueError, TypeError):
        return _json_error("Poll schedule and closing time must be valid dates.", 400)
    dashboard_settings = _database(request).get_dashboard_settings(
        server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS
    )
    valid_channels = {item["channel_id"] for item in dashboard_settings["channels"]}
    valid_roles = {item["role_id"] for item in dashboard_settings["roles"]}
    if (
        len(question) < 3 or not 2 <= len(options) <= 8
        or channel_id not in valid_channels
        or len({item["emoji"] for item in options}) != len(options)
        or (closes_at is not None and closes_at <= scheduled_for)
        or (required_role_id is not None and required_role_id not in valid_roles)
        or not 0 <= quorum <= 100000
        or reminder_minutes not in {None, 5, 15, 30, 60, 1440}
        or (reminder_minutes is not None and closes_at is None)
    ):
        return _json_error("Choose a channel, a question, and between two and eight options.", 400)
    scheduled_iso = scheduled_for.isoformat(timespec="seconds")
    closes_iso = closes_at.isoformat(timespec="seconds") if closes_at else None
    poll_id = _database(request).create_poll(
        server_id, channel_id, question, options, user_id, closes_iso,
        multiple_choice=multiple_choice,
        scheduled_for=scheduled_iso if scheduled_for > now else None,
        anonymous=anonymous,
        required_role_id=required_role_id,
        quorum=quorum,
        reminder_minutes=reminder_minutes,
    )
    action_id = _database(request).enqueue_dashboard_action(
        server_id, "publish_poll", user_id, {"poll_id": poll_id},
        not_before=scheduled_iso if scheduled_for > now else None,
    )
    if closes_iso:
        _database(request).enqueue_dashboard_action(
            server_id, "close_poll", user_id, {"poll_id": poll_id},
            not_before=closes_iso,
        )
        if reminder_minutes is not None:
            reminder_at = closes_at - timedelta(minutes=reminder_minutes)
            if reminder_at > max(now, scheduled_for):
                _database(request).enqueue_dashboard_action(
                    server_id,
                    "send_poll_reminder",
                    user_id,
                    {"poll_id": poll_id},
                    not_before=reminder_at.isoformat(timespec="seconds"),
                )
    poll = _database(request).get_poll(poll_id)
    if poll is not None:
        poll.pop("votes", None)
    return web.json_response(
        {"queued": True, "action_id": action_id, "poll": poll},
        status=202,
    )


async def polls(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    try:
        page = max(1, int(request.query.get("page", "1")))
        page_size = max(1, min(20, int(request.query.get("page_size", "6"))))
    except (TypeError, ValueError):
        return _json_error("Poll page and page size must be whole numbers.", 400)
    database = _database(request)
    total_items = database.count_polls(server_id)
    total_pages = max(1, (total_items + page_size - 1) // page_size)
    page = min(page, total_pages)
    items = database.list_polls(
        server_id, limit=page_size, offset=(page - 1) * page_size
    )
    for item in items:
        item.pop("votes", None)
    return web.json_response(
        {
            "polls": items,
            "templates": database.list_poll_templates(server_id),
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": total_pages,
        }
    )


async def close_poll_now(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        poll_id = int(request.match_info["poll_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Poll not found.", 404)
    poll = _database(request).get_poll(poll_id)
    if poll is None or poll["server_id"] != server_id:
        return _json_error("Poll not found.", 404)
    action_id = _database(request).enqueue_dashboard_action(
        server_id, "close_poll", user_id, {"poll_id": poll_id}
    )
    return web.json_response({"queued": True, "action_id": action_id}, status=202)


async def save_poll_template(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            raise ValueError("A poll template request must be an object.")
        name = str(payload.get("name", "")).strip()[:80]
        question = str(payload.get("question", "")).strip()[:500]
        options = _normalize_poll_options(payload.get("options"))
        required_role_id = str(payload.get("required_role_id") or "").strip() or None
        quorum = int(payload.get("quorum", 0))
        reminder_minutes = (
            int(payload["reminder_minutes"])
            if payload.get("reminder_minutes") not in {None, ""}
            else None
        )
        valid_roles = {
            role["role_id"]
            for role in _database(request).get_dashboard_settings(
                server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS
            )["roles"]
        }
        if len(name) < 2:
            raise ValueError("Template names must be at least two characters.")
        if len(question) < 3:
            raise ValueError("Poll questions must be at least three characters.")
        if required_role_id is not None and required_role_id not in valid_roles:
            raise ValueError("The selected voting role is not in this server.")
        if not 0 <= quorum <= 100000:
            raise ValueError("Poll quorum is outside the supported range.")
        if reminder_minutes not in {None, 5, 15, 30, 60, 1440}:
            raise ValueError("Choose a supported poll reminder.")
        template = _database(request).save_poll_template(
            server_id,
            name,
            question,
            options,
            user_id,
            multiple_choice=bool(payload.get("multiple_choice", False)),
            anonymous=bool(payload.get("anonymous", False)),
            required_role_id=required_role_id,
            quorum=quorum,
            reminder_minutes=reminder_minutes,
        )
    except (TypeError, ValueError) as exc:
        return _json_error(str(exc), 400)
    return web.json_response({"template": template}, status=201)


async def delete_poll_template(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, _user_id = _session(request)
    try:
        template_id = int(request.match_info["template_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Poll template not found.", 404)
    if not _database(request).delete_poll_template(server_id, template_id):
        return _json_error("Poll template not found.", 404)
    return web.json_response({"ok": True})


async def export_poll_results(request: web.Request) -> web.Response:
    server_id, _user_id = _session(request)
    try:
        poll_id = int(request.match_info["poll_id"])
    except (KeyError, TypeError, ValueError):
        return _json_error("Poll not found.", 404)
    poll = _database(request).get_poll(poll_id)
    if poll is None or poll["server_id"] != server_id:
        return _json_error("Poll not found.", 404)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Option", "Emoji", "Votes"])
    for option in poll["options"]:
        writer.writerow([
            option.get("label", ""), option.get("emoji", ""),
            poll["vote_counts"].get(str(option.get("emoji", "")), 0),
        ])
    writer.writerow([])
    writer.writerow(["Total voters", poll["total_voters"]])
    writer.writerow(["Quorum", poll.get("quorum", 0)])
    writer.writerow(["Quorum met", "yes" if poll["quorum_met"] else "no"])
    return web.Response(
        text=output.getvalue(),
        content_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="poll-{poll_id}-results.csv"'},
    )


async def delete_poll(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        poll_id = int(request.match_info["poll_id"])
    except (TypeError, ValueError):
        return _json_error("Poll not found.", 404)
    database = _database(request)
    poll = database.delete_poll(server_id, poll_id)
    if poll is None:
        return _json_error("Poll not found.", 404)
    action_id = None
    if poll.get("message_id"):
        action_id = database.enqueue_dashboard_action(
            server_id,
            "delete_poll_message",
            user_id,
            {
                "poll_id": poll_id,
                "channel_id": poll["channel_id"],
                "message_id": poll["message_id"],
            },
        )
    database.add_event(
        server_id=server_id,
        event_type="poll_deleted",
        actor_id=user_id,
        message_id=poll.get("message_id"),
        channel_id=poll["channel_id"],
        details={"poll_id": poll_id, "question": poll["question"]},
    )
    return web.json_response({"ok": True, "action_id": action_id})


async def update_settings(request: web.Request) -> web.Response:
    _require_csrf(request)
    server_id, user_id = _session(request)
    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    database = _database(request)
    submitted_exempt_channels = payload.get("exempt_channels")
    removed_deleted_channel_ids = await _prune_confirmed_deleted_exempt_channels(
        database,
        server_id,
        additional_channel_ids=(
            submitted_exempt_channels
            if isinstance(submitted_exempt_channels, list)
            and len(submitted_exempt_channels) <= 100
            else None
        ),
    )
    current_settings = database.get_dashboard_settings(
        server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS
    )
    # Older dashboards still send this retired field.
    payload.pop("low_threshold_confirmation", None)
    normalized: dict[str, Any] = {}
    if "locale" in payload:
        locale = str(payload["locale"]).strip().casefold()
        if locale not in {"en", "fr", "pt", "es"}:
            return _json_error(
                "Language must be English, French, Portuguese, or Spanish.", 400
            )
        normalized["locale"] = locale
    boolean_setters = {
        "join_protection": database.set_join_protection,
        "captcha_all_members": database.set_captcha_all_members,
        "nickname_protection": database.set_nickname_protection,
        "link_protection": database.set_link_protection,
        "allow_gifs": database.set_allow_gifs,
        "spam_detection": database.set_spam_detection,
        "image_scanning": database.set_image_scanning,
        "ai_thinking": database.set_ai_thinking,
        "moderator_exemption": database.set_moderator_exemption,
        "public_stats": database.set_public_stats_enabled,
    }
    for key in boolean_setters:
        if key in payload:
            if not isinstance(payload[key], bool):
                return _json_error(f"{key} must be true or false.", 400)
            normalized[key] = payload[key]

    if "join_limits" in payload:
        try:
            normalized["join_limits"] = normalize_join_limits(payload["join_limits"])
        except ValueError as error:
            return _json_error(str(error), 400)

    if "spam_settings" in payload:
        spam_settings = payload["spam_settings"]
        expected_keys = set(DEFAULT_SPAM_SETTINGS)
        if not isinstance(spam_settings, dict) or set(spam_settings) != expected_keys:
            return _json_error("Every spam-protection setting is required.", 400)
        spam_labels = {
            "repeat_count": "Repeated-message count",
            "repeat_window_seconds": "Repeated-message window",
            "rapid_count": "Rapid-message count",
            "rapid_window_seconds": "Rapid-message window",
            "score_threshold": "Spam-score threshold",
            "score_half_life_seconds": "Spam-score memory",
            "mass_mention_limit": "Mass-mention limit",
            "timeout_seconds": "Spam timeout",
        }
        normalized_spam: dict[str, int | float] = {}
        for key, limits in SPAM_SETTING_LIMITS.items():
            value = spam_settings[key]
            if isinstance(value, bool):
                return _json_error(f"{spam_labels[key]} must be a number.", 400)
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return _json_error(f"{spam_labels[key]} must be a number.", 400)
            minimum, maximum = limits
            if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
                return _json_error(
                    f"{spam_labels[key]} must be between {minimum:g} and {maximum:g}.",
                    400,
                )
            if key in SPAM_INTEGER_SETTINGS and not numeric.is_integer():
                return _json_error(f"{spam_labels[key]} must be a whole number.", 400)
            normalized_spam[key] = (
                int(numeric) if key in SPAM_INTEGER_SETTINGS else numeric
            )
        normalized["spam_settings"] = normalized_spam

    if "moderation_threshold" in payload:
        try:
            threshold = float(payload["moderation_threshold"])
        except (TypeError, ValueError):
            return _json_error("Moderation threshold must be a number.", 400)
        if not 0 <= threshold <= 1:
            return _json_error("Moderation threshold must be between 0 and 1.", 400)
        normalized["moderation_threshold"] = threshold

    if "retention_days" in payload:
        return _json_error("Server history retention settings have been removed. Refresh the dashboard.", 400)

    if "warning_expiry_days" in payload:
        warning_expiry_days = payload["warning_expiry_days"]
        if warning_expiry_days is not None:
            try:
                warning_expiry_days = int(warning_expiry_days)
            except (TypeError, ValueError):
                return _json_error("Warning expiry must be Never, 7, 30, 90, 180, or 365 days.", 400)
            if warning_expiry_days not in {7, 30, 90, 180, 365}:
                return _json_error("Warning expiry must be Never, 7, 30, 90, 180, or 365 days.", 400)
        normalized["warning_expiry_days"] = warning_expiry_days

    if "log_channel_id" in payload:
        channel_id = payload["log_channel_id"]
        valid_channels = {
            channel["channel_id"] for channel in current_settings["channels"]
        }
        if not isinstance(channel_id, str) or channel_id not in valid_channels:
            return _json_error("Choose a text channel from this server.", 400)
        normalized["log_channel_id"] = channel_id

    if "warning_policy" in payload:
        policy = payload["warning_policy"]
        try:
            timeout_count = int(policy["timeout"])
            kick_count = int(policy["kick"])
            ban_count = int(policy["ban"])
        except (KeyError, TypeError, ValueError):
            return _json_error("Warning thresholds must be whole numbers.", 400)
        if not 0 < timeout_count < kick_count < ban_count:
            return _json_error(
                "Warning thresholds must be positive and increase from timeout to kick to ban.",
                400,
            )
        normalized_policy = {
            "timeout": timeout_count,
            "kick": kick_count,
            "ban": ban_count,
        }
        normalized["warning_policy"] = normalized_policy

    if "penalty_rules" in payload:
        rules = payload["penalty_rules"]
        if not isinstance(rules, list):
            return _json_error("Penalty rules must be a list.", 400)
        try:
            # Validate without committing; the database method repeats validation.
            normalized_rules: list[dict[str, Any]] = []
            seen_thresholds: set[int] = set()
            if not 1 <= len(rules) <= 12:
                raise ValueError("Configure between one and twelve penalty stages.")
            for rule in rules:
                threshold = int(rule["threshold"])
                action = str(rule["action"])
                duration = rule.get("duration_seconds")
                duration_seconds = int(duration) if duration is not None else None
                if threshold < 1 or threshold > 100 or threshold in seen_thresholds:
                    raise ValueError("Penalty thresholds must be unique from 1 to 100.")
                if action not in {"timeout", "kick", "ban"}:
                    raise ValueError("Choose timeout, kick, or ban.")
                if action == "timeout" and (
                    duration_seconds is None or not 60 <= duration_seconds <= 2419200
                ):
                    raise ValueError("Timeout duration must be from one minute to four weeks.")
                if action != "timeout":
                    duration_seconds = None
                seen_thresholds.add(threshold)
                normalized_rules.append({
                    "threshold": threshold, "action": action,
                    "duration_seconds": duration_seconds,
                })
            normalized["penalty_rules"] = sorted(normalized_rules, key=lambda item: item["threshold"])
        except (KeyError, TypeError, ValueError) as exc:
            return _json_error(str(exc) or "Invalid penalty rules.", 400)

    if "disabled_moderation_categories" in payload:
        category_values = payload["disabled_moderation_categories"]
        if not isinstance(category_values, list) or len(category_values) > len(
            SUPPORTED_MODERATION_CATEGORIES
        ):
            return _json_error("Moderation categories must be a valid list.", 400)
        cleaned_categories: list[str] = []
        for raw_category in category_values:
            category = str(raw_category).strip().casefold().replace("_", "-")
            if category not in SUPPORTED_MODERATION_CATEGORIES:
                return _json_error(f"Unsupported moderation category: {category}", 400)
            if any(
                category == prefix or category.startswith(f"{prefix}/")
                for prefix in PROTECTED_MODERATION_CATEGORY_PREFIXES
            ):
                return _json_error(
                    "Self-harm safety categories are always included.", 400
                )
            if any(
                category == parent or category.startswith(f"{parent}/")
                for parent in cleaned_categories
            ):
                continue
            cleaned_categories = [
                existing
                for existing in cleaned_categories
                if not existing.startswith(f"{category}/")
            ]
            cleaned_categories.append(category)
        normalized["disabled_moderation_categories"] = sorted(
            cleaned_categories,
            key=SUPPORTED_MODERATION_CATEGORIES.index,
        )

    if "auto_roles" in payload:
        role_ids = payload["auto_roles"]
        if not isinstance(role_ids, list) or len(role_ids) > 25:
            return _json_error("Automatic roles must be a list of at most 25 role IDs.", 400)
        cleaned_roles: list[str] = []
        role_settings = {
            role["role_id"]: role for role in current_settings["roles"]
        }
        valid_roles = set(role_settings) | set(current_settings["auto_roles"])
        for raw_role_id in role_ids:
            role_id = str(raw_role_id).strip()
            if not role_id.isalnum() or not 10 <= len(role_id) <= 64:
                return _json_error("Each automatic role must be a valid Stoat role ID.", 400)
            if role_id not in valid_roles:
                return _json_error("Each automatic role must exist in this server.", 400)
            role = role_settings.get(role_id)
            if (
                role_id not in current_settings["auto_roles"]
                and role is not None
                and role.get("assignable") is False
            ):
                return _json_error(
                    "Move the Stoatmod role above every new automatic role before adding it.",
                    400,
                )
            if role_id not in cleaned_roles:
                cleaned_roles.append(role_id)
        normalized["auto_roles"] = cleaned_roles

    if "exempt_channels" in payload:
        channel_ids = payload["exempt_channels"]
        if not isinstance(channel_ids, list) or len(channel_ids) > 100:
            return _json_error("Exempt channels must be a list of at most 100 channel IDs.", 400)
        valid_channels = {
            channel["channel_id"] for channel in current_settings["channels"]
        }
        existing_exempt_channels = set(current_settings["exempt_channels"])
        cleaned_channels: list[str] = []
        for raw_channel_id in channel_ids:
            channel_id = str(raw_channel_id).strip()
            if channel_id in removed_deleted_channel_ids:
                # The browser may have loaded this ID before the live 404 check
                # removed it. Silently drop that stale value from this save.
                continue
            if (
                channel_id not in valid_channels
                and channel_id not in existing_exempt_channels
            ):
                return _json_error("Each exempt channel must exist in this server.", 400)
            if channel_id not in cleaned_channels:
                cleaned_channels.append(channel_id)
        normalized["exempt_channels"] = sorted(cleaned_channels)

    if "exempt_categories" in payload:
        category_ids = payload["exempt_categories"]
        if not isinstance(category_ids, list) or len(category_ids) > 100:
            return _json_error("Exempt categories must be a list of at most 100 category IDs.", 400)
        valid_categories = {
            category["category_id"] for category in current_settings["categories"]
        }
        cleaned_categories: list[str] = []
        for raw_category_id in category_ids:
            category_id = str(raw_category_id).strip()
            if category_id not in valid_categories:
                return _json_error("Each exempt category must exist in this server.", 400)
            if category_id not in cleaned_categories:
                cleaned_categories.append(category_id)
        normalized["exempt_categories"] = sorted(cleaned_categories)

    changed: dict[str, Any] = {}
    for key, value in normalized.items():
        if value == current_settings.get(key):
            continue
        if key in boolean_setters:
            boolean_setters[key](server_id, value)
        elif key == "locale":
            database.set_server_locale(server_id, value)
        elif key == "moderation_threshold":
            database.set_moderation_threshold(server_id, value)
        elif key == "join_limits":
            database.join_limits.set_settings(server_id, value)
        elif key == "spam_settings":
            database.set_spam_settings(server_id, value)
        elif key == "warning_expiry_days":
            database.set_warning_expiry_days(server_id, value)
        elif key == "log_channel_id":
            database.set_log_channel(server_id, value)
        elif key == "warning_policy":
            database.set_warning_policy(
                server_id, value["timeout"], value["kick"], value["ban"]
            )
        elif key == "penalty_rules":
            database.set_penalty_rules(server_id, value)
        elif key == "disabled_moderation_categories":
            database.reset_moderation_categories(server_id)
            for category in value:
                database.disable_moderation_category(server_id, category, user_id)
        elif key == "auto_roles":
            database.clear_auto_roles(server_id)
            for role_id in value:
                database.add_auto_role(server_id, role_id, user_id)
        elif key == "exempt_channels":
            current_channels = set(current_settings["exempt_channels"])
            desired_channels = set(value)
            for channel_id in current_channels - desired_channels:
                database.include_scope(server_id, channel_id)
            for channel_id in desired_channels - current_channels:
                database.exclude_scope(server_id, channel_id, "channel", user_id)
        elif key == "exempt_categories":
            current_categories = set(current_settings["exempt_categories"])
            desired_categories = set(value)
            for category_id in current_categories - desired_categories:
                database.include_scope(server_id, category_id)
            for category_id in desired_categories - current_categories:
                database.exclude_scope(server_id, category_id, "category", user_id)
        changed[key] = value

    if {"join_protection", "captcha_all_members"} & changed.keys():
        join_enabled = normalized.get(
            "join_protection", current_settings["join_protection"]
        )
        all_members_enabled = normalized.get(
            "captcha_all_members", current_settings["captcha_all_members"]
        )
        if not join_enabled and not all_members_enabled:
            database.enqueue_dashboard_action(
                server_id, "release_join_challenges", user_id
            )

    if not changed:
        return web.json_response(current_settings)
    database.add_event(
        server_id=server_id,
        event_type="dashboard_settings_updated",
        actor_id=user_id,
        details={"changed": changed},
    )
    database.enqueue_dashboard_action(
        server_id,
        "send_settings_log",
        user_id,
        {"changed": changed},
    )
    return web.json_response(
        database.get_dashboard_settings(server_id, DEFAULT_THRESHOLD, SPAM_DEFAULTS)
    )


async def verification_status(request: web.Request) -> web.Response:
    token = request.query.get("token", "")
    if len(token) < 32:
        return _json_error("This verification link is invalid or expired.", 404)
    challenge = _database(request).get_web_verification_challenge(
        _token_hash(token)
    )
    if challenge is None:
        return _json_error("This verification link is invalid or expired.", 404)
    database = _database(request)
    server = database.get_dashboard_overview(challenge.server_id)["server"]
    attempts_used = min(max(int(challenge.failure_count), 0), 3)
    application = database.applications.current(challenge.server_id, challenge.user_id)
    return web.json_response({
        "application_required": bool(application and application["status"] == "screening"),
        "server_name": server["name"],
        "locale": database.get_server_locale(challenge.server_id),
        "expires_at": challenge.expires_at,
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "turnstile_configured": bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY),
        "privacy_policy_version": VERIFICATION_PRIVACY_VERSION,
        "verification_retention_days": 30,
        "attempts_used": attempts_used,
        "attempts_remaining": max(0, 3 - attempts_used),
        "max_attempts": 3,
        "last_failure_reason": database.get_latest_captcha_failure_reason(
            challenge.server_id, challenge.user_id
        ),
    })


async def _validate_turnstile(response_token: str, *, expected_action: str) -> bool:
    if not TURNSTILE_SECRET_KEY or not response_token:
        return False
    timeout = ClientTimeout(total=10)
    async with ClientSession(timeout=timeout) as session:
        async with session.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": TURNSTILE_SECRET_KEY,
                "response": response_token,
            },
        ) as response:
            if response.status != 200:
                raise RuntimeError("CAPTCHA provider rejected the validation request")
            result = await response.json()
    error_codes = set(result.get("error-codes") or [])
    if error_codes & {
        "missing-input-secret",
        "invalid-input-secret",
        "internal-error",
    }:
        raise RuntimeError("CAPTCHA provider is unavailable or misconfigured")
    return bool(result.get("success")) and result.get("action") == expected_action


def _record_verification_failure(
    request: web.Request,
    challenge: Any,
    reason: str,
) -> web.Response:
    database = _database(request)
    attempts = database.increment_captcha_failure(
        challenge.server_id, challenge.user_id
    )
    if attempts is None:
        return _json_error("This verification link is invalid or expired.", 404)
    details: dict[str, Any] = {"reason": reason, "attempt": attempts}
    database.add_event(
        server_id=challenge.server_id,
        event_type="join_web_verification_failed",
        user_id=challenge.user_id,
        details=details,
    )
    should_kick = attempts >= 3
    application = database.applications.current(challenge.server_id, challenge.user_id)
    if application and application["status"] == "screening":
        if should_kick:
            database.applications.fail_screening(application["id"], reason)
        return web.json_response({
            "error": "Verification failed three times. Removal from the server is queued." if should_kick else f"Verification failed. Attempt {attempts} of 3.",
            "reason": reason, "attempt": attempts, "attempts_remaining": max(0, 3 - attempts),
            "max_attempts": 3, "kicked": should_kick,
        }, status=403)
    kick_reason = reason if should_kick else None
    if should_kick:
        database.remove_captcha_challenge(challenge.server_id, challenge.user_id)
    database.enqueue_dashboard_action(
        challenge.server_id,
        "handle_join_verification_failure",
        challenge.user_id,
        {
            "user_id": challenge.user_id,
            "reason": reason,
            "kick_reason": kick_reason,
            "attempt": attempts,
            "kick": should_kick,
        },
    )
    if should_kick:
        message = (
            "Verification failed three times. You have been removed from the server. "
            f"Reason: {reason}."
        )
    else:
        message = f"Verification failed. Attempt {attempts} of 3."
    return web.json_response(
        {
            "error": message,
            "reason": reason,
            "attempt": attempts,
            "attempts_remaining": max(0, 3 - attempts),
            "max_attempts": 3,
            "kicked": should_kick,
        },
        status=403,
    )


async def complete_verification(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except Exception:
        return _json_error("A JSON request body is required.", 400)
    if not isinstance(payload, dict):
        return _json_error("A JSON object is required.", 400)
    if payload.get("privacy_policy_agreed") is not True:
        return _json_error("Agree to the privacy policy and verification processing before submitting.", 400)
    if payload.get("privacy_policy_version") != VERIFICATION_PRIVACY_VERSION:
        return _json_error("The verification privacy notice has changed. Refresh and review it before agreeing.", 409)
    token = str(payload.get("token", ""))
    database = _database(request)
    token_hash = _token_hash(token)
    challenge = database.get_web_verification_challenge(token_hash) if 32 <= len(token) <= 256 else None
    if challenge is None:
        return _json_error("This verification link is invalid or expired.", 404)
    # Challenge-scoped limits never collect an IP address or fingerprint.
    now = time.monotonic()
    attempts = request.app[LOGIN_ATTEMPTS_KEY][f"verify:{token_hash}"]
    while attempts and now-attempts[0] > 600:
        attempts.popleft()
    if len(attempts) >= 8:
        return _json_error("Too many verification attempts. Try again later.", 429)
    attempts.append(now)
    if not TURNSTILE_SITE_KEY or not TURNSTILE_SECRET_KEY:
        return _json_error("Browser CAPTCHA is not configured yet.", 503)
    database.record_verification_consent(token_hash, challenge.server_id, challenge.user_id, VERIFICATION_PRIVACY_VERSION)
    try:
        turnstile_ok = await _validate_turnstile(str(payload.get("turnstile_token", "")), expected_action="join-verification")
    except Exception:
        return _json_error("Browser CAPTCHA is temporarily unavailable. Try again later.", 503)
    if not turnstile_ok:
        return _record_verification_failure(request, challenge, "Browser CAPTCHA was not completed successfully")
    application = database.applications.pending(challenge.server_id, challenge.user_id)
    if application is not None:
        if application["status"] != "screening":
            return _json_error("This application is no longer waiting for verification.", 409)
        if not database.applications.complete_screening(application["id"], token_hash):
            return _json_error("This verification link has already been used or expired.", 409)
        database.add_event(server_id=challenge.server_id, event_type="join_web_verification_passed",
            user_id=challenge.user_id, details={"application_id": application["id"], "privacy_policy_version": VERIFICATION_PRIVACY_VERSION})
        return web.json_response({"ok": True, "application_required": True,
            "server_name": database.get_dashboard_overview(challenge.server_id)["server"]["name"]})
    identity = database.consume_web_verification_challenge(token_hash)
    if identity is None:
        return _json_error("This verification link has already been used.", 409)
    server_id, user_id = identity
    database.add_event(server_id=server_id, event_type="join_web_verification_passed", user_id=user_id,
        details={"privacy_policy_version": VERIFICATION_PRIVACY_VERSION})
    database.enqueue_dashboard_action(server_id, "complete_join_verification", user_id, {"user_id": user_id})
    return web.json_response({"ok": True, "server_name": database.get_dashboard_overview(server_id)["server"]["name"]})


async def health(request: web.Request) -> web.Response:
    try:
        _database(request).connection.execute("SELECT 1").fetchone()
    except Exception:
        return web.json_response({"status": "error"}, status=503)
    return web.json_response({"status": "ok"})


def _heartbeat_age_seconds(heartbeat: dict[str, Any] | None) -> float | None:
    if not heartbeat:
        return None
    try:
        updated_at = datetime.fromisoformat(str(heartbeat["updated_at"]))
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)
    except (KeyError, TypeError, ValueError):
        return None
    return max(0.0, (datetime.now(timezone.utc) - updated_at).total_seconds())


async def public_system_status(request: web.Request) -> web.Response:
    """Return current, public-safe liveness data for the status page."""
    window = request.query.get("days", "30")
    if window not in {"30", "90"}:
        return _json_error("Choose a 30 or 90 day history window.", 400)
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    services: list[dict[str, Any]] = [
        {
            "id": "api",
            "name": "Public API",
            "status": "operational",
            "detail": "Requests are being accepted normally.",
            "updated_at": checked_at,
        }
    ]
    database = _database(request)
    try:
        database.connection.execute("SELECT 1").fetchone()
        public_stats = database.get_public_dashboard_stats()
        database_ok = True
    except Exception:
        public_stats = None
        database_ok = False
    services.append(
        {
            "id": "database",
            "name": "Moderation database",
            "status": "operational" if database_ok else "outage",
            "detail": (
                "Cases, settings and activity data are available."
                if database_ok
                else "Stored moderation data is currently unavailable."
            ),
            "updated_at": checked_at,
        }
    )
    services.append(
        {
            "id": "dashboard",
            "name": "Moderator dashboard",
            "status": "operational" if public_stats is not None else "outage",
            "detail": (
                "Dashboard data and server snapshots are available."
                if public_stats is not None
                else "Dashboard data cannot currently be loaded."
            ),
            "updated_at": checked_at,
        }
    )

    heartbeat = database.get_system_heartbeat("bot") if database_ok else None
    heartbeat_age = _heartbeat_age_seconds(heartbeat)
    heartbeat_details = heartbeat.get("details", {}) if heartbeat else {}
    if heartbeat_age is None or heartbeat_age > 120:
        bot_status = "outage"
        bot_detail = "The bot has not reported a recent heartbeat."
    elif heartbeat_age > 45 or not heartbeat_details.get("connected", False):
        bot_status = "degraded"
        bot_detail = "The bot process is reporting, but connectivity may be limited."
    else:
        bot_status = "operational"
        server_count = int(heartbeat_details.get("server_count", 0))
        bot_detail = f"Connected and monitoring {server_count:,} server{'s' if server_count != 1 else ''}."
    services.insert(
        0,
        {
            "id": "bot",
            "name": "Stoatmod bot",
            "status": bot_status,
            "detail": bot_detail,
            "updated_at": heartbeat.get("updated_at") if heartbeat else None,
        },
    )
    email_heartbeat = database.get_system_heartbeat("email") if database_ok else None
    email_age = _heartbeat_age_seconds(email_heartbeat)
    email_details = email_heartbeat.get("details", {}) if email_heartbeat else {}
    if email_age is None or email_age > 120:
        email_status = "outage"
        email_detail = "The email relay has not reported a recent mailbox check."
    elif not email_details.get("connected", False):
        email_status = "outage"
        email_detail = "The email relay cannot currently reach its mailbox."
    elif email_age > 45:
        email_status = "degraded"
        email_detail = "Email delivery is reporting more slowly than expected."
    else:
        email_status = "operational"
        email_detail = "Incoming support mail and dashboard replies are being processed."
    services.append(
        {
            "id": "email",
            "name": "Email service",
            "status": email_status,
            "detail": email_detail,
            "updated_at": (
                email_heartbeat.get("updated_at") if email_heartbeat else None
            ),
        }
    )
    history = read_history(request.app[STATUS_HISTORY_PATH_KEY], days=int(window))
    monitored = history["services"]
    model = monitored.get("local_ai", {}).get("current") or {
        "id": "local_ai", "name": "Local AI model", "status": "unknown",
        "detail": "Waiting for the local model's first monitoring check.", "updated_at": None,
    }
    services.insert(1, model)
    if "dashboard" in monitored:
        services = [monitored["dashboard"]["current"] if service["id"] == "dashboard" else service for service in services]
    overall = (
        "outage"
        if all(service["status"] == "outage" for service in services)
        else "degraded"
        if any(service["status"] != "operational" for service in services)
        else "operational"
    )
    response = web.json_response(
        {"overall": overall, "checked_at": checked_at, "services": services, "history": history}
    )
    response.headers["Cache-Control"] = "no-store"
    return response


async def public_stats(request: web.Request) -> web.Response:
    response = web.json_response(_database(request).get_public_dashboard_stats())
    response.headers["Cache-Control"] = "public, max-age=60, stale-while-revalidate=120"
    return response


def _report_webhook_text(value: str, limit: int) -> str:
    value = "".join(
        character
        for character in value
        if character >= " " or character in "\n\t"
    )
    value = value.replace("@", "@\u200b").strip()
    if len(value) > limit:
        value = value[: max(0, limit - 1)].rstrip() + "…"
    return value


def _report_webhook_api_url(webhook_url: str) -> str:
    parsed = urlparse(webhook_url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "stoat.chat",
        "api.stoat.chat",
    }:
        raise ValueError(
            "STOAT_REPORT_WEBHOOK must be an HTTPS stoat.chat webhook URL"
        )
    path = parsed.path.rstrip("/")
    if parsed.hostname == "stoat.chat" and path.startswith("/webhooks/"):
        path = "/api" + path
    valid_path = (
        path.startswith("/api/webhooks/")
        if parsed.hostname == "stoat.chat"
        else path.startswith("/webhooks/")
    )
    if not valid_path:
        raise ValueError("STOAT_REPORT_WEBHOOK has an invalid webhook path")
    return parsed._replace(path=path, params="", query="", fragment="").geturl()


def _report_webhook_payload(
    *,
    report_id: int,
    report_reference: str,
    server_name: str | None,
    server_id: str,
    reporter_username: str | None,
    reporter_id: str,
    target_username: str | None,
    target_id: str,
    reason: str,
    evidence: str,
    attachment_count: int,
    network_risk: dict[str, Any] | None = None,
    linked_user_ids: list[str] | None = None,
) -> dict[str, Any]:
    attachments = (
        f"{attachment_count} file(s), stored in the owner dashboard."
        if attachment_count
        else "None"
    )
    safe_server_name = _report_webhook_text(server_name or "Unknown server", 100)
    safe_reporter_username = _report_webhook_text(
        reporter_username or "Unknown username", 100
    )
    safe_target_username = _report_webhook_text(
        target_username or "Unknown username", 100
    )
    description = (
        f"**Reporter:** {safe_reporter_username}\n"
        f"**Reporter ID:** `{_report_webhook_text(reporter_id, 80)}`\n"
        f"**Reported user:** {safe_target_username}\n"
        f"**Reported user ID:** `{_report_webhook_text(target_id, 80)}`\n"
        f"**Server:** {safe_server_name}\n"
        f"**Server ID:** `{_report_webhook_text(server_id, 80)}`\n"
        f"**Reason:** {_report_webhook_text(reason, 300)}\n\n"
        f"**Evidence:**\n{_report_webhook_text(evidence, 950) or 'None provided.'}\n\n"
        f"**Attachments:** {attachments}\n\n"
        f"**Network scan:** `{_report_webhook_text(str(network_risk or {}), 500)}`\n"
        f"**Alt matches:** `{_report_webhook_text(', '.join(linked_user_ids or []) or 'None', 500)}`\n\n"
        "Review the complete report and attachments in the Global Owner Dashboard."
    )
    return {
        "embeds": [
            {
                "title": f"Global report {report_reference}",
                "description": description,
                "colour": "#ED4245",
            }
        ],
        "mention_everyone": False,
        "mention_online": False,
    }


async def _send_report_webhook(
    webhook_url: str,
    *,
    report_id: int,
    report_reference: str,
    server_name: str | None,
    server_id: str,
    reporter_username: str | None,
    reporter_id: str,
    target_username: str | None,
    target_id: str,
    reason: str,
    evidence: str,
    attachment_count: int,
    network_risk: dict[str, Any] | None = None,
    linked_user_ids: list[str] | None = None,
) -> None:
    api_url = _report_webhook_api_url(webhook_url)
    payload = _report_webhook_payload(
        report_id=report_id,
        report_reference=report_reference,
        server_name=server_name,
        server_id=server_id,
        reporter_username=reporter_username,
        reporter_id=reporter_id,
        target_username=target_username,
        target_id=target_id,
        reason=reason,
        evidence=evidence,
        attachment_count=attachment_count,
        network_risk=network_risk,
        linked_user_ids=linked_user_ids,
    )
    async with ClientSession(timeout=ClientTimeout(total=20)) as session:
        async with session.post(api_url, json=payload) as response:
            if response.status < 200 or response.status >= 300:
                body = await response.text()
                raise RuntimeError(
                    f"report webhook returned HTTP {response.status}: {body[:300]}"
                )


async def get_report_info(request: web.Request) -> web.Response:
    token = request.match_info["token"]
    if not token:
        return _json_error("Missing token.", 400)

    token_hash = _token_hash(token)
    info = _database(request).get_report_token(token_hash)
    if not info:
        return _json_error("This report link has expired or is invalid.", 404)
        
    local_settings = _database(request).get_local_report_settings(info["server_id"])
    overview = _database(request).get_dashboard_overview(info["server_id"])
    token_scope = str(info.get("report_scope") or "global")
    return web.json_response({
        "server_id": info["server_id"],
        "server_name": overview["server"]["name"],
        "scope": "server" if token_scope == "local" else "global",
        "allow_anonymous": bool(
            token_scope == "local"
            and local_settings.get("anonymous_allowed")
        ),
        "subject_types": (
            ["user"]
            if token_scope == "global"
            else ["user", "message", "channel", "server", "other"]
        ),
        "turnstile_site_key": TURNSTILE_SITE_KEY,
        "turnstile_configured": bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY),
    })

async def submit_report(request: web.Request) -> web.Response:
    ip = _client_ip(request)
    now = time.monotonic()
    attempts: deque[float] = request.app[LOGIN_ATTEMPTS_KEY][f"report:{ip}"]
    while attempts and now - attempts[0] > 3600:
        attempts.popleft()
    if len(attempts) >= 10:
        return _json_error("Too many report attempts. Try again later.", 429)
    attempts.append(now)

    token = request.match_info["token"]
    if not token:
        logging.warning("Report failed: Missing token.")
        return _json_error("Missing token.", 400)
        
    token_hash = _token_hash(token)
    info = _database(request).get_report_token(token_hash)
    if not info:
        logging.warning("Report failed: Expired link for token_hash %s", token_hash)
        return _json_error("This report link has expired.", 404)
    report_scope = str(info.get("report_scope") or "global")
        
    reader = await request.multipart()
    target_id = ""
    reason = ""
    evidence = ""
    subject_type = "user"
    subject_text = ""
    reported_channel_id = ""
    reported_message_id = ""
    anonymous = False
    turnstile_token = ""
    files = []
    
    while True:
        field = await reader.next()
        if field is None:
            break
        if field.name == "target_id":
            target_id = (await field.read()).decode("utf-8").strip()
        elif field.name == "reason":
            reason = (await field.read()).decode("utf-8").strip()
        elif field.name == "evidence":
            evidence = (await field.read()).decode("utf-8").strip()
        elif field.name == "subject_type":
            subject_type = (await field.read()).decode("utf-8").strip().lower()
        elif field.name == "subject_text":
            subject_text = (await field.read()).decode("utf-8").strip()
        elif field.name == "reported_channel_id":
            reported_channel_id = (await field.read()).decode("utf-8").strip()
        elif field.name == "reported_message_id":
            reported_message_id = (await field.read()).decode("utf-8").strip()
        elif field.name == "anonymous":
            anonymous = (await field.read()).decode("utf-8").strip().lower() in {"1", "true", "yes", "on"}
        elif field.name == "turnstile_token":
            turnstile_token = (await field.read()).decode("utf-8").strip()
        elif field.name == "attachments":
            filename = Path(field.filename or "").name.strip()[:180]
            content_type = field.headers.get("Content-Type", "application/octet-stream")
            data = await field.read()
            if filename and data:
                files.append({"filename": filename, "content_type": content_type, "data": data})

    if subject_type not in {"user", "message", "channel", "server", "other"}:
        return _json_error("Choose a valid report subject.", 400)
    if report_scope == "global" and subject_type != "user":
        return _json_error("Global reports must identify a Stoat user.", 400)
    if not reason or not 3 <= len(reason) <= 2000:
        return _json_error("A reason between 3 and 2,000 characters is required.", 400)
    if len(evidence) > 8000 or len(subject_text) > 500:
        return _json_error("Report evidence or subject details are too long.", 400)
    if subject_type == "user" and not target_id:
        return _json_error("A target user ID is required for member reports.", 400)
    if report_scope == "global":
        try:
            target_id = _normalize_stoat_user_id(target_id)
        except ValueError as exc:
            return _json_error(str(exc), 400)
    if report_scope == "global" and target_id == GLOBAL_COMMAND_OWNER_ID:
        return _json_error("The global owner cannot be reported for a global ban.", 400)
    if subject_type != "user" and not (subject_text or reported_channel_id or reported_message_id):
        return _json_error("Describe what you are reporting.", 400)

    user_agent = request.headers.get("User-Agent", "").strip()
    if len(user_agent) < 8:
        logging.warning("Report failed: Invalid user_agent.")
        return _json_error("Your browser could not be verified.", 400)

    db = _database(request)
    local_settings = db.get_local_report_settings(info["server_id"])
    if report_scope == "local" and not local_settings.get("enabled"):
        return _json_error("Server reporting is no longer enabled for this server.", 409)
    if report_scope != "local":
        anonymous = False
    elif anonymous and not local_settings.get("anonymous_allowed"):
        return _json_error("Anonymous reports are not enabled for this server.", 400)

    if TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY:
        try:
            turnstile_ok = await _validate_turnstile(turnstile_token, expected_action="user-report")
        except Exception as e:
            logging.exception("Report failed: Turnstile exception")
            return _json_error("Browser CAPTCHA is temporarily unavailable. Try again later.", 503)
        if not turnstile_ok:
            logging.warning("Report failed: Turnstile rejected")
            return _json_error("Browser CAPTCHA was not completed successfully.", 400)

    ip_risk: dict[str, Any] = {}

    if len(files) > 5:
        logging.warning("Report failed: Too many files.")
        return _json_error("Maximum 5 attachments allowed.", 400)
    
    total_size = sum(len(f["data"]) for f in files)
    if total_size > 8 * 1024 * 1024:
        logging.warning("Report failed: Files too large.")
        return _json_error("Total attachments size must be under 8MB.", 400)

    if report_scope == "global" and not STOAT_REPORT_WEBHOOK:
        logging.error("Report failed: STOAT_REPORT_WEBHOOK is not configured.")
        return _json_error("Report delivery is temporarily unavailable.", 503)

    claimed_info = db.claim_report_token(token_hash)
    if claimed_info is None:
        return _json_error("This report link was already used or has expired.", 409)
    info = claimed_info
    report_id: int | None = None
    receipt = secrets.token_urlsafe(32)
    try:
        linked_users: list[str] = []
        delivery_context = db.get_report_delivery_context(
            info["server_id"], info["reporter_id"], target_id
        )
        report_id = db.create_user_report(
            info["server_id"], info["reporter_id"], target_id, reason, evidence,
            ip_risk,
            report_scope=report_scope,
            anonymous=anonymous,
            receipt_token_hash=_token_hash(receipt),
            subject_type=subject_type,
            subject_text=subject_text or None,
            reported_channel_id=reported_channel_id or None,
            reported_message_id=reported_message_id or None,
        )
        stored_report = db.get_report_for_notification(report_id)
        if stored_report is None:
            raise RuntimeError("The saved report could not be reloaded")
        report_reference = str(stored_report["reference_id"])

        for f in files:
            db.add_report_attachment(
                report_id, f["filename"], f["content_type"], f["data"]
            )

        if report_scope == "global":
            await _send_report_webhook(
                STOAT_REPORT_WEBHOOK,
                report_id=report_id,
                report_reference=report_reference,
                server_name=delivery_context["server_name"],
                server_id=info["server_id"],
                reporter_username=delivery_context["reporter_username"],
                reporter_id=info["reporter_id"],
                target_username=delivery_context["target_username"],
                target_id=target_id,
                reason=reason,
                evidence=evidence,
                attachment_count=len(files),
                network_risk=ip_risk,
                linked_user_ids=linked_users,
            )
        else:
            db.enqueue_dashboard_action(
                info["server_id"],
                "send_local_report_log",
                info["reporter_id"],
                {"report_id": report_id},
            )
    except Exception:
        if report_id is not None:
            db.delete_user_report(report_id)
        db.restore_report_token(claimed_info)
        logging.exception("Failed to deliver report")
        return _json_error("Report delivery failed. Please try again.", 502)

    return web.json_response({
        "success": True,
        "report_id": report_reference,
        "scope": "server" if report_scope == "local" else "global",
        "receipt": receipt,
        "status_url": f"{ALLOWED_ORIGIN.rstrip('/')}/report?receipt={quote(receipt, safe='')}",
    })


def _public_report_status(report: dict[str, Any]) -> dict[str, Any]:
    public_report = dict(report)
    public_report.pop("id", None)
    public_report["report_scope"] = (
        "server" if public_report.get("report_scope") == "local" else "global"
    )
    return public_report


async def report_status(request: web.Request) -> web.Response:
    receipt = request.match_info.get("receipt", "").strip()
    if len(receipt) < 32:
        return _json_error("Report receipt not found.", 404)
    report = _database(request).get_report_by_receipt(_token_hash(receipt))
    if report is None:
        return _json_error("Report receipt not found.", 404)
    return web.json_response({"report": _public_report_status(report)})


async def report_status_respond(request: web.Request) -> web.Response:
    receipt = request.match_info.get("receipt", "").strip()
    receipt_hash = _token_hash(receipt)
    rate_key = f"report-response:{_client_ip(request)}:{receipt_hash[:16]}"
    now = time.monotonic()
    attempts: deque[float] = request.app[LOGIN_ATTEMPTS_KEY][rate_key]
    while attempts and now - attempts[0] > 3600:
        attempts.popleft()
    if len(attempts) >= 20:
        return _json_error("Too many report responses. Try again later.", 429)
    attempts.append(now)
    database = _database(request)
    report = database.get_report_by_receipt(receipt_hash)
    if report is None:
        return _json_error("Report receipt not found.", 404)
    if report["status"] != "pending":
        return _json_error("This report is closed and no longer accepts responses.", 409)
    try:
        payload, images = await _case_entry_form(request)
    except web.HTTPException as exc:
        return _json_error(exc.reason, exc.status)
    message = str(payload.get("message", "")).strip()
    if not 3 <= len(message) <= 4000:
        return _json_error("Your response must be between 3 and 4,000 characters.", 400)
    report_id = int(report["id"])
    usage = database.get_report_followup_usage(report_id)
    incoming_bytes = sum(len(data) for _filename, _content_type, data in images)
    if usage["message_count"] >= 20:
        return _json_error("This report has reached its follow-up message limit.", 409)
    if usage["attachment_count"] + len(images) > 25:
        return _json_error("This report has reached its attachment limit.", 409)
    if usage["attachment_bytes"] + incoming_bytes > 32 * 1024 * 1024:
        return _json_error("This report has reached its evidence storage limit.", 413)
    private = database.get_report_for_notification(int(report["id"]))
    sender_id = None if private is None or bool(private.get("anonymous")) else str(private["reporter_id"])
    database.add_report_message(
        report_id, "reporter", sender_id, message
    )
    for filename, content_type, data in images:
        database.add_report_attachment(report_id, filename, content_type, data)
    if report["report_scope"] == "local":
        database.add_event(
            server_id=str(report["server_id"]),
            event_type="server_report_response",
            actor_id=None if bool(report.get("anonymous")) else sender_id,
            details={
                "report_id": report["id"],
                "report_reference": report.get("reference_id"),
            },
        )
    updated_report = database.get_report_by_receipt(receipt_hash)
    assert updated_report is not None
    return web.json_response(
        {"report": _public_report_status(updated_report)}
    )


async def report_status_attachment(request: web.Request) -> web.Response:
    receipt = request.match_info.get("receipt", "").strip()
    report = _database(request).get_report_by_receipt(_token_hash(receipt))
    if report is None:
        return web.Response(status=404)
    try:
        attachment_id = int(request.match_info["attachment_id"])
    except (KeyError, TypeError, ValueError):
        return web.Response(status=404)
    attachment = _database(request).get_report_attachment(
        attachment_id, report_id=int(report["id"])
    )
    if attachment is None:
        return web.Response(status=404)
    return web.Response(
        body=attachment["data"],
        content_type=attachment["content_type"],
        headers={"Content-Disposition": f'attachment; filename="{attachment["filename"]}"'},
    )


STATUS_HISTORY_PATH_KEY = web.AppKey("status_history_path", str)


def create_app(database_path: str = DATABASE_PATH) -> web.Application:
    app = web.Application(
        middlewares=[security_middleware],
        client_max_size=10 * 1024 * 1024,
    )
    app[DATABASE_KEY] = ModerationDatabase(database_path)
    app[STATUS_HISTORY_PATH_KEY] = os.getenv("STATUS_HISTORY_PATH", str(Path(database_path).parent / "status-history.sqlite3"))
    app[LOGIN_ATTEMPTS_KEY] = defaultdict(deque)
    app.router.add_get("/api/health", health)
    app.router.add_get("/api/public/status", public_system_status)
    app.router.add_get("/api/public/stats", public_stats)
    app.router.add_get("/api/public/discovery", public_discovery)
    app.router.add_get("/api/public/discovery/og/{server_id}.png", public_discovery_og)
    app.router.add_get("/api/verification", verification_status)
    app.router.add_post("/api/verification/complete", complete_verification)
    app.router.add_get("/api/applications/settings", application_settings)
    app.router.add_get("/api/reaction-roles", reaction_roles_api)
    app.router.add_post("/api/reaction-roles", reaction_roles_api)
    app.router.add_post("/api/reaction-roles/{panel_id}", reaction_roles_api)
    app.router.add_post("/api/applications/settings", application_settings)
    app.router.add_post("/api/applications/preview", application_preview)
    app.router.add_post("/api/applications/notifications", application_notifications)
    app.router.add_get("/api/applications", list_applications)
    app.router.add_get("/api/applications/{application_id}", application_detail)
    app.router.add_post("/api/applications/{application_id}/review", review_application)
    app.router.add_post("/api/applications/{application_id}/retry", retry_application)
    app.router.add_post("/api/appeals/lookup", appeal_lookup)
    app.router.add_post("/api/appeals/submit", appeal_submit)
    app.router.add_post("/api/appeals/respond", appeal_respond)
    app.router.add_delete("/api/appeals/ai-permission", withdraw_appeal_ai_permission)
    app.router.add_get(
        "/api/appeals/evidence/{attachment_id}", appeal_evidence_attachment
    )
    app.router.add_get(
        "/api/appeals/attachments/{attachment_id}", appeal_message_attachment
    )
    app.router.add_post("/api/auth/verify", verify_code)
    app.router.add_get("/api/session", session_status)
    app.router.add_post("/api/logout", logout)
    app.router.add_get("/api/dashboard", dashboard)
    app.router.add_get("/api/dashboard/notifications", dashboard_notifications)
    app.router.add_post(
        "/api/dashboard/notifications/{section}/read",
        mark_dashboard_notification_read,
    )
    app.router.add_get("/api/dashboard/access", dashboard_access)
    app.router.add_post("/api/dashboard/access", grant_dashboard_access)
    app.router.add_delete(
        "/api/dashboard/access/{user_id}", revoke_dashboard_access
    )
    app.router.add_post(
        "/api/dashboard/access/{user_id}/restore", restore_dashboard_access
    )
    app.router.add_post(
        "/api/dashboard/sessions/revoke-all", revoke_all_dashboard_sessions
    )
    app.router.add_get("/api/discovery", discovery_status)
    app.router.add_post("/api/discovery/bump", bump_discovery_listing)
    app.router.add_get("/api/stats", stats)
    app.router.add_get("/api/cases", cases)
    app.router.add_get("/api/members", members)
    app.router.add_get("/api/members/{user_id}", member_detail)
    app.router.add_post("/api/members/{user_id}/refresh", refresh_member_profile)
    app.router.add_post("/api/members/{user_id}/actions", moderate_member)
    app.router.add_get("/api/cases/{reference}", case_detail)
    app.router.add_get(
        "/api/cases/{reference}/attachments/{attachment_id}",
        case_entry_attachment,
    )
    app.router.add_delete("/api/cases/{reference}", remove_case)
    app.router.add_post("/api/cases/{reference}/entries", add_case_entry)
    app.router.add_get("/api/logs", events)
    app.router.add_post(
        "/api/announcements/{announcement_id}/dismiss",
        dismiss_dashboard_announcement,
    )
    app.router.add_get("/api/appeals", appeals)
    app.router.add_post("/api/appeals/notifications", appeal_notifications)
    app.router.add_get(
        "/api/appeals/{appeal_id}/attachments/{attachment_id}",
        dashboard_appeal_message_attachment,
    )
    app.router.add_put("/api/appeals/{appeal_id}", review_appeal)
    app.router.add_post(
        "/api/appeals/{appeal_id}/request-information",
        request_appeal_information,
    )
    app.router.add_get("/api/settings", settings)
    app.router.add_put("/api/settings", update_settings)
    app.router.add_get("/api/moderation-policy", moderation_policy)
    app.router.add_put("/api/moderation-policy", update_moderation_policy)
    app.router.add_get("/api/onboarding", onboarding_status)
    app.router.add_put("/api/onboarding", update_onboarding)
    app.router.add_post("/api/global-reports/access", create_global_report_access)
    app.router.add_get("/api/server-reports", local_reports)
    app.router.add_put("/api/server-reports/settings", update_local_report_settings)
    app.router.add_get("/api/server-reports/{report_id}", local_report_detail)
    app.router.add_put("/api/server-reports/{report_id}", update_local_report)
    app.router.add_get(
        "/api/server-reports/{report_id}/attachments/{attachment_id}",
        local_report_attachment,
    )
    # Compatibility aliases for links created before the server-report rename.
    app.router.add_get("/api/local-reports", local_reports)
    app.router.add_put("/api/local-reports/settings", update_local_report_settings)
    app.router.add_get("/api/local-reports/{report_id}", local_report_detail)
    app.router.add_put("/api/local-reports/{report_id}", update_local_report)
    app.router.add_get(
        "/api/local-reports/{report_id}/attachments/{attachment_id}",
        local_report_attachment,
    )
    app.router.add_get("/api/automations", automations)
    app.router.add_post("/api/automations", create_automation)
    app.router.add_post("/api/automations/simulate", simulate_automation)
    app.router.add_post("/api/automations/{rule_id}/clone", clone_automation)
    app.router.add_put("/api/automations/{rule_id}", update_automation)
    app.router.add_delete("/api/automations/{rule_id}", delete_automation)
    app.router.add_get("/api/leaderboards", leaderboards)
    app.router.add_get("/api/polls", polls)
    app.router.add_post("/api/polls", create_poll)
    app.router.add_post("/api/polls/{poll_id}/close", close_poll_now)
    app.router.add_get("/api/polls/{poll_id}/export", export_poll_results)
    app.router.add_delete("/api/polls/{poll_id}", delete_poll)
    app.router.add_post("/api/poll-templates", save_poll_template)
    app.router.add_delete(
        "/api/poll-templates/{template_id}", delete_poll_template
    )

    app.router.add_get("/api/report/{token}", get_report_info)
    app.router.add_post("/api/report/{token}", submit_report)
    app.router.add_get("/api/report-status/{receipt}", report_status)
    app.router.add_post("/api/report-status/{receipt}", report_status_respond)
    app.router.add_get(
        "/api/report-status/{receipt}/attachments/{attachment_id}",
        report_status_attachment,
    )


    async def close_database(application: web.Application) -> None:
        application[DATABASE_KEY].close()

    async def verification_retention(application: web.Application):
        async def prune():
            while True:
                try:
                    application[DATABASE_KEY].prune_verification_privacy_data()
                    application[DATABASE_KEY].appeal_privacy.prune()
                    application[DATABASE_KEY].applications.prune()
                    now = time.monotonic()
                    for key, attempts in list(application[LOGIN_ATTEMPTS_KEY].items()):
                        while attempts and now - attempts[0] > 600:
                            attempts.popleft()
                        if not attempts:
                            application[LOGIN_ATTEMPTS_KEY].pop(key, None)
                except Exception:
                    logging.exception("verification_retention_failed")
                await asyncio.sleep(60)
        task = asyncio.create_task(prune())
        yield
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    discovery_extras.register(
        app,
        discovery_extras.Hooks(
            database=_database,
            session=_session,
            require_csrf=_require_csrf,
            json_error=_json_error,
            client_ip=_client_ip,
            listing_fields=_discovery_listing_fields,
            validate_turnstile=_validate_turnstile,
            turnstile_configured=lambda: bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY),
            turnstile_site_key=TURNSTILE_SITE_KEY,
            system_actor=GLOBAL_COMMAND_OWNER_ID,
        ),
        app[DATABASE_KEY].connection,
        stoat_api_base=STOAT_API_BASE,
        threshold=DEFAULT_THRESHOLD,
    )
    app.cleanup_ctx.append(verification_retention)
    app.on_cleanup.append(close_database)
    return app


if __name__ == "__main__":
    web.run_app(
        create_app(),
        access_log=None,
        host=os.getenv("DASHBOARD_API_HOST", "127.0.0.1"),
        port=int(os.getenv("DASHBOARD_API_PORT", "8081")),
    )
