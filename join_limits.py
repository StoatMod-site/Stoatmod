"""Join protection options: limit links and attachments from new members for a set time.

A member who joins starts a protection window. Until it ends, their messages with
links or attachments are removed. They are told by DM when the window starts and
again when it ends. The only stored record is the server, the member and the
window times, and it is deleted when the window ends or the member leaves.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger("stoat_moderator")

DEFAULT_DURATION_SECONDS = 24 * 60 * 60
MIN_DURATION_SECONDS = 60 * 60
MAX_DURATION_SECONDS = 30 * 24 * 60 * 60
EXPIRY_CHECK_SECONDS = 60
# A member whose messages keep getting removed is reminded at most this often.
REMINDER_COOLDOWN_SECONDS = 10 * 60
DEFAULT_SETTINGS = {
    "enabled": True,
    "duration_seconds": DEFAULT_DURATION_SECONDS,
    "links": True,
    "attachments": True,
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def format_duration(seconds: int) -> str:
    for unit_seconds, label in ((7 * 86400, "week"), (86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds % unit_seconds == 0:
            amount = seconds // unit_seconds
            return f"{amount} {label}{'' if amount == 1 else 's'}"
    return f"{seconds} second{'' if seconds == 1 else 's'}"


def format_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def normalize_settings(value: Any) -> dict[str, Any]:
    """Validate a dashboard payload. Raises ValueError with a readable message."""
    if not isinstance(value, dict) or set(value) != set(DEFAULT_SETTINGS):
        raise ValueError("Every join protection option is required.")
    for key in ("enabled", "links", "attachments"):
        if not isinstance(value[key], bool):
            raise ValueError(f"Join protection {key} must be true or false.")
    duration = value["duration_seconds"]
    if isinstance(duration, bool) or not isinstance(duration, int):
        raise ValueError("Join protection length must be a whole number of seconds.")
    if not MIN_DURATION_SECONDS <= duration <= MAX_DURATION_SECONDS:
        raise ValueError("Join protection length must be between 1 hour and 30 days.")
    return {key: value[key] for key in DEFAULT_SETTINGS}


class JoinLimitStore:
    def __init__(self, database: Any):
        self.connection = database.connection
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS join_limit_settings (
                server_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                duration_seconds INTEGER NOT NULL DEFAULT 86400,
                links INTEGER NOT NULL DEFAULT 1,
                attachments INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS join_limit_members (
                server_id TEXT NOT NULL, user_id TEXT NOT NULL,
                started_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                PRIMARY KEY(server_id, user_id)
            );
            CREATE INDEX IF NOT EXISTS join_limit_members_expiry ON join_limit_members(expires_at);
        """)

    def settings(self, server_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT enabled, duration_seconds, links, attachments FROM join_limit_settings WHERE server_id=?",
            (server_id,),
        ).fetchone()
        if row is None:
            return dict(DEFAULT_SETTINGS)
        return {"enabled": bool(row[0]), "duration_seconds": int(row[1]),
                "links": bool(row[2]), "attachments": bool(row[3])}

    def set_settings(self, server_id: str, value: dict[str, Any]) -> None:
        value = normalize_settings(value)
        self.connection.execute(
            """INSERT INTO join_limit_settings(server_id, enabled, duration_seconds, links, attachments)
               VALUES (?,?,?,?,?) ON CONFLICT(server_id) DO UPDATE SET enabled=excluded.enabled,
               duration_seconds=excluded.duration_seconds, links=excluded.links, attachments=excluded.attachments""",
            (server_id, int(value["enabled"]), value["duration_seconds"], int(value["links"]), int(value["attachments"])),
        )
        self.connection.commit()

    def active(self, server_id: str) -> bool:
        config = self.settings(server_id)
        return config["enabled"] and (config["links"] or config["attachments"])

    def start(self, server_id: str, user_id: str, *, now: datetime | None = None) -> datetime:
        now = now or utcnow()
        expires = now + timedelta(seconds=self.settings(server_id)["duration_seconds"])
        self.connection.execute(
            """INSERT INTO join_limit_members(server_id, user_id, started_at, expires_at) VALUES (?,?,?,?)
               ON CONFLICT(server_id, user_id) DO UPDATE SET started_at=excluded.started_at, expires_at=excluded.expires_at""",
            (server_id, user_id, now.isoformat(), expires.isoformat()),
        )
        self.connection.commit()
        return expires

    def expires_at(self, server_id: str, user_id: str, *, now: datetime | None = None) -> datetime | None:
        """When the member's protection ends, or None when they are not under protection."""
        row = self.connection.execute(
            "SELECT expires_at FROM join_limit_members WHERE server_id=? AND user_id=?", (server_id, user_id)
        ).fetchone()
        if row is None:
            return None
        expires = datetime.fromisoformat(row[0])
        return expires if expires > (now or utcnow()) else None

    def end(self, server_id: str, user_id: str) -> bool:
        removed = self.connection.execute(
            "DELETE FROM join_limit_members WHERE server_id=? AND user_id=?", (server_id, user_id)
        ).rowcount
        self.connection.commit()
        return bool(removed)

    def due(self, *, now: datetime | None = None, limit: int = 100) -> list[tuple[str, str]]:
        return [(row[0], row[1]) for row in self.connection.execute(
            "SELECT server_id, user_id FROM join_limit_members WHERE expires_at<=? ORDER BY expires_at LIMIT ?",
            ((now or utcnow()).isoformat(), limit),
        )]


class JoinLimitFlow:
    def __init__(self, bot: Any):
        self.bot = bot
        self.task: asyncio.Task[None] | None = None
        self.reminded: dict[tuple[str, str], float] = {}

    @property
    def store(self) -> JoinLimitStore | None:
        return getattr(self.bot.database, "join_limits", None)

    def start(self) -> None:
        if self.store is None:
            return
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._run_expiry(), name="join-limit-expiry")

    def _limited_sentence(self, server_id: str) -> str:
        config = self.store.settings(server_id)
        limited = " or ".join(name for name in ("links", "attachments") if config[name])
        return f"As a new member, you can't send {limited} there yet."

    def _after_text(self, server_id: str) -> str:
        """What the member may send once protection ends, following the server's link rules."""
        config = self.store.settings(server_id)
        allowed = [name for name in ("links", "attachments") if config[name]]
        link_rule = ""
        if config["links"] and self.bot.database.get_link_protection(server_id):
            allowed.remove("links")
            link_rule = (
                "\n\nThis server's link rules still apply to everyone: only GifBox links are allowed."
                if self.bot._server_allows_gifs(server_id)
                else "\n\nThis server's link rules still apply to everyone: links are not allowed."
            )
        return (f" You can now send {' and '.join(allowed)}." if allowed else "") + link_rule

    async def on_join(self, server: Any, member: Any, user: Any | None) -> None:
        server_id = str(server.id)
        if self.store is None or user is None or getattr(user, "bot", None) is not None:
            return
        if not self.store.active(server_id):
            return
        expires = self.store.start(server_id, member.id)
        await self.bot._send_user_dm(
            member.id,
            "You're under join protection",
            f"Welcome to **{server.name}**. {self._limited_sentence(server_id)}\n\n"
            f"**Ends:** {format_time(expires)}\n\n"
            "Messages that contain them are removed until then. You'll get a DM when your join protection ends.",
            server_id=server_id, user=user, color="#F59E0B",
        )

    def on_leave(self, server_id: str, user_id: str) -> None:
        if self.store is not None:
            self.store.end(server_id, user_id)
        self.reminded.pop((server_id, user_id), None)

    def blocked_reason(self, message: Any, server_id: str) -> str | None:
        """Why this message breaks the author's join protection, or None."""
        if self.store is None or not self.store.active(server_id):
            return None
        if self.store.expires_at(server_id, message.author_id) is None:
            return None
        config = self.store.settings(server_id)
        if config["attachments"] and getattr(message, "attachments", None):
            return "attachment"
        if config["links"] and self.bot._contains_link(message.content or ""):
            return "link"
        return None

    async def handle_message(self, message: Any) -> bool:
        server, server_id = message.get_server()
        if server is None or not server_id:
            return False
        reason = self.blocked_reason(message, server_id)
        if reason is None:
            return False
        if not await self.bot.require_action_permissions(server, "manage_messages"):
            return True
        deleted = await self.bot._delete_automatic_message(message)
        expires = self.store.expires_at(server_id, message.author_id)
        self.bot.database.add_event(
            server_id=server_id, event_type="join_protection_deletion", user_id=message.author_id,
            actor_id=self.bot.state.my_id, message_id=message.id, channel_id=message.channel_id,
            details={"message_deleted": deleted, "warning_added": False, "blocked": reason,
                     "original_content": message.content},
        )
        user_tag = await self.bot._resolve_user_tag(message.author_id, message.get_author_as_user())
        await self.bot.send_log(
            server_id,
            "Join protection removed a message" if deleted else "Join protection — deletion failed",
            f"**User:** `{user_tag}`\n**Channel:** <#{message.channel_id}>\n**Message:** `{message.id}`\n"
            f"**Blocked:** {'Attachment' if reason == 'attachment' else 'Link'}\n**Warning added:** No"
            + (f"\n**Protection ends:** {format_time(expires)}" if expires else "")
            + f"\n\n**Original message:**\n{self.bot._original_message_text(message.content)}",
            color="#F59E0B" if deleted else "#ED4245",
        )
        key = (server_id, message.author_id)
        if deleted and expires and time.monotonic() - self.reminded.get(key, -REMINDER_COOLDOWN_SECONDS) >= REMINDER_COOLDOWN_SECONDS:
            self.reminded[key] = time.monotonic()
            await self.bot._send_user_dm(
                message.author_id,
                "Message removed: join protection",
                f"Your message in **{server.name}** was removed because you're still under join protection.\n\n"
                f"**Ends:** {format_time(expires)}",
                server_id=server_id, user=message.get_author_as_user(), color="#F59E0B",
            )
        return True

    async def expire_due(self, *, now: datetime | None = None) -> int:
        ended = 0
        for server_id, user_id in self.store.due(now=now):
            if not self.store.end(server_id, user_id):
                continue
            self.reminded.pop((server_id, user_id), None)
            ended += 1
            server = self.bot.get_server(server_id)
            name = getattr(server, "name", None) or "the server"
            await self.bot._send_user_dm(
                user_id,
                "Join protection has ended",
                f"Your join protection in **{name}** has ended." + self._after_text(server_id),
                server_id=server_id, color="#3BA55D",
            )
        return ended

    async def _run_expiry(self) -> None:
        while True:
            try:
                await self.expire_due()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("join_limit_expiry_failed")
            await asyncio.sleep(EXPIRY_CHECK_SECONDS)
