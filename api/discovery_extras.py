"""Discovery listing extras.

Everything a listed server can add on top of the reviewed application stored in
``discovery_applications``: edits that go live after automatic checks, custom
``modstoat.site/<slug>`` links, uploaded logos and banners, privacy-safe visit
statistics, verification, profile fields (language, categories and links),
bump reminders, weekly digests and public listing reports.

Statistics are daily per-server counters only. No IP address, cookie, user
agent or referrer is stored: the referrer is reduced to a source category
before counting, and rate limiting keeps a short-lived keyed hash of the client
address in memory that never reaches the database.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable
from urllib.parse import quote, urlparse

from aiohttp import ClientSession, ClientTimeout, web

logger = logging.getLogger("stoat_dashboard.discovery")

# --------------------------------------------------------------------------- constants

VERIFICATION_TIERS: dict[str, str] = {
    "official": "Official Stoatmod server",
    "organization": "Verified organisation",
    "standing": "Community of high standing",
    "impact": "Impactful community",
}
# "official" is granted by the Stoatmod team only; servers apply for the others.
APPLICABLE_TIERS = ("organization", "standing", "impact")

LANGUAGES = (
    "en", "pt", "es", "fr", "de", "it", "nl", "pl", "ru", "uk", "tr",
    "ar", "hi", "id", "ja", "ko", "zh", "other",
)
# Must match discoveryCategories in website/app/lib/discovery-catalog.ts.
CATEGORY_SLUGS = (
    "gaming", "anime", "art-and-creative", "music", "roleplay",
    "social", "lgbtq", "brasil", "tech",
)
REPORT_REASONS = {
    "scam": "Scam, phishing or fake giveaway",
    "nsfw": "Sexual or graphic content",
    "hate": "Hate, harassment or extremism",
    "impersonation": "Impersonation",
    "broken_invite": "Invite does not work",
    "spam": "Spam or misleading listing",
    "other": "Something else",
}
STAT_SOURCES = ("search", "discovery", "stoat", "direct", "other")

DESCRIPTION_MIN, DESCRIPTION_MAX = 20, 500
INFORMATION_MAX = 2000
MAX_LINKS = 4
MAX_CATEGORIES = 2
MEDIA_MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MEDIA_MAX_PIXELS = 40_000_000
VANITY_RETIRED_DAYS = 30
VANITY_CHANGE_COOLDOWN = timedelta(hours=24)
VERIFICATION_DENIED_COOLDOWN = timedelta(days=30)
BUMP_COOLDOWN = timedelta(hours=2)

SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,30})[a-z0-9]$")
# Top-level routes of the website: never usable as custom links, even by staff.
SITE_ROUTE_SLUGS = frozenset({
    "_next", "_sites-preview", "about", "admin", "api", "appeal", "changelog", "compare",
    "content", "dashboard", "discovery", "docs", "features", "guides", "i18n", "lib",
    "login", "owner", "privacy", "privacy-changes", "report", "security", "status", "verify",
})
# Names people could mistake for Stoatmod or for future pages. Only the Stoatmod team can assign them.
RESERVED_SLUGS = SITE_ROUTE_SLUGS | frozenset({
    "app", "appeals", "apply", "assets", "auth", "blog", "brand", "contact", "cdn",
    "discover", "download", "email", "es", "faq", "fr", "help", "home", "invite", "join",
    "legal", "logout", "mail", "mod", "moderation", "moderator", "news", "official",
    "partner", "partners", "pricing", "pt", "reports", "server", "servers", "settings",
    "signin", "signup", "staff", "static", "stoat", "stoatmod", "modstoat", "support",
    "team", "terms", "tos", "verified", "www",
})
# Names only a verified server may claim, so nobody squats a brand's link.
PROTECTED_SLUG_WORDS = (
    "stoatmod", "modstoat", "stoat", "official", "admin", "staff", "support",
    "minecraft", "roblox", "fortnite", "valorant", "pokemon", "nintendo", "playstation",
    "xbox", "steam", "discord", "revolt", "youtube", "twitch", "github", "google",
    "apple", "microsoft", "mojang", "riot", "epic", "hoyoverse", "genshin",
)
LINK_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "v.gd", "lnkd.in", "grabify.link",
    "iplogger.org", "iplogger.com", "2no.co", "yip.su",
})
SEARCH_HOST_MARKERS = (
    "google.", "bing.", "duckduckgo.", "yahoo.", "yandex.", "ecosia.", "brave.",
    "baidu.", "naver.", "startpage.", "qwant.", "search.",
)
BOT_USER_AGENT = re.compile(
    r"bot|crawl|spider|slurp|preview|facebookexternalhit|embedly|headless|python|curl|wget|"
    r"httpclient|go-http|node-fetch|undici|axios|monitor|lighthouse|scrapy|okhttp|java/",
    re.IGNORECASE,
)
MARKDOWN_LINK = re.compile(r"\[([^\]\n]{1,200})\]\(([^)\s]{1,500})\)")
BARE_URL = re.compile(r"https?://[^\s)<>\]]+", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _json_list(value: Any) -> list[Any]:
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


# --------------------------------------------------------------------------- validation


def normalize_slug(value: Any) -> str:
    return str(value or "").strip().lower()


def validate_slug(value: Any, *, verified: bool = False, staff: bool = False) -> str:
    slug = normalize_slug(value)
    if not SLUG_PATTERN.match(slug) or "--" in slug:
        raise ValueError(
            "Custom links use 3 to 32 lowercase letters, numbers and single hyphens, "
            "and cannot start or end with a hyphen."
        )
    if slug in SITE_ROUTE_SLUGS:
        raise ValueError("That link is a page of the Stoatmod website.")
    if staff:
        return slug
    if slug in RESERVED_SLUGS:
        raise ValueError("That link is reserved by Stoatmod. Choose another one.")
    if not verified and any(word in slug for word in PROTECTED_SLUG_WORDS):
        raise ValueError(
            "That link contains a protected brand name. Verified servers can claim "
            "brand names; apply for verification or choose another link."
        )
    return slug


def validate_public_url(value: Any) -> str:
    url = str(value or "").strip()
    if len(url) > 300:
        raise ValueError("Links must be 300 characters or fewer.")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or "." not in host or parsed.username or parsed.password:
        raise ValueError("Links must be full https:// web addresses.")
    if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):
        raise ValueError("Links must use a domain name, not an IP address.")
    return url


def validate_links(values: Any) -> list[str]:
    if values in (None, ""):
        return []
    if not isinstance(values, list):
        raise ValueError("Links must be provided as a list.")
    links: list[str] = []
    for value in values:
        if not str(value or "").strip():
            continue
        url = validate_public_url(value)
        if url not in links:
            links.append(url)
    if len(links) > MAX_LINKS:
        raise ValueError(f"A listing can show up to {MAX_LINKS} links.")
    return links


def validate_language(value: Any) -> str:
    language = str(value or "").strip().lower()
    if language and language not in LANGUAGES:
        raise ValueError("Choose a language from the list.")
    return language


def validate_categories(values: Any) -> list[str]:
    if values in (None, ""):
        return []
    if not isinstance(values, list):
        raise ValueError("Categories must be provided as a list.")
    categories: list[str] = []
    for value in values:
        slug = str(value or "").strip().lower()
        if slug not in CATEGORY_SLUGS:
            raise ValueError("Choose categories from the list.")
        if slug not in categories:
            categories.append(slug)
    if len(categories) > MAX_CATEGORIES:
        raise ValueError(f"Choose up to {MAX_CATEGORIES} categories.")
    return categories


def validate_information(value: Any) -> str:
    """Long description in the safe Markdown subset the website renders."""
    information = str(value or "").strip().replace("\r\n", "\n")
    if len(information) > INFORMATION_MAX:
        raise ValueError(f"Server information must be {INFORMATION_MAX:,} characters or fewer.")
    for _label, target in MARKDOWN_LINK.findall(information):
        validate_public_url(target)
    return information


def text_urls(*texts: str) -> list[str]:
    urls: list[str] = []
    for text in texts:
        urls.extend(target for _label, target in MARKDOWN_LINK.findall(text))
        urls.extend(BARE_URL.findall(text))
    return urls


def uses_link_shortener(urls: list[str]) -> bool:
    for url in urls:
        host = (urlparse(url).hostname or "").lower().removeprefix("www.")
        if host in LINK_SHORTENERS:
            return True
    return False


def classify_referrer(referrer: Any) -> str:
    host = (urlparse(str(referrer or "")).hostname or "").lower()
    if not host:
        return "direct"
    if host.endswith("modstoat.site") or host.endswith("modstoat.online"):
        return "discovery"
    if host in {"stoat.chat", "stt.gg"} or host.endswith(".stoat.chat"):
        return "stoat"
    if any(marker in host for marker in SEARCH_HOST_MARKERS):
        return "search"
    return "other"


def is_automated(user_agent: Any) -> bool:
    agent = str(user_agent or "").strip()
    return not agent or bool(BOT_USER_AGENT.search(agent))


def invite_code(invite_url: str) -> str:
    path = urlparse(invite_url).path.strip("/")
    return path.rsplit("/", 1)[-1] if path else ""


def process_media(data: bytes, kind: str) -> bytes:
    """Re-encode an upload: first frame only, EXIF stripped, cropped and resized to WebP."""
    from PIL import Image, ImageOps

    if not data:
        raise ValueError("Choose an image to upload.")
    if len(data) > MEDIA_MAX_UPLOAD_BYTES:
        raise ValueError("Images must be 2 MB or smaller.")
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.format not in {"PNG", "JPEG", "GIF", "WEBP"}:
                raise ValueError("Upload a PNG, JPEG, GIF or WebP image.")
            if image.width * image.height > MEDIA_MAX_PIXELS:
                raise ValueError("That image is too large. Use one under 40 megapixels.")
            image.seek(0)
            frame = ImageOps.exif_transpose(image.copy()).convert("RGBA")
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001 - Pillow raises many types for broken files
        raise ValueError("That file could not be read as an image.") from exc
    width, height = frame.size
    if kind == "logo":
        if min(width, height) < 128:
            raise ValueError("Logos must be at least 128 × 128 pixels.")
        side = min(width, height)
        left, top = (width - side) // 2, (height - side) // 2
        frame = frame.crop((left, top, left + side, top + side)).resize((512, 512), Image.LANCZOS)
    elif kind == "banner":
        if width < 600 or height < 200:
            raise ValueError("Banners must be at least 600 × 200 pixels.")
        target = 3.0
        if width / height > target:
            new_width = int(height * target)
            left = (width - new_width) // 2
            frame = frame.crop((left, 0, left + new_width, height))
        else:
            new_height = int(width / target)
            top = (height - new_height) // 2
            frame = frame.crop((0, top, width, top + new_height))
        frame = frame.resize((1500, 500), Image.LANCZOS)
    else:
        raise ValueError("Unknown image type.")
    output = io.BytesIO()
    frame.save(output, format="WEBP", quality=86, method=4)
    return output.getvalue()


# --------------------------------------------------------------------------- storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS discovery_profiles (
    server_id TEXT PRIMARY KEY,
    language TEXT NOT NULL DEFAULT '',
    categories_json TEXT NOT NULL DEFAULT '[]',
    links_json TEXT NOT NULL DEFAULT '[]',
    verified_tier TEXT,
    verified_at TEXT,
    verified_by TEXT,
    bump_reminders INTEGER NOT NULL DEFAULT 0,
    weekly_digest INTEGER NOT NULL DEFAULT 0,
    reminded_for_bump TEXT,
    digest_week TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discovery_vanity (
    slug TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_discovery_vanity_server ON discovery_vanity(server_id, retired_at);

CREATE TABLE IF NOT EXISTS discovery_media (
    server_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('logo', 'banner')),
    content_type TEXT NOT NULL,
    data BLOB NOT NULL,
    digest TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (server_id, kind)
);

CREATE TABLE IF NOT EXISTS discovery_stats_daily (
    server_id TEXT NOT NULL,
    day TEXT NOT NULL,
    views INTEGER NOT NULL DEFAULT 0,
    joins INTEGER NOT NULL DEFAULT 0,
    link_visits INTEGER NOT NULL DEFAULT 0,
    src_search INTEGER NOT NULL DEFAULT 0,
    src_discovery INTEGER NOT NULL DEFAULT 0,
    src_stoat INTEGER NOT NULL DEFAULT 0,
    src_direct INTEGER NOT NULL DEFAULT 0,
    src_other INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_id, day)
);

CREATE TABLE IF NOT EXISTS discovery_listing_edits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    previous_json TEXT NOT NULL,
    proposed_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('live', 'held', 'approved', 'rejected', 'reverted', 'withdrawn', 'superseded')),
    reason TEXT NOT NULL DEFAULT '',
    submitted_by TEXT,
    created_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_discovery_edits_server ON discovery_listing_edits(server_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_discovery_edits_status ON discovery_listing_edits(status, created_at DESC);

CREATE TABLE IF NOT EXISTS discovery_verification_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    reason TEXT NOT NULL,
    links_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'withdrawn')),
    submitted_by TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_discovery_verification_server ON discovery_verification_requests(server_id, submitted_at DESC);

CREATE TABLE IF NOT EXISTS discovery_listing_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed')),
    created_at TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_discovery_reports_status ON discovery_listing_reports(status, created_at DESC);
"""

LISTING_FIELDS = ("description", "information", "invite_url", "tags", "language", "categories", "links")


class DiscoveryExtrasStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    # ---------------------------------------------------------------- listings and profiles

    def get_profile(self, server_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM discovery_profiles WHERE server_id=?", (server_id,)
        ).fetchone()
        tier = row["verified_tier"] if row else None
        return {
            "language": row["language"] if row else "",
            "categories": _json_list(row["categories_json"]) if row else [],
            "links": _json_list(row["links_json"]) if row else [],
            "verified_tier": tier if tier in VERIFICATION_TIERS else None,
            "verified_at": row["verified_at"] if row else None,
            "bump_reminders": bool(row["bump_reminders"]) if row else False,
            "weekly_digest": bool(row["weekly_digest"]) if row else False,
        }

    def _ensure_profile(self, server_id: str) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO discovery_profiles(server_id, updated_at) VALUES (?, ?)",
            (server_id, iso(utc_now())),
        )

    def save_profile_fields(self, server_id: str, language: str, categories: list[str], links: list[str]) -> None:
        self._ensure_profile(server_id)
        self.connection.execute(
            """
            UPDATE discovery_profiles
            SET language=?, categories_json=?, links_json=?, updated_at=?
            WHERE server_id=?
            """,
            (language, _dumps(categories), _dumps(links), iso(utc_now()), server_id),
        )

    def set_notifications(self, server_id: str, bump_reminders: bool, weekly_digest: bool) -> None:
        self._ensure_profile(server_id)
        self.connection.execute(
            """
            UPDATE discovery_profiles SET bump_reminders=?, weekly_digest=?, updated_at=?
            WHERE server_id=?
            """,
            (int(bump_reminders), int(weekly_digest), iso(utc_now()), server_id),
        )
        self.connection.commit()

    def get_listing(self, server_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT description, information, invite_url, tags_json, status, is_revoked
            FROM discovery_applications WHERE server_id=?
            """,
            (server_id,),
        ).fetchone()
        if row is None:
            return None
        profile = self.get_profile(server_id)
        return {
            "description": row["description"],
            "information": row["information"] or "",
            "invite_url": row["invite_url"],
            "tags": _json_list(row["tags_json"]),
            "language": profile["language"],
            "categories": profile["categories"],
            "links": profile["links"],
            "status": "revoked" if row["is_revoked"] else row["status"],
        }

    def is_live(self, server_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM discovery_applications WHERE server_id=? AND status='approved' AND is_revoked=0",
            (server_id,),
        ).fetchone()
        return row is not None

    def write_listing(self, server_id: str, fields: dict[str, Any], submitted_by: str | None) -> None:
        """Store listing content without touching its review status or bump time."""
        self.connection.execute(
            """
            UPDATE discovery_applications
            SET description=?, information=?, invite_url=?, tags_json=?,
                submitted_by=COALESCE(?, submitted_by), updated_at=?
            WHERE server_id=?
            """,
            (
                fields["description"], fields["information"], fields["invite_url"],
                _dumps(fields["tags"]), submitted_by, iso(utc_now()), server_id,
            ),
        )
        self.save_profile_fields(server_id, fields["language"], fields["categories"], fields["links"])

    # ---------------------------------------------------------------- edits

    def record_edit(
        self, server_id: str, previous: dict[str, Any], proposed: dict[str, Any],
        status: str, reason: str, submitted_by: str | None,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO discovery_listing_edits(
                server_id, previous_json, proposed_json, status, reason, submitted_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                _dumps({key: previous[key] for key in LISTING_FIELDS}),
                _dumps({key: proposed[key] for key in LISTING_FIELDS}),
                status, reason, submitted_by, iso(utc_now()),
            ),
        )
        return int(cursor.lastrowid)

    def close_held_edits(self, server_id: str, status: str, reviewed_by: str | None = None) -> None:
        self.connection.execute(
            """
            UPDATE discovery_listing_edits SET status=?, reviewed_by=?, reviewed_at=?
            WHERE server_id=? AND status='held'
            """,
            (status, reviewed_by, iso(utc_now()), server_id),
        )

    def _edit(self, row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["previous"] = json.loads(item.pop("previous_json"))
        item["proposed"] = json.loads(item.pop("proposed_json"))
        item["changed"] = [
            key for key in LISTING_FIELDS
            if item["previous"].get(key) != item["proposed"].get(key)
        ]
        return item

    def get_edit(self, edit_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM discovery_listing_edits WHERE id=?", (edit_id,)
        ).fetchone()
        return self._edit(row) if row else None

    def held_edit(self, server_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM discovery_listing_edits WHERE server_id=? AND status='held'
            ORDER BY id DESC LIMIT 1
            """,
            (server_id,),
        ).fetchone()
        return self._edit(row) if row else None

    def list_edits(self, server_id: str | None = None, limit: int = 60) -> list[dict[str, Any]]:
        if server_id:
            rows = self.connection.execute(
                """
                SELECT * FROM discovery_listing_edits WHERE server_id=?
                ORDER BY id DESC LIMIT ?
                """,
                (server_id, limit),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT edit.*, snapshot.server_name
                FROM discovery_listing_edits AS edit
                LEFT JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=edit.server_id
                ORDER BY edit.status='held' DESC, edit.id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._edit(row) for row in rows]

    def set_edit_status(self, edit_id: int, status: str, reviewed_by: str) -> None:
        self.connection.execute(
            "UPDATE discovery_listing_edits SET status=?, reviewed_by=?, reviewed_at=? WHERE id=?",
            (status, reviewed_by, iso(utc_now()), edit_id),
        )

    # ---------------------------------------------------------------- custom links

    def vanity_for(self, server_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT slug, created_at FROM discovery_vanity
            WHERE server_id=? AND retired_at IS NULL
            """,
            (server_id,),
        ).fetchone()
        return dict(row) if row else None

    def resolve_vanity(self, slug: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT vanity.slug, vanity.server_id, vanity.retired_at, application.invite_url,
                   snapshot.server_name
            FROM discovery_vanity AS vanity
            JOIN discovery_applications AS application ON application.server_id=vanity.server_id
            LEFT JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=vanity.server_id
            WHERE vanity.slug=? AND application.status='approved' AND application.is_revoked=0
              AND application.invite_url<>''
            """,
            (normalize_slug(slug),),
        ).fetchone()
        if row is None:
            return None
        retired = parse_iso(row["retired_at"])
        if retired and utc_now() - retired > timedelta(days=VANITY_RETIRED_DAYS):
            return None
        current = self.vanity_for(row["server_id"]) if retired else None
        return {
            "slug": row["slug"],
            "server_id": row["server_id"],
            "server_name": row["server_name"] or "",
            "invite_url": row["invite_url"],
            "current_slug": current["slug"] if current else row["slug"],
        }

    def claim_vanity(
        self, server_id: str, value: Any, *, verified: bool, staff: bool = False, now: datetime | None = None,
    ) -> dict[str, Any]:
        """Give a listing its custom link. Staff may assign reserved names and skip the change cooldown."""
        now = now or utc_now()
        if not self.is_live(server_id):
            raise ValueError("Custom links are available once the listing is approved.")
        slug = validate_slug(value, verified=verified, staff=staff)
        current = self.vanity_for(server_id)
        if current and current["slug"] == slug:
            return current
        owner = self.connection.execute(
            "SELECT server_id, retired_at FROM discovery_vanity WHERE slug=?", (slug,)
        ).fetchone()
        if owner and owner["server_id"] != server_id:
            retired = parse_iso(owner["retired_at"])
            if not retired or (not staff and now - retired <= timedelta(days=VANITY_RETIRED_DAYS)):
                raise ValueError("That custom link is already taken.")
            self.connection.execute("DELETE FROM discovery_vanity WHERE slug=?", (slug,))
        if current:
            created = parse_iso(current["created_at"])
            if not staff and created and now - created < VANITY_CHANGE_COOLDOWN:
                raise ValueError("You can change the custom link once every 24 hours.")
            self.connection.execute(
                "UPDATE discovery_vanity SET retired_at=? WHERE slug=?", (iso(now), current["slug"])
            )
        self.connection.execute(
            """
            INSERT INTO discovery_vanity(slug, server_id, created_at, retired_at) VALUES (?, ?, ?, NULL)
            ON CONFLICT(slug) DO UPDATE SET created_at=excluded.created_at, retired_at=NULL
            """,
            (slug, server_id, iso(now)),
        )
        self.connection.commit()
        return {"slug": slug, "created_at": iso(now)}

    def release_vanity(self, server_id: str, *, immediately: bool = False) -> None:
        if immediately:
            self.connection.execute("DELETE FROM discovery_vanity WHERE server_id=?", (server_id,))
        else:
            self.connection.execute(
                "UPDATE discovery_vanity SET retired_at=? WHERE server_id=? AND retired_at IS NULL",
                (iso(utc_now()), server_id),
            )
        self.connection.commit()

    # ---------------------------------------------------------------- media

    def put_media(self, server_id: str, kind: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()[:16]
        self.connection.execute(
            """
            INSERT INTO discovery_media(server_id, kind, content_type, data, digest, updated_at)
            VALUES (?, ?, 'image/webp', ?, ?, ?)
            ON CONFLICT(server_id, kind) DO UPDATE SET
                content_type=excluded.content_type, data=excluded.data,
                digest=excluded.digest, updated_at=excluded.updated_at
            """,
            (server_id, kind, sqlite3.Binary(data), digest, iso(utc_now())),
        )
        self.connection.commit()
        return digest

    def delete_media(self, server_id: str, kind: str) -> None:
        self.connection.execute(
            "DELETE FROM discovery_media WHERE server_id=? AND kind=?", (server_id, kind)
        )
        self.connection.commit()

    def get_media(self, server_id: str, kind: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT content_type, data, digest FROM discovery_media WHERE server_id=? AND kind=?",
            (server_id, kind),
        ).fetchone()
        return dict(row) if row else None

    def stoat_media(self, server_id: str) -> dict[str, str | None]:
        row = self.connection.execute(
            "SELECT server_icon_url, server_banner_url FROM dashboard_server_snapshots WHERE server_id=?",
            (server_id,),
        ).fetchone()
        return {
            "icon_url": (row["server_icon_url"] or None) if row else None,
            "banner_url": (row["server_banner_url"] or None) if row else None,
        }

    def media_urls(self, server_id: str) -> dict[str, str | None]:
        rows = self.connection.execute(
            "SELECT kind, digest FROM discovery_media WHERE server_id=?", (server_id,)
        ).fetchall()
        urls: dict[str, str | None] = {"logo_url": None, "banner_url": None}
        for row in rows:
            urls[f"{row['kind']}_url"] = media_path(server_id, row["kind"], row["digest"])
        return urls

    # ---------------------------------------------------------------- statistics

    def record_stat(
        self, server_id: str, *, views: int = 0, joins: int = 0, link_visits: int = 0,
        source: str | None = None, day: str | None = None,
    ) -> None:
        day = day or utc_now().date().isoformat()
        column = f"src_{source}" if source in STAT_SOURCES else None
        self.connection.execute(
            f"""
            INSERT INTO discovery_stats_daily(server_id, day, views, joins, link_visits{', ' + column if column else ''})
            VALUES (?, ?, ?, ?, ?{', 1' if column else ''})
            ON CONFLICT(server_id, day) DO UPDATE SET
                views=views+excluded.views,
                joins=joins+excluded.joins,
                link_visits=link_visits+excluded.link_visits
                {f', {column}={column}+1' if column else ''}
            """,
            (server_id, day, views, joins, link_visits),
        )
        self.connection.commit()

    def stats(self, server_id: str, days: int = 30, today: datetime | None = None) -> dict[str, Any]:
        today_date = (today or utc_now()).date()
        start = today_date - timedelta(days=days - 1)
        rows = {
            row["day"]: dict(row)
            for row in self.connection.execute(
                "SELECT * FROM discovery_stats_daily WHERE server_id=? AND day>=?",
                (server_id, start.isoformat()),
            ).fetchall()
        }
        series = []
        for offset in range(days):
            day = (start + timedelta(days=offset)).isoformat()
            row = rows.get(day, {})
            series.append({
                "day": day,
                "views": int(row.get("views", 0)),
                "joins": int(row.get("joins", 0)),
                "link_visits": int(row.get("link_visits", 0)),
            })

        def total(window: list[dict[str, Any]], key: str) -> int:
            return sum(item[key] for item in window)

        last7, prev7 = series[-7:], series[-14:-7]
        sources = {
            source: sum(int(row.get(f"src_{source}", 0)) for row in rows.values())
            for source in STAT_SOURCES
        }
        totals = {key: total(series, key) for key in ("views", "joins", "link_visits")}
        return {
            "days": series,
            "totals": totals,
            "week": {key: total(last7, key) for key in ("views", "joins", "link_visits")},
            "previous_week": {key: total(prev7, key) for key in ("views", "joins", "link_visits")},
            "sources": sources,
            "join_rate": round(totals["joins"] / totals["views"], 3) if totals["views"] else None,
        }

    def spotlight(self, server_ids: list[str], today: datetime | None = None) -> str | None:
        """Server of the week: most engagement over the last seven days, with a minimum."""
        if not server_ids:
            return None
        start = ((today or utc_now()).date() - timedelta(days=6)).isoformat()
        rows = self.connection.execute(
            """
            SELECT server_id, SUM(joins) * 3 + SUM(views) + SUM(link_visits) * 2 AS score
            FROM discovery_stats_daily WHERE day>=?
            GROUP BY server_id ORDER BY score DESC, server_id
            """,
            (start,),
        ).fetchall()
        allowed = set(server_ids)
        for row in rows:
            if row["server_id"] in allowed and int(row["score"] or 0) >= 15:
                return row["server_id"]
        return None

    # ---------------------------------------------------------------- verification

    def latest_verification(self, server_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM discovery_verification_requests WHERE server_id=?
            ORDER BY id DESC LIMIT 1
            """,
            (server_id,),
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["links"] = _json_list(item.pop("links_json"))
        return item

    def request_verification(
        self, server_id: str, tier: str, reason: str, links: list[str], submitted_by: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        now = now or utc_now()
        if tier not in APPLICABLE_TIERS:
            raise ValueError("Choose the kind of verification you are applying for.")
        if not 50 <= len(reason) <= 1500:
            raise ValueError("Explain why the server should be verified in 50 to 1,500 characters.")
        if not self.is_live(server_id):
            raise ValueError("Only approved Discovery listings can apply for verification.")
        if self.get_profile(server_id)["verified_tier"]:
            raise ValueError("This server is already verified.")
        latest = self.latest_verification(server_id)
        if latest and latest["status"] == "pending":
            raise ValueError("A verification request is already waiting for review.")
        if latest and latest["status"] == "denied":
            reviewed = parse_iso(latest["reviewed_at"])
            if reviewed and now - reviewed < VERIFICATION_DENIED_COOLDOWN:
                raise ValueError(
                    "You can apply again 30 days after the last decision ("
                    + (reviewed + VERIFICATION_DENIED_COOLDOWN).date().isoformat() + ")."
                )
        self.connection.execute(
            """
            INSERT INTO discovery_verification_requests(
                server_id, tier, reason, links_json, status, submitted_by, submitted_at
            ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """,
            (server_id, tier, reason, _dumps(links), submitted_by, iso(now)),
        )
        self.connection.commit()
        return self.latest_verification(server_id) or {}

    def withdraw_verification(self, server_id: str) -> None:
        self.connection.execute(
            """
            UPDATE discovery_verification_requests SET status='withdrawn', reviewed_at=?
            WHERE server_id=? AND status='pending'
            """,
            (iso(utc_now()), server_id),
        )
        self.connection.commit()

    def list_verification_requests(self, limit: int = 60) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT request.*, snapshot.server_name, snapshot.member_count
            FROM discovery_verification_requests AS request
            LEFT JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=request.server_id
            ORDER BY request.status='pending' DESC, request.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["links"] = _json_list(item.pop("links_json"))
            items.append(item)
        return items

    def review_verification(
        self, request_id: int, decision: str, reviewed_by: str, note: str = "", tier: str | None = None,
    ) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM discovery_verification_requests WHERE id=?", (request_id,)
        ).fetchone()
        if row is None or row["status"] != "pending":
            raise ValueError("Only pending verification requests can be reviewed.")
        if decision not in {"approved", "denied"}:
            raise ValueError("Decision must be approved or denied.")
        tier = tier or row["tier"]
        if decision == "approved":
            if tier not in VERIFICATION_TIERS:
                raise ValueError("Choose a verification tier.")
            self.set_verified(row["server_id"], tier, reviewed_by, commit=False)
        self.connection.execute(
            """
            UPDATE discovery_verification_requests
            SET status=?, reviewed_by=?, reviewed_at=?, review_note=?, tier=?
            WHERE id=?
            """,
            (decision, reviewed_by, iso(utc_now()), note or None, tier, request_id),
        )
        self.connection.commit()
        return {"server_id": row["server_id"], "tier": tier, "status": decision}

    def set_verified(self, server_id: str, tier: str | None, by: str, *, commit: bool = True) -> None:
        if tier is not None and tier not in VERIFICATION_TIERS:
            raise ValueError("Unknown verification tier.")
        self._ensure_profile(server_id)
        self.connection.execute(
            """
            UPDATE discovery_profiles SET verified_tier=?, verified_at=?, verified_by=?, updated_at=?
            WHERE server_id=?
            """,
            (tier, iso(utc_now()) if tier else None, by if tier else None, iso(utc_now()), server_id),
        )
        if commit:
            self.connection.commit()

    # ---------------------------------------------------------------- reports

    def add_report(self, server_id: str, reason: str, details: str) -> int:
        if reason not in REPORT_REASONS:
            raise ValueError("Choose a reason for the report.")
        if len(details) > 1000:
            raise ValueError("Details must be 1,000 characters or fewer.")
        cursor = self.connection.execute(
            """
            INSERT INTO discovery_listing_reports(server_id, reason, details, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (server_id, reason, details, iso(utc_now())),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def list_reports(self, limit: int = 60) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT report.*, snapshot.server_name
            FROM discovery_listing_reports AS report
            LEFT JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=report.server_id
            ORDER BY report.status='open' DESC, report.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]

    def resolve_report(self, report_id: int, status: str, by: str) -> None:
        if status not in {"resolved", "dismissed"}:
            raise ValueError("Status must be resolved or dismissed.")
        cursor = self.connection.execute(
            """
            UPDATE discovery_listing_reports SET status=?, resolved_by=?, resolved_at=?
            WHERE id=? AND status='open'
            """,
            (status, by, iso(utc_now()), report_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("Only open reports can be closed.")
        self.connection.commit()

    # ---------------------------------------------------------------- public listing

    def enrich(self, servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ids = [str(server["server_id"]) for server in servers]
        if not ids:
            return servers
        marks = ",".join("?" for _ in ids)
        profiles = {
            row["server_id"]: row
            for row in self.connection.execute(
                f"SELECT * FROM discovery_profiles WHERE server_id IN ({marks})", ids
            ).fetchall()
        }
        vanity = {
            row["server_id"]: row["slug"]
            for row in self.connection.execute(
                f"SELECT server_id, slug FROM discovery_vanity WHERE retired_at IS NULL AND server_id IN ({marks})",
                ids,
            ).fetchall()
        }
        media: dict[str, dict[str, str]] = defaultdict(dict)
        for row in self.connection.execute(
            f"SELECT server_id, kind, digest FROM discovery_media WHERE server_id IN ({marks})", ids
        ).fetchall():
            media[row["server_id"]][row["kind"]] = media_path(row["server_id"], row["kind"], row["digest"])
        for server in servers:
            server_id = str(server["server_id"])
            profile = profiles.get(server_id)
            tier = profile["verified_tier"] if profile else None
            server["verified"] = (
                {"tier": tier, "label": VERIFICATION_TIERS[tier]} if tier in VERIFICATION_TIERS else None
            )
            server["vanity"] = vanity.get(server_id)
            server["logo_url"] = media[server_id].get("logo")
            server["custom_banner_url"] = media[server_id].get("banner")
            server["language"] = profile["language"] if profile else ""
            server["categories"] = _json_list(profile["categories_json"]) if profile else []
            server["links"] = _json_list(profile["links_json"]) if profile else []
        return servers

    # ---------------------------------------------------------------- housekeeping

    def prune(self, now: datetime | None = None) -> None:
        now = now or utc_now()
        self.connection.execute(
            "DELETE FROM discovery_stats_daily WHERE day<?", ((now - timedelta(days=400)).date().isoformat(),)
        )
        self.connection.execute(
            "DELETE FROM discovery_vanity WHERE retired_at IS NOT NULL AND retired_at<?",
            (iso(now - timedelta(days=VANITY_RETIRED_DAYS)),),
        )
        self.connection.execute(
            "DELETE FROM discovery_listing_edits WHERE status<>'held' AND created_at<?",
            (iso(now - timedelta(days=180)),),
        )
        self.connection.execute(
            "DELETE FROM discovery_listing_reports WHERE status<>'open' AND resolved_at<?",
            (iso(now - timedelta(days=90)),),
        )
        self.connection.execute(
            "DELETE FROM discovery_verification_requests WHERE status IN ('denied', 'withdrawn') AND reviewed_at<?",
            (iso(now - timedelta(days=365)),),
        )
        self.connection.commit()

    def due_bump_reminders(self, now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or utc_now()
        rows = self.connection.execute(
            """
            SELECT profile.server_id, profile.reminded_for_bump, application.last_bumped_at,
                   snapshot.server_name
            FROM discovery_profiles AS profile
            JOIN discovery_applications AS application ON application.server_id=profile.server_id
            LEFT JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=profile.server_id
            WHERE profile.bump_reminders=1 AND application.status='approved' AND application.is_revoked=0
            """
        ).fetchall()
        due = []
        for row in rows:
            marker = row["last_bumped_at"] or "never"
            if row["reminded_for_bump"] == marker:
                continue
            bumped = parse_iso(row["last_bumped_at"])
            if bumped and now - bumped < BUMP_COOLDOWN:
                continue
            due.append({"server_id": row["server_id"], "server_name": row["server_name"] or "", "marker": marker})
        return due

    def mark_reminded(self, server_id: str, marker: str) -> None:
        self.connection.execute(
            "UPDATE discovery_profiles SET reminded_for_bump=? WHERE server_id=?", (marker, server_id)
        )
        self.connection.commit()

    def due_digests(self, now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or utc_now()
        if now.weekday() != 0 or now.hour < 9:
            return []
        week = "%d-W%02d" % now.isocalendar()[:2]
        rows = self.connection.execute(
            """
            SELECT profile.server_id, snapshot.server_name
            FROM discovery_profiles AS profile
            JOIN discovery_applications AS application ON application.server_id=profile.server_id
            LEFT JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=profile.server_id
            WHERE profile.weekly_digest=1 AND application.status='approved' AND application.is_revoked=0
              AND COALESCE(profile.digest_week, '')<>?
            """,
            (week,),
        ).fetchall()
        return [{"server_id": row["server_id"], "server_name": row["server_name"] or "", "week": week} for row in rows]

    def mark_digest(self, server_id: str, week: str) -> None:
        self.connection.execute(
            "UPDATE discovery_profiles SET digest_week=? WHERE server_id=?", (week, server_id)
        )
        self.connection.commit()


def media_path(server_id: str, kind: str, digest: str) -> str:
    return f"/api/public/discovery/media/{quote(server_id, safe='')}/{kind}.webp?v={digest[:12]}"


def digest_text(stats: dict[str, Any]) -> str:
    week, previous = stats["week"], stats["previous_week"]

    def change(key: str) -> str:
        if not previous[key]:
            return ""
        delta = round((week[key] - previous[key]) / previous[key] * 100)
        return f" ({'+' if delta >= 0 else ''}{delta}% on the week before)"

    sources = {key: value for key, value in stats["sources"].items() if value}
    names = {"search": "search engines", "discovery": "Stoatmod Discovery", "stoat": "Stoat", "direct": "direct visits", "other": "other websites"}
    top = max(sources, key=sources.get) if sources else None
    lines = [
        f"**Profile views:** {week['views']:,}{change('views')}",
        f"**Join clicks:** {week['joins']:,}{change('joins')}",
        f"**Custom link visits:** {week['link_visits']:,}{change('link_visits')}",
    ]
    if top:
        lines.append(f"**Most visitors came from:** {names[top]}")
    lines.append("\nFull charts are in Dashboard → Discovery. Turn this summary off there at any time.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- automatic checks


@dataclass
class CheckOutcome:
    hold: bool
    reason: str = ""


class ListingChecks:
    """Runs the same classifier the bot uses, plus an invite ownership check."""

    def __init__(self, stoat_api_base: str, threshold: float) -> None:
        self.stoat_api_base = stoat_api_base.rstrip("/")
        self.threshold = threshold

    def _moderator(self) -> Any:
        base_url = os.getenv("LOCAL_AI_BASE_URL", "").strip()
        version = os.getenv("LOCAL_AI_EXPECTED_VERSION", "").strip()
        if not base_url or not version:
            return None
        from moderation import StoatGuardModerator

        return StoatGuardModerator(
            base_url=base_url, expected_version=version,
            api_key=os.getenv("LOCAL_AI_API_KEY", "").strip(), timeout_seconds=30,
        )

    @staticmethod
    def _blocked(result: Any, threshold: float) -> list[str]:
        import moderation

        support_only = getattr(moderation, "SUPPORT_ONLY_CATEGORIES", frozenset())
        return [name for name in result.blocked_categories(threshold) if name not in support_only]

    async def text(self, texts: list[str]) -> CheckOutcome:
        texts = [text for text in texts if text.strip()]
        if not texts:
            return CheckOutcome(False)
        moderator = self._moderator()
        if moderator is None:
            return CheckOutcome(True, "automatic checks are not configured")
        try:
            async with moderator:
                blocked: set[str] = set()
                for text in texts:
                    result = await moderator.classify_text(text, thinking=True)
                    blocked.update(self._blocked(result, self.threshold))
        except Exception:  # noqa: BLE001 - any failure holds the edit for a person
            logger.warning("discovery_text_check_unavailable", exc_info=True)
            return CheckOutcome(True, "automatic checks were unavailable")
        if blocked:
            return CheckOutcome(True, "possible " + ", ".join(sorted(blocked)).replace("_", " "))
        return CheckOutcome(False)

    async def image(self, data: bytes, content_type: str = "image/webp") -> CheckOutcome:
        moderator = self._moderator()
        if moderator is None:
            return CheckOutcome(True, "image checks are not configured")
        try:
            import moderation

            async with moderator:
                body = await moderator._request_json(
                    "POST", moderator.image_endpoint,
                    payload={
                        "image": f"data:{content_type};base64," + base64.b64encode(data).decode("ascii"),
                        "caption": "", "policy_mode": "stoat",
                    },
                )
                if body.get("version") != moderator.expected_version:
                    raise moderation.ModerationError("unexpected model version")
                result = moderator._validate_result(
                    body.get("result"), expected_categories=moderation.IMAGE_MODERATION_CATEGORIES
                )
        except Exception:  # noqa: BLE001
            logger.warning("discovery_image_check_unavailable", exc_info=True)
            return CheckOutcome(True, "image checks were unavailable")
        blocked = self._blocked(result, self.threshold)
        if blocked:
            return CheckOutcome(True, "possible " + ", ".join(sorted(blocked)).replace("_", " "))
        return CheckOutcome(False)

    async def invite_server(self, invite_url: str) -> str | None:
        """Return the server an invite opens. Raises ValueError for a dead invite, None if unknown."""
        code = invite_code(invite_url)
        if not code or not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", code):
            raise ValueError("Enter a valid Stoat server invite URL.")
        try:
            async with ClientSession(
                timeout=ClientTimeout(total=6),
                headers={"User-Agent": "Stoatmod/1.0 (+https://modstoat.site)"},
            ) as session:
                async with session.get(f"{self.stoat_api_base}/invites/{quote(code, safe='')}") as response:
                    if response.status == 404:
                        raise ValueError("That invite has expired or does not exist.")
                    if response.status != 200:
                        return None
                    payload = await response.json()
        except ValueError:
            raise
        except Exception:  # noqa: BLE001
            logger.warning("discovery_invite_check_unavailable", exc_info=True)
            return None
        if not isinstance(payload, dict) or payload.get("type") != "Server":
            raise ValueError("That invite is not a server invite.")
        return str(payload.get("server_id") or "") or None


# --------------------------------------------------------------------------- HTTP layer


@dataclass
class Hooks:
    database: Callable[[web.Request], Any]
    session: Callable[[web.Request], tuple[str, str]]
    require_csrf: Callable[[web.Request], None]
    json_error: Callable[[str, int], web.Response]
    client_ip: Callable[[web.Request], str]
    listing_fields: Callable[[dict[str, Any]], tuple[str, str, str, list[str]]]
    validate_turnstile: Callable[..., Awaitable[bool]]
    turnstile_configured: Callable[[], bool]
    system_actor: str
    turnstile_site_key: str = ""


HOOKS_KEY = web.AppKey("discovery_hooks", Hooks)
STORE_KEY = web.AppKey("discovery_store", DiscoveryExtrasStore)
CHECKS_KEY = web.AppKey("discovery_checks", ListingChecks)
LIMITER_KEY = web.AppKey("discovery_limiter", dict)


class RateLimiter:
    """Short-lived, in-memory only. Keys are keyed hashes, so raw addresses are never kept."""

    def __init__(self) -> None:
        self._salt = secrets.token_bytes(32)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._seen: dict[str, float] = {}

    def _key(self, *parts: str) -> str:
        return hmac.new(self._salt, "|".join(parts).encode(), hashlib.sha256).hexdigest()[:24]

    def allow(self, ip: str, bucket: str, limit: int, window: float, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        events = self._events[self._key(bucket, ip)]
        while events and now - events[0] > window:
            events.popleft()
        if len(events) >= limit:
            return False
        events.append(now)
        return True

    def first_time(self, ip: str, *parts: str, window: float = 1800, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        key = self._key(ip, *parts)
        seen = self._seen.get(key)
        if seen is not None and now - seen < window:
            return False
        self._seen[key] = now
        return True

    def prune(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        for key, events in list(self._events.items()):
            while events and now - events[0] > 3600:
                events.popleft()
            if not events:
                self._events.pop(key, None)
        for key, seen in list(self._seen.items()):
            if now - seen > 3600:
                self._seen.pop(key, None)


def _hooks(request: web.Request) -> Hooks:
    return request.app[HOOKS_KEY]


def _store(request: web.Request) -> DiscoveryExtrasStore:
    return request.app[STORE_KEY]


def _limiter(request: web.Request) -> RateLimiter:
    return request.app[LIMITER_KEY]["limiter"]


def _error(request: web.Request, message: str, status: int = 400) -> web.Response:
    return _hooks(request).json_error(message, status)


async def _json_body(request: web.Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception as exc:  # noqa: BLE001
        raise ValueError("A JSON request body is required.") from exc
    if not isinstance(payload, dict):
        raise ValueError("A JSON request body is required.")
    return payload


def _redirect(location: str) -> web.Response:
    return web.Response(
        status=302,
        headers={"Location": location, "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
    )


def _log_to_server(request: web.Request, server_id: str, title: str, description: str, *, positive: bool) -> None:
    hooks = _hooks(request)
    try:
        hooks.database(request).enqueue_dashboard_action(
            server_id, "discovery_status_log", hooks.system_actor,
            {"status": "approved" if positive else "updated", "title": title, "description": description},
        )
    except Exception:  # noqa: BLE001 - a log message never blocks the change itself
        logger.warning("discovery_log_enqueue_failed server_id=%s", server_id, exc_info=True)


def _proposed_listing(hooks: Hooks, payload: dict[str, Any]) -> dict[str, Any]:
    # The long description has its own (larger, Markdown-aware) limit below.
    description, _information, invite_url, tags = hooks.listing_fields({**payload, "information": ""})
    return {
        "description": description,
        "information": validate_information(payload.get("information", "")),
        "invite_url": invite_url,
        "tags": tags,
        "language": validate_language(payload.get("language")),
        "categories": validate_categories(payload.get("categories")),
        "links": validate_links(payload.get("links")),
    }


async def run_edit_checks(
    checks: ListingChecks, server_id: str, previous: dict[str, Any], proposed: dict[str, Any],
) -> CheckOutcome:
    """Decide whether an edit to a live listing can go live straight away."""
    reasons: list[str] = []
    if proposed["invite_url"] != previous["invite_url"]:
        invite_server = await checks.invite_server(proposed["invite_url"])
        if invite_server is None:
            reasons.append("the new invite could not be checked")
        elif invite_server != server_id:
            raise ValueError("That invite opens a different server. Use an invite to this server.")
    new_urls = set(text_urls(proposed["description"], proposed["information"]) + proposed["links"])
    old_urls = set(text_urls(previous["description"], previous["information"]) + previous["links"])
    if uses_link_shortener(sorted(new_urls - old_urls)):
        reasons.append("a shortened link hides where it goes")
    texts = []
    if proposed["description"] != previous["description"]:
        texts.append(proposed["description"])
    if proposed["information"] != previous["information"]:
        texts.append(proposed["information"])
    if proposed["tags"] != previous["tags"]:
        texts.append("Tags: " + ", ".join(proposed["tags"]))
    outcome = await checks.text(texts)
    if outcome.hold:
        reasons.append(outcome.reason)
    return CheckOutcome(bool(reasons), "; ".join(reasons))


async def dashboard_extras(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, _user_id = hooks.session(request)
    store = _store(request)
    profile = store.get_profile(server_id)
    payload = {
        "profile": profile,
        "verified": (
            {"tier": profile["verified_tier"], "label": VERIFICATION_TIERS[profile["verified_tier"]]}
            if profile["verified_tier"] else None
        ),
        "verification_request": store.latest_verification(server_id),
        "vanity": store.vanity_for(server_id),
        "media": store.media_urls(server_id),
        # The icon and banner set on Stoat, used when no custom logo or banner is uploaded.
        "stoat_media": store.stoat_media(server_id),
        "stats": store.stats(server_id, 30),
        "held_edit": store.held_edit(server_id),
        "edits": store.list_edits(server_id, 10),
        "options": {
            "languages": list(LANGUAGES),
            "categories": list(CATEGORY_SLUGS),
            "verification_tiers": {tier: VERIFICATION_TIERS[tier] for tier in APPLICABLE_TIERS},
            "information_max": INFORMATION_MAX,
            "max_links": MAX_LINKS,
            "max_categories": MAX_CATEGORIES,
        },
    }
    response = web.json_response(payload)
    response.headers["Cache-Control"] = "no-store"
    return response


async def apply_for_discovery(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, user_id = hooks.session(request)
    hooks.require_csrf(request)
    store = _store(request)
    try:
        payload = await _json_body(request)
        fields = _proposed_listing(hooks, payload)
        result = hooks.database(request).submit_discovery_application(
            server_id, user_id, fields["description"], fields["information"], fields["invite_url"], fields["tags"]
        )
        store.save_profile_fields(server_id, fields["language"], fields["categories"], fields["links"])
        store.connection.commit()
    except ValueError as exc:
        return _error(request, str(exc))
    return web.json_response(result, status=201)


async def update_listing(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, user_id = hooks.session(request)
    hooks.require_csrf(request)
    store = _store(request)
    database = hooks.database(request)
    try:
        payload = await _json_body(request)
        proposed = _proposed_listing(hooks, payload)
        current = store.get_listing(server_id)
        if current is None:
            raise ValueError("Apply for discovery before saving listing details.")
        if all(current[key] == proposed[key] for key in LISTING_FIELDS):
            return web.json_response({**database.get_discovery_application(server_id), "edit": None})
        if current["status"] != "approved":
            # Not public yet (or removed): the content is reviewed with the application.
            store.write_listing(server_id, proposed, user_id)
            store.connection.commit()
            return web.json_response({**database.get_discovery_application(server_id), "edit": None})
        outcome = await run_edit_checks(request.app[CHECKS_KEY], server_id, current, proposed)
        store.close_held_edits(server_id, "superseded")
        if outcome.hold:
            edit_id = store.record_edit(server_id, current, proposed, "held", outcome.reason, user_id)
        else:
            store.write_listing(server_id, proposed, user_id)
            edit_id = store.record_edit(server_id, current, proposed, "live", "", user_id)
        store.connection.commit()
    except ValueError as exc:
        store.connection.rollback()
        return _error(request, str(exc))
    database.add_event(
        server_id=server_id, event_type="discovery_listing_edited", actor_id=user_id,
        details={"edit_id": edit_id, "held": outcome.hold},
    )
    return web.json_response({
        **database.get_discovery_application(server_id),
        "edit": {"id": edit_id, "status": "held" if outcome.hold else "live", "reason": outcome.reason},
    })


async def withdraw_held_edit(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, user_id = hooks.session(request)
    hooks.require_csrf(request)
    store = _store(request)
    store.close_held_edits(server_id, "withdrawn", user_id)
    store.connection.commit()
    return web.json_response({"ok": True})


async def update_notifications(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, _user_id = hooks.session(request)
    hooks.require_csrf(request)
    try:
        payload = await _json_body(request)
    except ValueError as exc:
        return _error(request, str(exc))
    _store(request).set_notifications(
        server_id, bool(payload.get("bump_reminders")), bool(payload.get("weekly_digest"))
    )
    return web.json_response({"profile": _store(request).get_profile(server_id)})


async def claim_vanity(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, user_id = hooks.session(request)
    hooks.require_csrf(request)
    store = _store(request)
    try:
        payload = await _json_body(request)
        vanity = store.claim_vanity(
            server_id, payload.get("slug"), verified=bool(store.get_profile(server_id)["verified_tier"])
        )
    except ValueError as exc:
        store.connection.rollback()
        return _error(request, str(exc))
    hooks.database(request).add_event(
        server_id=server_id, event_type="discovery_custom_link_changed", actor_id=user_id,
        details={"slug": vanity["slug"]},
    )
    return web.json_response({"vanity": vanity})


async def remove_vanity(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, _user_id = hooks.session(request)
    hooks.require_csrf(request)
    _store(request).release_vanity(server_id)
    return web.json_response({"vanity": None})


async def _read_upload(request: web.Request) -> bytes:
    if not request.content_type.startswith("multipart/"):
        raise ValueError("Upload the image as a file.")
    reader = await request.multipart()
    async for field in reader:
        if getattr(field, "name", None) != "file":
            continue
        data = bytearray()
        while chunk := await field.read_chunk(64 * 1024):
            data.extend(chunk)
            if len(data) > MEDIA_MAX_UPLOAD_BYTES:
                raise ValueError("Images must be 2 MB or smaller.")
        return bytes(data)
    raise ValueError("Choose an image to upload.")


async def upload_media(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, user_id = hooks.session(request)
    hooks.require_csrf(request)
    kind = request.match_info["kind"]
    if kind not in {"logo", "banner"}:
        raise web.HTTPNotFound()
    store = _store(request)
    if store.get_listing(server_id) is None:
        return _error(request, "Apply for Discovery before adding images.")
    if not _limiter(request).allow(server_id, "media-upload", 12, 3600):
        return _error(request, "Too many uploads. Try again in an hour.", 429)
    try:
        data = await _read_upload(request)
        processed = await asyncio.get_running_loop().run_in_executor(None, process_media, data, kind)
    except ValueError as exc:
        return _error(request, str(exc))
    outcome = await request.app[CHECKS_KEY].image(processed)
    if outcome.hold:
        if "unavailable" in outcome.reason or "not configured" in outcome.reason:
            return _error(request, "Image checks are temporarily unavailable. Try again in a few minutes.", 503)
        return _error(request, "This image cannot be used on Discovery. Choose a different one.", 422)
    store.put_media(server_id, kind, processed)
    hooks.database(request).add_event(
        server_id=server_id, event_type="discovery_media_updated", actor_id=user_id, details={"kind": kind},
    )
    return web.json_response({"media": store.media_urls(server_id)})


async def delete_media(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, _user_id = hooks.session(request)
    hooks.require_csrf(request)
    kind = request.match_info["kind"]
    if kind not in {"logo", "banner"}:
        raise web.HTTPNotFound()
    _store(request).delete_media(server_id, kind)
    return web.json_response({"media": _store(request).media_urls(server_id)})


async def apply_for_verification(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, user_id = hooks.session(request)
    hooks.require_csrf(request)
    try:
        payload = await _json_body(request)
        verification = _store(request).request_verification(
            server_id,
            str(payload.get("tier", "")).strip(),
            str(payload.get("reason", "")).strip(),
            validate_links(payload.get("links")),
            user_id,
        )
    except ValueError as exc:
        return _error(request, str(exc))
    return web.json_response({"verification_request": verification}, status=201)


async def withdraw_verification(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    server_id, _user_id = hooks.session(request)
    hooks.require_csrf(request)
    _store(request).withdraw_verification(server_id)
    return web.json_response({"verification_request": _store(request).latest_verification(server_id)})


# ------------------------------------------------------------------ public endpoints


def _public_listing(request: web.Request, server_id: str) -> dict[str, Any] | None:
    row = _store(request).connection.execute(
        """
        SELECT server_id, invite_url FROM discovery_applications
        WHERE lower(server_id)=lower(?) AND status='approved' AND is_revoked=0 AND invite_url<>''
        """,
        (server_id,),
    ).fetchone()
    return dict(row) if row else None


def _count(request: web.Request, server_id: str, kind: str, source: str) -> None:
    if is_automated(request.headers.get("User-Agent")):
        return
    ip = _hooks(request).client_ip(request)
    limiter = _limiter(request)
    if not limiter.allow(ip, "discovery-stats", 120, 600):
        return
    if not limiter.first_time(ip, kind, server_id):
        return
    store = _store(request)
    if kind == "view":
        store.record_stat(server_id, views=1, source=source)
    elif kind == "join":
        store.record_stat(server_id, joins=1)
    else:
        store.record_stat(server_id, link_visits=1, source=source)


async def public_record_view(request: web.Request) -> web.Response:
    try:
        payload = await _json_body(request)
    except ValueError:
        return web.Response(status=204)
    server_id = str(payload.get("server_id", "")).strip()
    source = str(payload.get("source", "")).strip()
    if source not in STAT_SOURCES:
        source = "other"
    listing = _public_listing(request, server_id) if server_id.isalnum() and len(server_id) <= 64 else None
    if listing:
        _count(request, listing["server_id"], "view", source)
    return web.Response(status=204, headers={"Cache-Control": "no-store"})


async def public_join(request: web.Request) -> web.Response:
    server_id = request.match_info["server_id"]
    listing = _public_listing(request, server_id) if server_id.isalnum() and len(server_id) <= 64 else None
    if listing is None:
        raise web.HTTPNotFound(reason="This server is not listed on Discovery.")
    _count(request, listing["server_id"], "join", "discovery")
    return _redirect(listing["invite_url"])


async def public_vanity(request: web.Request) -> web.Response:
    vanity = _store(request).resolve_vanity(request.match_info["slug"])
    if vanity is None:
        raise web.HTTPNotFound(reason="This custom link does not exist.")
    response = web.json_response({
        "slug": vanity["slug"], "current_slug": vanity["current_slug"],
        "server_id": vanity["server_id"], "server_name": vanity["server_name"],
    })
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


async def public_vanity_go(request: web.Request) -> web.Response:
    vanity = _store(request).resolve_vanity(request.match_info["slug"])
    if vanity is None:
        raise web.HTTPNotFound(reason="This custom link does not exist.")
    _count(request, vanity["server_id"], "link", classify_referrer(request.headers.get("Referer")))
    return _redirect(vanity["invite_url"])


async def public_media(request: web.Request) -> web.Response:
    server_id = request.match_info["server_id"]
    kind = request.match_info["kind"]
    if kind not in {"logo", "banner"} or not server_id.isalnum():
        raise web.HTTPNotFound()
    media = _store(request).get_media(server_id, kind)
    if media is None:
        raise web.HTTPNotFound()
    return web.Response(
        body=media["data"], content_type=media["content_type"],
        headers={"Cache-Control": "public, max-age=86400, stale-while-revalidate=604800", "ETag": f'"{media["digest"]}"'},
    )


async def public_report(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    try:
        payload = await _json_body(request)
        server_id = str(payload.get("server_id", "")).strip()
        reason = str(payload.get("reason", "")).strip()
        details = str(payload.get("details", "")).strip()
        listing = _public_listing(request, server_id) if server_id.isalnum() and len(server_id) <= 64 else None
        if listing is None:
            raise ValueError("This server is not listed on Discovery.")
        if not _limiter(request).allow(hooks.client_ip(request), "discovery-report", 5, 3600):
            return _error(request, "Too many reports. Try again later.", 429)
        if hooks.turnstile_configured():
            try:
                passed = await hooks.validate_turnstile(
                    str(payload.get("turnstile_token", "")), expected_action="discovery-report"
                )
            except Exception:  # noqa: BLE001
                return _error(request, "The security check is unavailable. Try again shortly.", 503)
            if not passed:
                return _error(request, "Complete the security check and try again.")
        report_id = _store(request).add_report(listing["server_id"], reason, details)
    except ValueError as exc:
        return _error(request, str(exc))
    return web.json_response({"ok": True, "id": report_id}, status=201)


async def public_report_config(request: web.Request) -> web.Response:
    hooks = _hooks(request)
    configured = hooks.turnstile_configured()
    response = web.json_response({
        "reasons": REPORT_REASONS,
        "turnstile_configured": configured,
        "turnstile_site_key": hooks.turnstile_site_key if configured else "",
    })
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


def badge_svg(name: str, members: int, verified: bool) -> str:
    """A small "Listed on Stoatmod Discovery" badge for server websites and READMEs."""
    from xml.sax.saxutils import escape

    label = "Stoatmod Discovery"
    value = f"{members:,} member{'s' if members != 1 else ''}"
    tick = 18 if verified else 0
    left = 14 + int(len(label) * 7.2) + 12
    right = 12 + tick + int(len(value) * 7.6) + 12
    width = left + right
    check = (
        f'<circle cx="{left + 19}" cy="14" r="7" fill="#72c591"/>'
        f'<path d="M{left + 15.6} 14.2l2.4 2.4 4.4-4.6" fill="none" stroke="#0d0d0d" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
    ) if verified else ""
    title = escape(f"{name} – listed on Stoatmod Discovery")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="28" viewBox="0 0 {width} 28" role="img" aria-label="{title}">'
        f"<title>{title}</title>"
        f'<rect width="{width}" height="28" rx="7" fill="#0d0d0d"/>'
        f'<rect x="{left}" width="{right}" height="28" rx="7" fill="#f4f4f1"/>'
        f'<rect x="{left}" width="8" height="28" fill="#f4f4f1"/>'
        f'<g font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" font-weight="600">'
        f'<text x="14" y="18" fill="#f4f4f1">{label}</text>{check}'
        f'<text x="{left + 12 + tick}" y="18" fill="#0d0d0d">{escape(value)}</text></g></svg>'
    )


async def public_badge(request: web.Request) -> web.Response:
    server_id = request.match_info["server_id"]
    if not server_id.isalnum() or len(server_id) > 64:
        raise web.HTTPNotFound()
    row = _store(request).connection.execute(
        """
        SELECT application.server_id, snapshot.server_name, snapshot.member_count
        FROM discovery_applications AS application
        JOIN dashboard_server_snapshots AS snapshot ON snapshot.server_id=application.server_id
        WHERE lower(application.server_id)=lower(?) AND application.status='approved' AND application.is_revoked=0
        """,
        (server_id,),
    ).fetchone()
    if row is None:
        raise web.HTTPNotFound()
    verified = bool(_store(request).get_profile(row["server_id"])["verified_tier"])
    return web.Response(
        text=badge_svg(row["server_name"] or "Stoat server", int(row["member_count"] or 0), verified),
        content_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=3600, stale-while-revalidate=86400"},
    )


# ------------------------------------------------------------------ staff endpoints


# ------------------------------------------------------------------ background work


async def run_housekeeping(app: web.Application, now: datetime | None = None) -> None:
    store = app[STORE_KEY]
    hooks = app[HOOKS_KEY]
    store.prune(now)
    app[LIMITER_KEY]["limiter"].prune()
    db = hooks.database(_AppRequest(app))
    for item in store.due_bump_reminders(now):
        db.enqueue_dashboard_action(
            item["server_id"], "discovery_status_log", hooks.system_actor,
            {
                "status": "approved",
                "title": "Your Discovery listing can be bumped",
                "description": (
                    f"{item['server_name'] or 'This server'} can be bumped again. Use `~bump` or the Bump "
                    "button in Dashboard → Discovery to move it to the top of Stoatmod Discovery.\n\n"
                    "Turn these reminders off in Dashboard → Discovery."
                ),
            },
        )
        store.mark_reminded(item["server_id"], item["marker"])
    for item in store.due_digests(now):
        db.enqueue_dashboard_action(
            item["server_id"], "discovery_status_log", hooks.system_actor,
            {
                "status": "approved",
                "title": "Your week on Stoatmod Discovery",
                "description": digest_text(store.stats(item["server_id"], 14, now)),
            },
        )
        store.mark_digest(item["server_id"], item["week"])


class _AppRequest:
    """Lets the request-based database hook run outside a request."""

    def __init__(self, app: web.Application) -> None:
        self.app = app


async def _background(app: web.Application):
    async def loop() -> None:
        while True:
            try:
                await run_housekeeping(app)
            except Exception:  # noqa: BLE001
                logger.exception("discovery_housekeeping_failed")
            await asyncio.sleep(300)

    task = asyncio.create_task(loop())
    yield
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def register(app: web.Application, hooks: Hooks, connection: sqlite3.Connection, *, stoat_api_base: str, threshold: float) -> None:
    app[HOOKS_KEY] = hooks
    app[STORE_KEY] = DiscoveryExtrasStore(connection)
    app[CHECKS_KEY] = ListingChecks(stoat_api_base, threshold)
    app[LIMITER_KEY] = {"limiter": RateLimiter()}
    router = app.router
    router.add_post("/api/discovery/apply", apply_for_discovery)
    router.add_put("/api/discovery/listing", update_listing)
    router.add_get("/api/discovery/extras", dashboard_extras)
    router.add_delete("/api/discovery/edits/held", withdraw_held_edit)
    router.add_put("/api/discovery/notifications", update_notifications)
    router.add_put("/api/discovery/vanity", claim_vanity)
    router.add_delete("/api/discovery/vanity", remove_vanity)
    router.add_post("/api/discovery/media/{kind}", upload_media)
    router.add_delete("/api/discovery/media/{kind}", delete_media)
    router.add_post("/api/discovery/verification", apply_for_verification)
    router.add_delete("/api/discovery/verification", withdraw_verification)
    router.add_post("/api/public/discovery/view", public_record_view)
    router.add_get("/api/public/discovery/join/{server_id}", public_join)
    router.add_get("/api/public/discovery/vanity/{slug}", public_vanity)
    router.add_get("/api/public/discovery/go/{slug}", public_vanity_go)
    router.add_get("/api/public/discovery/media/{server_id}/{kind}.webp", public_media)
    router.add_post("/api/public/discovery/report", public_report)
    router.add_get("/api/public/discovery/report-config", public_report_config)
    router.add_get("/api/public/discovery/badge/{server_id}.svg", public_badge)
    app.cleanup_ctx.append(_background)


