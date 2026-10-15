"""Durable, server-scoped admission forms and their DM conversations.

All decisions use conditional SQL updates. The decision and its bot action are
committed together, so a restart cannot lose an approval or an expiry kick.
"""
from __future__ import annotations

import json
import secrets
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from application_embeds import APPLICATION_PRIVACY_VERSION, DEFAULT_APPEARANCE, validate_appearance


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def seven_days() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(timespec="seconds")


OPEN_STATES = ("screening", "answering", "submitted")


class ApplicationStore:
    def __init__(self, database: Any):
        self.database = database
        self.connection = database.connection
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS join_form_settings (
                server_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                questions_json TEXT NOT NULL DEFAULT '[]',
                introduction TEXT NOT NULL DEFAULT '',
                version INTEGER NOT NULL DEFAULT 0,
                access_role_id TEXT,
                setup_status TEXT NOT NULL DEFAULT 'disabled',
                setup_error TEXT,
                visible_channel_ids_json TEXT NOT NULL DEFAULT '[]',
                gate_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS join_applications (
                id TEXT PRIMARY KEY, server_id TEXT NOT NULL, user_id TEXT NOT NULL,
                joined_at TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                status TEXT NOT NULL, screening_required INTEGER NOT NULL,
                screening_passed INTEGER NOT NULL DEFAULT 0,
                questions_json TEXT NOT NULL, introduction TEXT NOT NULL,
                form_version INTEGER NOT NULL, access_role_id TEXT NOT NULL,
                previous_timeout TEXT, verification_timeout TEXT,
                submitted_at TEXT, reviewed_at TEXT, reviewer_id TEXT, reason TEXT,
                enforcement_status TEXT NOT NULL DEFAULT 'pending',
                error TEXT, prompt_message_id TEXT, dm_channel_id TEXT,
                prompt_position INTEGER NOT NULL DEFAULT -1,
                notification_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(server_id, user_id, joined_at)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS join_applications_one_open
                ON join_applications(server_id, user_id)
                WHERE status IN ('screening','answering','submitted');
            CREATE INDEX IF NOT EXISTS join_applications_expiry
                ON join_applications(status, expires_at);
            CREATE TABLE IF NOT EXISTS join_application_answers (
                application_id TEXT NOT NULL REFERENCES join_applications(id) ON DELETE CASCADE,
                position INTEGER NOT NULL, message_id TEXT NOT NULL UNIQUE,
                answer TEXT NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY(application_id, position)
            );
            CREATE TABLE IF NOT EXISTS join_application_dm_sessions (
                user_id TEXT PRIMARY KEY, application_id TEXT NOT NULL
                    REFERENCES join_applications(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS join_application_notifications (
                server_id TEXT NOT NULL, user_id TEXT NOT NULL, enabled INTEGER NOT NULL,
                PRIMARY KEY(server_id, user_id)
            );
        """)
        # The bot and API can start together. Hold SQLite's write lock across
        # both the column check and ALTER so only one process migrates a column.
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            for table, additions in (
                ("join_form_settings", {"visible_channel_ids_json": "[]", "appearance_json": "{}"}),
                ("join_applications", {"appearance_json": "{}", "timeout_history_json": "[]",
                                       "privacy_notice_version": "", "privacy_version": "", "privacy_accepted_at": ""}),
            ):
                columns = {row[1] for row in self.connection.execute(f"PRAGMA table_info({table})")}
                for column, default in additions.items():
                    if column not in columns:
                        self.connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT NOT NULL DEFAULT '{default}'")
            if not self.connection.execute("SELECT 1 FROM app_metadata WHERE key='application_privacy_v1'").fetchone():
                for row in self.connection.execute("SELECT id,submitted_at FROM join_applications WHERE submitted_at IS NOT NULL").fetchall():
                    deadline = (datetime.fromisoformat(row["submitted_at"]) + timedelta(days=14)).isoformat(timespec="seconds")
                    self.connection.execute("UPDATE join_applications SET expires_at=? WHERE id=?", (deadline, row["id"]))
                # Existing unfinished questionnaires must show the new notice.
                self.connection.execute("""UPDATE join_applications SET prompt_message_id=NULL,prompt_position=-1,error=NULL
                    WHERE status IN ('screening','answering')""")
                self.connection.execute("INSERT INTO app_metadata(key,value) VALUES('application_privacy_v1','1')")

    def settings(self, server_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM join_form_settings WHERE server_id=?", (server_id,)
        ).fetchone()
        result = dict(row) if row else {
            "server_id": server_id, "enabled": False, "questions_json": "[]",
            "introduction": "", "version": 0, "access_role_id": None,
            "setup_status": "disabled", "setup_error": None, "gate_json": "{}",
            "visible_channel_ids_json": "[]",
            "appearance_json": "{}",
        }
        result["enabled"] = bool(result["enabled"])
        result["questions"] = json.loads(result.pop("questions_json"))
        result["gate"] = json.loads(result.pop("gate_json"))
        result["visible_channel_ids"] = json.loads(result.pop("visible_channel_ids_json"))
        result["appearance"] = {**DEFAULT_APPEARANCE, **json.loads(result.pop("appearance_json"))}
        return result

    @staticmethod
    def validate_form(payload: dict[str, Any], *, draft: bool = False) -> tuple[bool, str, list[dict[str, Any]]]:
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError("Choose whether applications are enabled.")
        introduction = payload.get("introduction", "")
        if not isinstance(introduction, str) or len(introduction) > 1000:
            raise ValueError("The introduction must be at most 1,000 characters.")
        raw = payload.get("questions")
        if not isinstance(raw, list) or len(raw) > 20 or (enabled and not raw and not draft):
            raise ValueError("Add between 1 and 20 questions before enabling applications.")
        questions = []
        for question in raw:
            if not isinstance(question, dict):
                raise ValueError("Each question must be an object.")
            title, prompt = question.get("title", ""), question.get("prompt", "")
            kind = question.get("type", "text")
            if not isinstance(title, str) or not (0 if draft else 1) <= len(title.strip()) <= 120:
                raise ValueError("Question titles must be between 1 and 120 characters.")
            if not isinstance(prompt, str) or not (0 if draft else 1) <= len(prompt.strip()) <= 1200:
                raise ValueError("Question text must be between 1 and 1,200 characters.")
            if kind not in {"text", "choice", "agreement"}:
                raise ValueError("Choose text, multiple choice, or rules agreement.")
            options = question.get("options", []) if kind == "choice" else []
            if (not isinstance(options, list) or (kind == "choice" and not (0 if draft else 2) <= len(options) <= 8)
                    or any(not isinstance(o, str) or not (0 if draft else 1) <= len(o.strip()) <= 100 for o in options)):
                raise ValueError("Multiple-choice questions need 2–8 options, at most 100 characters each.")
            if not draft and len(set(o.strip().casefold() for o in options)) != len(options):
                raise ValueError("Answer options must be different.")
            required = question.get("required", True)
            if not isinstance(required, bool):
                raise ValueError("Question required must be true or false.")
            questions.append({"title": title.strip(), "prompt": prompt.strip(), "type": kind,
                              "required": required, "options": [o.strip() for o in options]})
            if "emoji" in question:
                if not isinstance(question["emoji"], str) or len(question["emoji"]) > 32 or any(ord(c) < 32 for c in question["emoji"]):
                    raise ValueError("Question emoji must be at most 32 characters, without line breaks.")
                questions[-1]["emoji"] = question["emoji"].strip()
            if "color" in question:
                if not isinstance(question["color"], str) or (question["color"] and not re.fullmatch(r"#[0-9a-fA-F]{6}", question["color"])):
                    raise ValueError("Choose a valid question colour, such as #5865F2.")
                questions[-1]["color"] = question["color"]
        return enabled, introduction.strip(), questions

    def _queue(self, server_id: str, action: str, actor_id: str, payload: dict[str, Any]) -> int:
        cursor = self.connection.execute(
            "INSERT INTO dashboard_actions(server_id, action, actor_id, payload_json, created_at) VALUES(?,?,?,?,?)",
            (server_id, action, actor_id, json.dumps(payload), now_iso()),
        )
        return int(cursor.lastrowid)

    def save_settings(self, server_id: str, actor_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        enabled, introduction, questions = self.validate_form(payload)
        current = self.settings(server_id)
        appearance = validate_appearance(payload.get("appearance", current["appearance"]))
        visible_channels = payload.get("visible_channel_ids", current["visible_channel_ids"])
        if (not isinstance(visible_channels, list) or len(visible_channels) > 1000
                or any(not isinstance(channel_id, str) or not channel_id or len(channel_id) > 100
                       for channel_id in visible_channels)):
            raise ValueError("Choose visible channels from this server's channel list.")
        visible_channels = sorted(set(visible_channels))
        known_channels = {row[0] for row in self.connection.execute(
            "SELECT channel_id FROM dashboard_channels WHERE server_id=?", (server_id,))}
        # Retain previously saved IDs through a stale snapshot, but never accept
        # a new ID belonging to another server or an unknown channel.
        if set(visible_channels) - known_channels - set(current["visible_channel_ids"]):
            raise ValueError("A selected channel is unavailable in this server. Refresh the channel list.")
        if current["setup_status"] == "configuring":
            raise ValueError("Server permissions are being prepared. Wait for setup to finish.")
        # Keep the access gate after disabling: existing applicants must still be
        # reviewed, and ordinary new joins receive the access role immediately.
        visibility_changed = visible_channels != sorted(current["visible_channel_ids"])
        needs_setup = (enabled or current["access_role_id"]) and (
            current["setup_status"] != "ready" or visibility_changed or payload.get("repair_access") is True)
        setup = "pending" if needs_setup else current["setup_status"]
        with self.connection:
            saved = self.connection.execute("""
                INSERT INTO join_form_settings(server_id,enabled,introduction,questions_json,version,setup_status,visible_channel_ids_json)
                VALUES(?,?,?,?,1,?,?) ON CONFLICT(server_id) DO UPDATE SET
                    enabled=excluded.enabled,introduction=excluded.introduction,
                    questions_json=excluded.questions_json,version=join_form_settings.version+1,
                    setup_status=excluded.setup_status,setup_error=NULL,
                    visible_channel_ids_json=excluded.visible_channel_ids_json
                WHERE join_form_settings.setup_status<>'configuring' AND join_form_settings.version=?
            """, (server_id, int(enabled), introduction, json.dumps(questions), setup, json.dumps(visible_channels), current["version"]))
            if not saved.rowcount:
                raise ValueError("Application settings changed while saving. Refresh and try again after setup finishes.")
            self.connection.execute("UPDATE join_form_settings SET appearance_json=? WHERE server_id=?", (json.dumps(appearance), server_id))
            if setup == "pending":
                self._queue(server_id, "configure_applications", actor_id, {})
        return self.settings(server_id)

    def begin_setup(self, server_id: str) -> dict[str, Any] | None:
        # Take the write lock before reading: an API save during server lookup
        # must be included, or wait until this permission update has completed.
        with self.connection:
            changed = self.connection.execute("""UPDATE join_form_settings
                SET setup_status='configuring',setup_error=NULL WHERE server_id=?
                AND setup_status<>'ready' AND (enabled=1 OR access_role_id IS NOT NULL)""", (server_id,))
            return self.settings(server_id) if changed.rowcount else None

    def update_setup(self, server_id: str, *, status: str, role_id: str | None = None,
                     gate: dict[str, Any] | None = None, error: str | None = None) -> None:
        with self.connection:
            self.connection.execute("""UPDATE join_form_settings SET setup_status=?,setup_error=?,
                access_role_id=COALESCE(?,access_role_id),gate_json=COALESCE(?,gate_json) WHERE server_id=?""",
                (status, error, role_id, json.dumps(gate) if gate is not None else None, server_id))

    def _decode(self, row: Any) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        result["questions"] = json.loads(result.pop("questions_json"))
        result["notifications"] = json.loads(result.pop("notification_json"))
        result["appearance"] = {**DEFAULT_APPEARANCE, **json.loads(result.pop("appearance_json"))}
        result["screening_required"] = bool(result["screening_required"])
        result["timeout_history"] = json.loads(result.pop("timeout_history_json"))
        result["screening_passed"] = bool(result["screening_passed"])
        result["answers"] = [dict(a) for a in self.connection.execute(
            "SELECT position,answer,created_at FROM join_application_answers WHERE application_id=? ORDER BY position",
            (result["id"],))]
        return result

    def get(self, application_id: str, server_id: str | None = None) -> dict[str, Any] | None:
        return self._decode(self.connection.execute(
            "SELECT * FROM join_applications WHERE id=? AND (? IS NULL OR server_id=?) AND expires_at>?",
            (application_id, server_id, server_id, now_iso())).fetchone())

    def current(self, server_id: str, user_id: str) -> dict[str, Any] | None:
        return self._decode(self.connection.execute("""SELECT * FROM join_applications
            WHERE server_id=? AND user_id=? AND expires_at>? ORDER BY created_at DESC,rowid DESC LIMIT 1""",
            (server_id, user_id, now_iso())).fetchone())

    def pending(self, server_id: str, user_id: str) -> dict[str, Any] | None:
        app = self.current(server_id, user_id)
        return app if app and (app["status"] in OPEN_STATES or (
            app["status"] in {"approved", "denied", "expired"} and app["enforcement_status"] != "applied")) else None

    def list(self, server_id: str, *, limit: int = 100, before: str | None = None) -> list[dict[str, Any]]:
        rows = self.connection.execute("""SELECT * FROM join_applications WHERE server_id=? AND expires_at>?
            AND (? IS NULL OR rowid < (SELECT rowid FROM join_applications WHERE id=? AND server_id=?))
            ORDER BY rowid DESC LIMIT ?""", (server_id, now_iso(), before, before, server_id, min(limit, 100))).fetchall()
        return [self._decode(row) for row in rows]

    def user_applications(self, user_id: str) -> list[dict[str, Any]]:
        return [self._decode(row) for row in self.connection.execute("""SELECT * FROM join_applications
            WHERE user_id=? AND expires_at>? AND status IN ('screening','answering','submitted') ORDER BY created_at,id""", (user_id, now_iso()))]

    def accept_privacy(self, application_id: str, user_id: str, version: str, *, agreed: bool) -> dict[str, Any]:
        if agreed is not True or version != APPLICATION_PRIVACY_VERSION:
            raise ValueError("Review the current application privacy agreement and reply I agree.")
        with self.connection:
            changed = self.connection.execute("""UPDATE join_applications SET privacy_version=?,privacy_accepted_at=?,
                prompt_message_id=NULL,prompt_position=-1 WHERE id=? AND user_id=? AND expires_at>?
                AND status IN ('screening','answering') AND privacy_notice_version=? AND prompt_position=-2
                AND prompt_message_id IS NOT NULL""", (version, now_iso(), application_id, user_id, now_iso(), version))
            if changed.rowcount != 1:
                raise ValueError("Use ~application to read the current privacy agreement before accepting.")
        return self.get(application_id)

    def create(self, server_id: str, user_id: str, joined_at: str, *, screening_required: bool,
               previous_timeout: str | None = None) -> dict[str, Any]:
        self.prune()
        config = self.settings(server_id)
        if not config["enabled"] or not config["questions"] or not config["access_role_id"]:
            raise ValueError("Application setup has not finished.")
        existing = self.current(server_id, user_id)
        if existing and existing["joined_at"] == joined_at:
            return existing
        _, previous_timeout = self.resolve_timeout(server_id, user_id, previous_timeout)
        application_id = secrets.token_hex(8).upper()
        with self.connection:
            self.connection.execute("""UPDATE join_applications SET status='left',enforcement_status='applied'
                WHERE server_id=? AND user_id=? AND status IN ('screening','answering','submitted')""", (server_id, user_id))
            self.connection.execute("DELETE FROM captcha_challenges WHERE server_id=? AND user_id=?", (server_id, user_id))
            self.connection.execute("DELETE FROM join_application_dm_sessions WHERE user_id=?", (user_id,))
            self.connection.execute("""INSERT INTO join_applications
                (id,server_id,user_id,joined_at,created_at,expires_at,status,screening_required,screening_passed,
                questions_json,introduction,form_version,access_role_id,previous_timeout,appearance_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    application_id, server_id, user_id, joined_at, now_iso(), seven_days(),
                    "screening" if screening_required else "answering", int(screening_required), int(not screening_required),
                    json.dumps(config["questions"]), config["introduction"], config["version"],
                    config["access_role_id"], previous_timeout, json.dumps(config["appearance"])))
        return self.get(application_id)

    def mark_screened(self, application_id: str) -> bool:
        with self.connection:
            return self.connection.execute("""UPDATE join_applications SET screening_passed=1,status='answering',
                prompt_message_id=NULL,prompt_position=-1 WHERE id=? AND status='screening' AND expires_at>?""",
                (application_id, now_iso())).rowcount == 1

    def complete_screening(self, application_id: str, token_hash: str) -> bool:
        app = self.get(application_id)
        if not app:
            return False
        with self.connection:
            updated = self.connection.execute("""UPDATE join_applications SET screening_passed=1,status='answering',
                prompt_message_id=NULL,prompt_position=-1,error=NULL WHERE id=? AND status='screening' AND expires_at>?
                AND EXISTS(SELECT 1 FROM captcha_challenges c WHERE c.server_id=join_applications.server_id
                    AND c.user_id=join_applications.user_id AND c.answer_hash=? AND c.salt='web'
                    AND c.created_at>=join_applications.created_at AND c.expires_at>?)""",
                (application_id, now_iso(), token_hash, now_iso()))
            if updated.rowcount != 1:
                return False
            self.connection.execute("DELETE FROM captcha_challenges WHERE answer_hash=? AND salt='web'", (token_hash,))
            self._queue(app["server_id"], "resume_application", app["user_id"], {"application_id": application_id})
        return True

    def fail_screening(self, application_id: str, reason: str) -> None:
        app = self.get(application_id)
        if not app:
            return
        with self.connection:
            updated = self.connection.execute("""UPDATE join_applications SET status='denied',reason=?,reviewed_at=?,
                enforcement_status='pending' WHERE id=? AND status='screening'""", (reason, now_iso(), application_id))
            if updated.rowcount:
                self.connection.execute("DELETE FROM captcha_challenges WHERE server_id=? AND user_id=?", (app["server_id"], app["user_id"]))
                self._queue(app["server_id"], "resolve_application", app["user_id"], {"application_id": application_id})

    def update_delivery(self, application_id: str, *, error: str | None,
                        prompt_id: str | None = None, channel_id: str | None = None, position: int = -1) -> None:
        with self.connection:
            self.connection.execute("""UPDATE join_applications SET error=?,prompt_message_id=?,
                dm_channel_id=?,prompt_position=? WHERE id=?""",
                (error, prompt_id, channel_id, position, application_id))
            if position == -2 and prompt_id:
                self.connection.execute("UPDATE join_applications SET privacy_notice_version=? WHERE id=?",
                                        (APPLICATION_PRIVACY_VERSION, application_id))

    def resolve_timeout(self, server_id: str, user_id: str, value: str | None) -> tuple[bool, str | None]:
        """Remove verification timeouts from the restoration chain for this member.

        Stoat retains timeouts across leave/rejoin. Older releases saved the
        previous application's timeout as though it were a moderator's action.
        Walk newest to oldest so repeated joins and identical deadlines resolve
        to the original moderation timeout, or None when no such timeout exists.
        """
        def normalized(value: str | None) -> str | None:
            if value is None:
                return None
            parsed = datetime.fromisoformat(value)
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc).isoformat()

        remaining = normalized(value)
        owned = False
        if remaining is not None:
            rows = self.connection.execute("""SELECT verification_timeout,previous_timeout,timeout_history_json
                FROM join_applications WHERE server_id=? AND user_id=?
                ORDER BY created_at DESC,rowid DESC""", (server_id, user_id))
            for row in rows:
                history = {normalized(t) for t in json.loads(row["timeout_history_json"])}
                if row["verification_timeout"]:
                    history.add(normalized(row["verification_timeout"]))
                if remaining in history:
                    owned = True
                    remaining = normalized(row["previous_timeout"])
                    if remaining is None:
                        break
        return owned, remaining

    def set_timeout(self, application_id: str, value: str, previous_timeout: str | None = None) -> None:
        with self.connection:
            app = self.get(application_id)
            previous = previous_timeout if previous_timeout is not None else app["previous_timeout"]
            _, previous = self.resolve_timeout(app["server_id"], app["user_id"], previous)
            history = list(dict.fromkeys([*app["timeout_history"],
                *([app["verification_timeout"]] if app["verification_timeout"] else []), value]))
            self.connection.execute("""UPDATE join_applications SET verification_timeout=?,
                previous_timeout=?,timeout_history_json=? WHERE id=?""", (value, previous, json.dumps(history), application_id))

    def select(self, user_id: str, application_id: str) -> None:
        app = self.get(application_id)
        if not app or app["user_id"] != user_id or app["status"] not in OPEN_STATES:
            raise ValueError("Choose one of your active applications.")
        with self.connection:
            self.connection.execute("""INSERT INTO join_application_dm_sessions VALUES(?,?)
                ON CONFLICT(user_id) DO UPDATE SET application_id=excluded.application_id""", (user_id, application_id))

    def selected(self, user_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT application_id FROM join_application_dm_sessions WHERE user_id=?", (user_id,)).fetchone()
        app = self.get(row[0]) if row else None
        return app if app and app["status"] in OPEN_STATES else None

    def answer(self, application_id: str, user_id: str, position: int, message_id: str, text: str) -> dict[str, Any]:
        app = self.get(application_id)
        if not app or app["user_id"] != user_id or app["status"] != "answering" or app["expires_at"] <= now_iso():
            raise ValueError("This application is not accepting answers.")
        if not app["privacy_accepted_at"] or app["privacy_version"] != APPLICATION_PRIVACY_VERSION:
            raise ValueError("Agree to the application privacy notice before answering questions.")
        if self.connection.execute("SELECT 1 FROM join_application_answers WHERE message_id=?", (message_id,)).fetchone():
            return app
        if position != len(app["answers"]) or position >= len(app["questions"]):
            raise ValueError("That question has already been answered. Use ~application to resume.")
        question = app["questions"][position]
        text = text.strip()
        if not text or len(text) > 2000:
            raise ValueError("Reply with between 1 and 2,000 characters.")
        if text.casefold() == "skip" and not question["required"]:
            text = "(Skipped)"
        elif question["type"] == "agreement":
            if text.casefold() not in {"yes", "agree", "i agree"}:
                raise ValueError("Reply with agree to accept these rules.")
            text = "Agreed"
        elif question["type"] == "choice":
            options = question["options"]
            if text.isdigit() and 1 <= int(text) <= len(options):
                text = options[int(text) - 1]
            else:
                match = next((option for option in options if option.casefold() == text.casefold()), None)
                if match is None:
                    raise ValueError("Reply with an option number or the exact option text.")
                text = match
        with self.connection:
            # Claim this question while holding the SQLite write lock. API and
            # duplicate gateway events cannot insert an answer after a decision.
            cursor = self.connection.execute("""UPDATE join_applications SET prompt_message_id=NULL,prompt_position=-1
                WHERE id=? AND status='answering' AND expires_at>? AND privacy_version=? AND privacy_accepted_at<>'' AND
                (SELECT COUNT(*) FROM join_application_answers WHERE application_id=?)=?""",
                (application_id, now_iso(), APPLICATION_PRIVACY_VERSION, application_id, position))
            if cursor.rowcount != 1:
                raise ValueError("This application changed. Use ~application to resume.")
            self.connection.execute("INSERT INTO join_application_answers VALUES(?,?,?,?,?)",
                (application_id, position, message_id, text, now_iso()))
            if position + 1 == len(app["questions"]):
                submitted = now_iso()
                deadline = (datetime.fromisoformat(submitted) + timedelta(days=14)).isoformat(timespec="seconds")
                self.connection.execute("""UPDATE join_applications SET status='submitted',submitted_at=?,expires_at=?
                    WHERE id=?""", (submitted, deadline, application_id))
                self._queue(app["server_id"], "application_submitted", user_id, {"application_id": application_id})
        return self.get(application_id)

    def decide(self, server_id: str, application_id: str, actor_id: str, decision: str, reason: str) -> dict[str, Any]:
        if decision not in {"approved", "denied"}:
            raise ValueError("Choose approve or deny.")
        reason = reason.strip()
        if (decision == "denied" and len(reason) < 3) or len(reason) > 1000:
            raise ValueError("A denial reason must be between 3 and 1,000 characters.")
        with self.connection:
            cursor = self.connection.execute("""UPDATE join_applications SET status=?,reviewer_id=?,reviewed_at=?,
                reason=?,enforcement_status='pending',error=NULL WHERE id=? AND server_id=?
                AND status='submitted' AND screening_passed=1 AND expires_at>?""",
                (decision, actor_id, now_iso(), reason, application_id, server_id, now_iso()))
            if cursor.rowcount != 1:
                raise ValueError("Only submitted, unexpired, undecided applications can be reviewed.")
            self._queue(server_id, "resolve_application", actor_id, {"application_id": application_id})
        return self.get(application_id)

    def expire(self) -> int:
        return len(self.prune())

    def prune(self) -> list[dict[str, Any]]:
        """Erase expired application records atomically; return only transient outcomes.

        An unapproved applicant never receives the access role. Deletion cannot
        wait for delivery, permission repairs, or a failed network action. The
        bot may attempt removal using these in-memory outcomes, with no durable
        copy of the deleted application or retry payload.
        """
        outcomes = []
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            rows = self.connection.execute("SELECT * FROM join_applications WHERE expires_at<=?", (now_iso(),)).fetchall()
            for row in rows:
                if row["status"] in OPEN_STATES or (row["status"] in {"denied", "expired"} and row["enforcement_status"] != "applied"):
                    outcomes.append({"server_id": row["server_id"], "user_id": row["user_id"], "joined_at": row["joined_at"], "status": "denied"})
                for table, column in (("moderation_events", "details_json"), ("dashboard_actions", "payload_json")):
                    self.connection.execute(f"DELETE FROM {table} WHERE json_valid({column}) AND json_extract({column}, '$.application_id')=?", (row["id"],))
                self.connection.execute("""DELETE FROM captcha_challenges WHERE server_id=? AND user_id=? AND created_at>=?
                    AND NOT EXISTS(SELECT 1 FROM join_applications WHERE server_id=? AND user_id=? AND id<>? AND created_at>?)""",
                    (row["server_id"], row["user_id"], row["created_at"], row["server_id"], row["user_id"], row["id"], row["created_at"]))
                self.connection.execute("DELETE FROM join_applications WHERE id=?", (row["id"],))
        if rows:
            self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return outcomes

    def leave(self, server_id: str, user_id: str) -> None:
        with self.connection:
            self.connection.execute("DELETE FROM captcha_challenges WHERE server_id=? AND user_id=?", (server_id, user_id))
            self.connection.execute("""UPDATE join_applications SET status='left',enforcement_status='applied',
                prompt_message_id=NULL WHERE server_id=? AND user_id=? AND status IN ('screening','answering','submitted')""",
                (server_id, user_id))

    def abandon(self, application_id: str) -> None:
        with self.connection:
            self.connection.execute("""UPDATE join_applications SET status='left',enforcement_status='applied',
                prompt_message_id=NULL WHERE id=? AND (status IN ('screening','answering','submitted')
                    OR enforcement_status!='applied')""", (application_id,))

    def finish(self, application_id: str, *, error: str | None = None) -> None:
        with self.connection:
            current = self.get(application_id)
            self.connection.execute("UPDATE join_applications SET enforcement_status=?,error=? WHERE id=?",
                ("failed" if error else "applied", error, application_id))
            if current and error is None and current["enforcement_status"] != "applied":
                self._queue(current["server_id"], "notify_application_decision", current["reviewer_id"] or current["user_id"],
                    {"application_id": application_id})

    def retry(self, server_id: str, application_id: str, actor_id: str) -> None:
        app = self.get(application_id, server_id)
        if not app:
            raise ValueError("Application not found.")
        with self.connection:
            if (app["status"] in {"approved", "denied", "expired"} and app["enforcement_status"] == "failed") or app["status"] == "approved":
                self.connection.execute("UPDATE join_applications SET enforcement_status='pending',error=NULL WHERE id=?", (application_id,))
                self._queue(server_id, "resolve_application", actor_id, {"application_id": application_id})
            elif app["status"] == "submitted":
                notifications = dict(app["notifications"])
                notifications.pop("applicant", None)
                self.connection.execute("UPDATE join_applications SET notification_json=? WHERE id=?", (json.dumps(notifications), application_id))
                self._queue(server_id, "application_submitted", actor_id, {"application_id": application_id})
            elif app["status"] in OPEN_STATES:
                self._queue(server_id, "resume_application", actor_id, {"application_id": application_id, "force": True})
            elif app["enforcement_status"] == "applied" and app["status"] in {"approved", "denied", "expired"}:
                self._queue(server_id, "notify_application_decision", actor_id, {"application_id": application_id})
            else:
                raise ValueError("This application has no action to retry.")

    def notification_preference(self, server_id: str, user_id: str, enabled: bool | None = None) -> bool:
        if enabled is not None:
            with self.connection:
                self.connection.execute("""INSERT INTO join_application_notifications VALUES(?,?,?)
                    ON CONFLICT(server_id,user_id) DO UPDATE SET enabled=excluded.enabled""", (server_id, user_id, int(enabled)))
        row = self.connection.execute("SELECT enabled FROM join_application_notifications WHERE server_id=? AND user_id=?", (server_id, user_id)).fetchone()
        return bool(row and row[0])

    def notification_recipients(self, server_id: str) -> list[str]:
        return [row[0] for row in self.connection.execute(
            "SELECT user_id FROM join_application_notifications WHERE server_id=? AND enabled=1", (server_id,))
            if self.database.dashboard_user_has_access(server_id, row[0])]

    def mark_notified(self, application_id: str, recipient: str) -> None:
        app = self.get(application_id)
        if app:
            notifications = {**app["notifications"], recipient: now_iso()}
            with self.connection:
                self.connection.execute("UPDATE join_applications SET notification_json=? WHERE id=?", (json.dumps(notifications), application_id))
