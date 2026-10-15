"""Persistent reaction-role panels, selections and ownership of role grants."""
from __future__ import annotations

import json
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def emoji_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).replace("\ufe0f", "")


def panel_embed(config: dict, *, paused: bool = False) -> dict:
    instructions = {"multiple": "React to add a role. Remove your reaction to remove it.",
                    "single": "Choose one role. Selecting another replaces your previous choice.",
                    "keep": "React to receive a role. Removing your reaction keeps the role."}[config["mode"]]
    options = "\n".join(f"{(':' + item['emoji'] + ':') if re.fullmatch(r'[0-9A-Z]{26}', item['emoji']) else item['emoji']} — {item['label']}"
                        for item in config["options"])
    description = "\n\n".join(part for part in [config["description"], options,
        "⏸ Role selection is paused." if paused else instructions, config["footer"]] if part)
    return {"title": config["title"], "description": description, "color": config["color"]}


class ReactionRoleStore:
    def __init__(self, database: Any):
        self.database = database
        self.connection = database.connection
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS reaction_role_panels (
                id TEXT PRIMARY KEY, server_id TEXT NOT NULL, config_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft', message_id TEXT UNIQUE,
                published_channel_id TEXT, revision INTEGER NOT NULL DEFAULT 1,
                operation TEXT, cleanup INTEGER NOT NULL DEFAULT 0, error TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS reaction_role_panels_server ON reaction_role_panels(server_id);
            CREATE TABLE IF NOT EXISTS reaction_role_choices (
                panel_id TEXT NOT NULL REFERENCES reaction_role_panels(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL, emoji TEXT NOT NULL, role_id TEXT NOT NULL,
                joined_at TEXT NOT NULL, selected_at TEXT NOT NULL,
                PRIMARY KEY(panel_id,user_id,emoji)
            );
            CREATE TABLE IF NOT EXISTS reaction_role_grants (
                server_id TEXT NOT NULL, user_id TEXT NOT NULL, role_id TEXT NOT NULL,
                joined_at TEXT NOT NULL, owned INTEGER NOT NULL,
                PRIMARY KEY(server_id,user_id,role_id)
            );
            CREATE TABLE IF NOT EXISTS reaction_role_directory (
                server_id TEXT PRIMARY KEY, data_json TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reaction_role_pending_members (
                server_id TEXT NOT NULL, user_id TEXT NOT NULL, panel_id TEXT NOT NULL,
                PRIMARY KEY(server_id,user_id)
            );
        """)

    def directory(self, server_id: str) -> dict | None:
        row = self.connection.execute("SELECT * FROM reaction_role_directory WHERE server_id=?", (server_id,)).fetchone()
        return {**json.loads(row["data_json"]), "updated_at": row["updated_at"]} if row else None

    def set_directory(self, server_id: str, data: dict):
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO reaction_role_directory VALUES(?,?,?)", (server_id,json.dumps(data),now()))

    def queue(self, server_id: str, actor: str, payload: dict) -> int:
        cursor = self.connection.execute("INSERT INTO dashboard_actions(server_id,action,actor_id,payload_json,created_at) VALUES(?,?,?,?,?)",
            (server_id,"reaction_roles",actor,json.dumps(payload),now()))
        return cursor.lastrowid

    def refresh_directory(self, server_id: str, actor: str):
        with self.connection:
            existing = self.connection.execute("SELECT 1 FROM dashboard_actions WHERE server_id=? AND action='reaction_roles' AND status IN ('pending','processing') AND json_extract(payload_json,'$.operation')='directory'", (server_id,)).fetchone()
            if not existing:
                self.queue(server_id, actor, {"operation":"directory"})

    def validate(self, server_id: str, payload: Any, *, draft: bool = False) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("Provide a reaction-role panel.")
        result = {}
        for key, maximum, required in [("title",100,True),("description",1000,False),("footer",160,False),("channel_id",100,True)]:
            value = payload.get(key, "")
            if not isinstance(value,str) or len(value)>maximum or (required and not draft and not value.strip()):
                raise ValueError(f"{key.replace('_',' ').title()} must be {'1–' if required else 'at most '}{maximum} characters.")
            result[key] = value.strip()
        if draft and not result["title"]:
            result["title"] = "Choose your roles"
        if payload.get("mode") not in {"multiple","single","keep"}:
            raise ValueError("Choose multiple roles, one role, or keep after selection.")
        result["mode"] = payload["mode"]
        color = payload.get("color", "#5865F2")
        if not isinstance(color,str) or not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            raise ValueError("Choose a valid embed colour.")
        result["color"] = color
        directory = self.directory(server_id)
        if not directory and not draft:
            raise ValueError("Refresh server roles and emojis before creating a panel.")
        directory = directory or {"channels":[], "roles":[], "emojis":[]}
        if not draft and result["channel_id"] not in {c["id"] for c in directory["channels"]}:
            raise ValueError("Choose a text channel in this server.")
        roles = {r["id"]:r for r in directory["roles"]}
        custom = {e["id"] for e in directory["emojis"]}
        options = payload.get("options")
        if not isinstance(options,list) or not 1<=len(options)<=12:
            raise ValueError("Add between 1 and 12 role options.")
        result["options"] = []
        used_emojis, used_roles = set(), set()
        for option in options:
            if not isinstance(option,dict):
                raise ValueError("Each option needs an emoji and a role.")
            emoji, role_id, label = option.get("emoji"), option.get("role_id"), option.get("label","")
            if not isinstance(emoji,str) or not 1<=len(emoji)<=32 or any(c.isspace() or ord(c)<32 for c in emoji):
                raise ValueError("Choose one emoji for each option.")
            if re.fullmatch(r"[0-9A-Z]{26}",emoji):
                if not draft and emoji not in custom: raise ValueError("Choose a custom emoji from this server.")
            elif not any(ord(c)>=0x2300 or c in "©®" for c in emoji):
                raise ValueError("Choose a Unicode emoji or a server emoji.")
            if not isinstance(role_id,str) or (not draft and (role_id not in roles or not roles[role_id]["assignable"])):
                raise ValueError("Choose an assignable community role. Staff and verification roles cannot be offered.")
            if not draft and (emoji_key(emoji) in used_emojis or role_id in used_roles):
                raise ValueError("Use a different emoji and role for every option.")
            if not isinstance(label,str) or len(label)>60:
                raise ValueError("Option labels must be at most 60 characters.")
            used_emojis.add(emoji_key(emoji)); used_roles.add(role_id)
            result["options"].append({"emoji":emoji,"role_id":role_id,"label":label.strip() or roles.get(role_id,{}).get("name","Choose a role")[:60]})
        if len(panel_embed(result)["description"])>1900:
            raise ValueError("Shorten the description or labels so the complete embed fits.")
        return result

    def get(self, panel_id: str, server_id: str | None = None) -> dict | None:
        row = self.connection.execute("SELECT * FROM reaction_role_panels WHERE id=?" + (" AND server_id=?" if server_id else ""),
            (panel_id,server_id) if server_id else (panel_id,)).fetchone()
        if not row: return None
        result = dict(row); result["config"] = json.loads(result.pop("config_json"))
        return result

    def panels(self, server_id: str | None = None) -> list[dict]:
        rows = self.connection.execute("SELECT id FROM reaction_role_panels WHERE status<>'deleted'" + (" AND server_id=?" if server_id else "") + " ORDER BY created_at DESC", (server_id,) if server_id else ()).fetchall()
        return [self.get(row[0]) for row in rows]

    def by_message(self, message_id: str) -> dict | None:
        row = self.connection.execute("SELECT id FROM reaction_role_panels WHERE message_id=? AND status='active'", (message_id,)).fetchone()
        return self.get(row[0]) if row else None

    def save(self, server_id: str, actor: str, payload: dict, panel_id: str | None = None) -> dict:
        config = self.validate(server_id,payload)
        with self.connection:
            if panel_id:
                previous = self.get(panel_id,server_id)
                if not previous: raise LookupError("Panel not found.")
                if previous["status"] in {"pending","deleted"}: raise ValueError("Wait for the pending operation to finish.")
                if payload.get("revision") != previous["revision"]: raise ValueError("This panel changed. Refresh before saving.")
                if previous["message_id"] and config["channel_id"] != previous["published_channel_id"]:
                    raise ValueError("A published panel stays in its channel. Create a new panel to use another channel.")
                operation = "pause" if previous["status"]=="paused" else "publish"
                self.connection.execute("UPDATE reaction_role_panels SET config_json=?,revision=revision+1,status='pending',operation=?,error=NULL,updated_at=? WHERE id=?",
                    (json.dumps(config),operation,now(),panel_id))
            else:
                if len(self.panels(server_id))>=30: raise ValueError("A server can have up to 30 reaction-role panels.")
                panel_id = secrets.token_hex(8).upper(); operation="publish"
                self.connection.execute("INSERT INTO reaction_role_panels(id,server_id,config_json,status,operation,created_by,created_at,updated_at) VALUES(?,?,?,'pending','publish',?,?,?)",
                    (panel_id,server_id,json.dumps(config),actor,now(),now()))
            panel = self.get(panel_id)
            self.queue(server_id,actor,{"operation":operation,"panel_id":panel_id,"revision":panel["revision"]})
        return panel

    def request(self, server_id: str, actor: str, panel_id: str, operation: str, revision: int, cleanup: bool=False) -> dict:
        if operation not in {"publish","pause","delete","retry"}: raise ValueError("Unknown panel action.")
        with self.connection:
            panel = self.get(panel_id,server_id)
            if not panel or panel["status"]=="deleted": raise LookupError("Panel not found.")
            if panel["status"]=="pending": raise ValueError("An operation is already pending.")
            if revision!=panel["revision"]: raise ValueError("This panel changed. Refresh before continuing.")
            if operation=="retry":
                operation=panel["operation"] or "publish"
                cleanup=bool(panel["cleanup"])
            self.connection.execute("UPDATE reaction_role_panels SET status='pending',operation=?,cleanup=?,revision=revision+1,error=NULL,updated_at=? WHERE id=?", (operation,int(cleanup),now(),panel_id))
            panel = self.get(panel_id)
            self.queue(server_id,actor,{"operation":operation,"panel_id":panel_id,"revision":panel["revision"],"cleanup":cleanup})
        return panel

    def update(self, panel_id: str, **fields):
        allowed={"status","error","message_id","published_channel_id"}
        if not fields or fields.keys()-allowed: raise ValueError("Invalid panel fields")
        with self.connection:
            self.connection.execute("UPDATE reaction_role_panels SET " + ",".join(key+"=?" for key in fields) + ",updated_at=? WHERE id=?", (*fields.values(),now(),panel_id))

    def choices(self, panel_id: str, user_id: str | None = None) -> list[dict]:
        return [dict(r) for r in self.connection.execute("SELECT * FROM reaction_role_choices WHERE panel_id=?" + (" AND user_id=?" if user_id else "") + " ORDER BY selected_at,emoji", (panel_id,user_id) if user_id else (panel_id,))]

    def select(self, panel: dict, user_id: str, joined_at: str, options: list[dict]):
        with self.connection:
            self.connection.execute("INSERT OR REPLACE INTO reaction_role_pending_members VALUES(?,?,?)", (panel["server_id"],user_id,panel["id"]))
            self.connection.execute("DELETE FROM reaction_role_choices WHERE panel_id=? AND user_id=?",(panel["id"],user_id))
            for option in options:
                self.connection.execute("INSERT INTO reaction_role_choices VALUES(?,?,?,?,?,?)",(panel["id"],user_id,emoji_key(option["emoji"]),option["role_id"],joined_at,now()))

    def desired(self, server_id: str, user_id: str, joined_at: str) -> set[str]:
        return {r[0] for r in self.connection.execute("SELECT c.role_id FROM reaction_role_choices c JOIN reaction_role_panels p ON p.id=c.panel_id WHERE p.server_id=? AND c.user_id=? AND c.joined_at=? AND p.status<>'deleted'",(server_id,user_id,joined_at))}

    def grants(self, server_id: str, user_id: str) -> list[dict]:
        return [dict(r) for r in self.connection.execute("SELECT * FROM reaction_role_grants WHERE server_id=? AND user_id=?",(server_id,user_id))]
