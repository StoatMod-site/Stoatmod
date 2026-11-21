"""Dashboard role management.

Lists, edits, orders, creates and deletes the roles of one Stoat server through the
Stoat REST API, using Stoatmod's own bot token. The dashboard API process already holds
that token, so a change is applied (and refused, with Stoat's reason) while the admin
waits instead of being queued for the gateway bot.

Two ceilings apply to every change, both checked here before Stoat is asked and again by
Stoat itself:

* Stoatmod can only touch roles ranked strictly below its own highest role (a lower rank
  number is a higher role). A bot without any role can touch none; Stoat answers
  ``NotElevated`` otherwise.
* The dashboard user is never allowed to do more through the bot than they could do
  themselves in Stoat: the server owner may edit every role below Stoatmod, anyone else
  needs Manage Roles (Manage Permissions to change permissions), can only touch roles
  below their own highest role, and can only grant permissions they hold.

Nothing the browser sends is trusted: role ids must exist in the freshly fetched server,
permission names must be in the catalogue, colours are parsed and re-written in a canonical
form that Stoat's own validator accepts, and every change is recorded in the activity log
(names, colours and permission names only; never message content).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
import unicodedata
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote

from aiohttp import ClientError, ClientSession, ClientTimeout, web

logger = logging.getLogger("stoat_dashboard.roles")

ULID = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
NAME_MAX = 32
COLOUR_MAX = 128
MAX_STOPS = 20  # a sanity cap; the 128 character limit is what really bounds a gradient
MAX_ROLES = 200  # Stoat's default; Stoat's own TooManyRoles answer is authoritative.
READ_LIMIT = (40, 60)  # requests, seconds, per server and user
WRITE_LIMIT = (20, 60)
# Stoat allows about 5 requests per 10 seconds per server for the bot, shared with the bot's own work.
# A wait up to this long is absorbed quietly before a request is sent; a longer one is reported to the
# dashboard, which shows a countdown, locks the page and retries by itself.
HOLD_MAX_SECONDS = 2.5
DEFAULT_RETRY_SECONDS = 5.0
MAX_RETRY_SECONDS = 60.0
NO_ROLE_RANK = float("inf")  # a member without a role sits below every role
OWNER_RANK = float("-inf")  # the owner outranks every role

# --------------------------------------------------------------------------- permissions

PERMISSION_GROUPS = [
    {"id": "server", "label": "Server"},
    {"id": "members", "label": "Members"},
    {"id": "text", "label": "Text channels"},
    {"id": "voice", "label": "Voice channels"},
]
# One entry per line: ``bit`` is the Stoat permission bit, ``name`` is shown as written
# (permission names are never translated) and ``description`` is translated.
PERMISSIONS: list[dict[str, Any]] = [
    {"key": "manage_channels", "bit": 0, "group": "server", "name": "Manage Channels", "description": "Create, edit, reorder and delete channels and categories."},
    {"key": "manage_server", "bit": 1, "group": "server", "name": "Manage Server", "description": "Change the server name, description, icon, banner and settings."},
    {"key": "manage_permissions", "bit": 2, "group": "server", "name": "Manage Permissions", "description": "Change the permissions of roles and channels."},
    {"key": "manage_roles", "bit": 3, "group": "server", "name": "Manage Roles", "description": "Create, edit, reorder and delete roles below their own."},
    {"key": "manage_customization", "bit": 4, "group": "server", "name": "Manage Customisation", "description": "Add and remove custom emoji."},
    {"key": "kick_members", "bit": 6, "group": "members", "name": "Kick Members", "description": "Remove members from the server. They can rejoin with an invite."},
    {"key": "ban_members", "bit": 7, "group": "members", "name": "Ban Members", "description": "Ban members from the server."},
    {"key": "timeout_members", "bit": 8, "group": "members", "name": "Timeout Members", "description": "Temporarily stop members from talking or reacting."},
    {"key": "assign_roles", "bit": 9, "group": "members", "name": "Assign Roles", "description": "Give and remove roles for members below their own."},
    {"key": "change_nickname", "bit": 10, "group": "members", "name": "Change Nickname", "description": "Change their own nickname."},
    {"key": "manage_nicknames", "bit": 11, "group": "members", "name": "Manage Nicknames", "description": "Change or remove other members' nicknames."},
    {"key": "change_avatar", "bit": 12, "group": "members", "name": "Change Avatar", "description": "Change their own server avatar."},
    {"key": "remove_avatars", "bit": 13, "group": "members", "name": "Remove Avatars", "description": "Remove other members' server avatars."},
    {"key": "view_channel", "bit": 20, "group": "text", "name": "View Channel", "description": "See channels and read what is in them."},
    {"key": "read_message_history", "bit": 21, "group": "text", "name": "Read Message History", "description": "Read earlier messages in a channel."},
    {"key": "send_messages", "bit": 22, "group": "text", "name": "Send Messages", "description": "Send messages in text channels."},
    {"key": "manage_messages", "bit": 23, "group": "text", "name": "Manage Messages", "description": "Delete other members' messages and pin messages."},
    {"key": "manage_webhooks", "bit": 24, "group": "text", "name": "Manage Webhooks", "description": "Create and manage webhooks."},
    {"key": "create_invites", "bit": 25, "group": "text", "name": "Create Invites", "description": "Create invite links to a channel."},
    {"key": "send_embeds", "bit": 26, "group": "text", "name": "Send Embeds", "description": "Send messages with embedded content and link previews."},
    {"key": "upload_files", "bit": 27, "group": "text", "name": "Upload Files", "description": "Attach files, images and other media."},
    {"key": "use_masquerade", "bit": 28, "group": "text", "name": "Masquerade", "description": "Send messages with a custom name and avatar."},
    {"key": "react", "bit": 29, "group": "text", "name": "React", "description": "Add reactions to messages."},
    {"key": "mention_everyone", "bit": 37, "group": "text", "name": "Mention Everyone", "description": "Mention everyone and all online members."},
    {"key": "mention_roles", "bit": 38, "group": "text", "name": "Mention Roles", "description": "Mention roles."},
    {"key": "connect", "bit": 30, "group": "voice", "name": "Connect", "description": "Join voice channels."},
    {"key": "speak", "bit": 31, "group": "voice", "name": "Speak", "description": "Talk in voice channels."},
    {"key": "video", "bit": 32, "group": "voice", "name": "Video", "description": "Share video and screens in voice channels."},
    {"key": "mute_members", "bit": 33, "group": "voice", "name": "Mute Members", "description": "Mute members with a lower rank in a voice channel."},
    {"key": "deafen_members", "bit": 34, "group": "voice", "name": "Deafen Members", "description": "Deafen members with a lower rank in a voice channel."},
    {"key": "move_members", "bit": 35, "group": "voice", "name": "Move Members", "description": "Move members between voice channels."},
    {"key": "listen", "bit": 36, "group": "voice", "name": "Listen", "description": "Hear other members in voice channels."},
]
PERMISSION_BITS: dict[str, int] = {item["key"]: 1 << item["bit"] for item in PERMISSIONS}
PERMISSION_NAMES: dict[str, str] = {item["key"]: item["name"] for item in PERMISSIONS}
KNOWN_BITS = 0
for _bit in PERMISSION_BITS.values():
    KNOWN_BITS |= _bit
MANAGE_ROLES = PERMISSION_BITS["manage_roles"]
MANAGE_PERMISSIONS = PERMISSION_BITS["manage_permissions"]


def bits_to_keys(value: int) -> list[str]:
    return [item["key"] for item in PERMISSIONS if value & (1 << item["bit"])]


def keys_to_bits(value: Any, label: str) -> int:
    if not isinstance(value, list) or len(value) > len(PERMISSIONS):
        raise ValueError(f"Choose the {label} permissions from the list.")
    bits = 0
    for key in value:
        if not isinstance(key, str) or key not in PERMISSION_BITS:
            raise ValueError("One of the permissions is not recognised.")
        bit = PERMISSION_BITS[key]
        if bits & bit:
            raise ValueError("A permission was listed twice.")
        bits |= bit
    return bits


def permission_names(value: int) -> str:
    return ", ".join(PERMISSION_NAMES[key] for key in bits_to_keys(value))


# --------------------------------------------------------------------------- names and colours

def validate_role_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Enter a role name.")
    name = " ".join(value.split())
    if not 1 <= len(name) <= NAME_MAX:
        raise ValueError(f"A role name must be 1 to {NAME_MAX} characters.")
    if any(unicodedata.category(character).startswith("C") for character in name):
        raise ValueError("A role name cannot contain control or invisible characters.")
    return name


# The CSS colour names that every browser and Stoat client renders the same way.
NAMED_COLOURS = frozenset(
    "aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown "
    "burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan "
    "darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid "
    "darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet "
    "deeppink deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro "
    "ghostwhite gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki "
    "lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow "
    "lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray "
    "lightslategrey lightsteelblue lightyellow lime limegreen linen magenta maroon mediumaquamarine "
    "mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen mediumturquoise "
    "mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy oldlace olive olivedrab "
    "orange orangered orchid palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru "
    "pink plum powderblue purple rebeccapurple red rosybrown royalblue saddlebrown salmon sandybrown "
    "seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen steelblue tan "
    "teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen".split()
)
_HEX = re.compile(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})")
_RGB = re.compile(r"(rgba?)\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*(?:,\s*([01])\s*)?\)", re.IGNORECASE)
_VAR = re.compile(r"var\(--[a-z0-9-]{1,40}\)", re.IGNORECASE)
_ANGLE = re.compile(r"(\d{1,3})deg", re.IGNORECASE)
_DIRECTION = re.compile(r"to (top|bottom|left|right)(?: (top|bottom|left|right))?", re.IGNORECASE)
_STOP = re.compile(r"(.+?)(?:\s+(\d{1,3}%|0))?")
COLOUR_ERROR = "Use a colour like #7c3aed, a CSS colour name, or a linear, radial or conic gradient of two or more colours."


def _colour_term(text: str) -> str:
    """One colour in the canonical spelling Stoat accepts, or ValueError."""
    text = text.strip()
    if _HEX.fullmatch(text):
        return text.lower()
    rgb = _RGB.fullmatch(text)
    if rgb:
        function, *parts = rgb.groups()
        channels = [int(part) for part in parts[:3]]
        if any(channel > 255 for channel in channels):
            raise ValueError("Colour channels go from 0 to 255.")
        if function.lower() == "rgb" and parts[3] is not None:
            raise ValueError(COLOUR_ERROR)
        suffix = f", {parts[3]}" if parts[3] is not None else ""
        return f"{function.lower()}({channels[0]}, {channels[1]}, {channels[2]}{suffix})"
    if _VAR.fullmatch(text):
        return text.lower()
    if text.lower() in NAMED_COLOURS:
        return text.lower()
    raise ValueError(COLOUR_ERROR)


def _split_arguments(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise ValueError(COLOUR_ERROR)
        elif character == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    if depth:
        raise ValueError(COLOUR_ERROR)
    parts.append(text[start:])
    return parts


def validate_role_colour(value: Any) -> str:
    """Return the canonical colour for ``value`` or raise ValueError.

    A canonical colour always satisfies Stoat's own role-colour validator (an
    allow-list of hex, rgb(a), named colours, var(--x) and gradients, 128 characters at
    most), so Stoat cannot reject it for its shape; the rules here are stricter."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(COLOUR_ERROR)
    text = value.strip()
    if len(text) > 400:
        raise ValueError(COLOUR_ERROR)
    gradient = re.fullmatch(r"(linear|radial|conic)-gradient\((.*)\)", text, re.IGNORECASE | re.DOTALL)
    if not gradient:
        result = _colour_term(text)
    else:
        kind = gradient.group(1).lower()
        arguments = [part.strip() for part in _split_arguments(gradient.group(2))]
        prefix = ""
        if kind == "linear" and arguments:
            angle = _ANGLE.fullmatch(arguments[0])
            direction = _DIRECTION.fullmatch(arguments[0])
            if angle:
                if int(angle.group(1)) > 360:
                    raise ValueError("A gradient angle goes from 0 to 360 degrees.")
                prefix = f"{int(angle.group(1))}deg"
            elif direction:
                prefix = " ".join(["to", *[side.lower() for side in direction.groups() if side]])
            if prefix:
                arguments = arguments[1:]
        if not 2 <= len(arguments) <= MAX_STOPS:
            raise ValueError(COLOUR_ERROR)
        stops = []
        for argument in arguments:
            stop = _STOP.fullmatch(argument)
            if not stop:
                raise ValueError(COLOUR_ERROR)
            colour = _colour_term(stop.group(1))
            position = stop.group(2)
            if position and position != "0" and int(position[:-1]) > 100:
                raise ValueError("A gradient stop goes from 0% to 100%.")
            stops.append(f"{colour} {position}" if position else colour)
        parts = [*([prefix] if prefix else []), *stops]
        result = f"{kind}-gradient({', '.join(parts)})"
        if len(result) > COLOUR_MAX:  # Stoat allows no space after the commas, which saves a few characters
            compact = f"{kind}-gradient({','.join(parts)})"
            result = compact if len(compact) <= COLOUR_MAX else result
    if len(result) > COLOUR_MAX:
        raise ValueError(f"A role colour can be at most {COLOUR_MAX} characters. Use fewer gradient stops.")
    return result


# --------------------------------------------------------------------------- hierarchy

@dataclass
class Role:
    id: str
    name: str
    colour: str | None
    hoist: bool
    rank: int
    allow: int
    deny: int


@dataclass
class Person:
    rank: float
    bits: int
    is_owner: bool
    in_server: bool


@dataclass
class State:
    server_id: str
    server_name: str
    roles: dict[str, Role]
    default_bits: int
    bot_id: str
    bot: Person
    actor: Person
    # The member records this state was built from, so a refresh right after a change can reuse them
    # instead of spending two more of Stoat's few requests.
    bot_member: dict[str, Any] | None = field(default=None, repr=False, compare=False)
    actor_member: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    @property
    def limit_rank(self) -> float:
        """Roles ranked at or above this are out of reach for this change."""
        return max(self.bot.rank, self.actor.rank)

    def refusal(self, role: Role, *, permissions: bool) -> str | None:
        """Why this role cannot be changed by this admin through Stoatmod, or None."""
        needed = MANAGE_PERMISSIONS if permissions else MANAGE_ROLES
        if self.bot.rank == NO_ROLE_RANK:
            return "bot_has_no_role"
        if role.rank <= self.bot.rank:
            return "above_bot"
        if not self.bot.bits & needed:
            return "bot_needs_manage_permissions" if permissions else "bot_needs_manage_roles"
        if not self.actor.is_owner and not self.actor.bits & needed:
            return "you_need_manage_permissions" if permissions else "you_need_manage_roles"
        if role.rank <= self.actor.rank:
            return "above_you"
        return None

    def grantable_bits(self) -> int:
        return self.bot.bits & self.actor.bits & KNOWN_BITS

    @property
    def sorted_roles(self) -> list[Role]:
        return sorted(self.roles.values(), key=lambda role: (role.rank, role.id))


def member_rank(roles: dict[str, Role], member: dict[str, Any] | None) -> float:
    if not member:
        return NO_ROLE_RANK
    ranks = [roles[role_id].rank for role_id in member.get("roles") or [] if role_id in roles]
    return min(ranks) if ranks else NO_ROLE_RANK


def server_bits(roles: dict[str, Role], default_bits: int, member: dict[str, Any] | None) -> int:
    """Server-level permissions: the default, then each role from the lowest up."""
    if not member:
        return 0
    value = default_bits
    owned = [roles[role_id] for role_id in member.get("roles") or [] if role_id in roles]
    for role in sorted(owned, key=lambda item: item.rank, reverse=True):
        value = (value | role.allow) & ~role.deny
    return value


def parse_role(role_id: str, raw: dict[str, Any]) -> Role:
    permissions = raw.get("permissions") or {}
    colour = raw.get("colour")
    return Role(
        id=role_id,
        name=str(raw.get("name") or ""),
        colour=colour if isinstance(colour, str) and colour else None,
        hoist=bool(raw.get("hoist")),
        rank=int(raw.get("rank") or 0),
        allow=int(permissions.get("a") or 0),
        deny=int(permissions.get("d") or 0),
    )


def build_state(server_id: str, user_id: str, bot_id: str, server: dict[str, Any],
                bot_member: dict[str, Any] | None, actor_member: dict[str, Any] | None) -> State:
    roles = {role_id: parse_role(role_id, raw) for role_id, raw in (server.get("roles") or {}).items()
             if isinstance(raw, dict) and ULID.fullmatch(str(role_id))}
    default_bits = int(server.get("default_permissions") or 0)
    owner_id = str(server.get("owner") or "")
    bot_is_owner = bot_id == owner_id
    actor_is_owner = user_id == owner_id
    everything = (1 << 64) - 1
    bot = Person(
        rank=OWNER_RANK if bot_is_owner else member_rank(roles, bot_member),
        bits=everything if bot_is_owner else server_bits(roles, default_bits, bot_member),
        is_owner=bot_is_owner, in_server=bot_member is not None,
    )
    actor = Person(
        rank=OWNER_RANK if actor_is_owner else member_rank(roles, actor_member),
        bits=everything if actor_is_owner else server_bits(roles, default_bits, actor_member),
        is_owner=actor_is_owner, in_server=actor_member is not None,
    )
    return State(server_id, str(server.get("name") or ""), roles, default_bits, bot_id, bot, actor,
                 bot_member=bot_member, actor_member=actor_member)


def create_refusal(state: State) -> str | None:
    """Why this admin cannot add a role right now, or None."""
    if state.bot.rank == NO_ROLE_RANK:
        return REFUSALS["bot_has_no_role"]
    if not state.bot.bits & MANAGE_ROLES:
        return REFUSALS["bot_needs_manage_roles"]
    if not state.actor.is_owner and not state.actor.bits & MANAGE_ROLES:
        return REFUSALS["you_need_manage_roles"]
    return None


def snapshot(state: State) -> dict[str, Any]:
    roles = []
    for role in state.sorted_roles:
        manage = state.refusal(role, permissions=False)
        permissions = state.refusal(role, permissions=True)
        roles.append({
            "id": role.id, "name": role.name, "colour": role.colour, "hoist": role.hoist, "rank": role.rank,
            "allow": bits_to_keys(role.allow), "deny": bits_to_keys(role.deny),
            "editable": manage is None, "permissions_editable": permissions is None,
            "locked_reason": manage or permissions,
            "locked_message": REFUSALS[manage or permissions] if (manage or permissions) else None,
        })
    return {
        "available": True,
        "server": {"id": state.server_id, "name": state.server_name},
        "limits": {"max_roles": MAX_ROLES, "name_max": NAME_MAX, "colour_max": COLOUR_MAX, "max_stops": MAX_STOPS},
        "catalog": {"groups": PERMISSION_GROUPS,
                    "permissions": [{key: item[key] for key in ("key", "group", "name", "description")} for item in PERMISSIONS]},
        "bot": {"in_server": state.bot.in_server, "rank": None if state.bot.rank in (NO_ROLE_RANK, OWNER_RANK) else state.bot.rank,
                "can_manage_roles": bool(state.bot.bits & MANAGE_ROLES), "can_manage_permissions": bool(state.bot.bits & MANAGE_PERMISSIONS)},
        "actor": {"is_owner": state.actor.is_owner,
                  "can_manage_roles": state.actor.is_owner or bool(state.actor.bits & MANAGE_ROLES),
                  "can_manage_permissions": state.actor.is_owner or bool(state.actor.bits & MANAGE_PERMISSIONS)},
        "create_blocked": create_refusal(state),
        "grantable": bits_to_keys(state.grantable_bits()),
        "default_permissions": bits_to_keys(state.default_bits),
        "roles": roles,
    }


# --------------------------------------------------------------------------- change planning

class RoleError(Exception):
    def __init__(self, message: str, status: int = 400, *, retry_after: float | None = None, source: str = ""):
        super().__init__(message)
        self.message = message
        self.status = status
        # Set only for a rate limit: seconds until the same request can be sent again, and who is limiting
        # ("stoat" or "stoatmod"), so the dashboard can count down, wait, and retry by itself.
        self.retry_after = retry_after
        self.source = source


def wait_seconds(value: float | None) -> float:
    """A usable wait: what Stoat said, kept within sensible bounds."""
    if value is None or value != value:
        return DEFAULT_RETRY_SECONDS
    return min(MAX_RETRY_SECONDS, max(1.0, float(value)))


def rate_limit_message(source: str, seconds: float) -> str:
    whole = max(1, math.ceil(seconds))
    unit = "second" if whole == 1 else "seconds"
    if source == "stoatmod":
        return f"You're making changes faster than Stoatmod allows. We'll retry your request in {whole} {unit} and reflect the change here."
    return f"Stoat is ratelimiting us! We'll retry your request in {whole} {unit} and reflect the change here."


def rate_limited(source: str, seconds: float | None) -> RoleError:
    wait = wait_seconds(seconds)
    return RoleError(rate_limit_message(source, wait), 429, retry_after=wait, source=source)


_REFUSAL_ROWS = [
    {"code": "bot_has_no_role", "message": "Stoatmod has no role in this server. Give the Stoatmod bot a role in Stoat and place it above the roles you want to manage."},
    {"code": "above_bot", "message": "Stoatmod's role is not above this role. Move the Stoatmod role higher in Stoat's role list to manage it."},
    {"code": "bot_needs_manage_roles", "message": "Stoatmod needs the Manage Roles permission to change roles."},
    {"code": "bot_needs_manage_permissions", "message": "Stoatmod needs the Manage Permissions permission to change role permissions."},
    {"code": "you_need_manage_roles", "message": "You need the Manage Roles permission in this server, or to be its owner, to change roles here."},
    {"code": "you_need_manage_permissions", "message": "You need the Manage Permissions permission in this server, or to be its owner, to change role permissions here."},
    {"code": "above_you", "message": "This role is not below your own highest role, so you cannot change it here."},
]
REFUSALS = {row["code"]: row["message"] for row in _REFUSAL_ROWS}


@dataclass
class Plan:
    edit: dict[str, Any]
    set_permissions: tuple[int, int] | None
    changes: list[dict[str, Any]]


def _colour_key(value: str | None) -> str:
    return (value or "").strip().lower()


def plan_update(state: State, role: Role, payload: Any) -> Plan:
    if not isinstance(payload, dict):
        raise RoleError("A JSON object is required.")
    unknown = set(payload) - {"name", "colour", "hoist", "allow", "deny"}
    if unknown:
        raise RoleError("One of the fields is not recognised.")
    edit: dict[str, Any] = {}
    changes: list[dict[str, Any]] = []
    try:
        if "name" in payload:
            name = validate_role_name(payload["name"])
            if name != role.name:
                edit["name"] = name
                changes.append({"field": "name", "from": role.name, "to": name})
        if "colour" in payload:
            if payload["colour"] is None:
                if role.colour:
                    edit["remove"] = ["Colour"]
                    changes.append({"field": "colour", "from": role.colour, "to": None})
            else:
                colour = validate_role_colour(payload["colour"])
                if _colour_key(colour) != _colour_key(role.colour):
                    edit["colour"] = colour
                    changes.append({"field": "colour", "from": role.colour, "to": colour})
        if "hoist" in payload:
            if not isinstance(payload["hoist"], bool):
                raise ValueError("Choose whether the role is shown separately.")
            if payload["hoist"] != role.hoist:
                edit["hoist"] = payload["hoist"]
                changes.append({"field": "hoist", "from": role.hoist, "to": payload["hoist"]})
        permissions: tuple[int, int] | None = None
        if "allow" in payload or "deny" in payload:
            if "allow" not in payload or "deny" not in payload:
                raise ValueError("Send both the allowed and the denied permissions.")
            allow = keys_to_bits(payload["allow"], "allowed")
            deny = keys_to_bits(payload["deny"], "denied")
            if allow & deny:
                raise ValueError("A permission cannot be both allowed and denied.")
            # Bits Stoat added after this catalogue was written are kept exactly as they are.
            allow |= role.allow & ~KNOWN_BITS
            deny |= role.deny & ~KNOWN_BITS
            if (allow, deny) != (role.allow, role.deny):
                permissions = (allow, deny)
                changes.append({
                    "field": "permissions",
                    "allowed": bits_to_keys(allow & ~role.allow), "no_longer_allowed": bits_to_keys(role.allow & ~allow),
                    "denied": bits_to_keys(deny & ~role.deny), "no_longer_denied": bits_to_keys(role.deny & ~deny),
                })
    except ValueError as error:
        raise RoleError(str(error)) from None
    if not changes:
        raise RoleError("There are no changes to save.")
    if edit:
        reason = state.refusal(role, permissions=False)
        if reason:
            raise RoleError(REFUSALS[reason], 403)
    if permissions is not None:
        reason = state.refusal(role, permissions=True)
        if reason:
            raise RoleError(REFUSALS[reason], 403)
        added = (permissions[0] & ~role.allow) & KNOWN_BITS
        missing = added & ~state.grantable_bits()
        if missing:
            raise RoleError(f"Stoatmod and you can only grant permissions you both have. Not available to grant: {permission_names(missing)}.", 403)
    return Plan(edit, permissions, changes)


def plan_order(state: State, payload: Any) -> list[str]:
    """The complete role order, highest first, that Stoat's ranks endpoint expects."""
    if not isinstance(payload, dict) or not isinstance(payload.get("order"), list):
        raise RoleError("Send the new role order.")
    order = payload["order"]
    if not all(isinstance(item, str) and ULID.fullmatch(item) for item in order) or len(set(order)) != len(order):
        raise RoleError("The role order is not valid.")
    movable = [role for role in state.sorted_roles if state.refusal(role, permissions=False) is None]
    if not movable:
        reason = next((state.refusal(role, permissions=False) for role in state.sorted_roles), None)
        raise RoleError(REFUSALS[reason or "above_bot"], 403)
    if set(order) != {role.id for role in movable}:
        raise RoleError("The role list changed. Reload the roles and try again.", 409)
    if order == [role.id for role in movable]:
        raise RoleError("The role order has not changed.")
    locked = [role for role in state.sorted_roles if role.id not in set(order)]
    if [role.rank for role in locked] != list(range(len(locked))):
        # Stoat requires every role above Stoatmod to keep its own position, which cannot be met
        # when their ranks have gaps or repeats. Say so instead of sending a request Stoat will refuse.
        raise RoleError("Stoat cannot reorder these roles from here because the ranks above Stoatmod are not in a simple sequence. Reorder them once in Stoat's own role settings, then try again.", 409)
    return [*(role.id for role in locked), *order]


# --------------------------------------------------------------------------- Stoat client

class StoatError(Exception):
    def __init__(self, status: int, kind: str = "", message: str = "", *, retry_after: float | None = None):
        super().__init__(f"Stoat error {status} {kind}")
        self.status = status
        self.kind = kind
        self.message = message
        self.retry_after = retry_after  # seconds, only on a 429


_STOAT_ERROR_ROWS = [
    {"type": "NotElevated", "status": 403, "message": REFUSALS["above_bot"]},
    {"type": "MissingPermission", "status": 403, "message": "Stoatmod does not have the permission Stoat requires for this change."},
    {"type": "CannotGiveMissingPermissions", "status": 403, "message": "Stoat does not let Stoatmod grant permissions that Stoatmod does not have itself."},
    {"type": "CannotRemoveOwnChannelView", "status": 409, "message": "That change would stop Stoatmod from seeing channels, so Stoat refused it."},
    {"type": "TooManyRoles", "status": 409, "message": "This server has reached Stoat's limit for roles."},
    {"type": "FailedValidation", "status": 400, "message": "Stoat rejected one of the values."},
    {"type": "NotFound", "status": 404, "message": "That role no longer exists in the server."},
    {"type": "InvalidSession", "status": 502, "message": "Stoatmod could not sign in to Stoat. Try again shortly."},
]
STOAT_ERRORS = {row["type"]: (row["status"], row["message"]) for row in _STOAT_ERROR_ROWS}


def describe_stoat_error(error: StoatError) -> RoleError:
    if error.kind in STOAT_ERRORS:
        status, message = STOAT_ERRORS[error.kind]
        return RoleError(message, status)
    if error.status == 404:
        return RoleError(STOAT_ERRORS["NotFound"][1], 404)
    if error.status == 429:
        return rate_limited("stoat", error.retry_after)
    return RoleError("Stoat could not complete the change. Try again in a moment.", 502)


class StoatRoleClient:
    """The few Stoat REST calls role management needs, authenticated as the bot."""

    def __init__(self, api_base: str, token: Callable[[], str]):
        self.api_base = api_base.rstrip("/")
        self.token = token
        self._bot_id: str | None = None
        # What Stoat last told us about each rate-limit bucket: requests left and when it refills.
        self._windows: dict[str, tuple[int, float]] = {}
        self._gates: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _bucket(path: str) -> str:
        """Stoat limits per resource: every call about one server shares a budget."""
        parts = path.split("?", 1)[0].strip("/").split("/")
        return "/".join(parts[:2]) if parts[0] in ("servers", "channels") and len(parts) > 1 else parts[0]

    def _remember(self, bucket: str, headers: Any) -> None:
        try:
            remaining = int(headers.get("x-ratelimit-remaining"))
            refills = int(headers.get("x-ratelimit-reset-after")) / 1000
        except (TypeError, ValueError):
            return
        if len(self._windows) > 500:
            now = time.monotonic()
            self._windows = {key: value for key, value in self._windows.items() if value[1] > now}
        self._windows[bucket] = (remaining, time.monotonic() + refills)

    async def _wait_for_budget(self, bucket: str) -> None:
        remaining, refills_at = self._windows.get(bucket, (1, 0.0))
        wait = refills_at - time.monotonic()
        if remaining > 0 or wait <= 0:
            return
        if wait > HOLD_MAX_SECONDS:
            raise StoatError(429, "RateLimited", retry_after=wait)
        await asyncio.sleep(wait)

    async def request(self, method: str, path: str, *, json_body: Any = None, allow_missing: bool = False) -> Any:
        token = self.token()
        if not token:
            raise RoleError("Role management is not available right now.", 503)
        bucket = self._bucket(path)
        # One request at a time per bucket, so the budget Stoat reports is spent in order, not all at once.
        async with self._gates.setdefault(bucket, asyncio.Lock()):
            await self._wait_for_budget(bucket)
            try:
                async with ClientSession(timeout=ClientTimeout(total=10, connect=3)) as session:
                    async with session.request(method, f"{self.api_base}{path}", json=json_body,
                                               headers={"X-Bot-Token": token}) as response:
                        text = await response.text()
                        try:
                            body = json.loads(text) if text.strip() else None
                        except ValueError:
                            body = None
                        retry_after = None
                        if response.status == 429:
                            milliseconds = body.get("retry_after") if isinstance(body, dict) else None
                            if isinstance(milliseconds, (int, float)) and not isinstance(milliseconds, bool):
                                retry_after = wait_seconds(milliseconds / 1000)
                            else:
                                try:
                                    retry_after = wait_seconds(int(response.headers.get("x-ratelimit-reset-after")) / 1000)
                                except (TypeError, ValueError):
                                    retry_after = wait_seconds(None)
                            self._windows[bucket] = (0, time.monotonic() + retry_after)
                        else:
                            self._remember(bucket, response.headers)
                        if response.status == 404 and allow_missing:
                            return None
                        if response.status >= 400:
                            kind = str(body.get("type") or "") if isinstance(body, dict) else ""
                            raise StoatError(response.status, kind, retry_after=retry_after)
                        return body
            except (asyncio.TimeoutError, ClientError, OSError):
                raise StoatError(502, "Unreachable") from None

    async def get_self_id(self) -> str:
        if self._bot_id is None:
            user = await self.request("GET", "/users/@me")
            self._bot_id = str(user["_id"])
        return self._bot_id

    async def get_server(self, server_id: str) -> dict[str, Any]:
        return await self.request("GET", f"/servers/{quote(server_id, safe='')}?include_channels=false")

    async def get_member(self, server_id: str, user_id: str) -> dict[str, Any] | None:
        return await self.request("GET", f"/servers/{quote(server_id, safe='')}/members/{quote(user_id, safe='')}",
                                  allow_missing=True)

    async def edit_role(self, server_id: str, role_id: str, payload: dict[str, Any]) -> None:
        await self.request("PATCH", f"/servers/{quote(server_id, safe='')}/roles/{quote(role_id, safe='')}", json_body=payload)

    async def set_role_permissions(self, server_id: str, role_id: str, allow: int, deny: int) -> None:
        await self.request("PUT", f"/servers/{quote(server_id, safe='')}/permissions/{quote(role_id, safe='')}",
                           json_body={"permissions": {"allow": allow, "deny": deny}})

    async def reorder_roles(self, server_id: str, ranks: list[str]) -> None:
        await self.request("PATCH", f"/servers/{quote(server_id, safe='')}/roles/ranks", json_body={"ranks": ranks})

    async def create_role(self, server_id: str, name: str) -> str:
        created = await self.request("POST", f"/servers/{quote(server_id, safe='')}/roles", json_body={"name": name})
        return str(created["id"])

    async def delete_role(self, server_id: str, role_id: str) -> None:
        await self.request("DELETE", f"/servers/{quote(server_id, safe='')}/roles/{quote(role_id, safe='')}")

    async def post_embed(self, channel_id: str, title: str, description: str, colour: str) -> None:
        await self.request("POST", f"/channels/{quote(channel_id, safe='')}/messages",
                           json_body={"embeds": [{"title": title, "description": description, "colour": colour}]})


# --------------------------------------------------------------------------- HTTP layer

@dataclass
class Hooks:
    database: Callable[[web.Request], Any]
    session: Callable[[web.Request], tuple[str, str]]
    require_csrf: Callable[[web.Request], None]
    json_error: Callable[[str, int], web.Response]


HOOKS_KEY = web.AppKey("role_manager_hooks", Hooks)
CLIENT_KEY = web.AppKey("role_manager_client", object)
LIMITS_KEY = web.AppKey("role_manager_limits", dict)
LOCKS_KEY = web.AppKey("role_manager_locks", dict)
SEEN_KEY = web.AppKey("role_manager_blocked_seen", dict)


def _limit(request: web.Request, kind: str, server_id: str, user_id: str, allowed: tuple[int, int]) -> None:
    count, window = allowed
    attempts: deque[float] = request.app[LIMITS_KEY][f"{kind}:{server_id}:{user_id}"]
    now = time.monotonic()
    while attempts and now - attempts[0] > window:
        attempts.popleft()
    if len(attempts) >= count:
        raise rate_limited("stoatmod", window - (now - attempts[0]))
    attempts.append(now)


async def _load(request: web.Request, server_id: str, user_id: str, *, members_from: State | None = None) -> State:
    """Fetch the server and both members. `members_from` reuses the members of a state loaded moments ago
    (a role change never changes who holds which role), so a refresh after a change costs one request, not three."""
    client = request.app[CLIENT_KEY]
    try:
        bot_id = await client.get_self_id()
        if members_from is not None:
            server = await client.get_server(server_id)
            bot_member, actor_member = members_from.bot_member, members_from.actor_member
        else:
            results = await asyncio.gather(
                client.get_server(server_id), client.get_member(server_id, bot_id), client.get_member(server_id, user_id),
                return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
            server, bot_member, actor_member = results
    except StoatError as error:
        if error.status == 404:
            raise RoleError("Stoatmod is not in this server any more.", 404) from None
        raise describe_stoat_error(error) from None
    return build_state(server_id, user_id, bot_id, server, bot_member, actor_member)


def _error_response(hooks: Hooks, error: RoleError) -> web.Response:
    if error.retry_after is None:
        return hooks.json_error(error.message, error.status)
    wait = wait_seconds(error.retry_after)
    return web.json_response(
        {"error": error.message, "rate_limited": True, "retry_after": round(wait, 1), "source": error.source},
        status=429, headers={"Retry-After": str(math.ceil(wait))})


async def _guarded(request: web.Request, work: Callable[..., Any], *, write: bool, csrf: bool) -> web.Response:
    hooks: Hooks = request.app[HOOKS_KEY]
    if csrf:
        hooks.require_csrf(request)
    server_id, user_id = hooks.session(request)
    try:
        _limit(request, "write" if write else "read", server_id, user_id, WRITE_LIMIT if write else READ_LIMIT)
        if not write:
            return web.json_response(await work(server_id, user_id))
        lock = request.app[LOCKS_KEY].setdefault(server_id, asyncio.Lock())
        async with lock:  # one change at a time per server, so every check sees the previous result
            return await work(server_id, user_id)
    except RoleError as error:
        return _error_response(hooks, error)
    except StoatError as error:
        return _error_response(hooks, describe_stoat_error(error))


async def _body(request: web.Request) -> Any:
    try:
        return await request.json()
    except (ValueError, TypeError):
        raise RoleError("A JSON request body is required.") from None


def _record(request: web.Request, server_id: str, user_id: str, event: str, message: str, **details: Any) -> None:
    request.app[HOOKS_KEY].database(request).add_event(
        server_id=server_id, event_type=event, actor_id=user_id, details={"message": message[:300], **details})


# --------------------------------------------------------------------------- moderation log channel

LOG_TIMEOUT = 5  # seconds: a slow log post never holds up the admin for long
LOG_LIMIT = 1700  # characters of embed description
BLOCKED_LOG_SECONDS = 600  # one "blocked" post per user, role and reason in this time
BLUE, GREEN, AMBER, RED = "#5865F2", "#3BA55D", "#F59E0B", "#ED4245"


def _code(value: Any, limit: int = 90) -> str:
    """Text as inline code: backticks, line breaks and long runs cannot break out of it."""
    text = " ".join(str(value).replace("`", "'").split()) or "-"
    return f"`{text[:limit]}…`" if len(text) > limit else f"`{text}`"


def _colour_text(value: str | None) -> str:
    return _code(value, 140) if value else "*none*"


def accent_colour(css: str | None) -> str:
    """A safe embed accent for a role colour: the solid colour, or the first colour of a gradient."""
    if not css:
        return BLUE
    try:
        value = validate_role_colour(css)
    except ValueError:
        return BLUE
    candidates = [value]
    if "-gradient(" in value:
        candidates = [part.strip() for part in _split_arguments(value[value.index("(") + 1:-1])]
    for candidate in candidates:
        stop = _STOP.fullmatch(candidate)
        try:
            term = _colour_term(stop.group(1) if stop else candidate)
        except ValueError:
            continue
        if not term.startswith("var("):
            return term
    return BLUE


def _actor_label(database: Any, server_id: str, user_id: str) -> str:
    identity = database.get_recorded_user_identity(user_id, server_id) or {}
    return _code(identity.get("full_username") or user_id)


def _log_text(title: str, colour: str, lines: list[str]) -> tuple[str, str, str]:
    text = "\n".join(lines)
    return title, (text[:LOG_LIMIT].rstrip() + "…" if len(text) > LOG_LIMIT else text), colour


def _change_lines(changes: list[dict[str, Any]]) -> list[str]:
    lines = []
    for change in changes:
        field = change["field"]
        if field == "name":
            lines.append(f"**Name:** {_code(change['from'])} → {_code(change['to'])}")
        elif field == "colour":
            lines.append(f"**Colour:** {_colour_text(change['from'])} → {_colour_text(change['to'])}")
        elif field == "hoist":
            lines.append(f"**Shown separately:** {'Yes' if change['from'] else 'No'} → {'Yes' if change['to'] else 'No'}")
        elif field == "permissions":
            for label, key in (("Now allowed", "allowed"), ("No longer allowed", "no_longer_allowed"),
                               ("Now denied", "denied"), ("No longer denied", "no_longer_denied")):
                if change[key]:
                    lines.append(f"**{label}:** {', '.join(PERMISSION_NAMES[name] for name in change[key])}")
    return lines


def update_log(actor: str, role: Role, changes: list[dict[str, Any]], failure: str | None = None) -> tuple[str, str, str]:
    name = next((change["to"] for change in changes if change["field"] == "name"), role.name)
    colour = next((change["to"] for change in changes if change["field"] == "colour"), role.colour)
    lines = [f"**Role:** {_code(name)} (`{role.id}`)", f"**Changed by:** {actor}", *_change_lines(changes)]
    if failure:
        lines.append(f"**Not applied:** {failure}")
    heading = "⚠️ Role partly updated from dashboard" if failure else "🔧 Role updated from dashboard"
    return _log_text(heading, AMBER if failure else accent_colour(colour), lines)


def order_log(actor: str, names: list[str]) -> tuple[str, str, str]:
    shown = names[:25]
    lines = [f"**Changed by:** {actor}", "**New order, highest first:**",
             *[f"{index}. {_code(name)}" for index, name in enumerate(shown, start=1)]]
    if len(names) > len(shown):
        lines.append(f"…and {len(names) - len(shown)} more")
    lines.append("*Roles above Stoatmod keep their place.*")
    return _log_text("🔧 Role order changed from dashboard", BLUE, lines)


def created_log(actor: str, name: str, role_id: str) -> tuple[str, str, str]:
    return _log_text("✨ Role created from dashboard", GREEN, [f"**Role:** {_code(name)} (`{role_id}`)", f"**Changed by:** {actor}"])


def deleted_log(actor: str, role: Role) -> tuple[str, str, str]:
    lines = [f"**Role:** {_code(role.name)} (`{role.id}`)", f"**Changed by:** {actor}"]
    if role.colour:
        lines.append(f"**Colour it had:** {_colour_text(role.colour)}")
    if role.allow & KNOWN_BITS:
        lines.append(f"**Permissions it allowed:** {permission_names(role.allow)}")
    return _log_text("🧹 Role deleted from dashboard", RED, lines)


def blocked_log(actor: str, attempt: str, reason: str, role: Role | None) -> tuple[str, str, str]:
    lines = [f"**Attempt:** {attempt}", f"**Attempted by:** {actor}"]
    if role is not None:
        lines.insert(0, f"**Role:** {_code(role.name)} (`{role.id}`)")
    lines.append(f"**Why it was refused:** {reason}")
    return _log_text("🚫 Role change blocked", AMBER, lines)


async def _post_log(request: web.Request, server_id: str, entry: tuple[str, str, str]) -> str:
    """Post to the moderation log channel. Returns 'posted', 'no_channel' or 'failed'; never raises,
    because the change itself has already been made."""
    channel_id = request.app[HOOKS_KEY].database(request).get_log_channel(server_id)
    if not channel_id:
        return "no_channel"
    try:
        await asyncio.wait_for(request.app[CLIENT_KEY].post_embed(channel_id, *entry), LOG_TIMEOUT)
        return "posted"
    except Exception as error:  # noqa: BLE001 - a log post must never undo or hide a role change
        logger.warning("role_log_post_failed server_id=%s channel_id=%s error=%s", server_id, channel_id, type(error).__name__)
        return "failed"


async def _blocked(request: web.Request, server_id: str, user_id: str, attempt: str, error: RoleError, role: Role | None = None) -> None:
    """Record, and tell the log channel about, a request the hierarchy rules refused."""
    if error.status != 403:
        return
    key = (server_id, user_id, role.id if role else "", attempt, error.message)
    seen: dict = request.app[SEEN_KEY]
    now = time.monotonic()
    if now - seen.get(key, -BLOCKED_LOG_SECONDS) < BLOCKED_LOG_SECONDS:
        return
    if len(seen) > 500:
        seen.clear()
    seen[key] = now
    database = request.app[HOOKS_KEY].database(request)
    _record(request, server_id, user_id, "role_change_blocked", f"Blocked: {attempt}.",
            attempt=attempt, reason=error.message, **({"role_id": role.id, "role_name": role.name} if role else {}))
    await _post_log(request, server_id, blocked_log(_actor_label(database, server_id, user_id), attempt, error.message, role))


async def _fresh(request: web.Request, server_id: str, user_id: str, *, members_from: State | None = None) -> dict[str, Any]:
    state = await _load(request, server_id, user_id, members_from=members_from)
    configured = bool(request.app[HOOKS_KEY].database(request).get_log_channel(server_id))
    return {**snapshot(state), "log_channel": {"configured": configured}}


async def _after_change(request: web.Request, server_id: str, user_id: str, before: State,
                        extra: dict[str, Any], status: int = 200) -> web.Response:
    """Answer a change that is already live in Stoat with the new list. If Stoat will not give us the list
    right now, still answer success and say when the dashboard should fetch it; a saved change is never an error."""
    try:
        return web.json_response({**await _fresh(request, server_id, user_id, members_from=before), **extra}, status=status)
    except RoleError as error:
        limited = error.retry_after is not None
        logger.info("role_refresh_deferred server_id=%s rate_limited=%s", server_id, limited)
        wait = wait_seconds(error.retry_after) if limited else 2.0
        return web.json_response({"saved": True, "needs_refresh": True, "rate_limited": limited,
                                  "retry_after": round(wait, 1), **extra}, status=status)


async def list_roles(request: web.Request) -> web.Response:
    async def work(server_id: str, user_id: str) -> dict[str, Any]:
        return await _fresh(request, server_id, user_id)
    return await _guarded(request, work, write=False, csrf=False)


async def update_role(request: web.Request) -> web.Response:
    role_id = request.match_info["role_id"]

    async def work(server_id: str, user_id: str) -> web.Response:
        payload = await _body(request)
        state = await _load(request, server_id, user_id)
        role = state.roles.get(role_id) if ULID.fullmatch(role_id) else None
        if role is None:
            raise RoleError("That role does not exist in this server.", 404)
        try:
            plan = plan_update(state, role, payload)
        except RoleError as error:
            await _blocked(request, server_id, user_id, "Edit role", error, role)
            raise
        client = request.app[CLIENT_KEY]
        applied: list[dict[str, Any]] = []
        failure: RoleError | None = None
        try:
            if plan.edit:
                await client.edit_role(server_id, role_id, plan.edit)
                applied = [change for change in plan.changes if change["field"] != "permissions"]
            if plan.set_permissions is not None:
                await client.set_role_permissions(server_id, role_id, *plan.set_permissions)
                applied = plan.changes
        except StoatError as error:
            failure = describe_stoat_error(error)
        database = request.app[HOOKS_KEY].database(request)
        log_status = "no_channel"
        if applied:
            fields = ", ".join(sorted({change["field"] for change in applied}))
            _record(request, server_id, user_id, "role_updated", f"Updated role {role.name}: {fields}.",
                    role_id=role_id, role_name=role.name, changes=applied)
            log_status = await _post_log(request, server_id, update_log(
                _actor_label(database, server_id, user_id), role, applied, failure.message if failure else None))
        if failure is not None:
            if not applied:
                await _blocked(request, server_id, user_id, "Edit role", failure, role)
            if applied:
                failure.message = f"Some changes were saved, but not all. {failure.message}"
            raise failure
        return await _after_change(request, server_id, user_id, state, {"changed_role_id": role_id, "log_status": log_status})
    return await _guarded(request, work, write=True, csrf=True)


async def reorder_roles(request: web.Request) -> web.Response:
    async def work(server_id: str, user_id: str) -> web.Response:
        payload = await _body(request)
        state = await _load(request, server_id, user_id)
        try:
            ranks = plan_order(state, payload)
        except RoleError as error:
            await _blocked(request, server_id, user_id, "Reorder roles", error)
            raise
        await request.app[CLIENT_KEY].reorder_roles(server_id, ranks)
        names = [state.roles[role_id].name for role_id in payload["order"]]
        _record(request, server_id, user_id, "roles_reordered", "Changed the order of the roles.",
                order=[{"role_id": role_id, "role_name": name} for role_id, name in zip(payload["order"], names)])
        database = request.app[HOOKS_KEY].database(request)
        log_status = await _post_log(request, server_id, order_log(_actor_label(database, server_id, user_id), names))
        return await _after_change(request, server_id, user_id, state, {"log_status": log_status})
    return await _guarded(request, work, write=True, csrf=True)


async def create_role(request: web.Request) -> web.Response:
    async def work(server_id: str, user_id: str) -> web.Response:
        payload = await _body(request)
        if not isinstance(payload, dict) or set(payload) - {"name"}:
            raise RoleError("A JSON object with a name is required.")
        try:
            name = validate_role_name(payload.get("name"))
        except ValueError as error:
            raise RoleError(str(error)) from None
        state = await _load(request, server_id, user_id)
        blocked = create_refusal(state)
        if blocked:
            error = RoleError(blocked, 403)
            await _blocked(request, server_id, user_id, "Create role", error)
            raise error
        if len(state.roles) >= MAX_ROLES:
            raise RoleError(STOAT_ERRORS["TooManyRoles"][1], 409)
        role_id = await request.app[CLIENT_KEY].create_role(server_id, name)
        _record(request, server_id, user_id, "role_created", f"Created role {name}.", role_id=role_id, role_name=name)
        database = request.app[HOOKS_KEY].database(request)
        log_status = await _post_log(request, server_id, created_log(_actor_label(database, server_id, user_id), name, role_id))
        return await _after_change(request, server_id, user_id, state, {"changed_role_id": role_id, "log_status": log_status}, status=201)
    return await _guarded(request, work, write=True, csrf=True)


def role_uses(database: Any, server_id: str, role_id: str) -> list[str]:
    """Stoatmod features that point at this role; deleting it would silently break them."""
    uses = []
    if role_id in database.list_auto_roles(server_id):
        uses.append("Auto-roles")
    if role_id == (database.applications.settings(server_id).get("access_role_id") or ""):
        uses.append("Applications")
    for panel in database.reaction_roles.panels(server_id):
        if panel.get("status") != "deleted" and any(option.get("role_id") == role_id for option in panel["config"]["options"]):
            uses.append("Reaction roles")
            break
    if any(role_id in json.dumps(rule, default=str) for rule in database.list_automation_rules(server_id)):
        uses.append("Automation Lab")
    return uses


async def delete_role(request: web.Request) -> web.Response:
    role_id = request.match_info["role_id"]

    async def work(server_id: str, user_id: str) -> web.Response:
        payload = await _body(request)
        state = await _load(request, server_id, user_id)
        role = state.roles.get(role_id) if ULID.fullmatch(role_id) else None
        if role is None:
            raise RoleError("That role does not exist in this server.", 404)
        reason = state.refusal(role, permissions=False)
        if reason:
            error = RoleError(REFUSALS[reason], 403)
            await _blocked(request, server_id, user_id, "Delete role", error, role)
            raise error
        if not isinstance(payload, dict) or payload.get("confirm_name") != role.name:
            raise RoleError("Type the role name exactly to confirm that you want to delete it.")
        database = request.app[HOOKS_KEY].database(request)
        uses = role_uses(database, server_id, role_id)
        if uses:
            raise RoleError(f"This role is used by {', '.join(uses)}. Remove it there first, then delete the role.", 409)
        await request.app[CLIENT_KEY].delete_role(server_id, role_id)
        _record(request, server_id, user_id, "role_deleted", f"Deleted role {role.name}.", role_id=role_id, role_name=role.name)
        log_status = await _post_log(request, server_id, deleted_log(_actor_label(database, server_id, user_id), role))
        return await _after_change(request, server_id, user_id, state, {"log_status": log_status})
    return await _guarded(request, work, write=True, csrf=True)


def register(app: web.Application, hooks: Hooks, client: Any) -> None:
    app[HOOKS_KEY] = hooks
    app[CLIENT_KEY] = client
    app[LIMITS_KEY] = defaultdict(deque)
    app[LOCKS_KEY] = {}
    app[SEEN_KEY] = {}
    app.router.add_get("/api/roles", list_roles)
    app.router.add_post("/api/roles", create_role)
    app.router.add_put("/api/roles/order", reorder_roles)
    app.router.add_put("/api/roles/{role_id}", update_role)
    app.router.add_delete("/api/roles/{role_id}", delete_role)
