import asyncio
import copy
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer

from api import role_manager as rm
from api.server import CSRF_COOKIE, DATABASE_KEY, create_app

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "role-colours.json").read_text(encoding="utf-8"))
# Stoat's own validator for role colours (crates/core/models/src/v0/server_members.rs, RE_COLOUR).
STOAT_COLOUR = re.compile(
    r"^(?:[a-z ]+|var\(--[a-z\d-]+\)|rgba?\([\d, ]+\)|#[a-f0-9]+|(repeating-)?(linear|conic|radial)-gradient\("
    r"([a-z ]+|var\(--[a-z\d-]+\)|rgba?\([\d, ]+\)|#[a-f0-9]+|\d+deg)([ ]+in[ ]+[a-z-]+([ ]+(shorter|longer|increasing|decreasing)[ ]+hue)?)?"
    r"([ ]+(\d{1,3}%|0))?(,[ ]*([a-z ]+|var\(--[a-z\d-]+\)|rgba?\([\d, ]+\)|#[a-f0-9]+)([ ]+(\d{1,3}%|0))?)+\))$",
    re.IGNORECASE,
)


def ulid(number: int) -> str:
    return f"01{number:024d}"


ADMIN, BOT_ROLE, MODS, MEMBERS, VIP = (ulid(n) for n in (1, 2, 3, 4, 5))
BOT = ulid(99)
OWNER = ulid(50)


def raw_role(name, rank, allow=0, deny=0, colour=None, hoist=False):
    role = {"name": name, "rank": rank, "permissions": {"a": allow, "d": deny}, "hoist": hoist}
    if colour:
        role["colour"] = colour
    return role


def bit(key):
    return rm.PERMISSION_BITS[key]


def server_json(owner=OWNER):
    return {
        "_id": "server", "name": "Test", "owner": owner, "default_permissions": bit("view_channel") | bit("send_messages"),
        "roles": {
            ADMIN: raw_role("Admin", 0, allow=bit("manage_roles") | bit("manage_permissions") | bit("ban_members")),
            BOT_ROLE: raw_role("Stoatmod", 1, allow=bit("manage_roles") | bit("manage_permissions") | bit("kick_members") | bit("view_channel") | bit("send_messages") | bit("react")),
            MODS: raw_role("Mods", 2, allow=bit("kick_members"), colour="#00ff00", hoist=True),
            MEMBERS: raw_role("Members", 3, allow=bit("react")),
            VIP: raw_role("VIP", 4),
        },
    }


class FakeStoat:
    """A Stoat server that enforces nothing, so tests show what the dashboard itself refuses."""

    def __init__(self):
        self.servers = {"server": server_json()}
        self.members = {("server", BOT): {"roles": [BOT_ROLE]}, ("server", "admin"): {"roles": [ADMIN]}}
        self.calls = []
        self.fail = None
        self.posts = []
        self.fail_post = None
        self.post_delay = 0

    async def get_self_id(self):
        return BOT

    async def get_server(self, server_id):
        if server_id not in self.servers:
            raise rm.StoatError(404, "NotFound")
        return copy.deepcopy(self.servers[server_id])

    async def get_member(self, server_id, user_id):
        member = self.members.get((server_id, user_id))
        return copy.deepcopy(member) if member else None

    def _maybe_fail(self):
        if self.fail:
            raise self.fail

    async def edit_role(self, server_id, role_id, payload):
        self.calls.append(("edit", role_id, payload))
        self._maybe_fail()
        role = self.servers[server_id]["roles"][role_id]
        for key in ("name", "colour", "hoist"):
            if key in payload:
                role[key] = payload[key]
        if "Colour" in payload.get("remove", []):
            role.pop("colour", None)

    async def set_role_permissions(self, server_id, role_id, allow, deny):
        self.calls.append(("permissions", role_id, allow, deny))
        if self.fail_permissions:
            raise self.fail_permissions
        self.servers[server_id]["roles"][role_id]["permissions"] = {"a": allow, "d": deny}

    fail_permissions = None

    async def post_embed(self, channel_id, title, description, colour):
        if self.post_delay:
            await asyncio.sleep(self.post_delay)
        if self.fail_post:
            raise self.fail_post
        self.posts.append((channel_id, title, description, colour))

    async def reorder_roles(self, server_id, ranks):
        self.calls.append(("ranks", ranks))
        self._maybe_fail()
        for index, role_id in enumerate(ranks):
            self.servers[server_id]["roles"][role_id]["rank"] = index

    async def create_role(self, server_id, name):
        self.calls.append(("create", name))
        self._maybe_fail()
        role_id = ulid(100 + len(self.servers[server_id]["roles"]))
        self.servers[server_id]["roles"][role_id] = raw_role(name, len(self.servers[server_id]["roles"]))
        return role_id

    async def delete_role(self, server_id, role_id):
        self.calls.append(("delete", role_id))
        self._maybe_fail()
        del self.servers[server_id]["roles"][role_id]


class ColourTests(unittest.TestCase):
    def test_valid_colours_are_canonical_and_accepted_by_stoat(self):
        for text, expected in FIXTURE["valid"].items():
            with self.subTest(text):
                result = rm.validate_role_colour(text)
                self.assertEqual(result, expected)
                self.assertLessEqual(len(result), rm.COLOUR_MAX)
                self.assertRegex(result, STOAT_COLOUR)

    def test_invalid_colours_are_refused(self):
        for text in FIXTURE["invalid"]:
            with self.subTest(text):
                with self.assertRaises(ValueError):
                    rm.validate_role_colour(text)

    def test_non_strings_are_refused(self):
        for value in (None, 5, ["red"], {"colour": "red"}, True):
            with self.assertRaises(ValueError):
                rm.validate_role_colour(value)

    def test_gradients_cannot_exceed_stoats_length_limit(self):
        stops = ", ".join(["rgb(255, 255, 255)"] * 8)
        with self.assertRaises(ValueError):
            rm.validate_role_colour(f"linear-gradient({stops})")

    def test_names_are_trimmed_and_limited(self):
        self.assertEqual(rm.validate_role_name("  Night   Owls "), "Night Owls")
        self.assertEqual(rm.validate_role_name("new\nline"), "new line")
        self.assertEqual(rm.validate_role_name("x" * 32), "x" * 32)
        for value in ("", "   ", "x" * 33, "bad\x00name", "zero​width", None, 7):
            with self.assertRaises(ValueError):
                rm.validate_role_name(value)


class PermissionCatalogueTests(unittest.TestCase):
    def test_bits_are_unique_and_match_the_stoat_library(self):
        self.assertEqual(len(rm.PERMISSION_BITS), len({item["bit"] for item in rm.PERMISSIONS}))
        try:
            import stoat
        except ImportError:  # the library is optional for the dashboard process
            self.skipTest("stoat.py is not installed")
        for key, value in rm.PERMISSION_BITS.items():
            with self.subTest(key):
                self.assertEqual(stoat.Permissions(**{key: True}).value, value)

    def test_every_permission_is_grouped_and_described(self):
        groups = {group["id"] for group in rm.PERMISSION_GROUPS}
        for item in rm.PERMISSIONS:
            self.assertIn(item["group"], groups)
            self.assertTrue(item["name"] and item["description"].endswith("."))

    def test_permission_lists_reject_unknown_duplicate_and_non_list_values(self):
        self.assertEqual(rm.keys_to_bits(["react", "send_messages"], "allowed"), bit("react") | bit("send_messages"))
        for value in (["administrator"], ["react", "react"], "react", [1], None, [["react"]], ["react"] * 100):
            with self.assertRaises(ValueError):
                rm.keys_to_bits(value, "allowed")


class HierarchyTests(unittest.TestCase):
    def state(self, *, user="admin", owner=OWNER, bot_roles=(BOT_ROLE,), actor_roles=(ADMIN,), server=None):
        server = server or server_json(owner)
        return rm.build_state("server", user, BOT, server, {"roles": list(bot_roles)} if bot_roles is not None else None,
                              {"roles": list(actor_roles)} if actor_roles is not None else None)

    def role(self, state, role_id):
        return state.roles[role_id]

    def test_only_roles_below_the_bot_are_editable(self):
        state = self.state(user=OWNER, actor_roles=())
        self.assertEqual(state.refusal(self.role(state, ADMIN), permissions=False), "above_bot")
        self.assertEqual(state.refusal(self.role(state, BOT_ROLE), permissions=False), "above_bot")  # equal rank is refused too
        for role_id in (MODS, MEMBERS, VIP):
            self.assertIsNone(state.refusal(self.role(state, role_id), permissions=False))

    def test_a_bot_without_a_role_can_edit_nothing(self):
        state = self.state(user=OWNER, bot_roles=())
        self.assertEqual(state.refusal(self.role(state, VIP), permissions=False), "bot_has_no_role")
        self.assertTrue(all(not role["editable"] for role in rm.snapshot(state)["roles"]))

    def test_the_bot_needs_manage_roles_and_manage_permissions(self):
        server = server_json()
        server["roles"][BOT_ROLE]["permissions"]["a"] = bit("view_channel")
        state = self.state(user=OWNER, server=server)
        self.assertEqual(state.refusal(self.role(state, MODS), permissions=False), "bot_needs_manage_roles")
        self.assertEqual(state.refusal(self.role(state, MODS), permissions=True), "bot_needs_manage_permissions")

    def test_a_non_owner_cannot_touch_roles_at_or_above_their_own(self):
        state = self.state(actor_roles=(MODS,))
        self.assertEqual(state.refusal(self.role(state, MODS), permissions=False), "you_need_manage_roles")
        server = server_json()
        server["roles"][MODS]["permissions"]["a"] |= bit("manage_roles")
        state = self.state(actor_roles=(MODS,), server=server)
        self.assertEqual(state.refusal(self.role(state, MODS), permissions=False), "above_you")
        self.assertEqual(state.refusal(self.role(state, MEMBERS), permissions=False), None)

    def test_an_actor_outside_the_server_has_no_authority(self):
        state = self.state(actor_roles=None)
        self.assertEqual(state.refusal(self.role(state, VIP), permissions=False), "you_need_manage_roles")

    def test_the_owner_is_limited_only_by_the_bot(self):
        state = self.state(user=OWNER, actor_roles=None)
        self.assertEqual(state.refusal(self.role(state, MODS), permissions=False), None)
        self.assertEqual(state.refusal(self.role(state, ADMIN), permissions=False), "above_bot")

    def test_permissions_resolve_default_then_roles_from_the_lowest_up(self):
        server = server_json()
        server["roles"][MEMBERS]["permissions"] = {"a": bit("manage_messages"), "d": bit("send_messages")}
        roles = {role_id: rm.parse_role(role_id, raw) for role_id, raw in server["roles"].items()}
        bits = rm.server_bits(roles, server["default_permissions"], {"roles": [MEMBERS, VIP]})
        self.assertTrue(bits & bit("manage_messages"))
        self.assertTrue(bits & bit("view_channel"))
        self.assertFalse(bits & bit("send_messages"))

    def test_grantable_permissions_are_the_ones_both_hold(self):
        state = self.state(actor_roles=(ADMIN,))
        grantable = set(rm.bits_to_keys(state.grantable_bits()))
        self.assertIn("manage_roles", grantable)  # both hold it
        self.assertIn("send_messages", grantable)  # both get it from the default permissions
        self.assertNotIn("ban_members", grantable)  # the admin has it, the bot does not
        self.assertNotIn("kick_members", grantable)  # the bot has it, the admin does not


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.state = rm.build_state("server", OWNER, BOT, server_json(), {"roles": [BOT_ROLE]}, None)

    def plan(self, role_id, payload, state=None):
        state = state or self.state
        return rm.plan_update(state, state.roles[role_id], payload)

    def test_only_changed_fields_are_sent(self):
        plan = self.plan(MODS, {"name": "Mods", "colour": "#00FF00", "hoist": False})
        self.assertEqual(plan.edit, {"hoist": False})
        self.assertEqual([change["field"] for change in plan.changes], ["hoist"])

    def test_removing_a_colour_uses_stoats_remove_list(self):
        self.assertEqual(self.plan(MODS, {"colour": None}).edit, {"remove": ["Colour"]})
        with self.assertRaises(rm.RoleError):
            self.plan(VIP, {"colour": None})  # nothing to remove: no changes

    def test_a_noop_is_refused(self):
        with self.assertRaises(rm.RoleError) as caught:
            self.plan(MODS, {"name": "Mods"})
        self.assertEqual(caught.exception.status, 400)

    def test_unknown_fields_and_bad_types_are_refused(self):
        for payload in ({"rank": 0}, {"permissions": 1}, {"hoist": "yes"}, {"name": 5}, {"colour": "url(x)"}, [], "x", None, {}):
            with self.subTest(payload):
                with self.assertRaises(rm.RoleError):
                    self.plan(MODS, payload)

    def test_permission_changes_need_both_lists_and_no_overlap(self):
        for payload in ({"allow": ["react"]}, {"deny": ["react"]}, {"allow": ["react"], "deny": ["react"]},
                        {"allow": ["everything"], "deny": []}, {"allow": [], "deny": ["react", "react"]}):
            with self.subTest(payload):
                with self.assertRaises(rm.RoleError):
                    self.plan(MODS, payload)

    def test_permission_diff_and_unknown_bits_are_preserved(self):
        server = server_json()
        server["roles"][MODS]["permissions"] = {"a": bit("kick_members") | (1 << 50), "d": 1 << 51}
        state = rm.build_state("server", OWNER, BOT, server, {"roles": [BOT_ROLE]}, None)
        plan = self.plan(MODS, {"allow": ["kick_members", "react"], "deny": ["send_messages"]}, state)
        allow, deny = plan.set_permissions
        self.assertEqual(allow, bit("kick_members") | bit("react") | (1 << 50))
        self.assertEqual(deny, bit("send_messages") | (1 << 51))
        change = plan.changes[0]
        self.assertEqual((change["allowed"], change["denied"]), (["react"], ["send_messages"]))

    def test_permissions_the_bot_lacks_cannot_be_granted(self):
        with self.assertRaises(rm.RoleError) as caught:
            self.plan(MODS, {"allow": ["kick_members", "ban_members"], "deny": []})
        self.assertEqual(caught.exception.status, 403)
        self.assertIn("Ban Members", caught.exception.message)

    def test_permissions_the_actor_lacks_cannot_be_granted(self):
        state = rm.build_state("server", "helper", BOT, server_json(), {"roles": [BOT_ROLE]}, {"roles": [ulid(7)]})
        server = server_json()
        server["roles"][ulid(7)] = raw_role("Helper", 1, allow=bit("manage_roles") | bit("manage_permissions"))
        server["roles"][BOT_ROLE]["rank"] = 0
        state = rm.build_state("server", "helper", BOT, server, {"roles": [BOT_ROLE]}, {"roles": [ulid(7)]})
        with self.assertRaises(rm.RoleError) as caught:
            self.plan(VIP, {"allow": ["react", "kick_members"], "deny": []}, state)
        self.assertIn("Kick Members", caught.exception.message)

    def test_denying_or_removing_a_permission_the_bot_lacks_is_left_to_stoat(self):
        plan = self.plan(MODS, {"allow": [], "deny": ["ban_members"]})
        self.assertEqual(plan.set_permissions, (0, bit("ban_members")))

    def test_roles_above_the_bot_are_refused_for_every_kind_of_change(self):
        for payload in ({"name": "Boss"}, {"allow": ["react"], "deny": []}):
            with self.assertRaises(rm.RoleError) as caught:
                self.plan(ADMIN, payload)
            self.assertEqual(caught.exception.status, 403)

    def test_a_name_change_does_not_need_manage_permissions(self):
        server = server_json()
        server["roles"][BOT_ROLE]["permissions"]["a"] &= ~bit("manage_permissions")
        state = rm.build_state("server", OWNER, BOT, server, {"roles": [BOT_ROLE]}, None)
        self.assertEqual(self.plan(MODS, {"name": "Moderators"}, state).edit, {"name": "Moderators"})
        with self.assertRaises(rm.RoleError):
            self.plan(MODS, {"allow": [], "deny": ["react"]}, state)

    def test_order_keeps_locked_roles_in_place_and_covers_every_editable_role(self):
        self.assertEqual(rm.plan_order(self.state, {"order": [VIP, MODS, MEMBERS]}), [ADMIN, BOT_ROLE, VIP, MODS, MEMBERS])
        for order in ([MODS, MEMBERS], [VIP, MODS, MEMBERS, ADMIN], [MODS, MODS, MEMBERS, VIP], [MODS, MEMBERS, VIP],
                      ["nope", MEMBERS, VIP], "x", None):
            with self.subTest(order):
                with self.assertRaises(rm.RoleError):
                    rm.plan_order(self.state, {"order": order})
        with self.assertRaises(rm.RoleError):
            rm.plan_order(self.state, {})


class OrderGapTests(unittest.TestCase):
    def state(self, ranks):
        server = server_json()
        for role_id, rank in zip((ADMIN, BOT_ROLE, MODS, MEMBERS, VIP), ranks):
            server["roles"][role_id]["rank"] = rank
        return rm.build_state("server", OWNER, BOT, server, {"roles": [BOT_ROLE]}, None)

    def test_gaps_among_the_roles_below_stoatmod_are_fine(self):
        state = self.state([0, 1, 5, 9, 20])
        self.assertEqual(rm.plan_order(state, {"order": [VIP, MODS, MEMBERS]}), [ADMIN, BOT_ROLE, VIP, MODS, MEMBERS])

    def test_gaps_or_repeats_above_stoatmod_stop_a_reorder_that_stoat_would_refuse(self):
        for ranks in ([0, 3, 4, 5, 6], [0, 1, 1, 5, 6], [1, 2, 3, 4, 5]):
            state = self.state(ranks)
            movable = [role.id for role in state.sorted_roles if state.refusal(role, permissions=False) is None]
            self.assertGreaterEqual(len(movable), 2)
            with self.assertRaises(rm.RoleError) as caught:
                rm.plan_order(state, {"order": list(reversed(movable))})
            self.assertEqual(caught.exception.status, 409)
            self.assertIn("simple sequence", caught.exception.message)

    def test_real_world_gradients_with_many_colours_are_accepted(self):
        stops = ",".join(f"#{n:06x}" for n in (0x50cc7f, 0xf5d100, 0x007adf, 0x00ecbc, 0x20e2d7, 0xf9fea5, 0x00dbde, 0xfc00ff, 0xf9d423, 0xff4e50, 0xcc2200))
        self.assertEqual(rm.validate_role_colour(f"linear-gradient({stops})"), f"linear-gradient({stops.replace(',', ', ')})")


class RoleApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.client = TestClient(TestServer(create_app(str(Path(self.temp.name) / "api.db"))), cookie_jar=CookieJar(unsafe=True))
        await self.client.start_server()
        self.db = self.client.app[DATABASE_KEY]
        self.stoat = FakeStoat()
        self.client.app[rm.CLIENT_KEY] = self.stoat
        self.db.update_dashboard_server_snapshot("server", "Test", 1, [], [], owner_id="admin")
        self.db.update_dashboard_server_snapshot("other", "Other", 1, [], [], owner_id="other-admin")
        await self.login("server", "admin", "AB12CD34")

    async def asyncTearDown(self):
        await self.client.close()
        self.temp.cleanup()

    async def login(self, server_id, user_id, code):
        self.db.create_dashboard_login_code(hashlib.sha256(code.encode()).hexdigest(), server_id, user_id, "2099-01-01T00:00:00+00:00")
        response = await self.client.post("/api/auth/verify", json={"code": code})
        self.assertEqual(response.status, 200)
        self.csrf = {"X-CSRF-Token": self.client.session.cookie_jar.filter_cookies(self.client.make_url("/"))[CSRF_COOKIE].value}

    def make_owner(self):
        self.stoat.servers["server"]["owner"] = "admin"
        self.stoat.members.pop(("server", "admin"), None)

    async def test_roles_require_a_dashboard_session_and_csrf(self):
        anonymous = TestClient(TestServer(self.client.app))
        await anonymous.start_server()
        try:
            self.assertEqual((await anonymous.get("/api/roles")).status, 401)
            anonymous.session.cookie_jar.update_cookies({CSRF_COOKIE: "forged"})
            response = await anonymous.put(f"/api/roles/{MODS}", json={"name": "x"}, headers={"X-CSRF-Token": "forged"})
            self.assertEqual(response.status, 401)
        finally:
            await anonymous.close()
        for response in (await self.client.put(f"/api/roles/{MODS}", json={"name": "Moderators"}),
                         await self.client.post("/api/roles", json={"name": "New"}),
                         await self.client.put("/api/roles/order", json={"order": []}),
                         await self.client.delete(f"/api/roles/{VIP}", json={"confirm_name": "VIP"})):
            self.assertEqual(response.status, 403)
        self.assertEqual(self.stoat.calls, [])

    async def test_the_list_is_ordered_and_marks_what_can_be_edited(self):
        self.make_owner()
        response = await self.client.get("/api/roles")
        self.assertEqual(response.status, 200)
        data = await response.json()
        self.assertEqual([role["name"] for role in data["roles"]], ["Admin", "Stoatmod", "Mods", "Members", "VIP"])
        self.assertEqual({role["name"]: role["editable"] for role in data["roles"]},
                         {"Admin": False, "Stoatmod": False, "Mods": True, "Members": True, "VIP": True})
        self.assertEqual(data["roles"][0]["locked_reason"], "above_bot")
        self.assertEqual(data["roles"][2]["colour"], "#00ff00")
        self.assertTrue(data["roles"][2]["hoist"])
        self.assertEqual(data["roles"][2]["allow"], ["kick_members"])
        self.assertTrue(data["actor"]["is_owner"])
        self.assertEqual(data["catalog"]["permissions"][0]["key"], "manage_channels")
        self.assertEqual(data["default_permissions"], ["view_channel", "send_messages"])
        self.assertNotIn("manage_roles", {key for role in data["roles"] for key in role.get("deny", [])})

    async def test_an_admin_without_manage_roles_sees_everything_read_only(self):
        self.stoat.members[("server", "admin")] = {"roles": [VIP]}
        data = await (await self.client.get("/api/roles")).json()
        self.assertTrue(all(not role["editable"] and not role["permissions_editable"] for role in data["roles"]))
        self.assertEqual(data["roles"][4]["locked_reason"], "you_need_manage_roles")
        response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Everyone"})
        self.assertEqual(response.status, 403)
        self.assertEqual(self.stoat.calls, [])

    async def test_saving_a_role_edits_name_colour_hoist_and_permissions(self):
        self.make_owner()
        gradient = "linear-gradient(90deg, #ff0000 0%, #0000ff 100%)"
        response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={
            "name": "  Regulars ", "colour": gradient, "hoist": True,
            "allow": ["react", "view_channel"], "deny": ["mention_everyone"]})
        self.assertEqual(response.status, 200, await response.text())
        data = await response.json()
        self.assertEqual(data["changed_role_id"], MEMBERS)
        saved = self.stoat.servers["server"]["roles"][MEMBERS]
        self.assertEqual((saved["name"], saved["colour"], saved["hoist"]), ("Regulars", gradient, True))
        self.assertEqual(saved["permissions"], {"a": bit("react") | bit("view_channel"), "d": bit("mention_everyone")})
        self.assertEqual([call[0] for call in self.stoat.calls], ["edit", "permissions"])
        row = next(role for role in data["roles"] if role["id"] == MEMBERS)
        self.assertEqual((row["name"], row["colour"], row["deny"]), ("Regulars", gradient, ["mention_everyone"]))

    async def test_removing_the_colour_sends_stoats_remove_field(self):
        self.make_owner()
        response = await self.client.put(f"/api/roles/{MODS}", headers=self.csrf, json={"colour": None})
        self.assertEqual(response.status, 200)
        self.assertEqual(self.stoat.calls, [("edit", MODS, {"remove": ["Colour"]})])
        self.assertNotIn("colour", self.stoat.servers["server"]["roles"][MODS])

    async def test_invalid_input_never_reaches_stoat(self):
        self.make_owner()
        for payload in ({"colour": "url(javascript:alert(1))"}, {"colour": "linear-gradient(red)"}, {"name": ""}, {"name": "x" * 33},
                        {"allow": ["superuser"], "deny": []}, {"allow": ["react"], "deny": ["react"]}, {"rank": 0}, {"hoist": 1}, {}):
            with self.subTest(payload):
                response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json=payload)
                self.assertEqual(response.status, 400)
        response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, data="not json")
        self.assertEqual(response.status, 400)
        self.assertEqual(self.stoat.calls, [])

    async def test_roles_above_the_bot_are_refused_with_the_hierarchy_message(self):
        self.make_owner()
        for role_id in (ADMIN, BOT_ROLE):
            response = await self.client.put(f"/api/roles/{role_id}", headers=self.csrf, json={"name": "Taken over"})
            self.assertEqual(response.status, 403)
            self.assertIn("not above this role", (await response.json())["error"])
        response = await self.client.delete(f"/api/roles/{ADMIN}", headers=self.csrf, json={"confirm_name": "Admin"})
        self.assertEqual(response.status, 403)
        self.assertEqual(self.stoat.calls, [])

    async def test_role_ids_are_checked_against_this_server_only(self):
        self.make_owner()
        self.stoat.servers["other"] = server_json("other-admin")
        foreign = ulid(77)
        self.stoat.servers["other"]["roles"][foreign] = raw_role("Other server role", 9)
        for role_id in (foreign, "not-a-role", ulid(1234), "01arz3ndektsv4rrffq69g5fav"):
            response = await self.client.put(f"/api/roles/{role_id}", headers=self.csrf, json={"name": "Hijacked"})
            self.assertEqual(response.status, 404, role_id)
            response = await self.client.delete(f"/api/roles/{role_id}", headers=self.csrf, json={"confirm_name": "x"})
            self.assertEqual(response.status, 404, role_id)
        self.assertEqual(self.stoat.calls, [])
        self.assertEqual(self.stoat.servers["other"]["roles"][foreign]["name"], "Other server role")

    async def test_a_session_for_another_server_only_ever_reads_its_own_server(self):
        self.stoat.servers["other"] = server_json("other-admin")
        self.stoat.servers["other"]["roles"][MODS]["name"] = "Other server mods"
        self.stoat.members[("other", BOT)] = {"roles": [BOT_ROLE]}
        await self.login("other", "other-admin", "ZX98CV76")
        data = await (await self.client.get("/api/roles")).json()
        self.assertEqual(data["server"]["id"], "other")
        self.assertIn("Other server mods", [role["name"] for role in data["roles"]])
        self.assertNotIn("Mods", [role["name"] for role in data["roles"]])

    async def test_stoat_refusals_are_translated_and_partial_saves_are_reported(self):
        self.make_owner()
        self.stoat.fail_permissions = rm.StoatError(403, "CannotGiveMissingPermissions")
        response = await self.client.put(f"/api/roles/{MODS}", headers=self.csrf, json={"name": "Moderators", "allow": ["react"], "deny": []})
        self.assertEqual(response.status, 403)
        message = (await response.json())["error"]
        self.assertIn("Some changes were saved", message)
        self.assertIn("grant permissions", message)
        self.assertEqual(self.stoat.servers["server"]["roles"][MODS]["name"], "Moderators")
        events = [event for event in self.db.list_dashboard_events("server", limit=20) if event["event_type"] == "role_updated"]
        self.assertEqual(len(events), 1)
        self.assertEqual([change["field"] for change in events[0]["details"]["changes"]], ["name"])

    async def test_stoat_errors_are_never_leaked_verbatim(self):
        self.make_owner()
        for error, status in ((rm.StoatError(403, "NotElevated"), 403), (rm.StoatError(404, "NotFound"), 404),
                               (rm.StoatError(502, "Unreachable"), 502), (rm.StoatError(429, ""), 429),
                               (rm.StoatError(500, "DatabaseError"), 502)):
            self.stoat.fail = error
            response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Retry"})
            self.assertEqual(response.status, status)
            self.assertNotIn("DatabaseError", await response.text())

    async def test_changes_are_audited_without_message_content(self):
        self.make_owner()
        await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Regulars", "colour": "#123456", "allow": ["react", "view_channel"], "deny": []})
        events = [event for event in self.db.list_dashboard_events("server", limit=20) if event["event_type"] == "role_updated"]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["actor_id"], "admin")
        self.assertEqual(event["details"]["role_id"], MEMBERS)
        fields = {change["field"] for change in event["details"]["changes"]}
        self.assertEqual(fields, {"name", "colour", "permissions"})
        permissions = next(change for change in event["details"]["changes"] if change["field"] == "permissions")
        self.assertEqual(permissions["allowed"], ["view_channel"])
        self.assertIn("Updated role Members", event["details"]["message"])
        self.assertIsNone(event["message_id"])

    async def test_reordering_applies_the_full_order_and_is_logged(self):
        self.make_owner()
        response = await self.client.put("/api/roles/order", headers=self.csrf, json={"order": [VIP, MEMBERS, MODS]})
        self.assertEqual(response.status, 200)
        self.assertEqual(self.stoat.calls, [("ranks", [ADMIN, BOT_ROLE, VIP, MEMBERS, MODS])])
        data = await response.json()
        self.assertEqual([role["name"] for role in data["roles"]], ["Admin", "Stoatmod", "VIP", "Members", "Mods"])
        self.assertTrue(any(event["event_type"] == "roles_reordered" for event in self.db.list_dashboard_events("server", limit=20)))
        stale = await self.client.put("/api/roles/order", headers=self.csrf, json={"order": [VIP, MEMBERS]})
        self.assertEqual(stale.status, 409)
        locked = await self.client.put("/api/roles/order", headers=self.csrf, json={"order": [ADMIN, VIP, MEMBERS, MODS]})
        self.assertEqual(locked.status, 409)

    async def test_creating_a_role(self):
        self.make_owner()
        response = await self.client.post("/api/roles", headers=self.csrf, json={"name": " Night owls "})
        self.assertEqual(response.status, 201)
        data = await response.json()
        created = next(role for role in data["roles"] if role["id"] == data["changed_role_id"])
        self.assertEqual((created["name"], created["editable"]), ("Night owls", True))
        self.assertEqual(self.stoat.calls, [("create", "Night owls")])
        self.assertTrue(any(event["event_type"] == "role_created" for event in self.db.list_dashboard_events("server", limit=20)))
        for payload in ({}, {"name": ""}, {"name": "x" * 33}, {"name": "ok", "rank": 0}):
            self.assertEqual((await self.client.post("/api/roles", headers=self.csrf, json=payload)).status, 400)

    async def test_creating_needs_authority_and_respects_the_role_limit(self):
        self.stoat.members[("server", "admin")] = {"roles": [VIP]}
        self.assertEqual((await self.client.post("/api/roles", headers=self.csrf, json={"name": "New"})).status, 403)
        self.make_owner()
        for number in range(rm.MAX_ROLES):
            self.stoat.servers["server"]["roles"][ulid(1000 + number)] = raw_role(f"Filler {number}", 10 + number)
        self.assertEqual((await self.client.post("/api/roles", headers=self.csrf, json={"name": "One too many"})).status, 409)
        self.assertEqual(self.stoat.calls, [])

    async def test_deleting_needs_the_exact_name_and_an_unused_role(self):
        self.make_owner()
        for payload in ({}, {"confirm_name": "vip"}, {"confirm_name": ""}):
            response = await self.client.delete(f"/api/roles/{VIP}", headers=self.csrf, json=payload)
            self.assertEqual(response.status, 400)
        self.assertEqual(self.stoat.calls, [])
        self.db.add_auto_role("server", VIP, "admin")
        response = await self.client.delete(f"/api/roles/{VIP}", headers=self.csrf, json={"confirm_name": "VIP"})
        self.assertEqual(response.status, 409)
        self.assertIn("Auto-roles", (await response.json())["error"])
        self.db.remove_auto_role("server", VIP)
        response = await self.client.delete(f"/api/roles/{VIP}", headers=self.csrf, json={"confirm_name": "VIP"})
        self.assertEqual(response.status, 200)
        self.assertNotIn(VIP, self.stoat.servers["server"]["roles"])
        self.assertEqual(self.stoat.calls, [("delete", VIP)])
        self.assertTrue(any(event["event_type"] == "role_deleted" for event in self.db.list_dashboard_events("server", limit=20)))

    async def test_requests_are_rate_limited(self):
        for _ in range(rm.READ_LIMIT[0]):
            self.assertEqual((await self.client.get("/api/roles")).status, 200)
        limited = await self.client.get("/api/roles")
        self.assertEqual(limited.status, 429)
        self.make_owner()
        for _ in range(rm.WRITE_LIMIT[0]):
            await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={})
        self.assertEqual((await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={})).status, 429)

    async def test_the_feature_reports_when_stoat_is_unreachable_or_unconfigured(self):
        self.client.app[rm.CLIENT_KEY] = rm.StoatRoleClient("http://127.0.0.1:9", lambda: "")
        response = await self.client.get("/api/roles")
        self.assertEqual(response.status, 503)
        self.client.app[rm.CLIENT_KEY] = rm.StoatRoleClient("http://127.0.0.1:9", lambda: "token")
        response = await self.client.get("/api/roles")
        self.assertEqual(response.status, 502)

    async def test_the_bot_missing_from_the_server_is_reported(self):
        del self.stoat.servers["server"]
        response = await self.client.get("/api/roles")
        self.assertEqual(response.status, 404)

    # ------------------------------------------------------------------ moderation log channel

    def use_log_channel(self):
        self.db.set_log_channel("server", "LOGCHANNEL")

    async def test_an_edit_is_posted_to_the_log_channel_with_what_changed(self):
        self.make_owner()
        self.use_log_channel()
        self.db.add_event(server_id="server", event_type="seed", user_id="admin", details={"username": "Alex", "discriminator": "1234"})
        response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={
            "name": "Regulars", "colour": "#123456", "hoist": True, "allow": ["react", "view_channel"], "deny": ["mention_everyone"]})
        self.assertEqual(response.status, 200)
        data = await response.json()
        self.assertEqual(data["log_status"], "posted")
        self.assertEqual(data["log_channel"], {"configured": True})
        self.assertEqual(len(self.stoat.posts), 1)
        channel, title, description, colour = self.stoat.posts[0]
        self.assertEqual((channel, title, colour), ("LOGCHANNEL", "🔧 Role updated from dashboard", "#123456"))
        for line in ("**Role:** `Regulars`", "**Changed by:** `Alex#1234`", "**Name:** `Members` → `Regulars`",
                     "**Colour:** *none* → `#123456`", "**Shown separately:** No → Yes", "**Now allowed:** View Channel",
                     "**Now denied:** Mention Everyone"):
            self.assertIn(line, description)
        self.assertIn(MEMBERS, description)

    async def test_the_embed_takes_its_accent_from_the_new_colour(self):
        self.make_owner()
        self.use_log_channel()
        await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"colour": "linear-gradient(90deg, #ff0000 0%, #0000ff 100%)"})
        self.assertEqual(self.stoat.posts[0][3], "#ff0000")
        await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"colour": None})
        self.assertEqual(self.stoat.posts[1][3], "#5865F2")
        self.assertIn("→ *none*", self.stoat.posts[1][2])

    async def test_no_log_channel_means_no_post_and_a_clear_status(self):
        self.make_owner()
        data = await (await self.client.get("/api/roles")).json()
        self.assertEqual(data["log_channel"], {"configured": False})
        response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Regulars"})
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["log_status"], "no_channel")
        self.assertEqual(self.stoat.posts, [])

    async def test_a_failed_log_post_never_undoes_or_hides_the_change(self):
        self.make_owner()
        self.use_log_channel()
        self.stoat.fail_post = rm.StoatError(403, "MissingPermission")
        response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Regulars"})
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["log_status"], "failed")
        self.assertEqual(self.stoat.servers["server"]["roles"][MEMBERS]["name"], "Regulars")
        self.assertTrue(any(event["event_type"] == "role_updated" for event in self.db.list_dashboard_events("server", limit=20)))

    async def test_a_slow_log_channel_does_not_hold_the_admin_up(self):
        self.make_owner()
        self.use_log_channel()
        self.stoat.post_delay = 1
        original = rm.LOG_TIMEOUT
        rm.LOG_TIMEOUT = 0.05
        try:
            response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Regulars"})
        finally:
            rm.LOG_TIMEOUT = original
        self.assertEqual((response.status, (await response.json())["log_status"]), (200, "failed"))

    async def test_names_cannot_forge_log_lines_or_markdown(self):
        self.make_owner()
        self.use_log_channel()
        name = "a`b **x** @everyone [c](h://e)"
        self.assertLessEqual(len(name), 32)
        await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": name})
        description = self.stoat.posts[0][2]
        line = next(item for item in description.split("\n") if item.startswith("**Name:**"))
        self.assertEqual(line, "**Name:** `Members` → `a'b **x** @everyone [c](h://e)`")
        self.assertEqual(len(description.split("\n")), 3)  # role, changed by, name: nothing was forged

    async def test_a_partly_saved_change_is_logged_with_what_was_not_applied(self):
        self.make_owner()
        self.use_log_channel()
        self.stoat.fail_permissions = rm.StoatError(403, "CannotGiveMissingPermissions")
        response = await self.client.put(f"/api/roles/{MODS}", headers=self.csrf, json={"name": "Moderators", "allow": ["react"], "deny": []})
        self.assertEqual(response.status, 403)
        _channel, title, description, colour = self.stoat.posts[0]
        self.assertEqual((title, colour), ("⚠️ Role partly updated from dashboard", "#F59E0B"))
        self.assertIn("**Name:** `Mods` → `Moderators`", description)
        self.assertIn("**Not applied:** Stoat does not let Stoatmod grant permissions", description)

    async def test_reordering_creating_and_deleting_are_posted(self):
        self.make_owner()
        self.use_log_channel()
        await self.client.put("/api/roles/order", headers=self.csrf, json={"order": [VIP, MEMBERS, MODS]})
        created = await (await self.client.post("/api/roles", headers=self.csrf, json={"name": "Night owls"})).json()
        await self.client.delete(f"/api/roles/{MODS}", headers=self.csrf, json={"confirm_name": "Mods"})
        titles = [post[1] for post in self.stoat.posts]
        self.assertEqual(titles, ["🔧 Role order changed from dashboard", "✨ Role created from dashboard", "🧹 Role deleted from dashboard"])
        order = self.stoat.posts[0][2]
        self.assertLess(order.index("1. `VIP`"), order.index("2. `Members`"))
        self.assertIn("Roles above Stoatmod keep their place.", order)
        self.assertIn(created["changed_role_id"], self.stoat.posts[1][2])
        deleted = self.stoat.posts[2][2]
        self.assertIn("**Colour it had:** `#00ff00`", deleted)
        self.assertIn("**Permissions it allowed:** Kick Members", deleted)
        self.assertEqual([post[3] for post in self.stoat.posts], ["#5865F2", "#3BA55D", "#ED4245"])

    async def test_refused_attempts_are_logged_once_in_a_while(self):
        self.use_log_channel()
        self.stoat.members[("server", "admin")] = {"roles": [VIP]}
        for _ in range(3):
            response = await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json={"name": "Everyone"})
            self.assertEqual(response.status, 403)
        self.assertEqual(len(self.stoat.posts), 1)
        _channel, title, description, _colour = self.stoat.posts[0]
        self.assertEqual(title, "🚫 Role change blocked")
        for line in ("**Role:** `Members`", "**Attempt:** Edit role", "**Attempted by:** `admin`", "**Why it was refused:** You need the Manage Roles permission"):
            self.assertIn(line, description)
        blocked = [event for event in self.db.list_dashboard_events("server", limit=20) if event["event_type"] == "role_change_blocked"]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["details"]["role_id"], MEMBERS)
        other = await self.client.delete(f"/api/roles/{VIP}", headers=self.csrf, json={"confirm_name": "VIP"})
        self.assertEqual(other.status, 403)
        self.assertEqual(len(self.stoat.posts), 2)
        self.assertIn("**Attempt:** Delete role", self.stoat.posts[1][2])

    async def test_invalid_requests_are_not_logged_as_blocked(self):
        self.make_owner()
        self.use_log_channel()
        for payload in ({"name": ""}, {"colour": "url(x)"}, {}):
            self.assertEqual((await self.client.put(f"/api/roles/{MEMBERS}", headers=self.csrf, json=payload)).status, 400)
        self.assertEqual(self.stoat.posts, [])
        self.assertFalse(any(event["event_type"] == "role_change_blocked" for event in self.db.list_dashboard_events("server", limit=20)))

    async def test_roles_above_the_bot_are_logged_as_blocked_for_the_owner_too(self):
        self.make_owner()
        self.use_log_channel()
        response = await self.client.put(f"/api/roles/{ADMIN}", headers=self.csrf, json={"name": "Taken over"})
        self.assertEqual(response.status, 403)
        self.assertIn("Stoatmod's role is not above this role", self.stoat.posts[0][2])


class LogFormattingTests(unittest.TestCase):
    def test_accent_colours_are_always_safe(self):
        self.assertEqual(rm.accent_colour("#7C3AED"), "#7c3aed")
        self.assertEqual(rm.accent_colour("red"), "red")
        self.assertEqual(rm.accent_colour("rgb(1, 2, 3)"), "rgb(1, 2, 3)")
        self.assertEqual(rm.accent_colour("linear-gradient(90deg, #112233, #445566)"), "#112233")
        self.assertEqual(rm.accent_colour("linear-gradient(rgb(1, 2, 3) 10%, red)"), "rgb(1, 2, 3)")
        for value in (None, "", "var(--accent)", "url(x)", "nonsense", "linear-gradient(var(--a), var(--b))"):
            self.assertEqual(rm.accent_colour(value), "#5865F2")

    def test_inline_code_cannot_be_broken_out_of(self):
        self.assertEqual(rm._code("a`b\nc"), "`a'b c`")
        self.assertEqual(rm._code(""), "`-`")
        self.assertEqual(rm._code("x" * 100, 10), "`xxxxxxxxxx…`")

    def test_a_long_order_is_shortened(self):
        title, description, colour = rm.order_log("`admin`", [f"Role number {number} " + "x" * 15 for number in range(200)])
        self.assertLessEqual(len(description), rm.LOG_LIMIT + 1)
        self.assertIn("25. `Role number 24", description)
        self.assertNotIn("26. ", description)
        self.assertIn("…and 175 more", description)

    def test_an_update_log_lists_every_kind_of_change(self):
        role = rm.Role(ulid(9), "Old", "red", False, 3, 0, 0)
        changes = [
            {"field": "name", "from": "Old", "to": "New"}, {"field": "colour", "from": "red", "to": None},
            {"field": "hoist", "from": False, "to": True},
            {"field": "permissions", "allowed": ["react"], "no_longer_allowed": ["speak"], "denied": ["connect"], "no_longer_denied": ["listen"]},
        ]
        _title, description, colour = rm.update_log("`admin`", role, changes)
        for line in ("**Colour:** `red` → *none*", "**Now allowed:** React", "**No longer allowed:** Speak",
                     "**Now denied:** Connect", "**No longer denied:** Listen"):
            self.assertIn(line, description)
        self.assertEqual(colour, "#5865F2")


if __name__ == "__main__":
    unittest.main()
