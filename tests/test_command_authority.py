"""Commands and dashboard actions are held to Stoat's own permission and role rules."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import stoat

from bot import ModerationBot

OWNER, MOD = "owner", "moderator"
ADMIN, MEMBER = "01KHBPN31QT1THM1A0CEM8JA91", "01KHBPN31QT1THM1A0CEM8JA92"


def member(user_id: str, rank: int | None, **permissions: bool) -> SimpleNamespace:
    return SimpleNamespace(
        id=user_id,
        top_role=None if rank is None else SimpleNamespace(rank=rank),
        permissions=SimpleNamespace(**permissions),
    )


def make_server(*members: SimpleNamespace) -> SimpleNamespace:
    by_id = {item.id: item for item in members}

    async def fetch(user_id):
        if user_id not in by_id:
            raise stoat.errors.NotFound.__new__(stoat.errors.NotFound)
        return by_id[user_id]

    return SimpleNamespace(
        id="server",
        owner_id=OWNER,
        get_member=Mock(side_effect=by_id.get),
        fetch_member=AsyncMock(side_effect=fetch),
        permissions_for=Mock(side_effect=lambda item: item.permissions),
        ban=AsyncMock(),
    )


def make_message(author: SimpleNamespace, content: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        author_id=author.id,
        content=content,
        channel_id="channel",
        get_author_as_member=Mock(return_value=author),
    )


def make_bot() -> ModerationBot:
    bot = object.__new__(ModerationBot)
    bot._state = SimpleNamespace(my_id="bot")
    bot._pending_ban_attribution = {}
    bot._pending_kick_attribution = {}
    bot.require_action_permissions = AsyncMock(return_value=True)
    bot.send_command_response = AsyncMock()
    bot._resolve_user_tag = AsyncMock(return_value="user#0001")
    bot._kick_member_with_reason = AsyncMock()
    return bot


def run(coro):
    return asyncio.run(coro)


class InvokerPermissionTests(unittest.TestCase):
    def test_manage_messages_alone_cannot_ban(self):
        bot = make_bot()
        author = member(MOD, 2, manage_messages=True, ban_members=False)
        refusal = run(bot._command_permission_refusal(
            make_message(author), make_server(author), "~ban", ["~ban", MEMBER, "spam"]
        ))
        self.assertIn("Ban Members", refusal)

    def test_ban_members_permission_allows_ban(self):
        bot = make_bot()
        author = member(MOD, 2, ban_members=True)
        self.assertIsNone(run(bot._command_permission_refusal(
            make_message(author), make_server(author), "~ban", ["~ban", MEMBER, "spam"]
        )))

    def test_settings_changes_need_manage_server(self):
        bot = make_bot()
        author = member(MOD, 2, kick_members=True, manage_server=False)
        refusal = run(bot._command_permission_refusal(
            make_message(author), make_server(author),
            "~moderator-exemption", ["~moderator-exemption", "disable"],
        ))
        self.assertIn("Manage Server", refusal)

    def test_settings_status_is_open_to_moderators(self):
        bot = make_bot()
        author = member(MOD, 2, kick_members=True, manage_server=False)
        for parts in (["~threshold"], ["~threshold", "status"], ["~auto-role", "list"]):
            self.assertIsNone(run(bot._command_permission_refusal(
                make_message(author), make_server(author), parts[0], parts
            )))

    def test_server_owner_needs_no_specific_permission(self):
        bot = make_bot()
        author = member(OWNER, None)
        self.assertIsNone(run(bot._command_permission_refusal(
            make_message(author), make_server(author), "~ban", ["~ban", MEMBER, "x"]
        )))

    def test_unverifiable_permissions_fail_closed(self):
        bot = make_bot()
        message = SimpleNamespace(author_id=MOD, get_author_as_member=Mock(return_value=None))
        server = make_server()
        server.fetch_member = AsyncMock(side_effect=RuntimeError("network"))
        self.assertIsNotNone(run(bot._command_permission_refusal(
            message, server, "~kick", ["~kick", MEMBER, "x"]
        )))

    def test_handle_command_blocks_ban_for_message_only_moderator(self):
        bot = make_bot()
        author = member(MOD, 2, manage_messages=True, ban_members=False)
        target = member(MEMBER, None)
        server = make_server(author, target)
        message = make_message(author, f"~ban {MEMBER} spam")
        message.get_server = Mock(return_value=(server, "server"))
        bot._is_moderator = Mock(return_value=True)
        handled = run(bot.handle_command(message))
        self.assertTrue(handled)
        server.ban.assert_not_awaited()
        self.assertEqual(bot.send_command_response.await_args.args[1], "Permission denied")


class HierarchyTests(unittest.TestCase):
    def setUp(self):
        self.bot = make_bot()
        self.mod = member(MOD, 5, ban_members=True, kick_members=True)
        self.admin = member(ADMIN, 1)
        self.peer = member("peer", 5)
        self.plain = member(MEMBER, None)
        self.owner = member(OWNER, None)
        self.server = make_server(self.mod, self.admin, self.peer, self.plain, self.owner)

    def refusal(self, actor, target_id):
        return run(self.bot._target_hierarchy_refusal(self.server, actor.id, target_id))

    def test_lower_moderator_cannot_target_higher_role(self):
        self.assertIsNotNone(self.refusal(self.mod, ADMIN))

    def test_equal_rank_is_refused(self):
        self.assertIsNotNone(self.refusal(self.mod, "peer"))

    def test_moderator_can_target_member_below(self):
        self.assertIsNone(self.refusal(self.mod, MEMBER))

    def test_nobody_can_target_server_owner(self):
        self.assertIsNotNone(self.refusal(self.admin, OWNER))

    def test_owner_can_target_anyone_else(self):
        self.assertIsNone(self.refusal(self.owner, ADMIN))

    def test_non_member_can_be_banned_by_id(self):
        self.assertIsNone(self.refusal(self.mod, "someone-outside"))

    def test_ban_command_refuses_higher_target(self):
        message = make_message(self.mod)
        run(self.bot.handle_kick_ban_command(
            message, self.server, "server", "~ban", ["~ban", ADMIN, "abuse"]
        ))
        self.server.ban.assert_not_awaited()
        self.assertEqual(self.bot.send_command_response.await_args.args[1], "Ban refused")

    def test_bulk_ban_skips_only_higher_targets(self):
        message = make_message(self.mod)
        run(self.bot.handle_kick_ban_command(
            message, self.server, "server", "~ban",
            ["~ban", f"<@{ADMIN}> <@{MEMBER}>", "raid"],
        ))
        self.assertEqual([call.args[0] for call in self.server.ban.await_args_list], [MEMBER])


class DashboardAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.bot = make_bot()
        self.delegate = member("delegate", 5, ban_members=False, kick_members=True)
        self.banner = member("banner", 5, ban_members=True)
        self.admin = member(ADMIN, 1)
        self.plain = member(MEMBER, None)
        self.owner = member(OWNER, None)
        self.server = make_server(self.delegate, self.banner, self.admin, self.plain, self.owner)

    def check(self, actor_id, target_id, action):
        return run(self.bot._require_dashboard_actor_authority(
            self.server, actor_id, target_id, action
        ))

    def test_delegate_without_ban_permission_cannot_ban(self):
        with self.assertRaisesRegex(PermissionError, "Ban Members"):
            self.check("delegate", MEMBER, "ban")

    def test_delegate_cannot_kick_higher_role(self):
        with self.assertRaisesRegex(PermissionError, "highest role"):
            self.check("delegate", ADMIN, "kick")

    def test_permitted_delegate_can_ban_member_below(self):
        self.assertIsNone(self.check("banner", MEMBER, "ban"))

    def test_owner_can_ban_admin(self):
        self.assertIsNone(self.check(OWNER, ADMIN, "ban"))

    def test_non_member_dashboard_user_is_refused(self):
        with self.assertRaisesRegex(PermissionError, "member of this server"):
            self.check("gone", MEMBER, "warn")


if __name__ == "__main__":
    unittest.main()
