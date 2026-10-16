"""~kick and ~ban accept several members listed before one shared reason."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from bot import MAX_BULK_TARGETS, ModerationBot

A, B, C = "01KHBPN31QT1THM1A0CEM8JA91", "01KHBPN31QT1THM1A0CEM8JA92", "01KHBPN31QT1THM1A0CEM8JA93"
BOT_ID = "01KY6VVK6E7N1KFJVKK9YJ1KE1"


def fixture(failing: set[str] = frozenset()):
    bot = object.__new__(ModerationBot)
    bot._state = SimpleNamespace(my_id=BOT_ID)
    bot._pending_ban_attribution = {}
    bot._pending_kick_attribution = {}
    bot.require_action_permissions = AsyncMock(return_value=True)
    bot._resolve_user_tag = AsyncMock(side_effect=lambda user_id, _user=None: f"user-{user_id[-2:]}")
    bot.send_command_response = AsyncMock()

    async def kick(member, server_id, user_id, reason, *, actor_id=None):
        if user_id in failing:
            raise RuntimeError("hierarchy")
    bot._kick_member_with_reason = AsyncMock(side_effect=kick)

    async def ban(user_id, *, reason):
        if user_id in failing:
            raise RuntimeError("hierarchy")
    server = SimpleNamespace(get_member=Mock(side_effect=lambda user_id: SimpleNamespace(id=user_id)), fetch_member=AsyncMock(), ban=AsyncMock(side_effect=ban))
    message = SimpleNamespace(author_id="moderator", channel_id="commands")
    return bot, server, message


def run(bot, server, message, content):
    parts = content.split(maxsplit=2)
    asyncio.run(bot.handle_kick_ban_command(message, server, "server", parts[0], parts))


class SplitTargetsTests(unittest.TestCase):
    def test_mentions_and_ids_before_the_reason(self):
        targets, reason = ModerationBot._split_bulk_targets(f"<@{A}> <@{B}>, {C} unverified for 5+ days")
        self.assertEqual(targets, [A, B, C])
        self.assertEqual(reason, "unverified for 5+ days")

    def test_mentions_inside_the_reason_are_not_targets(self):
        targets, reason = ModerationBot._split_bulk_targets(f"<@{A}> raided with <@{B}>")
        self.assertEqual(targets, [A])
        self.assertEqual(reason, f"raided with <@{B}>")

    def test_duplicates_are_removed(self):
        targets, _ = ModerationBot._split_bulk_targets(f"<@{A}> {A} <@{B}> spam")
        self.assertEqual(targets, [A, B])


class BulkKickBanTests(unittest.TestCase):
    def test_kicks_every_listed_member_with_the_shared_reason(self):
        bot, server, message = fixture()
        run(bot, server, message, f"~kick <@{A}> <@{B}> <@{C}> unverified for 5+ days")
        kicked = [call.args[2] for call in bot._kick_member_with_reason.await_args_list]
        self.assertEqual(kicked, [A, B, C])
        self.assertTrue(all(call.args[3] == "unverified for 5+ days" for call in bot._kick_member_with_reason.await_args_list))
        title, body = bot.send_command_response.await_args.args[1:3]
        self.assertEqual(title, "3 members kicked")
        self.assertIn("**Reason:** unverified for 5+ days", body)
        self.assertNotIn(f"<@{B}>", body.split("**Reason:**")[1])

    def test_bans_every_listed_member_and_records_attribution(self):
        bot, server, message = fixture()
        run(bot, server, message, f"~ban <@{A}> {B} alt accounts")
        self.assertEqual([call.args[0] for call in server.ban.await_args_list], [A, B])
        self.assertEqual(bot._pending_ban_attribution[("server", A)], ("moderator", "alt accounts"))
        self.assertEqual(bot.send_command_response.await_args.args[1], "2 members banned")

    def test_partial_failure_is_reported_per_member(self):
        bot, server, message = fixture(failing={B})
        run(bot, server, message, f"~kick <@{A}> <@{B}> spam")
        title, body = bot.send_command_response.await_args.args[1:3]
        self.assertEqual(title, "1 of 2 members kicked")
        self.assertIn("Not kicked (1)", body)
        self.assertNotIn(("server", B), bot._pending_kick_attribution)

    def test_moderator_and_bot_are_never_actioned(self):
        bot, server, message = fixture()
        message.author_id = A
        run(bot, server, message, f"~ban <@{A}> <@{BOT_ID}> <@{C}> spam")
        self.assertEqual([call.args[0] for call in server.ban.await_args_list], [C])
        self.assertIn("you can't ban yourself", bot.send_command_response.await_args.args[2])

    def test_reason_is_still_required(self):
        bot, server, message = fixture()
        run(bot, server, message, f"~kick <@{A}> <@{B}>")
        bot._kick_member_with_reason.assert_not_awaited()
        self.assertEqual(bot.send_command_response.await_args.args[1], "Reason required")

    def test_limit_on_members_per_command(self):
        bot, server, message = fixture()
        ids = ["01KHBPN31QT1THM1A0CEM8J%03d" % i for i in range(MAX_BULK_TARGETS + 1)]
        run(bot, server, message, "~kick " + " ".join(f"<@{i}>" for i in ids) + " raid")
        bot._kick_member_with_reason.assert_not_awaited()
        self.assertEqual(bot.send_command_response.await_args.args[1], "Too many members")

    def test_needs_the_permission_first(self):
        bot, server, message = fixture()
        bot.require_action_permissions = AsyncMock(return_value=False)
        run(bot, server, message, f"~kick <@{A}> <@{B}> spam")
        bot._kick_member_with_reason.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
