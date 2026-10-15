import asyncio
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from bot import ModerationBot
from database import WarningPolicy

EVERYONE = 1 << 1
ONLINE = 1 << 2
SETTINGS = {"repeat_window_seconds": 30.0}


def make_bot() -> ModerationBot:
    bot = object.__new__(ModerationBot)
    bot._state = SimpleNamespace(my_id="bot")
    bot.moderation_settings = SimpleNamespace(
        mass_mention_limit=5, spam_timeout_seconds=3600, spam_repeat_count=3,
        spam_repeat_window_seconds=30, spam_rapid_count=5, spam_rapid_window_seconds=10,
        spam_score_threshold=7, spam_score_half_life_seconds=30,
    )
    bot._spam_history = {}
    bot._spam_scores = {}
    bot._spam_timeout_until = {}
    bot._bot_deleted_ids = set()
    bot.database = SimpleNamespace(
        add_warning=Mock(return_value=43), count_warnings=Mock(return_value=1), add_event=Mock(),
        get_warning_policy=Mock(return_value=WarningPolicy()),
    )
    bot._resolve_user_tag = AsyncMock(return_value="member#1234")
    bot.send_log = AsyncMock()
    bot.enforce_warning_policy = AsyncMock()
    return bot


def make_message(content, flags=EVERYONE, *, author="user", message_id="message", server_id="server"):
    member = SimpleNamespace(timeout=AsyncMock())
    server = SimpleNamespace(get_member=Mock(return_value=member), permissions_for=Mock(return_value=SimpleNamespace()))
    return SimpleNamespace(
        author_id=author, id=message_id, channel_id="channel", content=content,
        mention_ids=[], role_mention_ids=[], raw_flags=flags, delete=AsyncMock(),
        get_server=Mock(return_value=(server, server_id)),
        get_author_as_member=Mock(return_value=member), get_author_as_user=Mock(return_value=None),
    ), member


class EveryoneMentionTests(unittest.TestCase):
    def test_counts_only_real_mentions_and_only_when_the_author_is_allowed(self) -> None:
        uses = ModerationBot._everyone_mention_uses
        self.assertEqual(uses(SimpleNamespace(raw_flags=EVERYONE, content="@everyone hello")), 1)
        self.assertEqual(uses(SimpleNamespace(raw_flags=EVERYONE | ONLINE, content="@everyone @online @Everyone")), 3)
        self.assertEqual(uses(SimpleNamespace(raw_flags=ONLINE, content="free nitro @online")), 1)
        self.assertEqual(uses(SimpleNamespace(raw_flags=0, content="@everyone @everyone")), 0)  # no permission, no ping
        self.assertEqual(uses(SimpleNamespace(raw_flags=EVERYONE, content="mail me at bob@everyone.com")), 1)  # flag set, text is not a mention
        self.assertEqual(uses(SimpleNamespace(raw_flags=EVERYONE, content="@everyones @onlinefriends")), 1)
        self.assertEqual(uses(SimpleNamespace(raw_flags=EVERYONE, content=None)), 1)

    def test_one_allowed_everyone_mention_is_not_spam(self) -> None:
        bot = make_bot()
        message, member = make_message("@everyone game night at 8, join voice!")

        self.assertIsNone(bot._mass_mention_reason(message))
        self.assertFalse(asyncio.run(bot.handle_spam(message)))
        member.timeout.assert_not_awaited()
        message.delete.assert_not_awaited()
        bot.database.add_warning.assert_not_called()

    def test_one_online_mention_is_not_spam(self) -> None:
        bot = make_bot()
        message, member = make_message("@online anyone want to play?", ONLINE)
        self.assertFalse(asyncio.run(bot.handle_spam(message)))
        member.timeout.assert_not_awaited()

    def test_using_it_twice_in_one_message_is_spam(self) -> None:
        bot = make_bot()
        message, member = make_message("@everyone @everyone look at this")

        self.assertIn("more than once in one message", bot._mass_mention_reason(message) or "")
        self.assertTrue(asyncio.run(bot.handle_spam(message)))
        message.delete.assert_awaited_once()
        member.timeout.assert_awaited_once_with(timedelta(hours=1))
        self.assertIn("more than once in one message", bot.database.add_warning.call_args.kwargs["reason"])

    def test_everyone_plus_online_in_one_message_is_spam(self) -> None:
        bot = make_bot()
        message, _member = make_message("@everyone @online", EVERYONE | ONLINE)
        self.assertTrue(asyncio.run(bot.handle_spam(message)))

    def test_text_without_permission_is_not_spam(self) -> None:
        bot = make_bot()
        message, member = make_message("@everyone @everyone @everyone", 0)
        self.assertIsNone(bot._mass_mention_reason(message))
        self.assertFalse(asyncio.run(bot.handle_spam(message)))
        member.timeout.assert_not_awaited()

    def test_second_message_within_the_window_is_spam(self) -> None:
        bot = make_bot()
        first, first_member = make_message("@everyone first", message_id="m1")
        second, second_member = make_message("@everyone second", message_id="m2")

        async def scenario():
            return await bot.handle_spam(first), await bot.handle_spam(second)

        first_handled, second_handled = asyncio.run(scenario())

        self.assertFalse(first_handled)
        first_member.timeout.assert_not_awaited()
        self.assertTrue(second_handled)
        second.delete.assert_awaited_once()
        second_member.timeout.assert_awaited_once()
        self.assertIn("more than once within 30 seconds", bot.database.add_warning.call_args.kwargs["reason"])

    def test_window_expiry_other_members_and_servers_do_not_count(self) -> None:
        bot = make_bot()
        message, _member = make_message("@everyone", message_id="m")
        reason = bot._repeated_everyone_reason
        self.assertIsNone(reason(message, "server", SETTINGS, now=100.0))
        self.assertIsNone(reason(message, "server", SETTINGS, now=131.0))  # first use expired
        self.assertIn("more than once within 30 seconds", reason(message, "server", SETTINGS, now=150.0) or "")
        self.assertIsNone(reason(message, "server", SETTINGS, now=151.0))  # history cleared after a trigger
        other_member, _ = make_message("@everyone", author="someone-else")
        self.assertIsNone(reason(other_member, "server", SETTINGS, now=152.0))
        self.assertIsNone(reason(message, "other-server", SETTINGS, now=152.0))

    def test_the_window_follows_the_servers_repeat_window_setting(self) -> None:
        bot = make_bot()
        message, _member = make_message("@everyone")
        wide = {"repeat_window_seconds": 300.0}
        self.assertIsNone(bot._repeated_everyone_reason(message, "server", wide, now=0.0))
        self.assertIn("within 300 seconds", bot._repeated_everyone_reason(message, "server", wide, now=250.0) or "")

    def test_messages_without_the_flag_never_start_a_window(self) -> None:
        bot = make_bot()
        plain, _ = make_message("hello", 0)
        self.assertIsNone(bot._repeated_everyone_reason(plain, "server", SETTINGS, now=0.0))
        flagged, _ = make_message("@everyone")
        self.assertIsNone(bot._repeated_everyone_reason(flagged, "server", SETTINGS, now=1.0))

    def test_clearing_a_servers_spam_state_forgets_its_everyone_history(self) -> None:
        bot = make_bot()
        message, _member = make_message("@everyone")
        bot._repeated_everyone_reason(message, "server", SETTINGS, now=0.0)
        bot._clear_spam_state("server")
        self.assertIsNone(bot._repeated_everyone_reason(message, "server", SETTINGS, now=1.0))

    def test_user_and_role_mention_limit_still_applies(self) -> None:
        bot = make_bot()
        message, _member = make_message("hello", 0)
        message.mention_ids = ["u1", "u2", "u3", "u4", "u5"]
        self.assertIn("mentioned 5 users or roles", bot._mass_mention_reason(message) or "")


if __name__ == "__main__":
    unittest.main()
