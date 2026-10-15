import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock

from bot import GLOBAL_COMMAND_OWNER_ID, ModerationBot


class CommandRoutingTests(unittest.TestCase):
    def test_ordinary_tilde_text_is_not_handled_or_answered_as_a_command(self):
        examples = (
            "~~wait i googled koikatsu didn't know such things exist~~",
            "~ does this work",
            "~",
            "~~",
            "~~~python\nprint('hello')\n~~~",
            "~~help~~",
            "~help~",
            "~ help",
            "~\thelp",
            "~\nhelp",
            "~\u00a0help",
            "~500 people",
            "~3.5 hours",
            "~https://example.com",
            "~:)",
            "text with ~help in the middle",
            r"\~help",
            "  ~~some crossed-out text~~  ",
            "",
        )
        for content in examples:
            with self.subTest(content=content):
                bot = object.__new__(ModerationBot)
                bot.send_command_response = AsyncMock()
                bot.handle_global_command = AsyncMock()
                message = SimpleNamespace(content=content)

                self.assertFalse(asyncio.run(bot.handle_command(message)))
                bot.send_command_response.assert_not_awaited()
                bot.handle_global_command.assert_not_awaited()

    def test_help_command_remains_case_insensitive_and_whitespace_tolerant(self):
        for content in ("~help", "  ~HELP  ", "~help\t", "~help\n"):
            with self.subTest(content=content):
                bot = object.__new__(ModerationBot)
                bot.send_command_response = AsyncMock()
                self.assertTrue(asyncio.run(bot.handle_command(SimpleNamespace(content=content))))
                bot.send_command_response.assert_awaited_once()
                self.assertNotEqual(bot.send_command_response.await_args.args[1], "Invalid command")

    def test_misspelled_command_still_gets_correct_usage(self):
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(content="~polciy set 3 5 7", author_id="moderator")

        self.assertTrue(asyncio.run(bot.handle_command(message)))
        bot.send_command_response.assert_awaited_once()
        self.assertEqual(bot.send_command_response.await_args.args[1], "Invalid command")
        self.assertIn("~policy [show|set", bot.send_command_response.await_args.args[2])

    def test_hyphenated_command_still_reaches_its_server_check(self):
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            content="~auto-role list", author_id="moderator",
            get_server=Mock(return_value=(None, None)),
        )

        self.assertTrue(asyncio.run(bot.handle_command(message)))
        self.assertEqual(bot.send_command_response.await_args.args[1], "Server-only command")
        self.assertIn("~auto-role", bot.send_command_response.await_args.args[2])

    def test_underscored_owner_command_preserves_arguments(self):
        bot = object.__new__(ModerationBot)
        bot.handle_global_command = AsyncMock()
        message = SimpleNamespace(content="~global_lookup USER_ID", author_id=GLOBAL_COMMAND_OWNER_ID)

        self.assertTrue(asyncio.run(bot.handle_command(message)))
        bot.handle_global_command.assert_awaited_once_with(
            message, "~global_lookup", ["~global_lookup", "USER_ID"]
        )

    def test_owner_command_permissions_still_apply(self):
        bot = object.__new__(ModerationBot)
        bot.handle_global_command = AsyncMock()
        message = SimpleNamespace(content="~global_lookup USER_ID", author_id="ordinary-user")

        with self.assertLogs("stoat_moderator", level="WARNING"):
            self.assertTrue(asyncio.run(bot.handle_command(message)))
        bot.handle_global_command.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
