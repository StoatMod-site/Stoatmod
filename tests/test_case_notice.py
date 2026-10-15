import asyncio
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from bot import ModerationBot
from case_notice import APPEAL_MARKER, CaseNotice, merged_title
from database import WarningPolicy

APPEAL = (
    "\n\n**Appeal this decision**\nCase: `CASE-UJD6QL42`\nAppeal code: `CD8ZQQCJ3W`\n"
    "Open: https://modstoat.site/appeal\nEnter the code with your Stoat user ID."
)
REUSED_APPEAL = (
    "\n\n**Appeal this decision**\nCase: `CASE-UJD6QL42`\n"
    "Use the appeal code already sent for this case. That appeal covers the warning and its timeout."
)
SPAM_TEXT = (
    "Automatic spam protection acted in **Chatnarchy**.\n\n**Reason:** mass mention\n"
    "**Actions:** 1 warning and a timeout of 1 minute\n**Warnings in this server:** 3\n"
    "The warning and timeout are part of the same case. One appeal covers both actions."
)


class CaseNoticeTests(unittest.TestCase):
    def test_titles_describe_every_action_once(self) -> None:
        self.assertEqual(merged_title("You received a warning", "timeout"), "You were warned and timed out")
        self.assertEqual(merged_title("You received a warning", "kick"), "You were warned and kicked")
        self.assertEqual(merged_title("You were warned and timed out", "timeout"), "You were warned and timed out")
        self.assertEqual(merged_title("You were warned and timed out", "ban"), "You were warned, timed out and banned")
        self.assertEqual(merged_title("Your nickname violated server rules", "timeout"), "Your nickname violated server rules")

    def test_escalation_goes_before_the_single_appeal_block(self) -> None:
        notice = CaseNotice("user", "You were warned and timed out", SPAM_TEXT + APPEAL,
                            server_id="server", user=None, color="#ED4245")
        notice.add_escalation("timeout", 3, "Timed out for 5 minutes", "Chatnarchy", REUSED_APPEAL)
        title, description = notice.compose()
        self.assertEqual(title, "You were warned and timed out")
        self.assertEqual(description.count("Appeal this decision"), 1)
        self.assertIn("CD8ZQQCJ3W", description)
        self.assertNotIn("already sent", description)
        self.assertLess(description.index("Warning policy"), description.index("Appeal this decision"))
        self.assertIn("because you reached 3 warnings", description)
        self.assertIn("**Action:** Timed out for 5 minutes", description)
        self.assertTrue(description.endswith("Enter the code with your Stoat user ID."))

    def test_without_an_escalation_the_message_is_unchanged(self) -> None:
        notice = CaseNotice("user", "You received a warning", "body" + APPEAL, server_id=None, user=None, color="#ED4245")
        self.assertEqual(notice.compose(), ("You received a warning", "body" + APPEAL))

    def test_a_message_without_an_appeal_gets_the_escalations_appeal(self) -> None:
        notice = CaseNotice("user", "You received a warning", "body", server_id=None, user=None, color="#ED4245")
        notice.add_escalation("ban", 5, "Banned", "Server", APPEAL)
        _title, description = notice.compose()
        self.assertEqual(description.count("Appeal this decision"), 1)
        self.assertTrue(description.endswith("Enter the code with your Stoat user ID."))
        self.assertIn(APPEAL_MARKER, description)


    def test_merged_message_is_translated_for_other_server_languages(self) -> None:
        from localization import localize_delivery
        notice = CaseNotice("user", "You received a warning", "You received a warning in **S**." + APPEAL,
                            server_id="server", user=None, color="#ED4245")
        notice.add_escalation("kick", 5, "Kicked", "S", REUSED_APPEAL)
        title, description = notice.compose()
        for locale, heading, title_text in (
            ("fr", "Politique d’avertissements", "avertissement et avez été expulsé"),
            ("pt", "Política de advertências", "advertência e foi expulso"),
            ("es", "Política de advertencias", "advertencia y has sido expulsado"),
        ):
            localized_title, localized = localize_delivery(locale, title, description)
            self.assertIn(title_text, localized_title)
            self.assertIn(heading, localized)
            self.assertNotIn("Warning policy", localized)


class OneMessagePerCaseTests(unittest.TestCase):
    def make_bot(self, policy=None):
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(timeout=AsyncMock(), name="member", discriminator="1234")
        bot_member = SimpleNamespace(name="bot")
        bot_permissions = SimpleNamespace(manage_messages=True, kick_members=True, ban_members=True,
                                          timeout_members=True, manage_server=False)
        member_permissions = SimpleNamespace(manage_messages=False, kick_members=False, ban_members=False,
                                             timeout_members=False, manage_server=False)
        server = SimpleNamespace(id="server", name="Chatnarchy", ban=AsyncMock(),
                                 get_member=lambda uid: bot_member if uid == "bot" else member,
                                 permissions_for=lambda who: bot_permissions if who is bot_member else member_permissions)
        bot.database = SimpleNamespace(
            get_warning_policy=Mock(return_value=policy or WarningPolicy()),
            claim_warning_policy_action=Mock(return_value=True),
            release_warning_policy_action=Mock(), add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)
        bot._appeal_instructions = Mock(return_value=REUSED_APPEAL)
        bot._kick_member_with_reason = AsyncMock()
        return bot, server, member

    def test_warning_and_policy_timeout_arrive_as_one_message(self) -> None:
        bot, server, member = self.make_bot()

        async def scenario():
            await bot._send_case_dm("user", "You were warned and timed out", SPAM_TEXT + APPEAL,
                                    warning_id=30, server_id="server")
            self.assertEqual(bot._send_user_dm.await_count, 0)  # held until the policy has been decided
            await bot._enforce_warning_policy_and_notify(server, "server", "user", 30, 3)

        asyncio.run(scenario())

        member.timeout.assert_awaited_once_with(timedelta(hours=1))
        bot._send_user_dm.assert_awaited_once()
        args = bot._send_user_dm.await_args
        title, description = args.args[1], args.args[2]
        self.assertEqual(title, "You were warned and timed out")
        self.assertIn("Automatic spam protection acted", description)
        self.assertIn("because you reached 3 warnings", description)
        self.assertIn("Timed out for 1 hour", description)
        self.assertEqual(description.count("Appeal this decision"), 1)
        self.assertEqual(args.kwargs["server_id"], "server")

    def test_a_plain_warning_below_the_threshold_is_sent_once_unchanged(self) -> None:
        bot, server, member = self.make_bot()

        async def scenario():
            await bot._send_case_dm("user", "You received a warning", "body" + APPEAL,
                                    warning_id=31, server_id="server")
            await bot._enforce_warning_policy_and_notify(server, "server", "user", 31, 1)

        asyncio.run(scenario())

        member.timeout.assert_not_awaited()
        bot._send_user_dm.assert_awaited_once()
        self.assertEqual(bot._send_user_dm.await_args.args[1:3], ("You received a warning", "body" + APPEAL))

    def test_warning_that_triggers_a_kick_becomes_one_kick_message(self) -> None:
        policy = WarningPolicy(timeout_count=3, kick_count=4, ban_count=6)
        bot, server, member = self.make_bot(policy)

        async def scenario():
            await bot._send_case_dm("user", "You received a warning", "You received a warning in **Chatnarchy**." + APPEAL,
                                    warning_id=32, server_id="server")
            await bot._enforce_warning_policy_and_notify(server, "server", "user", 32, 4)

        asyncio.run(scenario())

        bot._kick_member_with_reason.assert_awaited_once()
        bot._send_user_dm.assert_awaited_once()
        title, description = bot._send_user_dm.await_args.args[1:3]
        self.assertEqual(title, "You were warned and kicked")
        self.assertIn("**Action:** Kicked", description)
        self.assertEqual(description.count("Appeal this decision"), 1)

    def test_an_escalation_without_a_warning_message_still_sends_its_own(self) -> None:
        bot, server, _member = self.make_bot()
        asyncio.run(bot._enforce_warning_policy_and_notify(server, "server", "user", 33, 3))
        bot._send_user_dm.assert_awaited_once()
        self.assertEqual(bot._send_user_dm.await_args.args[1], "You have been timed out")

    def test_the_held_message_is_sent_even_when_the_policy_step_fails(self) -> None:
        bot, server, _member = self.make_bot()
        bot.enforce_warning_policy = AsyncMock(side_effect=RuntimeError("API unavailable"))

        async def scenario():
            await bot._send_case_dm("user", "You received a warning", "body", warning_id=34, server_id="server")
            with self.assertRaises(RuntimeError):
                await bot._enforce_warning_policy_and_notify(server, "server", "user", 34, 3)

        asyncio.run(scenario())
        bot._send_user_dm.assert_awaited_once()
        self.assertEqual(bot._send_user_dm.await_args.args[1:3], ("You received a warning", "body"))

    def test_safety_timer_sends_the_message_if_the_policy_step_never_runs(self) -> None:
        bot, _server, _member = self.make_bot()

        async def scenario():
            with patch("bot.CASE_NOTICE_GRACE_SECONDS", 0.05):
                await bot._send_case_dm("user", "You received a warning", "body", warning_id=35, server_id="server")
                await asyncio.sleep(0.3)
            return await bot._flush_case_notice(("server", "user", 35))

        self.assertFalse(asyncio.run(scenario()))  # nothing left to send: the timer already did
        bot._send_user_dm.assert_awaited_once()

    def test_without_a_warning_id_the_message_is_sent_immediately(self) -> None:
        bot, _server, _member = self.make_bot()
        asyncio.run(bot._send_case_dm("user", "Title", "body", warning_id=None, server_id="server"))
        bot._send_user_dm.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
