import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from bot import GLOBAL_COMMAND_OWNER_ID, ModerationBot
from database import ModerationDatabase
from localization import help_description


class ModerationCommandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.directory.name) / "test.db")
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.db.connection.close)
        self.member = SimpleNamespace(timeout=AsyncMock())
        self.server = SimpleNamespace(
            id="server", name="Test server", owner_id="moderator",
            get_member=Mock(return_value=self.member), fetch_member=AsyncMock(return_value=self.member),
            ban=AsyncMock(), unban=AsyncMock(),
            fetch_bans=AsyncMock(return_value=[SimpleNamespace(user_id="target")]),
            permissions_for=Mock(return_value=SimpleNamespace(manage_server=True)),
        )
        self.bot = object.__new__(ModerationBot)
        self.bot.database = self.db
        self.bot._is_moderator = Mock(return_value=True)
        self.bot._member_is_moderator = Mock(return_value=False)
        self.bot._moderator_is_exempt = Mock(return_value=False)
        self.bot.require_action_permissions = AsyncMock(return_value=True)
        self.bot._resolve_user_tag = AsyncMock(side_effect=lambda user_id, *_args: user_id)
        self.bot._send_user_dm = AsyncMock(return_value=True)
        self.bot._appeal_instructions = Mock(return_value="\nAppeal instructions")
        self.bot._active_warning_count = Mock(return_value=1)
        self.bot.enforce_warning_policy = AsyncMock()
        self.bot._kick_member_with_reason = AsyncMock()
        self.bot._pending_ban_attribution = {}
        self.bot.send_command_response = AsyncMock()
        self.bot.send_log = AsyncMock()

    async def command(self, content, author="moderator"):
        message = SimpleNamespace(
            content=content, author_id=author, channel_id="commands",
            get_server=Mock(return_value=(self.server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        self.assertTrue(await self.bot.handle_command(message))

    async def test_mute_examples_reach_timeout_with_reason_and_appeal(self):
        for arguments, duration, reason in (
            ("spam!!", 3600, "spam!!"),
            ("spam 25m", 1500, "spam"),
            ("25m spam", 1500, "spam"),
            ("25 minutes repeated spam", 1500, "repeated spam"),
            ("repeated spam 25 minutes", 1500, "repeated spam"),
            ("1h30m repeated spam", 5400, "repeated spam"),
            ("repeated spam 1 hour 30 minutes", 5400, "repeated spam"),
            ("4w continued harassment", 2419200, "continued harassment"),
            ("Repeated spam in 3 channels", 3600, "Repeated spam in 3 channels"),
            ("Breaking rule 2", 3600, "Breaking rule 2"),
        ):
            with self.subTest(arguments=arguments):
                self.member.timeout.reset_mock()
                await self.command("~MuTe <@target> " + arguments)
                self.member.timeout.assert_awaited_once_with(timedelta(seconds=duration))
                case = self.db.list_moderation_cases("server", "target", limit=1)[0]
                self.assertEqual(case.reason, reason)
                self.bot._appeal_instructions.assert_called_with("target", "moderation", case.reference_id, server_id="server")
                self.assertIn("**Reason:** " + reason, self.bot.send_command_response.await_args.args[2])
                self.assertIn("Appeal instructions", self.bot._send_user_dm.await_args.args[2])

    async def test_mute_rejects_missing_reason_and_bad_durations_without_side_effects(self):
        for arguments in ("", "25m", "1 hour 30 minutes", '25m ""', "29d spam", "spam 0m", "spam 25x", "spam 1h30x", "30m spam 1h", "-25m spam", "1.5h spam"):
            with self.subTest(arguments=arguments):
                await self.command("~mute target " + arguments)
                self.member.timeout.assert_not_awaited()
                self.server.fetch_member.assert_not_awaited()
                self.assertEqual(self.db.list_moderation_cases("server", "target"), [])
                self.bot._send_user_dm.assert_not_awaited()

    async def test_all_manual_actions_require_reasons(self):
        for command in ("warn", "kick", "ban", "unban", "unmute", "approve", "deny", "bypass"):
            for suffix in ("", ' ""', "   "):
                with self.subTest(command=command, suffix=suffix):
                    await self.command(f"~{command} target{suffix}")
                    self.assertEqual(self.bot.send_command_response.await_args.args[1], "Reason required")
        self.server.ban.assert_not_awaited()
        self.server.unban.assert_not_awaited()
        self.member.timeout.assert_not_awaited()
        self.bot._kick_member_with_reason.assert_not_awaited()
        self.assertEqual(self.db.list_moderation_cases("server", "target"), [])

    async def test_global_actions_require_reasons(self):
        for command in ("global_warn", "global_ban", "global_unban"):
            with self.subTest(command=command):
                await self.command(f"~{command} target", author=GLOBAL_COMMAND_OWNER_ID)
                self.assertEqual(self.bot.send_command_response.await_args.args[1], "Reason required")

    async def test_ban_preserves_complete_reason(self):
        await self.command("~ban <@target> Repeated harassment after warnings")
        self.server.ban.assert_awaited_once_with("target", reason="Repeated harassment after warnings")
        self.assertEqual(self.bot._pending_ban_attribution[("server", "target")], ("moderator", "Repeated harassment after warnings"))

    async def test_global_unban_reason_is_preserved_in_audit(self):
        self.db.add_global_ban("ABC123", "target", "Original reason", GLOBAL_COMMAND_OWNER_ID)
        self.bot._apply_global_ban_to_servers = AsyncMock(return_value=(["Test server"], []))
        await self.command("~global_unban target Mistaken identity", author=GLOBAL_COMMAND_OWNER_ID)
        self.assertIsNone(self.db.get_global_ban("target"))
        row = self.db.connection.execute("SELECT details_json FROM moderation_events WHERE event_type='manual_global_unban'").fetchone()
        self.assertIn("Mistaken identity", row[0])

    async def test_warning_stores_required_reason(self):
        await self.command("~warn <@target> Repeated unsolicited messages")
        self.assertEqual(self.db.list_moderation_cases("server", "target")[0].reason, "Repeated unsolicited messages")

    async def test_unmute_stores_reason_and_notifies_member(self):
        await self.command("~unmute <@target> Appeal accepted after review")
        self.member.timeout.assert_awaited_once_with(None)
        self.assertIn("Appeal accepted after review", self.bot._send_user_dm.await_args.args[2])
        self.assertIn("Appeal accepted after review", self.bot.send_log.await_args.args[2])

    async def test_unban_works_without_server_membership(self):
        await self.command("~unban <@target> Mistaken identity confirmed")
        self.server.unban.assert_awaited_once_with("target")
        self.server.get_member.assert_not_called()
        self.server.fetch_member.assert_not_awaited()
        self.bot.require_action_permissions.assert_awaited_once_with(self.server, "ban_members")
        self.assertIn("Mistaken identity confirmed", self.bot.send_log.await_args.args[2])
        row = self.db.connection.execute("SELECT * FROM moderation_events WHERE event_type='manual_unban'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(self.db.list_moderation_cases("server", "target"), [])

    async def test_unban_not_banned_has_no_success_event(self):
        self.server.fetch_bans.return_value = []
        await self.command("~unban target Mistaken ban")
        self.server.unban.assert_not_awaited()
        self.assertEqual(self.bot.send_command_response.await_args.args[1], "User is not banned")
        self.bot.send_log.assert_not_awaited()

    async def test_unban_cannot_override_a_global_ban(self):
        with patch.object(self.db, "get_global_ban", return_value=object()):
            await self.command("~unban target Reviewed case")
        self.server.unban.assert_not_awaited()
        self.assertEqual(self.bot.send_command_response.await_args.args[1], "User is globally banned")

    async def test_unban_api_failure_has_no_success_event(self):
        self.server.unban.side_effect = RuntimeError("permission denied")
        with self.assertLogs("stoat_moderator", level="ERROR"):
            await self.command("~unban target Reviewed case")
        self.assertEqual(self.bot.send_command_response.await_args.args[1], "Unban failed")
        self.bot.send_log.assert_not_awaited()
        self.bot._send_user_dm.assert_not_awaited()

    async def test_permissions_checked_for_unban_and_mute(self):
        self.bot.require_action_permissions.return_value = False
        await self.command("~unban target Reviewed case")
        await self.command("~mute target 25m Repeated spam")
        self.server.unban.assert_not_awaited()
        self.member.timeout.assert_not_awaited()

    async def test_ordinary_user_cannot_unban(self):
        self.bot._is_moderator.return_value = False
        await self.command("~unban target Reviewed case")
        self.server.unban.assert_not_awaited()

    async def test_appeal_both_orders_store_reason(self):
        appeal = dict(id=7, status="submitted", user_id="target", case_reference="K7M2Q9XA")
        self.bot.database = SimpleNamespace(
            get_server_appeal_by_case=Mock(return_value=appeal),
            review_appeal=Mock(return_value=appeal), enqueue_dashboard_action=Mock(), add_event=Mock(),
        )
        for arguments in ("CASE-K7M2Q9XA accept", "accept CASE-K7M2Q9XA", "accept case K7M2Q9XA", "case K7M2Q9XA accepted"):
            with self.subTest(arguments=arguments):
                await self.command("~appeal " + arguments + " Reviewed the evidence")
                self.bot.database.review_appeal.assert_called_with(7, "moderator", "approved", "Reviewed the evidence")
                self.assertEqual(self.bot.database.add_event.call_args.kwargs["details"]["reason"], "Reviewed the evidence")

    async def test_appeal_missing_reason_cannot_decide(self):
        self.bot.database = Mock()
        for arguments in ("CASE-K7M2Q9XA accept", "deny CASE-K7M2Q9XA", 'CASE-K7M2Q9XA accept ""'):
            await self.command("~appeal " + arguments)
            self.bot.database.review_appeal.assert_not_called()
            self.bot.database.enqueue_dashboard_action.assert_not_called()

    async def test_remove_still_needs_no_reason_and_accepts_spaced_case_id(self):
        event = self.db.add_event(server_id="server", event_type="manual_mute", user_id="target", details={"reason": "spam", "duration_seconds": 1500})
        case = self.db.get_event_case("server", event)
        await self.command("~remove case " + case.reference_id)
        self.assertEqual(self.db.get_event_case("server", event).status, "removed")
        self.assertEqual(self.bot.send_command_response.await_args.args[1], "Moderation case removed")

    def test_help_lists_unban_and_required_reasons(self):
        for language in ("en", "fr", "pt", "es"):
            description = help_description(language)
            self.assertIn("~unban USER_ID", description)
            self.assertNotIn("~warn USER_ID [", description)
            self.assertNotIn("~ban USER_ID [", description)


if __name__ == "__main__":
    unittest.main()
