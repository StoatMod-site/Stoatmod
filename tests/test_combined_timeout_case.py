import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from bot import ModerationBot
from database import ModerationDatabase


class CombinedTimeoutCaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "cases.db"
        self.db = ModerationDatabase(self.path)

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def warning(self, **changes):
        values = dict(server_id="server", user_id="user", moderator_id="bot",
                      source="automatic", reason="Mass mentions and repeated messages",
                      message_id="message", channel_id="channel", original_content="evidence")
        values.update(changes)
        return self.db.add_warning(**values)

    def timeout(self, warning_id, **changes):
        values = dict(server_id="server", user_id="user", actor_id="bot",
                      event_type="automatic_spam_timeout", message_id="message",
                      details={"warning_id": warning_id, "timeout_seconds": 3600,
                               "reason": "mentioned 6 users or roles in one message"})
        values.update(changes)
        return self.db.add_event(**values)

    def bot(self):
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = self.db
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://modstoat.site", spam_timeout_seconds=3600,
            mass_mention_limit=5,
        )
        bot._spam_timeout_until = {}
        bot._bot_deleted_ids = set()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.enforce_warning_policy = AsyncMock()
        return bot

    def test_spam_sends_one_code_and_stores_one_case_with_both_actions(self):
        bot = self.bot()
        member = SimpleNamespace(timeout=AsyncMock())
        server = SimpleNamespace(name="Server", get_member=Mock(return_value=member),
                                 permissions_for=Mock(return_value=SimpleNamespace()))
        message = SimpleNamespace(
            author_id="user", id="message", channel_id="channel", content="evidence",
            mention_ids=["u1", "u2", "u3", "u4", "u5", "u6"], role_mention_ids=[],
            raw_flags=0, delete=AsyncMock(), get_server=Mock(return_value=(server, "server")),
            get_author_as_member=Mock(return_value=member), get_author_as_user=Mock(return_value=None),
        )
        self.assertTrue(asyncio.run(bot.handle_spam(message)))
        cases = self.db.list_moderation_cases("server", "user")
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].action, "warning_and_timeout")
        self.assertEqual(self.db.count_warnings("server", "user"), 1)
        bot._send_user_dm.assert_awaited_once()
        description = bot._send_user_dm.await_args.args[2]
        self.assertEqual(description.count("Appeal code:"), 1)
        self.assertEqual(description.count("**Appeal this decision**"), 1)
        self.assertIn("1 warning and a timeout", description)
        self.assertIn("One appeal covers both actions", description)
        self.assertIn("mentioned 6 users or roles", description)
        self.assertIn(cases[0].reference_id, description)
        message.delete.assert_awaited_once()
        member.timeout.assert_awaited_once()
        dashboard = self.db.list_dashboard_cases_for_user("server", "user")
        self.assertEqual(len(dashboard), 1)
        self.assertEqual(dashboard[0]["action"], "warning_and_timeout")
        self.assertIn("3600 seconds", dashboard[0]["reason"])

    def test_link_evidence_and_single_case_survive_restart_and_removal(self):
        warning_id = self.warning()
        event_id = self.timeout(warning_id)
        case = self.db.get_warning_case("server", warning_id)
        self.assertEqual(self.db.get_event_case("server", event_id).reference_id, case.reference_id)
        detail = self.db.get_moderation_case_detail("server", case.reference_id)
        self.assertEqual(detail["source"]["original_content"], "evidence")
        self.assertIn("3600 seconds", detail["entries"][0]["content"])
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.assertEqual(len(self.db.list_moderation_cases("server", "user")), 1)
        self.db.remove_moderation_case("server", case.reference_id)
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.assertEqual(len(self.db.list_moderation_cases("server", "user")), 1)
        self.assertEqual(self.db.get_event_case("server", event_id).status, "removed")
        self.assertEqual(self.db.count_warnings("server", "user"), 0)

    def test_unrelated_user_server_message_and_missing_warning_do_not_merge(self):
        warning_id = self.warning()
        for changes in ({"user_id": "other"}, {"server_id": "other"},
                        {"message_id": "other"}, {"details": {"warning_id": 999999}}):
            with self.subTest(changes=changes):
                event_id = self.timeout(warning_id, **changes)
                case = self.db.get_event_case(changes.get("server_id", "server"), event_id)
                self.assertEqual(case.source_type, "event")
                self.assertEqual(case.action, "timeout")
        self.assertEqual(self.db.get_warning_case("server", warning_id).action, "warning")

    def test_separate_messages_keep_separate_cases(self):
        first = self.warning()
        second = self.warning(message_id="message2")
        self.timeout(first)
        self.timeout(second, message_id="message2")
        cases = self.db.list_moderation_cases("server", "user")
        self.assertEqual(len(cases), 2)
        self.assertNotEqual(cases[0].reference_id, cases[1].reference_id)

    def test_historic_two_case_references_and_codes_are_preserved(self):
        warning_id = self.warning()
        event_id = self.timeout(warning_id, details={"reason": "Legacy spam"})
        case = self.db.get_event_case("server", event_id)
        self.db.connection.execute("UPDATE moderation_events SET details_json=? WHERE id=?",
                                   (json.dumps({"warning_id": warning_id, "reason": "Legacy spam"}), event_id))
        self.db.create_appeal_access("oldhash", "user", "moderation", case.reference_id, "server")
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.assertEqual(len(self.db.list_moderation_cases("server", "user")), 2)
        self.assertEqual(self.db.get_event_case("server", event_id).reference_id, case.reference_id)
        self.assertIsNotNone(self.db.get_appeal_by_credentials("oldhash", "user"))

    def test_warning_policy_timeout_reuses_existing_appeal_without_rotating_code(self):
        warning_id = self.warning()
        case = self.db.get_warning_case("server", warning_id)
        bot = self.bot()
        original = bot._appeal_instructions("user", "moderation", case.reference_id, server_id="server")
        code = re.search(r"Appeal code: `([^`]+)`", original)[1]
        event_id = self.timeout(warning_id, event_type="warning_policy_timeout", message_id=None,
                                details={"warning_id": warning_id, "warning_count": 3, "duration_seconds": 3600})
        repeated = bot._appeal_instructions("user", "moderation", case.reference_id,
                                           server_id="server", reuse_existing=True)
        self.assertNotIn("Appeal code:", repeated)
        self.assertIn("already sent", repeated)
        appeal = self.db.get_appeal_by_credentials(bot._dashboard_code_hash(code), "user")
        self.assertEqual(appeal["evidence"]["action"], "warning_and_timeout")
        self.assertEqual(appeal["evidence"]["original_message"], "evidence")
        self.assertEqual(self.db.get_event_case("server", event_id).reference_id, case.reference_id)

    def run_review(self, decision, *, fail_timeout=False):
        warning_id = self.warning()
        self.timeout(warning_id)
        case = self.db.get_warning_case("server", warning_id)
        appeal_id = self.db.create_appeal_access("hash", "user", "moderation", case.reference_id, "server")
        self.db.submit_appeal(appeal_id, "user", "Please review this incident")
        self.db.review_appeal(appeal_id, "moderator", decision, "Reviewed evidence")
        bot = self.bot()
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        member = SimpleNamespace(timeout=AsyncMock(side_effect=RuntimeError("unavailable") if fail_timeout else None))
        server = SimpleNamespace(get_member=Mock(return_value=member))
        bot.get_server = Mock(return_value=server)
        action = dict(id=1, server_id="server", actor_id="moderator", action="resolve_appeal",
                      payload={"appeal_id": appeal_id, "decision": decision})

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            claim_dashboard_actions=Mock(side_effect=claim_once), get_appeal=self.db.get_appeal,
            remove_moderation_case=self.db.remove_moderation_case, add_event=Mock(),
            finish_dashboard_action=Mock(return_value=True),
        )
        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())
        return bot, member, case

    def test_approved_appeal_reverses_both_warning_and_timeout(self):
        bot, member, case = self.run_review("approved")
        member.timeout.assert_awaited_once_with(None)
        self.assertEqual(self.db.count_warnings("server", "user"), 0)
        self.assertEqual(self.db.get_moderation_case("server", case.reference_id).status, "removed")
        self.assertIn("Warning and timeout removed", bot._send_user_dm.await_args.args[2])
        self.assertTrue(bot.database.finish_dashboard_action.call_args.kwargs["success"])

    def test_denied_appeal_keeps_both_actions(self):
        bot, member, case = self.run_review("denied")
        member.timeout.assert_not_awaited()
        self.assertEqual(self.db.count_warnings("server", "user"), 1)
        self.assertEqual(self.db.get_moderation_case("server", case.reference_id).status, "active")

    def test_failed_timeout_reversal_does_not_claim_warning_was_removed(self):
        bot, member, case = self.run_review("approved", fail_timeout=True)
        self.assertEqual(self.db.count_warnings("server", "user"), 1)
        self.assertEqual(self.db.get_moderation_case("server", case.reference_id).status, "active")
        bot._send_user_dm.assert_not_awaited()
        self.assertFalse(bot.database.finish_dashboard_action.call_args.kwargs["success"])


if __name__ == "__main__":
    unittest.main()
