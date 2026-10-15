import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from appeal_privacy import APPEAL_PRIVACY_VERSION, AI_TRAINING_ENABLED
from database import ModerationDatabase


class AppealPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "moderation.db"
        self.db = ModerationDatabase(self.path)
        self.now = datetime.now(timezone.utc)
        self.clock = patch("appeal_privacy.utcnow", return_value=self.now)
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        self.db.close()
        self.folder.cleanup()

    def make_appeal(self, *, age=0, source="automatic", user="author", message="message"):
        warning = self.db.add_warning(
            server_id="server", user_id=user, moderator_id="moderator", source=source, reason="Safety decision",
            message_id=message, original_content="original synthetic test message",
            scores={"harassment": .9},
        )
        case = self.db.get_warning_case("server", warning)
        appeal_id = self.db.create_appeal_access(
            hashlib.sha256(f"code-{warning}".encode()).hexdigest(),
            user, "moderation", case.reference_id, "server",
        )
        self.db.connection.execute(
            "UPDATE moderated_content_lifecycles SET decided_at=? WHERE server_id=? AND message_id=?",
            ((self.now - timedelta(days=age)).isoformat(), "server", message),
        )
        self.db.connection.commit()
        return appeal_id, warning, case

    def submit(self, appeal_id, opt_in=False):
        return self.db.submit_appeal(
            appeal_id, "author", "Synthetic appeal statement with private context",
            privacy_version=APPEAL_PRIVACY_VERSION, ai_improvement_opt_in=opt_in,
        )

    def content(self, warning):
        return self.db.connection.execute("SELECT original_content FROM warnings WHERE id=?", (warning,)).fetchone()[0]

    def contributions(self):
        return [dict(row) for row in self.db.connection.execute("SELECT * FROM appeal_ai_contributions")]

    def test_exact_30_day_expiry_removes_all_message_copies_but_keeps_case(self):
        appeal_id, warning, case = self.make_appeal()
        self.db.add_event(
            server_id="server", event_type="automatic_deletion", user_id="author", message_id="message",
            details={"original_content": "original synthetic test message", "scores": {"harassment": .9}},
        )
        self.db.add_moderation_case_entry("server", case.reference_id, "evidence", "Additional content", "moderator", [("proof.png", "image/png", b"synthetic image bytes")])
        self.db.enqueue_dashboard_action("server", "test", "moderator", {"nested": {"message_id": "message", "content": "original synthetic test message"}})
        other = self.db.add_warning(server_id="other-server", user_id="author", moderator_id="mod", source="manual", reason="Unrelated", message_id="message", original_content="keep this")
        self.db.connection.execute("UPDATE moderated_content_lifecycles SET decided_at=? WHERE server_id='server'", ((self.now-timedelta(days=30)).isoformat(),))
        self.db.connection.commit()
        self.db.appeal_privacy.prune(now=self.now - timedelta(microseconds=1))
        self.assertIsNotNone(self.content(warning))
        result = self.db.appeal_privacy.prune(now=self.now)
        self.assertEqual(result["expired_messages"], 1)
        self.assertIsNone(self.content(warning))
        self.assertEqual(self.content(other), "keep this")
        self.assertIsNotNone(self.db.get_moderation_case("server", case.reference_id))
        detail = self.db.get_moderation_case_detail("server", case.reference_id)
        self.assertIsNone(detail["source"]["original_content"])
        self.assertEqual(detail["source"]["scores"], {"harassment": .9})
        for table in ("moderation_case_entries", "moderation_case_entry_attachments"):
            self.assertEqual(self.db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
        stored = " ".join(str(tuple(row)) for table in ("moderation_events", "dashboard_actions") for row in self.db.connection.execute(f"SELECT * FROM {table}"))
        self.assertNotIn("original synthetic test message", stored)
        self.assertEqual(self.db.get_appeal(appeal_id)["status"], "eligible")

    def test_pending_appeal_holds_content_beyond_30_days_until_exact_timeout(self):
        appeal_id, warning, case = self.make_appeal(age=29)
        self.submit(appeal_id, True)
        submitted_at = datetime.fromisoformat(self.db.get_appeal(appeal_id)["submitted_at"])
        self.db.appeal_privacy.prune(now=submitted_at + timedelta(days=10) - timedelta(microseconds=1))
        self.assertIsNotNone(self.content(warning))
        result = self.db.appeal_privacy.prune(now=submitted_at + timedelta(days=10))
        self.assertEqual(result["timed_out_appeals"], 1)
        appeal = self.db.get_appeal(appeal_id)
        self.assertEqual(appeal["status"], "denied")
        self.assertIsNone(appeal["statement"])
        self.assertEqual(appeal["messages"], [])
        self.assertIsNone(self.content(warning))
        self.assertEqual(self.contributions(), [])
        self.assertFalse(appeal["privacy"]["ai_improvement_opt_in"])
        detail = self.db.get_moderation_case_detail("server", case.reference_id)
        self.assertIsNone(detail["source"]["original_content"])
        self.assertEqual(detail["source"]["scores"], {"harassment": .9})
        self.db.appeal_privacy.prune(now=submitted_at + timedelta(days=11))
        count = self.db.connection.execute("SELECT COUNT(*) FROM dashboard_actions WHERE action='resolve_appeal'").fetchone()[0]
        self.assertEqual(count, 1)
        logs = self.db.connection.execute("SELECT server_id,payload_json FROM dashboard_actions WHERE action='log_automatic_appeal_decision'").fetchall()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['server_id'], 'server')
        self.assertEqual(json.loads(logs[0]['payload_json']), {'appeal_id': appeal_id})

    def test_manual_decision_destroys_content_and_blobs_without_opt_in(self):
        for decision in ("approved", "denied"):
            with self.subTest(decision=decision):
                appeal_id, warning, case = self.make_appeal(message=decision)
                self.submit(appeal_id)
                message_id = self.db.get_latest_appeal_message_id(appeal_id, "appellant")
                self.db.add_appeal_message_attachment(message_id, "proof.png", "image/png", b"synthetic image content")
                self.db.add_moderation_case_entry("server", case.reference_id, "evidence", "Context", "moderator", [("proof.png", "image/png", b"synthetic image content")])
                result = self.db.review_appeal(appeal_id, "reviewer", decision, "Reviewed under the rules.")
                self.assertEqual(result["reviewer_response"], "Reviewed under the rules.")
                self.assertIsNone(result["statement"])
                self.assertEqual(result["messages"], [])
                self.assertIsNone(self.content(warning))
                detail = self.db.get_moderation_case_detail("server", case.reference_id)
                self.assertEqual(detail["source"]["scores"], {"harassment": .9})
                self.assertEqual(self.contributions(), [])
                self.assertIsNone(self.db.get_appeal_message_attachment(message_id))
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM appeal_message_attachments").fetchone()[0], 0)
        self.db.appeal_privacy.checkpoint()
        for path in Path(self.folder.name).glob("moderation.db*"):
            data = path.read_bytes()
            self.assertNotIn(b"original synthetic test message", data)
            self.assertNotIn(b"synthetic image content", data)
            self.assertNotIn(b"Synthetic appeal statement", data)

    def test_opt_in_preserves_only_own_original_for_90_days_after_manual_decision(self):
        appeal_id, warning, _ = self.make_appeal()
        self.submit(appeal_id, True)
        result = self.db.review_appeal(appeal_id, "reviewer", "approved", "False positive.")
        contribution, = self.contributions()
        self.assertEqual(contribution["original_content"], "original synthetic test message")
        self.assertEqual(contribution["user_id"], "author")
        self.assertEqual(contribution["review_status"], "not_approved_for_training")
        self.assertFalse(AI_TRAINING_ENABLED)
        self.assertNotIn("statement", contribution)
        self.assertIsNone(self.content(warning))
        self.assertIsNone(result["statement"])
        expires = datetime.fromisoformat(contribution["expires_at"])
        self.assertEqual(expires - datetime.fromisoformat(contribution["created_at"]), timedelta(days=90))
        self.db.appeal_privacy.prune(now=expires - timedelta(microseconds=1))
        self.assertEqual(len(self.contributions()), 1)
        self.db.appeal_privacy.prune(now=expires)
        self.assertEqual(self.contributions(), [])

    def test_withdrawal_destroys_saved_contribution_immediately(self):
        appeal_id, _, _ = self.make_appeal()
        self.submit(appeal_id, True)
        self.db.review_appeal(appeal_id, "reviewer", "denied", "Decision upheld.")
        self.db.appeal_privacy.withdraw(appeal_id)
        self.assertEqual(self.contributions(), [])
        self.assertFalse(self.db.get_appeal(appeal_id)["privacy"]["ai_improvement_opt_in"])

    def test_manual_and_other_authors_messages_cannot_be_contributed(self):
        appeal_id, _, _ = self.make_appeal(source="manual")
        with self.assertRaises(ValueError):
            self.submit(appeal_id, True)
        self.assertFalse(self.db.connection.in_transaction)
        other_id, _, _ = self.make_appeal(user="someone-else", message="other")
        self.db.connection.execute("UPDATE appeals SET user_id='author' WHERE id=?", (other_id,))
        self.db.connection.commit()
        with self.assertRaises(ValueError):
            self.submit(other_id, True)
        self.assertEqual(self.contributions(), [])

    def test_follow_up_does_not_extend_deadline_and_cannot_reopen_closed_appeal(self):
        appeal_id, _, _ = self.make_appeal()
        submitted = self.submit(appeal_id)
        before = submitted["privacy"]["appeal_deadline"]
        self.db.add_appeal_message(appeal_id, "appellant", "author", "Further context", privacy_version=APPEAL_PRIVACY_VERSION)
        self.assertEqual(self.db.get_appeal(appeal_id)["privacy"]["appeal_deadline"], before)
        self.db.review_appeal(appeal_id, "reviewer", "denied", "Reviewed.")
        with self.assertRaises(ValueError):
            self.db.add_appeal_message(appeal_id, "appellant", "author", "Late response", privacy_version=APPEAL_PRIVACY_VERSION)

    def test_stale_notice_does_not_save_statement_or_consent(self):
        appeal_id, _, _ = self.make_appeal()
        with self.assertRaises(ValueError):
            self.db.submit_appeal(appeal_id, "author", "Statement", privacy_version="old")
        self.assertEqual(self.db.get_appeal(appeal_id)["status"], "eligible")
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM appeal_privacy_consents").fetchone()[0], 0)

    def test_pending_appeal_preserves_evidence_with_retired_history_setting(self):
        appeal_id, warning, case = self.make_appeal(age=29)
        self.submit(appeal_id)
        old = (self.now-timedelta(days=31)).isoformat()
        self.db.connection.execute("UPDATE warnings SET created_at=? WHERE id=?", (old, warning))
        self.db.connection.execute("UPDATE moderation_cases SET created_at=? WHERE reference_id=?", (old, case.reference_id))
        self.db.connection.execute("UPDATE moderated_content_lifecycles SET decided_at=?", (old,))
        self.db.connection.commit()
        self.db.appeal_privacy.prune(now=self.now)
        self.assertEqual(self.content(warning), "original synthetic test message")
        self.assertIsNotNone(self.db.get_moderation_case("server", case.reference_id))

    def test_late_event_and_new_case_entry_cannot_restore_disposed_content(self):
        appeal_id, warning, case = self.make_appeal(age=31)
        self.db.appeal_privacy.prune(now=self.now)
        self.db.add_event(server_id="server", event_type="message_edited", message_id="message", user_id="author", details={"after_content": "Later edited content"})
        row = self.db.connection.execute("SELECT details_json FROM moderation_events WHERE event_type='message_edited'").fetchone()
        self.assertIsNone(row)
        with self.assertRaises(ValueError):
            self.db.add_moderation_case_entry("server", case.reference_id, "evidence", "Reintroduced content", "moderator")
        self.assertIsNone(self.content(warning))

    def test_old_closed_appeal_is_purged_without_retroactive_ai_consent(self):
        appeal_id, warning, _ = self.make_appeal()
        self.submit(appeal_id)
        self.db.connection.execute("UPDATE appeals SET status='denied',reviewed_at=? WHERE id=?", ((self.now-timedelta(days=20)).isoformat(), appeal_id))
        self.db.connection.commit()
        self.db.appeal_privacy.prune(now=self.now)
        self.assertIsNone(self.content(warning))
        self.assertEqual(self.contributions(), [])

    def event_details(self, event_id):
        return json.loads(self.db.connection.execute("SELECT details_json FROM moderation_events WHERE id=?", (event_id,)).fetchone()[0])

    def add_aged_event(self, event_type, age_days, message_id="loose-message", **details):
        event_id = self.db.add_event(
            server_id="server", event_type=event_type, user_id="author", message_id=message_id,
            details={"original_content": "private synthetic message", "kind": event_type, **details},
        )
        self.db.connection.execute("UPDATE moderation_events SET created_at=? WHERE id=?", ((self.now - timedelta(days=age_days)).isoformat(), event_id))
        self.db.connection.commit()
        return event_id

    def test_message_content_in_every_event_type_expires_after_30_days(self):
        old = [
            self.add_aged_event("automatic_link_deletion", 31, message_id="m-link"),
            self.add_aged_event("automatic_self_harm_deletion", 45, message_id="m-self"),
            self.add_aged_event("automation_executed", 60, message_id=None),
        ]
        recent = self.add_aged_event("automatic_link_deletion", 10, message_id="m-recent")

        result = self.db.appeal_privacy.prune(now=self.now + timedelta(hours=1))

        self.assertEqual(result["expired_event_content"], 3)
        for event_id in old:
            details = self.event_details(event_id)
            self.assertNotIn("original_content", details)
            self.assertIn("kind", details)
        self.assertEqual(self.event_details(recent)["original_content"], "private synthetic message")

    def test_open_appeal_keeps_event_content_for_its_message(self):
        appeal_id, _warning, _case = self.make_appeal(message="appealed")
        self.submit(appeal_id)
        event_id = self.add_aged_event("automatic_link_deletion", 35, message_id="appealed")

        self.db.appeal_privacy.prune(now=self.now + timedelta(hours=1))

        self.assertEqual(self.event_details(event_id)["original_content"], "private synthetic message")


if __name__ == "__main__":
    unittest.main()
