import json
import tempfile
import unittest
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

from database import DEFAULT_SPAM_SETTINGS, ModerationDatabase
from admin_credentials import admin_login_subject_hash, hash_password, verify_password


class ModerationDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = ModerationDatabase(Path(self.directory.name, "moderation.db"))

    def tearDown(self) -> None:
        self.database.close()
        self.directory.cleanup()

    def test_onboarding_redesign_resets_every_user_once(self) -> None:
        self.database.save_onboarding_state(
            "server-a", "owner-a", 4, complete=True
        )
        self.database.save_onboarding_state(
            "server-a", "moderator-a", 3, dismissed=True
        )
        self.database.connection.execute(
            "DELETE FROM app_metadata "
            "WHERE key='dashboard_onboarding_redesign_v2_reset'"
        )
        self.database.connection.commit()
        database_path = self.database.path
        self.database.close()

        self.database = ModerationDatabase(database_path)

        for user_id in ("owner-a", "moderator-a"):
            with self.subTest(user_id=user_id):
                state = self.database.get_onboarding_state("server-a", user_id)
                self.assertEqual(state["current_step"], 0)
                self.assertFalse(state["completed"])
                self.assertFalse(state["dismissed"])

        self.database.save_onboarding_state("server-a", "owner-a", 2)
        self.database.close()
        self.database = ModerationDatabase(database_path)
        self.assertEqual(
            self.database.get_onboarding_state("server-a", "owner-a")[
                "current_step"
            ],
            2,
        )

        self.database.save_onboarding_state(
            "server-a", "owner-a", 4, complete=True
        )
        reopened = self.database.save_onboarding_state(
            "server-a", "owner-a", 0, reopen=True
        )
        self.assertEqual(reopened["current_step"], 0)
        self.assertFalse(reopened["completed"])
        self.assertFalse(reopened["dismissed"])

    def test_global_announcement_targets_use_durable_server_snapshots(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-two", "Second server", 20, [], owner_id="owner-two"
        )
        self.database.update_dashboard_server_snapshot(
            "server-one", "First server", 10, [], owner_id="owner-one"
        )
        self.database.set_log_channel("server-one", "log-one")

        self.assertEqual(
            self.database.list_global_announcement_targets(),
            [
                {
                    "server_id": "server-one",
                    "server_name": "First server",
                    "owner_id": "owner-one",
                    "log_channel_id": "log-one",
                },
                {
                    "server_id": "server-two",
                    "server_name": "Second server",
                    "owner_id": "owner-two",
                    "log_channel_id": None,
                },
            ],
        )

    def test_dashboard_delivery_action_can_be_deferred_with_claim_token(self) -> None:
        action_id = self.database.enqueue_dashboard_action(
            "server-a", "publish_poll", "owner-a", {"poll_id": 12}
        )
        claimed = self.database.claim_dashboard_actions()[0]

        self.assertFalse(
            self.database.defer_dashboard_action(
                action_id,
                payload={"poll_id": 12, "retry_count": 1},
                delay_seconds=5,
                error="Temporary delivery failure",
                claim_token="wrong-token",
            )
        )
        self.assertTrue(
            self.database.defer_dashboard_action(
                action_id,
                payload={"poll_id": 12, "retry_count": 1},
                delay_seconds=5,
                error="Temporary delivery failure",
                claim_token=claimed["claim_token"],
            )
        )
        action = self.database.get_dashboard_action(action_id)
        self.assertEqual(action["status"], "pending")
        self.assertEqual(action["payload"]["retry_count"], 1)
        self.assertTrue(action["result"]["retry_scheduled"])
        self.assertEqual(self.database.claim_dashboard_actions(), [])

    def test_local_report_instruction_message_never_rewinds_new_settings(self) -> None:
        self.database.save_local_report_settings(
            "server-a",
            enabled=True,
            channel_id="reports-a",
            anonymous_allowed=True,
            updated_by="owner-a",
        )
        self.assertTrue(
            self.database.set_local_report_instruction_message(
                "server-a", "reports-a", "message-a"
            )
        )
        self.assertEqual(
            self.database.get_local_report_settings("server-a")["message_id"],
            "message-a",
        )

        changed = self.database.save_local_report_settings(
            "server-a",
            enabled=True,
            channel_id="reports-b",
            anonymous_allowed=True,
            updated_by="owner-a",
        )
        self.assertIsNone(changed["message_id"])
        self.assertFalse(
            self.database.set_local_report_instruction_message(
                "server-a", "reports-a", "stale-message"
            )
        )
        current = self.database.get_local_report_settings("server-a")
        self.assertEqual(current["channel_id"], "reports-b")
        self.assertIsNone(current["message_id"])

    def test_member_directory_keeps_server_total_exact_and_idempotent(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 2, [], [], []
        )
        self.database.replace_dashboard_members(
            "server-a",
            [
                {"user_id": "member-a", "username": "one"},
                {"user_id": "member-a", "username": "one-updated"},
                {"user_id": "member-b", "username": "two"},
            ],
        )

        self.assertEqual(
            self.database.get_dashboard_overview("server-a")["server"][
                "member_count"
            ],
            2,
        )

        self.database.upsert_dashboard_member(
            "server-a",
            {"user_id": "member-b", "username": "two-updated"},
            adjust_count_on_insert=True,
        )
        self.assertEqual(
            self.database.get_dashboard_overview("server-a")["server"][
                "member_count"
            ],
            2,
        )

        self.database.upsert_dashboard_member(
            "server-a",
            {"user_id": "member-c", "username": "three"},
            adjust_count_on_insert=True,
        )
        self.assertEqual(
            self.database.get_dashboard_overview("server-a")["server"][
                "member_count"
            ],
            3,
        )

        self.database.remove_dashboard_member(
            "server-a", "missing-member", adjust_count_on_delete=True
        )
        self.assertEqual(
            self.database.get_dashboard_overview("server-a")["server"][
                "member_count"
            ],
            3,
        )

        self.database.remove_dashboard_member(
            "server-a", "member-a", adjust_count_on_delete=True
        )
        self.assertEqual(
            self.database.get_dashboard_overview("server-a")["server"][
                "member_count"
            ],
            2,
        )

    def test_dashboard_member_count_can_be_reconciled_from_live_stoat_data(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 3, [], [], []
        )

        updated = self.database.update_dashboard_server_member_count("server-a", 17)

        self.assertTrue(updated)
        self.assertEqual(
            self.database.get_dashboard_server_member_count("server-a"), 17
        )
        self.assertIsNone(
            self.database.get_dashboard_server_member_count("missing-server")
        )

    def test_recorded_full_username_survives_member_removal_in_logs(self) -> None:
        self.database.replace_dashboard_members(
            "server-a",
            [
                {
                    "user_id": "user-a",
                    "username": "readable-user",
                    "discriminator": "0420",
                    "display_name": "Readable User",
                }
            ],
        )
        self.database.add_event(
            server_id="server-a", event_type="member_join", user_id="user-a"
        )
        self.database.remove_dashboard_member("server-a", "user-a")

        event = self.database.list_dashboard_events("server-a")[0]

        self.assertEqual(event["username"], "readable-user#0420")
        self.assertEqual(event["display_name"], "Readable User")
        self.assertEqual(
            self.database.get_recorded_user_identity("user-a")["full_username"],
            "readable-user#0420",
        )


    def _make_discovery_ready_server(self, server_id: str = "discovery-server") -> None:
        self.database.update_dashboard_server_snapshot(
            server_id,
            "Discovery Community",
            125,
            [("general", "general")],
            [],
            [],
            "https://cdn.example/discovery.png",
            {
                "available": True,
                "permissions": [
                    {"name": "manage_messages", "granted": True},
                    {"name": "ban_members", "granted": True},
                ],
            },
        )

    def test_discovery_requires_review_and_live_eligibility(self) -> None:
        self._make_discovery_ready_server()
        state = self.database.get_discovery_application("discovery-server")
        self.assertTrue(state["eligibility"]["eligible"])
        self.assertTrue(state["can_apply"])

        submitted = self.database.submit_discovery_application(
            "discovery-server",
            "moderator",
            "A welcoming community for people who enjoy building things.",
            "Weekly events and beginner-friendly discussion.",
            "https://stt.gg/discovery-community",
            ["Gaming", "Friendly", "gaming"],
        )
        self.assertEqual(submitted["application"]["status"], "pending")
        self.assertEqual(submitted["application"]["tags"], ["Gaming", "Friendly"])
        self.assertEqual(self.database.list_public_discovery_servers(), [])

        approved = self.database.review_discovery_application(
            "discovery-server", "approved", "owner"
        )
        self.assertEqual(approved["application"]["status"], "approved")
        self.database.record_daily_message("discovery-server", "member-a")
        self.database.record_daily_message("discovery-server", "member-a")
        self.database.record_daily_message("discovery-server", "member-b")
        listing = self.database.list_public_discovery_servers()[0]
        self.assertEqual(listing["server_name"], "Discovery Community")
        self.assertEqual(listing["daily_messages"], 3)
        self.assertNotIn("active_members", listing)
        self.assertEqual(listing["global_rank"], 1)
        self.assertEqual(listing["tags"], ["Gaming", "Friendly"])
        self.assertIsNotNone(listing["approved_at"])

        self.database.set_public_stats_enabled("discovery-server", False)
        self.assertFalse(
            self.database.get_discovery_eligibility("discovery-server")["eligible"]
        )
        self.assertEqual(self.database.list_public_discovery_servers(), [])

    def test_discovery_banner_tracks_snapshot_updates_and_removal(self) -> None:
        self._make_discovery_ready_server()
        self.database.submit_discovery_application(
            "discovery-server", "moderator", "A community for games and conversation.",
            "", "https://stt.gg/community", ["gaming"],
        )
        self.database.review_discovery_application("discovery-server", "approved", "owner")
        audit = {"available": True, "permissions": [{"name": "manage_messages", "granted": True}]}
        for banner in ["https://cdn.stoatusercontent.com/banners/first", "https://cdn.stoatusercontent.com/banners/second", None]:
            self.database.update_dashboard_server_snapshot(
                "discovery-server", "Discovery Community", 125, [],
                server_icon_url="https://cdn.stoatusercontent.com/icons/icon",
                permission_audit=audit, server_banner_url=banner,
            )
            self.assertEqual(self.database.list_public_discovery_servers()[0]["server_banner_url"], banner)

    def test_denied_discovery_application_has_seven_day_cooldown(self) -> None:
        self._make_discovery_ready_server()
        self.database.submit_discovery_application(
            "discovery-server",
            "moderator",
            "A welcoming community for people who enjoy building things.",
            "",
            "https://stt.gg/discovery-community",
        )
        denied = self.database.review_discovery_application(
            "discovery-server", "denied", "owner", "Add more detail."
        )
        self.assertEqual(denied["application"]["status"], "denied")
        self.assertIsNotNone(denied["cooldown_until"])
        self.assertFalse(denied["can_apply"])
        with self.assertRaisesRegex(ValueError, "seven-day cooldown"):
            self.database.submit_discovery_application(
                "discovery-server",
                "moderator",
                "A more detailed community description for another review.",
                "",
                "https://stt.gg/discovery-community",
            )

    def test_editing_approved_discovery_content_requires_fresh_review(self) -> None:
        self._make_discovery_ready_server()
        description = "A welcoming community for people who enjoy building things."
        information = "Weekly events and beginner-friendly discussion."
        invite_url = "https://stt.gg/discovery-community"
        self.database.submit_discovery_application(
            "discovery-server", "moderator", description, information,
            invite_url, ["Friendly"],
        )
        self.database.review_discovery_application(
            "discovery-server", "approved", "owner"
        )

        unchanged = self.database.update_discovery_listing(
            "discovery-server", description, information, invite_url,
            ["Friendly"], "moderator",
        )
        self.assertEqual(unchanged["application"]["status"], "approved")

        updated = self.database.update_discovery_listing(
            "discovery-server",
            "An updated community description that needs another review.",
            information,
            invite_url,
            ["Friendly", "Events"],
            "second-moderator",
        )

        self.assertEqual(updated["application"]["status"], "pending")
        self.assertIsNone(updated["application"]["reviewed_at"])
        self.assertFalse(updated["can_bump"])
        self.assertEqual(self.database.list_public_discovery_servers(), [])
        self.database.review_discovery_application(
            "discovery-server", "approved", "owner"
        )
        self.assertEqual(
            self.database.list_public_discovery_servers()[0]["description"],
            "An updated community description that needs another review.",
        )

    def test_discovery_rejects_non_stoat_invites(self) -> None:
        self._make_discovery_ready_server()
        with self.assertRaisesRegex(ValueError, "valid HTTPS Stoat"):
            self.database.submit_discovery_application(
                "discovery-server",
                "moderator",
                "A welcoming community for people who enjoy building things.",
                "",
                "https://example.com/not-a-stoat-invite",
            )

    def test_discovery_allows_at_most_five_valid_tags(self) -> None:
        self._make_discovery_ready_server()
        with self.assertRaisesRegex(ValueError, "maximum of five tags"):
            self.database.submit_discovery_application(
                "discovery-server",
                "moderator",
                "A welcoming community for people who enjoy building things.",
                "",
                "https://stt.gg/discovery-community",
                ["Gaming", "Social", "Music", "Art", "Coding", "Events"],
            )
        with self.assertRaisesRegex(ValueError, "may only contain"):
            self.database.validate_discovery_tags(["not/a/tag"])

    def test_discovery_bump_has_two_hour_cooldown(self) -> None:
        self._make_discovery_ready_server()
        self._make_discovery_ready_server("other-discovery-server")
        self.database.submit_discovery_application(
            "discovery-server", "moderator",
            "A welcoming community for people who enjoy building things.", "",
            "https://stt.gg/discovery-community",
        )
        self.database.review_discovery_application(
            "discovery-server", "approved", "owner"
        )
        self.database.submit_discovery_application(
            "other-discovery-server", "other-moderator",
            "Another approved community with a public Discovery listing.", "",
            "https://stt.gg/other-community",
        )
        self.database.review_discovery_application(
            "other-discovery-server", "approved", "owner"
        )

        first = self.database.bump_discovery_server(
            "discovery-server", "moderator"
        )
        second = self.database.bump_discovery_server(
            "discovery-server", "moderator"
        )

        self.assertTrue(first["bumped"])
        self.assertFalse(second["bumped"])
        self.assertEqual(second["next_bump_at"], first["next_bump_at"])
        self.assertEqual(
            self.database.list_public_discovery_servers()[0]["server_id"],
            "discovery-server",
        )

    def test_owner_can_revoke_and_server_can_reapply(self) -> None:
        self._make_discovery_ready_server()
        self.database.submit_discovery_application(
            "discovery-server", "moderator",
            "A welcoming community for people who enjoy building things.", "",
            "https://stt.gg/discovery-community",
        )
        self.database.review_discovery_application(
            "discovery-server", "approved", "owner"
        )
        revoked = self.database.revoke_discovery_server(
            "discovery-server", "owner", "Invite no longer works."
        )

        self.assertEqual(revoked["application"]["status"], "revoked")
        self.assertEqual(
            revoked["application"]["revocation_note"], "Invite no longer works."
        )
        self.assertTrue(revoked["can_apply"])
        self.assertEqual(self.database.list_public_discovery_servers(), [])

        reapplied = self.database.submit_discovery_application(
            "discovery-server", "moderator",
            "A welcoming community for people who enjoy building things.", "",
            "https://stt.gg/new-community-invite",
        )
        self.assertEqual(reapplied["application"]["status"], "pending")
        self.assertFalse(reapplied["application"]["is_revoked"])

    def test_report_delivery_context_includes_server_and_usernames(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a", "Community Hub", 2, [], [], []
        )
        self.database.replace_dashboard_members("server-a", [
            {"user_id": "reporter-id", "username": "reporter-name"},
            {"user_id": "target-id", "username": "target-name"},
        ])

        self.assertEqual(
            self.database.get_report_delivery_context(
                "server-a", "reporter-id", "target-id"
            ),
            {
                "server_name": "Community Hub",
                "reporter_username": "reporter-name",
                "target_username": "target-name",
            },
        )

    def test_report_delivery_context_allows_missing_snapshots(self) -> None:
        self.assertEqual(
            self.database.get_report_delivery_context(
                "missing-server", "missing-reporter", "missing-target"
            ),
            {
                "server_name": None,
                "reporter_username": None,
                "target_username": None,
            },
        )

    def test_report_review_stores_note_and_atomically_queues_reporter_dm(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a", "Community Hub", 2, [], [], []
        )
        report_id = self.database.create_user_report(
            "server-a", "reporter-id", "target-id", "Harassment", "Evidence"
        )

        action_id = self.database.review_user_report(
            report_id,
            "resolved",
            "Thank you. The moderation team handled this report.",
            "owner-id",
        )

        self.assertIsInstance(action_id, int)
        report = self.database.get_owner_report(report_id)
        assert report is not None
        self.assertEqual(report["status"], "resolved")
        self.assertEqual(
            report["review_note"],
            "Thank you. The moderation team handled this report.",
        )
        self.assertEqual(report["reviewed_by"], "owner-id")
        self.assertIsNotNone(report["reviewed_at"])
        self.assertEqual(report["reporter_notification_status"], "pending")
        queued = self.database.claim_dashboard_actions()
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["id"], action_id)
        self.assertEqual(queued[0]["action"], "notify_report_outcome")
        self.assertEqual(queued[0]["payload"], {"report_id": report_id})

        self.assertTrue(
            self.database.mark_reporter_notification(report_id, success=True)
        )
        notified = self.database.get_owner_report(report_id)
        assert notified is not None
        self.assertEqual(notified["reporter_notification_status"], "sent")
        self.assertIsNotNone(notified["reporter_notified_at"])
        with self.assertRaisesRegex(ValueError, "already resolved"):
            self.database.review_user_report(
                report_id, "dismissed", "Changed decision", "owner-id"
            )
        self.assertIsNone(
            self.database.review_user_report(
                999999, "resolved", "Missing report", "owner-id"
            )
        )

    def test_report_notification_can_be_deferred_and_manually_retried(self) -> None:
        report_id = self.database.create_user_report(
            "server-a", "reporter-id", "target-id", "Spam", "Evidence"
        )
        action_id = self.database.review_user_report(
            report_id, "dismissed", "We could not verify this report.", "owner-id"
        )
        claimed = self.database.claim_dashboard_actions()
        self.assertEqual([item["id"] for item in claimed], [action_id])

        self.assertTrue(
            self.database.defer_report_notification_action(
                action_id,
                report_id,
                payload={"report_id": report_id, "retry_count": 1},
                delay_seconds=60,
                error="Delivery attempt 1 failed. Automatic retry is scheduled.",
            )
        )
        deferred = self.database.connection.execute(
            "SELECT status, payload_json, not_before FROM dashboard_actions WHERE id=?",
            (action_id,),
        ).fetchone()
        self.assertEqual(deferred["status"], "pending")
        self.assertEqual(
            json.loads(deferred["payload_json"]),
            {"report_id": report_id, "retry_count": 1},
        )
        self.assertIsNotNone(deferred["not_before"])
        report = self.database.get_owner_report(report_id)
        assert report is not None
        self.assertEqual(report["reporter_notification_status"], "pending")
        self.assertIn("retry", report["reporter_notification_error"].lower())
        self.assertEqual(self.database.claim_dashboard_actions(), [])

        self.database.connection.execute(
            "UPDATE dashboard_actions SET status='failed' WHERE id=?", (action_id,)
        )
        self.database.connection.commit()
        self.database.mark_reporter_notification(
            report_id, success=False, error="Direct messages are closed."
        )
        retry_action_id = self.database.retry_reporter_notification(
            report_id, "owner-id"
        )
        self.assertIsInstance(retry_action_id, int)
        retried = self.database.get_owner_report(report_id)
        assert retried is not None
        self.assertEqual(retried["reporter_notification_status"], "pending")
        self.assertIsNone(retried["reporter_notification_error"])
        with self.assertRaisesRegex(ValueError, "already queued"):
            self.database.retry_reporter_notification(report_id, "owner-id")

        self.database.mark_reporter_notification(report_id, success=True)
        with self.assertRaisesRegex(ValueError, "already been notified"):
            self.database.retry_reporter_notification(report_id, "owner-id")
        self.assertIsNone(
            self.database.retry_reporter_notification(999999, "owner-id")
        )

    def test_existing_reports_gain_review_and_notification_fields(self) -> None:
        legacy_path = Path(self.directory.name, "legacy-reports.db")
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            """
            CREATE TABLE user_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                reporter_id TEXT NOT NULL,
                target_user_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                evidence TEXT,
                network_risk_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO user_reports(
                server_id, reporter_id, target_user_id, reason, evidence,
                network_risk_json, status, created_at
            ) VALUES ('server-a', 'reporter', 'target', 'Reason', 'Evidence',
                      '{}', 'pending', '2026-08-26T12:00:00+00:00')
            """
        )
        connection.commit()
        connection.close()

        migrated = ModerationDatabase(legacy_path)
        try:
            report = migrated.get_owner_report(1)
            assert report is not None
            self.assertEqual(report["review_note"], "")
            self.assertIsNone(report["reviewed_at"])
            self.assertEqual(
                report["reporter_notification_status"], "not_requested"
            )
            self.assertRegex(
                report["reference_id"], r"^[A-HJ-NP-Z2-9]{8}$"
            )
            index_columns = [
                row["name"]
                for row in migrated.connection.execute(
                    "PRAGMA index_info(idx_user_reports_server_reference)"
                ).fetchall()
            ]
            self.assertEqual(index_columns, ["server_id", "reference_id"])
        finally:
            migrated.close()

    def test_report_references_are_randomized_and_unique_within_each_server(self) -> None:
        first_id = self.database.create_user_report(
            "server-a", "reporter", "target", "First reason", "Evidence"
        )
        second_id = self.database.create_user_report(
            "server-a", "reporter", "target", "Second reason", "Evidence"
        )
        other_server_id = self.database.create_user_report(
            "server-b", "reporter", "target", "Third reason", "Evidence"
        )

        references = [
            self.database.get_report_for_notification(report_id)["reference_id"]
            for report_id in (first_id, second_id, other_server_id)
        ]
        for reference in references:
            self.assertRegex(reference, r"^[A-HJ-NP-Z2-9]{8}$")
        self.assertNotEqual(references[0], references[1])
        self.assertNotEqual(references[0], str(first_id))

    def test_server_report_review_queues_outcome_dm_and_uses_server_event_names(self) -> None:
        report_id = self.database.create_user_report(
            "server-a",
            "reporter",
            "target",
            "Server rule violation",
            "Evidence",
            report_scope="local",
        )
        report = self.database.get_local_report("server-a", report_id)
        assert report is not None
        self.assertRegex(report["reference_id"], r"^[A-HJ-NP-Z2-9]{8}$")
        events = self.database.list_dashboard_events("server-a")
        self.assertEqual(events[0]["event_type"], "server_report_submitted")

        action_id = self.database.review_local_report(
            "server-a", report_id, "resolved", "Handled by server staff.", "moderator"
        )

        self.assertIsInstance(action_id, int)
        reviewed = self.database.get_local_report("server-a", report_id)
        assert reviewed is not None
        self.assertEqual(reviewed["reporter_notification_status"], "pending")
        queued = self.database.claim_dashboard_actions()
        self.assertEqual(queued[0]["action"], "notify_report_outcome")
        self.assertEqual(queued[0]["payload"], {"report_id": report_id})

    def test_existing_dashboard_snapshots_gain_optional_server_icon(self) -> None:
        legacy_path = Path(self.directory.name, "legacy-dashboard.db")
        connection = sqlite3.connect(legacy_path)
        connection.execute(
            """
            CREATE TABLE dashboard_server_snapshots (
                server_id TEXT PRIMARY KEY,
                server_name TEXT NOT NULL,
                member_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO dashboard_server_snapshots VALUES (?, ?, ?, ?)",
            ("legacy-server", "Legacy server", 7, "2026-08-11T00:00:00+00:00"),
        )
        connection.commit()
        connection.close()

        legacy_database = ModerationDatabase(legacy_path)
        try:
            columns = {
                row["name"]
                for row in legacy_database.connection.execute(
                    "PRAGMA table_info(dashboard_server_snapshots)"
                ).fetchall()
            }
            self.assertIn("server_icon_url", columns)
            self.assertIn("server_banner_url", columns)
            self.assertIsNone(legacy_database.connection.execute(
                "SELECT server_banner_url FROM dashboard_server_snapshots WHERE server_id=?",
                ("legacy-server",),
            ).fetchone()[0])
            self.assertIsNone(
                legacy_database.get_dashboard_overview("legacy-server")["server"][
                    "icon_url"
                ]
            )
        finally:
            legacy_database.close()

    def test_log_channel_is_persistent_per_server(self) -> None:
        self.assertIsNone(self.database.get_log_channel("server-a"))

        self.database.set_log_channel("server-a", "channel-a")

        self.assertEqual(self.database.get_log_channel("server-a"), "channel-a")
        self.assertIsNone(self.database.get_log_channel("server-b"))

    def test_server_locale_defaults_to_english_and_is_server_scoped(self) -> None:
        self.assertEqual(self.database.get_server_locale("server-a"), "en")

        self.database.set_server_locale("server-a", "fr")

        self.assertEqual(self.database.get_server_locale("server-a"), "fr")
        self.assertEqual(self.database.get_server_locale("server-b"), "en")
        self.assertEqual(
            self.database.get_dashboard_settings("server-a")["locale"], "fr"
        )
        with self.assertRaises(ValueError):
            self.database.set_server_locale("server-a", "de")

    def test_moderation_threshold_is_server_scoped_and_resettable(self) -> None:
        self.assertEqual(
            self.database.get_moderation_threshold("server-a", 0.9), 0.9
        )

        self.database.set_moderation_threshold("server-a", 0.925)

        self.assertEqual(
            self.database.get_moderation_threshold("server-a", 0.9), 0.925
        )
        self.assertEqual(
            self.database.get_moderation_threshold("server-b", 0.9), 0.9
        )
        self.assertTrue(self.database.reset_moderation_threshold("server-a"))
        self.assertEqual(
            self.database.get_moderation_threshold("server-a", 0.9), 0.9
        )
        self.assertFalse(self.database.reset_moderation_threshold("server-a"))

        with self.assertRaises(ValueError):
            self.database.set_moderation_threshold("server-a", 1.01)

    def test_server_announcement_is_recorded_once(self) -> None:
        self.assertFalse(self.database.has_server_announcement("server-a"))

        self.database.record_server_announcement("server-a", "channel-a")
        self.database.record_server_announcement("server-a", "channel-b")

        self.assertTrue(self.database.has_server_announcement("server-a"))
        row = self.database.connection.execute(
            "SELECT channel_id FROM server_announcements WHERE server_id=?",
            ("server-a",),
        ).fetchone()
        self.assertEqual(row["channel_id"], "channel-a")

    def test_permission_notices_are_persistent_and_unique_per_permission(self) -> None:
        self.assertEqual(
            self.database.list_server_permission_notices("server-a"), set()
        )

        self.database.record_server_permission_notices(
            "server-a", ["manage_messages", "kick_members"], "channel-a"
        )
        self.database.record_server_permission_notices(
            "server-a", ["manage_messages"], "channel-b"
        )

        self.assertEqual(
            self.database.list_server_permission_notices("server-a"),
            {"manage_messages", "kick_members"},
        )
        rows = self.database.connection.execute(
            """
            SELECT permission_name, channel_id FROM server_permission_notices
            WHERE server_id=? ORDER BY permission_name
            """,
            ("server-a",),
        ).fetchall()
        self.assertEqual(
            [(row["permission_name"], row["channel_id"]) for row in rows],
            [("kick_members", "channel-a"), ("manage_messages", "channel-a")],
        )

    def test_permission_notice_cooldown_can_refresh_after_twenty_four_hours(self) -> None:
        self.database.record_server_permission_notices(
            "server-a", ["ban_members"], "channel-a"
        )
        self.assertEqual(
            self.database.list_server_permission_notices(
                "server-a", within_seconds=86_400
            ),
            {"ban_members"},
        )
        self.database.connection.execute(
            "UPDATE server_permission_notices SET notified_at='2000-01-01T00:00:00+00:00' WHERE server_id='server-a'"
        )
        self.database.connection.commit()
        self.assertEqual(
            self.database.list_server_permission_notices(
                "server-a", within_seconds=86_400
            ),
            set(),
        )
        self.database.record_server_permission_notices(
            "server-a", ["ban_members"], "channel-b", refresh_existing=True
        )
        row = self.database.connection.execute(
            "SELECT channel_id FROM server_permission_notices WHERE server_id='server-a' AND permission_name='ban_members'"
        ).fetchone()
        self.assertEqual(row["channel_id"], "channel-b")

    def test_warning_policy_defaults_can_be_changed_and_reset(self) -> None:
        default = self.database.get_warning_policy("server-a")
        self.assertEqual(
            (default.timeout_count, default.kick_count, default.ban_count),
            (3, 5, 7),
        )

        changed = self.database.set_warning_policy("server-a", 2, 4, 6)
        self.assertEqual(
            (changed.timeout_count, changed.kick_count, changed.ban_count),
            (2, 4, 6),
        )
        self.assertEqual(self.database.get_log_channel("server-a"), None)

        reset = self.database.reset_warning_policy("server-a")
        self.assertEqual(
            (reset.timeout_count, reset.kick_count, reset.ban_count),
            (3, 5, 7),
        )

    def test_adjustable_penalty_rules_support_multiple_timeout_durations(self) -> None:
        rules = self.database.set_penalty_rules("server-a", [
            {"threshold": 2, "action": "timeout", "duration_seconds": 600},
            {"threshold": 4, "action": "timeout", "duration_seconds": 86400},
            {"threshold": 6, "action": "kick"},
            {"threshold": 8, "action": "ban"},
        ])
        self.assertEqual(
            [(rule.threshold, rule.action, rule.duration_seconds) for rule in rules],
            [(2, "timeout", 600), (4, "timeout", 86400), (6, "kick", None), (8, "ban", None)],
        )
        self.database.set_warning_policy("server-a", 3, 5, 7)
        self.assertEqual(
            [(rule.threshold, rule.action) for rule in self.database.list_penalty_rules("server-a")],
            [(3, "timeout"), (5, "kick"), (7, "ban")],
        )

    def test_dashboard_automations_can_be_created_toggled_and_deleted(self) -> None:
        rule = self.database.create_automation_rule(
            "server-a", "Keyword cleanup", "keyword", "spoiler", "delete_message", {}, "mod",
            [{"type": "username_contains", "value": "guest"}], "all",
        )
        self.assertTrue(rule["enabled"])
        self.assertEqual(rule["conditions"], [{"type": "username_contains", "value": "guest"}])
        self.assertTrue(self.database.update_automation_rule(
            "server-a", rule["id"], {"enabled": False}
        ))
        self.assertFalse(self.database.list_automation_rules("server-a")[0]["enabled"])
        self.assertTrue(self.database.delete_automation_rule("server-a", rule["id"]))

    def test_poll_votes_are_single_choice_and_removable(self) -> None:
        poll_id = self.database.create_poll(
            "server-a", "channel", "Choose", [
                {"emoji": "1️⃣", "label": "One"},
                {"emoji": "2️⃣", "label": "Two"},
            ], "mod",
        )
        self.database.set_poll_message(poll_id, "message")
        self.assertTrue(self.database.record_poll_vote("message", "user", "1️⃣"))
        rejected = self.database.record_poll_vote("message", "user", "2️⃣")
        self.assertEqual(rejected["reason"], "single_choice_limit")
        self.assertEqual(self.database.list_polls("server-a")[0]["votes"], {"user": ["1️⃣"]})
        self.assertTrue(self.database.record_poll_vote("message", "user", "1️⃣", remove=True))

    def test_poll_listing_supports_count_and_page_offsets(self) -> None:
        poll_ids = [
            self.database.create_poll(
                "server-a",
                "channel",
                f"Question {index}",
                [
                    {"emoji": "1️⃣", "label": "One"},
                    {"emoji": "2️⃣", "label": "Two"},
                ],
                "mod",
            )
            for index in range(8)
        ]

        self.assertEqual(self.database.count_polls("server-a"), 8)
        first_page = self.database.list_polls("server-a", limit=3, offset=0)
        second_page = self.database.list_polls("server-a", limit=3, offset=3)
        self.assertEqual([poll["id"] for poll in first_page], poll_ids[-1:-4:-1])
        self.assertEqual([poll["id"] for poll in second_page], poll_ids[-4:-7:-1])
        self.assertFalse(
            {poll["id"] for poll in first_page}
            & {poll["id"] for poll in second_page}
        )

    def test_multiple_choice_poll_and_schedule_are_persistent(self) -> None:
        poll_id = self.database.create_poll(
            "server-a", "channel", "Choose several", [
                {"emoji": "🍎", "label": "Apple"},
                {"emoji": "🍐", "label": "Pear"},
            ], "mod", "2099-01-02T00:00:00+00:00",
            multiple_choice=True, scheduled_for="2099-01-01T00:00:00+00:00",
        )
        self.database.set_poll_message(poll_id, "multi-message")
        self.assertTrue(self.database.record_poll_vote("multi-message", "user", "🍎"))
        self.assertTrue(self.database.record_poll_vote("multi-message", "user", "🍐"))
        poll = self.database.get_poll(poll_id)
        self.assertTrue(poll["multiple_choice"])
        self.assertEqual(poll["votes"], {"user": ["🍎", "🍐"]})

        self.database.enqueue_dashboard_action(
            "server-a", "publish_poll", "mod", {"poll_id": poll_id},
            not_before="2099-01-01T00:00:00+00:00",
        )
        self.assertEqual(self.database.claim_dashboard_actions(), [])
        self.database.enqueue_dashboard_action(
            "server-a", "close_poll", "mod", {"poll_id": poll_id},
            not_before="2000-01-01T00:00:00+00:00",
        )
        self.assertEqual(self.database.claim_dashboard_actions()[0]["action"], "close_poll")

    def test_join_protection_and_captcha_challenges_are_persistent(self) -> None:
        self.assertFalse(self.database.get_join_protection("server-a"))
        self.database.set_join_protection("server-a", False)
        self.assertFalse(self.database.get_join_protection("server-a"))
        self.database.set_join_protection("server-a", True)
        self.assertTrue(self.database.get_join_protection("server-a"))

        challenge = self.database.set_captcha_challenge(
            "server-a",
            "user-a",
            "answer-hash",
            "salt",
            "2026-08-05T12:30:00+00:00",
        )
        self.assertEqual(
            self.database.get_captcha_challenge("server-a", "user-a"),
            challenge,
        )
        self.assertEqual(
            self.database.list_captcha_challenges("user-a"), [challenge]
        )
        self.assertTrue(
            self.database.remove_captcha_challenge("server-a", "user-a")
        )
        self.assertFalse(
            self.database.remove_captcha_challenge("server-a", "user-a")
        )

    def test_join_protection_disable_survives_restart(self) -> None:
        self.database.set_join_protection("server-a", False)
        database_path = self.database.path
        self.database.close()

        self.database = ModerationDatabase(database_path)

        self.assertFalse(self.database.get_join_protection("server-a"))

    def test_captcha_failures_increment_and_reset_for_new_challenge(self) -> None:
        self.database.set_web_verification_challenge(
            "server-a", "user-a", "token-one", "2099-01-01T00:00:00+00:00"
        )
        self.assertEqual(
            self.database.increment_captcha_failure("server-a", "user-a"), 1
        )
        self.assertEqual(
            self.database.increment_captcha_failure("server-a", "user-a"), 2
        )
        self.database.set_web_verification_challenge(
            "server-a", "user-a", "token-two", "2099-01-01T00:00:00+00:00"
        )
        self.assertEqual(
            self.database.get_captcha_challenge("server-a", "user-a").failure_count,
            0,
        )

    def test_captcha_challenge_issuance_is_matched_to_current_challenge(self) -> None:
        challenge = self.database.set_web_verification_challenge(
            "server-a", "user-a", "token", "2099-01-01T00:00:00+00:00"
        )

        self.assertFalse(
            self.database.captcha_challenge_was_issued(
                "server-a", "user-a", since=challenge.created_at
            )
        )

        self.database.add_event(
            server_id="server-a",
            event_type="join_captcha_issued",
            user_id="user-a",
        )

        self.assertTrue(
            self.database.captcha_challenge_was_issued(
                "server-a", "user-a", since=challenge.created_at
            )
        )

    def test_dashboard_snapshot_exposes_roles_and_exempt_channels(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a",
            "Server A",
            12,
            [("channel-a", "general", "category-a"), ("channel-b", "staff", None)],
            [("role-a", "Members"), ("role-b", "Verified")],
            [("category-a", "Public")],
            "https://cdn.example/server-a.png",
            owner_id="owner-a",
            bot_joined_at="2025-06-01T10:00:00+00:00",
        )
        self.database.upsert_dashboard_member("server-a", {
            "user_id": "owner-a",
            "username": "server.owner",
            "discriminator": "0042",
            "display_name": "Server Owner",
        })
        self.database.exclude_scope(
            "server-a", "channel-b", "channel", "moderator"
        )
        self.database.exclude_scope(
            "server-a", "category-a", "category", "moderator"
        )

        settings = self.database.get_dashboard_settings("server-a")

        self.assertEqual(settings["exempt_channels"], ["channel-b"])
        self.assertEqual(settings["exempt_categories"], ["category-a"])
        self.assertIn("hateful-conduct", settings["moderation_categories"])
        self.assertEqual(settings["disabled_moderation_categories"], [])
        self.assertIn("credentials", settings["protected_moderation_categories"])
        self.assertIn("suicidal-thoughts", settings["protected_moderation_categories"])
        self.assertEqual(
            settings["categories"],
            [{"category_id": "category-a", "category_name": "Public"}],
        )
        self.assertEqual(settings["channels"][0]["category_id"], "category-a")
        self.assertEqual(
            settings["roles"],
            [
                {
                    "role_id": "role-a",
                    "role_name": "Members",
                    "assignable": None,
                },
                {
                    "role_id": "role-b",
                    "role_name": "Verified",
                    "assignable": None,
                },
            ],
        )
        self.assertEqual(
            self.database.get_dashboard_overview("server-a")["server"]["icon_url"],
            "https://cdn.example/server-a.png",
        )
        self.assertEqual(
            self.database.list_owner_servers()[0]["server_icon_url"],
            "https://cdn.example/server-a.png",
        )
        self.assertFalse(
            self.database.list_owner_servers()[0]["has_permissions"]
        )
        owner_server = self.database.list_owner_servers()[0]
        self.assertEqual(owner_server["owner_id"], "owner-a")
        self.assertEqual(owner_server["owner_username"], "server.owner#0042")
        self.assertEqual(
            owner_server["bot_joined_at"], "2025-06-01T10:00:00+00:00"
        )

        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="moderator-a",
            source="manual",
            reason="Test case",
        )
        self.assertGreater(warning_id, 0)
        self.assertEqual(
            self.database.list_owner_cases()[0]["server_icon_url"],
            "https://cdn.example/server-a.png",
        )

    def test_server_blacklist_is_persistent_and_queues_departure_atomically(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-blocked",
            "Blocked Community",
            20,
            [],
            [],
            [],
            owner_id="owner-blocked",
        )

        blacklist, action_id = self.database.blacklist_server(
            "server-blocked", "Repeated safety violations", "admin-user"
        )

        self.assertEqual(blacklist["server_name"], "Blocked Community")
        self.assertEqual(blacklist["owner_id"], "owner-blocked")
        self.assertEqual(blacklist["reason"], "Repeated safety violations")
        self.assertEqual(blacklist["blacklisted_by"], "admin-user")
        action = self.database.get_dashboard_action(action_id)
        self.assertIsNotNone(action)
        self.assertEqual(action["action"], "blacklist_server")
        self.assertEqual(action["actor_id"], "admin-user")
        self.assertEqual(action["payload"]["reason"], "Repeated safety violations")

        with self.assertRaisesRegex(ValueError, "already blacklisted"):
            self.database.blacklist_server(
                "server-blocked", "A second reason", "another-admin"
            )

        same_blacklist, same_action_id = self.database.blacklist_server(
            "server-blocked", "Repeated safety violations", "admin-user"
        )
        self.assertEqual(same_action_id, action_id)
        self.assertEqual(same_blacklist["created_at"], blacklist["created_at"])

        self.database.connection.execute(
            "UPDATE dashboard_actions SET status='processing' WHERE id=?",
            (action_id,),
        )
        self.database.connection.commit()
        self.assertTrue(
            self.database.finish_dashboard_action(
                action_id,
                success=False,
                result={"error": "Stoat was temporarily unavailable."},
            )
        )
        retried_blacklist, retry_action_id = self.database.blacklist_server(
            "server-blocked", "Updated safety reason", "admin-user"
        )
        self.assertNotEqual(retry_action_id, action_id)
        self.assertEqual(retried_blacklist["created_at"], blacklist["created_at"])
        self.assertEqual(retried_blacklist["reason"], "Updated safety reason")
        self.assertEqual(
            self.database.get_dashboard_action(retry_action_id)["status"], "pending"
        )

        self.database.purge_server_data("server-blocked")
        preserved_action = self.database.get_dashboard_action(action_id)
        self.assertIsNotNone(preserved_action)
        self.assertEqual(preserved_action["action"], "blacklist_server")
        self.assertIsNotNone(self.database.get_dashboard_action(retry_action_id))
        self.assertIsNotNone(self.database.get_server_blacklist("server-blocked"))
        deletion = self.database.delete_privacy_data("server-blocked")
        self.assertIn(
            "server_blacklist",
            {item["table"] for item in deletion["retained_tables"]},
        )
        self.assertIn(
            "dashboard_actions",
            {item["table"] for item in deletion["retained_tables"]},
        )
        self.assertIsNotNone(self.database.get_dashboard_action(action_id))
        self.assertIsNotNone(self.database.get_dashboard_action(retry_action_id))
        self.assertIsNotNone(self.database.get_server_blacklist("server-blocked"))

    def test_server_blacklist_rejects_missing_snapshot_and_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 3 and 1,000"):
            self.database.blacklist_server("server", " ", "admin")
        with self.assertRaisesRegex(ValueError, "not found"):
            self.database.blacklist_server("missing", "Safety issue", "admin")

    def test_ready_reconciliation_removes_servers_no_longer_connected(self) -> None:
        for server_id in ("server-a", "server-b"):
            self.database.update_dashboard_server_snapshot(
                server_id, server_id.title(), 10, [], [], []
            )

        removed = self.database.reconcile_dashboard_server_snapshots({"server-b"})

        self.assertEqual(removed, ["server-a"])
        self.assertEqual(self.database.get_public_dashboard_stats()["server_count"], 1)
        self.assertEqual(
            [server["server_id"] for server in self.database.list_owner_servers()],
            ["server-b"],
        )

    def test_departed_server_purge_removes_all_server_owned_data(self) -> None:
        today = self.database.connection.execute(
            "SELECT date('now') AS value"
        ).fetchone()["value"]
        for server_id in ("server-a", "server-b"):
            self.database.update_dashboard_server_snapshot(
                server_id, server_id.title(), 10, [], [], []
            )
            self.database.record_daily_message(server_id, "user", today)
        self.database.replace_dashboard_members(
            "server-a", [{"user_id": "user", "username": "Member"}]
        )
        self.database.set_link_protection("server-a", True)
        self.database.create_dashboard_login_code(
            "code-a", "server-a", "user", "2099-01-01T00:00:00+00:00"
        )
        self.database.create_dashboard_session(
            "session-a", "server-a", "user", "2099-01-01T00:00:00+00:00"
        )
        report_id = self.database.create_user_report(
            "server-a", "reporter", "target", "Reason", "Evidence"
        )
        self.database.add_report_attachment(
            report_id, "evidence.txt", "text/plain", b"evidence"
        )
        self.database.create_automation_rule(
            "server-a", "Cleanup", "every_message", None,
            "delete_message", {}, "moderator"
        )
        self.database.create_poll(
            "server-a", "channel", "Choose", [
                {"emoji": "1", "label": "One"},
                {"emoji": "2", "label": "Two"},
            ], "moderator"
        )
        self.database.add_warning(
            server_id="server-a", user_id="user", moderator_id="moderator",
            source="manual", reason="Warning",
        )
        self.database.add_event(
            server_id="server-a", event_type="member_kicked", user_id="user",
            actor_id="moderator", details={"reason": "Test"},
        )
        case = self.database.list_dashboard_cases("server-a")[0]
        self.database.create_appeal_access(
            "appeal-a", "user", "moderation", case["reference_id"], "server-a"
        )

        deleted = self.database.purge_server_data("server-a")

        self.assertIn("dashboard_server_snapshots", deleted)
        self.assertIn("server_daily_stats", deleted)
        self.assertIn("moderation_cases", deleted)
        self.assertIn("user_reports", deleted)
        tables = self.database.connection.execute(
            """
            SELECT name FROM sqlite_schema
            WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        for table_row in tables:
            table = table_row["name"]
            columns = {
                row["name"] for row in self.database.connection.execute(
                    f'PRAGMA table_info("{table}")'
                ).fetchall()
            }
            if "server_id" in columns:
                remaining = self.database.connection.execute(
                    f'SELECT COUNT(*) AS count FROM "{table}" WHERE server_id=?',
                    ("server-a",),
                ).fetchone()["count"]
                self.assertEqual(remaining, 0, table)
        self.assertEqual(
            self.database.connection.execute(
                "SELECT COUNT(*) AS count FROM user_report_attachments WHERE report_id=?",
                (report_id,),
            ).fetchone()["count"],
            0,
        )
        self.assertEqual(
            [item["server_id"] for item in self.database.get_global_leaderboard("members")],
            ["server-b"],
        )
        self.assertEqual(
            self.database.get_public_dashboard_stats()["server_count"], 1
        )

    def test_owner_permission_status_uses_roles_not_channel_overrides(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a",
            "Server A",
            10,
            [],
            [],
            [],
            permission_audit={
                "available": True,
                "missing_count": 0,
                "permissions": [
                    {"name": "ban_members", "granted": True},
                    {"name": "kick_members", "granted": True},
                ],
                "inaccessible_channels": ["private-channel"],
                "log_channel": {
                    "configured": True,
                    "accessible": False,
                    "missing": ["Send Messages"],
                },
            },
        )

        self.assertTrue(
            self.database.list_owner_servers()[0]["has_permissions"]
        )

    def test_unavailable_restart_audit_preserves_last_valid_permissions(self) -> None:
        valid_audit = {
            "available": True,
            "permissions": [{"name": "ban_members", "granted": True}],
            "missing_count": 0,
        }
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 10, [], [], [],
            permission_audit=valid_audit,
        )

        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 10, [], [], [],
            permission_audit={
                "available": False,
                "permissions": [],
                "missing_count": 0,
            },
        )

        self.assertTrue(
            self.database.list_owner_servers()[0]["has_permissions"]
        )

    def test_auto_roles_are_server_scoped_persistent_and_removable(self) -> None:
        self.assertEqual(self.database.list_auto_roles("server-a"), [])
        self.assertTrue(
            self.database.add_auto_role("server-a", "role-a", "moderator")
        )
        self.assertFalse(
            self.database.add_auto_role("server-a", "role-a", "moderator")
        )
        self.assertTrue(
            self.database.add_auto_role("server-a", "role-b", "moderator")
        )
        self.assertEqual(
            self.database.list_auto_roles("server-a"), ["role-a", "role-b"]
        )
        self.assertEqual(self.database.list_auto_roles("server-b"), [])

        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        self.assertEqual(
            self.database.list_auto_roles("server-a"), ["role-a", "role-b"]
        )
        self.assertTrue(self.database.remove_auto_role("server-a", "role-a"))
        self.assertFalse(self.database.remove_auto_role("server-a", "role-a"))
        self.assertEqual(self.database.clear_auto_roles("server-a"), 1)
        self.assertEqual(self.database.list_auto_roles("server-a"), [])

    def test_dashboard_roles_include_assignability_for_auto_role_validation(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a",
            "Server A",
            10,
            [],
            [
                ("assignable-role", "Members", True),
                ("blocked-role", "Administrators", False),
                ("unknown-role", "Unknown hierarchy", None),
            ],
            [],
        )

        roles = {
            role["role_id"]: role
            for role in self.database.get_dashboard_settings("server-a")["roles"]
        }

        self.assertIs(roles["assignable-role"]["assignable"], True)
        self.assertIs(roles["blocked-role"]["assignable"], False)
        self.assertIsNone(roles["unknown-role"]["assignable"])

    def test_dashboard_codes_are_single_use_and_sessions_expire(self) -> None:
        self.database.create_dashboard_login_code(
            "code-hash",
            "server-a",
            "moderator-a",
            "2099-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            self.database.consume_dashboard_login_code("code-hash"),
            ("server-a", "moderator-a"),
        )
        self.assertIsNone(
            self.database.consume_dashboard_login_code("code-hash")
        )

        self.database.create_dashboard_session(
            "session-hash",
            "server-a",
            "moderator-a",
            "2099-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            self.database.get_dashboard_session("session-hash"),
            ("server-a", "moderator-a"),
        )
        self.assertTrue(
            self.database.remove_dashboard_session("session-hash")
        )
        self.assertIsNone(
            self.database.get_dashboard_session("session-hash")
        )

    def test_manage_server_grants_dashboard_access_until_owner_revokes_it(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 2, [], owner_id="owner-a"
        )
        self.database.replace_dashboard_members(
            "server-a",
            [
                {
                    "user_id": "manager-a",
                    "username": "manager",
                    "manage_server": True,
                },
                {
                    "user_id": "member-a",
                    "username": "member",
                    "manage_server": False,
                },
            ],
        )

        self.assertTrue(
            self.database.dashboard_user_has_access("server-a", "owner-a")
        )
        self.assertTrue(
            self.database.dashboard_user_has_access("server-a", "manager-a")
        )
        self.assertFalse(
            self.database.dashboard_user_has_access("server-a", "member-a")
        )
        self.assertEqual(
            self.database.list_dashboard_access("server-a")["users"][1]["access_source"],
            "manage_server",
        )

        self.assertTrue(
            self.database.revoke_dashboard_access(
                "server-a", "manager-a", "owner-a"
            )
        )
        self.assertFalse(
            self.database.dashboard_user_has_access(
                "server-a", "manager-a", manage_server=True
            )
        )
        access = self.database.list_dashboard_access("server-a")
        self.assertEqual(access["revoked_users"][0]["user_id"], "manager-a")
        self.assertTrue(access["revoked_users"][0]["manage_server"])

        self.assertTrue(
            self.database.restore_dashboard_access("server-a", "manager-a")
        )
        self.assertTrue(
            self.database.dashboard_user_has_access("server-a", "manager-a")
        )
        self.assertTrue(
            self.database.grant_dashboard_access(
                "server-a", "member-a", "owner-a"
            )
        )
        self.assertTrue(
            self.database.dashboard_user_has_access("server-a", "member-a")
        )

    def test_dashboard_daily_statistics_store_only_aggregate_counts(self) -> None:
        self.database.record_daily_message(
            "server-a", "user-a", "2026-08-11"
        )
        self.database.record_daily_message(
            "server-a", "user-a", "2026-08-11"
        )
        self.database.record_daily_message(
            "server-a", "user-b", "2026-08-11"
        )
        self.database.record_daily_member_change(
            "server-a", "join", "2026-08-11"
        )
        self.database.record_daily_member_change(
            "server-a", "leave", "2026-08-11"
        )
        row = self.database.connection.execute(
            """
            SELECT s.message_count, s.new_joins, s.new_leaves,
                   COUNT(a.user_id) AS active_users
            FROM server_daily_stats AS s
            LEFT JOIN server_daily_active_users AS a
              ON a.server_id=s.server_id AND a.stat_date=s.stat_date
            WHERE s.server_id=? AND s.stat_date=?
            GROUP BY s.server_id, s.stat_date
            """,
            ("server-a", "2026-08-11"),
        ).fetchone()
        self.assertEqual(
            (row["message_count"], row["active_users"], row["new_joins"], row["new_leaves"]),
            (3, 0, 1, 1),
        )

    def test_activity_insights_do_not_store_or_expose_individual_activity(self) -> None:
        today = self.database.connection.execute(
            "SELECT date('now') AS value"
        ).fetchone()["value"]
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 20,
            [("general", "general"), ("support", "support")], [], [],
        )
        self.database.record_daily_message(
            "server-a", "user-a", today,
            channel_id="general",
            content="Stoat moderation moderation community the https://example.com/private",
        )
        self.database.record_daily_message(
            "server-a", "user-b", today,
            channel_id="general",
            content="Community moderation is useful",
        )
        self.database.record_daily_message(
            "server-a", "user-a", today,
            channel_id="support",
            content="Support community support",
        )

        overview = self.database.get_dashboard_overview("server-a")
        insights = overview["insights"]
        self.assertEqual(insights["messages"], 3)
        self.assertEqual(set(insights), {"period_days", "messages", "joins", "leaves", "net_growth"})
        for table in ("server_daily_active_users", "server_daily_user_stats", "server_daily_channel_stats", "server_daily_word_stats"):
            with self.subTest(table=table):
                self.assertEqual(self.database.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
        self.assertNotIn("active_users", overview["today"])
        self.assertTrue(all("active_users" not in row for row in overview["daily"]))
        self.assertEqual(self.database.get_activity_insights(days=7), insights)
        owner = self.database.get_owner_dashboard_summary()
        self.assertNotIn("active_channels_today", owner)
        self.assertNotIn("active_users_today", owner)

    def test_startup_erases_legacy_identifying_statistics_and_preserves_totals(self) -> None:
        self.database.record_daily_message("server-a", stat_date="2026-10-01")
        for table, column in (("server_daily_active_users", "user_id"), ("server_daily_user_stats", "user_id"), ("server_daily_channel_stats", "channel_id"), ("server_daily_word_stats", "word")):
            self.database.connection.execute(
                f"INSERT INTO {table}(server_id, stat_date, {column}) VALUES (?, ?, ?)",
                ("server-a", "2026-10-01", "private-statistics-canary"),
            )
        self.database.connection.commit()
        path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(path)
        for table in ("server_daily_active_users", "server_daily_user_stats", "server_daily_channel_stats", "server_daily_word_stats"):
            self.assertEqual(self.database.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
        self.assertEqual(self.database.connection.execute("SELECT message_count FROM server_daily_stats WHERE server_id='server-a'").fetchone()[0], 1)

    def test_global_leaderboards_support_filters(self) -> None:
        today = self.database.connection.execute("SELECT date('now') AS value").fetchone()["value"]
        self.database.update_dashboard_server_snapshot("server-a", "Server A", 20, [], [], [])
        self.database.update_dashboard_server_snapshot("server-b", "Server B", 50, [], [], [])
        self.database.replace_dashboard_members("server-a", [{
            "user_id": "user-a", "username": "Alice",
            "avatar_url": "https://cdn.example/alice.png",
        }])
        for _ in range(3):
            self.database.record_daily_message("server-a", "user-a", today)
        self.database.record_daily_message("server-a", "user-b", today)
        self.database.record_daily_message("server-b", "user-c", today)
        self.assertEqual(
            self.database.get_global_leaderboard("activity", "day")[0]["server_id"],
            "server-a",
        )
        self.assertEqual(
            self.database.get_global_leaderboard("members")[0]["server_id"],
            "server-b",
        )

    def test_public_stats_opt_out_filters_totals_and_rankings(self) -> None:
        permissions_ready = {
            "available": True,
            "permissions": [{"name": "manage_messages", "granted": True}],
        }
        today = self.database.connection.execute(
            "SELECT date('now') AS value"
        ).fetchone()["value"]
        yesterday = self.database.connection.execute(
            "SELECT date('now', '-1 day') AS value"
        ).fetchone()["value"]
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 100, [], [], [], "https://cdn.example/a.png",
            permissions_ready,
        )
        self.database.update_dashboard_server_snapshot(
            "server-b", "Server B", 50, [], [], [], "https://cdn.example/b.png",
            permissions_ready,
        )
        for _ in range(3):
            self.database.record_daily_message("server-b", "user-b", yesterday)
            self.database.record_daily_message("server-a", "user-a", today)
        self.database.record_daily_message("server-a", "user-a", yesterday)
        self.database.record_daily_message("server-b", "user-b", today)

        activity = self.database.get_global_leaderboard("activity", "day")
        self.assertEqual(activity[0]["server_id"], "server-a")
        self.assertEqual(activity[0]["rank_change"], 1)
        self.assertEqual(activity[1]["rank_change"], -1)

        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 40, [], [], [], "https://cdn.example/a.png",
            permissions_ready,
        )
        self.database.update_dashboard_server_snapshot(
            "server-b", "Server B", 60, [], [], [], "https://cdn.example/b.png",
            permissions_ready,
        )
        members = self.database.get_global_leaderboard("members")
        self.assertEqual(members[0]["server_id"], "server-b")
        self.assertEqual(members[0]["rank_change"], 1)

        self.database.submit_discovery_application(
            "server-a", "moderator",
            "A reviewed public listing for the first server.",
            "", "https://stt.gg/server-a",
        )
        self.database.review_discovery_application(
            "server-a", "approved", "owner"
        )
        self.database.set_public_stats_enabled("server-b", False)
        public = self.database.get_public_dashboard_stats()
        self.assertEqual(public["server_count"], 1)
        self.assertEqual(public["member_count"], 40)
        self.assertEqual(public["top_servers"][0]["server_id"], "server-a")
        self.assertEqual(
            [item["server_id"] for item in self.database.get_global_leaderboard("members")],
            ["server-a"],
        )
        self.assertFalse(
            self.database.get_dashboard_settings("server-b")["public_stats"]
        )

    def test_public_top_servers_require_permissions_and_rank_by_members(self) -> None:
        permissions_ready = {
            "available": True,
            "permissions": [
                {"name": "manage_messages", "granted": True},
                {"name": "ban_members", "granted": True},
            ],
        }
        permissions_missing = {
            "available": True,
            "permissions": [
                {"name": "manage_messages", "granted": True},
                {"name": "ban_members", "granted": False},
            ],
        }
        self.database.update_dashboard_server_snapshot(
            "unconfigured", "Unconfigured", 500, [], [], [],
            "https://cdn.example/unconfigured.png",
            permission_audit=permissions_missing,
        )
        self.database.update_dashboard_server_snapshot(
            "iconless", "Iconless", 250, [], [], [],
            permission_audit=permissions_ready,
        )
        self.database.update_dashboard_server_snapshot(
            "smaller", "Smaller", 50, [], [], [],
            "https://cdn.example/smaller.png",
            permission_audit=permissions_ready,
        )
        self.database.update_dashboard_server_snapshot(
            "larger", "Larger", 100, [], [], [],
            "https://cdn.example/larger.png",
            permission_audit=permissions_ready,
        )
        self.assertEqual(
            self.database.get_public_dashboard_stats()["top_servers"], []
        )
        for server_id in ("smaller", "larger"):
            self.database.submit_discovery_application(
                server_id, "moderator",
                "A reviewed public community listing for leaderboard proof.",
                "", "https://stt.gg/" + server_id,
            )
            self.database.review_discovery_application(
                server_id, "approved", "owner"
            )

        top_servers = self.database.get_public_dashboard_stats()["top_servers"]

        self.assertEqual(
            [server["server_id"] for server in top_servers],
            ["larger", "smaller"],
        )

    def test_dashboard_actions_are_claimed_and_completed_once(self) -> None:
        action_id = self.database.enqueue_dashboard_action(
            "server-a", "release_join_challenges", "moderator-a"
        )
        actions = self.database.claim_dashboard_actions()
        self.assertEqual(actions[0]["id"], action_id)
        self.assertEqual(actions[0]["action"], "release_join_challenges")
        self.assertEqual(self.database.claim_dashboard_actions(), [])
        self.database.finish_dashboard_action(
            action_id, success=True, result={"released_challenges": 2}
        )
        action = self.database.get_dashboard_action(action_id)
        self.assertEqual(action["status"], "completed")
        self.assertEqual(action["result"]["released_challenges"], 2)
        self.assertIsNone(self.database.get_dashboard_action(action_id + 1000))

    def test_dashboard_action_claim_tokens_fence_stale_workers(self) -> None:
        action_id = self.database.enqueue_dashboard_action(
            "server-a", "release_join_challenges", "moderator-a"
        )
        first = self.database.claim_dashboard_actions()[0]
        self.database.connection.execute(
            "UPDATE dashboard_actions "
            "SET claimed_at=datetime('now', '-6 minutes') WHERE id=?",
            (action_id,),
        )
        self.database.connection.commit()
        second = self.database.claim_dashboard_actions()[0]
        self.assertNotEqual(first["claim_token"], second["claim_token"])
        self.assertFalse(self.database.finish_dashboard_action(
            action_id,
            success=False,
            result={"worker": "stale"},
            claim_token=first["claim_token"],
        ))
        self.assertTrue(self.database.finish_dashboard_action(
            action_id,
            success=True,
            result={"worker": "current"},
            claim_token=second["claim_token"],
        ))
        completed = self.database.get_dashboard_action(action_id)
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["result"], {"worker": "current"})

    def test_warning_expiry_defaults_to_never_and_excludes_old_warnings(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a", user_id="user-a", moderator_id="moderator",
            source="manual", reason="Old warning",
        )
        self.database.connection.execute(
            "UPDATE warnings SET created_at='2025-01-01T00:00:00+00:00' WHERE id=?",
            (warning_id,),
        )
        self.database.connection.commit()
        self.assertIsNone(self.database.get_warning_expiry_days("server-a"))
        self.assertEqual(self.database.count_warnings("server-a", "user-a"), 1)
        self.database.set_warning_expiry_days("server-a", 30)
        self.assertEqual(self.database.count_warnings("server-a", "user-a"), 0)
        self.assertEqual(len(self.database.list_warnings("server-a", "user-a")), 1)

    def test_active_warning_count_excludes_inactive_case_history(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="moderator",
            source="manual",
            reason="Historical warning",
        )
        self.assertEqual(
            self.database.count_active_warnings("server-a", "user-a"), 1
        )
        self.database.connection.execute(
            """
            UPDATE moderation_cases SET status='removed'
            WHERE server_id=? AND source_type='warning' AND source_id=?
            """,
            ("server-a", warning_id),
        )
        self.database.connection.commit()

        self.assertEqual(
            self.database.count_active_warnings("server-a", "user-a"), 0
        )

    def test_member_snapshot_exposes_profile_and_server_history(self) -> None:
        self.database.replace_dashboard_members("server-a", [{
            "user_id": "member-a", "username": "stoat", "display_name": "Stoat",
            "avatar_url": "https://cdn.example/avatar.png",
            "joined_at": "2026-08-01T12:00:00+00:00", "role_ids": ["role-a"],
        }])
        self.database.add_warning(
            server_id="server-a", user_id="member-a", moderator_id="moderator",
            source="manual", reason="Test warning",
        )
        member = self.database.get_dashboard_member("server-a", "member-a")
        self.assertEqual(member["display_name"], "Stoat")
        self.assertEqual(member["role_ids"], ["role-a"])
        self.assertEqual(member["active_warning_count"], 1)
        self.assertEqual(member["cases"][0]["action"], "warning")

    def test_member_directory_is_not_truncated_at_five_hundred(self) -> None:
        self.database.replace_dashboard_members("server-a", [
            {
                "user_id": f"member-{index:04d}",
                "username": f"member-{index:04d}",
                "role_ids": [],
            }
            for index in range(525)
        ])

        self.assertEqual(len(self.database.list_dashboard_members("server-a")), 525)
        self.assertEqual(
            len(self.database.list_dashboard_members("server-a", limit=25)), 25
        )

    def test_member_directory_excludes_bot_accounts(self) -> None:
        self.database.replace_dashboard_members("server-a", [
            {"user_id": "human", "username": "human", "is_bot": False},
            {"user_id": "bot", "username": "bot", "is_bot": True},
        ])

        members = self.database.list_dashboard_members("server-a")

        self.assertEqual([member["user_id"] for member in members], ["human"])

    def test_captcha_all_members_is_disabled_by_default(self) -> None:
        self.assertFalse(self.database.get_captcha_all_members("server-a"))
        self.database.set_captcha_all_members("server-a", True)
        self.assertTrue(self.database.get_captcha_all_members("server-a"))
    def test_nickname_protection_is_enabled_by_default_and_persistent(self) -> None:
        self.assertTrue(self.database.get_nickname_protection("server-a"))
        self.database.set_nickname_protection("server-a", False)
        self.assertFalse(self.database.get_nickname_protection("server-a"))
        database_path = self.database.path
        self.database.close()

        self.database = ModerationDatabase(database_path)

        self.assertFalse(self.database.get_nickname_protection("server-a"))

    def test_link_protection_allows_only_gifbox_by_default_and_persists(self) -> None:
        self.assertTrue(self.database.get_link_protection("server-a"))
        self.assertTrue(self.database.get_allow_gifs("server-a"))
        self.database.set_link_protection("server-a", False)
        self.database.set_allow_gifs("server-a", False)
        self.assertFalse(self.database.get_link_protection("server-a"))
        self.assertFalse(self.database.get_allow_gifs("server-a"))
        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        self.assertFalse(self.database.get_link_protection("server-a"))
        self.assertFalse(self.database.get_allow_gifs("server-a"))

    def test_spam_detection_is_enabled_by_default_and_persistent(self) -> None:
        self.assertTrue(self.database.get_spam_detection("server-a"))
        self.database.set_spam_detection("server-a", False)
        self.assertFalse(self.database.get_spam_detection("server-a"))
        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        self.assertFalse(self.database.get_spam_detection("server-a"))

    def test_spam_settings_are_per_server_and_persistent(self) -> None:
        defaults = {
            "repeat_count": 3,
            "repeat_window_seconds": 30,
            "rapid_count": 5,
            "rapid_window_seconds": 10,
            "score_threshold": 7,
            "score_half_life_seconds": 30,
            "mass_mention_limit": 5,
            "timeout_seconds": 3600,
        }
        customized = {
            "repeat_count": 6,
            "repeat_window_seconds": 20,
            "rapid_count": 9,
            "rapid_window_seconds": 12,
            "score_threshold": 8.5,
            "score_half_life_seconds": 18,
            "mass_mention_limit": 7,
            "timeout_seconds": 900,
        }

        self.assertEqual(self.database.get_spam_settings("server-a", defaults), defaults)
        self.database.set_spam_settings("server-a", customized)
        self.assertEqual(self.database.get_spam_settings("server-a", defaults), customized)
        self.assertEqual(self.database.get_spam_settings("server-b", defaults), defaults)

        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        self.assertEqual(self.database.get_spam_settings("server-a", defaults), customized)

    def test_old_default_spam_score_is_migrated_without_changing_custom_scores(self) -> None:
        old_defaults = {**DEFAULT_SPAM_SETTINGS, "score_threshold": 5}
        self.database.set_spam_settings("server-default", old_defaults)
        self.database.set_spam_settings(
            "server-custom", {**old_defaults, "score_threshold": 8.5}
        )
        self.database.connection.execute(
            "DELETE FROM app_metadata WHERE key='spam_score_threshold_default_7_v1'"
        )
        self.database.connection.commit()

        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)

        self.assertEqual(
            self.database.get_spam_settings("server-default")["score_threshold"], 7
        )
        self.assertEqual(
            self.database.get_spam_settings("server-custom")["score_threshold"], 8.5
        )

    def test_image_scanning_has_server_default_and_channel_overrides(self) -> None:
        # On by default since 2026-10-19.
        self.assertTrue(self.database.get_image_scanning("server-a"))
        self.assertTrue(
            self.database.get_image_scanning("server-a", "channel-a")
        )
        self.database.set_image_scanning("server-a", False)
        self.assertFalse(self.database.get_image_scanning("server-a", "channel-a"))

        self.database.set_image_scanning("server-a", True)
        self.assertTrue(
            self.database.get_image_scanning("server-a", "channel-a")
        )
        self.database.set_channel_image_scanning(
            "server-a", "channel-a", False, "moderator-a"
        )
        self.assertFalse(
            self.database.get_image_scanning("server-a", "channel-a")
        )
        self.assertTrue(
            self.database.get_image_scanning("server-a", "channel-b")
        )
        self.assertFalse(
            self.database.get_channel_image_scanning_override(
                "server-a", "channel-a"
            )
        )
        self.assertIsNone(
            self.database.get_channel_image_scanning_override(
                "server-a", "channel-b"
            )
        )

        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        self.assertFalse(
            self.database.get_image_scanning("server-a", "channel-a")
        )
        self.assertTrue(
            self.database.get_image_scanning("server-a", "channel-b")
        )

    def test_image_scanning_default_on_migration_keeps_latest_server_wide_denials(self) -> None:
        connection = self.database.connection
        for server in ("untouched", "denied", "denied-then-enabled", "channel-only", "dashboard-denied"):
            connection.execute(
                "INSERT INTO server_settings(server_id, image_scanning_enabled, image_scanning_on) VALUES (?, 0, 0)",
                (server,),
            )
        self.database.add_event(server_id="denied", event_type="image_scanning_disabled", details={"target_channel_id": None})
        self.database.add_event(server_id="denied-then-enabled", event_type="image_scanning_disabled", details={"target_channel_id": None})
        self.database.add_event(server_id="denied-then-enabled", event_type="image_scanning_enabled", details={"target_channel_id": None})
        self.database.add_event(server_id="channel-only", event_type="image_scanning_disabled", details={"target_channel_id": "channel-a"})
        self.database.add_event(server_id="dashboard-denied", event_type="dashboard_settings_updated",
                                details={"changed": {"image_scanning": False}})
        self.database.set_channel_image_scanning("channel-only", "channel-a", False, "moderator-a")
        connection.execute("DELETE FROM app_metadata WHERE key='image_scanning_default_on_v1'")
        connection.commit()

        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)

        self.assertTrue(self.database.get_image_scanning("untouched"))
        self.assertFalse(self.database.get_image_scanning("denied"))
        self.assertTrue(self.database.get_image_scanning("denied-then-enabled"))
        self.assertTrue(self.database.get_image_scanning("channel-only"))
        self.assertFalse(self.database.get_image_scanning("channel-only", "channel-a"))
        self.assertFalse(self.database.get_image_scanning("dashboard-denied"))

    def test_moderator_exemption_is_enabled_by_default_and_persistent(self) -> None:
        self.assertTrue(self.database.get_moderator_exemption("server-a"))

        self.database.set_moderator_exemption("server-a", False)
        self.assertFalse(self.database.get_moderator_exemption("server-a"))

        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)

        self.assertFalse(self.database.get_moderator_exemption("server-a"))
        self.assertTrue(self.database.get_moderator_exemption("server-b"))

    def test_warning_policy_action_claim_prevents_duplicates(self) -> None:
        self.assertTrue(
            self.database.claim_warning_policy_action(
                "server", "user", "timeout", 3, 10
            )
        )
        self.assertFalse(
            self.database.claim_warning_policy_action(
                "server", "user", "timeout", 3, 11
            )
        )
        self.database.release_warning_policy_action(
            "server", "user", "timeout", 3
        )
        self.assertTrue(
            self.database.claim_warning_policy_action(
                "server", "user", "timeout", 3, 12
            )
        )

    def test_global_bans_and_warnings_have_shared_unique_references(self) -> None:
        ban = self.database.add_global_ban(
            "BAN123", "user-a", "global ban reason", "owner"
        )
        warning = self.database.add_global_warning(
            "WARN12", "user-a", "global warning reason", "owner"
        )

        self.assertTrue(self.database.global_reference_exists("BAN123"))
        self.assertTrue(self.database.global_reference_exists("WARN12"))
        self.assertEqual(self.database.get_global_ban("user-a"), ban)
        self.assertEqual(self.database.get_global_ban("ban123"), ban)
        self.assertEqual(
            self.database.list_global_warnings("user-a"), [warning]
        )
        self.assertEqual(
            self.database.remove_global_warning("warn12"), warning
        )
        self.assertEqual(self.database.remove_global_ban("user-a"), ban)
        self.assertIsNone(self.database.get_global_ban("user-a"))

    def test_channel_and_category_scope_exclusions(self) -> None:
        self.database.exclude_scope(
            "server-a", "channel-a", "channel", "moderator-a"
        )
        self.database.exclude_scope(
            "server-a", "category-a", "category", "moderator-a"
        )

        self.assertTrue(
            self.database.is_scope_excluded("server-a", "channel-a", None)
        )
        self.assertTrue(
            self.database.is_scope_excluded(
                "server-a", "different-channel", "category-a"
            )
        )
        self.assertFalse(
            self.database.is_scope_excluded("server-b", "channel-a", "category-a")
        )
        self.assertTrue(self.database.include_scope("server-a", "channel-a"))
        self.assertFalse(
            self.database.is_scope_excluded("server-a", "channel-a", None)
        )
        self.assertFalse(self.database.include_scope("server-a", "channel-a"))
        self.assertEqual(self.database.count_scope_exclusions("server-a"), 1)

    def test_confirmed_deleted_channel_removes_snapshot_and_exemption(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server-a",
            "Server A",
            12,
            [("channel-a", "general"), ("channel-b", "staff")],
        )
        self.database.exclude_scope(
            "server-a", "channel-b", "channel", "moderator-a"
        )

        removed = self.database.remove_deleted_channel_reference(
            "server-a", "channel-b"
        )

        self.assertTrue(removed)
        settings = self.database.get_dashboard_settings("server-a")
        self.assertEqual(settings["exempt_channels"], [])
        self.assertEqual(
            [channel["channel_id"] for channel in settings["channels"]],
            ["channel-a"],
        )
        self.assertFalse(
            self.database.remove_deleted_channel_reference(
                "server-a", "channel-b"
            )
        )

    def test_disabled_moderation_categories_are_hierarchical(self) -> None:
        self.database.disable_moderation_category(
            "server-a", "violence", "moderator"
        )

        self.assertTrue(
            self.database.is_moderation_category_disabled(
                "server-a", "violence"
            )
        )
        self.assertTrue(
            self.database.is_moderation_category_disabled(
                "server-a", "violence/graphic"
            )
        )
        self.assertFalse(
            self.database.is_moderation_category_disabled(
                "server-a", "harassment"
            )
        )
        self.assertEqual(
            self.database.list_disabled_moderation_categories("server-a"),
            ["violence"],
        )
        self.assertEqual(
            self.database.enable_moderation_category("server-a", "violence"),
            1,
        )
        self.assertFalse(
            self.database.is_moderation_category_disabled(
                "server-a", "violence/graphic"
            )
        )

    def test_warning_round_trip_and_count_are_scoped_per_server(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="bot",
            source="automatic",
            reason="Automatic content moderation: violence",
            message_id="message-a",
            channel_id="channel-a",
            categories={"violence": True},
            scores={"violence": 0.95},
            original_content="complete original message",
        )

        self.assertEqual(self.database.count_warnings("server-a", "user-a"), 1)
        self.assertEqual(self.database.count_warnings("server-b", "user-a"), 0)
        record = self.database.list_warnings("server-a", "user-a")[0]
        self.assertEqual(record.id, warning_id)
        self.assertEqual(record.categories, {"violence": True})
        self.assertEqual(record.scores, {"violence": 0.95})
        self.assertEqual(record.original_content, "complete original message")

    def test_general_event_is_recorded(self) -> None:
        event_id = self.database.add_event(
            server_id="server-a",
            event_type="member_ban",
            user_id="user-a",
            details={"actor_attribution": "unavailable_from_stoat_event"},
        )

        row = self.database.connection.execute(
            "SELECT * FROM moderation_events WHERE id=?", (event_id,)
        ).fetchone()
        self.assertEqual(row["event_type"], "member_ban")
        self.assertEqual(row["user_id"], "user-a")

        case = self.database.get_event_case("server-a", event_id)
        self.assertIsNotNone(case)
        self.assertEqual(case.action if case else None, "ban")
        self.assertEqual(case.reason if case else None, "Member banned")

    def test_only_stoatmod_kicks_create_cases(self) -> None:
        external_event_id = self.database.add_event(
            server_id="server-a", event_type="member_kick", user_id="external",
            details={
                "reason": "Kick",
                "actor_attribution": "unavailable_from_stoat_event",
                "stoatmod_initiated": False,
            },
        )
        self.database.add_event(
            server_id="server-a", event_type="member_kick", user_id="internal",
            actor_id="bot", details={
                "reason": "Failed CAPTCHA",
                "actor_attribution": "known_bot_action",
                "stoatmod_initiated": True,
            },
        )

        cases = {
            case["user_id"]: case
            for case in self.database.list_dashboard_cases("server-a")
        }
        self.assertNotIn("external", cases)
        self.assertIsNone(
            self.database.get_event_case("server-a", external_event_id)
        )
        self.assertTrue(cases["internal"]["stoatmod_initiated"])
        self.assertEqual(cases["internal"]["reason"], "Failed CAPTCHA")

    def test_external_kick_case_cleanup_preserves_audit_event(self) -> None:
        event_id = self.database.add_event(
            server_id="server-a", event_type="member_kick", user_id="external",
            details={
                "reason": "Kick",
                "actor_attribution": "unavailable_from_stoat_event",
            },
        )
        case = self.database.get_event_case("server-a", event_id)
        self.assertIsNotNone(case)
        self.database.connection.execute(
            """
            UPDATE moderation_events
            SET details_json=json_set(details_json, '$.stoatmod_initiated', 0)
            WHERE id=?
            """,
            (event_id,),
        )
        self.database.connection.commit()

        self.assertEqual(self.database.remove_external_kick_cases(), 1)
        self.assertIsNone(self.database.get_event_case("server-a", event_id))
        event = self.database.connection.execute(
            "SELECT id FROM moderation_events WHERE id=?", (event_id,)
        ).fetchone()
        self.assertIsNotNone(event)

    def test_legacy_captcha_kick_reason_is_backfilled(self) -> None:
        kick_event_id = self.database.add_event(
            server_id="server-a", event_type="member_kick", user_id="member",
            details={
                "reason": "Kick",
                "actor_attribution": "unavailable_from_stoat_event",
            },
        )
        self.database.add_event(
            server_id="server-a", event_type="join_captcha_failed",
            user_id="member", details={
                "result": "kicked_after_30_minutes",
                "reason": "Legacy expiry reason",
            },
        )

        self.assertEqual(
            self.database.backfill_captcha_kick_reasons("bot-user"), 1
        )
        case = self.database.get_event_case("server-a", kick_event_id)
        self.assertIsNotNone(case)
        self.assertEqual(case.reason if case else None, "Legacy expiry reason")
        event = next(
            item for item in self.database.list_dashboard_events("server-a")
            if item["id"] == kick_event_id
        )
        self.assertEqual(event["actor_id"], "bot-user")
        self.assertTrue(event["details"]["stoatmod_initiated"])

    def test_warnings_create_cases_and_removal_preserves_audit_record(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="moderator",
            source="manual",
            reason="Repeated spam",
        )

        case = self.database.get_warning_case("server-a", warning_id)
        self.assertIsNotNone(case)
        self.assertEqual(case.action if case else None, "warning")
        self.assertEqual(case.reason if case else None, "Repeated spam")
        self.assertEqual(case.status if case else None, "active")
        self.assertEqual(len(case.reference_id if case else ""), 8)
        self.assertTrue(any(c.isalpha() for c in case.reference_id if case))
        self.assertTrue(any(c.isdigit() for c in case.reference_id if case))
        self.assertIsNone(
            self.database.get_moderation_case(
                "server-b", case.reference_id if case else "MISSING1"
            )
        )

        result = self.database.remove_moderation_case(
            "server-a", case.reference_id if case else "MISSING1"
        )

        self.assertIsNotNone(result)
        self.assertEqual(result[1].id if result and result[1] else None, warning_id)
        self.assertEqual(self.database.count_warnings("server-a", "user-a"), 0)
        self.assertEqual(self.database.list_warnings("server-a", "user-a"), [])
        retained_warning = self.database.connection.execute(
            "SELECT original_content FROM warnings WHERE id=?", (warning_id,)
        ).fetchone()
        self.assertIsNotNone(retained_warning)
        preserved = self.database.get_moderation_case(
            "server-a", case.reference_id if case else "MISSING1"
        )
        self.assertIsNotNone(preserved)
        self.assertEqual(preserved.status if preserved else None, "removed")

    def test_removed_legacy_warning_recovers_evidence_from_audit_event(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="bot",
            source="automatic",
            reason="Automatic content moderation: harassment",
        )
        case = self.database.get_warning_case("server-a", warning_id)
        self.database.add_event(
            server_id="server-a",
            event_type="automatic_deletion",
            user_id="user-a",
            actor_id="bot",
            message_id="message-a",
            channel_id="channel-a",
            details={
                "warning_id": warning_id,
                "original_content": "Recovered message evidence",
                "categories": {"harassment": True},
                "scores": {"harassment": 0.96},
            },
        )
        self.database.connection.execute("DELETE FROM warnings WHERE id=?", (warning_id,))
        self.database.connection.execute(
            "UPDATE moderation_cases SET status='removed' WHERE id=?", (case.id,)
        )
        self.database.connection.commit()

        detail = self.database.get_moderation_case_detail(
            "server-a", case.reference_id
        )

        self.assertIsNotNone(detail)
        self.assertEqual(detail["source"]["original_content"], "Recovered message evidence")
        self.assertEqual(detail["source"]["scores"]["harassment"], 0.96)
        self.assertTrue(detail["source"]["recovered_from_audit_event"])

    def test_non_warning_case_removal_keeps_underlying_audit_event(self) -> None:
        event_id = self.database.add_event(
            server_id="server-a",
            event_type="manual_mute",
            user_id="user-a",
            actor_id="moderator",
            details={"duration_seconds": 3600},
        )
        case = self.database.get_event_case("server-a", event_id)
        self.assertIsNotNone(case)

        result = self.database.remove_moderation_case(
            "server-a", case.reference_id if case else "MISSING1"
        )

        self.assertIsNotNone(result)
        self.assertIsNone(result[1] if result else None)
        preserved_event = self.database.connection.execute(
            "SELECT 1 FROM moderation_events WHERE id=?", (event_id,)
        ).fetchone()
        self.assertIsNotNone(preserved_event)
        removed_case = self.database.get_event_case("server-a", event_id)
        self.assertEqual(removed_case.status if removed_case else None, "removed")

    def test_case_references_are_unique_randomized_letters_and_numbers(self) -> None:
        references: set[str] = set()
        for index in range(25):
            warning_id = self.database.add_warning(
                server_id="server-a",
                user_id=f"user-{index}",
                moderator_id="moderator",
                source="manual",
                reason="Test warning",
            )
            case = self.database.get_warning_case("server-a", warning_id)
            self.assertIsNotNone(case)
            reference = case.reference_id if case else ""
            self.assertEqual(len(reference), 8)
            self.assertTrue(any(character.isalpha() for character in reference))
            self.assertTrue(any(character.isdigit() for character in reference))
            references.add(reference)

        self.assertEqual(len(references), 25)

    def test_only_enforcement_events_create_moderation_cases(self) -> None:
        mute_event = self.database.add_event(
            server_id="server-a",
            event_type="manual_mute",
            user_id="user-a",
            actor_id="moderator",
            details={"duration_seconds": 3600},
        )
        join_event = self.database.add_event(
            server_id="server-a",
            event_type="member_join",
            user_id="user-a",
        )

        mute_case = self.database.get_event_case("server-a", mute_event)
        self.assertIsNotNone(mute_case)
        self.assertEqual(mute_case.action if mute_case else None, "mute")
        self.assertEqual(
            mute_case.reason if mute_case else None,
            "Manual mute for 3600 seconds",
        )
        self.assertIsNone(self.database.get_event_case("server-a", join_event))

    def test_existing_records_are_backfilled_when_case_table_is_added(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="moderator",
            source="manual",
            reason="Legacy warning",
        )
        ban_event_id = self.database.add_event(
            server_id="server-a",
            event_type="member_ban",
            user_id="user-a",
            details={"reason": "Legacy ban"},
        )
        self.database.connection.execute("DROP TABLE moderation_cases")
        self.database.connection.commit()

        self.database._initialize()

        warning_case = self.database.get_warning_case("server-a", warning_id)
        ban_case = self.database.get_event_case("server-a", ban_event_id)
        self.assertIsNotNone(warning_case)
        self.assertEqual(warning_case.reason if warning_case else None, "Legacy warning")
        self.assertIsNotNone(ban_case)
        self.assertEqual(ban_case.reason if ban_case else None, "Legacy ban")


    def test_member_network_history_includes_active_server_and_global_bans(self) -> None:
        user_id = "network-user"
        self.database.update_dashboard_server_snapshot(
            "server-a", "Server A", 1, [], [], []
        )
        self.database.update_dashboard_server_snapshot(
            "server-b", "Server B", 1, [], [], []
        )
        self.database.upsert_dashboard_member(
            "server-a", {"user_id": user_id, "username": "network.user"}
        )
        self.database.add_event(
            server_id="server-b",
            event_type="member_ban",
            user_id=user_id,
            details={"reason": "Banned in Server B"},
        )
        self.database.add_global_ban(
            "GB1234", user_id, "Cross-network abuse", "global-owner"
        )

        member = self.database.get_dashboard_member("server-a", user_id)

        self.assertIsNotNone(member)
        assert member is not None
        self.assertEqual(member["server_history"], [])
        self.assertIsNotNone(self.database.get_global_ban(user_id))


    def test_retired_zero_tolerance_history_is_removed_on_startup(self) -> None:
        legacy_reason = (
            "Automatic global ban: zero-tolerance slur detected in message"
        )
        self.database.add_event(
            server_id="server-a",
            event_type="zero_tolerance_global_ban",
            user_id="legacy-user",
            details={"reason": legacy_reason},
        )
        self.database.add_event(
            server_id="server-b",
            event_type="global_ban_enforced",
            user_id="legacy-user",
            details={"reason": legacy_reason},
        )
        retained_event_id = self.database.add_event(
            server_id="server-c",
            event_type="global_ban_enforced",
            user_id="legacy-user",
            details={"reason": "Unrelated global ban"},
        )
        database_path = Path(self.directory.name, "moderation.db")
        self.database.close()
        self.database = ModerationDatabase(database_path)

        stored_events = self.database.connection.execute(
            "SELECT id, event_type FROM moderation_events WHERE user_id=?",
            ("legacy-user",),
        ).fetchall()

        self.assertEqual(
            [(row["id"], row["event_type"]) for row in stored_events],
            [(retained_event_id, "global_ban_enforced")],
        )

    def test_dashboard_announcement_dismissal_is_permanent_per_user(self) -> None:
        announcement = self.database.create_dashboard_announcement(
            "server", "Service notice", "Maintenance at 20:00 UTC", "owner"
        )

        self.assertEqual(
            self.database.list_dashboard_announcements("server", "moderator")[0]["id"],
            announcement["id"],
        )
        self.assertTrue(
            self.database.dismiss_dashboard_announcement(
                "server", "moderator", announcement["id"]
            )
        )
        self.assertEqual(
            self.database.list_dashboard_announcements("server", "moderator"), []
        )
        self.assertEqual(
            len(self.database.list_dashboard_announcements("server", "other-moderator")),
            1,
        )

    def test_dashboard_announcements_expire_after_three_days(self) -> None:
        recent = self.database.create_dashboard_announcement(
            "server", "Recent notice", "Still visible", "owner"
        )
        expired = self.database.create_dashboard_announcement(
            "server", "Old notice", "No longer visible", "owner"
        )
        expired_at = (
            datetime.now(timezone.utc) - timedelta(days=3, seconds=1)
        ).isoformat(timespec="seconds")
        self.database.connection.execute(
            "UPDATE dashboard_announcements SET created_at=? WHERE id=?",
            (expired_at, expired["id"]),
        )
        self.database.connection.commit()

        announcements = self.database.list_dashboard_announcements(
            "server", "moderator"
        )

        self.assertEqual([item["id"] for item in announcements], [recent["id"]])
        self.assertEqual(
            datetime.fromisoformat(announcements[0]["expires_at"])
            - datetime.fromisoformat(announcements[0]["created_at"]),
            timedelta(days=3),
        )


    def test_appeal_credentials_reveal_warning_evidence_and_support_decisions(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server-a",
            user_id="user-a",
            moderator_id="moderator",
            source="automatic",
            reason="Automatic content moderation: harassment",
            original_content="original message",
            categories={"harassment": True},
            scores={"harassment": 0.91},
        )
        case = self.database.get_warning_case("server-a", warning_id)
        self.assertIsNotNone(case)
        self.database.create_appeal_access(
            "hashed-code", "user-a", "moderation", case.reference_id, "server-a"
        )

        self.assertIsNone(
            self.database.get_appeal_by_credentials("hashed-code", "wrong-user")
        )
        appeal = self.database.get_appeal_by_credentials("hashed-code", "user-a")
        self.assertEqual(
            self.database.get_server_appeal_by_case(
                "server-a", case.reference_id
            )["id"],
            appeal["id"],
        )
        self.assertIsNone(
            self.database.get_server_appeal_by_case(
                "server-b", case.reference_id
            )
        )
        self.assertEqual(appeal["evidence"]["original_message"], "original message")
        self.assertEqual(
            appeal["evidence"]["detected_thresholds"]["scores"]["harassment"],
            0.91,
        )
        submitted = self.database.submit_appeal(
            appeal["id"], "user-a", "The automated decision was incorrect."
        )
        self.assertEqual(submitted["status"], "submitted")
        reviewed = self.database.review_appeal(
            appeal["id"], "moderator", "approved", "Warning removed after review."
        )
        self.assertEqual(reviewed["status"], "approved")

    def test_global_bans_are_not_eligible_for_dashboard_appeals(self) -> None:
        with self.assertRaisesRegex(ValueError, "only server moderation cases"):
            self.database.create_appeal_access(
                "global-code", "global-user", "global_ban", "GBAN01"
            )

        self.database.connection.execute(
            """
            INSERT INTO appeals(
                code_hash, server_id, user_id, case_kind, case_reference,
                status, statement, created_at, submitted_at
            ) VALUES (?, NULL, ?, 'global_ban', ?, 'submitted', ?, ?, ?)
            """,
            (
                "legacy-global-code",
                "global-user",
                "GBAN01",
                "Legacy global appeal",
                "2026-08-20T12:00:00+00:00",
                "2026-08-20T12:01:00+00:00",
            ),
        )
        self.database.connection.commit()

        self.assertIsNone(
            self.database.get_appeal_by_credentials(
                "legacy-global-code", "global-user"
            )
        )
        self.assertEqual(self.database.list_dashboard_appeals("server-a"), [])
        self.assertEqual(self.database.list_owner_appeals(), [])
        summary = self.database.get_owner_dashboard_summary()
        self.assertEqual(summary["appeal_count"], 0)
        self.assertEqual(summary["pending_appeals"], 0)

    def test_system_heartbeat_round_trip_is_public_safe(self) -> None:
        self.assertIsNone(self.database.get_system_heartbeat("bot"))
        written = self.database.update_system_heartbeat(
            "bot", {"connected": True, "server_count": 3}
        )
        stored = self.database.get_system_heartbeat("bot")
        self.assertEqual(stored, written)
        self.assertTrue(stored["details"]["connected"])
        self.assertEqual(stored["details"]["server_count"], 3)

    def test_privacy_export_and_delete_cover_related_case_data(self) -> None:
        user_id = "01PRIVACYUSER1234567890ABC"
        self.database.replace_dashboard_members("privacy-server", [{
            "user_id": user_id,
            "username": "privacy.user",
            "display_name": "Privacy User",
            "discriminator": "0420",
            "avatar_url": "https://cdn.example/privacy-user.png",
        }])
        warning_id = self.database.add_warning(
            server_id="privacy-server",
            user_id=user_id,
            moderator_id="moderator",
            source="manual",
            reason="Privacy request test",
            original_content="Stored subject content",
        )
        case = self.database.get_warning_case("privacy-server", warning_id)
        self.assertIsNotNone(case)
        assert case is not None
        self.database.add_moderation_case_entry(
            "privacy-server",
            case.reference_id,
            "evidence",
            "Related case evidence",
            "owner",
            [("case-proof.png", "image/png", b"case attachment contents")],
        )
        self.database.add_event(
            server_id="privacy-server",
            event_type="privacy_network_record",
            user_id=user_id,
            details={"ip_address": "203.0.113.42"},
        )
        self.database.connection.execute("INSERT INTO user_ip_addresses VALUES (?,?,?,?,?,?)", ('203.0.113.42', user_id, 'privacy-server', 'verification', "2026-09-01", "2026-09-01"))
        self.database.connection.commit()
        report_id = self.database.create_user_report(
            "privacy-server", user_id, "target", "Test report", "Evidence"
        )
        self.database.add_report_attachment(
            report_id, "evidence.txt", "text/plain", b"attachment contents"
        )

        export = self.database.export_privacy_data(user_id, "user")
        username_matches = self.database.search_privacy_subjects("privacy.user")
        case_matches = self.database.search_privacy_subjects(
            f"CASE-{case.reference_id}"
        )

        table_names = {table["table"] for table in export["tables"]}
        self.assertIn("warnings", table_names)
        self.assertIn("moderation_cases", table_names)
        self.assertIn("moderation_case_entries", table_names)
        self.assertIn("moderation_case_entry_attachments", table_names)
        self.assertIn("user_report_attachments", table_names)
        self.assertIn("user_ip_addresses", table_names)
        self.assertEqual(export["export_version"], 2)
        self.assertEqual(export["identity"]["full_username"], "privacy.user#0420")
        self.assertEqual(
            export["identity"]["profile_picture"],
            "https://cdn.example/privacy-user.png",
        )
        self.assertEqual(
            [item["address"] for item in export["ip_addresses"]],
            ["203.0.113.42"],
        )
        attachment_table = next(
            table for table in export["tables"]
            if table["table"] == "user_report_attachments"
        )
        self.assertEqual(
            attachment_table["records"][0]["data"]["encoding"], "base64"
        )
        self.assertGreaterEqual(export["total_records"], 3)
        self.assertEqual(username_matches[0]["identifier"], user_id)
        self.assertEqual(case_matches[0]["identifier"], user_id)
        self.assertIn(
            f"CASE-{case.reference_id}", case_matches[0]["case_references"]
        )

        deleted = self.database.delete_privacy_data(user_id)

        self.assertGreaterEqual(deleted["deleted_records"], 3)
        remaining = self.database.export_privacy_data(user_id, "user")
        self.assertEqual(remaining["deletable_records"], 0)
        self.assertEqual(
            remaining["total_records"], remaining["retained_records"]
        )
        self.assertIsNone(
            self.database.get_moderation_case("privacy-server", case.reference_id)
        )
        identity_cache = self.database.connection.execute(
            "SELECT 1 FROM user_identities WHERE user_id=?", (user_id,)
        ).fetchone()
        self.assertIsNone(identity_cache)
        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        identity_cache = self.database.connection.execute(
            "SELECT 1 FROM user_identities WHERE user_id=?", (user_id,)
        ).fetchone()
        self.assertIsNone(identity_cache)

    def test_privacy_delete_preserves_global_enforcement_records(self) -> None:
        user_id = "01PRIVACYBANNED1234567890AB"
        self.database.add_global_ban("BAN123", user_id, "Safety risk", "owner")
        self.database.add_global_warning("WARN12", user_id, "Prior risk", "owner")
        self.database.connection.execute("INSERT INTO user_ip_fingerprints VALUES (?,?,?,?,?,?)", ('fingerprint-value', user_id, 'server-a', 'verification', "2026-09-01", "2026-09-01"))
        self.database.connection.commit()
        self.database.add_event(
            server_id="server-a",
            event_type="member_join",
            user_id=user_id,
            details={"note": "deletable activity"},
        )

        before = self.database.export_privacy_data(user_id, "user")
        self.assertGreaterEqual(before["retained_records"], 2)
        self.assertGreaterEqual(before["deletable_records"], 1)

        result = self.database.delete_privacy_data(user_id)

        self.assertTrue(result["requires_review"])
        self.assertGreaterEqual(result["deleted_records"], 1)
        self.assertGreaterEqual(result["retained_records"], 2)
        self.assertIsNotNone(self.database.get_global_ban(user_id))
        self.assertEqual(len(self.database.list_global_warnings(user_id)), 1)
        fingerprint = self.database.connection.execute(
            "SELECT 1 FROM user_ip_fingerprints WHERE user_id=?", (user_id,)
        ).fetchone()
        self.assertIsNone(fingerprint)

    def test_owner_global_ban_detail_includes_identity_cases_and_enforcement(self) -> None:
        user_id = "01GLOBALDETAIL1234567890ABC"
        self.database.update_dashboard_server_snapshot(
            "detail-server", "Detail Server", 10, [], [], []
        )
        self.database.upsert_dashboard_member("detail-server", {
            "user_id": user_id,
            "username": "banned.member",
            "discriminator": "7654",
            "display_name": "Banned Member",
            "avatar_url": "https://cdn.example/banned-member.png",
            "account_created_at": "2025-01-01T00:00:00+00:00",
        })
        self.database.add_global_ban("GBD123", user_id, "Network risk", "owner")
        self.database.add_global_warning("GWD123", user_id, "Prior warning", "owner")
        warning_id = self.database.add_warning(
            server_id="detail-server",
            user_id=user_id,
            moderator_id="moderator",
            source="manual",
            reason="Server warning",
        )
        case = self.database.get_warning_case("detail-server", warning_id)
        self.database.add_event(
            server_id="detail-server",
            event_type="global_ban_enforced",
            user_id=user_id,
            actor_id="bot",
            details={"reason": "Network risk"},
        )

        detail = self.database.get_owner_global_ban_detail(user_id)

        self.assertIsNotNone(detail)
        assert detail is not None and case is not None
        self.assertEqual(detail["identity"]["full_username"], "banned.member#7654")
        self.assertEqual(
            detail["identity"]["profile_picture"],
            "https://cdn.example/banned-member.png",
        )
        self.assertEqual(detail["cases"][0]["reference_id"], case.reference_id)
        self.assertEqual(detail["global_warnings"][0]["reference_id"], "GWD123")
        self.assertEqual(
            detail["enforcement_events"][0]["event_type"],
            "global_ban_enforced",
        )

    def test_retired_history_retention_is_cleared_without_deleting_cases(self) -> None:
        self.database.set_log_channel("server-a", "logs")
        warning = self.database.add_warning(
            server_id="server-a", user_id="user", moderator_id="mod",
            source="manual", reason="Active warning",
        )
        self.database.connection.execute("UPDATE server_settings SET retention_days=30")
        self.database.connection.commit()
        database_path = self.database.path
        self.database.close()
        self.database = ModerationDatabase(database_path)
        value = self.database.connection.execute("SELECT retention_days FROM server_settings WHERE server_id='server-a'").fetchone()[0]
        self.assertIsNone(value)
        self.assertNotIn("retention_days", self.database.get_dashboard_settings("server-a"))
        self.assertIsNotNone(self.database.get_warning_case("server-a", warning))
        self.assertFalse(hasattr(self.database, "set_retention_days"))
        self.assertFalse(hasattr(self.database, "prune_expired_server_data"))

    def test_email_threads_are_deduplicated_and_replies_are_queued(self) -> None:
        thread_key = "a" * 64
        inserted = self.database.record_email_message(
            message_key="message-key",
            thread_key=thread_key,
            message_id="<message@example.com>",
            direction="inbound",
            sender="Sender <sender@example.com>",
            recipient="admin@modstoat.site",
            subject="Account question",
            body="Can you help?",
            sent_at="2026-08-11T21:00:00+00:00",
            in_reply_to=None,
            references=[],
            status="received",
        )
        duplicate = self.database.record_email_message(
            message_key="message-key",
            thread_key=thread_key,
            message_id="<message@example.com>",
            direction="inbound",
            sender="Sender <sender@example.com>",
            recipient="admin@modstoat.site",
            subject="Account question",
            body="Can you help?",
            sent_at="2026-08-11T21:00:00+00:00",
            in_reply_to=None,
            references=[],
            status="received",
        )
        self.assertTrue(inserted)
        self.assertFalse(duplicate)
        self.assertEqual(self.database.list_owner_email_threads()[0]["unread_count"], 1)
        detail = self.database.get_owner_email_thread(thread_key)
        self.assertEqual(detail["messages"][0]["body"], "Can you help?")
        queued = self.database.queue_owner_email_reply(
            thread_key, "Yes, I can help.", "owner"
        )
        self.assertEqual(queued["status"], "pending")
        pending_reply = self.database.claim_email_replies()[0]
        self.assertEqual(
            pending_reply["to_address"], "Sender <sender@example.com>"
        )
        self.assertEqual(pending_reply["subject"], "Account question")

    def test_email_compose_attachments_and_deletion(self) -> None:
        queued = self.database.queue_owner_new_email(
            "customer@example.com",
            "New support message",
            "Hello **there**",
            "owner",
            [("guide.txt", "text/plain", b"attachment content")],
            cc_addresses=["copy@example.com"],
            bcc_addresses=["blind@example.com"],
        )
        pending = self.database.claim_email_replies()
        self.assertEqual(pending[0]["id"], queued["id"])
        self.assertEqual(pending[0]["attachments"][0]["filename"], "guide.txt")
        self.assertEqual(pending[0]["cc"], ["copy@example.com"])
        self.assertEqual(pending[0]["bcc"], ["blind@example.com"])
        self.assertEqual(
            bytes(pending[0]["attachments"][0]["content"]),
            b"attachment content",
        )
        self.database.complete_email_reply(
            queued["id"],
            message_key="a" * 64,
            message_id="<new@example.com>",
            sender="admin@modstoat.site",
        )
        detail = self.database.get_owner_email_thread(queued["thread_key"])
        self.assertEqual(detail["messages"][0]["attachments"][0]["size"], 18)
        self.assertEqual(detail["messages"][0]["cc"], ["copy@example.com"])
        self.assertEqual(detail["messages"][0]["bcc"], ["blind@example.com"])
        self.assertTrue(self.database.delete_owner_email_message("a" * 64))
        self.assertIsNone(
            self.database.get_owner_email_thread(queued["thread_key"])
        )

        second = self.database.queue_owner_new_email(
            "second@example.com", "Second", "Message", "owner"
        )
        self.database.complete_email_reply(
            second["id"], message_key="b" * 64, sender="admin@modstoat.site"
        )
        self.assertEqual(
            self.database.delete_owner_email_thread(second["thread_key"]), 1
        )
        self.assertIsNone(self.database.get_owner_email_thread(second["thread_key"]))

    def test_email_relay_baselines_are_scoped_to_each_mailbox(self) -> None:
        self.assertFalse(
            self.database.is_email_relay_initialized(
                "admin@modstoat.site", "Labels/stoatmod"
            )
        )
        self.database.initialize_email_relay(
            "admin@modstoat.site", [], "Labels/stoatmod"
        )
        self.assertTrue(
            self.database.is_email_relay_initialized(
                "admin@modstoat.site", "Labels/stoatmod"
            )
        )
        self.assertFalse(
            self.database.is_email_relay_initialized(
                "admin@modstoat.site", "INBOX"
            )
        )


    def test_dashboard_notification_cursors_are_user_scoped_and_race_safe(self) -> None:
        historical = self.database.add_event(
            server_id="server-a", event_type="member_join", user_id="member-a"
        )

        first = self.database.get_dashboard_notification_snapshot(
            "server-a", "moderator-a"
        )
        self.assertEqual(first["activity"], {
            "unread_count": 0,
            "latest_event_id": historical,
        })
        self.assertEqual(first["appeals"]["unread_count"], 0)

        ordinary = self.database.add_event(
            server_id="server-a", event_type="message_deleted", user_id="member-a"
        )
        appeal = self.database.add_event(
            server_id="server-a",
            event_type="moderation_appeal_submitted",
            user_id="member-a",
        )
        unread = self.database.get_dashboard_notification_snapshot(
            "server-a", "moderator-a"
        )
        self.assertEqual(unread["activity"]["unread_count"], 2)
        self.assertEqual(unread["appeals"]["unread_count"], 1)
        self.assertEqual(unread["activity"]["latest_event_id"], appeal)

        later = self.database.add_event(
            server_id="server-a", event_type="member_leave", user_id="member-a"
        )
        marked = self.database.mark_dashboard_notification_read(
            "server-a", "moderator-a", "activity", appeal
        )
        self.assertEqual(marked["unread_count"], 1)
        self.assertEqual(marked["latest_event_id"], later)
        self.assertGreater(ordinary, historical)

        other_user = self.database.get_dashboard_notification_snapshot(
            "server-a", "moderator-b"
        )
        self.assertEqual(other_user["activity"]["unread_count"], 0)
        other_server = self.database.get_dashboard_notification_snapshot(
            "server-b", "moderator-a"
        )
        self.assertEqual(other_server["activity"]["unread_count"], 0)

    def test_owner_and_support_mailboxes_are_isolated_and_choose_the_sender(self) -> None:
        owner_thread = "a" * 64
        support_thread = "b" * 64
        common = {
            "message_id": None,
            "direction": "inbound",
            "sender": "person@example.com",
            "subject": "Help",
            "body": "Please help",
            "sent_at": "2026-08-27T01:00:00+00:00",
            "in_reply_to": None,
            "references": [],
            "status": "received",
        }
        self.database.record_email_message(
            message_key="1" * 64,
            thread_key=owner_thread,
            recipient="admin@modstoat.site",
            mailbox_address="admin@modstoat.site",
            **common,
        )
        self.database.record_email_message(
            message_key="2" * 64,
            thread_key=support_thread,
            recipient="support@modstoat.site",
            mailbox_address="support@modstoat.site",
            **common,
        )

        self.assertEqual(
            [item["thread_key"] for item in self.database.list_owner_email_threads(
                mailbox_address="admin@modstoat.site"
            )],
            [owner_thread],
        )
        self.assertIsNone(self.database.get_owner_email_thread(
            support_thread, mailbox_address="admin@modstoat.site"
        ))
        self.assertEqual(
            self.database.get_owner_notification_counts("admin@modstoat.site")[
                "unread_email"
            ],
            1,
        )
        self.database.get_owner_email_thread(
            support_thread, mailbox_address="support@modstoat.site"
        )
        self.assertEqual(
            self.database.get_owner_notification_counts("admin@modstoat.site")[
                "unread_email"
            ],
            1,
        )

        queued = self.database.queue_owner_email_reply(
            support_thread,
            "We can help.",
            "staffer@modstoat.site",
            mailbox_address="support@modstoat.site",
        )
        self.assertIsNotNone(queued)
        claimed = self.database.claim_email_replies()
        self.assertEqual(claimed[0]["from_address"], "support@modstoat.site")
        self.assertEqual(claimed[0]["mailbox_address"], "support@modstoat.site")
        self.assertEqual(claimed[0]["created_by"], "staffer@modstoat.site")

        dual_message = {**common, "message_id": "<dual@example.com>"}
        self.assertTrue(self.database.record_email_message(
            message_key="3" * 64,
            thread_key="c" * 64,
            recipient="admin@modstoat.site",
            mailbox_address="admin@modstoat.site",
            **dual_message,
        ))
        self.assertTrue(self.database.record_email_message(
            message_key="4" * 64,
            thread_key="d" * 64,
            recipient="support@modstoat.site",
            mailbox_address="support@modstoat.site",
            **dual_message,
        ))

    def test_global_ban_requests_require_owner_review_and_enforce_once(self) -> None:
        denied = self.database.create_global_ban_request(
            "01ADMINREQUESTDENIED", "Insufficient evidence", "staff@modstoat.site"
        )
        self.assertIsNone(self.database.get_global_ban("01ADMINREQUESTDENIED"))
        self.assertEqual(self.database.claim_dashboard_actions(), [])
        reviewed_denial = self.database.review_global_ban_request(
            denied["id"],
            "denied",
            "admin@modstoat.online",
            "Not enough context",
            reference_id=None,
            action_server_id="server-a",
            action_actor_id="owner-id",
        )
        self.assertEqual(reviewed_denial["status"], "denied")
        self.assertEqual(self.database.claim_dashboard_actions(), [])

        approved = self.database.create_global_ban_request(
            "01ADMINREQUESTAPPROVED", "Confirmed network abuse", "staff@modstoat.site"
        )
        with self.assertRaisesRegex(ValueError, "already awaiting review"):
            self.database.create_global_ban_request(
                "01ADMINREQUESTAPPROVED", "Duplicate request", "other@modstoat.site"
            )
        reviewed = self.database.review_global_ban_request(
            approved["id"],
            "approved",
            "admin@modstoat.online",
            "Approved after review",
            reference_id="REQ123",
            action_server_id="server-a",
            action_actor_id="owner-id",
        )
        self.assertEqual(reviewed["status"], "approved")
        self.assertEqual(reviewed["global_reference_id"], "REQ123")
        self.assertEqual(
            self.database.get_global_ban("01ADMINREQUESTAPPROVED").reason,
            "Confirmed network abuse",
        )
        actions = self.database.claim_dashboard_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action"], "owner_global_ban")
        self.assertEqual(actions[0]["payload"]["request_id"], approved["id"])
        self.database.finish_dashboard_action(
            actions[0]["id"], success=False, result={"error": "Temporary failure"}
        )
        failed = self.database.get_global_ban_request(approved["id"])
        self.assertEqual(failed["enforcement_status"], "failed")
        self.assertEqual(failed["enforcement_result"]["error"], "Temporary failure")
        retried = self.database.retry_global_ban_request_enforcement(approved["id"])
        self.assertEqual(retried["enforcement_status"], "pending")
        with self.assertRaisesRegex(ValueError, "Only failed"):
            self.database.retry_global_ban_request_enforcement(approved["id"])
        with self.assertRaisesRegex(ValueError, "already been reviewed"):
            self.database.review_global_ban_request(
                approved["id"],
                "approved",
                "admin@modstoat.online",
                "Double click",
                reference_id="REQ124",
                action_server_id="server-a",
                action_actor_id="owner-id",
            )

    def test_report_attachment_lookup_requires_matching_report(self) -> None:
        first = self.database.create_user_report(
            "server", "reporter", "target", "Reason one", "Evidence one"
        )
        second = self.database.create_user_report(
            "server", "reporter", "target", "Reason two", "Evidence two"
        )
        attachment = self.database.add_report_attachment(
            first, "proof.png", "image/png", b"proof"
        )

        self.assertIsNotNone(self.database.get_report_attachment(
            attachment, report_id=first
        ))
        self.assertIsNone(self.database.get_report_attachment(
            attachment, report_id=second
        ))

    def test_privacy_delete_retains_global_ban_approval_requests(self) -> None:
        subject = "01PRIVACYBANREQUESTTARGET123"
        request = self.database.create_global_ban_request(
            subject, "Pending owner review", "staffer@modstoat.site"
        )

        export = self.database.export_privacy_data(subject, "user")
        request_table = next(
            table
            for table in export["tables"]
            if table["table"] == "global_ban_requests"
        )
        self.assertEqual(request_table["retained_count"], 1)

        result = self.database.delete_privacy_data(subject)
        self.assertGreaterEqual(result["retained_records"], 1)
        retained = self.database.list_global_ban_requests()
        self.assertEqual(retained[0]["id"], request["id"])
        self.assertEqual(retained[0]["status"], "pending")

    def test_concurrent_startup_serializes_legacy_schema_migrations(self) -> None:
        legacy_path = Path(self.directory.name, "concurrent-legacy.db")
        connection = sqlite3.connect(legacy_path)
        connection.executescript(
            """
            CREATE TABLE dashboard_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                action TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                created_at TEXT NOT NULL,
                processed_at TEXT
            );
            CREATE TABLE admin_login_failures (
                scope TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0,
                window_started_at TEXT NOT NULL,
                locked_until TEXT,
                PRIMARY KEY (scope, key_hash)
            );
            """
        )
        connection.close()
        barrier = Barrier(6)

        def open_database(_: int) -> None:
            barrier.wait()
            database = ModerationDatabase(legacy_path)
            database.close()

        with ThreadPoolExecutor(max_workers=6) as executor:
            list(executor.map(open_database, range(6)))

        migrated = sqlite3.connect(legacy_path)
        try:
            action_columns = {
                row[1] for row in migrated.execute("PRAGMA table_info(dashboard_actions)")
            }
            failure_columns = {
                row[1]
                for row in migrated.execute("PRAGMA table_info(admin_login_failures)")
            }
        finally:
            migrated.close()
        self.assertIn("claim_token", action_columns)
        self.assertIn("subject_hash", failure_columns)

    def test_admin_account_delivery_is_fail_closed_versioned_and_secret_free(self) -> None:
        user_id = "01H00000000000000000000000"
        pending = self.database.provision_admin_dashboard_account(
            user_id, "admin@modstoat.online"
        )
        self.assertFalse(pending["active"])
        action = self.database.get_dashboard_action(pending["delivery_action_id"])
        self.assertEqual(
            action["payload"],
            {"user_id": user_id, "password_version": 1},
        )
        serialized = json.dumps(action)
        self.assertNotIn("password_hash", serialized)
        self.assertNotIn("nonce", serialized)
        with self.assertRaises(ValueError):
            self.database.provision_admin_dashboard_account(
                user_id, "admin@modstoat.online"
            )

        password = "SM-random-generated-password"
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=7)
        ).isoformat(timespec="seconds")
        self.assertFalse(self.database.activate_admin_dashboard_account_credentials(
            user_id, 2, pending["delivery_action_id"], hash_password(password), expires_at
        ))
        password_hash = hash_password(password)
        self.assertTrue(self.database.activate_admin_dashboard_account_credentials(
            user_id, 1, pending["delivery_action_id"], password_hash, expires_at
        ))
        active = self.database.get_admin_dashboard_account(
            user_id, include_password_hash=True
        )
        self.assertTrue(active["active"])
        self.assertTrue(verify_password(password, active["password_hash"]))

        self.database.create_admin_dashboard_session(
            "session-one", user_id, 1, expires_at
        )
        self.assertIsNotNone(self.database.get_admin_dashboard_session("session-one"))
        replacement = self.database.provision_admin_dashboard_account(
            user_id, "admin@modstoat.online", replace=True
        )
        self.assertEqual(replacement["password_version"], 2)
        self.assertFalse(replacement["active"])
        self.assertIsNone(self.database.get_admin_dashboard_session("session-one"))
        self.assertFalse(self.database.activate_admin_dashboard_account_credentials(
            user_id, 1, pending["delivery_action_id"], password_hash, expires_at
        ))

        revoked = self.database.revoke_admin_dashboard_account(
            user_id, "admin@modstoat.online"
        )
        self.assertFalse(revoked["active"])
        self.assertIsNotNone(revoked["revoked_at"])
        replacement_action = self.database.get_dashboard_action(
            replacement["delivery_action_id"]
        )
        self.assertEqual(replacement_action["status"], "failed")

    def test_admin_credential_activation_requires_the_current_action_claim(self) -> None:
        user_id = "01H00000000000000000000008"
        pending = self.database.provision_admin_dashboard_account(
            user_id, "admin@modstoat.online"
        )
        first = self.database.claim_dashboard_actions()[0]
        self.database.connection.execute(
            "UPDATE dashboard_actions "
            "SET claimed_at=datetime('now', '-6 minutes') WHERE id=?",
            (pending["delivery_action_id"],),
        )
        self.database.connection.commit()
        second = self.database.claim_dashboard_actions()[0]
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=7)
        ).isoformat(timespec="seconds")
        password_hash = hash_password("SM-current-claim-password")
        self.assertFalse(self.database.admin_dashboard_delivery_is_current(
            user_id,
            1,
            pending["delivery_action_id"],
            claim_token=first["claim_token"],
        ))
        self.assertFalse(self.database.activate_admin_dashboard_account_credentials(
            user_id,
            1,
            pending["delivery_action_id"],
            password_hash,
            expires_at,
            claim_token=first["claim_token"],
        ))
        self.assertTrue(self.database.admin_dashboard_delivery_is_current(
            user_id,
            1,
            pending["delivery_action_id"],
            claim_token=second["claim_token"],
            renew_claim=True,
        ))
        self.assertTrue(self.database.activate_admin_dashboard_account_credentials(
            user_id,
            1,
            pending["delivery_action_id"],
            password_hash,
            expires_at,
            claim_token=second["claim_token"],
        ))


    def test_admin_privacy_delete_cancels_delivery_and_removes_login_failures(self) -> None:
        user_id = "01H00000000000000000000007"
        pending = self.database.provision_admin_dashboard_account(
            user_id, "admin@modstoat.online"
        )
        self.database.record_admin_login_failure(
            "user_ip",
            "keyed-rate-limit-value",
            max_attempts=8,
            subject_hash=admin_login_subject_hash(user_id),
        )
        exported = self.database.export_privacy_data(user_id, "user")
        table_names = {table["table"] for table in exported["tables"]}
        self.assertIn("admin_dashboard_accounts", table_names)
        self.assertIn("admin_login_failures", table_names)

        result = self.database.delete_privacy_data(user_id)

        self.assertGreaterEqual(result["deleted_records"], 3)
        self.assertIsNone(self.database.get_admin_dashboard_account(user_id))
        self.assertIsNone(
            self.database.get_dashboard_action(pending["delivery_action_id"])
        )
        self.assertIsNone(self.database.connection.execute(
            "SELECT 1 FROM admin_login_failures WHERE subject_hash=?",
            (admin_login_subject_hash(user_id),),
        ).fetchone())


if __name__ == "__main__":
    unittest.main()
