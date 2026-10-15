import asyncio
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from admin_credentials import hash_password, verify_password
from bot import ModerationBot
from database import ModerationDatabase


class AdminRotationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "rotation.db"
        self.db = ModerationDatabase(self.path)
        self.user_id = "01H00000000000000000000008"
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def grant(self, expiry, user_id=None):
        identifier = user_id or self.user_id
        pending = self.db.provision_admin_dashboard_account(identifier, "owner")
        action = self.db.claim_dashboard_actions()[0]
        self.db.activate_admin_dashboard_account_credentials(
            identifier, 1, pending["delivery_action_id"], hash_password("SM-old-password"),
            expiry.isoformat(timespec="seconds"), claim_token=action["claim_token"],
        )
        self.db.finish_dashboard_action(action["id"], success=True, claim_token=action["claim_token"])
        return pending

    def run_worker_once(self, dm):
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = self.db
        bot.moderation_settings = SimpleNamespace(dashboard_url="https://modstoat.site")
        bot.get_user = Mock(return_value=SimpleNamespace(bot=None))
        bot._resolve_user_tag = AsyncMock(return_value="staff#1200")
        bot._send_user_dm = dm
        claim = self.db.claim_dashboard_actions

        def claim_once():
            bot._closing = True
            return claim()

        with patch.object(self.db, "claim_dashboard_actions", side_effect=claim_once), patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())
        return bot

    def test_exact_seven_day_boundary_and_invalidation_are_atomic(self):
        due = self.now + timedelta(days=7)
        self.grant(due)
        self.db.create_admin_dashboard_session("old-session", self.user_id, 1, (due + timedelta(hours=1)).isoformat())
        self.assertIsNotNone(self.db.get_admin_dashboard_session("old-session"))
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=due - timedelta(seconds=1)), 0)
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=due), 1)
        account = self.db.get_admin_dashboard_account(self.user_id, include_password_hash=True)
        self.assertFalse(account["active"])
        self.assertEqual(account["password_hash"], "")
        self.assertEqual(account["password_version"], 2)
        self.assertIsNone(self.db.get_admin_dashboard_session("old-session"))
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=due + timedelta(days=1)), 0)
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=due + timedelta(days=1)), 0)
        self.assertEqual(self.db.get_admin_dashboard_account(self.user_id)["delivery_action_id"], account["delivery_action_id"])

    def test_concurrent_schedulers_queue_one_rotation(self):
        self.grant(self.now - timedelta(days=2))
        barrier = Barrier(2)

        def schedule():
            database = ModerationDatabase(self.path)
            try:
                barrier.wait(timeout=10)
                return database.queue_due_admin_password_rotations()
            finally:
                database.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(schedule), pool.submit(schedule)
            self.assertEqual(first.result() + second.result(), 1)
        self.assertEqual(self.db.get_admin_dashboard_account(self.user_id)["password_version"], 2)

    def test_revoked_and_pending_accounts_never_rotate(self):
        self.grant(self.now - timedelta(days=10))
        self.db.revoke_admin_dashboard_account(self.user_id, "owner")
        pending_id = "01H00000000000000000000009"
        pending = self.db.provision_admin_dashboard_account(pending_id, "owner")
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=self.now + timedelta(days=50)), 0)
        self.assertEqual(self.db.get_admin_dashboard_account(pending_id)["delivery_action_id"], pending["delivery_action_id"])
        self.assertIsNotNone(self.db.get_admin_dashboard_account(self.user_id)["revoked_at"])

    def test_worker_catches_up_without_login_dms_and_repeats_after_seven_days(self):
        self.grant(self.now - timedelta(days=2))
        dm = AsyncMock(return_value=True)
        with patch("bot.generate_temporary_password", return_value="SM-new-delivered-password"):
            self.run_worker_once(dm)
        dm.assert_awaited_once()
        self.assertIn("automatically reset after 7 days", dm.await_args.args[2])
        self.assertIn("SM-new-delivered-password", dm.await_args.args[2])
        self.assertTrue(dm.await_args.kwargs["sensitive"])
        account = self.db.get_admin_dashboard_account(self.user_id, include_password_hash=True)
        self.assertTrue(account["active"])
        self.assertTrue(verify_password("SM-new-delivered-password", account["password_hash"]))
        self.assertFalse(verify_password("SM-old-password", account["password_hash"]))
        expiry = datetime.fromisoformat(account["password_expires_at"])
        self.assertLess(abs((expiry - datetime.now(timezone.utc) - timedelta(days=7)).total_seconds()), 10)
        stored_action = self.db.get_dashboard_action(account["delivery_action_id"])
        self.assertEqual(stored_action["status"], "completed")
        self.assertNotIn("SM-new-delivered-password", json.dumps(stored_action))
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=expiry - timedelta(seconds=1)), 0)
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=expiry), 1)
        self.assertEqual(self.db.get_admin_dashboard_account(self.user_id)["password_version"], 3)

    def test_failed_dm_retries_durably_without_persisting_or_logging_secret(self):
        self.grant(self.now - timedelta(seconds=5))
        with patch("bot.generate_temporary_password", return_value="SM-sensitive-secret"), self.assertLogs("stoat_moderator", level="WARNING") as captured:
            self.run_worker_once(AsyncMock(side_effect=RuntimeError("transport echoed SM-sensitive-secret")))
        account = self.db.get_admin_dashboard_account(self.user_id, include_password_hash=True)
        self.assertFalse(account["active"])
        self.assertEqual(account["password_hash"], "")
        action = self.db.get_dashboard_action(account["delivery_action_id"])
        self.assertEqual(action["status"], "pending")
        self.assertEqual(action["payload"]["retry_count"], 1)
        self.assertGreater(datetime.fromisoformat(action["not_before"]), self.now + timedelta(minutes=4))
        self.assertNotIn("SM-sensitive-secret", json.dumps(action) + str(captured.output))
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.assertEqual(self.db.claim_dashboard_actions(), [])
        self.db.connection.execute("UPDATE dashboard_actions SET not_before=NULL WHERE id=?", (action["id"],))
        self.db.connection.commit()
        dm = AsyncMock(return_value=True)
        self.run_worker_once(dm)
        dm.assert_awaited_once()
        self.assertTrue(self.db.get_admin_dashboard_account(self.user_id)["active"])
        self.assertEqual(self.db.get_admin_dashboard_account(self.user_id)["password_version"], 2)

    def test_stale_retry_and_revoked_delivery_cannot_reenable_access(self):
        pending = self.db.provision_admin_dashboard_account(self.user_id, "owner")
        claim = self.db.claim_dashboard_actions()[0]
        self.assertFalse(self.db.defer_admin_credential_delivery(claim["id"], claim_token="old-claim", retry_count=1, delay_seconds=300))
        self.db.revoke_admin_dashboard_account(self.user_id, "owner")
        self.assertFalse(self.db.defer_admin_credential_delivery(claim["id"], claim_token=claim["claim_token"], retry_count=1, delay_seconds=300))
        self.assertFalse(self.db.activate_admin_dashboard_account_credentials(self.user_id, 1, pending["delivery_action_id"], "hash", (self.now + timedelta(days=7)).isoformat(), claim_token=claim["claim_token"]))
        self.assertEqual(self.db.queue_due_admin_password_rotations(now=self.now + timedelta(days=8)), 0)

    def test_sensitive_dm_transport_error_is_not_logged(self):
        bot = ModerationBot.__new__(ModerationBot)
        user = SimpleNamespace(open_dm=AsyncMock(side_effect=RuntimeError("echoed SM-private")))
        with self.assertLogs("stoat_moderator", level="WARNING") as captured:
            delivered = asyncio.run(bot._send_user_dm(self.user_id, "Credentials", "SM-private", user=user, sensitive=True))
        self.assertFalse(delivered)
        self.assertNotIn("SM-private", str(captured.output))


if __name__ == "__main__":
    unittest.main()

