import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from bot import ModerationBot
from database import ModerationDatabase


class ServerIdentityRefreshTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = ModerationDatabase(Path(self.directory.name) / "test.db")
        self.addCleanup(self.db.close)
        self.db.update_dashboard_server_snapshot(
            "server-a", "Old name", 234, [("channel-a", "General")],
            [("role-a", "Moderator", True)], [("category-a", "Channels")],
            "https://cdn.stoatusercontent.com/icons/old",
            {"available": True, "missing": []}, owner_id="owner-a",
            server_banner_url="https://cdn.stoatusercontent.com/banners/old",
        )
        self.bot = ModerationBot.__new__(ModerationBot)
        self.bot.database = self.db

    def snapshot(self):
        return dict(self.db.connection.execute(
            "SELECT * FROM dashboard_server_snapshots WHERE server_id='server-a'"
        ).fetchone())

    def server(self, icon="new", banner="new"):
        def asset(kind, value):
            return None if value is None else SimpleNamespace(url=lambda: f"https://cdn.stoatusercontent.com/{kind}/{value}")
        return SimpleNamespace(
            id="server-a", name="New name", icon=asset("icons", icon),
            banner=asset("banners", banner), members={},
        )

    def test_update_uses_after_state_without_overwriting_counts_or_permissions(self):
        before = self.snapshot()
        self.bot.fetch_server = AsyncMock()
        event = SimpleNamespace(server=SimpleNamespace(id="server-a"), after=self.server())
        asyncio.run(self.bot.handle_server_update(event))
        after = self.snapshot()
        self.assertEqual(after["server_name"], "New name")
        self.assertTrue(after["server_icon_url"].endswith("/icons/new"))
        self.assertTrue(after["server_banner_url"].endswith("/banners/new"))
        for field in before.keys() - {"server_name", "server_icon_url", "server_banner_url", "updated_at"}:
            self.assertEqual(after[field], before[field], field)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM dashboard_channels").fetchone()[0], 1)
        self.bot.fetch_server.assert_not_awaited()

    def test_removing_images_clears_both_saved_urls(self):
        asyncio.run(self.bot.handle_server_update(SimpleNamespace(
            server=SimpleNamespace(id="server-a"), after=self.server(None, None),
        )))
        self.assertIsNone(self.snapshot()["server_icon_url"])
        self.assertIsNone(self.snapshot()["server_banner_url"])

    def test_missing_cache_fetches_full_server_and_failures_preserve_previous_images(self):
        self.bot.fetch_server = AsyncMock(return_value=self.server())
        event = SimpleNamespace(server=SimpleNamespace(id="server-a"), after=None)
        asyncio.run(self.bot.handle_server_update(event))
        self.bot.fetch_server.assert_awaited_once_with("server-a")
        before = self.snapshot()
        self.bot.fetch_server = AsyncMock(side_effect=RuntimeError("temporary outage"))
        with patch("bot.logger.exception"):
            asyncio.run(self.bot.handle_server_update(event))
        self.assertEqual(self.snapshot(), before)

    def test_unchanged_identity_keeps_timestamp_and_unknown_servers_are_not_created(self):
        before = self.snapshot()
        self.db.update_dashboard_server_identity("server-a", before["server_name"], before["server_icon_url"], before["server_banner_url"])
        self.assertEqual(before, self.snapshot())
        self.db.update_dashboard_server_identity("unknown", "Unknown", None, None)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM dashboard_server_snapshots").fetchone()[0], 1)

    def test_ready_repairs_offline_changes_without_extra_network_requests(self):
        self.bot.moderation_settings = SimpleNamespace(local_ai_expected_version="test")
        for name in ("start_status_rotation", "start_dashboard_action_worker", "start_global_ban_sync_worker", "start_dashboard_member_refresh_worker", "update_bot_heartbeat"):
            setattr(self.bot, name, Mock())
        self.bot.reject_blacklisted_server = AsyncMock(return_value=False)
        self.bot.resume_captcha_challenges = AsyncMock()
        self.bot.fetch_server = AsyncMock()
        event = SimpleNamespace(me=SimpleNamespace(id="bot", tag="bot#0001"), servers=[self.server()], channels=[])
        with patch("bot.logger.info"):
            asyncio.run(self.bot._run_ready_reconciliation(event))
        self.assertEqual(self.snapshot()["server_name"], "New name")
        self.bot.fetch_server.assert_not_awaited()

    def test_periodic_refresh_repairs_identity_even_if_member_request_fails(self):
        self.bot._fetch_complete_dashboard_members = AsyncMock(return_value=None)
        with patch.object(ModerationBot, "servers", new_callable=PropertyMock, return_value={"server-a": self.server()}):
            asyncio.run(self.bot.refresh_all_dashboard_member_counts())
        self.assertTrue(self.snapshot()["server_banner_url"].endswith("/banners/new"))
        self.assertEqual(self.snapshot()["member_count"], 234)


if __name__ == "__main__":
    unittest.main()
