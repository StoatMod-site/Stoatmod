"""Join protection options and the GifBox-only default link policy."""
import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from bot import ModerationBot
from database import ModerationDatabase
from join_limits import JoinLimitFlow, normalize_settings
from localization import localize_delivery


class DatabaseCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / "moderation.db"
        self.db = ModerationDatabase(self.path)

    def tearDown(self):
        self.db.close()
        self.folder.cleanup()


class LinkPolicyDefaultTests(DatabaseCase):
    def test_links_are_filtered_and_gifbox_allowed_by_default(self):
        self.assertTrue(self.db.get_link_protection("server"))
        self.assertTrue(self.db.get_allow_gifs("server"))
        # A row created by an unrelated setting gets the same defaults.
        self.db.set_spam_detection("server", True)
        self.assertTrue(self.db.get_link_protection("server"))
        self.assertTrue(self.db.get_allow_gifs("server"))

    def test_explicit_choices_persist(self):
        self.db.set_link_protection("server", False)
        self.db.set_allow_gifs("server", False)
        self.assertFalse(self.db.get_link_protection("server"))
        self.assertFalse(self.db.get_allow_gifs("server"))

    def test_migration_keeps_only_choices_a_moderator_made(self):
        connection = self.db.connection
        for server in ("untouched", "dashboard", "command"):
            connection.execute(
                "INSERT INTO server_settings(server_id, link_protection_enabled, allow_gifs_enabled,"
                " link_filter_enabled, gifbox_links_allowed) VALUES (?, 0, 0, 0, 0)",
                (server,),
            )
        self.db.add_event(server_id="dashboard", event_type="dashboard_settings_updated",
                          details={"changed": {"allow_gifs": False}})
        self.db.add_event(server_id="command", event_type="link_protection_disabled")
        connection.execute("DELETE FROM app_metadata WHERE key='link_policy_gifbox_default_v2'")
        connection.execute("UPDATE server_settings SET link_filter_enabled=1, gifbox_links_allowed=1")
        connection.commit()
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.assertEqual((self.db.get_link_protection("untouched"), self.db.get_allow_gifs("untouched")), (True, True))
        self.assertEqual((self.db.get_link_protection("dashboard"), self.db.get_allow_gifs("dashboard")), (True, False))
        self.assertEqual((self.db.get_link_protection("command"), self.db.get_allow_gifs("command")), (False, True))


class JoinLimitStoreTests(DatabaseCase):
    def test_on_by_default_for_one_day(self):
        store = self.db.join_limits
        self.assertEqual(store.settings("server"), {"enabled": True, "duration_seconds": 86400, "links": True, "attachments": True})
        self.assertTrue(store.active("server"))
        self.assertEqual(self.db.get_dashboard_settings("server", 0.9, None)["join_limits"]["duration_seconds"], 86400)

    def test_window_starts_ends_and_expires(self):
        store = self.db.join_limits
        now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
        expires = store.start("server", "member", now=now)
        self.assertEqual(expires, now + timedelta(days=1))
        self.assertEqual(store.expires_at("server", "member", now=now), expires)
        self.assertEqual(store.due(now=now), [])
        self.assertEqual(store.due(now=expires), [("server", "member")])
        self.assertIsNone(store.expires_at("server", "member", now=expires))
        self.assertTrue(store.end("server", "member"))
        self.assertFalse(store.end("server", "member"))

    def test_settings_validation(self):
        good = {"enabled": True, "duration_seconds": 3600, "links": True, "attachments": False}
        self.assertEqual(normalize_settings(good), good)
        for bad in ({**good, "duration_seconds": 60}, {**good, "duration_seconds": 31 * 86400},
                    {**good, "duration_seconds": True}, {**good, "links": "yes"}, {"enabled": True}):
            with self.assertRaises(ValueError):
                normalize_settings(bad)
        self.db.join_limits.set_settings("server", good)
        self.assertEqual(self.db.join_limits.settings("server"), good)

    def test_records_are_deleted_with_the_server(self):
        self.db.join_limits.start("server", "member")
        self.db.purge_server_data("server")
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM join_limit_members").fetchone()[0], 0)


class JoinLimitFlowTests(DatabaseCase):
    def setUp(self):
        super().setUp()
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = self.db
        bot._send_user_dm = AsyncMock(return_value=True)
        bot._delete_automatic_message = AsyncMock(return_value=True)
        bot._resolve_user_tag = AsyncMock(return_value="member#1")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.get_server = Mock(return_value=SimpleNamespace(name="Cafe"))
        self.bot = bot
        self.flow = JoinLimitFlow(bot)
        self.server = SimpleNamespace(id="server", name="Cafe")

    def message(self, content="", attachments=()):
        return SimpleNamespace(
            id="message", author_id="member", channel_id="channel", content=content, attachments=list(attachments),
            get_server=Mock(return_value=(self.server, "server")), get_author_as_user=Mock(return_value=None),
        )

    def join(self, *, bot_user=False):
        user = SimpleNamespace(bot=SimpleNamespace() if bot_user else None)
        asyncio.run(self.flow.on_join(self.server, SimpleNamespace(id="member"), user))

    def test_join_starts_protection_and_dms_the_member(self):
        self.join()
        self.assertIsNotNone(self.db.join_limits.expires_at("server", "member"))
        title, body = self.bot._send_user_dm.await_args.args[1:3]
        self.assertEqual(title, "You're under join protection")
        self.assertIn("can't send links or attachments", body)

    def test_bots_and_disabled_servers_are_not_limited(self):
        self.join(bot_user=True)
        self.assertIsNone(self.db.join_limits.expires_at("server", "member"))
        self.db.join_limits.set_settings("server", {"enabled": False, "duration_seconds": 86400, "links": True, "attachments": True})
        self.join()
        self.assertIsNone(self.db.join_limits.expires_at("server", "member"))
        self.bot._send_user_dm.assert_not_awaited()

    def test_links_and_attachments_are_removed_during_protection(self):
        self.join()
        for message, blocked in ((self.message("look https://gifbox.me/x"), "link"),
                                 (self.message("hi", attachments=[object()]), "attachment")):
            self.assertTrue(asyncio.run(self.flow.handle_message(message)))
            event = self.db.connection.execute(
                "SELECT details_json FROM moderation_events WHERE event_type='join_protection_deletion' ORDER BY id DESC"
            ).fetchone()
            self.assertEqual(json.loads(event[0])["blocked"], blocked)
        self.assertFalse(asyncio.run(self.flow.handle_message(self.message("hello there"))))
        # One reminder DM, not one per removed message.
        titles = [call.args[1] for call in self.bot._send_user_dm.await_args_list]
        self.assertEqual(titles.count("Message removed: join protection"), 1)

    def test_members_who_were_not_protected_are_not_affected(self):
        self.assertFalse(asyncio.run(self.flow.handle_message(self.message("https://example.com"))))

    def test_expiry_dm_follows_the_server_link_policy(self):
        self.join()
        later = datetime.now(timezone.utc) + timedelta(days=1, minutes=1)
        self.assertEqual(asyncio.run(self.flow.expire_due(now=later)), 1)
        title, body = self.bot._send_user_dm.await_args.args[1:3]
        self.assertEqual(title, "Join protection has ended")
        self.assertIn("You can now send attachments.", body)
        self.assertIn("only GifBox links are allowed", body)
        self.assertIsNone(self.db.join_limits.expires_at("server", "member"))

        self.db.set_link_protection("server", False)
        self.join()
        asyncio.run(self.flow.expire_due(now=later + timedelta(days=2)))
        self.assertIn("You can now send links and attachments.", self.bot._send_user_dm.await_args.args[2])

    def test_leaving_ends_protection_without_a_dm(self):
        self.join()
        self.bot._send_user_dm.reset_mock()
        self.flow.on_leave("server", "member")
        self.assertIsNone(self.db.join_limits.expires_at("server", "member"))
        self.assertEqual(asyncio.run(self.flow.expire_due(now=datetime.now(timezone.utc) + timedelta(days=2))), 0)
        self.bot._send_user_dm.assert_not_awaited()

    def test_dms_are_translated(self):
        title, body = localize_delivery(
            "fr", "Join protection has ended",
            "Your join protection in **Cafe** has ended. You can now send attachments."
            "\n\nThis server's link rules still apply to everyone: only GifBox links are allowed.",
        )
        self.assertEqual(title, "La protection d’arrivée est terminée")
        self.assertNotIn("You can", body)
        self.assertIn("seuls les liens GifBox", body)


if __name__ == "__main__":
    unittest.main()
