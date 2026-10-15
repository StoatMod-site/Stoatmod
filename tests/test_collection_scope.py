"""Regression coverage for moderated-content-only storage and local safety logs."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from bot import ModerationBot
from database import ModerationDatabase


class MessageCollectionTests(unittest.IsolatedAsyncioTestCase):
    def bot(self):
        bot = object.__new__(ModerationBot)
        bot._bot_deleted_ids = {"deleted"}
        bot.database = SimpleNamespace(add_event=Mock())
        bot.send_log = AsyncMock()
        return bot

    async def test_deleting_messages_never_reads_or_records_their_content(self):
        bot = self.bot()
        await bot.handle_message_delete(SimpleNamespace(message_id="deleted"))
        await bot.handle_message_delete_bulk(SimpleNamespace(message_ids=["another"]))
        bot.database.add_event.assert_not_called()
        bot.send_log.assert_not_awaited()
        self.assertFalse(bot._bot_deleted_ids)

    async def test_edit_is_reassessed_without_a_before_after_archive(self):
        bot = self.bot()
        bot.get_channel = Mock(return_value=SimpleNamespace(server_id="server"))
        bot.message_is_in_scope = Mock(return_value=True)
        bot._message_author_is_moderator = AsyncMock(return_value=False)
        bot.handle_link_filter = AsyncMock(return_value=False)
        bot._mass_mention_reason = Mock(return_value=None)
        bot.dispatch_scan = Mock()
        message = SimpleNamespace(id="message", content="new content", get_server=lambda: (None, "server"))
        await bot.handle_message_update(SimpleNamespace(
            message=SimpleNamespace(content=message.content, channel_id="channel"),
            before=SimpleNamespace(content="old content"), after=message))
        bot.dispatch_scan.assert_called_once_with(message)
        bot.database.add_event.assert_not_called()
        bot.send_log.assert_not_awaited()


class CollectionMigrationTests(unittest.TestCase):
    def test_legacy_archives_are_erased_without_removing_global_bans_or_local_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.db"
            db = ModerationDatabase(path)
            db.connection.execute("DELETE FROM app_metadata WHERE key='retired_message_archives_and_sharing_v1'")
            for kind in ["message_edited", "external_message_deletion", "external_message_deletion_bulk", "cross_server_ban"]:
                db.connection.execute("""INSERT INTO moderation_events(server_id,event_type,details_json,created_at)
                    VALUES('server',?,'{"original_content":"private old body"}','2026-01-01')""", (kind,))
            db.connection.execute("INSERT INTO server_daily_word_stats VALUES('server','2026-01-01','private',1)")
            db.connection.commit()
            db.add_global_ban("GLOBAL1", "user", "Global rule", "owner")
            db.add_event(server_id="server", event_type="member_ban", user_id="user", details={"reason": "Local action"})
            db.close()
            db = ModerationDatabase(path)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM moderation_events WHERE event_type!='member_ban'").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM server_daily_word_stats").fetchone()[0], 0)
            self.assertIsNotNone(db.get_global_ban("user"))
            self.assertTrue(db.list_dashboard_cases_for_user("server", "user"))
            for kind in ["message_edited", "external_message_deletion", "external_message_deletion_bulk", "cross_server_ban"]:
                self.assertEqual(db.add_event(server_id="server", event_type=kind, details={"original_content": "new body"}), 0)
            db.record_daily_message("server", "user", content="private words from ordinary messages")
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM server_daily_word_stats").fetchone()[0], 0)
            db.close()
