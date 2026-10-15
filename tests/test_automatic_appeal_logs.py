import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from appeal_privacy import APPEAL_PRIVACY_VERSION
from bot import DASHBOARD_DELIVERY_RETRY_DELAYS, ModerationBot
from database import ModerationDatabase


class AutomaticAppealLogTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.directory.name) / 'moderation.db')
        self.now = datetime.now(timezone.utc)
        warning = self.db.add_warning(
            server_id='server', user_id='author', moderator_id='bot',
            source='automatic', reason='Safety decision', message_id='message',
            original_content='Synthetic private message content',
        )
        self.case = self.db.get_warning_case('server', warning)
        self.appeal_id = self.db.create_appeal_access(
            'test-code-hash', 'author', 'moderation', self.case.reference_id, 'server',
        )
        self.db.submit_appeal(
            self.appeal_id, 'author', 'Synthetic private appeal statement',
            privacy_version=APPEAL_PRIVACY_VERSION,
        )
        self.db.connection.execute(
            'UPDATE appeals SET submitted_at=? WHERE id=?',
            ((self.now - timedelta(days=10)).isoformat(), self.appeal_id),
        )
        self.db.connection.commit()
        self.db.set_log_channel('server', 'logs')
        self.db.appeal_privacy.prune(now=self.now)

        self.bot = ModerationBot.__new__(ModerationBot)
        self.bot.database = self.db
        self.bot._last_heartbeat_write = float('inf')
        self.bot._send_user_dm = AsyncMock(return_value=True)
        self.bot._send_embed_pages = AsyncMock()
        self.bot._server_locale = Mock(return_value='en')
        self.channel = SimpleNamespace(id='logs')
        self.bot.get_channel = Mock(return_value=self.channel)

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def run_worker(self):
        claim = self.db.claim_dashboard_actions

        def claim_once():
            self.bot._closing = True
            return claim()

        self.bot._closing = False
        with patch.object(self.db, 'claim_dashboard_actions', side_effect=claim_once), \
             patch.object(self.db, 'queue_due_admin_password_rotations', return_value=0), \
             patch('bot.asyncio.sleep', new_callable=AsyncMock):
            asyncio.run(self.bot._run_dashboard_actions())

    def action(self, action_type):
        rows = self.db.connection.execute(
            'SELECT id FROM dashboard_actions WHERE action=?', (action_type,),
        ).fetchall()
        self.assertEqual(len(rows), 1)
        return self.db.get_dashboard_action(rows[0]['id'])

    def retry_now(self):
        with self.db.connection:
            self.db.connection.execute(
                "UPDATE dashboard_actions SET not_before=NULL WHERE status='pending'"
            )

    def assert_content_deleted(self):
        appeal = self.db.get_appeal(self.appeal_id)
        self.assertEqual(appeal['status'], 'denied')
        self.assertIsNone(appeal['statement'])
        self.assertEqual(appeal['messages'], [])
        self.assertIsNone(self.db.connection.execute(
            'SELECT original_content FROM warnings'
        ).fetchone()[0])
        stored = ' '.join(str(tuple(row)) for row in self.db.connection.execute(
            'SELECT payload_json,result_json FROM dashboard_actions'
        ))
        self.assertNotIn('Synthetic private', stored)

    def test_timeout_logs_outcome_without_content_and_only_once(self):
        self.run_worker()
        self.bot.get_channel.assert_called_once_with('logs', partial=True)
        self.bot._send_embed_pages.assert_awaited_once()
        channel, title, description, color = self.bot._send_embed_pages.await_args.args
        self.assertIs(channel, self.channel)
        self.assertEqual(title, 'Appeal automatically rejected')
        self.assertIn(self.case.reference_id, description)
        self.assertIn('<@author>', description)
        self.assertIn('Stoatmod (automatic)', description)
        self.assertIn('10 days of submission', description)
        self.assertIn('original moderation decision remains in place', description)
        self.assertIn('deleted from Stoatmod', description)
        self.assertNotIn('STOATMOD_APPEAL_TIMEOUT', description)
        self.assertNotIn('Synthetic private', description)
        self.assertEqual(self.action('log_automatic_appeal_decision')['status'], 'completed')
        self.assert_content_deleted()
        self.db.appeal_privacy.prune(now=self.now + timedelta(days=1))
        self.run_worker()
        self.bot._send_embed_pages.assert_awaited_once()
        self.bot._send_user_dm.assert_awaited_once()

    def test_no_configured_log_channel_is_skipped_successfully(self):
        with self.db.connection:
            self.db.connection.execute("UPDATE server_settings SET log_channel_id=NULL")
        self.run_worker()
        self.bot.get_channel.assert_not_called()
        self.bot._send_embed_pages.assert_not_awaited()
        action = self.action('log_automatic_appeal_decision')
        self.assertEqual(action['status'], 'completed')
        self.assertIn('No moderation log channel', action['result']['skipped'])
        self.assert_content_deleted()

    def test_log_failure_retries_without_repeating_dm_or_delaying_deletion(self):
        self.bot._send_embed_pages.side_effect = [RuntimeError('Unavailable'), None]
        with self.assertLogs('stoat_moderator', level='WARNING'):
            self.run_worker()
        action = self.action('log_automatic_appeal_decision')
        self.assertEqual(action['status'], 'pending')
        self.assertEqual(action['payload']['retry_count'], 1)
        self.assertTrue(action['not_before'])
        self.assert_content_deleted()
        self.retry_now()
        self.run_worker()
        self.assertEqual(self.action('log_automatic_appeal_decision')['status'], 'completed')
        self.assertEqual(self.bot._send_embed_pages.await_count, 2)
        self.bot._send_user_dm.assert_awaited_once()

    def test_dm_exception_does_not_prevent_channel_log(self):
        self.bot._send_user_dm.side_effect = RuntimeError('DM unavailable')
        with self.assertLogs('stoat_moderator', level='ERROR'):
            self.run_worker()
        self.bot._send_embed_pages.assert_awaited_once()
        self.assertEqual(self.action('resolve_appeal')['status'], 'failed')
        self.assertEqual(self.action('log_automatic_appeal_decision')['status'], 'completed')
        self.assert_content_deleted()

    def test_log_cannot_be_sent_to_another_server(self):
        self.db.set_log_channel('other-server', 'other-logs')
        with self.db.connection:
            self.db.connection.execute(
                "UPDATE dashboard_actions SET server_id='other-server' "
                "WHERE action='log_automatic_appeal_decision'"
            )
        with self.assertLogs('stoat_moderator', level='WARNING'):
            self.run_worker()
        self.bot._send_embed_pages.assert_not_awaited()

    def test_exhausted_delivery_retries_are_recorded_as_failed(self):
        self.bot._send_embed_pages.side_effect = RuntimeError('Unavailable')
        for _ in range(1 + len(DASHBOARD_DELIVERY_RETRY_DELAYS)):
            with self.assertLogs('stoat_moderator', level='WARNING'):
                self.run_worker()
            self.retry_now()
        self.assertEqual(self.action('log_automatic_appeal_decision')['status'], 'failed')
        self.bot._send_user_dm.assert_awaited_once()
        self.assert_content_deleted()


class AppealSubmissionNotificationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.directory.name) / 'moderation.db')
        warning = self.db.add_warning(
            server_id='server', user_id='author', moderator_id='bot',
            source='automatic', reason='Safety decision', message_id='message',
            original_content='Synthetic private message content',
        )
        case = self.db.get_warning_case('server', warning)
        self.appeal_id = self.db.create_appeal_access(
            'submission-code-hash', 'author', 'moderation', case.reference_id,
            'server',
        )
        self.db.submit_appeal(
            self.appeal_id, 'author', 'Synthetic private appeal statement',
            privacy_version=APPEAL_PRIVACY_VERSION,
        )
        self.db.set_log_channel('server', 'logs')
        self.db.grant_dashboard_access('server', 'moderator', 'owner')
        self.db.appeal_notification_preference('server', 'moderator', True)
        self.db.grant_dashboard_access('server', 'disabled-moderator', 'owner')
        self.db.appeal_notification_preference(
            'server', 'disabled-moderator', False
        )
        self.db.appeal_notification_preference('server', 'no-access', True)
        self.action_id = self.db.enqueue_dashboard_action(
            'server', 'send_appeal_submitted_log', 'author',
            {'appeal_id': self.appeal_id},
        )

        self.bot = ModerationBot.__new__(ModerationBot)
        self.bot.database = self.db
        self.bot.moderation_settings = SimpleNamespace(
            dashboard_url='https://modstoat.site'
        )
        self.bot._last_heartbeat_write = float('inf')
        self.bot._send_user_dm = AsyncMock(return_value=True)
        self.bot._send_embed_pages = AsyncMock()
        self.bot._server_locale = Mock(return_value='en')
        self.channel = SimpleNamespace(id='logs')
        self.bot.get_channel = Mock(return_value=self.channel)

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def run_worker(self):
        claim = self.db.claim_dashboard_actions

        def claim_once():
            self.bot._closing = True
            return claim()

        self.bot._closing = False
        with patch.object(
            self.db, 'claim_dashboard_actions', side_effect=claim_once
        ), patch.object(
            self.db, 'queue_due_admin_password_rotations', return_value=0
        ), patch('bot.asyncio.sleep', new_callable=AsyncMock):
            asyncio.run(self.bot._run_dashboard_actions())

    def test_submission_dms_only_opted_in_moderators_with_access(self):
        self.assertEqual(
            self.db.appeal_notification_recipients('server'), ['moderator']
        )
        self.run_worker()

        self.bot._send_embed_pages.assert_awaited_once()
        self.bot._send_user_dm.assert_awaited_once()
        user_id, title, description = self.bot._send_user_dm.await_args.args
        self.assertEqual(user_id, 'moderator')
        self.assertIn('New moderation appeal', title)
        self.assertIn('CASE-', description)
        self.assertIn('author', description)
        self.assertIn('/dashboard?view=appeals', description)
        self.assertNotIn('Synthetic private message content', description)
        self.assertNotIn('Synthetic private appeal statement', description)
        self.assertTrue(self.bot._send_user_dm.await_args.kwargs['sensitive'])
        action = self.db.get_dashboard_action(self.action_id)
        self.assertEqual(action['status'], 'completed')
        self.assertEqual(action['result']['moderator_dms_sent'], 1)
        self.assertEqual(action['result']['moderator_dms_failed'], 0)

    def test_dm_failure_does_not_block_the_server_log_or_complete_action(self):
        self.bot._send_user_dm.return_value = False
        self.run_worker()

        self.bot._send_embed_pages.assert_awaited_once()
        action = self.db.get_dashboard_action(self.action_id)
        self.assertEqual(action['status'], 'completed')
        self.assertEqual(action['result']['moderator_dms_sent'], 0)
        self.assertEqual(action['result']['moderator_dms_failed'], 1)

    def test_revoking_dashboard_access_removes_the_preference(self):
        self.assertTrue(
            self.db.appeal_notification_preference('server', 'moderator')
        )
        self.db.revoke_dashboard_access('server', 'moderator', 'owner')
        self.assertFalse(
            self.db.appeal_notification_preference('server', 'moderator')
        )
        self.assertEqual(self.db.appeal_notification_recipients('server'), [])


if __name__ == '__main__':
    unittest.main()
