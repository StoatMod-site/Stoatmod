import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from bot import ModerationBot
from database import ModerationDatabase
from moderation import ModerationError, ModerationResult
from moderation_policy import CATEGORY_LABELS


class LocalModerationFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.directory.name)/'test.db')
        self.bot = object.__new__(ModerationBot)
        bot = self.bot
        bot._state = SimpleNamespace(my_id='bot')
        bot._bot_deleted_ids = set()
        bot.database = self.db
        bot.limiter = asyncio.Semaphore(1)
        bot.moderation_settings = SimpleNamespace(threshold=.9, max_image_bytes=10000, notification='silent')
        bot._message_author_is_moderator = AsyncMock(return_value=False)
        bot.log_result = Mock()
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.send_log = AsyncMock()
        bot._resolve_user_tag = AsyncMock(return_value='member')
        bot._warning_case_reference = Mock(return_value='ABCD2345')
        bot._appeal_instructions = Mock(return_value='')
        bot._active_warning_count = Mock(return_value=1)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.enforce_warning_policy = AsyncMock()
        self.server = SimpleNamespace(id='server', name='Test server')
        self.message = SimpleNamespace(id='message', author_id='member', channel_id='channel',
            content='test message', attachments=[], embeds=[],
            get_server=Mock(return_value=(self.server, 'server')),
            get_author_as_user=Mock(return_value=SimpleNamespace(id='member')),
            delete=AsyncMock())

    async def asyncTearDown(self):
        self.db.close()
        self.directory.cleanup()

    def set_scores(self, **scores):
        result = ModerationResult(True, {k: v >= .9 for k, v in scores.items()}, scores)
        self.bot.moderator = SimpleNamespace(classify_text=AsyncMock(return_value=result))
        return result

    async def test_personal_thoughts_support_only_in_every_policy_mode(self):
        for mode in ['enforce', 'review', 'observe']:
            self.db.save_moderation_policy_studio('server', mode, .9, [], 'owner')
            self.bot._support_dm_times = {}
            self.set_scores(**{'suicidal-thoughts': .98, 'self-harm/promotion': .2})
            await self.bot.scan_message(self.message)
        self.assertEqual(self.bot._send_user_dm.await_count, 3)
        for call in self.bot._send_user_dm.await_args_list:
            self.assertNotIn('removed', call.args[2].lower())
            self.assertIn('support message, not a warning', call.args[2].lower())
        # Enforce removes exposed content; review and observe leave it in place.
        self.message.delete.assert_awaited_once()
        self.bot.enforce_warning_policy.assert_not_awaited()
        self.bot.require_action_permissions.assert_awaited_once()
        self.assertEqual(self.bot.send_log.await_count, 3)
        support_log = self.bot.send_log.await_args_list[0]
        self.assertEqual(support_log.args[1], 'Deleted for support')
        self.assertEqual(support_log.kwargs['color'], '#3498DB')
        self.assertIn('98.00%', support_log.args[2])
        self.assertIn('**Warning added:** No', support_log.args[2])
        self.assertEqual(self.db.count_warnings('server', 'member'), 0)
        self.assertEqual(self.db.list_moderation_cases('server', 'member'), [])

    async def test_credentials_are_support_only_even_if_policy_requests_timeout(self):
        self.db.save_moderation_policy_studio('server', 'enforce', .9, [{
            'category': 'credentials',
            'threshold': .9,
            'enabled': False,
            'action': 'timeout',
            'timeout_seconds': 3600,
        }], 'owner')
        policy = {
            item['category']: item
            for item in self.db.get_moderation_policy_studio('server')['policies']
        }['credentials']
        self.assertTrue(policy['enabled'])
        self.assertTrue(policy['protected'])
        self.assertEqual(policy['action'], 'observe')
        self.assertIsNone(policy['timeout_seconds'])
        self.set_scores(credentials=.99)

        await self.bot.scan_message(self.message)

        self.message.delete.assert_awaited_once()
        self.bot._send_user_dm.assert_not_awaited()
        self.bot.enforce_warning_policy.assert_not_awaited()
        self.bot.require_action_permissions.assert_awaited_once()
        self.bot.send_log.assert_awaited_once()
        self.assertEqual(self.bot.send_log.await_args.args[1], 'Deleted for support')
        self.assertEqual(self.bot.send_log.await_args.kwargs['color'], '#3498DB')
        self.assertIn('99.00%', self.bot.send_log.await_args.args[2])
        self.assertEqual(self.db.count_warnings('server', 'member'), 0)
        self.assertEqual(self.db.list_moderation_cases('server', 'member'), [])

    async def test_encouraging_other_person_is_disciplinary_not_support(self):
        self.set_scores(**{'self-harm/promotion': .98, 'suicidal-thoughts': .01})
        await self.bot.scan_message(self.message)
        self.message.delete.assert_awaited_once()
        self.assertEqual(self.db.count_warnings('server', 'member'), 1)
        self.assertEqual(self.bot._send_user_dm.await_args.args[1], 'Your message violated the server moderation policy')

    async def test_mixed_support_and_violation_still_sends_support(self):
        self.set_scores(**{'suicidal-thoughts': .98, 'scams': .99})
        await self.bot.scan_message(self.message)
        self.assertEqual(self.bot._send_user_dm.await_count, 2)
        self.assertEqual(self.bot._send_user_dm.await_args_list[0].args[1], "We hope you're okay")
        self.message.delete.assert_awaited_once()
        self.assertEqual(self.bot.send_log.await_args.kwargs['color'], '#ED4245')
        self.assertNotIn('Support only', self.bot.send_log.await_args.args[2])
        self.assertEqual(self.db.count_warnings('server', 'member'), 1)

    async def test_support_deletion_failure_does_not_claim_the_message_was_removed(self):
        self.set_scores(credentials=.99)
        self.message.delete.side_effect = RuntimeError('deletion unavailable')
        with patch('bot.asyncio.sleep', new_callable=AsyncMock):
            await self.bot.scan_message(self.message)
        self.assertEqual(self.message.delete.await_count, 2)
        log = self.bot.send_log.await_args
        self.assertEqual(log.args[1], 'Support — deletion failed')
        self.assertEqual(log.kwargs['color'], '#3498DB')
        self.assertIn('99.00%', log.args[2])
        self.assertIn('**Warning added:** No', log.args[2])
        self.assertEqual(self.db.count_warnings('server', 'member'), 0)
        self.bot.enforce_warning_policy.assert_not_awaited()

    async def test_support_missing_permission_is_explicit_in_blue_log(self):
        self.set_scores(credentials=.99)
        self.bot.require_action_permissions.return_value = False
        await self.bot.scan_message(self.message)
        self.message.delete.assert_not_awaited()
        log = self.bot.send_log.await_args
        self.assertEqual(log.args[1], 'Support — message not deleted')
        self.assertEqual(log.kwargs['color'], '#3498DB')
        self.assertIn('missing Manage Messages', log.args[2])
        self.assertIn('Support only', log.args[2])
        self.assertEqual(self.db.count_warnings('server', 'member'), 0)

    async def test_regular_delete_only_policy_keeps_disciplinary_log(self):
        self.db.save_moderation_policy_studio('server', 'enforce', .9, [
            {'category': 'scams', 'action': 'delete', 'threshold': .9, 'enabled': True},
        ], 'owner')
        self.set_scores(scams=.99, credentials=.2)
        await self.bot.scan_message(self.message)
        log = self.bot.send_log.await_args
        self.assertEqual(log.args[1], 'Automatic policy deletion')
        self.assertEqual(log.kwargs['color'], '#ED4245')
        self.assertEqual(self.db.count_warnings('server', 'member'), 0)

    async def test_support_dm_cooldown_and_no_nickname_punishment(self):
        result = self.set_scores(**{'suicidal-thoughts': .98})
        await self.bot.scan_message(self.message)
        await self.bot.scan_message(self.message)
        self.bot._send_user_dm.assert_awaited_once()
        self.assertEqual(self.bot._enforced_display_name_categories('server', result), [])
        self.assertEqual(self.db.list_moderation_cases('server', 'member'), [])

    async def test_bad_provider_response_leaves_message_and_member_alone(self):
        self.bot.moderator = SimpleNamespace(classify_text=AsyncMock(side_effect=ModerationError('offline')))
        await self.bot.scan_message(self.message)
        self.message.delete.assert_not_awaited()
        self.bot._send_user_dm.assert_not_awaited()
        self.assertEqual(self.db.count_warnings('server', 'member'), 0)

    def test_action_exempt_result_keeps_scores_without_actions(self):
        result = ModerationResult(False, {'hate': True}, {'hate': .99}, action_exempt=True)
        self.assertEqual(self.bot._moderation_policy_matches('server', result), [])
        self.assertEqual(result.scores, {'hate': .99})
        self.assertIn('99.00%', self.bot._format_scores(result.scores))

    def test_custom_threshold_and_disabled_category_and_support_protection(self):
        self.db.save_moderation_policy_studio('server','enforce',.9,[
            {'category':'scams','threshold':.97,'enabled':True},
            {'category':'hate','enabled':False},
            {'category':'suicidal-thoughts','threshold':.95,'enabled':False,'action':'warn'},
        ],'owner')
        result = ModerationResult(True, {}, {'scams':.96,'hate':.99,'suicidal-thoughts':.95})
        matches = self.bot._moderation_policy_matches('server',result)
        self.assertEqual([m['category'] for m in matches],['suicidal-thoughts'])
        self.assertTrue(matches[0]['protected'])
        self.assertEqual(matches[0]['action'],'self_harm')
        for bad in [-.01, 1.01, float('nan'), float('inf')]:
            with self.assertRaises(ValueError): self.db.save_moderation_policy_studio('server','enforce',bad,[],'owner')
            with self.assertRaises(ValueError): self.db.save_moderation_policy_studio('server','enforce',.9,[{'category':'scams','threshold':bad}],'owner')

    async def test_saved_threshold_below_ninety_is_used_for_message_actions(self):
        self.db.save_moderation_policy_studio('server', 'enforce', .8, [], 'owner')
        result = self.set_scores(scams=.8, hate=.79)
        self.assertFalse(result.categories['scams'])
        await self.bot.scan_message(self.message)
        self.message.delete.assert_awaited_once()
        self.assertEqual(self.db.count_warnings('server', 'member'), 1)
        self.assertEqual([match["category"] for match in self.bot._moderation_policy_matches('server', result)], ['scams'])

    def test_zero_category_override_survives_reopening_and_is_not_inherited(self):
        self.db.save_moderation_policy_studio('server', 'enforce', .8, [
            {'category': 'scams', 'threshold': 0, 'action': 'delete'},
        ], 'owner')
        database_path = self.db.path
        self.db.close()
        self.db = ModerationDatabase(database_path)
        self.bot.database = self.db
        policy = self.db.get_moderation_policy_studio('server')
        self.assertEqual(policy['default_threshold'], .8)
        self.assertEqual(policy['minimum_threshold'], 0)
        self.assertEqual(self.db.get_moderation_threshold('server', .9), .8)
        matches = self.bot._moderation_policy_matches(
            'server', ModerationResult(False, {}, {'scams': 0, 'hate': .79})
        )
        self.assertEqual([(match['category'], match['threshold']) for match in matches], [('scams', 0)])
        self.assertEqual(self.db.get_moderation_policy_studio('another-server')['default_threshold'], .9)

    def test_local_category_migration_keeps_relevant_preferences_and_history(self):
        self.db.connection.execute("DELETE FROM app_metadata WHERE key='local_moderation_categories_v1'")
        self.db.connection.execute("INSERT INTO moderation_category_policies VALUES ('server','harassment',.96,'review',NULL,'owner','today')")
        self.db.connection.execute("INSERT INTO moderation_category_policies VALUES ('server','self-harm/intent',.98,'warn',NULL,'owner','today')")
        self.db.connection.execute("INSERT INTO moderation_category_policies VALUES ('server','violence/graphic',.97,'delete',NULL,'owner','today')")
        self.db.connection.execute("INSERT INTO moderation_category_policies VALUES ('server','sexual',.8,'warn',NULL,'owner','today')")
        self.db.disable_moderation_category('server','harassment','owner')
        self.db._migrate_local_moderation_categories()
        policy=self.db.get_moderation_policy_studio('server')
        items={x['category']:x for x in policy['policies']}
        self.assertEqual(set(items),set(CATEGORY_LABELS))
        self.assertEqual(items['hateful-conduct']['effective_threshold'],.96)
        self.assertFalse(items['hateful-conduct']['enabled'])
        self.assertEqual(items['suicidal-thoughts']['effective_threshold'],.98)
        self.assertEqual(items['suicidal-thoughts']['action'],'observe')
        self.assertEqual(items['violence']['effective_threshold'],.97)
        self.assertEqual(items['violence']['action'],'delete')
        self.assertEqual(items['sexual']['effective_threshold'], .8)
        self.assertTrue(items['credentials']['protected'])
        self.assertTrue(items['credentials']['enabled'])
        self.assertEqual(items['credentials']['action'],'observe')
        self.db._migrate_local_moderation_categories()
        self.assertEqual(policy,self.db.get_moderation_policy_studio('server'))


if __name__ == '__main__': unittest.main()
