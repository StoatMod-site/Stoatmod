from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from types import SimpleNamespace
from unittest.mock import Mock

from aiohttp.test_utils import TestClient, TestServer

from database import ModerationDatabase
from api.server import DATABASE_KEY, VERIFICATION_PRIVACY_VERSION, create_app
from api.server import _validate_turnstile
from bot import ModerationBot


class CollectionRetirementTests(unittest.TestCase):
    def test_legacy_migration_erases_copies_and_identifiers_without_destroying_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy.db'
            db = ModerationDatabase(path)
            db.connection.execute("DELETE FROM app_metadata WHERE key='privacy_retired_collection_20261001_v1'")
            db.connection.execute("INSERT INTO user_ip_addresses VALUES (?,?,?,?,?,?)", ('203.0.113.44','user','server','verification','2026-09-01','2026-09-01'))
            db.connection.execute("INSERT INTO user_ip_fingerprints VALUES (?,?,?,?,?,?)", ('legacy-fingerprint','user','server','verification','2026-09-01','2026-09-01'))
            # A retired developer webhook table from an old release still holds a copied message.
            db.connection.execute("CREATE TABLE dev_webhook_events(id INTEGER PRIMARY KEY, event_kind TEXT, payload_json TEXT, created_at TEXT)")
            db.connection.execute("INSERT INTO dev_webhook_events(event_kind,payload_json,created_at) VALUES ('moderation_event',?,?)", (json.dumps({'content':'private copied message'}),'2026-09-01'))
            db.connection.commit()
            db.add_event(server_id='server',event_type='join_web_verification_passed',user_id='user',details={'risk':{'vpn':True},'ip_address':'203.0.113.44','alt_detection':{'linked_user_ids':['other']},'result':'passed'})
            db.enqueue_dashboard_action('server','moderate_member','STOATMOD_ALT_DETECTION',{'source':'alt_detection','action':'ban','user_id':'user'})
            db.connection.execute("INSERT INTO server_settings(server_id,join_protection_enabled,captcha_all_members_enabled) VALUES ('server',1,1)")
            db.connection.commit()
            db.close()
            db = ModerationDatabase(path)
            self.assertIsNone(db.connection.execute("SELECT name FROM sqlite_master WHERE name='dev_webhook_events'").fetchone())
            for table in ('user_ip_addresses','user_ip_fingerprints','dashboard_actions'):
                self.assertEqual(db.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],0,table)
            details=json.loads(db.connection.execute('SELECT details_json FROM moderation_events').fetchone()[0])
            self.assertEqual(details,{'result':'passed'})
            self.assertFalse(db.get_join_protection('server'))
            self.assertFalse(db.get_captcha_all_members('server'))
            db.set_join_protection('server',True)
            db.close()
            db=ModerationDatabase(path)
            self.assertTrue(db.get_join_protection('server'))
            self.assertFalse(db.get_captcha_all_members('server'))
            db.close()

    def test_old_schema_defaults_do_not_enable_join_captcha(self):
        db=ModerationDatabase(':memory:')
        db.connection.execute("INSERT INTO server_settings(server_id,join_protection_enabled,captcha_all_members_enabled) VALUES ('old-default',1,1)")
        db.connection.commit()
        self.assertFalse(db.get_join_protection('old-default'))
        self.assertFalse(db.get_captcha_all_members('old-default'))
        db.set_captcha_all_members('old-default',True)
        self.assertTrue(db.get_captcha_all_members('old-default'))
        self.assertFalse(db.get_join_protection('old-default'))
        db.close()

    def test_verification_retention_keeps_current_records_and_removes_expired(self):
        db=ModerationDatabase(':memory:')
        db.record_verification_consent('old','server','user',VERIFICATION_PRIVACY_VERSION)
        db.record_verification_consent('current','server','user',VERIFICATION_PRIVACY_VERSION)
        db.connection.execute("UPDATE verification_consents SET expires_at='2000-01-01' WHERE challenge_hash='old'")
        db.connection.commit()
        db.add_event(server_id='server',event_type='join_web_verification_passed')
        db.connection.execute("UPDATE moderation_events SET created_at='2000-01-01'")
        db.connection.commit()
        db.prune_verification_privacy_data()
        self.assertEqual(db.connection.execute('SELECT challenge_hash FROM verification_consents').fetchone()[0],'current')
        self.assertEqual(db.connection.execute('SELECT COUNT(*) FROM moderation_events').fetchone()[0],0)
        db.close()


class VerificationPrivacyTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_verification_does_not_resume_old_expiry_timer(self):
        bot=ModerationBot.__new__(ModerationBot)
        challenge=SimpleNamespace(server_id='server',user_id='user')
        bot.database=SimpleNamespace(list_captcha_challenges=lambda:[challenge],get_join_protection=lambda _:False,get_captcha_all_members=lambda _:False)
        bot._recover_unissued_captcha=AsyncMock()
        bot._schedule_captcha_expiry=Mock()
        await bot.resume_captcha_challenges()
        bot._recover_unissued_captcha.assert_awaited_once_with(challenge,disabled=True)
        bot._schedule_captcha_expiry.assert_not_called()

    async def test_turnstile_request_omits_ip_and_checks_action(self):
        response=AsyncMock()
        response.status=200
        response.json=AsyncMock(return_value={'success':True,'action':'join-verification'})
        response.__aenter__.return_value=response
        session=AsyncMock()
        session.__aenter__.return_value=session
        session.post=Mock(return_value=response)
        with patch('api.server.ClientSession',return_value=session),patch('api.server.TURNSTILE_SECRET_KEY','test-secret'):
            self.assertTrue(await _validate_turnstile('test-response',expected_action='join-verification'))
            self.assertEqual(session.post.call_args.kwargs['data'],{'secret':'test-secret','response':'test-response'})
            response.json.return_value={'success':True,'action':'user-report'}
            self.assertFalse(await _validate_turnstile('test-response',expected_action='join-verification'))

    async def asyncSetUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.client=TestClient(TestServer(create_app(str(Path(self.directory.name)/'db.sqlite'))))
        await self.client.start_server()
        self.db=self.client.app[DATABASE_KEY]
        self.token='synthetic-private-verification-token-0123456789'
        self.db.set_web_verification_challenge('server','user',hashlib.sha256(self.token.encode()).hexdigest(),(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat())

    async def asyncTearDown(self):
        await self.client.close()
        self.directory.cleanup()

    def payload(self):
        return {'token':self.token,'turnstile_token':'synthetic-captcha','privacy_policy_agreed':True,'privacy_policy_version':VERIFICATION_PRIVACY_VERSION}

    async def test_consent_is_strict_and_precedes_provider_processing(self):
        with patch('api.server._validate_turnstile',new_callable=AsyncMock) as provider, patch('api.server._client_ip',side_effect=AssertionError('must not collect IP')):
            for value in (None,False,'true',1):
                payload=self.payload()
                payload['privacy_policy_agreed']=value
                response=await self.client.post('/api/verification/complete',json=payload)
                self.assertEqual(response.status,400)
            payload=self.payload()
            payload['privacy_policy_version']='old-notice'
            response=await self.client.post('/api/verification/complete',json=payload)
            self.assertEqual(response.status,409)
            provider.assert_not_awaited()
        self.assertEqual(self.db.connection.execute('SELECT COUNT(*) FROM verification_consents').fetchone()[0],0)

    async def test_success_does_not_scan_store_or_forward_visitor_ip(self):
        with patch('api.server.TURNSTILE_SITE_KEY','site'), patch('api.server.TURNSTILE_SECRET_KEY','secret'), patch('api.server._client_ip',side_effect=AssertionError('must not collect IP')), patch('api.server._validate_turnstile',AsyncMock(return_value=True)) as provider:
            payload=self.payload()
            payload['browser']={'language':'unneeded','timezone':'unneeded'}
            response=await self.client.post('/api/verification/complete',json=payload,headers={'X-Forwarded-For':'203.0.113.55'})
            self.assertEqual(response.status,200,await response.text())
            provider.assert_awaited_once_with('synthetic-captcha',expected_action='join-verification')
            replay=await self.client.post('/api/verification/complete',json=payload)
            self.assertEqual(replay.status,404)
        for table in ('user_ip_addresses','user_ip_fingerprints'):
            self.assertEqual(self.db.connection.execute('SELECT COUNT(*) FROM '+table).fetchone()[0],0)
        consent=self.db.connection.execute('SELECT * FROM verification_consents').fetchone()
        self.assertEqual(consent['policy_version'],VERIFICATION_PRIVACY_VERSION)
        events=self.db.connection.execute('SELECT details_json FROM moderation_events').fetchall()
        self.assertNotIn('203.0.113.55',str(events))
        self.assertNotIn('browser',str(events))
        actions=self.db.claim_dashboard_actions()
        self.assertEqual([a['action'] for a in actions],['complete_join_verification'])


if __name__ == '__main__':
    unittest.main()
