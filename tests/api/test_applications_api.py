from application_embeds import APPLICATION_PRIVACY_VERSION
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer

from api.server import create_app, DATABASE_KEY, CSRF_COOKIE


QUESTION = {"title": "About you", "prompt": "Why join?", "type": "text", "required": True, "options": []}


class ApplicationApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_expired_answers_are_inaccessible_before_cleanup_runs(self):
        app = self.application()
        app = self.store.answer(app["id"], "member", 0, "message", "Private application answer")
        with patch("applications.now_iso", return_value=app["expires_at"]):
            detail = await self.client.get(f"/api/applications/{app['id']}")
            self.assertEqual(detail.status, 404)
            listing = await self.client.get("/api/applications")
            self.assertEqual((await listing.json())["applications"], [])
            decision = await self.client.post(f"/api/applications/{app['id']}/review", json={"decision": "approved"}, headers=self.csrf)
            self.assertEqual(decision.status, 409)
            retry = await self.client.post(f"/api/applications/{app['id']}/retry", headers=self.csrf)
            self.assertEqual(retry.status, 409)
            self.store.prune()
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM join_application_answers").fetchone()[0], 0)

    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.client = TestClient(TestServer(create_app(str(Path(self.directory.name) / "api.db"))), cookie_jar=CookieJar(unsafe=True))
        await self.client.start_server()
        self.db = self.client.app[DATABASE_KEY]
        self.db.update_dashboard_server_snapshot("server", "Test server", 1, [], [], owner_id="admin")
        token = "AB12CD34"
        self.db.create_dashboard_login_code(hashlib.sha256(token.encode()).hexdigest(), "server", "admin", "2099-01-01T00:00:00+00:00")
        response = await self.client.post("/api/auth/verify", json={"code": token})
        self.assertEqual(response.status, 200)
        self.csrf = {"X-CSRF-Token": self.client.session.cookie_jar.filter_cookies(self.client.make_url("/"))[CSRF_COOKIE].value}
        self.store = self.db.applications

    async def asyncTearDown(self):
        await self.client.close()
        self.directory.cleanup()

    def application(self, server="server", screening=False):
        self.store.save_settings(server, "admin", {"enabled": True, "questions": [QUESTION]})
        self.store.update_setup(server, status="ready", role_id="access")
        app = self.store.create(server, "member", "2026-09-10T00:00:00+00:00", screening_required=screening)
        self.store.update_delivery(app["id"], error=None, prompt_id="notice", channel_id="dm", position=-2)
        return self.store.accept_privacy(app["id"], "member", APPLICATION_PRIVACY_VERSION, agreed=True)

    async def test_form_settings_require_csrf_and_queue_permission_setup(self):
        payload = {"enabled": True, "questions": [QUESTION]}
        response = await self.client.post("/api/applications/settings", json=payload)
        self.assertEqual(response.status, 403)
        response = await self.client.post("/api/applications/settings", json={"enabled": True, "questions": []}, headers=self.csrf)
        self.assertEqual(response.status, 400)
        response = await self.client.post("/api/applications/settings", json=payload, headers=self.csrf)
        self.assertEqual(response.status, 200)
        body = await response.json()
        self.assertEqual(body["settings"]["setup_status"], "pending")
        self.assertNotIn("gate", body["settings"])
        self.assertFalse(body["dm_notifications"])
        self.assertTrue(any(action["action"] == "configure_applications" for action in self.db.claim_dashboard_actions()))

    async def test_review_cannot_cross_servers_or_approve_unsubmitted_application(self):
        app = self.application()
        other = self.application("other-server")
        response = await self.client.get("/api/applications/" + other["id"])
        self.assertEqual(response.status, 404)
        response = await self.client.post(f"/api/applications/{app['id']}/review", json={"decision": "approved"}, headers=self.csrf)
        self.assertEqual(response.status, 409)
        self.store.answer(app["id"], "member", 0, "message", "Hello")
        response = await self.client.post(f"/api/applications/{app['id']}/review", json={"decision": "approved"}, headers=self.csrf)
        self.assertEqual(response.status, 202)
        self.assertEqual((await response.json())["application"]["enforcement_status"], "pending")
        response = await self.client.post(f"/api/applications/{app['id']}/review", json={"decision": "denied", "reason": "Changed"}, headers=self.csrf)
        self.assertEqual(response.status, 409)

    async def test_channel_directory_and_selections_are_server_scoped(self):
        self.db.update_dashboard_server_snapshot("server", "Test", 1,
            [("rules", "Rules", "important"), ("general", "General", None)], [],
            categories=[("important", "Important")], owner_id="admin")
        self.db.update_dashboard_server_snapshot("other", "Other", 1, [("secret", "Secret")], [])
        response = await self.client.get("/api/applications/settings")
        body = await response.json()
        self.assertEqual({c["channel_id"] for c in body["channels"]}, {"rules", "general"})
        self.assertEqual(body["categories"], [{"category_id": "important", "category_name": "Important"}])
        payload = {"enabled": True, "questions": [QUESTION], "visible_channel_ids": ["secret"]}
        response = await self.client.post("/api/applications/settings", json=payload, headers=self.csrf)
        self.assertEqual(response.status, 400)
        payload["visible_channel_ids"] = ["rules"]
        response = await self.client.post("/api/applications/settings", json=payload, headers=self.csrf)
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["settings"]["visible_channel_ids"], ["rules"])
        self.assertEqual(self.store.settings("other")["visible_channel_ids"], [])

    async def test_notifications_are_personal_and_revoked_admins_are_excluded(self):
        response = await self.client.post("/api/applications/notifications", json={"enabled": True}, headers=self.csrf)
        self.assertEqual(response.status, 200)
        self.assertEqual(self.store.notification_recipients("server"), ["admin"])
        self.store.notification_preference("server", "not-an-admin", True)
        self.assertEqual(self.store.notification_recipients("server"), ["admin"])
        self.assertFalse(self.store.notification_preference("other", "admin"))

    async def test_anonymous_users_cannot_read_applications(self):
        self.application()
        self.client.session.cookie_jar.clear()
        for path in ("/api/applications", "/api/applications/settings"):
            response = await self.client.get(path)
            self.assertEqual(response.status, 401)

    async def test_live_preview_uses_unsaved_draft_and_never_queues_messages(self):
        before = self.store.settings("server")
        self.db.claim_dashboard_actions()  # Discard the login audit action.
        payload = {"enabled": True, "introduction": "Welcome **friend**", "questions": [
            {**QUESTION, "title": "", "emoji": "🦦", "color": "#123456"}], "appearance": {"footer": "Private answers"}}
        response = await self.client.post("/api/applications/preview", json=payload)
        self.assertEqual(response.status, 403)
        response = await self.client.post("/api/applications/preview", json=payload, headers=self.csrf)
        self.assertEqual(response.status, 200)
        preview = await response.json()
        self.assertEqual(preview["embeds"][0]["title"], "🦦 Question title")
        self.assertEqual(preview["embeds"][0]["color"], "#123456")
        self.assertIn("Test server", preview["embeds"][0]["description"])
        self.assertIn("Private answers", preview["embeds"][0]["description"])
        self.assertEqual(self.store.settings("server"), before)
        self.assertEqual(self.db.claim_dashboard_actions(), [])
        response = await self.client.post("/api/applications/preview", json={**payload, "stage": "submitted"}, headers=self.csrf)
        self.assertIn("14 days", (await response.json())["embeds"][0]["description"])
        response = await self.client.post("/api/applications/preview", json={**payload, "position": -1}, headers=self.csrf)
        self.assertEqual(response.status, 400)
        self.client.session.cookie_jar.clear()
        response = await self.client.post("/api/applications/preview", json=payload, headers=self.csrf)
        self.assertIn(response.status, (401, 403))

    async def test_browser_pass_starts_dm_questions_without_release_action(self):
        app = self.application(screening=True)
        token = "a" * 40
        self.db.set_web_verification_challenge("server", "member", hashlib.sha256(token.encode()).hexdigest(), app["expires_at"])
        status = await self.client.get("/api/verification?token=" + token)
        self.assertTrue((await status.json())["application_required"])
        with patch("api.server.TURNSTILE_SITE_KEY", "site"), patch("api.server.TURNSTILE_SECRET_KEY", "secret"), \
             patch("api.server._validate_turnstile", AsyncMock(return_value=True)):
            response = await self.client.post("/api/verification/complete", json={"privacy_policy_agreed": True, "privacy_policy_version": "2026-10-01", "token": token, "turnstile_token": "solved"})
        self.assertEqual(response.status, 200, await response.text())
        self.assertTrue((await response.json())["application_required"])
        self.assertEqual(self.store.get(app["id"])["status"], "answering")
        actions = self.db.claim_dashboard_actions()
        self.assertTrue(any(a["action"] == "resume_application" for a in actions))
        self.assertFalse(any(a["action"] == "complete_join_verification" for a in actions))

    async def test_three_failed_checks_reject_application_and_queue_kick(self):
        app = self.application(screening=True)
        token = "b" * 40
        self.db.set_web_verification_challenge("server", "member", hashlib.sha256(token.encode()).hexdigest(), app["expires_at"])
        with patch("api.server.TURNSTILE_SITE_KEY", "site"), patch("api.server.TURNSTILE_SECRET_KEY", "secret"), \
             patch("api.server._validate_turnstile", AsyncMock(return_value=False)):
            for _ in range(3):
                response = await self.client.post("/api/verification/complete", json={"privacy_policy_agreed": True, "privacy_policy_version": "2026-10-01", "token": token, "turnstile_token": "failed"})
                self.assertEqual(response.status, 403)
        rejected = self.store.get(app["id"])
        self.assertEqual(rejected["status"], "denied")
        self.assertIn("CAPTCHA", rejected["reason"])
        self.assertTrue(any(a["action"] == "resolve_application" for a in self.db.claim_dashboard_actions()))
