from __future__ import annotations

import hashlib
import io
from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from aiohttp import CookieJar
from aiohttp import FormData
from aiohttp.test_utils import TestClient, TestServer
from PIL import Image

from api.server import CSRF_COOKIE, DATABASE_KEY, create_app, _report_webhook_api_url, _report_webhook_payload


class DashboardApiTests(unittest.IsolatedAsyncioTestCase):
    ADMIN_USER_ID = "01H00000000000000000000000"

    async def asyncSetUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.directory.name, "dashboard.db")
        self.client = TestClient(
            TestServer(create_app(str(self.database_path))),
            cookie_jar=CookieJar(unsafe=True),
        )
        await self.client.start_server()
        self.database = self.client.app[DATABASE_KEY]
        self.database.update_dashboard_server_snapshot(
            "server",
            "Test server",
            42,
            [("channel", "mod-log"), ("general", "general")],
            [("01ABCDEFGHIJKLMNOPQRSTUVWX", "Verified")],
            [("category", "Community")],
            "https://cdn.example/test-server.png",
            {
                "available": True,
                "missing_count": 1,
                "permissions": [{
                    "name": "manage_messages",
                    "label": "Manage Messages",
                    "impact": "remove moderated messages",
                    "granted": False,
                }],
                "log_channel": {
                    "configured": True,
                    "accessible": True,
                    "channel_id": "channel",
                    "missing": [],
                },
            },
            owner_id="moderator",
            bot_joined_at="2025-05-10T09:00:00+00:00",
        )
        self.database.upsert_dashboard_member("server", {
            "user_id": "moderator",
            "username": "server.owner",
            "display_name": "Server Owner",
            "discriminator": "1200",
        })

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self.directory.cleanup()

    async def _login(self) -> None:
        code = "AB12CD34"
        self.database.create_dashboard_login_code(
            hashlib.sha256(code.encode()).hexdigest(),
            "server",
            "moderator",
            "2099-01-01T00:00:00+00:00",
        )
        response = await self.client.post(
            "/api/auth/verify", json={"code": code}
        )
        self.assertEqual(response.status, 200)


    async def test_dashboard_notification_api_auth_csrf_and_sections(self) -> None:
        self.assertEqual(
            (await self.client.get("/api/dashboard/notifications")).status, 401
        )
        await self._login()
        initial = await self.client.get("/api/dashboard/notifications")
        self.assertEqual(initial.status, 200)
        self.database.add_event(
            server_id="server", event_type="message_deleted", user_id="member"
        )
        appeal_id = self.database.add_event(
            server_id="server",
            event_type="moderation_appeal_submitted",
            user_id="member",
        )
        snapshot = await self.client.get("/api/dashboard/notifications")
        notification = (await snapshot.json())["notifications"]
        self.assertEqual(notification["activity"]["unread_count"], 2)
        self.assertEqual(notification["appeals"]["unread_count"], 1)

        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        rejected = await self.client.post(
            "/api/dashboard/notifications/activity/read",
            json={"through_event_id": appeal_id},
        )
        self.assertEqual(rejected.status, 403)
        later = self.database.add_event(
            server_id="server", event_type="member_leave", user_id="member"
        )
        marked = await self.client.post(
            "/api/dashboard/notifications/activity/read",
            json={"through_event_id": appeal_id},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(marked.status, 200)
        marked_payload = await marked.json()
        self.assertEqual(marked_payload["unread_count"], 1)
        self.assertEqual(marked_payload["latest_event_id"], later)
        still_unread = await self.client.get("/api/dashboard/notifications")
        self.assertEqual(
            (await still_unread.json())["notifications"]["appeals"]["unread_count"],
            1,
        )
        invalid = await self.client.post(
            "/api/dashboard/notifications/not-a-section/read",
            json={"through_event_id": later},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(invalid.status, 400)

    async def test_dashboard_announcements_stay_dismissed_for_the_user(self) -> None:
        await self._login()
        initial_refresh = await self.client.get("/api/dashboard/notifications")
        self.assertEqual((await initial_refresh.json())["announcements"], [])

        announcement = self.database.create_dashboard_announcement(
            "server",
            "Official Stoatmod announcement",
            "Scheduled maintenance begins at 20:00 UTC.",
            "global-owner",
        )

        live_refresh = await self.client.get("/api/dashboard/notifications")
        self.assertEqual(
            (await live_refresh.json())["announcements"][0]["id"],
            announcement["id"],
        )

        dashboard = await self.client.get("/api/dashboard")
        self.assertEqual(dashboard.status, 200)
        self.assertEqual(
            (await dashboard.json())["announcements"][0]["id"], announcement["id"]
        )
        dashboard_payload = await (await self.client.get("/api/dashboard")).json()
        visible_announcement = dashboard_payload["announcements"][0]
        self.assertEqual(
            datetime.fromisoformat(visible_announcement["expires_at"])
            - datetime.fromisoformat(visible_announcement["created_at"]),
            timedelta(days=3),
        )
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        dismissed = await self.client.post(
            f"/api/announcements/{announcement['id']}/dismiss",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(dismissed.status, 200)
        refreshed = await self.client.get("/api/dashboard")
        self.assertEqual((await refreshed.json())["announcements"], [])
        refreshed_notifications = await self.client.get(
            "/api/dashboard/notifications"
        )
        self.assertEqual(
            (await refreshed_notifications.json())["announcements"], []
        )

        other_announcement = self.database.create_dashboard_announcement(
            "another-server", "Other server", "Private announcement", "owner"
        )
        cross_server = await self.client.post(
            f"/api/announcements/{other_announcement['id']}/dismiss",
            json={},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(cross_server.status, 404)


    async def test_public_stats_do_not_require_a_login(self) -> None:
        response = await self.client.get("/api/public/stats")
        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertEqual(payload["server_count"], 1)
        self.assertEqual(payload["member_count"], 42)
        self.assertIn("updated_at", payload)
        self.assertEqual(payload["top_servers"], [])

    async def test_discovery_application_review_and_public_listing(self) -> None:
        await self._login()
        initial = await self.client.get("/api/discovery")
        self.assertEqual(initial.status, 200)
        self.assertFalse((await initial.json())["eligibility"]["eligible"])

        self.database.update_dashboard_server_snapshot(
            "server",
            "Test server",
            42,
            [("channel", "mod-log"), ("general", "general")],
            [("01ABCDEFGHIJKLMNOPQRSTUVWX", "Verified")],
            [("category", "Community")],
            "https://cdn.example/test-server.png",
            {
                "available": True,
                "permissions": [
                    {"name": "manage_messages", "granted": True},
                    {"name": "ban_members", "granted": True},
                ],
            },
        )
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        missing_invite = await self.client.post(
            "/api/discovery/apply",
            json={
                "description": "A welcoming Stoat community for makers and friends.",
                "information": "Weekly events and beginner-friendly channels.",
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(missing_invite.status, 400)
        applied = await self.client.post(
            "/api/discovery/apply",
            json={
                "description": "A welcoming Stoat community for makers and friends.",
                "information": "Weekly events and beginner-friendly channels.",
                "invite_url": "https://stt.gg/test-community",
                "tags": ["Makers", "Friendly"],
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(applied.status, 201)
        self.assertEqual((await applied.json())["application"]["status"], "pending")
        self.assertEqual(
            (await (await self.client.get("/api/public/discovery")).json())["servers"],
            [],
        )

        self.database.review_discovery_application("server", "approved", "owner")
        bumped = await self.client.post(
            "/api/discovery/bump", headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(bumped.status, 200)
        bumped_payload = await bumped.json()
        self.assertTrue(bumped_payload["bump"]["bumped"])
        self.assertFalse(bumped_payload["can_bump"])
        self.assertIsNotNone(bumped_payload["bump_cooldown_until"])
        cooldown = await self.client.post(
            "/api/discovery/bump", headers={"X-CSRF-Token": csrf}
        )
        self.assertFalse((await cooldown.json())["bump"]["bumped"])
        self.database.record_daily_message("server", "member-one")
        self.database.record_daily_message("server", "member-two")
        public = await self.client.get("/api/public/discovery")
        self.assertEqual(public.status, 200)
        listed = (await public.json())["servers"]
        self.assertEqual(listed[0]["server_name"], "Test server")
        self.assertEqual(listed[0]["daily_messages"], 2)
        self.assertNotIn("active_members", listed[0])
        self.assertEqual(listed[0]["global_rank"], 1)
        self.assertEqual(listed[0]["invite_url"], "https://stt.gg/test-community")
        self.assertEqual(listed[0]["tags"], ["Makers", "Friendly"])
        self.assertIn("approved_at", listed[0])
        self.assertIn("last_bumped_at", listed[0])

        self.database.set_public_stats_enabled("server", False)
        hidden = await self.client.get("/api/public/discovery")
        self.assertEqual((await hidden.json())["servers"], [])

    async def test_existing_discovery_application_can_add_missing_invite(self) -> None:
        await self._login()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.database.connection.execute(
            """
            INSERT INTO discovery_applications(
                server_id, description, information, invite_url, status,
                submitted_by, submitted_at, updated_at
            ) VALUES (?, ?, '', '', 'approved', ?, ?, ?)
            """,
            (
                "server",
                "A legacy approved community that needs a public invite.",
                "moderator",
                now,
                now,
            ),
        )
        self.database.connection.commit()
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        updated = await self.client.put(
            "/api/discovery/listing",
            json={
                "description": "A legacy approved community that needs a public invite.",
                "information": "The listing can now be joined.",
                "invite_url": "https://stt.gg/legacy-community",
            },
            headers={"X-CSRF-Token": csrf},
        )

        self.assertEqual(updated.status, 200)
        updated_payload = await updated.json()
        self.assertEqual(
            updated_payload["application"]["invite_url"],
            "https://stt.gg/legacy-community",
        )
        self.assertEqual(updated_payload["application"]["status"], "pending")
        self.assertEqual(
            (await (await self.client.get("/api/public/discovery")).json())["servers"],
            [],
        )

    def test_report_webhook_url_is_normalized_to_stoat_api(self) -> None:
        self.assertEqual(
            _report_webhook_api_url(
                "https://stoat.chat/webhooks/channel/token"
            ),
            "https://stoat.chat/api/webhooks/channel/token",
        )
        self.assertEqual(
            _report_webhook_api_url(
                "https://stoat.chat/api/webhooks/channel/token"
            ),
            "https://stoat.chat/api/webhooks/channel/token",
        )
        self.assertEqual(
            _report_webhook_api_url(
                "https://api.stoat.chat/webhooks/channel/token"
            ),
            "https://api.stoat.chat/webhooks/channel/token",
        )
        with self.assertRaises(ValueError):
            _report_webhook_api_url("https://example.com/webhooks/channel/token")

    def test_report_webhook_payload_identifies_people_and_server(self) -> None:
        payload = _report_webhook_payload(
            report_id=7,
            report_reference="ABCD2345",
            server_name="Community Hub",
            server_id="server-id",
            reporter_username="reporter-name",
            reporter_id="reporter-id",
            target_username="target-name",
            target_id="target-id",
            reason="Scam report",
            evidence="Message link",
            attachment_count=0,
        )
        description = payload["embeds"][0]["description"]
        self.assertEqual(payload["embeds"][0]["title"], "Global report ABCD2345")
        self.assertIn("**Reporter:** reporter-name", description)
        self.assertIn("**Reporter ID:** `reporter-id`", description)
        self.assertIn("**Reported user:** target-name", description)
        self.assertIn("**Reported user ID:** `target-id`", description)
        self.assertIn("**Server:** Community Hub", description)
        self.assertIn("**Server ID:** `server-id`", description)

    async def test_public_status_reports_real_bot_heartbeat(self) -> None:
        missing = await self.client.get("/api/public/status")
        self.assertEqual(missing.status, 200)
        missing_payload = await missing.json()
        missing_services = {item["id"]: item for item in missing_payload["services"]}
        self.assertEqual(missing_services["bot"]["status"], "outage")
        self.assertEqual(missing_services["api"]["status"], "operational")
        self.assertEqual(missing.headers["Cache-Control"], "no-store")

        self.database.update_system_heartbeat(
            "bot", {"connected": True, "server_count": 1}
        )
        self.database.update_system_heartbeat(
            "email", {"connected": True, "mailbox": "Labels/stoatmod"}
        )
        healthy = await self.client.get("/api/public/status")
        healthy_payload = await healthy.json()
        healthy_services = {item["id"]: item for item in healthy_payload["services"]}
        self.assertEqual(healthy_payload["overall"], "degraded")
        self.assertEqual(healthy_services["local_ai"]["status"], "unknown")
        self.assertEqual(healthy_services["bot"]["status"], "operational")
        self.assertEqual(healthy_services["email"]["status"], "operational")
        self.assertIn("1 server", healthy_services["bot"]["detail"])

    async def test_web_verification_link_metadata_is_public_and_token_scoped(self) -> None:
        token = "verification-token-that-is-long-enough-123"
        self.database.set_web_verification_challenge(
            "server",
            "new-member",
            hashlib.sha256(token.encode()).hexdigest(),
            (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        )
        response = await self.client.get(f"/api/verification?token={token}")
        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertEqual(payload["server_name"], "Test server")
        self.assertEqual(payload["locale"], "en")
        self.assertIn("turnstile_configured", payload)

        self.database.set_server_locale("server", "es")
        localized = await self.client.get(f"/api/verification?token={token}")
        self.assertEqual(localized.status, 200)
        self.assertEqual((await localized.json())["locale"], "es")

        incomplete = await self.client.post(
            "/api/verification/complete",
            json={"privacy_policy_agreed": True, "privacy_policy_version": "2026-10-01", "token": token, "turnstile_token": ""},
            headers={"User-Agent": "Test Browser 1.0"},
        )
        self.assertEqual(incomplete.status, 503)
        self.assertIsNotNone(
            self.database.get_web_verification_challenge(
                hashlib.sha256(token.encode()).hexdigest()
            )
        )

        invalid = await self.client.get("/api/verification?token=wrong")
        self.assertEqual(invalid.status, 404)

    async def test_report_submission_only_sends_stoatmod_webhook(self) -> None:
        reported_user_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
        self.database.replace_dashboard_members("server", [
            {"user_id": "reporter", "username": "helpful-reporter"},
            {"user_id": reported_user_id, "username": "reported-account"},
        ])
        token = "report-token-that-is-long-enough-123"
        self.database.create_report_token(
            hashlib.sha256(token.encode()).hexdigest(),
            "server",
            "reporter",
            (datetime.now(timezone.utc) + timedelta(minutes=60)).isoformat(),
        )
        form = FormData()
        form.add_field("target_id", reported_user_id)
        form.add_field("reason", "Repeated harassment")
        form.add_field(
            "evidence", "Message links and context", content_type="text/plain"
        )
        with (
            patch(
                "api.server.STOAT_REPORT_WEBHOOK",
                "https://stoat.chat/webhooks/test/token",
            ),
            patch(
                "api.server._send_report_webhook", new_callable=AsyncMock
            ) as send_webhook,
        ):
            response = await self.client.post(
                f"/api/report/{token}",
                data=form,
                headers={"User-Agent": "Test Browser 1.0"},
            )
        self.assertEqual(response.status, 200)
        submission = await response.json()
        self.assertRegex(submission["report_id"], r"^[A-HJ-NP-Z2-9]{8}$")
        send_webhook.assert_awaited_once()
        webhook_args = send_webhook.await_args.kwargs
        self.assertEqual(webhook_args["server_name"], "Test server")
        self.assertEqual(webhook_args["server_id"], "server")
        self.assertEqual(webhook_args["reporter_username"], "helpful-reporter")
        self.assertEqual(webhook_args["reporter_id"], "reporter")
        self.assertEqual(webhook_args["target_username"], "reported-account")
        self.assertEqual(webhook_args["target_id"], reported_user_id)
        self.assertRegex(
            webhook_args["report_reference"], r"^[A-HJ-NP-Z2-9]{8}$"
        )
        status_response = await self.client.get(
            f"/api/report-status/{submission['receipt']}"
        )
        self.assertEqual(status_response.status, 200)
        public_report = (await status_response.json())["report"]
        self.assertNotIn("id", public_report)
        self.assertEqual(public_report["reference_id"], submission["report_id"])
        self.assertEqual(public_report["report_scope"], "global")
        self.assertEqual(webhook_args["reason"], "Repeated harassment")
        self.assertEqual(self.database.claim_dashboard_actions(), [])
        self.assertEqual(self.database.list_global_bans(), [])


    async def test_dashboard_can_issue_global_report_access_with_prefilled_target(self) -> None:
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        target_user_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

        response = await self.client.post(
            "/api/global-reports/access",
            json={"target_user_id": target_user_id.lower()},
            headers={"X-CSRF-Token": csrf},
        )

        self.assertEqual(response.status, 201)
        payload = await response.json()
        parsed = urlparse(payload["report_url"])
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.path, "/report")
        self.assertEqual(query["target"], [target_user_id])
        token = query["token"][0]
        token_info = self.database.get_report_token(
            hashlib.sha256(token.encode()).hexdigest()
        )
        assert token_info is not None
        self.assertEqual(token_info["report_scope"], "global")
        self.assertEqual(token_info["reporter_id"], "moderator")

    async def test_server_report_portal_stores_evidence_and_uses_public_reference(self) -> None:
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        settings_response = await self.client.put(
            "/api/server-reports/settings",
            json={
                "enabled": True,
                "channel_id": "channel",
                "anonymous_allowed": True,
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(settings_response.status, 200)
        token = "server-report-token-that-is-long-enough"
        self.database.create_report_token(
            hashlib.sha256(token.encode()).hexdigest(),
            "server",
            "reporter",
            (datetime.now(timezone.utc) + timedelta(minutes=60)).isoformat(),
            report_scope="local",
        )
        form = FormData()
        form.add_field("subject_type", "message")
        form.add_field("subject_text", "Message in #general")
        form.add_field("reason", "Server rule violation")
        form.add_field("evidence", "The message and surrounding context")
        form.add_field("anonymous", "true")
        form.add_field(
            "attachments",
            b"screenshot evidence",
            filename="evidence.png",
            content_type="image/png",
        )

        submitted = await self.client.post(
            f"/api/report/{token}",
            data=form,
            headers={"User-Agent": "Test Browser 1.0"},
        )

        self.assertEqual(submitted.status, 200, await submitted.text())
        submission = await submitted.json()
        self.assertEqual(submission["scope"], "server")
        self.assertRegex(submission["report_id"], r"^[A-HJ-NP-Z2-9]{8}$")
        actions = self.database.claim_dashboard_actions()
        report_actions = [
            action for action in actions if action["action"] == "send_local_report_log"
        ]
        self.assertEqual(len(report_actions), 1)
        self.assertEqual(
            report_actions[0]["payload"]["report_id"],
            self.database.list_local_reports("server")[0]["id"],
        )

        status_response = await self.client.get(
            f"/api/report-status/{submission['receipt']}"
        )
        self.assertEqual(status_response.status, 200)
        public_report = (await status_response.json())["report"]
        self.assertNotIn("id", public_report)
        self.assertEqual(public_report["reference_id"], submission["report_id"])
        self.assertEqual(public_report["report_scope"], "server")
        self.assertEqual(public_report["attachments"][0]["filename"], "evidence.png")

        inbox_response = await self.client.get("/api/server-reports")
        self.assertEqual(inbox_response.status, 200)
        inbox_report = (await inbox_response.json())["reports"][0]
        self.assertEqual(inbox_report["reference_id"], submission["report_id"])
        detail_response = await self.client.get(
            f"/api/server-reports/{inbox_report['id']}"
        )
        detail = (await detail_response.json())["report"]
        attachment_response = await self.client.get(
            f"/api/server-reports/{inbox_report['id']}/attachments/"
            f"{detail['attachments'][0]['id']}"
        )
        self.assertEqual(attachment_response.status, 200)
        self.assertEqual(await attachment_response.read(), b"screenshot evidence")


    async def test_code_is_single_use_and_opens_server_scoped_dashboard(self) -> None:
        await self._login()
        dashboard = await self.client.get("/api/dashboard")
        self.assertEqual(dashboard.status, 200)
        payload = await dashboard.json()
        self.assertEqual(payload["overview"]["server"]["name"], "Test server")
        self.assertEqual(
            payload["overview"]["server"]["icon_url"],
            "https://cdn.example/test-server.png",
        )
        self.assertEqual(
            payload["overview"]["permission_audit"]["missing_count"], 1
        )
        self.assertEqual(
            payload["overview"]["permission_audit"]["permissions"][0]["label"],
            "Manage Messages",
        )

        public_stats = await self.client.get("/api/public/stats")
        self.assertEqual(
            public_stats.headers["Cache-Control"],
            "public, max-age=60, stale-while-revalidate=120",
        )

        second_client = TestClient(
            TestServer(create_app(str(self.database_path))),
            cookie_jar=CookieJar(unsafe=True),
        )
        await second_client.start_server()
        try:
            reused = await second_client.post(
                "/api/auth/verify", json={"code": "AB12CD34"}
            )
            self.assertEqual(reused.status, 401)
        finally:
            await second_client.close()

    async def test_setting_writes_require_csrf_and_are_audited(self) -> None:
        await self._login()
        rejected = await self.client.put(
            "/api/settings", json={"link_protection": True}
        )
        self.assertEqual(rejected.status, 403)

        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        updated = await self.client.put(
            "/api/settings",
            json={
                "link_protection": False,
                "allow_gifs": False,
                "spam_detection": False,
                "spam_settings": {
                    "repeat_count": 5,
                    "repeat_window_seconds": 20,
                    "rapid_count": 8,
                    "rapid_window_seconds": 12,
                    "score_threshold": 8.5,
                    "score_half_life_seconds": 18,
                    "mass_mention_limit": 7,
                    "timeout_seconds": 900,
                },
                "locale": "pt",
                "log_channel_id": "channel",
                "moderation_threshold": 0.98,
                "warning_policy": {"timeout": 2, "kick": 4, "ban": 6},
                "penalty_rules": [
                    {"threshold": 2, "action": "timeout", "duration_seconds": 600},
                    {"threshold": 5, "action": "kick", "duration_seconds": None},
                    {"threshold": 8, "action": "ban", "duration_seconds": None},
                ],
                "auto_roles": ["01ABCDEFGHIJKLMNOPQRSTUVWX"],
                "exempt_channels": ["general"],
                "exempt_categories": ["category"],
                "warning_expiry_days": 30,
                "captcha_all_members": True,
                "public_stats": False,
                "ai_thinking": True,
                "disabled_moderation_categories": ["hateful-conduct"],
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(updated.status, 200)
        payload = await updated.json()
        self.assertTrue(payload["ai_thinking"])
        self.assertFalse(payload["link_protection"])
        self.assertFalse(payload["allow_gifs"])
        self.assertFalse(payload["spam_detection"])
        self.assertEqual(payload["spam_settings"]["repeat_count"], 5)
        self.assertEqual(payload["spam_settings"]["rapid_count"], 8)
        self.assertEqual(payload["spam_settings"]["score_threshold"], 8.5)
        self.assertEqual(payload["spam_settings"]["timeout_seconds"], 900)
        self.assertEqual(payload["locale"], "pt")
        self.assertEqual(payload["moderation_threshold"], 0.98)
        self.assertEqual(payload["penalty_rules"][0]["duration_seconds"], 600)
        self.assertEqual(payload["auto_roles"], ["01ABCDEFGHIJKLMNOPQRSTUVWX"])
        self.assertEqual(payload["exempt_channels"], ["general"])
        self.assertEqual(payload["exempt_categories"], ["category"])
        self.assertNotIn("retention_days", payload)
        self.assertEqual(payload["warning_expiry_days"], 30)
        self.assertTrue(payload["captcha_all_members"])
        self.assertFalse(payload["public_stats"])
        self.assertEqual(payload["disabled_moderation_categories"], ["hateful-conduct"])
        self.assertTrue(
            self.database.is_moderation_category_disabled("server", "hateful-conduct")
        )
        events = self.database.list_dashboard_events("server")
        self.assertEqual(events[0]["event_type"], "dashboard_settings_updated")
        actions = self.database.claim_dashboard_actions()
        settings_action = next(
            action for action in actions if action["action"] == "send_settings_log"
        )
        self.assertFalse(settings_action["payload"]["changed"]["link_protection"])
        self.assertFalse(settings_action["payload"]["changed"]["allow_gifs"])
        self.assertFalse(settings_action["payload"]["changed"]["spam_detection"])
        self.assertEqual(
            settings_action["payload"]["changed"]["spam_settings"]["mass_mention_limit"],
            7,
        )
        public = await self.client.get("/api/public/stats")
        self.assertEqual((await public.json())["server_count"], 0)
        self.assertIn("send_dashboard_login_log", {action["action"] for action in actions})

    async def test_removed_history_retention_is_rejected_without_changing_settings(self) -> None:
        await self._login()
        csrf = next(morsel.value for morsel in self.client.session.cookie_jar if morsel.key == CSRF_COOKIE)
        before = self.database.get_warning_expiry_days("server")
        for value in (None, 30, 90):
            response = await self.client.put(
                "/api/settings", json={"retention_days": value, "warning_expiry_days": 7},
                headers={"X-CSRF-Token": csrf},
            )
            self.assertEqual(response.status, 400)
            self.assertIn("removed", (await response.json())["error"])
            self.assertEqual(self.database.get_warning_expiry_days("server"), before)

    async def test_spam_settings_require_complete_safe_values(self) -> None:
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        incomplete = await self.client.put(
            "/api/settings",
            json={"spam_settings": {"rapid_count": 8}},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(incomplete.status, 400)

        invalid = {
            **self.database.get_spam_settings("server"),
            "timeout_seconds": 30,
        }
        rejected = await self.client.put(
            "/api/settings",
            json={"spam_settings": invalid},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rejected.status, 400)
        self.assertEqual(
            self.database.get_spam_settings("server")["timeout_seconds"],
            3600,
        )

    async def test_join_protection_options_are_validated_and_saved(self) -> None:
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        current = await (await self.client.get("/api/settings")).json()
        self.assertEqual(
            current["join_limits"],
            {"enabled": True, "duration_seconds": 86400, "links": True, "attachments": True},
        )
        options = {"enabled": True, "duration_seconds": 3 * 86400, "links": True, "attachments": False}
        saved = await self.client.put(
            "/api/settings", json={"join_limits": options}, headers={"X-CSRF-Token": csrf}
        )
        self.assertEqual(saved.status, 200)
        self.assertEqual((await saved.json())["join_limits"], options)
        self.assertEqual(self.database.join_limits.settings("server"), options)
        rejected = await self.client.put(
            "/api/settings",
            json={"join_limits": {**options, "duration_seconds": 60}},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(rejected.status, 400)
        self.assertEqual(self.database.join_limits.settings("server"), options)

    async def test_stale_existing_exemption_does_not_block_other_settings(self) -> None:
        self.database.exclude_scope(
            "server", "deleted-channel", "channel", "moderator"
        )
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        with patch("api.server.STOAT_BOT_TOKEN", ""):
            response = await self.client.put(
                "/api/settings",
                json={
                    "link_protection": True,
                    "exempt_channels": ["deleted-channel"],
                },
                headers={"X-CSRF-Token": csrf},
            )

        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertTrue(payload["link_protection"])
        self.assertEqual(payload["exempt_channels"], ["deleted-channel"])

    async def test_dashboard_prunes_confirmed_deleted_exemption_without_bot_process(
        self,
    ) -> None:
        self.database.exclude_scope(
            "server", "general", "channel", "moderator"
        )
        await self._login()
        requested_urls: list[str] = []

        class MissingChannelResponse:
            status = 404

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        class StoatSession:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

            def get(self, url: str, **kwargs):
                requested_urls.append(url)
                self.assert_bot_header = kwargs["headers"]["X-Bot-Token"]
                return MissingChannelResponse()

        with (
            patch("api.server.STOAT_BOT_TOKEN", "bot-token"),
            patch("api.server.ClientSession", StoatSession),
        ):
            response = await self.client.get("/api/dashboard")

        self.assertEqual(response.status, 200)
        payload = await response.json()
        self.assertEqual(payload["settings"]["exempt_channels"], [])
        self.assertNotIn(
            "general",
            {
                channel["channel_id"]
                for channel in payload["settings"]["channels"]
            },
        )
        self.assertEqual(
            requested_urls,
            ["https://api.stoat.chat/0.8/channels/general"],
        )
        self.assertEqual(self.database.count_scope_exclusions("server"), 0)

    async def test_dashboard_saves_threshold_below_90_percent(
        self,
    ) -> None:
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        updated = await self.client.put(
            "/api/settings",
            json={"moderation_threshold": 0.89},
            headers={"X-CSRF-Token": csrf},
        )

        self.assertEqual(updated.status, 200)
        self.assertEqual((await updated.json())["moderation_threshold"], 0.89)
        self.assertEqual(
            self.database.get_moderation_threshold("server", 0.9), 0.89
        )

    async def test_policy_accepts_lower_and_zero_overrides_and_rejects_invalid_ranges(self) -> None:
        await self._login()
        csrf = next(m.value for m in self.client.session.cookie_jar if m.key == CSRF_COOKIE)
        headers = {"X-CSRF-Token": csrf}
        policy = {"mode": "enforce", "default_threshold": .75, "policies": [
            {"category": "scams", "threshold": 0, "action": "delete"},
            {"category": "hate", "threshold": .65, "action": "warn"},
        ]}
        updated = await self.client.put("/api/moderation-policy", json=policy, headers=headers)
        self.assertEqual(updated.status, 200)
        saved = (await updated.json())["policy"]
        current = await self.client.get("/api/moderation-policy")
        self.assertEqual((await current.json())["policy"], saved)
        self.assertEqual(saved["default_threshold"], .75)
        self.assertEqual(saved["minimum_threshold"], 0)
        by_category = {item["category"]: item for item in saved["policies"]}
        self.assertEqual(by_category["scams"]["effective_threshold"], 0)
        self.assertEqual(by_category["hate"]["effective_threshold"], .65)
        self.assertEqual(by_category["illicit"]["effective_threshold"], .75)
        for invalid in (-.01, 1.01):
            response = await self.client.put("/api/moderation-policy", json={**policy, "default_threshold": invalid}, headers=headers)
            self.assertEqual(response.status, 400)
            response = await self.client.put("/api/moderation-policy", json={**policy, "policies": [{"category": "scams", "threshold": invalid}]}, headers=headers)
            self.assertEqual(response.status, 400)
            response = await self.client.put("/api/settings", json={"moderation_threshold": invalid}, headers=headers)
            self.assertEqual(response.status, 400)
        self.assertEqual(self.database.get_moderation_policy_studio("server"), saved)

    async def test_dashboard_allows_90_percent_without_confirmation(self) -> None:
        await self._login()
        self.database.set_moderation_threshold("server", 0.98)
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        updated = await self.client.put(
            "/api/settings",
            json={"moderation_threshold": 0.9},
            headers={"X-CSRF-Token": csrf},
        )

        self.assertEqual(updated.status, 200)
        self.assertEqual((await updated.json())["moderation_threshold"], 0.9)

    async def test_dashboard_rejects_new_auto_role_blocked_by_hierarchy(self) -> None:
        self.database.update_dashboard_server_snapshot(
            "server",
            "Test server",
            42,
            [("channel", "mod-log")],
            [("01ABCDEFGHIJKLMNOPQRSTUVWX", "Administrators", False)],
            [],
        )
        await self._login()
        csrf = next(
            morsel.value
            for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        response = await self.client.put(
            "/api/settings",
            json={"auto_roles": ["01ABCDEFGHIJKLMNOPQRSTUVWX"]},
            headers={"X-CSRF-Token": csrf},
        )

        self.assertEqual(response.status, 400)
        payload = await response.json()
        self.assertIn("above every new automatic role", payload["error"])
        self.assertEqual(self.database.list_auto_roles("server"), [])

    async def test_dashboard_automation_poll_and_leaderboard_endpoints(self) -> None:
        await self._login()
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        created = await self.client.post(
            "/api/automations",
            json={
                "name": "Keyword cleanup", "trigger_type": "keyword",
                "trigger_value": "spoiler", "action_type": "delete_message",
                "action_config": {}, "condition_mode": "all",
                "conditions": [{"type": "username_contains", "value": "guest"}],
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(created.status, 201)
        automation = (await created.json())["automation"]
        self.assertEqual(automation["trigger_value"], "spoiler")
        self.assertEqual(automation["conditions"][0]["type"], "username_contains")

        poll = await self.client.post(
            "/api/polls",
            json={
                "channel_id": "channel", "question": "Choose one",
                "options": [
                    {"emoji": "🍎", "label": "One"},
                    {"emoji": "🍐", "label": "Two"},
                ],
                "multiple_choice": True,
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(poll.status, 202)
        poll_record = (await poll.json())["poll"]
        self.assertEqual([item["emoji"] for item in poll_record["options"]], ["🍎", "🍐"])
        default_poll = await self.client.post(
            "/api/polls",
            json={
                "channel_id": "channel", "question": "Use safe defaults",
                "options": ["First", "Second"],
            },
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(default_poll.status, 202)
        self.assertEqual(
            [item["emoji"] for item in (await default_poll.json())["poll"]["options"]],
            ["🍎", "🍐"],
        )
        self.assertIn(
            "publish_poll",
            {action["action"] for action in self.database.claim_dashboard_actions()},
        )
        deleted_poll = await self.client.delete(
            f"/api/polls/{poll_record['id']}",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(deleted_poll.status, 200)
        self.assertIsNone(self.database.get_poll(poll_record["id"]))
        missing_poll = await self.client.delete(
            f"/api/polls/{poll_record['id']}",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(missing_poll.status, 404)

        leaderboard = await self.client.get("/api/leaderboards?period=week")
        self.assertEqual(leaderboard.status, 410)
        self.assertNotIn("entries", await leaderboard.json())
        global_leaderboard = await self.client.get(
            "/api/leaderboards?scope=global&metric=members&period=month"
        )
        self.assertEqual(global_leaderboard.status, 200)
        self.assertEqual((await global_leaderboard.json())["scope"], "global")

        deleted = await self.client.delete(
            f"/api/automations/{automation['id']}",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(deleted.status, 200)

        protected = await self.client.put(
            "/api/settings",
            json={"disabled_moderation_categories": ["self-harm"]},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(protected.status, 400)

    async def test_poll_results_endpoint_paginates_every_poll(self) -> None:
        await self._login()
        poll_ids = [
            self.database.create_poll(
                "server",
                "channel",
                f"Paged poll {index}",
                [
                    {"emoji": "🍎", "label": "One"},
                    {"emoji": "🍐", "label": "Two"},
                ],
                "moderator",
            )
            for index in range(8)
        ]

        first_response = await self.client.get("/api/polls?page=1&page_size=3")
        second_response = await self.client.get("/api/polls?page=2&page_size=3")
        clamped_response = await self.client.get("/api/polls?page=999&page_size=3")

        self.assertEqual(first_response.status, 200)
        first = await first_response.json()
        second = await second_response.json()
        clamped = await clamped_response.json()
        self.assertEqual(first["total_items"], 8)
        self.assertEqual(first["total_pages"], 3)
        self.assertEqual(first["page_size"], 3)
        self.assertEqual([item["id"] for item in first["polls"]], poll_ids[-1:-4:-1])
        self.assertEqual([item["id"] for item in second["polls"]], poll_ids[-4:-7:-1])
        self.assertEqual(clamped["page"], 3)
        self.assertEqual([item["id"] for item in clamped["polls"]], poll_ids[1::-1])
        self.assertTrue(all("votes" not in poll for poll in first["polls"]))

    async def test_member_directory_detail_and_actions_are_server_scoped(self) -> None:
        self.database.replace_dashboard_members("server", [{
            "user_id": "01MEMBER1234567890ABCDEFG", "username": "member",
            "display_name": "Test Member", "joined_at": "2026-08-01T12:00:00+00:00",
            "account_created_at": "2026-01-01T12:00:00+00:00", "role_ids": [],
        }])
        self.database.add_warning(
            server_id="server", user_id="01MEMBER1234567890ABCDEFG",
            moderator_id="moderator", source="manual", reason="Previous warning",
        )
        self.database.update_dashboard_server_snapshot(
            "other-server", "Other Stoatmod Server", 12, [], [], []
        )
        self.database.add_event(
            server_id="other-server",
            event_type="member_ban",
            user_id="01MEMBER1234567890ABCDEFG",
            actor_id="moderator",
            channel_id="other-log-channel",
            details={"reason": "Cross-server safety risk", "global_reference": "GB1234"},
        )
        await self._login()
        listing = await self.client.get("/api/members")
        self.assertEqual(listing.status, 200)
        self.assertEqual((await listing.json())["members"][0]["case_count"], 1)
        detail = await self.client.get("/api/members/01MEMBER1234567890ABCDEFG")
        self.assertEqual(detail.status, 200)
        member_detail = (await detail.json())["member"]
        self.assertEqual(member_detail["active_warning_count"], 1)
        self.assertEqual(member_detail["server_history"], [])
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        queued = await self.client.post(
            "/api/members/01MEMBER1234567890ABCDEFG/actions",
            json={"action": "kick", "reason": "Repeated disruption"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(queued.status, 202)
        actions = self.database.claim_dashboard_actions()
        member_action = next(item for item in actions if item["action"] == "moderate_member")
        self.assertEqual(member_action["payload"]["action"], "kick")
        self.assertEqual(member_action["payload"]["user_id"], "01MEMBER1234567890ABCDEFG")

        warning = await self.client.post(
            "/api/members/01MEMBER1234567890ABCDEFG/actions",
            json={"action": "warn", "reason": "Dashboard warning"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(warning.status, 202)
        warning_action = next(
            item for item in self.database.claim_dashboard_actions()
            if item["action"] == "moderate_member"
        )
        self.assertEqual(warning_action["payload"]["action"], "warn")

    async def test_three_failed_web_verifications_enqueue_kick_without_case(self) -> None:
        token = "verification-token-that-is-long-enough-456"
        self.database.set_web_verification_challenge(
            "server",
            "new-member",
            hashlib.sha256(token.encode()).hexdigest(),
            (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        )
        with (
            patch("api.server.TURNSTILE_SITE_KEY", "site-key"),
            patch("api.server.TURNSTILE_SECRET_KEY", "secret-key"),
            patch("api.server._validate_turnstile", AsyncMock(return_value=False)),
        ):
            for expected_attempt in range(1, 4):
                response = await self.client.post(
                    "/api/verification/complete",
                    json={"privacy_policy_agreed": True, "privacy_policy_version": "2026-10-01", "token": token, "turnstile_token": "failed"},
                    headers={"User-Agent": "Test Browser 1.0"},
                )
                self.assertEqual(response.status, 403)
                body = await response.json()
                self.assertIn(
                    "three times" if expected_attempt == 3 else f"{expected_attempt} of 3",
                    body["error"],
                )

        self.assertIsNone(
            self.database.get_captcha_challenge("server", "new-member")
        )
        actions = self.database.claim_dashboard_actions()
        failure_actions = [
            action for action in actions
            if action["action"] == "handle_join_verification_failure"
        ]
        self.assertEqual(len(failure_actions), 3)
        self.assertFalse(failure_actions[0]["payload"]["kick"])
        self.assertTrue(failure_actions[-1]["payload"]["kick"])
        self.assertEqual(
            failure_actions[-1]["payload"]["kick_reason"],
            "Browser CAPTCHA was not completed successfully",
        )
        self.assertIn(
            "Reason: Browser CAPTCHA was not completed successfully.",
            body["error"],
        )
        self.assertEqual(self.database.list_dashboard_cases("server"), [])


    async def test_global_ban_appeals_are_hidden_and_unavailable(self) -> None:
        code = "GB12CD34EF"
        cursor = self.database.connection.execute(
            """
            INSERT INTO appeals(
                code_hash, server_id, user_id, case_kind, case_reference,
                status, statement, created_at, submitted_at
            ) VALUES (?, NULL, ?, 'global_ban', ?, 'submitted', ?, ?, ?)
            """,
            (
                hashlib.sha256(code.encode()).hexdigest(),
                "01GLOBALUSER1234567890ABCD",
                "GBAN01",
                "Legacy global appeal",
                "2026-08-20T12:00:00+00:00",
                "2026-08-20T12:01:00+00:00",
            ),
        )
        self.database.connection.commit()

        lookup = await self.client.post(
            "/api/appeals/lookup",
            json={"code": code, "user_id": "01GLOBALUSER1234567890ABCD"},
        )
        self.assertEqual(lookup.status, 404)

        await self._login()
        dashboard = await self.client.get("/api/dashboard")
        self.assertEqual((await dashboard.json())["appeals"], [])
        listing = await self.client.get("/api/appeals")
        self.assertEqual((await listing.json())["appeals"], [])
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        reviewed = await self.client.put(
            f"/api/appeals/{cursor.lastrowid}",
            json={"decision": "approved", "response": "Legacy review rejected."},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(reviewed.status, 404)

    async def test_public_appeal_requires_both_credentials_and_can_be_reviewed(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server",
            user_id="01APPEALUSER1234567890ABCD",
            moderator_id="moderator",
            source="automatic",
            reason="Threshold exceeded",
            original_content="Message evidence",
            scores={"harassment": 0.93},
        )
        case = self.database.get_warning_case("server", warning_id)
        image_buffer = io.BytesIO()
        Image.new("RGB", (2, 2), "blue").save(image_buffer, format="PNG")
        image_data = image_buffer.getvalue()
        self.database.add_moderation_case_entry(
            "server",
            case.reference_id,
            "note",
            "Private moderator note",
            "moderator",
        )
        self.database.add_moderation_case_entry(
            "server",
            case.reference_id,
            "evidence",
            "Screenshot showing the full message context",
            "moderator",
            [("appeal-proof.png", "image/png", image_data)],
        )
        code = "AB12CD34EF"
        self.database.create_appeal_access(
            hashlib.sha256(code.encode()).hexdigest(),
            "01APPEALUSER1234567890ABCD",
            "moderation",
            case.reference_id,
            "server",
        )
        wrong = await self.client.post(
            "/api/appeals/lookup", json={"code": code, "user_id": "01WRONGUSER1234567890ABCDE"}
        )
        self.assertEqual(wrong.status, 404)
        lookup = await self.client.post(
            "/api/appeals/lookup",
            json={"code": code, "user_id": "01APPEALUSER1234567890ABCD"},
        )
        self.assertEqual(lookup.status, 200)
        appeal = (await lookup.json())["appeal"]
        self.assertEqual(appeal["evidence"]["original_message"], "Message evidence")
        public_entries = appeal["evidence"]["entries"]
        self.assertEqual(len(public_entries), 1)
        self.assertEqual(
            public_entries[0]["content"],
            "Screenshot showing the full message context",
        )
        self.assertNotIn("created_by", public_entries[0])
        public_attachment = public_entries[0]["attachments"][0]
        self.assertEqual(public_attachment["filename"], "appeal-proof.png")
        evidence_image = await self.client.get(
            f"/api/appeals/evidence/{public_attachment['id']}",
            headers={
                "X-Appeal-Code": code,
                "X-Stoat-User-ID": "01APPEALUSER1234567890ABCD",
            },
        )
        self.assertEqual(evidence_image.status, 200)
        self.assertEqual(evidence_image.content_type, "image/png")
        self.assertEqual(await evidence_image.read(), image_data)
        denied_image = await self.client.get(
            f"/api/appeals/evidence/{public_attachment['id']}",
            headers={
                "X-Appeal-Code": "WRONGCODE1",
                "X-Stoat-User-ID": "01APPEALUSER1234567890ABCD",
            },
        )
        self.assertEqual(denied_image.status, 404)
        submitted = await self.client.post(
            "/api/appeals/submit",
            json={
                "code": code,
                "user_id": "01APPEALUSER1234567890ABCD",
                "statement": "Please review this automated warning decision.",
                "privacy_policy_agreed": True,
                "privacy_policy_version": "2026-10-01-appeals-v1",
            },
        )
        self.assertEqual(submitted.status, 200, await submitted.text())

        await self._login()
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )
        reviewed = await self.client.put(
            f"/api/appeals/{appeal['id']}",
            json={"decision": "approved", "response": "Evidence reviewed."},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(reviewed.status, 200)
        actions = self.database.claim_dashboard_actions()
        self.assertIn("resolve_appeal", {action["action"] for action in actions})
        submitted_logs = [
            action for action in actions
            if action["action"] == "send_appeal_submitted_log"
        ]
        self.assertEqual(len(submitted_logs), 1)
        appeal_events = self.database.list_dashboard_events("server")
        self.assertIn(
            "moderation_appeal_submitted",
            {event["event_type"] for event in appeal_events},
        )

    async def test_appeal_dm_notifications_are_explicit_and_server_scoped(self):
        self.assertEqual((await self.client.get("/api/appeals")).status, 401)
        await self._login()
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        initial = await self.client.get("/api/appeals")
        self.assertEqual(initial.status, 200)
        self.assertFalse((await initial.json())["dm_notifications"])
        missing_csrf = await self.client.post(
            "/api/appeals/notifications", json={"enabled": True}
        )
        self.assertEqual(missing_csrf.status, 403)
        invalid = await self.client.post(
            "/api/appeals/notifications",
            json={"enabled": "true"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(invalid.status, 400)

        enabled = await self.client.post(
            "/api/appeals/notifications",
            json={"enabled": True},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(enabled.status, 200)
        self.assertTrue((await enabled.json())["dm_notifications"])
        self.assertEqual(
            self.database.appeal_notification_recipients("server"),
            ["moderator"],
        )
        self.database.appeal_notification_preference(
            "another-server", "moderator", True
        )
        refreshed = await self.client.get("/api/appeals")
        self.assertTrue((await refreshed.json())["dm_notifications"])

        disabled = await self.client.post(
            "/api/appeals/notifications",
            json={"enabled": False},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(disabled.status, 200)
        self.assertFalse((await disabled.json())["dm_notifications"])
        self.assertFalse(
            self.database.appeal_notification_preference("server", "moderator")
        )
        self.assertTrue(
            self.database.appeal_notification_preference(
                "another-server", "moderator"
            )
        )

    def _create_privacy_appeal(self):
        user = "01PRIVACYUSER1234567890ABCD"
        warning_id = self.database.add_warning(
            server_id="server", user_id=user, moderator_id="moderator",
            source="automatic", reason="Synthetic moderation decision",
            message_id="synthetic-message", original_content="Synthetic original message",
            scores={"harassment": .95},
        )
        case = self.database.get_warning_case("server", warning_id)
        code = "PR12CD34EF"
        appeal_id = self.database.create_appeal_access(hashlib.sha256(code.encode()).hexdigest(), user, "moderation", case.reference_id, "server")
        return {"code": code, "user_id": user, "statement": "Please review this synthetic test decision.", "privacy_policy_version": "2026-10-01-appeals-v1"}, appeal_id

    async def test_appeal_requires_explicit_current_consent_and_separate_ai_notice(self):
        payload, appeal_id = self._create_privacy_appeal()
        for invalid in (None, False, "true", 1):
            response = await self.client.post("/api/appeals/submit", json={**payload, "privacy_policy_agreed": invalid})
            self.assertEqual(response.status, 400)
            self.assertEqual(self.database.get_appeal(appeal_id)["status"], "eligible")
        response = await self.client.post("/api/appeals/submit", json={**payload, "privacy_policy_agreed": True, "privacy_policy_version": "old"})
        self.assertEqual(response.status, 409)
        response = await self.client.post("/api/appeals/submit", json={**payload, "privacy_policy_agreed": True, "ai_improvement_opt_in": True})
        self.assertEqual(response.status, 409)
        response = await self.client.post("/api/appeals/submit", json={**payload, "privacy_policy_agreed": True})
        self.assertEqual(response.status, 200, await response.text())
        appeal = (await response.json())["appeal"]
        self.assertFalse(appeal["privacy"]["ai_improvement_opt_in"])
        rejected = await self.client.post("/api/appeals/respond", json={**payload, "message": "More context"})
        self.assertEqual(rejected.status, 400)

    async def test_multipart_appeal_opt_in_can_be_withdrawn_only_with_valid_credentials(self):
        payload, appeal_id = self._create_privacy_appeal()
        form = FormData()
        for key, value in {**payload, "privacy_policy_agreed": "true", "ai_improvement_opt_in": "true", "ai_notice_version": "2026-10-01-ai-improvement-v1"}.items():
            form.add_field(key, value)
        image = io.BytesIO()
        Image.new("RGB", (2, 2), "blue").save(image, format="PNG")
        form.add_field("images", image.getvalue(), filename="synthetic.png", content_type="image/png")
        submitted = await self.client.post("/api/appeals/submit", data=form)
        self.assertEqual(submitted.status, 200, await submitted.text())
        appeal = (await submitted.json())["appeal"]
        self.assertTrue(appeal["privacy"]["ai_improvement_opt_in"])
        attachment_id = appeal["messages"][0]["attachments"][0]["id"]
        self.database.review_appeal(appeal_id, "moderator", "approved", "Reviewed.")
        denied = await self.client.delete("/api/appeals/ai-permission", json={"code": payload["code"], "user_id": "01WRONGUSER1234567890ABCD"})
        self.assertEqual(denied.status, 404)
        count = self.database.connection.execute("SELECT COUNT(*) FROM appeal_ai_contributions").fetchone()[0]
        self.assertEqual(count, 1)
        withdrawn = await self.client.delete("/api/appeals/ai-permission", json={"code": payload["code"], "user_id": payload["user_id"]})
        self.assertEqual(withdrawn.status, 200)
        self.assertFalse((await withdrawn.json())["appeal"]["privacy"]["ai_improvement_opt_in"])
        missing = await self.client.get(f"/api/appeals/attachments/{attachment_id}", headers={"X-Appeal-Code": payload["code"], "X-Stoat-User-ID": payload["user_id"]})
        self.assertEqual(missing.status, 404)

    async def test_expired_appeal_attachment_is_unavailable_without_prior_lookup(self):
        payload, appeal_id = self._create_privacy_appeal()
        self.database.submit_appeal(appeal_id, payload["user_id"], payload["statement"])
        message_id = self.database.get_latest_appeal_message_id(appeal_id, "appellant")
        attachment_id = self.database.add_appeal_message_attachment(message_id, "synthetic.png", "image/png", b"test bytes")
        old = (datetime.now(timezone.utc) - timedelta(days=11)).isoformat()
        self.database.connection.execute("UPDATE appeals SET submitted_at=? WHERE id=?", (old, appeal_id))
        self.database.connection.commit()
        response = await self.client.get(f"/api/appeals/attachments/{attachment_id}", headers={"X-Appeal-Code": payload["code"], "X-Stoat-User-ID": payload["user_id"]})
        self.assertEqual(response.status, 404)
        self.assertEqual(self.database.get_appeal(appeal_id)["status"], "denied")

    async def test_server_owner_can_open_case_and_add_note_or_evidence(self) -> None:
        warning_id = self.database.add_warning(
            server_id="server",
            user_id="01CASEUSER1234567890ABCDEFG",
            moderator_id="moderator",
            source="automatic",
            reason="Automated threshold exceeded",
            original_content="Stored message evidence",
            categories=["harassment"],
            scores={"harassment": 0.94},
        )
        case = self.database.get_warning_case("server", warning_id)
        await self._login()
        csrf = next(
            morsel.value for morsel in self.client.session.cookie_jar
            if morsel.key == CSRF_COOKIE
        )

        detail_response = await self.client.get(
            f"/api/cases/{case.reference_id}"
        )
        self.assertEqual(detail_response.status, 200)
        detail = (await detail_response.json())["case"]
        self.assertEqual(detail["source"]["original_content"], "Stored message evidence")
        self.assertEqual(detail["source"]["scores"]["harassment"], 0.94)

        image_buffer = io.BytesIO()
        Image.new("RGB", (2, 2), "red").save(image_buffer, format="PNG")
        image_data = image_buffer.getvalue()
        form = FormData()
        form.add_field("entry_type", "evidence")
        form.add_field("content", "Screenshot of the relevant message")
        form.add_field(
            "images",
            image_data,
            filename="message-proof.png",
            content_type="image/png",
        )
        added = await self.client.post(
            f"/api/cases/{case.reference_id}/entries",
            data=form,
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(added.status, 201)
        refreshed = await self.client.get(f"/api/cases/{case.reference_id}")
        entries = (await refreshed.json())["case"]["entries"]
        self.assertEqual(entries[0]["entry_type"], "evidence")
        self.assertEqual(entries[0]["created_by"], "moderator")
        self.assertEqual(entries[0]["attachments"][0]["filename"], "message-proof.png")
        attachment_id = entries[0]["attachments"][0]["id"]
        attachment = await self.client.get(
            f"/api/cases/{case.reference_id}/attachments/{attachment_id}"
        )
        self.assertEqual(attachment.status, 200)
        self.assertEqual(attachment.content_type, "image/png")
        self.assertEqual(await attachment.read(), image_data)
        actions = self.database.claim_dashboard_actions()
        self.assertIn("send_case_entry_log", {action["action"] for action in actions})

        removed = await self.client.delete(
            f"/api/cases/{case.reference_id}",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(removed.status, 200)
        self.assertEqual((await removed.json())["case"]["status"], "removed")
        self.assertEqual(self.database.count_active_warnings("server", case.user_id), 0)
        retained = await self.client.get(f"/api/cases/{case.reference_id}")
        retained_detail = (await retained.json())["case"]
        self.assertEqual(retained_detail["status"], "removed")
        self.assertEqual(
            retained_detail["source"]["original_content"],
            "Stored message evidence",
        )
        self.assertEqual(retained_detail["source"]["scores"]["harassment"], 0.94)
        self.assertEqual(len(retained_detail["entries"]), 1)
        removal_actions = self.database.claim_dashboard_actions()
        self.assertIn(
            "send_case_removed_log", {action["action"] for action in removal_actions}
        )
        removed_again = await self.client.delete(
            f"/api/cases/{case.reference_id}",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(removed_again.status, 404)


if __name__ == "__main__":
    unittest.main()
