from __future__ import annotations

import asyncio
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlsplit

import stoat

from application_flow import ApplicationFlow, iso, member_channel_bits
from application_embeds import APPLICATION_PRIVACY_VERSION, question_embeds, submission_embed
from applications import ApplicationStore, now_iso
from stoat.channel import calculate_server_channel_permissions
from database import ModerationDatabase
from bot import ModerationBot


QUESTIONS = [
    {"title": "Introduce yourself", "prompt": "Why would you like to join?", "type": "text", "required": True, "options": []},
    {"title": "Rules", "prompt": "Do you agree to the rules?", "type": "agreement", "required": True, "options": []},
]


class ApplicationDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "applications.db"
        self.db = ModerationDatabase(self.path)
        self.store = self.db.applications
        self.configure()

    def tearDown(self):
        self.db.close()
        self.directory.cleanup()

    def configure(self, server="server"):
        self.store.save_settings(server, "admin", {"enabled": True, "introduction": "Welcome!", "questions": QUESTIONS})
        self.store.update_setup(server, status="ready", role_id="access")

    def application(self, user="member", server="server", screened=True, joined=None, consent=True):
        app = self.store.create(server, user, joined or now_iso(), screening_required=not screened)
        if consent:
            self.store.update_delivery(app["id"], error=None, prompt_id="notice", channel_id="dm", position=-2)
            return self.store.accept_privacy(app["id"], user, APPLICATION_PRIVACY_VERSION, agreed=True)
        return app

    def submit(self, app):
        self.store.answer(app["id"], app["user_id"], 0, app["id"] + "-1", "To talk about stoats")
        return self.store.answer(app["id"], app["user_id"], 1, app["id"] + "-2", "agree")

    def test_opt_in_validation_and_form_snapshot(self):
        self.assertFalse(self.store.settings("another")["enabled"])
        with self.assertRaises(ValueError):
            self.store.save_settings("another", "admin", {"enabled": True, "questions": []})
        app = self.application()
        self.store.save_settings("server", "admin", {"enabled": True, "questions": [QUESTIONS[0]], "introduction": "Changed"})
        self.assertEqual(self.store.get(app["id"])["questions"], QUESTIONS)
        self.assertEqual(self.store.get(app["id"])["introduction"], "Welcome!")

    def test_only_screened_members_can_answer_and_token_consumption_is_atomic(self):
        app = self.application(screened=False)
        with self.assertRaises(ValueError):
            self.store.answer(app["id"], "member", 0, "message", "hello")
        token = hashlib.sha256(b"secret").hexdigest()
        self.db.set_web_verification_challenge("server", "member", token, app["expires_at"])
        self.assertFalse(self.store.complete_screening(app["id"], "wrong"))
        self.assertTrue(self.store.complete_screening(app["id"], token))
        self.assertFalse(self.store.complete_screening(app["id"], token))
        self.assertIsNone(self.db.get_captcha_challenge("server", "member"))
        self.assertEqual(self.store.get(app["id"])["status"], "answering")
        actions = self.db.claim_dashboard_actions()
        self.assertEqual(len([a for a in actions if a["action"] == "resume_application"]), 1)
        self.assertFalse(any(a["action"] == "complete_join_verification" for a in actions))

    def test_timeout_history_survives_review_extension_and_restart(self):
        app = self.application()
        manual = "2099-01-01T01:00:00+00:00"
        first = "2099-01-02T01:00:00+00:00"
        extended = "2099-01-03T01:00:00+00:00"
        self.store.set_timeout(app["id"], first, previous_timeout=manual)
        self.store.set_timeout(app["id"], extended)
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.store = self.db.applications
        self.assertEqual(self.store.resolve_timeout("server", "member", first.replace("+00:00", ".000Z")), (True, manual))
        self.assertEqual(self.store.resolve_timeout("server", "member", extended), (True, manual))
        self.assertEqual(self.store.resolve_timeout("another", "member", extended), (False, extended))
        self.assertEqual(self.store.resolve_timeout("server", "another", extended), (False, extended))

    def test_rejoin_does_not_save_old_application_timeout_as_moderation(self):
        first = self.application(joined="2026-01-01T01:00:00+00:00")
        self.store.set_timeout(first["id"], "2099-01-01T01:00:00+00:00")
        second = self.store.create("server", "member", "2026-01-02T01:00:00+00:00",
            screening_required=False, previous_timeout="2099-01-01T01:00:00.000Z")
        self.assertIsNone(second["previous_timeout"])
        # Same-second joins can have identical deadlines; they must not cycle.
        self.store.set_timeout(second["id"], "2099-01-01T01:00:00+00:00")
        self.assertEqual(self.store.resolve_timeout("server", "member", "2099-01-01T01:00:00+00:00"), (True, None))

    def test_timeout_history_migration_preserves_legacy_ownership(self):
        app = self.application()
        timeout = "2099-01-01T01:00:00+00:00"
        self.store.set_timeout(app["id"], timeout)
        with self.db.connection:
            self.db.connection.execute("ALTER TABLE join_applications DROP COLUMN timeout_history_json")
        migrated = ApplicationStore(self.db)
        self.assertEqual(migrated.resolve_timeout("server", "member", timeout), (True, None))

    def test_embed_customization_is_validated_and_snapshotted(self):
        question = {**QUESTIONS[0], "emoji": "🦦", "color": "#123ABC"}
        self.store.save_settings("server", "admin", {"enabled": True, "questions": [question],
            "appearance": {"color": "#F97316", "footer": "Welcome to the community", "submitted_title": "Thanks!",
                           "submitted_emoji": "🎉", "submitted_message": "Our team will be in touch."}})
        app = self.application()
        self.store.save_settings("server", "admin", {"enabled": True, "questions": QUESTIONS, "appearance": {"color": "#000000"}})
        saved = self.store.get(app["id"])
        self.assertEqual(saved["questions"][0], question)
        self.assertEqual(saved["appearance"]["color"], "#F97316")
        self.assertEqual(question_embeds(saved, "Test", 0)[0]["title"], "🦦 Introduce yourself")
        self.assertEqual(question_embeds(saved, "Test", 0)[0]["color"], "#123ABC")
        submitted = submission_embed(saved, "Test", app["expires_at"])
        self.assertEqual(submitted["title"], "🎉 Thanks!")
        self.assertIn("14 days", submitted["description"])
        self.assertIn("Our team will be in touch.", submitted["description"])
        for patch in ({"color": "javascript:alert(1)"}, {"footer": "x" * 161}, {"submitted_title": ""}):
            with self.assertRaises(ValueError):
                self.store.save_settings("server", "admin", {"enabled": True, "questions": QUESTIONS, "appearance": patch})
        for patch in ({"color": "red"}, {"emoji": "x" * 33}, {"emoji": "hi\nthere"}):
            with self.assertRaises(ValueError):
                self.store.save_settings("server", "admin", {"enabled": True, "questions": [{**QUESTIONS[0], **patch}]})

    def test_long_preview_and_dm_messages_fit_embed_limit_without_losing_text(self):
        form = {"introduction": "i" * 1000, "appearance": {"footer": "f" * 160}, "questions": [{
            **QUESTIONS[0], "prompt": "p" * 1200, "type": "choice", "required": False, "options": [str(i) * 100 for i in range(8)]}]}
        embeds = question_embeds(form, "Server", 0)
        self.assertEqual(len(embeds), 3)
        self.assertTrue(all(len(e["description"]) <= 1950 for e in embeds))
        self.assertIn(form["introduction"], embeds[0]["description"])
        self.assertIn(form["questions"][0]["prompt"], embeds[1]["description"])
        self.assertIn("8. " + "7" * 100, embeds[2]["description"])
        self.assertIn("skip", embeds[2]["description"])

    def test_repair_can_requeue_ready_access_without_changing_questions(self):
        self.db.claim_dashboard_actions()
        config = self.store.settings("server")
        result = self.store.save_settings("server", "admin", {**config, "repair_access": True})
        self.assertEqual(result["setup_status"], "pending")
        self.assertEqual(result["questions"], QUESTIONS)
        self.assertEqual([a["action"] for a in self.db.claim_dashboard_actions()], ["configure_applications"])

    def test_legacy_long_titles_and_emojis_fit_platform_limits(self):
        form = {"questions": [{**QUESTIONS[0], "title": "x" * 120, "emoji": "🦦"}],
                "appearance": {"submitted_title": "y" * 120, "submitted_emoji": "🎉"}}
        for embed in [*question_embeds(form, "Test", 0), submission_embed(form, "Test", "Next week")]:
            self.assertLessEqual(len(embed["title"]), 100)
            self.assertTrue(embed["title"].endswith("…"))
            self.assertLessEqual(len(embed["title"]) + len(embed["description"]), 2000)

    def test_channel_selection_survives_restart_and_queues_live_reconfiguration(self):
        self.db.update_dashboard_server_snapshot("server", "Test", 1, [("rules", "Rules")], [])
        app = self.application()
        self.db.claim_dashboard_actions()
        config = self.store.save_settings("server", "admin", {
            "enabled": True, "questions": QUESTIONS, "visible_channel_ids": ["rules", "rules"]})
        self.assertEqual(config["visible_channel_ids"], ["rules"])
        self.assertEqual(config["setup_status"], "pending")
        self.assertEqual(self.store.get(app["id"])["status"], "answering")
        self.assertEqual([a["action"] for a in self.db.claim_dashboard_actions()], ["configure_applications"])
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.store = self.db.applications
        self.assertEqual(self.store.settings("server")["visible_channel_ids"], ["rules"])
        self.store.update_setup("server", status="ready")
        self.configure()  # Older clients changing questions must preserve visibility.
        self.assertEqual(self.store.settings("server")["visible_channel_ids"], ["rules"])
        self.assertEqual(self.db.claim_dashboard_actions(), [])
        config = self.store.save_settings("server", "admin", {
            "enabled": False, "questions": QUESTIONS, "visible_channel_ids": []})
        self.assertEqual(config["setup_status"], "pending")

    def test_existing_database_migrates_to_hidden_channels_without_losing_form(self):
        with self.db.connection:
            self.db.connection.execute("ALTER TABLE join_form_settings DROP COLUMN visible_channel_ids_json")
        migrated = ApplicationStore(self.db).settings("server")
        self.assertEqual(migrated["visible_channel_ids"], [])
        self.assertEqual(migrated["questions"], QUESTIONS)
        self.assertEqual(migrated["access_role_id"], "access")

    def test_invalid_channel_selections_do_not_change_saved_settings(self):
        for value in ("rules", [None], [False], [""], ["unknown"], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.save_settings("server", "admin", {
                    "enabled": True, "questions": QUESTIONS, "visible_channel_ids": value})
        self.assertEqual(self.store.settings("server")["visible_channel_ids"], [])
        self.assertEqual(self.store.settings("server")["setup_status"], "ready")

    def test_permission_setup_claims_latest_saved_selection_and_blocks_concurrent_saves(self):
        self.db.update_dashboard_server_snapshot("server", "Test", 1, [("rules", "Rules"), ("intro", "Intro")], [])
        for selection in (["rules"], ["intro"]):
            self.store.save_settings("server", "admin", {
                "enabled": True, "questions": QUESTIONS, "visible_channel_ids": selection})
        claimed = self.store.begin_setup("server")
        self.assertEqual(claimed["visible_channel_ids"], ["intro"])
        with self.assertRaises(ValueError):
            self.store.save_settings("server", "admin", {
                "enabled": True, "questions": QUESTIONS, "visible_channel_ids": []})
        self.assertEqual(self.store.settings("server")["visible_channel_ids"], ["intro"])
        self.store.update_setup("server", status="ready")
        self.assertIsNone(self.store.begin_setup("server"))

    def test_duplicate_messages_and_replies_from_other_members(self):
        app = self.application()
        with self.assertRaises(ValueError):
            self.store.answer(app["id"], "intruder", 0, "message", "hello")
        self.store.answer(app["id"], "member", 0, "message", "hello")
        self.store.answer(app["id"], "member", 0, "message", "hello")
        self.assertEqual(len(self.store.get(app["id"])["answers"]), 1)
        with self.assertRaises(ValueError):
            self.store.answer(app["id"], "member", 0, "another", "hello")
        with self.assertRaises(ValueError):
            self.store.answer(app["id"], "member", 1, "another", "no")

    def test_submission_starts_full_fourteen_day_review_and_survives_restart(self):
        app = self.application()
        with self.db.connection:
            self.db.connection.execute("UPDATE join_applications SET expires_at=? WHERE id=?", (
                iso(datetime.now(timezone.utc) + timedelta(hours=1)), app["id"]))
        submitted = self.submit(app)
        remaining = datetime.fromisoformat(submitted["expires_at"]) - datetime.now(timezone.utc)
        self.assertGreater(remaining.total_seconds(), 14 * 86400 - 5)
        self.db.close()
        self.db = ModerationDatabase(self.path)
        self.store = self.db.applications
        self.assertEqual(self.store.get(app["id"])["status"], "submitted")
        self.assertTrue(any(a["action"] == "application_submitted" for a in self.db.claim_dashboard_actions()))

    def test_approval_scope_and_duplicate_decisions(self):
        app = self.application()
        with self.assertRaises(ValueError):
            self.store.decide("server", app["id"], "admin", "approved", "")
        self.submit(app)
        with self.assertRaises(ValueError):
            self.store.decide("other", app["id"], "admin", "approved", "")
        self.store.decide("server", app["id"], "admin", "approved", "Welcome")
        with self.assertRaises(ValueError):
            self.store.decide("server", app["id"], "admin", "denied", "Changed mind")
        actions = [a for a in self.db.claim_dashboard_actions() if a["action"] == "resolve_application"]
        self.assertEqual(len(actions), 1)

    def test_denial_requires_reason_and_expiry_does_not_requeue(self):
        app = self.submit(self.application())
        with self.assertRaises(ValueError):
            self.store.decide("server", app["id"], "admin", "denied", "")
        with self.db.connection:
            self.db.connection.execute("UPDATE join_applications SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (app["id"],))
        with self.assertRaises(ValueError):
            self.store.decide("server", app["id"], "admin", "approved", "")
        self.assertEqual(self.store.expire(), 1)
        self.assertEqual(self.store.expire(), 0)
        self.assertIsNone(self.store.get(app["id"]))

    def test_privacy_requires_current_notice_explicit_agreement_and_matching_owner(self):
        app = self.application(consent=False)
        with self.assertRaises(ValueError):
            self.store.answer(app["id"], "member", 0, "answer", "Must not be stored")
        with self.assertRaises(ValueError):
            self.store.accept_privacy(app["id"], "member", APPLICATION_PRIVACY_VERSION, agreed=True)
        self.store.update_delivery(app["id"], error=None, prompt_id="notice", channel_id="dm", position=-2)
        for user, version, agreed in [("other", APPLICATION_PRIVACY_VERSION, True), ("member", "old", True),
                                      ("member", APPLICATION_PRIVACY_VERSION, False), ("member", APPLICATION_PRIVACY_VERSION, "true")]:
            with self.assertRaises(ValueError):
                self.store.accept_privacy(app["id"], user, version, agreed=agreed)
        self.assertEqual(self.store.get(app["id"])["answers"], [])
        accepted = self.store.accept_privacy(app["id"], "member", APPLICATION_PRIVACY_VERSION, agreed=True)
        self.assertTrue(accepted["privacy_accepted_at"])
        self.assertEqual(accepted["privacy_version"], APPLICATION_PRIVACY_VERSION)
        self.store.answer(app["id"], "member", 0, "answer", "Now agreed")

    def test_all_decisions_delete_every_application_copy_at_original_deadline(self):
        for status in ["submitted", "approved", "denied"]:
            with self.subTest(status=status):
                app = self.submit(self.application(user=status))
                deadline = app["expires_at"]
                if status != "submitted":
                    app = self.store.decide("server", app["id"], "admin", status, "Review details")
                    self.store.finish(app["id"])
                self.assertEqual(app["expires_at"], deadline)
                self.db.add_event(server_id="server", event_type="application_"+status,
                                  details={"application_id": app["id"], "reason": "Private review"})
                with self.db.connection:
                    self.db.connection.execute("UPDATE join_applications SET expires_at='2000-01-01' WHERE id=?", (app["id"],))
                self.assertIsNone(self.store.get(app["id"]))
                self.assertNotIn(app["id"], [a["id"] for a in self.store.list("server")])
                with self.assertRaises(ValueError):
                    self.store.retry("server", app["id"], "admin")
                outcomes = self.store.prune()
                self.assertEqual([o["status"] for o in outcomes], ["denied"] if status == "submitted" else [])
                for table in ["join_applications", "join_application_answers", "join_application_dm_sessions"]:
                    self.assertEqual(self.db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
                for table, field in [("dashboard_actions", "payload_json"), ("moderation_events", "details_json")]:
                    self.assertEqual(self.db.connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {field} LIKE ?", ("%"+app["id"]+"%",)).fetchone()[0], 0)
                self.assertEqual(self.store.prune(), [])

    def test_expiring_old_application_does_not_remove_rejoined_members_new_challenge(self):
        old = self.application(joined="2026-01-01T00:00:00+00:00")
        new = self.application(joined="2026-01-02T00:00:00+00:00", screened=False)
        self.db.set_web_verification_challenge("server", "member", "new-token", new["expires_at"])
        with self.db.connection:
            self.db.connection.execute("UPDATE join_applications SET created_at='2000-01-01',expires_at='2000-01-02' WHERE id=?", (old["id"],))
        self.store.prune()
        self.assertIsNotNone(self.store.get(new["id"]))
        self.assertIsNotNone(self.db.get_captcha_challenge("server", "member"))

    def test_rejoin_invalidates_previous_tokens_and_dm_selection(self):
        app = self.application(screened=False, joined="2026-09-10T01:00:00+00:00")
        self.store.select("member", app["id"])
        self.db.set_web_verification_challenge("server", "member", "old-token", app["expires_at"])
        second = self.application(screened=False, joined="2026-09-10T02:00:00+00:00")
        self.assertNotEqual(second["id"], app["id"])
        self.assertEqual(self.store.get(app["id"])["status"], "left")
        self.assertIsNone(self.store.selected("member"))
        self.assertFalse(self.store.complete_screening(second["id"], "old-token"))
        self.assertEqual(self.application(screened=False, joined=second["joined_at"])["id"], second["id"])

    def test_privacy_export_includes_answers_and_server_purge_cascades(self):
        app = self.submit(self.application(user="01H00000000000000000000000"))
        matched = dict(self.db._privacy_matches(app["user_id"]))
        self.assertEqual(len(matched["join_application_answers"]), 2)
        self.db.purge_server_data("server")
        self.assertIsNone(self.store.get(app["id"]))
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM join_application_answers").fetchone()[0], 0)


class ApplicationFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.directory.name) / "flow.db")
        self.store = self.db.applications
        self.store.save_settings("server", "admin", {"enabled": True, "questions": QUESTIONS})
        self.store.update_setup("server", status="ready", role_id="access")
        self.joined = datetime.now(timezone.utc).replace(microsecond=0)
        self.member = SimpleNamespace(id="member", joined_at=self.joined, role_ids=[], timed_out_until=None)
        self.operations = []
        async def edit(**kwargs):
            self.operations.append(("roles", kwargs.get("roles")))
            if "roles" in kwargs:
                self.member.role_ids = kwargs["roles"]
            return self.member
        async def timeout(value):
            self.operations.append(("timeout", value))
            self.member.timed_out_until = value
            return self.member
        self.member.edit = AsyncMock(side_effect=edit)
        self.member.timeout = AsyncMock(side_effect=timeout)
        self.server = SimpleNamespace(id="server", name="Stoat fans", fetch_member=AsyncMock(return_value=self.member))
        self.messages = []
        self.message_counter = 1000
        async def send(*args, **kwargs):
            self.message_counter += 10
            sent = SimpleNamespace(id=str(self.message_counter).zfill(26), channel_id="dm", **kwargs)
            self.messages.append(sent)
            return sent
        self.dm = SimpleNamespace(send=AsyncMock(side_effect=send))
        self.user = SimpleNamespace(open_dm=AsyncMock(return_value=self.dm))
        self.bot = SimpleNamespace(database=self.db, _resolve_dashboard_server=AsyncMock(return_value=self.server),
            require_action_permissions=AsyncMock(return_value=True), get_user=Mock(return_value=self.user),
            fetch_user=AsyncMock(return_value=self.user), _send_user_dm=AsyncMock(return_value=True), send_log=AsyncMock(return_value=True),
            _kick_member_with_reason=AsyncMock(), _captcha_tasks={}, state=SimpleNamespace(my_id="bot"),
            moderation_settings=SimpleNamespace(dashboard_url="https://example.test"))
        self.flow = ApplicationFlow(self.bot)

    async def asyncTearDown(self):
        self.db.close()
        self.directory.cleanup()

    async def start(self, screening=False, consent=True):
        await self.flow.on_join(self.server, self.member, screening_required=screening, exempt=False)
        if consent:
            await self.answer("I agree")
        return self.store.current("server", "member")

    async def answer(self, text):
        self.message_counter += 1
        message = SimpleNamespace(id=str(self.message_counter).zfill(26), content=text, author_id="member",
            channel=self.dm, replies=[], get_server=lambda: (None, None))
        self.assertTrue(await self.flow.handle_dm(message))
        return message

    async def submit(self):
        app = await self.start()
        await self.answer("I love stoats")
        await self.answer("agree")
        return self.store.get(app["id"])

    async def test_complete_dm_application_approval_assigns_auto_role_and_releases_timeout(self):
        app = await self.start()
        self.assertEqual(len(self.messages), 2)
        self.assertIn("Application privacy agreement", self.messages[0].embeds[0].title)
        self.assertIn("Question 1 of 2", self.messages[1].embeds[0].description)
        self.assertEqual(self.member.role_ids, [])
        first_reply = await self.answer("I love stoats")
        self.assertIn("Question 2 of 2", self.messages[-1].embeds[0].description)
        await self.flow.handle_dm(first_reply)
        self.assertEqual(len(self.store.get(app["id"])["answers"]), 1)
        await self.answer("agree")
        app = self.store.get(app["id"])
        await self.flow.submitted(app)
        self.assertIn("14 days", self.messages[-1].embeds[0].description)
        self.db.add_auto_role("server", "starter", "admin")
        app = self.store.decide("server", app["id"], "admin", "approved", "Welcome")
        await self.flow.resolve(app)
        self.assertEqual(self.member.role_ids, ["starter", "access"])
        self.assertIsNone(self.member.timed_out_until)
        self.assertEqual(self.store.get(app["id"])["enforcement_status"], "applied")
        previous_operations = len(self.operations)
        await self.flow.resolve(app)
        self.assertEqual(len(self.operations), previous_operations)

    async def test_privacy_is_first_and_preconsent_replies_are_never_answers(self):
        app = await self.start(screening=True, consent=False)
        self.assertEqual(len(self.messages), 1)
        self.assertIn("Application privacy agreement", self.messages[0].embeds[0].title)
        self.assertIn("14 days", self.messages[0].embeds[0].description)
        self.assertIn("/privacy#applications", self.messages[0].content)
        self.assertIsNone(self.db.get_captcha_challenge("server", "member"))
        await self.answer("Here is private information, without agreeing")
        self.assertEqual(self.store.get(app["id"])["answers"], [])
        self.assertFalse(self.store.get(app["id"])["privacy_accepted_at"])
        await self.answer("I agree")
        self.assertIsNotNone(self.db.get_captcha_challenge("server", "member"))
        self.assertEqual(self.store.get(app["id"])["answers"], [])
        self.assertNotIn("IP scan", self.messages[-1].embeds[0].description)

    async def test_first_prompt_does_not_wait_for_slow_timeout_and_reuses_join_context(self):
        entered, release, delivered = asyncio.Event(), asyncio.Event(), asyncio.Event()
        original_timeout, original_send = self.member.timeout.side_effect, self.dm.send.side_effect
        async def delayed_timeout(value):
            entered.set()
            await release.wait()
            return await original_timeout(value)
        async def observe_send(*args, **kwargs):
            message = await original_send(*args, **kwargs)
            delivered.set()
            return message
        self.member.timeout.side_effect = delayed_timeout
        self.dm.send.side_effect = observe_send
        self.user.dm_channel = self.dm
        # The joining user was already resolved by the join handler.
        self.bot.get_user.return_value = None
        joining = asyncio.create_task(self.flow.on_join(self.server, self.member,
            screening_required=True, exempt=False, user=self.user))
        try:
            await asyncio.wait_for(asyncio.gather(entered.wait(), delivered.wait()), timeout=1)
            self.assertFalse(joining.done())
            self.assertIsNone(self.member.timed_out_until)
            self.server.fetch_member.assert_awaited_once_with("member")
            self.bot._resolve_dashboard_server.assert_not_awaited()
            self.bot.fetch_user.assert_not_awaited()
            self.user.open_dm.assert_not_awaited()
            self.assertEqual(self.member.role_ids, [])
        finally:
            release.set()
            await joining
        self.assertIsNotNone(self.member.timed_out_until)

    async def test_dm_open_and_membership_check_run_concurrently(self):
        fetching, opening, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def fetch_member(_uid):
            fetching.set()
            await release.wait()
            return self.member
        async def open_dm():
            opening.set()
            await release.wait()
            return self.dm
        self.server.fetch_member.side_effect = fetch_member
        self.user.open_dm.side_effect = open_dm
        joining = asyncio.create_task(self.start(consent=False))
        try:
            await asyncio.wait_for(asyncio.gather(fetching.wait(), opening.wait()), timeout=1)
            self.assertFalse(self.messages)
        finally:
            release.set()
            await joining
        self.assertEqual(len(self.messages), 1)

    async def test_access_role_is_removed_before_first_prompt(self):
        self.member.role_ids = ["access", "starter"]
        self.db.add_auto_role("server", "starter", "admin")
        original = self.dm.send.side_effect
        async def send(*args, **kwargs):
            self.assertEqual(self.member.role_ids, [])
            return await original(*args, **kwargs)
        self.dm.send.side_effect = send
        await self.start(consent=False)
        self.assertEqual(len(self.messages), 1)

    async def test_join_with_stale_membership_sends_no_application_prompt(self):
        self.server.fetch_member.return_value = SimpleNamespace(id="member", joined_at=self.joined + timedelta(minutes=1))
        app = await self.start(consent=False)
        self.assertEqual(app["status"], "left")
        self.assertFalse(self.messages)
        self.member.timeout.assert_not_awaited()

    async def test_timeout_failure_preserves_the_delivered_prompt_for_retry(self):
        self.member.timeout.side_effect = PermissionError("Missing timeout permission")
        app = await self.start(consent=False)
        self.assertEqual(len(self.messages), 1)
        self.assertEqual(app["prompt_message_id"], self.messages[0].id)
        self.assertEqual(app["dm_channel_id"], "dm")
        self.assertIn("Missing timeout permission", app["error"])
        self.bot.send_log.assert_awaited()

    async def test_deleted_cached_dm_is_reopened(self):
        deleted = SimpleNamespace(send=AsyncMock(side_effect=stoat.NotFound(SimpleNamespace(status=404), {"type":"NotFound"})))
        self.user.dm_channel = deleted
        await self.start(consent=False)
        self.user.open_dm.assert_awaited_once()
        self.assertEqual(len(self.messages), 1)

    async def test_screening_starts_no_questions_and_never_releases_timeout(self):
        app = await self.start(screening=True)
        self.assertEqual(app["status"], "screening")
        self.assertIn("Verify before applying", self.messages[-1].embeds[0].title)
        self.assertNotIn("Question 1", self.messages[-1].embeds[0].description)
        challenge = self.db.get_captcha_challenge("server", "member")
        self.assertTrue(self.store.complete_screening(app["id"], challenge.answer_hash))
        await self.flow.resume(app)
        self.assertIn("Question 1", self.messages[-1].embeds[0].description)
        self.assertIsNotNone(self.member.timed_out_until)
        self.assertEqual(self.member.role_ids, [])

    async def test_captcha_link_is_visible_in_message_content_and_embed_title(self):
        app = await self.start(screening=True)
        message = self.messages[-1]
        parts = urlsplit(message.content)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ("https", "example.test", "/verify"))
        token = parse_qs(parts.query)["token"][0]
        challenge = self.db.get_captcha_challenge("server", "member")
        self.assertEqual(hashlib.sha256(token.encode()).hexdigest(), challenge.answer_hash)
        self.assertEqual(message.embeds[0].url, message.content)
        self.assertIn(message.content, message.embeds[0].description)
        self.assertNotIn("[Complete verification]", message.embeds[0].description)
        self.assertEqual(self.store.get(app["id"])["prompt_message_id"], message.id)
        self.assertEqual(self.member.role_ids, [])
        self.assertIsNotNone(self.member.timed_out_until)

    async def test_captcha_retry_sends_a_visible_fresh_link_without_releasing_access(self):
        app = await self.start(screening=True)
        previous = self.db.get_captcha_challenge("server", "member").answer_hash
        self.store.retry("server", app["id"], "admin")
        actions = self.db.claim_dashboard_actions()
        retry = next(a for a in actions if a["action"] == "resume_application")
        await self.flow.action(retry)
        token = parse_qs(urlsplit(self.messages[-1].content).query)["token"][0]
        current = self.db.get_captcha_challenge("server", "member").answer_hash
        self.assertNotEqual(current, previous)
        self.assertEqual(current, hashlib.sha256(token.encode()).hexdigest())
        self.assertFalse(self.store.complete_screening(app["id"], previous))
        self.assertEqual(self.store.get(app["id"])["status"], "screening")
        self.assertEqual(self.member.role_ids, [])
        self.assertIsNotNone(self.member.timed_out_until)

    async def test_failed_dm_retains_restriction_and_notifies_admin_log(self):
        self.dm.send.side_effect = RuntimeError("DM blocked")
        app = await self.start(consent=False)
        self.assertIsNotNone(self.member.timed_out_until)
        self.assertEqual(self.member.role_ids, [])
        self.assertIn("DM blocked", app["error"])
        self.bot.send_log.assert_awaited()

    async def test_denial_passes_exact_reason_to_kick_and_notifications(self):
        app = await self.submit()
        app = self.store.decide("server", app["id"], "admin", "denied", "Your answers do not meet the server rules")
        await self.flow.resolve(app)
        self.bot._kick_member_with_reason.assert_awaited_once_with(self.member, "server", "member", "Admission application denied", actor_id="admin")
        await self.flow.notify_decision(self.store.get(app["id"]))
        self.assertIn(app["reason"], self.bot._send_user_dm.call_args.args[2])
        self.assertEqual(self.member.role_ids, [])

    async def test_new_moderation_timeout_survives_approval(self):
        app = await self.submit()
        manual_timeout = datetime.now(timezone.utc) + timedelta(days=14)
        self.member.timed_out_until = manual_timeout
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        await self.flow.resolve(app)
        self.assertEqual(self.member.timed_out_until, manual_timeout)

    async def test_approval_unwinds_legacy_timeouts_from_multiple_previous_applications(self):
        previous = None
        for offset in range(3):
            self.member.joined_at = self.joined + timedelta(minutes=offset)
            app = self.store.create("server", "member", iso(self.member.joined_at), screening_required=False)
            timeout = iso(datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=7, minutes=offset))
            # Recreate the exact chain left by the old release, without history.
            with self.db.connection:
                self.db.connection.execute("UPDATE join_applications SET previous_timeout=?,verification_timeout=? WHERE id=?",
                    (previous, timeout, app["id"]))
            previous = timeout
        self.member.timed_out_until = datetime.fromisoformat(timeout)
        self.store.update_delivery(app["id"], error=None, prompt_id="notice", channel_id="dm", position=-2)
        self.store.accept_privacy(app["id"], "member", APPLICATION_PRIVACY_VERSION, agreed=True)
        self.store.answer(app["id"], "member", 0, "first", "Hello")
        self.store.answer(app["id"], "member", 1, "second", "agree")
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        self.db.add_auto_role("server", "starter", "admin")
        await self.flow.resolve(app)
        self.assertIsNone(self.member.timed_out_until)
        self.assertEqual(self.member.role_ids, ["starter", "access"])
        await self.flow.notify_decision(self.store.get(app["id"]))
        self.assertNotIn("moderation timeout", self.bot._send_user_dm.call_args.args[2])

    async def test_approved_member_retry_clears_timeout_restored_by_old_release(self):
        app = await self.submit()
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        leftover = self.member.timed_out_until
        await self.flow.resolve(app)
        self.member.timed_out_until = leftover
        # The normal retry path rechecks access even if the old version claimed
        # it had already applied the approval successfully.
        self.store.retry("server", app["id"], "admin")
        self.assertEqual(self.store.get(app["id"])["enforcement_status"], "pending")
        await self.flow.resolve(self.store.get(app["id"]))
        self.assertIsNone(self.member.timed_out_until)
        self.assertIn("access", self.member.role_ids)

    async def test_delayed_submission_cannot_reapply_timeout_after_approval(self):
        submitted = await self.submit()
        approved = self.store.decide("server", submitted["id"], "admin", "approved", "")
        await self.flow.resolve(approved)
        operations = list(self.operations)
        await self.flow.submitted(submitted)
        await self.flow.ensure_timeout(self.server, self.member, submitted)
        self.assertEqual(self.operations, operations)
        self.assertIsNone(self.member.timed_out_until)

    async def test_approval_waits_for_inflight_submission_timeout_before_clearing_it(self):
        app = await self.submit()
        with self.db.connection:
            self.db.connection.execute("UPDATE join_applications SET expires_at=? WHERE id=?",
                (iso(datetime.now(timezone.utc) + timedelta(days=7, minutes=1)), app["id"]))
        started, release = asyncio.Event(), asyncio.Event()
        original = self.member.timeout.side_effect
        async def slow_timeout(value):
            started.set()
            await release.wait()
            return await original(value)
        self.member.timeout.side_effect = slow_timeout
        submission = asyncio.create_task(self.flow.submitted(app))
        await asyncio.wait_for(started.wait(), timeout=2)
        approved = self.store.decide("server", app["id"], "admin", "approved", "")
        approval = asyncio.create_task(self.flow.resolve(approved))
        await asyncio.sleep(0)
        self.assertFalse(approval.done())
        release.set()
        await asyncio.wait_for(asyncio.gather(submission, approval), timeout=2)
        self.assertIsNone(self.member.timed_out_until)
        self.assertEqual(self.store.get(app["id"])["enforcement_status"], "applied")

    async def test_unconfirmed_timeout_removal_does_not_report_approval_success(self):
        app = await self.submit()
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        self.member.timeout = AsyncMock(return_value=self.member)
        with self.assertRaisesRegex(RuntimeError, "timeout could not be removed"):
            await self.flow.resolve(app)
        self.assertEqual(self.store.get(app["id"])["enforcement_status"], "failed")
        await self.flow.notify_decision(self.store.get(app["id"]))
        self.bot._send_user_dm.assert_not_awaited()

    async def test_known_verification_timeout_is_never_called_a_moderation_timeout(self):
        app = await self.submit()
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        self.store.finish(app["id"])
        with self.assertRaisesRegex(RuntimeError, "application timeout is still active"):
            await self.flow.notify_decision(self.store.get(app["id"]))
        self.bot._send_user_dm.assert_not_awaited()
        self.assertEqual(self.store.get(app["id"])["enforcement_status"], "failed")

    async def test_role_failure_does_not_remove_timeout(self):
        app = await self.submit()
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        self.member.edit.side_effect = PermissionError("Role too high")
        with self.assertRaises(PermissionError):
            await self.flow.resolve(app)
        self.assertIsNotNone(self.member.timed_out_until)
        self.assertEqual(self.store.get(app["id"])["enforcement_status"], "failed")

    async def test_rejoined_member_cannot_be_kicked_or_approved_by_old_application(self):
        app = await self.submit()
        app = self.store.decide("server", app["id"], "admin", "denied", "No thank you")
        self.member.joined_at += timedelta(hours=1)
        await self.flow.resolve(app)
        self.bot._kick_member_with_reason.assert_not_awaited()
        self.assertEqual(self.member.role_ids, [])

    async def test_submission_notifications_continue_when_applicant_dm_fails(self):
        app = await self.submit()
        self.db.update_dashboard_server_snapshot("server", "Stoat fans", 1, [], [], owner_id="admin")
        self.store.notification_preference("server", "admin", True)
        self.dm.send.side_effect = RuntimeError("DM blocked")
        with self.assertRaises(RuntimeError):
            await self.flow.submitted(app)
        self.bot.send_log.assert_awaited()
        self.bot._send_user_dm.assert_awaited_once()
        self.assertIn("dashboard", self.bot._send_user_dm.call_args.args[2])

    async def test_channel_defaults_hidden_but_old_private_visibility_preserved(self):
        gate = {"server_default": stoat.Permissions(view_channel=True, send_messages=True).value, "channels": {}}
        self.server.channel_ids = ["general"]
        channel = Mock(spec=stoat.TextChannel)
        channel.id = "general"
        channel.default_permissions = stoat.PermissionOverride()
        channel.get_category.return_value = None
        channel.set_role_permissions = AsyncMock()
        async def set_default(permissions):
            channel.default_permissions = permissions
            return channel
        channel.set_default_permissions = AsyncMock(side_effect=set_default)
        self.bot.fetch_channel = AsyncMock(return_value=channel)
        await self.flow.protect_channel(self.server, channel, "access", gate)
        self.assertFalse(channel.default_permissions.deny.view_channel)
        self.assertFalse(channel.default_permissions.allow.view_channel)
        self.assertFalse(channel.set_role_permissions.call_args.kwargs["allow"].view_channel)
        channel.id = "private"
        channel.default_permissions = stoat.PermissionOverride(deny=stoat.Permissions(view_channel=True))
        await self.flow.protect_channel(self.server, channel, "access", gate)
        self.assertFalse(channel.set_role_permissions.call_args.kwargs["allow"].view_channel)

    async def test_setup_grants_existing_member_access_before_hiding_channels(self):
        self.store.update_setup("server", status="pending")
        self.server.owner_id = "owner"
        self.server.default_permissions = stoat.Permissions(view_channel=True, send_messages=True)
        self.server.roles = {"bot-role": SimpleNamespace(rank=1)}
        bot_member = SimpleNamespace(id="bot", role_ids=["bot-role"])
        self.server.fetch_member = AsyncMock(side_effect=lambda uid: bot_member if uid == "bot" else self.member)
        self.server.permissions_for = Mock(return_value=stoat.Permissions.all())
        self.server.fetch_members = AsyncMock(return_value=[self.member])
        self.server.set_role_permissions = AsyncMock()
        self.server.channel_ids = ["general"]
        channel = Mock(spec=stoat.TextChannel)
        channel.id = "general"
        channel.default_permissions = stoat.PermissionOverride()
        channel.get_category.return_value = None
        channel.set_role_permissions = AsyncMock()
        async def hide(permissions):
            self.assertIn("access", self.member.role_ids)
            channel.default_permissions = permissions
        channel.set_default_permissions = AsyncMock(side_effect=hide)
        self.bot.fetch_channel = AsyncMock(return_value=channel)
        async def defaults(permissions):
            self.assertIn("access", self.member.role_ids)
            self.server.default_permissions = permissions
        self.server.set_default_permissions = AsyncMock(side_effect=defaults)
        await self.flow.configure("server")
        self.assertEqual(self.server.default_permissions.value, 0)
        self.assertEqual(self.store.settings("server")["setup_status"], "ready")
        self.assertFalse(channel.default_permissions.allow.view_channel)
        self.assertFalse(channel.default_permissions.deny.view_channel)

    async def test_visible_channels_remain_read_only_and_approval_restores_baseline(self):
        original = stoat.Permissions(view_channel=True, read_message_history=True, send_messages=True,
                                     react=True, connect=True, manage_messages=True)
        gate = {"server_default": original.value, "channels": {}}
        channel = Mock(spec=stoat.TextChannel)
        channel.id = "rules"
        channel.default_permissions = stoat.PermissionOverride()
        channel.get_category.return_value = SimpleNamespace(id="category", default_permissions=stoat.PermissionOverride(
            allow=stoat.Permissions(manage_webhooks=True)))
        channel.set_role_permissions = AsyncMock()
        async def set_default(permissions):
            channel.default_permissions = permissions
        channel.set_default_permissions = AsyncMock(side_effect=set_default)
        self.bot.fetch_channel = AsyncMock(return_value=channel)
        await self.flow.protect_channel(self.server, channel, "access", gate, visible=True)
        effective = calculate_server_channel_permissions(stoat.Permissions.none(), [],
            default_permissions=channel.default_permissions, role_permissions={})
        self.assertEqual(effective, stoat.Permissions(view_channel=True, read_message_history=True))
        self.assertFalse(effective.send_messages)
        self.assertFalse(effective.connect)
        self.assertFalse(effective.react)
        verified = stoat.PermissionOverride(**channel.set_role_permissions.call_args.kwargs)
        approved = calculate_server_channel_permissions(stoat.Permissions(original.value | stoat.Permissions(manage_webhooks=True).value), [SimpleNamespace(id="access")],
            default_permissions=channel.default_permissions, role_permissions={"access": verified})
        self.assertEqual(approved.value, original.value | stoat.Permissions(manage_webhooks=True).value)
        snapshot = dict(gate["channels"]["rules"])
        await self.flow.protect_channel(self.server, channel, "access", gate, visible=False)
        hidden = calculate_server_channel_permissions(stoat.Permissions.none(), [],
            default_permissions=channel.default_permissions, role_permissions={})
        self.assertEqual(hidden.value, 0)
        self.assertEqual(gate["channels"]["rules"], snapshot)
        self.assertEqual(channel.set_role_permissions.call_args.kwargs["allow"], verified.allow)

    async def test_selected_private_channel_does_not_leak_to_verified_members(self):
        gate = {"server_default": stoat.Permissions(view_channel=True, read_message_history=True).value, "channels": {}}
        channel = Mock(spec=stoat.TextChannel)
        channel.id = "private"
        channel.default_permissions = stoat.PermissionOverride(deny=stoat.Permissions(view_channel=True))
        channel.get_category.return_value = None
        channel.set_role_permissions = AsyncMock()
        async def set_default(permissions):
            channel.default_permissions = permissions
        channel.set_default_permissions = AsyncMock(side_effect=set_default)
        self.bot.fetch_channel = AsyncMock(return_value=channel)
        await self.flow.protect_channel(self.server, channel, "access", gate, visible=True)
        self.assertTrue(channel.default_permissions.allow.view_channel)
        overrides = {"access": stoat.PermissionOverride(**channel.set_role_permissions.call_args.kwargs)}
        verified = calculate_server_channel_permissions(stoat.Permissions.none(), [SimpleNamespace(id="access")],
            default_permissions=channel.default_permissions, role_permissions=overrides)
        self.assertFalse(verified.view_channel)
        overrides["staff"] = stoat.PermissionOverride(allow=stoat.Permissions(view_channel=True, send_messages=True))
        staff = calculate_server_channel_permissions(stoat.Permissions.none(),
            [SimpleNamespace(id="access"), SimpleNamespace(id="staff")],
            default_permissions=channel.default_permissions, role_permissions=overrides)
        self.assertTrue(staff.view_channel)
        self.assertTrue(staff.send_messages)

    async def test_visibility_can_be_reconfigured_while_new_applications_are_disabled(self):
        self.db.update_dashboard_server_snapshot("server", "Test", 1, [("rules", "Rules")], [])
        await self.start()
        gate = {"server_default": stoat.Permissions(view_channel=True, send_messages=True).value,
                "channels": {"rules": {"allow": 0, "deny": 0, "baseline": stoat.Permissions(view_channel=True).value}}}
        self.store.update_setup("server", status="ready", gate=gate)
        self.store.save_settings("server", "admin", {"enabled": False, "questions": QUESTIONS, "visible_channel_ids": ["rules"]})
        self.server.owner_id = "owner"
        self.server.roles = {"bot-role": SimpleNamespace(rank=1)}
        self.server.fetch_member = AsyncMock(side_effect=lambda uid: SimpleNamespace(id="bot",role_ids=["bot-role"]) if uid == "bot" else self.member)
        self.server.permissions_for = Mock(return_value=stoat.Permissions.all())
        self.server.fetch_members = AsyncMock(return_value=[self.member])
        self.server.set_role_permissions = AsyncMock()
        self.server.set_default_permissions = AsyncMock()
        self.server.channel_ids = ["rules"]
        channel = Mock(spec=stoat.TextChannel)
        channel.id = "rules"
        channel.get_category.return_value = None
        self.bot.fetch_channel = AsyncMock(return_value=channel)
        self.flow.protect_channel = AsyncMock()
        await self.flow.configure("server")
        self.flow.protect_channel.assert_awaited_once_with(self.server, channel, "access", {**gate, "revision": 2}, visible=True)
        self.assertNotIn("access", self.member.role_ids)
        self.assertEqual(self.store.settings("server")["setup_status"], "ready")

    def permission_fixture(self, *, staff_allow=None, category_allow=0, private=False):
        """Actual role order: staff shares the bot's highest role (NotElevated)."""
        original = stoat.Permissions(view_channel=True, read_message_history=True, send_messages=True).value
        self.server.default_permissions = stoat.Permissions(original)
        self.server.owner_id = "owner"
        self.server.roles = {
            "staff": SimpleNamespace(id="staff", rank=0, permissions=stoat.PermissionOverride(
                allow=stoat.Permissions.all() if staff_allow is None else stoat.Permissions(staff_allow))),
            "access": SimpleNamespace(id="access", rank=1, permissions=stoat.PermissionOverride())}
        peer = SimpleNamespace(id="peer", role_ids=["staff"], joined_at=self.joined, edit=AsyncMock())
        bot_member = SimpleNamespace(id="bot", role_ids=["staff"], joined_at=self.joined)
        async def bot_edit(**kw):
            bot_member.role_ids = kw["roles"]
        bot_member.edit = AsyncMock(side_effect=bot_edit)
        members = {"peer": peer, "bot": bot_member, "member": self.member}
        self.server.fetch_member = AsyncMock(side_effect=lambda uid: members[uid])
        self.server.fetch_members = AsyncMock(return_value=list(members.values()))
        self.server.permissions_for = Mock(return_value=stoat.Permissions.all())
        async def role_permissions(role_id, **kwargs):
            self.server.roles[role_id].permissions = stoat.PermissionOverride(**kwargs)
        self.server.set_role_permissions = AsyncMock(side_effect=role_permissions)
        async def default_permissions(permissions):
            self.server.default_permissions = permissions
        self.server.set_default_permissions = AsyncMock(side_effect=default_permissions)
        category = SimpleNamespace(id="category", default_permissions=stoat.PermissionOverride(allow=stoat.Permissions(category_allow)), role_permissions={})
        channel = Mock(spec=stoat.TextChannel)
        channel.id = "general"
        channel.default_permissions = stoat.PermissionOverride(deny=stoat.Permissions(view_channel=private))
        channel.role_permissions = {}
        channel.get_category.return_value = category
        async def channel_role(role_id, **kwargs):
            channel.role_permissions[role_id] = stoat.PermissionOverride(**kwargs)
        async def channel_default(permissions):
            channel.default_permissions = permissions
        channel.set_role_permissions = AsyncMock(side_effect=channel_role)
        channel.set_default_permissions = AsyncMock(side_effect=channel_default)
        async def category_role(_sid, _cid, role_id, **kwargs):
            category.role_permissions[role_id] = stoat.PermissionOverride(**kwargs)
            return category
        async def category_default(_sid, _cid, **kwargs):
            category.default_permissions = stoat.PermissionOverride(**kwargs)
            return category
        self.bot.http = SimpleNamespace(set_category_permissions_for_role=AsyncMock(side_effect=category_role),
            set_default_category_permissions=AsyncMock(side_effect=category_default))
        self.server.channel_ids = [channel.id]
        self.bot.fetch_channel = AsyncMock(return_value=channel)
        self.store.update_setup("server", status="pending")
        return channel, category, peer

    async def test_equal_rank_staff_does_not_block_hiding_and_pending_member_stays_roleless(self):
        app = await self.start()
        channel, category, peer = self.permission_fixture(category_allow=stoat.Permissions(manage_webhooks=True).value)
        await self.flow.configure("server")
        self.assertEqual(self.store.settings("server")["setup_status"], "ready")
        self.assertEqual(self.server.default_permissions.value, 0)
        self.assertEqual(category.default_permissions.allow.value, 0)
        self.assertEqual(channel.default_permissions.allow.value, 0)
        peer.edit.assert_not_awaited()
        self.assertEqual(self.member.role_ids, [])
        self.assertEqual(self.store.get(app["id"])["status"], "answering")
        gate = self.store.settings("server")["gate"]
        self.assertEqual(member_channel_bits(self.server, self.member, channel, gate, gated=True, visible=False), 0)
        self.assertTrue(member_channel_bits(self.server, peer, channel, gate, gated=True, visible=False) & stoat.Permissions(view_channel=True).value)
        # An approved member recovers the original category grants too.
        await self.flow.add_roles(self.server, self.member, ["access"])
        approved = member_channel_bits(self.server, self.member, channel, gate, gated=True, visible=False)
        self.assertTrue(approved & stoat.Permissions(send_messages=True, manage_webhooks=True).value)

    async def test_elevated_member_who_depends_on_defaults_stops_setup_before_any_access_is_removed(self):
        channel, category, peer = self.permission_fixture(staff_allow=stoat.Permissions(manage_messages=True).value)
        with self.assertRaisesRegex(PermissionError, "at or above Stoatmod"):
            await self.flow.configure("server")
        channel.set_default_permissions.assert_not_awaited()
        self.server.set_default_permissions.assert_not_awaited()
        self.bot.http.set_default_category_permissions.assert_not_awaited()
        self.assertEqual(self.store.settings("server")["setup_status"], "error")
        peer.edit.assert_not_awaited()

    async def test_legacy_categories_do_not_require_new_permission_endpoints(self):
        channel, _category, peer = self.permission_fixture()
        await self.flow.configure("server")
        self.assertIn("access", self.member.role_ids)
        self.bot.http.set_default_category_permissions.assert_not_awaited()
        self.bot.http.set_category_permissions_for_role.assert_not_awaited()
        peer.edit.assert_not_awaited()
        gate = self.store.settings("server")["gate"]
        # A higher role's explicit global denial must survive verification.
        self.server.roles["restricted"] = SimpleNamespace(id="restricted", rank=0,
            permissions=stoat.PermissionOverride(deny=stoat.Permissions(send_messages=True)))
        self.member.role_ids.append("restricted")
        effective = member_channel_bits(self.server, self.member, channel, gate, gated=True, visible=False)
        self.assertFalse(effective & stoat.Permissions(send_messages=True).value)

    async def test_customized_dm_matches_the_shared_preview_formatter(self):
        settings = self.store.settings("server")
        settings["appearance"].update({"color": "#FFAA00", "footer": "A friendly place to meet"})
        settings["questions"][0].update({"emoji": "🌻", "color": "#224466"})
        self.store.save_settings("server", "admin", settings)
        app = await self.start()
        expected = question_embeds(app, self.server.name, 0)[0]
        actual = self.messages[-1].embeds[0]
        self.assertEqual((actual.title, actual.description, actual.color),
                         (expected["title"], expected["description"], expected["color"]))

    async def test_expiry_deletes_before_removal_and_does_not_retain_failed_retry(self):
        app = await self.submit()
        with self.db.connection:
            self.db.connection.execute("UPDATE join_applications SET expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (app["id"],))
        async def kick():
            self.assertIsNone(self.store.get(app["id"]))
            raise RuntimeError("Network unavailable")
        self.member.kick = AsyncMock(side_effect=kick)
        await self.flow.maintenance()
        self.member.kick.assert_awaited_once()
        self.assertIsNone(self.store.get(app["id"]))
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM join_application_answers").fetchone()[0], 0)
        self.flow.last_maintenance = 0
        await self.flow.maintenance()
        self.member.kick.assert_awaited_once()

    async def test_screening_restart_never_runs_legacy_timeout_rollback(self):
        await self.start(screening=True)
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = self.db
        bot._recover_unissued_captcha = AsyncMock()
        bot._schedule_captcha_expiry = Mock()
        await bot.resume_captcha_challenges()
        bot._recover_unissued_captcha.assert_not_awaited()
        bot._schedule_captcha_expiry.assert_not_called()
        self.assertIsNotNone(self.member.timed_out_until)

    async def test_shorter_manual_timeout_is_restored_after_review_extension(self):
        app = await self.start()
        manual = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=2)
        self.member.timed_out_until = manual
        await self.answer("Hello")
        await self.answer("agree")
        app = self.store.get(app["id"])
        await self.flow.submitted(app)
        app = self.store.decide("server", app["id"], "admin", "approved", "")
        await self.flow.resolve(app)
        self.assertEqual(self.member.timed_out_until, manual)

    async def test_approve_command_uses_admin_access_and_requires_submission(self):
        app = await self.submit()
        self.db.update_dashboard_server_snapshot("server", "Stoat fans", 1, [], [], owner_id="admin")
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = self.db
        bot.send_command_response = AsyncMock()
        self.server.owner_id = "admin"
        self.server.permissions_for = Mock(return_value=stoat.Permissions.none())
        message = SimpleNamespace(content="~approve member Application reviewed", author_id="intruder", get_server=lambda:(self.server,"server"))
        self.assertTrue(await bot.handle_command(message))
        self.assertEqual(self.store.get(app["id"])["status"], "submitted")
        message.author_id = "admin"
        self.assertTrue(await bot.handle_command(message))
        self.assertEqual(self.store.get(app["id"])["status"], "approved")

    def uncached_review_command(self, command="~approve member Application reviewed", author="admin"):
        self.db.update_dashboard_server_snapshot("server", "Test", 1, [], [], owner_id="admin")
        self.server.owner_id = "admin"
        self.server.permissions_for = Mock(return_value=stoat.Permissions.none())
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = self.db
        bot.fetch_channel = AsyncMock(return_value=SimpleNamespace(server_id="server"))
        bot._resolve_dashboard_server = AsyncMock(return_value=self.server)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(content=command, author_id=author, channel_id="logs", get_server=lambda:(None,""))
        return bot, message

    async def test_approve_recovers_server_from_uncached_channel_and_finishes_admission(self):
        app = await self.submit()
        bot, message = self.uncached_review_command()
        await bot.handle_command(message)
        bot.fetch_channel.assert_awaited_once_with("logs")
        bot._resolve_dashboard_server.assert_awaited_once_with("server")
        self.assertEqual(self.store.get(app["id"])["status"], "approved")
        self.assertEqual(bot.send_command_response.call_args.args[1], "Application decision saved")
        await self.flow.resolve(self.store.get(app["id"]))
        self.assertIn("access", self.member.role_ids)
        self.assertIsNone(self.member.timed_out_until)

    async def test_deny_recovers_server_from_uncached_channel(self):
        app = await self.submit()
        bot, message = self.uncached_review_command("~deny member Please read our rules")
        await bot.handle_command(message)
        self.assertEqual(self.store.get(app["id"])["status"], "denied")
        self.assertEqual(self.store.get(app["id"])["reason"], "Please read our rules")

    async def test_uncached_review_still_requires_server_admin_access(self):
        app = await self.submit()
        bot, message = self.uncached_review_command(author="intruder")
        await bot.handle_command(message)
        self.assertEqual(self.store.get(app["id"])["status"], "submitted")
        self.assertEqual(bot.send_command_response.call_args.args[1], "Permission denied")

    async def test_approve_in_actual_dm_cannot_select_a_server_implicitly(self):
        app = await self.submit()
        bot, message = self.uncached_review_command()
        bot.fetch_channel.return_value = SimpleNamespace()
        await bot.handle_command(message)
        self.assertEqual(self.store.get(app["id"])["status"], "submitted")
        self.assertEqual(bot.send_command_response.call_args.args[1], "Server-only command")
        bot._resolve_dashboard_server.assert_not_awaited()

    async def test_approve_lookup_failure_is_reported_as_temporary_not_a_dm(self):
        app = await self.submit()
        bot, message = self.uncached_review_command()
        bot.fetch_channel.side_effect = RuntimeError("Temporary API outage")
        await bot.handle_command(message)
        self.assertEqual(self.store.get(app["id"])["status"], "submitted")
        self.assertEqual(bot.send_command_response.call_args.args[1], "Application review temporarily unavailable")

    async def test_multiple_servers_require_selection_and_keep_answers_separate(self):
        first = await self.start()
        self.store.select("member", first["id"])
        self.store.save_settings("second", "admin", {"enabled": True, "questions": QUESTIONS})
        self.store.update_setup("second", status="ready", role_id="second-access")
        second = self.store.create("second", "member", iso(self.joined), screening_required=False)
        await self.answer("This answer must not go to a random server")
        self.assertEqual(self.store.get(first["id"])["answers"], [])
        self.assertEqual(self.store.get(second["id"])["answers"], [])
        await self.answer("~application " + first["id"])
        await self.answer("For the first server")
        self.assertEqual(self.store.get(first["id"])["answers"][0]["answer"], "For the first server")
        self.assertEqual(self.store.get(second["id"])["answers"], [])
