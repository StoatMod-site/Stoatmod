"""The optional per-server "thinking" check: classifier request, stored reasoning, case detail and 30-day purge."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestServer

from database import ModerationDatabase
from moderation import StoatGuardModerator, parse_thinking
from moderation_policy import SUPPORTED_MODERATION_CATEGORIES


VERSION = "nemotron-v15-test-thinking"
TEXT_SCORES = {category: 0.01 for category in SUPPORTED_MODERATION_CATEGORIES if category != "violence"}
TEXT_SCORES["illicit"] = 0.95
THINKING_BLOCK = {
    "applied": True,
    "verifier": "adapter",
    "heads": {
        "illicit": {
            "classifier_score": 0.95, "verdict": "unsafe", "final_score": 0.95,
            "reasoning": "The user states a concrete plan to sell drugs with a price and contact.",
            "tokens": 41, "forced_answer": False,
        },
        "not-a-category": {"verdict": "unsafe", "reasoning": "dropped"},
        "hate": {"verdict": "maybe", "reasoning": "dropped: invalid verdict"},
    },
    "request_seconds": 1.2,
}


class ParseThinkingTests(unittest.TestCase):
    def test_keeps_only_well_formed_heads_for_known_categories(self):
        parsed = parse_thinking(THINKING_BLOCK, TEXT_SCORES)
        self.assertEqual(set(parsed["heads"]), {"illicit"})
        self.assertEqual(parsed["heads"]["illicit"]["verdict"], "unsafe")
        self.assertEqual(parsed["heads"]["illicit"]["classifier_score"], 0.95)
        self.assertTrue(parsed["used"])

    def test_reasoning_is_capped(self):
        block = {"heads": {"illicit": {"verdict": "safe", "reasoning": "x" * 5000}}}
        self.assertEqual(len(parse_thinking(block, TEXT_SCORES)["heads"]["illicit"]["reasoning"]), 1000)

    def test_malformed_block_yields_no_heads(self):
        self.assertEqual(parse_thinking("nonsense", TEXT_SCORES), {"used": True, "heads": {}})


class ThinkingClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.payloads: list[dict] = []
        self.fail_thinking = False

        async def health(_request):
            return web.json_response({"ok": True, "version": VERSION,
                                      "vision": {"enabled": True, "image_categories": ["violence", "sexual"]}})

        async def classify(request):
            payload = await request.json()
            self.payloads.append(payload)
            if payload.get("thinking") and self.fail_thinking:
                return web.json_response({"error": "busy"}, status=503)
            result = {"version": VERSION, "scores": TEXT_SCORES, "fired": ["illicit"]}
            if payload.get("thinking"):
                result["thinking"] = THINKING_BLOCK
            return web.json_response({"version": VERSION, "results": [result], "thinking": bool(payload.get("thinking"))})

        app = web.Application()
        app.router.add_get("/health", health)
        app.router.add_post("/classify", classify)
        self.server = TestServer(app)
        await self.server.start_server()
        self.moderator = StoatGuardModerator(base_url=str(self.server.make_url("/")), expected_version=VERSION)
        await self.moderator.__aenter__()

    async def asyncTearDown(self):
        await self.moderator.__aexit__()
        await self.server.close()

    async def test_plain_request_does_not_ask_for_thinking(self):
        result = await self.moderator.classify_text("selling stuff")
        self.assertNotIn("thinking", self.payloads[-1])
        self.assertIsNone(result.thinking)

    async def test_thinking_request_returns_reasoning(self):
        result = await self.moderator.classify_text("selling stuff", thinking=True)
        self.assertTrue(self.payloads[-1]["thinking"])
        self.assertEqual(result.blocked_categories(0.9), ["illicit"])
        self.assertIn("concrete plan", result.thinking["heads"]["illicit"]["reasoning"])

    async def test_failed_thinking_request_falls_back_to_normal_classification(self):
        self.fail_thinking = True
        result = await self.moderator.classify_text("selling stuff", thinking=True)
        self.assertEqual([bool(p.get("thinking")) for p in self.payloads], [True, False])
        self.assertIsNone(result.thinking)
        self.assertEqual(result.blocked_categories(0.9), ["illicit"])


class ThinkingStorageTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.folder.name) / "moderation.db")
        self.now = datetime.now(timezone.utc)
        self.clock = patch("appeal_privacy.utcnow", return_value=self.now)
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        self.db.close()
        self.folder.cleanup()

    def add_ai_warning(self):
        thinking = parse_thinking(THINKING_BLOCK, TEXT_SCORES)
        warning = self.db.add_warning(
            server_id="server", user_id="author", moderator_id="bot", source="automatic",
            reason="Automatic content moderation: illicit", message_id="message", channel_id="channel",
            categories={"illicit": True}, scores={"illicit": 0.95},
            original_content="selling stuff, dm me", ai_thinking=thinking,
        )
        event = self.db.add_event(
            server_id="server", event_type="automatic_deletion", user_id="author", message_id="message",
            details={"warning_id": warning, "original_content": "selling stuff, dm me", "ai_thinking": thinking,
                     "scores": {"illicit": 0.95}},
        )
        return warning, event, self.db.get_warning_case("server", warning)

    def test_setting_defaults_off_and_appears_in_dashboard_settings(self):
        self.assertFalse(self.db.get_ai_thinking("server"))
        self.db.set_ai_thinking("server", True)
        self.assertTrue(self.db.get_ai_thinking("server"))
        settings = self.db.get_dashboard_settings("server", 0.9, None)
        self.assertTrue(settings["ai_thinking"])

    def test_case_detail_shows_the_reasoning_and_original_message(self):
        _warning, _event, case = self.add_ai_warning()
        source = self.db.get_moderation_case_detail("server", case.reference_id)["source"]
        self.assertEqual(source["original_content"], "selling stuff, dm me")
        self.assertEqual(source["ai_thinking"]["heads"]["illicit"]["verdict"], "unsafe")
        self.assertFalse(source["content_retention_ended"])

    def test_reasoning_is_deleted_with_the_original_message_after_30_days(self):
        warning, event, case = self.add_ai_warning()
        self.db.connection.execute(
            "UPDATE moderated_content_lifecycles SET decided_at=? WHERE server_id='server' AND message_id='message'",
            ((self.now - timedelta(days=30)).isoformat(),),
        )
        self.db.connection.commit()
        self.db.appeal_privacy.prune(now=self.now + timedelta(hours=1))
        row = self.db.connection.execute("SELECT original_content, ai_thinking_json FROM warnings WHERE id=?", (warning,)).fetchone()
        self.assertIsNone(row["original_content"])
        self.assertIsNone(row["ai_thinking_json"])
        details = json.loads(self.db.connection.execute("SELECT details_json FROM moderation_events WHERE id=?", (event,)).fetchone()[0])
        self.assertNotIn("ai_thinking", details)
        self.assertNotIn("original_content", details)
        source = self.db.get_moderation_case_detail("server", case.reference_id)["source"]
        self.assertIsNone(source["ai_thinking"])
        self.assertTrue(source["content_retention_ended"])
        self.assertEqual(source["scores"], {"illicit": 0.95})


if __name__ == "__main__":
    unittest.main()
