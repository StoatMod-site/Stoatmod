import unittest
from unittest.mock import AsyncMock

from aiohttp import web
from aiohttp.test_utils import TestServer

from moderation import ModerationError, ModerationResult, StoatGuardModerator, validate_model_base_url
from moderation_policy import IMAGE_MODERATION_CATEGORIES, SUPPORTED_MODERATION_CATEGORIES


class ScoreTests(unittest.TestCase):
    def test_category_boolean_cannot_bypass_stoatguard_score_threshold(self) -> None:
        result = ModerationResult(
            flagged=True,
            categories={"hate": True, "harassment": True},
            scores={"hate": 0.86, "harassment": 0.89},
            score_kind="stoatguard_policy_score",
        )

        self.assertEqual(result.blocked_categories(0.9), [])

    def test_inclusive_configured_threshold_below_ninety_percent(self):
        result = ModerationResult(True, {}, {"hate": .90, "scams": .8999})
        self.assertEqual(result.blocked_categories(.7), ["hate", "scams"])
        self.assertEqual(result.blocked_categories(.9), ["hate"])
        self.assertEqual(ModerationResult(False, {}, {"scams": 0}).blocked_categories(0), ["scams"])

    def test_production_category_vocabulary_matches_stoatguard(self):
        self.assertEqual(
            set(SUPPORTED_MODERATION_CATEGORIES),
            {
                "credentials", "violent-extremism", "hate", "hateful-conduct",
                "self-harm/promotion", "illicit", "scams",
                "unsolicited-advertising", "sexual/minors",
                "suicidal-thoughts", "sexual", "violence",
            },
        )
        self.assertEqual(IMAGE_MODERATION_CATEGORIES, {"violence", "sexual"})

    def test_model_url_must_be_self_hosted_and_credential_free(self):
        self.assertEqual(validate_model_base_url("http://127.0.0.1:18006/"), "http://127.0.0.1:18006")
        for url in ("https://api.openai.com/v1", "ftp://127.0.0.1", "http://user:pass@127.0.0.1",
                    "http://127.0.0.1/?key=1", "not a url"):
            with self.assertRaises(ValueError):
                validate_model_base_url(url)


class StoatGuardHTTPTests(unittest.IsolatedAsyncioTestCase):
    VERSION = "stoatguard-test-version"

    async def asyncSetUp(self):
        self.text_scores = {
            category: (0.95 if category == "suicidal-thoughts" else 0.01)
            for category in SUPPORTED_MODERATION_CATEGORIES
            if category != "violence"
        }
        self.image_scores = {"violence": 0.02, "sexual": 0.96}

        async def health(_request):
            return web.json_response({
                "ok": True,
                "version": self.VERSION,
                "vision": {
                    "enabled": True,
                    "image_categories": ["violence", "sexual"],
                },
            })

        async def classify(request):
            self.assertEqual((await request.json())["texts"], ["I need help"])
            return web.json_response({
                "version": self.VERSION,
                "results": [{
                    "version": self.VERSION,
                    "scores": self.text_scores,
                    "fired": ["suicidal-thoughts"],
                }],
            })

        async def classify_image(request):
            payload = await request.json()
            self.assertEqual(payload["policy_mode"], "stoat")
            self.assertEqual(payload["caption"], "")
            return web.json_response({
                "version": self.VERSION,
                "result": {
                    "version": self.VERSION,
                    "scores": self.image_scores,
                    "fired": ["sexual"],
                },
            })

        app = web.Application()
        app.router.add_get("/health", health)
        app.router.add_post("/classify", classify)
        app.router.add_post("/classify-image", classify_image)
        self.server = TestServer(app)
        await self.server.start_server()
        self.moderator = StoatGuardModerator(
            base_url=str(self.server.make_url("/")),
            expected_version=self.VERSION,
        )
        await self.moderator.__aenter__()

    async def asyncTearDown(self):
        await self.moderator.__aexit__()
        await self.server.close()

    async def test_text_uses_all_eleven_heads_without_provider_fallback(self):
        result = await self.moderator.classify_text("I need help")
        self.assertEqual(set(result.scores), set(self.text_scores))
        self.assertEqual(result.blocked_categories(0.9), ["suicidal-thoughts"])
        self.assertFalse(result.flagged)
        self.assertEqual(result.score_kind, "stoatguard_policy_score")

    async def test_image_exposes_exactly_violence_and_sexual(self):
        self.moderator._download_image = AsyncMock(
            return_value="data:image/png;base64,aW1hZ2U="
        )
        result = await self.moderator.classify_url(
            "https://cdn.example.test/image.png"
        )
        self.assertEqual(set(result.scores), {"violence", "sexual"})
        self.assertEqual(result.blocked_categories(0.9), ["sexual"])

    async def test_category_leakage_rejects_the_whole_image_result(self):
        self.image_scores["scams"] = 0.99
        self.moderator._download_image = AsyncMock(
            return_value="data:image/png;base64,aW1hZ2U="
        )
        with self.assertRaises(ModerationError):
            await self.moderator.classify_url(
                "https://cdn.example.test/image.png"
            )


if __name__ == '__main__': unittest.main()
