import io
import unittest
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase
from PIL import Image

from api import discovery_thumbs


def png(width: int, height: int, colour=(200, 40, 40, 255)) -> bytes:
    output = io.BytesIO()
    Image.new("RGBA", (width, height), colour).save(output, format="PNG")
    return output.getvalue()


def animated_gif() -> bytes:
    frames = [Image.new("RGB", (900, 300), colour) for colour in ((255, 0, 0), (0, 0, 255))]
    output = io.BytesIO()
    frames[0].save(output, format="GIF", save_all=True, append_images=frames[1:], duration=100, loop=0)
    return output.getvalue()


class ThumbnailImageTests(unittest.TestCase):
    def test_scales_down_to_the_requested_width_as_webp(self):
        with Image.open(io.BytesIO(discovery_thumbs.make_thumbnail(png(1500, 500), 640))) as image:
            self.assertEqual(image.format, "WEBP")
            self.assertEqual(image.size, (640, 213))

    def test_never_scales_up(self):
        with Image.open(io.BytesIO(discovery_thumbs.make_thumbnail(png(80, 80), 152))) as image:
            self.assertEqual(image.size, (80, 80))

    def test_animated_gif_becomes_its_first_frame(self):
        with Image.open(io.BytesIO(discovery_thumbs.make_thumbnail(animated_gif(), 480))) as image:
            self.assertEqual(getattr(image, "n_frames", 1), 1)
            red, green, blue, _ = image.convert("RGBA").getpixel((10, 10))
            self.assertGreater(red, 200)
            self.assertLess(blue, 60)

    def test_slightly_truncated_gif_still_gets_a_thumbnail(self):
        from PIL import ImageFile
        truncated = animated_gif()[:-10]
        with Image.open(io.BytesIO(discovery_thumbs.make_thumbnail(truncated, 480))) as image:
            self.assertEqual(image.width, 480)
        self.assertFalse(ImageFile.LOAD_TRUNCATED_IMAGES)

    def test_only_stoat_media_hosts_are_fetched(self):
        self.assertTrue(discovery_thumbs.is_stoat_media_url("https://cdn.stoatusercontent.com/icons/abc"))
        for url in ("http://cdn.stoatusercontent.com/icons/abc", "https://evil.example/icons/abc",
                    "https://stoatusercontent.com.evil.example/x", "https://user:pass@cdn.stoatusercontent.com/x", ""):
            self.assertFalse(discovery_thumbs.is_stoat_media_url(url), url)


class FakeResponse:
    def __init__(self, status, body=b"", location=""):
        self.status, self.headers = status, {"Location": location} if location else {}
        self.content = self
        self._body = body

    async def iter_chunked(self, size):
        # Deliver the body in small pieces, like a slow network, to prove every piece is collected.
        for start in range(0, len(self._body), 4):
            yield self._body[start:start + 4]

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses, self.requested = responses, []

    def get(self, url, allow_redirects):
        assert allow_redirects is False
        self.requested.append(url)
        return self.responses[url]


class FetchTests(unittest.IsolatedAsyncioTestCase):
    async def test_follows_redirects_only_within_stoat_media(self):
        start = "https://cdn.stoatusercontent.com/banners/abc"
        session = FakeSession({
            start: FakeResponse(308, location="/banners/abc/standard%20(1).gif"),
            "https://cdn.stoatusercontent.com/banners/abc/standard%20(1).gif": FakeResponse(200, b"GIF89a-data"),
        })
        self.assertEqual(await discovery_thumbs.fetch_stoat_media(session, start), b"GIF89a-data")
        outside = FakeSession({start: FakeResponse(302, location="https://evil.example/steal")})
        self.assertIsNone(await discovery_thumbs.fetch_stoat_media(outside, start))
        self.assertEqual(outside.requested, [start])

    async def test_rejects_oversized_media(self):
        url = "https://cdn.stoatusercontent.com/icons/big"
        session = FakeSession({url: FakeResponse(200, b"x" * 101)})
        self.assertIsNone(await discovery_thumbs.fetch_stoat_media(session, url, max_bytes=100))


class HandlerTests(AioHTTPTestCase):
    async def get_application(self):
        self.listings = {
            "01ABC": {"server_id": "01ABC", "server_icon_url": "https://cdn.stoatusercontent.com/icons/i", "server_banner_url": ""},
            "01UPL": {"server_id": "01UPL", "server_icon_url": "", "server_banner_url": ""},
        }
        self.uploads = {("01UPL", "banner"): {"data": png(1600, 400, (0, 200, 0, 255)), "digest": "d1"}}
        discovery_thumbs._cache.clear()
        handler = discovery_thumbs.create_handler(
            lambda request, server_id: self.listings.get(server_id.upper()),
            lambda request, server_id, kind: self.uploads.get((server_id, kind)),
        )
        app = web.Application()
        app.router.add_get("/thumb/{server_id}/{kind}.webp", handler)
        return app

    async def test_serves_a_cached_webp_of_the_listing_icon(self):
        calls = []

        async def fake_fetch(session, url, **_):
            calls.append(url)
            return png(512, 512)

        with patch.object(discovery_thumbs, "fetch_stoat_media", fake_fetch):
            for _ in range(2):
                response = await self.client.get("/thumb/01abc/icon.webp?w=150")
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["Content-Type"], "image/webp")
                self.assertIn("max-age=604800", response.headers["Cache-Control"])
                with Image.open(io.BytesIO(await response.read())) as image:
                    self.assertEqual(image.size, (152, 152))
        self.assertEqual(calls, ["https://cdn.stoatusercontent.com/icons/i"])

    async def test_uploaded_banner_wins_and_unknown_requests_are_404(self):
        response = await self.client.get("/thumb/01UPL/banner.webp?w=9999")
        self.assertEqual(response.status, 200)
        with Image.open(io.BytesIO(await response.read())) as image:
            self.assertEqual(image.width, 1200)
        for path in ("/thumb/01ABC/banner.webp?w=480", "/thumb/NOPE/icon.webp", "/thumb/01ABC/avatar.webp",
                     "/thumb/01ABC/icon.webp?w=abc", "/thumb/01A-C/icon.webp"):
            self.assertEqual((await self.client.get(path)).status, 404, path)


if __name__ == "__main__":
    unittest.main()
