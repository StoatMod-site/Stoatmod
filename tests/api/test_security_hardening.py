"""Regression tests for the 2026-11-19 security audit fixes in the dashboard API."""
import asyncio
import unittest
from collections import defaultdict, deque
from types import SimpleNamespace
from unittest.mock import Mock

from api import server
from api.server import LOGIN_ATTEMPTS_KEY, _download_attachment_response


class DownloadAttachmentTests(unittest.TestCase):
    def test_untrusted_type_is_served_as_octet_stream(self):
        response = _download_attachment_response(
            {"data": b"<script>alert(1)</script>", "content_type": "text/html", "filename": "x.html"}
        )
        self.assertEqual(response.content_type, "application/octet-stream")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_known_image_type_is_kept(self):
        response = _download_attachment_response(
            {"data": b"img", "content_type": "image/PNG; charset=x", "filename": "a.png"}
        )
        self.assertEqual(response.content_type, "image/png")

    def test_filename_cannot_break_the_header(self):
        response = _download_attachment_response(
            {"data": b"x", "content_type": "text/plain", "filename": 'a"; filename="evil.html'}
        )
        disposition = response.headers["Content-Disposition"]
        self.assertTrue(disposition.startswith('attachment; filename="attachment"; '))
        self.assertNotIn('evil.html"', disposition)
        self.assertIn("%22", disposition)


class DashboardCodeRateLimitTests(unittest.TestCase):
    def test_limit_is_per_client_not_per_proxy(self):
        app = {LOGIN_ATTEMPTS_KEY: defaultdict(deque)}

        def make(ip):
            return SimpleNamespace(
                remote="127.0.0.1", headers={"X-Forwarded-For": ip}, app=app,
                json=Mock(side_effect=ValueError),
            )

        async def attempt(ip):
            async def bad_json():
                raise ValueError
            request = make(ip)
            request.json = bad_json
            return await server.verify_code(request)

        for _ in range(10):
            asyncio.run(attempt("203.0.113.5"))
        self.assertEqual(asyncio.run(attempt("203.0.113.5")).status, 429)
        self.assertEqual(asyncio.run(attempt("198.51.100.7")).status, 400)


if __name__ == "__main__":
    unittest.main()
