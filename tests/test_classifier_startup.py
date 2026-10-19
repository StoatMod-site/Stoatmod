"""The bot must start even when the classifier is unreachable; scans then fail open until it answers."""
import socket
import unittest

from moderation import ModerationError, StoatGuardModerator


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ClassifierStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_unreachable_classifier_does_not_stop_startup(self):
        moderator = StoatGuardModerator(base_url=f"http://127.0.0.1:{closed_port()}", expected_version="v1", timeout_seconds=2)
        with self.assertLogs("stoat_moderator", level="WARNING") as logs:
            await moderator.__aenter__()
        try:
            self.assertIn("stoatguard_unavailable_at_startup", logs.output[0])
            with self.assertRaises(ModerationError):
                await moderator.classify_text("hello")
        finally:
            await moderator.__aexit__()


if __name__ == "__main__":
    unittest.main()
