import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("stoatmod_watchdog", ROOT / "ops" / "stoatmod_watchdog.py")
watchdog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watchdog)

SECRET = "version 'model-x' host 203.0.113.9 /opt/stoatmod/moderation.db ssh key"


class WatchdogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = {name: getattr(watchdog, name) for name in (
            "STATE_PATH", "read_env", "post_alert", "run", "kick_gpu_host",
            "check_ai", "check_heartbeat", "check_disk", "check_service", "log")}
        self.temp = tempfile.TemporaryDirectory()
        watchdog.STATE_PATH = os.path.join(self.temp.name, "state.json")
        self.ops = {"ALERT_WEBHOOK_URL": "https://stoat.chat/api/webhooks/id/token",
                    "WATCH_SERVICES": "stoatmod-bot,stoat-dashboard-api,stoat-dashboard-web",
                    "AI_TUNNEL_SERVICE": "ai-tunnel", "GPU_HOST": "203.0.113.9", "GPU_KICK_KEY": "/nonexistent"}
        watchdog.read_env = lambda path: self.ops if path.endswith("watchdog.env") else {}
        self.sent: list[tuple[str, str]] = []
        watchdog.post_alert = lambda url, title, description, colour: self.sent.append((title, description))
        self.commands: list[list[str]] = []
        watchdog.run = lambda args, timeout=30: (self.commands.append(args), (0, ""))[1]
        watchdog.kick_gpu_host = lambda ops: "the GPU host rejected the production SSH key"
        watchdog.log = lambda message: None
        watchdog.check_ai = lambda env: None
        watchdog.check_heartbeat = lambda env: None
        watchdog.check_disk = lambda: None
        watchdog.check_service = lambda name: None

    def tearDown(self) -> None:
        for name, value in self.original.items():
            setattr(watchdog, name, value)
        self.temp.cleanup()

    def test_alerts_after_three_minutes_and_on_recovery_without_internal_details(self) -> None:
        watchdog.check_ai = lambda env: "AI down " + SECRET
        watchdog.check_disk = lambda: "disk 95% full " + SECRET
        watchdog.check_service = lambda name: "ai-tunnel is activating" if name == "ai-tunnel" else None
        for _ in range(2):
            watchdog.main()
        self.assertEqual(self.sent, [])
        for _ in range(3):
            watchdog.main()
        self.assertEqual([title for title, _ in self.sent], ["AI moderation: outage"])
        watchdog.check_ai = lambda env: None
        watchdog.check_disk = lambda: None
        watchdog.check_service = lambda name: None
        watchdog.main()
        self.assertEqual([title for title, _ in self.sent], ["AI moderation: outage", "AI moderation: back to normal"])
        text = " ".join(title + " " + description for title, description in self.sent)
        for private in ("model-x", "203.0.113", "/opt", "ssh", "SSH", "tunnel", "disk", "GPU"):
            self.assertNotIn(private, text)
        self.assertIn(["systemctl", "restart", "ai-tunnel"], self.commands)

    def test_planned_maintenance_is_announced_as_maintenance(self) -> None:
        self.ops["PLANNED_MAINTENANCE"] = "AI moderation|2000-01-01T00:00:00Z|2999-01-01T00:00:00Z; bad entry"
        watchdog.check_ai = lambda env: "AI down " + SECRET
        for _ in range(4):
            watchdog.main()
        self.assertEqual([title for title, _ in self.sent], ["AI moderation: planned maintenance"])
        self.assertIn("planned maintenance", self.sent[0][1])
        self.assertFalse(watchdog.in_planned_maintenance(self.ops, "Stoatmod bot", time.time()))
        self.ops["PLANNED_MAINTENANCE"] = "AI moderation|2000-01-01T00:00:00Z|2000-01-02T00:00:00Z"
        self.assertFalse(watchdog.in_planned_maintenance(self.ops, "AI moderation", time.time()))

    def test_disk_problems_are_never_posted(self) -> None:
        watchdog.check_disk = lambda: "disk 99% full"
        for _ in range(10):
            watchdog.main()
        self.assertEqual(self.sent, [])

    def test_repeat_alert_waits_six_hours(self) -> None:
        watchdog.check_heartbeat = lambda env: "no heartbeat"
        for _ in range(20):
            watchdog.main()
        self.assertEqual([title for title, _ in self.sent], ["Stoatmod bot: outage"])

    def test_without_tunnel_setting_nothing_is_restarted(self) -> None:
        self.ops.pop("AI_TUNNEL_SERVICE")
        watchdog.check_ai = lambda env: "AI down"
        for _ in range(5):
            watchdog.main()
        self.assertFalse(any(command[:2] == ["systemctl", "restart"] for command in self.commands))
        self.assertEqual([title for title, _ in self.sent], ["AI moderation: outage"])


if __name__ == "__main__":
    unittest.main()
