from datetime import datetime, timezone
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer
from api.status_history import StatusHistory, day_state, read_history
from api.status_monitor import collect, service, model_health_url
from api.server import create_app, DATABASE_KEY, STATUS_HISTORY_PATH_KEY

START = datetime(2026, 9, 30, 12, tzinfo=timezone.utc).timestamp()


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "history.sqlite3"
        self.store = StatusHistory(self.path)
        self.addCleanup(self.store.close)

    def record(self, offset, status):
        self.store.record([service("bot", status, "Health check", now=START + offset)], now=START + offset)

    def test_outage_recovery_duration_and_uptime(self):
        self.record(0, "operational")
        self.record(30, "outage")
        self.record(60, "outage")
        self.record(90, "operational")
        report = read_history(self.path, now=START + 120)
        self.assertEqual(report["services"]["bot"]["outage_seconds"], 60)
        self.assertEqual(report["services"]["bot"]["uptime_percent"], 50)
        self.assertEqual(len(report["incidents"]), 1)
        self.assertEqual(report["incidents"][0]["resolution"], "recovered")
        self.assertEqual(report["incidents"][0]["duration_seconds"], 60)
        self.assertEqual(report["services"]["bot"]["days"][0]["status"], "unknown")

    def test_days_are_graded_by_how_long_the_service_was_down(self):
        self.assertEqual(day_state(86_400, 120, 0, 0), "operational")  # a 2 minute blip stays green
        self.assertEqual(day_state(86_400, 0, 0, 30), "operational")  # a quick restart stays green
        self.assertEqual(day_state(86_400, 0, 600, 0), "operational")  # 10 slow minutes stay green
        self.assertEqual(day_state(86_400, 299, 0, 0), "operational")
        self.assertEqual(day_state(86_400, 300, 0, 0), "degraded")
        self.assertEqual(day_state(86_400, 0, 1800, 0), "degraded")
        self.assertEqual(day_state(86_400, 3000, 0, 600), "outage")  # restarts count as downtime
        self.assertEqual(day_state(0, 0, 0, 30), "unknown")  # a logged restart alone does not claim monitored uptime
        self.assertEqual(day_state(0, 0, 0, 7200), "outage")

    def test_short_outage_keeps_the_day_operational_but_is_still_listed(self):
        for offset in range(0, 3600, 30):
            self.record(offset, "outage" if 600 <= offset < 720 else "operational")
        day = read_history(self.path, now=START + 3600)["services"]["bot"]["days"][-1]
        self.assertEqual(day["status"], "operational")
        self.assertEqual(day["downtime_seconds"], 120)
        self.assertEqual(read_history(self.path, now=START + 3600)["incident_count"], 1)

    def test_monitor_gap_is_not_counted_as_uptime_or_downtime(self):
        self.record(0, "operational")
        self.record(600, "outage")
        report = read_history(self.path, now=START + 630)
        self.assertEqual(report["services"]["bot"]["observed_seconds"], 60)
        self.assertEqual(report["services"]["bot"]["outage_seconds"], 30)
        stale = read_history(self.path, now=START + 800)
        self.assertEqual(stale["services"]["bot"]["current"]["status"], "unknown")
        self.assertEqual(stale["incidents"][0]["resolution"], "monitoring_gap")
        self.assertEqual(stale["incidents"][0]["duration_seconds"], 30)

    def test_recovery_after_gap_does_not_invent_recovery_time(self):
        self.record(0, "outage")
        self.record(600, "operational")
        report = read_history(self.path, now=START + 630)
        self.assertEqual(report["incidents"][0]["resolution"], "monitoring_gap")
        self.assertEqual(report["incidents"][0]["duration_seconds"], 30)

    def test_duplicate_and_out_of_order_samples_do_not_double_count(self):
        self.record(0, "operational")
        self.record(0, "outage")
        self.record(-10, "outage")
        report = read_history(self.path, now=START + 30)
        self.assertEqual(report["services"]["bot"]["observed_seconds"], 30)
        self.assertEqual(report["incident_count"], 0)

    def test_unverified_dependencies_are_not_downtime(self):
        self.record(0, "unknown")
        self.record(30, "unknown")
        report = read_history(self.path, now=START + 60)
        self.assertEqual(report["services"]["bot"]["observed_seconds"], 0)
        self.assertIsNone(report["services"]["bot"]["uptime_percent"])
        self.assertEqual(report["incident_count"], 0)

    def test_history_survives_connection_restart_and_supports_90_days(self):
        self.record(0, "outage")
        another = StatusHistory(self.path)
        try:
            another.record([service("bot", "operational", "Recovered", now=START + 30)], now=START + 30)
        finally:
            another.close()
        report = read_history(self.path, days=90, now=START + 60)
        self.assertEqual(len(report["services"]["bot"]["days"]), 90)
        self.assertEqual(report["incidents"][0]["duration_seconds"], 30)

    def test_unavailable_store_has_no_fabricated_records(self):
        report = read_history(self.path.with_name("missing.db"), now=START)
        self.assertFalse(report["available"])
        self.assertEqual(report["incidents"], [])
        self.assertFalse(self.path.with_name("missing.db").exists())


class MonitorTests(unittest.IsolatedAsyncioTestCase):
    def test_model_address_follows_current_configuration(self):
        with patch.dict("os.environ", {"LOCAL_AI_BASE_URL":"http://127.0.0.1:18006"}, clear=True):
            self.assertEqual(model_health_url(), "http://127.0.0.1:18006/health")
        with patch.dict("os.environ", {}, clear=True), patch("pathlib.Path.read_text", return_value='LOCAL_AI_BASE_URL="http://127.0.0.1:18007"\n'):
            self.assertEqual(model_health_url(), "http://127.0.0.1:18007/health")
        with patch.dict("os.environ", {"STATUS_LOCAL_AI_HEALTH_URL":"http://127.0.0.1:18008/ready"}, clear=True):
            self.assertEqual(model_health_url(), "http://127.0.0.1:18008/ready")

    async def test_unconfigured_model_is_unknown_not_an_outage(self):
        with patch("api.status_monitor.probe", new=AsyncMock(side_effect=[({"services":[]},10),({"ok":True},10)])):
            services = {item["id"]:item for item in await collect(None,"api","web",None)}
        self.assertEqual(services["local_ai"]["status"],"unknown")

    async def test_model_and_api_are_independent_and_private_metadata_is_not_exposed(self):
        with patch("api.status_monitor.probe", new=AsyncMock(side_effect=[
            (None, None), ({"ok": True}, 30),
            ({"ok": True, "model_name": "Stoat Nemotron", "mode": "observe-only", "endpoint": "secret-internal-host", "private_data": "secret"}, 40),
        ])):
            services = {item["id"]: item for item in await collect(None, "api", "web", "model")}
        self.assertEqual(services["api"]["status"], "outage")
        self.assertEqual(services["bot"]["status"], "unknown")
        self.assertEqual(services["database"]["status"], "unknown")
        self.assertEqual(services["local_ai"]["status"], "operational")
        self.assertNotIn("mode", services["local_ai"])
        self.assertNotIn("secret", str(services))

    async def test_model_readiness_must_be_confirmed(self):
        for model in (None, {}, {"ok": False}, {"ok": True, "ready": False}):
            with self.subTest(model=model), patch("api.status_monitor.probe", new=AsyncMock(side_effect=[
                ({"services": []}, 10), ({"ok": True}, 10), (model, 10),
            ])):
                services = {item["id"]: item for item in await collect(None, "api", "web", "model")}
                self.assertEqual(services["local_ai"]["status"], "outage")
                self.assertEqual(services["api"]["status"], "operational")


class PublicStatusTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.client = TestClient(TestServer(create_app(str(Path(self.directory.name) / "moderation.db"))))
        await self.client.start_server()
        self.db = self.client.app[DATABASE_KEY]

    async def asyncTearDown(self):
        await self.client.close()
        self.directory.cleanup()

    async def test_public_status_includes_model_and_persistent_history(self):
        self.db.update_system_heartbeat("bot", {"connected": True, "server_count": 1})
        self.db.update_system_heartbeat("email", {"connected": True})
        history = StatusHistory(self.client.app[STATUS_HISTORY_PATH_KEY])
        history.record([service("local_ai", "operational", "Model loaded", model_name="Stoat Nemotron"), service("dashboard", "operational", "Rendering normally")])
        with history.connection:
            history.connection.execute(
                "INSERT INTO status_intervals(service,status,started_at,ended_at,last_seen,end_reason,source) VALUES ('bot','outage',?,?,?,'recovered','service_log')",
                (time.time() - 86400, time.time() - 86400 + 5, time.time() - 86400 + 5),
            )
        history.close()
        response = await self.client.get("/api/public/status?days=90")
        payload = await response.json()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(payload["overall"], "operational")
        model = next(item for item in payload["services"] if item["id"] == "local_ai")
        self.assertEqual(model["model_name"], "Stoat Nemotron")
        self.assertEqual(payload["history"]["window_days"], 90)
        self.assertEqual(payload["history"]["incident_count"], 1)

    async def test_missing_history_does_not_claim_model_health(self):
        payload = await (await self.client.get("/api/public/status")).json()
        model = next(item for item in payload["services"] if item["id"] == "local_ai")
        self.assertEqual(model["status"], "unknown")
        self.assertFalse(payload["history"]["available"])

    async def test_history_range_validation(self):
        response = await self.client.get("/api/public/status?days=1000000")
        self.assertEqual(response.status, 400)
