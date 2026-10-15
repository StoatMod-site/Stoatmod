"""Persistent, public-safe status observations. Missing time stays unknown."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time

INTERVAL = 30
MAX_GAP = 90
RETENTION_DAYS = 90
SERVICE_NAMES = {
    "bot": "Stoatmod bot", "local_ai": "Local AI model", "api": "Public API",
    "dashboard": "Moderator dashboard", "database": "Moderation database", "email": "Email service",
}
STATUSES = {"operational", "degraded", "outage", "unknown"}


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


class StatusHistory:
    def __init__(self, path: str | Path):
        self.connection = sqlite3.connect(str(path), timeout=3)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS status_latest (
                service TEXT PRIMARY KEY, checked_at REAL NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS status_intervals (
                id INTEGER PRIMARY KEY, service TEXT NOT NULL, status TEXT NOT NULL,
                started_at REAL NOT NULL, ended_at REAL NOT NULL, last_seen REAL NOT NULL,
                end_reason TEXT, source TEXT NOT NULL DEFAULT 'monitor',
                UNIQUE(service, started_at, source)
            );
            CREATE INDEX IF NOT EXISTS status_intervals_time ON status_intervals(ended_at);
            CREATE INDEX IF NOT EXISTS status_intervals_service ON status_intervals(service, started_at);
        """)

    def close(self):
        self.connection.close()

    def record(self, services: list[dict], *, now: float | None = None):
        now = time.time() if now is None else now
        with self.connection:
            for service in services:
                key, status = service["id"], service["status"]
                if key not in SERVICE_NAMES or status not in STATUSES:
                    raise ValueError("Invalid public status observation")
                previous = self.connection.execute(
                    "SELECT * FROM status_intervals WHERE service=? AND source='monitor' ORDER BY started_at DESC LIMIT 1", (key,)
                ).fetchone()
                if previous and now <= previous["last_seen"]:
                    continue
                continuous = previous is not None and now - previous["last_seen"] <= MAX_GAP
                if continuous and previous["status"] == status:
                    self.connection.execute(
                        "UPDATE status_intervals SET ended_at=?, last_seen=? WHERE id=?",
                        (now + INTERVAL, now, previous["id"]),
                    )
                else:
                    if previous:
                        self.connection.execute(
                            "UPDATE status_intervals SET ended_at=?, end_reason=? WHERE id=?",
                            (now if continuous else previous["ended_at"],
                             ("recovered" if status == "operational" else "changed") if continuous else "monitoring_gap",
                             previous["id"]),
                        )
                    self.connection.execute(
                        "INSERT INTO status_intervals(service,status,started_at,ended_at,last_seen) VALUES (?,?,?,?,?)",
                        (key, status, now, now + INTERVAL, now),
                    )
                self.connection.execute(
                    "INSERT OR REPLACE INTO status_latest VALUES (?,?,?)", (key, now, json.dumps(service))
                )
            cutoff = now - (RETENTION_DAYS + 1) * 86400
            self.connection.execute("DELETE FROM status_intervals WHERE ended_at < ?", (cutoff,))


def read_history(path: str | Path, *, days: int = 30, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    days = 90 if days == 90 else 30
    today = datetime.fromtimestamp(now, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = (today - timedelta(days=days - 1)).timestamp()
    empty = {"available": False, "window_days": days, "monitoring_since": None, "last_check_at": None,
             "services": {}, "incidents": [], "incident_count": 0, "check_interval_seconds": INTERVAL}
    try:
        connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
        connection.row_factory = sqlite3.Row
        try:
            latest = connection.execute("SELECT * FROM status_latest").fetchall()
            rows = connection.execute("SELECT * FROM status_intervals WHERE ended_at > ? AND started_at <= ? ORDER BY started_at", (start, now)).fetchall()
            first = connection.execute("SELECT MIN(started_at) FROM status_intervals WHERE source='monitor'").fetchone()[0]
        finally:
            connection.close()
    except sqlite3.Error:
        return empty
    result = dict(empty, available=bool(latest or rows), monitoring_since=iso(first) if first else None)
    current = {row["service"]: row for row in latest}
    result["last_check_at"] = iso(max(row["checked_at"] for row in latest)) if latest else None
    incidents = []
    for key in SERVICE_NAMES:
        observed = [row for row in rows if row["service"] == key and row["source"] == "monitor" and row["status"] != "unknown"]
        logs = [row for row in rows if row["service"] == key and row["source"] == "service_log"]
        history_days = []
        total = {"operational": 0.0, "degraded": 0.0, "outage": 0.0}
        for offset in range(days):
            left = start + offset * 86400
            right = min(left + 86400, now)
            seconds = {"operational": 0.0, "degraded": 0.0, "outage": 0.0}
            for row in observed:
                seconds[row["status"]] += max(0, min(right, row["ended_at"]) - max(left, row["started_at"]))
            covered = sum(seconds.values())
            for status in seconds:
                total[status] += seconds[status]
            recorded_restart = sum(max(0, min(right, row["ended_at"]) - max(left, row["started_at"])) for row in logs)
            state = "outage" if seconds["outage"] or recorded_restart else "degraded" if seconds["degraded"] else "operational" if covered else "unknown"
            history_days.append({"date": iso(left)[:10], "status": state, "observed_seconds": round(covered, 1),
                                 "outage_seconds": round(seconds["outage"], 1), "degraded_seconds": round(seconds["degraded"], 1),
                                 "restart_seconds": round(recorded_restart, 3), "coverage_percent": round(100 * covered / max(1, right - left), 2)})
        covered = sum(total.values())
        row = current.get(key)
        service = json.loads(row["payload"]) if row else {"id": key, "name": SERVICE_NAMES[key], "status": "unknown", "updated_at": None}
        if row is None or now - row["checked_at"] > MAX_GAP:
            service = dict(service, status="unknown", detail="Waiting for a fresh monitoring check.", response_ms=None)
        result["services"][key] = {
            "current": service, "days": history_days, "observed_seconds": round(covered),
            "outage_seconds": round(total["outage"]), "degraded_seconds": round(total["degraded"]),
            "uptime_percent": round(100 * (covered - total["outage"]) / covered, 3) if covered else None,
        }
    for row in rows:
        if row["status"] not in {"degraded", "outage"}:
            continue
        reason = row["end_reason"]
        if reason is None and now - row["last_seen"] > MAX_GAP:
            reason = "monitoring_gap"
        incidents.append({
            "id": row["id"], "service_id": row["service"], "service_name": SERVICE_NAMES[row["service"]],
            "status": row["status"], "started_at": iso(row["started_at"]),
            "ended_at": iso(row["ended_at"]) if reason else None,
            "duration_seconds": round(max(0, min(now, row["ended_at"]) - row["started_at"]), 3),
            "resolution": reason, "source": row["source"],
        })
    result["incident_count"] = len(incidents)
    result["incidents"] = list(reversed(incidents))[:100]
    return result
