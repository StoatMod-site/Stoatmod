#!/usr/bin/env python3
"""Stoatmod production watchdog. Run every minute by stoatmod-watchdog.timer.

Checks the AI classifier, the bot heartbeat, the systemd services and disk space. It repairs what it can (restarts the AI
tunnel, optionally asks the GPU host to start its classifier) and posts an alert to a Stoat webhook when a component has failed
for ALERT_AFTER_MINUTES in a row, again every REPEAT_HOURS while it stays down, and once when it recovers.

Settings come from the bot's .env (LOCAL_AI_BASE_URL, LOCAL_AI_EXPECTED_VERSION, MODERATION_DATABASE_PATH) and from
ops/watchdog.env (see ops/watchdog.env.example). Alerts are written for a public channel: they only name the component
("Stoatmod bot", "AI moderation", "Website and dashboard") and how long it has been down. Details go to the journal.

Written after an October 2026 outage: the AI host lost the production SSH key, production rebooted, the tunnel could not
reconnect and nobody noticed for ~36 hours.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

ROOT = os.environ.get("STOATMOD_ROOT", "/opt/stoatmod")
STATE_PATH = "/var/lib/stoatmod-watchdog/state.json"
ALERT_AFTER_MINUTES = 3
REPEAT_HOURS = 6
HEARTBEAT_MAX_AGE = 180
DISK_MAX_PERCENT = 90
BOT_SERVICE = "stoatmod-bot"
DEFAULT_SERVICES = "stoatmod-bot,stoat-dashboard-api,stoat-dashboard-web"
PUBLIC_DOWN = {
    "Stoatmod bot": "The bot is offline, so commands and moderation are not working.",
    "AI moderation": "AI message and image checks are paused. Commands and the other protections keep working.",
    "Website and dashboard": "The website or the dashboard may not load.",
}


def in_planned_maintenance(ops: dict[str, str], component: str, now: float) -> bool:
    """PLANNED_MAINTENANCE="AI moderation|2026-10-21T18:00:00Z|2026-10-21T22:00:00Z; ..." (component|start|end, UTC)."""
    for window in ops.get("PLANNED_MAINTENANCE", "").split(";"):
        parts = [part.strip() for part in window.split("|")]
        if len(parts) != 3 or parts[0] != component:
            continue
        try:
            start, end = (datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() for value in parts[1:])
        except ValueError:
            continue
        if start <= now < end:
            return True
    return False


def format_minutes(minutes: int) -> str:
    if minutes < 90:
        return f"{minutes} minutes"
    hours = minutes / 60
    return f"{hours:.0f} hours" if hours < 48 else f"{hours / 24:.0f} days"


def read_env(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def log(message: str) -> None:
    print(message, flush=True)


def run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return done.returncode, (done.stdout + done.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def check_ai(env: dict[str, str]) -> str | None:
    base = env.get("LOCAL_AI_BASE_URL", "http://127.0.0.1:18006").rstrip("/")
    expected = env.get("LOCAL_AI_EXPECTED_VERSION", "")
    try:
        with urllib.request.urlopen(base + "/health", timeout=20) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return f"the AI service is not answering through the tunnel ({type(exc).__name__})"
    if body.get("ok") is not True:
        return "the AI service reports it is not healthy"
    if expected and body.get("version") != expected:
        return f"the AI service runs version {body.get('version')!r} but production expects {expected!r} (moderation fails open)"
    vision = body.get("vision")
    if not isinstance(vision, dict) or vision.get("enabled") is not True:
        return "the AI service has image scanning disabled"
    return None


def check_heartbeat(env: dict[str, str]) -> str | None:
    path = env.get("MODERATION_DATABASE_PATH", f"{ROOT}/moderation.db")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
        row = connection.execute("SELECT value FROM app_metadata WHERE key='system_heartbeat:bot'").fetchone()
        connection.close()
    except sqlite3.Error as exc:
        return f"the moderation database cannot be read ({exc})"
    if row is None:
        return "the bot has never written a heartbeat"
    try:
        heartbeat = json.loads(row[0])
        updated = datetime.fromisoformat(str(heartbeat["updated_at"]))
    except (ValueError, KeyError, TypeError):
        return "the bot heartbeat is unreadable"
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    if age > HEARTBEAT_MAX_AGE:
        return f"the bot has not sent a heartbeat for {int(age // 60)} minutes"
    if not (heartbeat.get("details") or {}).get("connected", True):
        return "the bot is running but not connected to Stoat"
    return None


def check_service(name: str) -> str | None:
    code, output = run(["systemctl", "is-active", name])
    return None if output == "active" else f"{name} is {output or 'not active'}"


def check_disk() -> str | None:
    usage = shutil.disk_usage("/")
    percent = usage.used * 100 / usage.total
    return f"the production disk is {percent:.0f}% full" if percent >= DISK_MAX_PERCENT else None


def kick_gpu_host(ops: dict[str, str]) -> str:
    """Ask the GPU host to start its classifier. The key only runs /workspace/ops/ensure_service.sh there."""
    host, port, key = ops.get("GPU_HOST"), ops.get("GPU_PORT", "22"), ops.get("GPU_KICK_KEY")
    if not host or not key or not os.path.exists(key):
        return "no GPU kick key configured"
    code, output = run([
        "ssh", "-p", port, "-i", key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={ops.get('GPU_KNOWN_HOSTS') or ROOT + '/.ssh-ai/known_hosts'}",
        f"root@{host}",
    ], timeout=60)
    lines = [line for line in output.splitlines() if line.strip() and "vast.ai" not in line and "Have fun" not in line]
    if "Permission denied" in output:
        return "the GPU host rejected the production SSH key"
    if "Host key verification failed" in output:
        return "the GPU host's SSH host key changed (the instance may have been replaced)"
    return (lines[-1] if lines else f"exit {code}")[:200]


def post_alert(url: str, title: str, description: str, colour: str) -> None:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")
    if parsed.hostname == "stoat.chat" and path.startswith("/webhooks/"):
        path = "/api" + path
    api_url = parsed._replace(path=path, params="", query="", fragment="").geturl()
    payload = {"embeds": [{"title": title, "description": description[:1900], "colour": colour}],
               "mention_everyone": False, "mention_online": False}
    request = urllib.request.Request(api_url, data=json.dumps(payload).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "stoatmod-watchdog"})
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status >= 300:
            raise RuntimeError(f"HTTP {response.status}")


def main() -> int:
    env = read_env(f"{ROOT}/.env")
    ops = read_env(f"{ROOT}/ops/watchdog.env")
    webhook = ops.get("ALERT_WEBHOOK_URL", "")
    try:
        with open(STATE_PATH, encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        state = {}
    now = time.time()

    tunnel = ops.get("AI_TUNNEL_SERVICE", "").strip()
    services = [name.strip() for name in ops.get("WATCH_SERVICES", DEFAULT_SERVICES).split(",") if name.strip()]
    if tunnel and tunnel not in services:
        services.append(tunnel)
    # Public alert components and the checks behind them. Disk space is internal and never posted.
    components = {
        "Stoatmod bot": ["bot heartbeat"] + [name for name in services if name == BOT_SERVICE],
        "AI moderation": ["ai"] + [name for name in services if name == tunnel],
        "Website and dashboard": [name for name in services if name not in (BOT_SERVICE, tunnel)],
    }

    results: dict[str, str | None] = {"ai": check_ai(env), "bot heartbeat": check_heartbeat(env), "disk": check_disk()}
    for name in services:
        results[name] = check_service(name)

    # Repairs. systemd restarts crashed services itself; the tunnel and the GPU classifier need help.
    if results["ai"]:
        failures = state.get("ai", {}).get("failures", 0) + 1
        if tunnel and (results[tunnel] or failures % 5 == 0):
            run(["systemctl", "restart", tunnel])
            log(f"restarted {tunnel}")
        if failures >= 2:
            kick = kick_gpu_host(ops)
            log(f"gpu kick: {kick}")
            if tunnel and kick == "healthy" and not failures % 5 == 0:
                # The classifier is fine on the GPU host, so the tunnel is the broken part.
                run(["systemctl", "restart", tunnel])
                log(f"restarted {tunnel} (GPU side healthy)")
            if kick not in ("healthy", "no GPU kick key configured"):
                results["ai"] = f"{results['ai']}; GPU host: {kick}"

    # Internal detail goes to the journal only (journalctl -u stoatmod-watchdog).
    for name, problem in results.items():
        entry = state.setdefault(name, {"failures": 0})
        if problem:
            entry["failures"] = entry.get("failures", 0) + 1
            log(f"FAIL {name}: {problem} ({entry['failures']} min)")
        else:
            state[name] = {"failures": 0}

    # The alert webhook posts to a PUBLIC channel: only fixed uptime wording per component, never the internal detail above
    # (no versions, hosts, service names, keys, paths or error text).
    public = state.setdefault("public", {})
    for component, checks in components.items():
        entry = public.setdefault(component, {"minutes": 0, "alerted_at": 0})
        if any(results.get(check) for check in checks):
            entry["minutes"] += 1
            due = entry["minutes"] >= ALERT_AFTER_MINUTES and now - entry.get("alerted_at", 0) >= REPEAT_HOURS * 3600
            if due and webhook:
                try:
                    if in_planned_maintenance(ops, component, now):
                        post_alert(webhook, f"{component}: planned maintenance", f"{PUBLIC_DOWN[component]} "
                                   "This is planned maintenance; see the status page for the expected end time.", "#5B8DEF")
                    else:
                        post_alert(webhook, f"{component}: outage", f"{PUBLIC_DOWN[component]} Down for about "
                                   f"{format_minutes(entry['minutes'])}. It is being repaired automatically.", "#ED4245")
                    entry["alerted_at"] = now
                except Exception as exc:  # noqa: BLE001 - alerting must never crash the watchdog
                    log(f"alert failed: {type(exc).__name__}")
        else:
            if entry.get("alerted_at") and webhook:
                try:
                    post_alert(webhook, f"{component}: back to normal",
                               f"{component} is working again after about {format_minutes(entry['minutes'])}.", "#3BA55D")
                except Exception as exc:  # noqa: BLE001
                    log(f"recovery alert failed: {type(exc).__name__}")
            public[component] = {"minutes": 0, "alerted_at": 0}

    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH + ".tmp", "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    os.replace(STATE_PATH + ".tmp", STATE_PATH)
    if not any(results.values()):
        log("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
