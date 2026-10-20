"""Independent status sampler: keeps recording when the dashboard API stops."""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import time

from aiohttp import ClientError, ClientSession, ClientTimeout
from api.status_history import INTERVAL, SERVICE_NAMES, StatusHistory, iso

logger = logging.getLogger("stoatmod_status")


def model_health_url() -> str | None:
    """Follow the bot's configured model address across model migrations."""
    override = os.getenv("STATUS_LOCAL_AI_HEALTH_URL", "").strip()
    if override:
        return override
    base = os.getenv("LOCAL_AI_BASE_URL", "").strip()
    if not base:
        env_path = Path(__file__).resolve().parent.parent / ".env"
        try:
            for line in env_path.read_text(encoding="utf-8").splitlines():
                key, separator, value = line.strip().partition("=")
                if separator and key.strip() == "LOCAL_AI_BASE_URL":
                    base = value.strip().strip("\"'")
                    break
        except OSError:
            pass
    return base.rstrip("/") + "/health" if base else None


def service(key, status, detail, *, now=None, **extra):
    return {"id": key, "name": SERVICE_NAMES[key], "status": status, "detail": detail,
            "updated_at": iso(time.time() if now is None else now), **extra}


RETRY_DELAY = 3  # one dropped request or a restart blip should not be recorded as 30 seconds of downtime


async def probe(session, url, *, expect_json=True, retries=1):
    for attempt in range(retries + 1):
        payload, elapsed = await _probe_once(session, url, expect_json=expect_json)
        if payload is not None or attempt == retries:
            return payload, elapsed
        await asyncio.sleep(RETRY_DELAY)
    return None, None


async def _probe_once(session, url, *, expect_json=True):
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=False) as response:
            if response.status != 200:
                return None, None
            if expect_json:
                payload = await response.json()
                if not isinstance(payload, dict):
                    return None, None
            else:
                # Read only enough to establish that the frontend rendered HTML.
                payload = {"ok": "text/html" in response.headers.get("Content-Type", "") and bool(await response.content.read(1024))}
            return payload, round((time.monotonic() - start) * 1000)
    except (ClientError, OSError, asyncio.TimeoutError, ValueError):
        return None, None


async def collect(session, api_url, web_url, model_url):
    async def model_probe():
        return await probe(session, model_url) if model_url else (None, None)
    (api_data, api_ms), (web_data, web_ms), (model, model_ms) = await asyncio.gather(
        probe(session, api_url), probe(session, web_url, expect_json=False), model_probe(),
    )
    api_ok = isinstance(api_data, dict) and isinstance(api_data.get("services"), list)
    services = [service("api", "operational" if api_ok else "outage",
                        "Status and dashboard requests are responding." if api_ok else "The API did not respond to its health check.", response_ms=api_ms)]
    received = {item.get("id"): item for item in api_data["services"] if isinstance(item, dict)} if api_ok else {}
    for key in ("bot", "email", "database"):
        item = received.get(key)
        if item and item.get("status") in {"operational", "degraded", "outage", "unknown"}:
            services.append({field: item.get(field) for field in ("id", "name", "status", "detail", "updated_at")})
        else:
            services.append(service(key, "unknown", "Health could not be verified while the API is unavailable."))
    web_ok = bool(web_data and web_data.get("ok"))
    services.append(service("dashboard", "operational" if web_ok else "outage",
                            "The dashboard is loading normally." if web_ok else "The dashboard did not respond to its health check.", response_ms=web_ms))
    model_ok = bool(model and model.get("ok") is True and model.get("ready", True) is not False)
    services.append(service("local_ai", "unknown" if not model_url else "operational" if model_ok else "outage",
                            "No local model endpoint is configured." if not model_url else "The local model is loaded and responding." if model_ok else "The local model did not pass its readiness check.",
                            response_ms=model_ms,
                            model_name=str(model.get("model_name") or "Local moderation model")[:60] if model else "Local moderation model"))
    return services


async def run():
    path = Path(os.getenv("STATUS_HISTORY_PATH", "/opt/stoatmod/status-history.sqlite3"))
    history = StatusHistory(path)
    try:
        async with ClientSession(timeout=ClientTimeout(total=8)) as session:
            while True:
                started = time.monotonic()
                try:
                    services = await collect(
                        session, os.getenv("STATUS_API_URL", "http://127.0.0.1:8081/api/public/status"),
                        os.getenv("STATUS_WEB_URL", "http://127.0.0.1:3000/login"),
                        model_health_url(),
                    )
                    history.record(services)
                except Exception:
                    logger.exception("status_sample_failed")
                await asyncio.sleep(max(1, INTERVAL - (time.monotonic() - started)))
    finally:
        history.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
