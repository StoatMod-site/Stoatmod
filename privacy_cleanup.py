"""Retire audit mirroring and collected network identifiers without exporting them."""
from __future__ import annotations

import json
import re
import sqlite3

NETWORK_KEYS = frozenset({
    "ip", "ip_address", "remote_ip", "client_ip", "fingerprint", "ip_fingerprint",
    "linked_user_ids", "linked_users", "linked_global_bans", "alt_detection",
    "network_risk", "provider_results",
})


def purge_retired_collection(connection: sqlite3.Connection, *, additional_identifiers: set[str] | None = None) -> dict[str, int]:
    """Delete retired stores and scrub their derived copies; caller commits/vacuums.

    Never return addresses, fingerprints, message content, or user identifiers.
    The original report/evidence and unrelated moderation records stay intact.
    """
    tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    counts: dict[str, int] = {}
    identifiers: set[str] = set(additional_identifiers or ())
    for table, column in (("user_ip_addresses", "ip_address"), ("user_ip_fingerprints", "fingerprint")):
        if table in tables:
            identifiers.update(str(r[0]) for r in connection.execute(f'SELECT "{column}" FROM "{table}"') if r[0])
    pattern = re.compile("|".join(re.escape(v) for v in sorted(identifiers, key=len, reverse=True))) if identifiers else None

    def scrub(value):
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items() if k.casefold() not in NETWORK_KEYS
                    and not (k == "risk" and isinstance(v, dict) and any(x in v for x in ("vpn", "proxy", "tor", "provider", "configured")))}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return pattern.sub("[removed network identifier]", value) if pattern and isinstance(value, str) else value

    for table in ("dev_webhook_events", "user_ip_addresses", "user_ip_fingerprints"):
        if table in tables:
            counts[table] = connection.execute(f'DELETE FROM "{table}"').rowcount
    if "dashboard_actions" in tables:
        counts["alt_detection_actions"] = connection.execute("""
            DELETE FROM dashboard_actions WHERE actor_id='STOATMOD_ALT_DETECTION'
            OR (json_valid(payload_json) AND json_extract(payload_json, '$.source')='alt_detection')
        """).rowcount
    if "moderation_events" in tables:
        counts["network_events"] = connection.execute("""DELETE FROM moderation_events
            WHERE event_type IN ('alt_account_detected','alt_account_server_ban_enforced','global_ban_evasion_detected',
                'join_web_verification_risk_disagreement','join_web_verification_low_risk_datacenter_allowed')""").rowcount
    if "user_reports" in tables:
        columns = {r[1] for r in connection.execute('PRAGMA table_info(user_reports)')}
        if "network_risk_json" in columns:
            counts["report_network_metadata"] = connection.execute("UPDATE user_reports SET network_risk_json='{}' WHERE network_risk_json!='{}'").rowcount
    if "server_settings" in tables:
        columns = {r[1] for r in connection.execute('PRAGMA table_info(server_settings)')}
        if "alt_detection_enabled" in columns:
            connection.execute("UPDATE server_settings SET alt_detection_enabled=0")

    # Scrub denormalised JSON and exact copies of the collected identifiers.
    # Skip credentials/configuration: these are not collected visitor data.
    for table in sorted(tables):
        if table.startswith("sqlite_") or table in {"app_metadata", "server_settings", "admin_dashboard_accounts"}:
            continue
        columns = [r[1] for r in connection.execute(f'PRAGMA table_info("{table}")')
                   if str(r[2]).upper() == "TEXT"]
        for column in columns:
            if any(part in column for part in ("token", "hash", "password", "secret")):
                continue
            changed = 0
            for rowid, value in connection.execute(f'SELECT rowid, "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL').fetchall():
                if not isinstance(value, str):
                    continue
                try:
                    parsed = json.loads(value) if value.startswith(("{", "[")) else None
                except (ValueError, TypeError):
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    cleaned = scrub(parsed)
                    replacement = json.dumps(cleaned, separators=(",", ":"), ensure_ascii=False) if cleaned != parsed else value
                else:
                    replacement = scrub(value)
                if replacement != value:
                    connection.execute(f'UPDATE "{table}" SET "{column}"=? WHERE rowid=?', (replacement, rowid))
                    changed += 1
            if changed:
                counts[f"{table}.{column}"] = changed
    return counts
