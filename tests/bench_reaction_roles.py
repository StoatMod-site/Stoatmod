"""Latency/request-count benchmark for reaction roles with a simulated Stoat API.

Run:  python -m tests.bench_reaction_roles [latency_seconds]
Not a unit test (the file name does not start with test_)."""
import asyncio
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock

import stoat
from application_flow import ApplicationFlow
from database import ModerationDatabase
from reaction_role_flow import ReactionRoleFlow

LATENCY = float(sys.argv[1]) if len(sys.argv) > 1 else 0.15


class World:
    def __init__(self, users, latency=LATENCY):
        self.latency = latency
        self.calls = Counter()
        self.temp = tempfile.TemporaryDirectory()
        self.db = ModerationDatabase(Path(self.temp.name) / "bench.db")
        self.store = self.db.reaction_roles
        directory = {"channels": [{"id": "channel", "name": "Roles"}], "roles": [
            {"id": "gaming", "name": "Gaming", "assignable": True, "reason": None},
            {"id": "art", "name": "Art", "assignable": True, "reason": None}], "emojis": []}
        self.store.set_directory("server", directory)
        config = {"title": "Roles", "description": "", "footer": "", "color": "#5865F2", "channel_id": "channel", "mode": "multiple",
                  "options": [{"emoji": "🎮", "role_id": "gaming", "label": "Gaming"}, {"emoji": "🎨", "role_id": "art", "label": "Art"}]}
        panel = self.store.save("server", "admin", config)
        self.store.update(panel["id"], status="active", message_id="message", published_channel_id="channel")
        self.panel = self.store.get(panel["id"])
        joined = datetime.now(timezone.utc)
        self.granted_at = {}
        self.members = {}
        for i in range(users):
            self.members[f"u{i}"] = self.make_member(f"u{i}", joined)
        roles = {r: NS(id=r, name=r, rank=i + 2, permissions=NS(allow=stoat.Permissions())) for i, r in enumerate(["gaming", "art", "unrelated"])}
        roles["bot"] = NS(id="bot", rank=0, permissions=NS(allow=stoat.Permissions.all()))
        self.bot_member = NS(id="bot", role_ids=["bot"])
        self.server = NS(id="server", owner_id="admin", roles=roles, channel_ids=["channel"],
                         permissions_for=Mock(return_value=stoat.Permissions(assign_roles=True, manage_server=True)))
        self.server.get_member = lambda uid: self.members.get(uid)  # gateway-maintained cache
        async def fetch_member(uid):
            self.calls["GET member"] += 1
            await asyncio.sleep(self.latency)
            return self.bot_member if uid == "bot" else self.members[uid]
        self.server.fetch_member = fetch_member
        async def fetch_emojis(): return []
        self.server.fetch_emojis = fetch_emojis
        self.message = NS(id="message", author_id="bot", nonce=None, reactions={})
        async def unreact(emoji, *, user=None, remove_all=False):
            self.calls["DELETE reaction"] += 1
            await asyncio.sleep(self.latency)
            self.message.reactions[emoji] = [u for u in self.message.reactions.get(emoji, []) if u != user]
        self.message.unreact = unreact
        async def fetch_message(mid):
            self.calls["GET message"] += 1
            await asyncio.sleep(self.latency)
            return self.message
        self.channel = NS(id="channel", server_id="server", role_permissions={}, name="Roles", fetch_message=fetch_message)
        async def fetch_user(uid): self.calls["GET user"] += 1; await asyncio.sleep(self.latency); return NS(bot=None)
        self.bot = NS(database=self.db, state=NS(my_id="bot", cache=NS(store_server_member=lambda m, c: None)),
                      fetch_server=None, fetch_channel=None, get_user=lambda uid: NS(bot=None), fetch_user=fetch_user,
                      get_channel=lambda cid: self.channel, _closing=False, _tasks=set())
        self.bot.application_flow = ApplicationFlow(self.bot)
        self.flow = ReactionRoleFlow(self.bot)
        self.flow.context = self.context

    async def context(self, server_id):
        return self.server, self.bot_member, [self.channel]

    def make_member(self, uid, joined):
        member = NS(id=uid, role_ids=[], joined_at=joined, timed_out_until=None)
        async def edit(**kwargs):
            self.calls["PATCH member"] += 1
            await asyncio.sleep(self.latency)
            member.role_ids = list(kwargs["roles"])
            self.granted_at[uid] = time.perf_counter()
            return member
        member.edit = edit
        return member

    def click(self, uid, emoji="🎮"):
        self.message.reactions.setdefault(emoji, []).append(uid)
        return self.flow.reaction(NS(message_id="message", user_id=uid, emoji=emoji), added=True)

    def age_member_cache(self):
        self.flow.member_checked.clear()

    def close(self):
        self.db.close(); self.temp.cleanup()


async def scenario_single_click():
    w = World(1)
    w.age_member_cache()
    start = time.perf_counter()
    await w.click("u0")
    done = w.granted_at["u0"] - start
    total = time.perf_counter() - start
    result = (done, total, dict(w.calls)); w.close(); return result


async def scenario_burst(users):
    w = World(users)
    w.age_member_cache()
    start = time.perf_counter()
    await asyncio.gather(*(w.click(f"u{i}") for i in range(users)))
    times = sorted(w.granted_at[f"u{i}"] - start for i in range(users))
    result = (times[len(times) // 2], times[-1], time.perf_counter() - start, dict(w.calls)); w.close(); return result


async def scenario_maintenance(users):
    w = World(users)
    for i in range(users):  # everybody reacted earlier and already has the role
        uid = f"u{i}"
        w.message.reactions.setdefault("🎮", []).append(uid)
        w.members[uid].role_ids = ["gaming"]
    await w.flow.sync(w.store.get(w.panel["id"]))   # first pass records ownership
    w.calls.clear(); w.age_member_cache()
    start = time.perf_counter()
    await w.flow.sync(w.store.get(w.panel["id"]))   # steady-state pass (the 60-second maintenance sweep)
    result = (time.perf_counter() - start, dict(w.calls)); w.close(); return result


async def scenario_click_during_maintenance(users):
    w = World(users)
    for i in range(users):
        uid = f"u{i}"
        w.message.reactions.setdefault("🎮", []).append(uid)
        w.members[uid].role_ids = ["gaming"]
    await w.flow.sync(w.store.get(w.panel["id"]))
    w.age_member_cache()
    newcomer = w.make_member("new", datetime.now(timezone.utc)); w.members["new"] = newcomer
    sweep = asyncio.create_task(w.flow.maintenance_sweep_for_bench(w.panel["id"]) if hasattr(w.flow, "maintenance_sweep_for_bench") else locked_sync(w))
    await asyncio.sleep(0.05)
    start = time.perf_counter()
    await w.click("new")
    done = w.granted_at["new"] - start
    await sweep
    w.close(); return done


async def locked_sync(w):
    # mirrors maintenance(): the panel is synchronised under the panel lock
    async with w.flow.lock(w.panel["id"]):
        await w.flow.sync(w.store.get(w.panel["id"]))


async def main():
    print(f"simulated API latency {LATENCY * 1000:.0f} ms per request")
    done, total, calls = await scenario_single_click()
    print(f"single click (member cache cold): role applied after {done:.3f}s, handler finished {total:.3f}s, requests {calls}")
    for users in (10, 50):
        median, last, total, calls = await scenario_burst(users)
        print(f"{users} users click at once: role applied median {median:.2f}s, last {last:.2f}s, all done {total:.2f}s, requests {calls}")
    for users in (50, 200):
        dur, calls = await scenario_maintenance(users)
        print(f"maintenance sweep, {users} reactors already up to date: {dur:.2f}s, requests {calls}")
    done = await scenario_click_during_maintenance(50)
    print(f"one click while a 50-reactor maintenance sweep is running: role applied after {done:.2f}s")


if __name__ == "__main__":
    asyncio.run(main())
