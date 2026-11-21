import asyncio
import unittest

import gateway_access


class FakeCache:
    def __init__(self, known):
        self.known = set(known)

    def get_channel(self, channel_id, ctx):
        return object() if channel_id in self.known else None


class FakeServer:
    def __init__(self, channel_ids):
        self.channel_ids = channel_ids


class FakeClient:
    def __init__(self, *, channels, cached, visible, fail_server=False):
        self.state = type("State", (), {"cache": FakeCache(cached)})()
        self.channels = channels
        self.visible = set(visible)
        self.fail_server = fail_server
        self.fetched = []

    async def fetch_server(self, server_id):
        if self.fail_server:
            raise RuntimeError("network")
        return FakeServer(self.channels)

    async def fetch_channel(self, channel_id):
        self.fetched.append(channel_id)
        if channel_id not in self.visible:
            raise PermissionError("Forbidden")
        return object()


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.slept.append(round(seconds, 3))
        self.now += seconds
        await asyncio.sleep(0)


def watcher(client, clock, reopened):
    async def reopen(_client):
        reopened.append(clock.now)
        return True

    return gateway_access.AccessWatcher(client, delays=(20, 60), min_interval=600, clock=clock, sleep=clock.sleep, reopen=reopen)


async def settle():
    for _ in range(50):
        await asyncio.sleep(0)


class AccessWatcherTests(unittest.IsolatedAsyncioTestCase):
    async def test_a_visible_channel_missing_from_the_gateway_is_found(self):
        client = FakeClient(channels=["general", "mod", "secret"], cached=["general"], visible=["general", "mod"])
        found = await watcher(client, Clock(), []).unstreamed_channels("S")
        self.assertEqual(found, ["mod"])
        self.assertEqual(client.fetched, ["mod", "secret"])  # cached channels are never fetched

    async def test_a_missing_visible_channel_reopens_the_gateway(self):
        clock, reopened = Clock(), []
        client = FakeClient(channels=["general", "mod"], cached=["general"], visible=["general", "mod"])
        watch = watcher(client, clock, reopened)
        watch.watch("S", "bot_roles")
        await settle()
        self.assertEqual(reopened, [1020.0])  # first check at +20 s found it

    async def test_nothing_happens_when_every_visible_channel_is_streamed(self):
        clock, reopened = Clock(), []
        client = FakeClient(channels=["general", "secret"], cached=["general"], visible=["general"])
        watch = watcher(client, clock, reopened)
        watch.watch("S", "joined")
        await settle()
        self.assertEqual(reopened, [])
        self.assertEqual(clock.slept, [20, 40])  # checked at +20 s and +60 s, then stopped

    async def test_access_given_later_is_caught_by_a_later_check(self):
        clock, reopened = Clock(), []
        client = FakeClient(channels=["general", "mod"], cached=["general"], visible=["general"])
        watch = watcher(client, clock, reopened)
        original = clock.sleep

        async def sleep(seconds):
            await original(seconds)
            if clock.now >= 1060:
                client.visible.add("mod")  # the owner adds the channel override after the first check

        watch.sleep = sleep
        watch.watch("S", "bot_roles")
        await settle()
        self.assertEqual(reopened, [1060.0])

    async def test_reconnects_are_spaced_out(self):
        clock, reopened = Clock(), []
        watch = watcher(FakeClient(channels=[], cached=[], visible=[]), clock, reopened)
        watch.request_reconnect("first")
        await settle()
        clock.now += 100
        watch.request_reconnect("second")
        await settle()
        self.assertEqual(reopened, [1000.0, 1600.0])  # the second waits out the ten-minute spacing

    async def test_a_failed_check_never_raises_or_reconnects(self):
        clock, reopened = Clock(), []
        watch = watcher(FakeClient(channels=[], cached=[], visible=[], fail_server=True), clock, reopened)
        with self.assertLogs("stoat_moderator", "WARNING"):
            watch.watch("S", "joined")
            await settle()
        self.assertEqual(reopened, [])

    async def test_a_new_event_restarts_the_checks_for_that_server(self):
        clock, reopened = Clock(), []
        watch = watcher(FakeClient(channels=[], cached=[], visible=[]), clock, reopened)
        watch.watch("S", "joined")
        first = watch._watches["S"]
        watch.watch("S", "bot_roles")
        await settle()
        self.assertTrue(first.cancelled())

    async def test_the_sweep_stops_at_the_first_server_with_a_missing_channel(self):
        clock, reopened = Clock(), []
        client = FakeClient(channels=["general", "mod"], cached=["general"], visible=["general"])
        client.servers = {"A": object(), "B": object(), "C": object()}
        checked = []
        watch = watcher(client, clock, reopened)
        original = watch.unstreamed_channels

        async def unstreamed(server_id):
            checked.append(server_id)
            if server_id == "B":
                client.visible.add("mod")
            return await original(server_id)

        watch.unstreamed_channels = unstreamed
        self.assertTrue(await watch.sweep(interval=3600))
        await settle()
        self.assertEqual(checked, ["A", "B"])
        self.assertEqual(len(reopened), 1)
        self.assertEqual(clock.slept, [20.0])  # spaced out between servers, capped at 20 s

    async def test_a_quiet_sweep_requests_nothing(self):
        clock, reopened = Clock(), []
        client = FakeClient(channels=["general"], cached=["general"], visible=["general"])
        client.servers = {"A": object(), "B": object()}
        self.assertFalse(await watcher(client, clock, reopened).sweep(interval=3600))
        self.assertEqual(reopened, [])

    async def test_large_servers_are_checked_a_bounded_number_of_channels_at_a_time(self):
        hidden = [f"c{number}" for number in range(100)]
        client = FakeClient(channels=hidden, cached=[], visible=[])
        await watcher(client, Clock(), []).unstreamed_channels("S")
        self.assertEqual(len(client.fetched), gateway_access.MAX_CHANNEL_FETCHES)

    async def test_an_empty_server_id_is_ignored(self):
        watch = watcher(FakeClient(channels=[], cached=[], visible=[]), Clock(), [])
        watch.watch("", "lost_channel")
        self.assertEqual(watch._watches, {})


class ReopenGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_closes_the_socket_without_marking_the_shard_closed(self):
        closed = []

        class Socket:
            async def close(self, *, code):
                closed.append(code)

        shard = type("Shard", (), {"_socket": Socket(), "_closed": False})()
        self.assertTrue(await gateway_access.reopen_gateway(type("Client", (), {"shard": shard})()))
        self.assertEqual(closed, [1000])
        self.assertFalse(shard._closed)

    async def test_does_nothing_while_disconnected_or_shutting_down(self):
        for shard in (type("Shard", (), {"_socket": None, "_closed": False})(), type("Shard", (), {"_socket": object(), "_closed": True})()):
            self.assertFalse(await gateway_access.reopen_gateway(type("Client", (), {"shard": shard})()))


if __name__ == "__main__":
    unittest.main()
