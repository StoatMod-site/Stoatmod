import asyncio
import unittest

import channel_cache


class FakeCache:
    def __init__(self) -> None:
        self.channels: dict[str, object] = {}

    def store_channel(self, channel, ctx) -> None:
        self.channels[channel.id] = channel


class FakeChannel:
    def __init__(self, channel_id: str, server_id: str = "S1") -> None:
        self.id = channel_id
        self.server_id = server_id


class FakeClient:
    def __init__(self, cache, *, known=None, fail=None) -> None:
        self.state = type("State", (), {"cache": cache})()
        self.known = known or {}
        self.fail = fail
        self.fetches: list[str] = []

    async def fetch_channel(self, channel_id: str):
        self.fetches.append(channel_id)
        if self.fail is not None:
            raise self.fail
        return self.known[channel_id]


class FakeMessage:
    def __init__(self, cache: FakeCache, channel_id: str = "C1") -> None:
        self._cache = cache
        self.channel_id = channel_id

    def get_channel(self):
        return self._cache.channels.get(self.channel_id)


class ChannelCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        channel_cache._next_try.clear()

    def run_it(self, client, message, now=1000.0) -> bool:
        return asyncio.run(channel_cache.ensure_message_channel_cached(client, message, now=now))

    def test_unknown_channel_is_fetched_and_cached_so_commands_find_their_server(self) -> None:
        cache = FakeCache()
        client = FakeClient(cache, known={"C1": FakeChannel("C1")})
        message = FakeMessage(cache)

        self.assertTrue(self.run_it(client, message))

        self.assertIs(message.get_channel(), cache.channels["C1"])
        self.assertEqual(client.fetches, ["C1"])

    def test_known_channel_is_never_fetched(self) -> None:
        cache = FakeCache()
        cache.channels["C1"] = FakeChannel("C1")
        client = FakeClient(cache, known={"C1": FakeChannel("C1")})

        self.assertFalse(self.run_it(client, FakeMessage(cache)))
        self.assertEqual(client.fetches, [])

    def test_a_channel_the_bot_cannot_read_is_retried_only_after_the_pause(self) -> None:
        cache = FakeCache()
        client = FakeClient(cache, fail=PermissionError("forbidden"))
        message = FakeMessage(cache)

        self.assertFalse(self.run_it(client, message, now=1000.0))
        self.assertFalse(self.run_it(client, message, now=1010.0))
        self.assertEqual(len(client.fetches), 1)

        self.assertFalse(self.run_it(client, message, now=1000.0 + channel_cache.RETRY_SECONDS + 1))
        self.assertEqual(len(client.fetches), 2)
        self.assertEqual(cache.channels, {})

    def test_a_failed_fetch_never_raises_into_the_message_handler(self) -> None:
        cache = FakeCache()
        client = FakeClient(cache, fail=RuntimeError("network down"))

        self.assertFalse(self.run_it(client, FakeMessage(cache)))

    def test_no_cache_or_channel_id_is_a_no_op(self) -> None:
        cache = FakeCache()
        client = FakeClient(None)
        self.assertFalse(self.run_it(client, FakeMessage(cache)))
        self.assertFalse(self.run_it(FakeClient(cache), FakeMessage(cache, channel_id="")))

    def test_tracking_table_stays_bounded(self) -> None:
        for number in range(channel_cache._MAX_TRACKED + 50):
            channel_cache._remember_attempt(f"C{number}", 1000.0)
        self.assertLessEqual(len(channel_cache._next_try), channel_cache._MAX_TRACKED)


if __name__ == "__main__":
    unittest.main()
