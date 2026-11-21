"""Reopen the Stoat gateway connection when the bot can see a channel the connection is not streaming.

Stoat's gateway streams a channel's messages to a connection only while the connection's session believes the
bot can see that channel. The session re-checks a server when the bot joins it or the bot's own roles change, but
a channel permission override changed later is only applied to channels the session already holds. So:

* the bot loses a channel (a role swap, an override removed) and gets it back through a channel override, or
* the bot joins, then is let into a private channel through a channel override,

and that channel's messages never reach the bot. Commands there are ignored without a reply and nothing there is
moderated, until the bot reconnects. Seen on 2026-11-21 with a private mod channel.

After the events that usually come right before this (the bot joins a server, its roles change, or it loses a
channel) the watcher re-checks that server a few times over the next ten minutes. A private channel created later
and opened to the bot only through an override sends the bot no event at all, so an hourly sweep also checks every
server, one at a time. A channel that the bot can fetch but that is not in the gateway cache is one the connection
is not streaming; the watcher then reopens the gateway connection (the library reconnects and Stoat sends a fresh
Ready), at most once every ten minutes.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Awaitable, Callable

logger = logging.getLogger("stoat_moderator")

CHECK_DELAYS = (20.0, 60.0, 180.0, 600.0)  # seconds after the event, so the owner has time to finish their changes
MIN_RECONNECT_INTERVAL = 600.0
SWEEP_INTERVAL = 3600.0
MAX_SWEEP_SPACING = 20.0  # seconds between servers during a sweep, so it never bursts against Stoat's limits
MAX_CHANNEL_FETCHES = 40  # per check, in random order so large servers are covered over a few sweeps


def _cache_context() -> Any:
    from stoat.cache import CacheContextType, UndefinedCacheContext

    return UndefinedCacheContext(type=CacheContextType.undefined)


async def reopen_gateway(client: Any) -> bool:
    """Close the live websocket without marking the shard closed; the library then reconnects by itself."""
    shard = client.shard
    socket = getattr(shard, "_socket", None)
    if socket is None or getattr(shard, "_closed", False):
        return False
    await socket.close(code=1000)
    return True


class AccessWatcher:
    def __init__(
        self,
        client: Any,
        *,
        delays: tuple[float, ...] = CHECK_DELAYS,
        min_interval: float = MIN_RECONNECT_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        reopen: Callable[[Any], Awaitable[bool]] = reopen_gateway,
    ) -> None:
        self.client = client
        self.delays = delays
        self.min_interval = min_interval
        self.clock = clock
        self.sleep = sleep
        self.reopen = reopen
        self._watches: dict[str, asyncio.Task] = {}
        self._reconnect_task: asyncio.Task | None = None
        self._sweep_task: asyncio.Task | None = None
        self._last_reconnect = float("-inf")

    def start_sweeps(self, interval: float = SWEEP_INTERVAL) -> None:
        """Start the hourly check of every server (idempotent; call from Ready)."""
        try:
            if self._sweep_task is None or self._sweep_task.done():
                self._sweep_task = asyncio.create_task(self._sweep_forever(interval), name="access-sweep")
        except Exception:
            logger.warning("access_sweep_start_failed", exc_info=True)

    async def _sweep_forever(self, interval: float) -> None:
        while True:
            await self.sleep(interval)
            try:
                await self.sweep(interval)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("access_sweep_failed", exc_info=True)

    async def sweep(self, interval: float = SWEEP_INTERVAL) -> bool:
        """Check each server once, spread over most of the interval. True if a reconnect was requested."""
        server_ids = list(getattr(self.client, "servers", {}) or {})
        spacing = min(MAX_SWEEP_SPACING, interval * 0.8 / max(1, len(server_ids)))
        for server_id in server_ids:
            try:
                missing = await self.unstreamed_channels(server_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                missing = []
            if missing:
                logger.warning("gateway_channel_not_streamed server_id=%s channels=%s reason=sweep",
                               server_id, ",".join(missing))
                self.request_reconnect(f"sweep server={server_id}")
                return True  # the reconnect refreshes every server at once
            await self.sleep(spacing)
        return False

    def watch(self, server_id: str, reason: str) -> None:
        """Start (or restart) the checks for one server. Never raises."""
        if not server_id:
            return
        try:
            current = self._watches.get(server_id)
            if current is not None and not current.done():
                current.cancel()
            self._watches[server_id] = asyncio.create_task(
                self._watch(server_id, reason), name=f"access-watch-{server_id}"
            )
        except Exception:
            logger.warning("access_watch_start_failed server_id=%s", server_id, exc_info=True)

    async def _watch(self, server_id: str, reason: str) -> None:
        started = self.clock()
        try:
            for delay in self.delays:
                wait = started + delay - self.clock()
                if wait > 0:
                    await self.sleep(wait)
                missing = await self.unstreamed_channels(server_id)
                if missing:
                    logger.warning(
                        "gateway_channel_not_streamed server_id=%s channels=%s reason=%s",
                        server_id, ",".join(missing), reason,
                    )
                    self.request_reconnect(f"server={server_id}")
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("access_watch_failed server_id=%s", server_id, exc_info=True)
        finally:
            if self._watches.get(server_id) is asyncio.current_task():
                self._watches.pop(server_id, None)

    async def unstreamed_channels(self, server_id: str) -> list[str]:
        """Channels of the server that the bot may see but that the gateway has not given it."""
        cache = self.client.state.cache
        if cache is None:
            return []
        server = await self.client.fetch_server(server_id)
        context = _cache_context()
        unknown = [
            channel_id for channel_id in list(getattr(server, "channel_ids", None) or [])
            if cache.get_channel(channel_id, context) is None
        ]
        if len(unknown) > MAX_CHANNEL_FETCHES:
            unknown = random.sample(unknown, MAX_CHANNEL_FETCHES)
        visible = []
        for channel_id in unknown:
            try:
                await self.client.fetch_channel(channel_id)
            except Exception:  # Forbidden: hidden from the bot as intended; NotFound: already gone
                continue
            visible.append(channel_id)
        return visible

    def request_reconnect(self, reason: str) -> None:
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return
        self._reconnect_task = asyncio.create_task(self._reconnect(reason), name="gateway-reconnect")

    async def _reconnect(self, reason: str) -> None:
        try:
            wait = self._last_reconnect + self.min_interval - self.clock()
            if wait > 0:
                logger.info("gateway_reconnect_deferred seconds=%d reason=%s", int(wait), reason)
                await self.sleep(wait)
            self._last_reconnect = self.clock()
            reopened = await self.reopen(self.client)
            logger.warning("gateway_reconnect reason=%s reopened=%s", reason, reopened)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("gateway_reconnect_failed reason=%s", reason, exc_info=True)
