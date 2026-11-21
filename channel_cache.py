"""Keep the bot's channel cache in step with channels a server opens to it later.

Stoat only puts a channel in the bot's cache when the bot could see it as it connected or joined. A common
setup is: invite the bot, then give its role access to a private channel (a mod channel, a log channel).
Messages from that channel do arrive, but `message.get_server()` finds no cached channel and returns nothing,
so every command there is treated as if it were sent outside a server and the channel is never moderated.
Until the bot restarts, nothing fixes itself.

`ensure_message_channel_cached` fetches the channel the first time a message from an unknown one arrives and
stores it, which is what the gateway would have done had the bot been able to see the channel earlier.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("stoat_moderator")

# After a failed fetch (or while one is running) the same channel is not fetched again for this long, so a
# busy channel the bot cannot actually read cannot turn every message into an API request.
RETRY_SECONDS = 60.0
_MAX_TRACKED = 2000
_next_try: dict[str, float] = {}


def _cache_context() -> Any:
    from stoat.cache import CacheContextType, UndefinedCacheContext

    return UndefinedCacheContext(type=CacheContextType.undefined)


def _remember_attempt(channel_id: str, now: float) -> None:
    if len(_next_try) >= _MAX_TRACKED:
        for key in [key for key, due in _next_try.items() if due <= now]:
            _next_try.pop(key, None)
        if len(_next_try) >= _MAX_TRACKED:
            _next_try.clear()
    _next_try[channel_id] = now + RETRY_SECONDS


async def ensure_message_channel_cached(
    client: Any, message: Any, *, now: float | None = None
) -> bool:
    """Cache `message`'s channel if the bot has never seen it. Returns True when it was added.

    Never raises: a message from a channel that cannot be fetched is handled exactly as before.
    """
    try:
        if message.get_channel() is not None:
            return False
        cache = client.state.cache
        channel_id = message.channel_id
        if cache is None or not channel_id:
            return False
        moment = time.monotonic() if now is None else now
        if _next_try.get(channel_id, 0.0) > moment:
            return False
        _remember_attempt(channel_id, moment)
        channel = await client.fetch_channel(channel_id)
        cache.store_channel(channel, _cache_context())
        _next_try.pop(channel_id, None)
        logger.info(
            "channel_cache_added channel_id=%s server_id=%s",
            channel_id,
            getattr(channel, "server_id", ""),
        )
        return True
    except Exception as exc:  # noqa: BLE001 - the caller carries on without the channel
        logger.warning(
            "channel_cache_fetch_failed channel_id=%s error=%s",
            getattr(message, "channel_id", ""),
            type(exc).__name__,
        )
        return False
