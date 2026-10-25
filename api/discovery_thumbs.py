"""Small WebP thumbnails of Discovery listing icons and banners.

Stoat's media host serves the original upload at any size (an animated banner can be several
megabytes) and cannot resize. Cards show these at a few hundred pixels, so the website asks for
/api/public/discovery/thumb/<server_id>/<icon|banner>.webp?w=<width> instead. The source is always
resolved from the listing itself (never from the request), so this is not an open image proxy.
Animated images become their first frame.
"""
from __future__ import annotations

import asyncio
import io
import threading
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse

from aiohttp import ClientSession, ClientTimeout, web
from PIL import Image, ImageFile, ImageOps

from image_safety import open_image

MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_PIXELS = 40_000_000
WIDTHS = {"icon": (96, 152, 256), "banner": (480, 640, 960, 1200)}
TTL_SECONDS = 6 * 60 * 60
CACHE_ENTRIES = 400
USER_AGENT = "Stoatmod/1.0 (+https://modstoat.site)"

_cache: "OrderedDict[tuple[str, str, int], tuple[float, str, bytes]]" = OrderedDict()


def is_stoat_media_url(url: Any) -> bool:
    parsed = urlparse(str(url or ""))
    host = (parsed.hostname or "").lower()
    return (
        parsed.scheme == "https"
        and not parsed.username
        and not parsed.password
        and (host == "stoatusercontent.com" or host.endswith(".stoatusercontent.com"))
    )


async def fetch_stoat_media(session: ClientSession, url: Any, *, max_bytes: int = MAX_SOURCE_BYTES) -> bytes | None:
    """Download a file from Stoat's media host, following its own redirects (animated banners redirect to a file name)."""
    current = str(url or "")
    for _ in range(4):
        if not is_stoat_media_url(current):
            return None
        try:
            async with session.get(current, allow_redirects=False) as response:
                if response.status in (301, 302, 303, 307, 308):
                    current = urljoin(current, response.headers.get("Location", ""))
                    continue
                if response.status != 200:
                    return None
                # read(n) returns whatever has arrived so far, so collect chunks until the end of the file.
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > max_bytes:
                        return None
                    chunks.append(chunk)
        except Exception:  # noqa: BLE001 - callers fall back to the original image
            return None
        return b"".join(chunks) if size else None
    return None


_truncated_lock = threading.Lock()


def _first_frame(data: bytes) -> Image.Image:
    with open_image(data) as image:
        if image.width * image.height > MAX_SOURCE_PIXELS:
            raise ValueError("image too large")
        image.seek(0)
        return (ImageOps.exif_transpose(image) or image).convert("RGBA")


def make_thumbnail(data: bytes, width: int) -> bytes:
    """First frame, scaled down to `width` (never up), as WebP."""
    try:
        frame = _first_frame(data)
    except OSError as error:
        if "truncated" not in str(error):
            raise
        # Browsers show GIFs that end a few bytes early; decode those leniently for this thumbnail only.
        with _truncated_lock:
            previous = ImageFile.LOAD_TRUNCATED_IMAGES
            ImageFile.LOAD_TRUNCATED_IMAGES = True
            try:
                frame = _first_frame(data)
            finally:
                ImageFile.LOAD_TRUNCATED_IMAGES = previous
    if frame.width > width:
        frame = frame.resize((width, max(1, round(frame.height * width / frame.width))), Image.LANCZOS)
    output = io.BytesIO()
    frame.save(output, format="WEBP", quality=80, method=4)
    return output.getvalue()


def _remember(key: tuple[str, str, int], source: str, body: bytes) -> None:
    _cache[key] = (time.monotonic(), source, body)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_ENTRIES:
        _cache.popitem(last=False)


def create_handler(
    find_listing: Callable[[web.Request, str], dict[str, Any] | None],
    uploaded_media: Callable[[web.Request, str, str], dict[str, Any] | None],
) -> Callable[[web.Request], Awaitable[web.StreamResponse]]:
    """`find_listing(request, server_id)` returns the public listing (with its current icon/banner URLs);
    `uploaded_media(request, server_id, "logo"|"banner")` returns a logo or banner uploaded on the dashboard."""

    async def public_discovery_thumbnail(request: web.Request) -> web.StreamResponse:
        server_id = request.match_info["server_id"]
        kind = request.match_info["kind"]
        if kind not in WIDTHS or not server_id.isalnum() or len(server_id) > 64:
            raise web.HTTPNotFound()
        try:
            requested = int(request.query.get("w", "0"))
        except ValueError:
            raise web.HTTPNotFound() from None
        # Round up to a fixed set of sizes so each image is rendered a handful of times at most.
        width = next((size for size in WIDTHS[kind] if size >= requested), WIDTHS[kind][-1])
        listing = find_listing(request, server_id)
        if listing is None:
            raise web.HTTPNotFound()
        uploaded = uploaded_media(request, listing["server_id"], "logo" if kind == "icon" else "banner")
        source = (
            "upload:" + str(uploaded.get("digest") or "")
            if uploaded
            else str(listing.get("server_icon_url" if kind == "icon" else "server_banner_url") or "")
        )
        if not source:
            raise web.HTTPNotFound()
        key = (str(listing["server_id"]), kind, width)
        cached = _cache.get(key)
        now = time.monotonic()
        if cached and cached[1] == source and now - cached[0] < TTL_SECONDS:
            body = cached[2]
        else:
            if uploaded:
                data = uploaded.get("data")
            else:
                async with ClientSession(timeout=ClientTimeout(total=10), headers={"User-Agent": USER_AGENT}) as session:
                    data = await fetch_stoat_media(session, source)
            if not data:
                raise web.HTTPNotFound()
            try:
                body = await asyncio.get_running_loop().run_in_executor(None, make_thumbnail, bytes(data), width)
            except Exception:  # noqa: BLE001 - an unreadable image falls back to the original in the browser
                raise web.HTTPNotFound() from None
            _remember(key, source, body)
        return web.Response(
            body=body,
            content_type="image/webp",
            headers={
                # The URL carries a version of the source image, so a changed icon gets a new URL.
                "Cache-Control": "public, max-age=604800, stale-while-revalidate=2592000",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return public_discovery_thumbnail
