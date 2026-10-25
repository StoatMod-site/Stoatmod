"""Pillow hardening shared by the bot and the dashboard API.

Stoatmod only ever needs PNG, JPEG, GIF and WebP. Opening untrusted bytes with
``formats=SAFE_IMAGE_FORMATS`` keeps Pillow away from its rarely used decoders
(TIFF, PDF, BMP, EPS, FlashPix and others), where most of its memory-safety
bugs have been found.
"""

from __future__ import annotations

import io

from PIL import Image

SAFE_IMAGE_FORMATS = ("PNG", "JPEG", "GIF", "WEBP")


def open_image(data: bytes) -> Image.Image:
    """Open untrusted image bytes, refusing any format outside the allowlist."""
    return Image.open(io.BytesIO(data), formats=SAFE_IMAGE_FORMATS)
