"""Copies of flagged images kept with a moderation case so moderators can see what was removed.

Graphic violence: a reduced copy (longest side 1280 px). Explicit nudity: only a tiny, heavily blurred thumbnail. The image
is shrunk to BLUR_SOURCE_PX pixels before anything is stored, so the detail is destroyed and the thumbnail can never be
un-blurred. Anything matching sexual/minors is never stored in any form. Copies are case entry attachments, so they are
deleted with the case content after 30 days (appeal_privacy.purge_message) or when an appeal is decided.
"""

from __future__ import annotations

import io
from collections.abc import Iterable

from PIL import Image, ImageFilter

CASE_IMAGE_AUTHOR = "STOATMOD_IMAGE_SCAN"
NEVER_STORED = frozenset({"sexual/minors"})
REDUCED_MAX_PX = 1280
BLUR_SOURCE_PX = 24
BLUR_OUTPUT_PX = 240
GORE_FILENAME = "flagged-gore.jpg"
NUDITY_FILENAME = "flagged-nudity-blurred.jpg"


def treatment(categories: Iterable[str]) -> str | None:
    """'blurred', 'reduced' or None (store nothing) for the categories an image was removed for."""
    names = {str(category) for category in categories}
    if names & NEVER_STORED:
        return None
    if "sexual" in names:
        return "blurred"
    if "violence" in names:
        return "reduced"
    return None


def case_copy(data: bytes, categories: Iterable[str]) -> tuple[str, str, bytes] | None:
    """(filename, content type, JPEG bytes) to keep with the case, or None."""
    kind = treatment(categories)
    if kind is None or not data:
        return None
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.seek(0)  # first frame of an animation
            frame = image.convert("RGB")
    except Exception:  # noqa: BLE001 - an unreadable image is simply not kept
        return None
    if kind == "reduced":
        frame.thumbnail((REDUCED_MAX_PX, REDUCED_MAX_PX), Image.Resampling.LANCZOS)
        filename, quality = GORE_FILENAME, 82
    else:
        # Shrinking to a few dozen pixels throws the detail away; only this tiny version is ever kept.
        frame.thumbnail((BLUR_SOURCE_PX, BLUR_SOURCE_PX), Image.Resampling.BOX)
        frame = frame.filter(ImageFilter.GaussianBlur(1))
        width, height = frame.size
        scale = BLUR_OUTPUT_PX / max(width, height)
        frame = frame.resize((max(1, round(width * scale)), max(1, round(height * scale))), Image.Resampling.BILINEAR)
        frame = frame.filter(ImageFilter.GaussianBlur(8))
        filename, quality = NUDITY_FILENAME, 70
    output = io.BytesIO()
    frame.save(output, "JPEG", quality=quality)
    return filename, "image/jpeg", output.getvalue()


def note_text(filenames: Iterable[str]) -> str:
    names = set(filenames)
    parts = []
    if GORE_FILENAME in names:
        parts.append("a reduced copy of the removed image (graphic violence)")
    if NUDITY_FILENAME in names:
        parts.append("a permanently blurred thumbnail of the removed image (explicit nudity; the original is not kept)")
    return (
        "Stoatmod kept " + " and ".join(parts) + ". It is hidden behind a content warning and deleted "
        "automatically after 30 days."
    )
