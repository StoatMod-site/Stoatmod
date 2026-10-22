"""Social preview images (1200x630) for Stoatmod Discovery, in the house style of /og.png: black grid, corner brackets,
monospace eyebrow, condensed uppercase headline and an orbit graphic.

Static page cards are generated into website/public/discovery/og by scripts/generate_discovery_og.py. Server cards are
rendered on demand by the public API (/api/public/discovery/og/<server_id>.png) from the listing's banner, icon, name and
public stats. Only open-source system fonts are used (Liberation, DejaVu); STOATMOD_OG_FONT_DIR can point elsewhere.
"""

from __future__ import annotations

import io
import math
import os
import unicodedata
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps

WIDTH, HEIGHT = 1200, 630
SCALE = 2  # draw at 2x and downsample for smooth lines and text
BACKGROUND = (5, 5, 5)
WHITE = (244, 244, 240)
MUTED = (163, 163, 160)
FAINT = (140, 140, 136)
GREEN = (114, 197, 145)

FONT_DIRS = [
    os.environ.get("STOATMOD_OG_FONT_DIR", ""),
    "/usr/share/fonts/truetype/liberation",
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/liberation",
    "/usr/share/fonts/dejavu",
]
HEADLINE = "LiberationSansNarrow-Bold.ttf"
SANS_BOLD = "LiberationSans-Bold.ttf"
SANS = "LiberationSans-Regular.ttf"
MONO = "DejaVuSansMono.ttf"
MONO_BOLD = "DejaVuSansMono-Bold.ttf"
NAME = "DejaVuSansCondensed-Bold.ttf"  # wide character coverage for server names
BODY_WIDE = "DejaVuSans.ttf"


@lru_cache(maxsize=64)
def _font(name: str, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for directory in FONT_DIRS:
        if not directory:
            continue
        for candidate in (Path(directory) / name, *Path(directory).rglob(name)):
            if candidate.is_file():
                return ImageFont.truetype(str(candidate), size * SCALE)
    return ImageFont.load_default(size * SCALE)


def clean_text(value: str) -> str:
    """Drop emoji and other symbols the fonts cannot draw, and collapse whitespace."""
    kept = []
    for character in value:
        category = unicodedata.category(character)
        if category in {"So", "Sk", "Cs", "Co", "Cn", "Cf"} or 0xFE00 <= ord(character) <= 0xFE0F:
            continue
        kept.append(character)
    return " ".join("".join(kept).split())


def _s(value: float) -> int:
    return int(round(value * SCALE))


def _canvas(background: Image.Image | None = None) -> Image.Image:
    if background is not None:
        return background.resize((WIDTH * SCALE, HEIGHT * SCALE), Image.Resampling.LANCZOS).convert("RGB")
    return Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BACKGROUND)


def _grid(image: Image.Image, *, strength: int = 13) -> None:
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    for x in range(0, WIDTH + 1, 75):
        draw.line([(_s(x), 0), (_s(x), image.height)], fill=(255, 255, 255, strength), width=_s(1))
    for y in range(0, HEIGHT + 1, 75):
        draw.line([(0, _s(y)), (image.width, _s(y))], fill=(255, 255, 255, strength), width=_s(1))
    for x in (150, 525, 675, 1050):
        for y in (75, 555):
            draw.line([(_s(x - 7), _s(y)), (_s(x + 7), _s(y))], fill=(255, 255, 255, 60), width=_s(1))
            draw.line([(_s(x), _s(y - 7)), (_s(x), _s(y + 7))], fill=(255, 255, 255, 60), width=_s(1))
    image.paste(overlay, (0, 0), overlay)


def _brackets(draw: ImageDraw.ImageDraw) -> None:
    length, margin, width = 28, 28, 2
    for x, y, dx, dy in ((margin, margin, 1, 1), (WIDTH - margin, margin, -1, 1), (margin, HEIGHT - margin, 1, -1), (WIDTH - margin, HEIGHT - margin, -1, -1)):
        draw.line([(_s(x), _s(y)), (_s(x + dx * length), _s(y))], fill=(220, 220, 216), width=_s(width))
        draw.line([(_s(x), _s(y)), (_s(x), _s(y + dy * length))], fill=(220, 220, 216), width=_s(width))


def _spaced(draw: ImageDraw.ImageDraw, xy: tuple[float, float], text: str, font, fill, spacing: float = 2.2) -> float:
    x, y = xy
    for character in text:
        draw.text((_s(x), _s(y)), character, font=font, fill=fill)
        x += draw.textlength(character, font=font) / SCALE + spacing
    return x


def _eyebrow(draw: ImageDraw.ImageDraw, x: float, y: float, text: str, *, live: bool = False) -> None:
    draw.rectangle([_s(x), _s(y + 5), _s(x + 9), _s(y + 14)], fill=GREEN if live else WHITE)
    _spaced(draw, (x + 20, y), text.upper(), _font(MONO, 17), (210, 210, 206))


def _wrap(draw: ImageDraw.ImageDraw, text: str, font, max_width: float) -> list[str]:
    words, lines, line = text.split(), [], ""
    for word in words:
        trial = f"{line} {word}".strip()
        if draw.textlength(trial, font=font) / SCALE <= max_width or not line:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    return lines


def _fit(draw, text: str, font_name: str, max_width: float, sizes: range, max_lines: int):
    for size in sizes:
        font = _font(font_name, size)
        lines = _wrap(draw, text, font, max_width)
        if len(lines) <= max_lines and all(draw.textlength(line, font=font) / SCALE <= max_width for line in lines):
            return font, lines, size
    font = _font(font_name, sizes[-1])
    all_lines = _wrap(draw, text, font, max_width)
    lines = all_lines[:max_lines]
    if len(all_lines) > max_lines:
        # Text was cut: always end the last line with an ellipsis.
        last = lines[-1]
        while last and draw.textlength(last + "…", font=font) / SCALE > max_width:
            last = last[:-1]
        lines[-1] = last.rstrip(" ,.;:") + "…"
    else:
        lines = [_ellipsis(draw, line, font, max_width) for line in lines]
    return font, lines, sizes[-1]


def _ellipsis(draw, text: str, font, max_width: float) -> str:
    if draw.textlength(text, font=font) / SCALE <= max_width:
        return text
    while text and draw.textlength(text + "…", font=font) / SCALE > max_width:
        text = text[:-1]
    return text.rstrip() + "…"


def _orbit(image: Image.Image, cx: float, cy: float, radius: float, labels: list[str], center: str = "") -> None:
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    # dashed axes
    for offset in range(int(cx - radius - 70), int(cx + radius + 70), 14):
        draw.line([(_s(offset), _s(cy)), (_s(offset + 7), _s(cy))], fill=(255, 255, 255, 70), width=_s(1))
    for offset in range(int(cy - radius - 40), int(cy + radius + 40), 14):
        draw.line([(_s(cx), _s(offset)), (_s(cx), _s(offset + 7))], fill=(255, 255, 255, 50), width=_s(1))
    # dotted outer ring
    outer = radius * 1.18
    for step in range(0, 360, 3):
        angle = math.radians(step)
        x, y = cx + outer * math.cos(angle), cy + outer * math.sin(angle)
        draw.ellipse([_s(x - 1.1), _s(y - 1.1), _s(x + 1.1), _s(y + 1.1)], fill=(255, 255, 255, 120))
    rings = [(radius, 255, 2.4), (radius * 0.72, 150, 1.6), (radius * 0.46, 110, 1.4)]
    for ring, alpha, width in rings:
        draw.ellipse([_s(cx - ring), _s(cy - ring), _s(cx + ring), _s(cy + ring)], outline=(255, 255, 255, alpha), width=_s(width))
    for ring, angle_deg, size in ((radius, 222, 9), (radius * 0.72, 205, 5), (radius * 0.46, 0, 5), (outer, 180, 7), (outer, 0, 7)):
        angle = math.radians(angle_deg)
        x, y = cx + ring * math.cos(angle), cy + ring * math.sin(angle)
        draw.ellipse([_s(x - size), _s(y - size), _s(x + size), _s(y + size)], fill=(255, 255, 255, 255))
    angle = math.radians(222)
    x, y = cx + radius * math.cos(angle), cy + radius * math.sin(angle)
    draw.ellipse([_s(x - 18), _s(y - 18), _s(x + 18), _s(y + 18)], outline=(255, 255, 255, 170), width=_s(1.4))
    label_font = _font(MONO, 15)
    for index, label in enumerate(labels[:4]):
        ring = [outer, radius, radius * 0.72, radius * 0.46][index]
        _spaced(draw, (cx + 12, cy - ring - 26 + index * 4), label.upper(), label_font, (230, 230, 226, 230), 1.6)
    if center:
        font = _font(HEADLINE, 44)
        width = draw.textlength(center, font=font) / SCALE
        draw.text((_s(cx - width / 2), _s(cy - 28)), center, font=font, fill=(255, 255, 255, 255))
    image.paste(overlay, (0, 0), overlay)


def _podium(image: Image.Image, x0: float, base: float) -> None:
    draw = ImageDraw.Draw(image)
    bars = [("02", 210, 0.62), ("01", 300, 1.0), ("03", 150, 0.42)]
    for index, (label, height, shade) in enumerate(bars):
        x = x0 + index * 128
        fill = tuple(int(40 + 204 * shade) for _ in range(3))
        draw.rectangle([_s(x), _s(base - height), _s(x + 104), _s(base)], fill=fill)
        font = _font(MONO_BOLD, 22)
        draw.text((_s(x + 12), _s(base - height + 12)), label, font=font, fill=(5, 5, 5) if shade > 0.5 else WHITE)
    draw.line([(_s(x0 - 30), _s(base)), (_s(x0 + 3 * 128 + 6), _s(base))], fill=WHITE, width=_s(2))


def _tiles(image: Image.Image, x0: float, y0: float, names: list[str]) -> None:
    draw = ImageDraw.Draw(image)
    size, gap = 132, 12
    font = _font(MONO, 14)
    for index, name in enumerate(names[:9]):
        column, row = index % 3, index // 3
        x, y = x0 + column * (size + gap), y0 + row * (size + gap)
        draw.rectangle([_s(x), _s(y), _s(x + size), _s(y + size)], outline=(255, 255, 255, 255) if index == 0 else (90, 90, 88), width=_s(1.4))
        draw.text((_s(x + 14), _s(y + 14)), f"{index + 1:02d}", font=font, fill=FAINT)
        lines = _wrap(draw, name.upper(), font, size - 28)[:2]
        for line_index, line in enumerate(lines):
            draw.text((_s(x + 14), _s(y + size - 22 - (len(lines) - line_index) * 20)), line, font=font, fill=WHITE)


def _finish(image: Image.Image) -> bytes:
    final = image.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
    output = io.BytesIO()
    final.save(output, "PNG", optimize=True)
    return output.getvalue()


def render_page_card(*, eyebrow: str, title: list[str], subtitle: str, facts: list[str], path: str, graphic: str = "orbit",
                     labels: list[str] | None = None, center: str = "", tiles: list[str] | None = None) -> bytes:
    image = _canvas()
    _grid(image)
    if graphic == "podium":
        _podium(image, 800, 470)
    elif graphic == "tiles":
        _tiles(image, 730, 110, tiles or [])
    else:
        _orbit(image, 905, 318, 168, labels or [], center)
    draw = ImageDraw.Draw(image)
    _brackets(draw)
    _eyebrow(draw, 70, 118, eyebrow, live=True)
    lines = [line.upper() for line in title][:3]
    size = 96  # leaves room for two subtitle lines, the facts row and the address
    while size > 56 and max(draw.textlength(line, font=_font(HEADLINE, size)) / SCALE for line in lines) > 600:
        size -= 4
    font = _font(HEADLINE, size)
    y = 158
    for line in lines:
        draw.text((_s(70), _s(y)), line, font=font, fill=WHITE)
        y += size * 0.98
    y += 18
    sub_font, sub_lines, _size = _fit(draw, subtitle, SANS_BOLD, 590, range(34, 24, -2), 2)
    for line in sub_lines:
        draw.text((_s(70), _s(y)), line, font=sub_font, fill=WHITE)
        y += _size * 1.25
    y += 16
    draw.line([(_s(70), _s(y)), (_s(650), _s(y))], fill=(150, 150, 146), width=_s(1.2))
    facts_font = _font(SANS, 25)
    _ellipsis_facts = _ellipsis(draw, "  ·  ".join(facts), facts_font, 590)
    draw.text((_s(70), _s(y + 22)), _ellipsis_facts, font=facts_font, fill=MUTED)
    _spaced(draw, (70, 552), path.upper(), _font(MONO, 15), FAINT, 1.8)
    return _finish(image)


def _load(data: bytes | None) -> Image.Image | None:
    if not data:
        return None
    try:
        with Image.open(io.BytesIO(data)) as image:
            image.seek(0)
            image.draft("RGB", (2400, 1260))
            return image.convert("RGBA")
    except Exception:  # noqa: BLE001 - an unreadable image falls back to the plain card
        return None


def _cover(image: Image.Image, size: tuple[int, int]) -> Image.Image:
    return ImageOps.fit(image.convert("RGB"), size, Image.Resampling.LANCZOS)


def _tick(draw: ImageDraw.ImageDraw, cx: float, cy: float, radius: float) -> None:
    """The Discovery verified tick: a green disc with a dark check."""
    draw.ellipse([_s(cx - radius), _s(cy - radius), _s(cx + radius), _s(cy + radius)], fill=(114, 197, 145))
    draw.line(
        [(_s(cx - radius * 0.45), _s(cy + radius * 0.02)), (_s(cx - radius * 0.1), _s(cy + radius * 0.38)), (_s(cx + radius * 0.48), _s(cy - radius * 0.36))],
        fill=BACKGROUND, width=max(2, _s(radius * 0.22)), joint="curve",
    )


def render_server_card(server: dict, *, icon: bytes | None = None, banner: bytes | None = None) -> bytes:
    banner_image = _load(banner)
    if banner_image is not None:
        background = _cover(banner_image, (WIDTH * SCALE, HEIGHT * SCALE)).filter(ImageFilter.GaussianBlur(_s(1.5)))
        image = _canvas(background)
        shade = Image.new("L", (WIDTH * SCALE, 1))
        for x in range(shade.width):
            shade.putpixel((x, 0), int(250 - 120 * (x / shade.width) ** 1.6))
        shade = shade.resize(image.size)
        image = Image.composite(Image.new("RGB", image.size, BACKGROUND), image, shade)
    else:
        image = _canvas()
        _grid(image)
        _orbit(image, 1010, 318, 150, [], "")
    draw = ImageDraw.Draw(image)
    _brackets(draw)
    _eyebrow(draw, 70, 70, "Stoatmod / Discovery / Stoat server", live=True)

    name = clean_text(str(server.get("server_name") or "")) or "Stoat server"
    icon_image = _load(icon)
    size = 150
    icon_box = Image.new("RGBA", (_s(size), _s(size)), (28, 28, 28, 255))
    if icon_image is not None:
        icon_box = _cover(icon_image, (_s(size), _s(size))).convert("RGBA")
    else:
        initial_font = _font(NAME, 70)
        initial = (name[:1] or "?").upper()
        icon_draw = ImageDraw.Draw(icon_box)
        width = icon_draw.textlength(initial, font=initial_font)
        icon_draw.text(((icon_box.width - width) / 2, _s(26)), initial, font=initial_font, fill=WHITE)
    mask = Image.new("L", icon_box.size, 0)
    ImageDraw.Draw(mask).ellipse([0, 0, icon_box.width - 1, icon_box.height - 1], fill=255)
    draw.ellipse([_s(70 - 4), _s(118 - 4), _s(70 + size + 4), _s(118 + size + 4)], fill=WHITE)
    image.paste(icon_box, (_s(70), _s(118)), mask)

    draw = ImageDraw.Draw(image)
    verified = bool(server.get("verified"))
    font, lines, font_size = _fit(draw, name, NAME, 940 if verified else 1000, range(74, 40, -4), 2)
    y = 298
    for index, line in enumerate(lines):
        draw.text((_s(70), _s(y)), line, font=font, fill=WHITE)
        if verified and index == len(lines) - 1:
            _tick(draw, 70 + draw.textlength(line, font=font) / SCALE + 30, y + font_size * 0.6, font_size * 0.3)
        y += font_size * 1.08
    description = clean_text(str(server.get("description") or ""))
    if description:
        body_font, body_lines, body_size = _fit(draw, description, BODY_WIDE, 900, range(26, 21, -1), 2 if len(lines) == 1 else 1)
        y += 22
        for line in body_lines:
            draw.text((_s(70), _s(y)), line, font=body_font, fill=(214, 214, 210))
            y += body_size * 1.35
    draw.line([(_s(70), _s(530)), (_s(1130), _s(530))], fill=(120, 120, 116), width=_s(1.2))
    members = int(server.get("member_count") or 0)
    messages = int(server.get("daily_messages") or 0)
    stats = [f"{members:,} {'member' if members == 1 else 'members'}", f"{messages:,} {'message' if messages == 1 else 'messages'} today"]
    if server.get("global_rank"):
        stats.append(f"#{server['global_rank']} activity")
    _spaced(draw, (70, 556), "  ·  ".join(stats).upper(), _font(MONO, 17), (230, 230, 226), 1.4)
    pill_font = _font(SANS_BOLD, 22)
    label = "Join on Stoat  →"
    width = draw.textlength(label, font=pill_font) / SCALE
    draw.rounded_rectangle([_s(1130 - width - 44), _s(546), _s(1130), _s(592)], radius=_s(10), fill=WHITE)
    draw.text((_s(1130 - width - 22), _s(555)), label, font=pill_font, fill=BACKGROUND)
    return _finish(image)
