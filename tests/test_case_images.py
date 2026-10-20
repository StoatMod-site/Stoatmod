import asyncio
import io
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from PIL import Image, ImageChops, ImageDraw, ImageStat

from bot import ModerationBot
from case_images import (
    BLUR_SOURCE_PX,
    CASE_IMAGE_AUTHOR,
    GORE_FILENAME,
    NUDITY_FILENAME,
    case_copy,
    note_text,
    treatment,
)


def _detailed_image(size=(1600, 1200), frames=1) -> bytes:
    """A high-detail test pattern (fine checkerboard + text) in place of a real photo."""
    images = []
    for frame in range(frames):
        image = Image.new("RGB", size, "white")
        draw = ImageDraw.Draw(image)
        for x in range(0, size[0], 8):
            for y in range(0, size[1], 8):
                if (x // 8 + y // 8 + frame) % 2:
                    draw.rectangle((x, y, x + 7, y + 7), fill=(200, 30, 30))
        draw.text((40, 40), "SECRET DETAIL 1234", fill="black")
        images.append(image)
    output = io.BytesIO()
    if frames > 1:
        images[0].save(output, "GIF", save_all=True, append_images=images[1:])
    else:
        images[0].save(output, "PNG")
    return output.getvalue()


class CaseImageTests(unittest.TestCase):
    def test_treatment_by_category(self) -> None:
        self.assertEqual(treatment({"violence"}), "reduced")
        self.assertEqual(treatment({"sexual"}), "blurred")
        self.assertEqual(treatment({"sexual", "violence"}), "blurred")
        self.assertIsNone(treatment({"sexual", "sexual/minors"}))
        self.assertIsNone(treatment({"hate"}))
        self.assertIsNone(case_copy(_detailed_image(), {"sexual/minors"}))

    def test_gore_copy_is_reduced_and_reencoded(self) -> None:
        filename, content_type, data = case_copy(_detailed_image((3000, 2000)), {"violence"})
        self.assertEqual((filename, content_type), (GORE_FILENAME, "image/jpeg"))
        with Image.open(io.BytesIO(data)) as image:
            self.assertEqual(max(image.size), 1280)
            self.assertNotIn("exif", image.info)

    def test_nudity_copy_cannot_be_unblurred(self) -> None:
        filename, _type, data = case_copy(_detailed_image(), {"sexual"})
        self.assertEqual(filename, NUDITY_FILENAME)
        with Image.open(io.BytesIO(data)) as stored:
            stored = stored.convert("RGB")
            self.assertLessEqual(max(stored.size), 240)
            # Everything stored is reproducible from a BLUR_SOURCE_PX-pixel image: the detail no longer exists.
            tiny = stored.resize((BLUR_SOURCE_PX, BLUR_SOURCE_PX * stored.height // stored.width), Image.Resampling.BOX)
            rebuilt = tiny.resize(stored.size, Image.Resampling.BILINEAR)
            difference = ImageStat.Stat(ImageChops.difference(stored, rebuilt)).mean
            self.assertLess(max(difference), 6)
            # The 8 px checkerboard (the "detail") is gone: neighbouring pixels are nearly identical.
            width, height = stored.size
            edges = ImageStat.Stat(ImageChops.difference(stored.crop((8, 0, width, height)), stored.crop((0, 0, width - 8, height)))).mean
            self.assertLess(max(edges), 6)

    def test_animated_and_unreadable_images(self) -> None:
        self.assertEqual(case_copy(_detailed_image((400, 300), frames=3), {"violence"})[0], GORE_FILENAME)
        self.assertIsNone(case_copy(b"not an image", {"violence"}))
        self.assertIsNone(case_copy(b"", {"violence"}))

    def test_note_text_names_what_was_kept(self) -> None:
        self.assertIn("graphic violence", note_text([GORE_FILENAME]))
        self.assertIn("original is not kept", note_text([NUDITY_FILENAME]))
        self.assertIn("30 days", note_text([GORE_FILENAME, NUDITY_FILENAME]))


class BotCaseImageTests(unittest.TestCase):
    def _bot(self) -> ModerationBot:
        bot = ModerationBot.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(max_image_bytes=10 * 1024 * 1024)
        bot.database = SimpleNamespace(
            get_warning_case=Mock(return_value=SimpleNamespace(reference_id="ABC123")),
            get_event_case=Mock(return_value=None),
            add_moderation_case_entry=Mock(),
        )
        return bot

    def test_flagged_images_are_attached_to_the_warning_case(self) -> None:
        bot = self._bot()
        bot._download_case_image = AsyncMock(return_value=_detailed_image((800, 600)))

        async def run() -> None:
            downloads = bot._start_case_image_downloads(
                [("img1", "https://cdn.stoat.chat/a.png"), ("img2", "https://cdn.stoat.chat/b.png"), ("img3", "https://cdn.stoat.chat/c.png")],
                [
                    ("img1", None, [{"category": "violence"}]),
                    ("img2", None, [{"category": "sexual"}]),
                    ("img3", None, [{"category": "sexual/minors"}, {"category": "sexual"}]),
                    ("text", None, [{"category": "hate"}]),
                ],
            )
            self.assertEqual(len(downloads), 2)
            await bot._store_case_images("server", 7, 99, downloads)

        asyncio.run(run())
        args, kwargs = bot.database.add_moderation_case_entry.call_args
        self.assertEqual(args[:3], ("server", "ABC123", "note"))
        self.assertEqual(args[4], CASE_IMAGE_AUTHOR)
        self.assertEqual([name for name, _type, _data in kwargs["attachments"]], [GORE_FILENAME, NUDITY_FILENAME])
        bot.database.get_warning_case.assert_called_once_with("server", 7)

    def test_without_a_case_nothing_is_stored(self) -> None:
        bot = self._bot()
        bot._download_case_image = AsyncMock(return_value=_detailed_image((200, 200)))

        async def run() -> None:
            downloads = bot._start_case_image_downloads([("img1", "https://cdn.stoat.chat/a.png")], [("img1", None, [{"category": "violence"}])])
            await bot._store_case_images("server", None, 99, downloads)

        asyncio.run(run())
        bot.database.get_event_case.assert_called_once_with("server", 99)
        bot.database.add_moderation_case_entry.assert_not_called()

    def test_downloads_refuse_internal_addresses(self) -> None:
        bot = self._bot()
        with patch("bot.aiohttp.ClientSession") as session:
            for url in ("http://cdn.stoat.chat/a.png", "https://127.0.0.1/a.png", "https://[::1]/a.png", "https://localhost/a.png", "https://x.localhost/a.png"):
                self.assertIsNone(asyncio.run(bot._download_case_image(url)), url)
            session.assert_not_called()


if __name__ == "__main__":
    unittest.main()
