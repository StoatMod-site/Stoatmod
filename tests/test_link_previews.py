"""Link previews that Stoat appends after a message is sent are scanned as images, without re-scanning the text."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import stoat

from bot import ModerationBot
from moderation import ModerationError


def image_embed(url: str) -> stoat.ImageEmbed:
    embed = object.__new__(stoat.ImageEmbed)
    for name, value in (("url", url), ("width", 100), ("height", 100), ("size", None)):
        object.__setattr__(embed, name, value)
    return embed


def website_embed(preview_url: str | None) -> stoat.WebsiteEmbed:
    embed = object.__new__(stoat.WebsiteEmbed)
    values = {
        "url": "https://example.com/page", "original_url": "https://example.com/page", "special": None, "title": "Page",
        "description": None, "image": image_embed(preview_url) if preview_url else None, "video": None,
        "site_name": "Example", "icon_url": None, "color": None,
    }
    for name, value in values.items():
        object.__setattr__(embed, name, value)
    return embed


def make_bot(image_scanning: bool = True) -> ModerationBot:
    bot = object.__new__(ModerationBot)
    bot._message_author_is_moderator = AsyncMock(return_value=False)
    bot.moderation_settings = SimpleNamespace(max_image_bytes=10_000_000)
    bot.database = SimpleNamespace(get_image_scanning=Mock(return_value=image_scanning))
    bot.moderator = SimpleNamespace(
        classify_text=AsyncMock(side_effect=ModerationError("offline")),
        classify_url=AsyncMock(side_effect=ModerationError("offline")),
    )
    bot.limiter = asyncio.Semaphore(4)
    bot.log_result = Mock()
    return bot


def make_message(content: str = "look at this", embeds=None, attachments=None):
    return SimpleNamespace(
        id="message", content=content, channel_id="channel", author_id="author",
        attachments=attachments or [], embeds=embeds or [],
        get_server=Mock(return_value=(SimpleNamespace(), "server")),
        get_author_as_user=Mock(return_value=None),
    )


class EmbedImageTests(unittest.TestCase):
    def test_collects_image_links_and_link_preview_pictures(self):
        bot = make_bot()
        images = bot._embed_images([
            image_embed("https://cdn.example/a.png"),
            website_embed("https://cdn.example/preview.jpg"),
            website_embed(None),
            website_embed("http://insecure.example/preview.jpg"),
        ])
        self.assertEqual(images, [("embed:0", "https://cdn.example/a.png"), ("embed:1:preview", "https://cdn.example/preview.jpg")])


class AppendedPreviewScanTests(unittest.TestCase):
    def test_appended_preview_is_scanned_without_text_or_attachments(self):
        bot = make_bot()
        attachment = SimpleNamespace(id="file", content_type="image/png", size=10, deleted=False, url=Mock(return_value="https://cdn.example/file.png"))
        message = make_message(attachments=[attachment])
        asyncio.run(bot.scan_message(message, appended_embeds=[website_embed("https://cdn.example/preview.jpg")]))
        bot.moderator.classify_text.assert_not_awaited()
        bot.moderator.classify_url.assert_awaited_once_with("https://cdn.example/preview.jpg")

    def test_normal_scan_includes_link_previews_already_on_the_message(self):
        bot = make_bot()
        message = make_message(embeds=[website_embed("https://cdn.example/preview.jpg")])
        asyncio.run(bot.scan_message(message))
        bot.moderator.classify_text.assert_awaited_once()
        bot.moderator.classify_url.assert_awaited_once_with("https://cdn.example/preview.jpg")

    def test_append_event_dispatches_preview_scan(self):
        bot = make_bot()
        bot.message_is_in_scope = Mock(return_value=True)
        bot.dispatch_scan = Mock()
        message = make_message()
        preview = website_embed("https://cdn.example/preview.jpg")
        event = SimpleNamespace(message=message, data=SimpleNamespace(embeds=[preview], id="message", channel_id="channel"))
        asyncio.run(bot.handle_message_append(event))
        bot.dispatch_scan.assert_called_once_with(message, appended_embeds=[preview])

    def test_append_event_ignored_without_image_scanning_or_previews(self):
        for scanning, embeds in ((False, [website_embed("https://cdn.example/preview.jpg")]), (True, [website_embed(None)]), (True, [])):
            bot = make_bot(image_scanning=scanning)
            bot.message_is_in_scope = Mock(return_value=True)
            bot.dispatch_scan = Mock()
            event = SimpleNamespace(message=make_message(), data=SimpleNamespace(embeds=embeds, id="message", channel_id="channel"))
            asyncio.run(bot.handle_message_append(event))
            bot.dispatch_scan.assert_not_called()

    def test_append_event_skips_out_of_scope_messages(self):
        bot = make_bot()
        bot.message_is_in_scope = Mock(return_value=False)
        bot.dispatch_scan = Mock()
        event = SimpleNamespace(message=make_message(), data=SimpleNamespace(embeds=[website_embed("https://cdn.example/p.jpg")], id="message", channel_id="channel"))
        asyncio.run(bot.handle_message_append(event))
        bot.dispatch_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
