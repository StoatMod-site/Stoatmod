"""Links to a channel or message in the same server are internal and are not removed by link protection."""
import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from bot import ModerationBot

SERVER = "01KNPJ6T0XGB9GD2ZST2B8GD84"
OTHER = "01KNPJ6T0XGB9GD2ZST2B8GD85"
MESSAGE_LINK = f"https://stoat.chat/server/{SERVER}/channel/01KWH8PZPVCCGFHEYPWZ78BZP6/01M4T5D3CH8Y2XCD27D6B14QPT"


class InternalLinkTests(unittest.TestCase):
    def filterable(self, content, **options):
        return ModerationBot._contains_filterable_link(content, server_id=SERVER, **options)

    def test_same_server_message_and_channel_links_are_internal(self):
        for content in (
            MESSAGE_LINK + " I have fixed this so you can kick multiple people",
            f"see https://stoat.chat/server/{SERVER}/channel/01KWH8PZPVCCGFHEYPWZ78BZP6",
            f"https://stoat.chat/app/server/{SERVER}/channel/01KWH8PZPVCCGFHEYPWZ78BZP6.",
        ):
            self.assertFalse(self.filterable(content), content)
            self.assertFalse(self.filterable(content, allow_gifs=True), content)

    def test_other_servers_invites_and_external_links_are_still_filtered(self):
        for content in (
            f"https://stoat.chat/server/{OTHER}/channel/01KWH8PZPVCCGFHEYPWZ78BZP6",
            "join https://stt.gg/abc123",
            "https://stoat.chat/invite/abc123",
            "https://evil.example/server/" + SERVER,
            MESSAGE_LINK + " and https://example.com",
        ):
            self.assertTrue(self.filterable(content), content)

    def test_without_a_server_every_link_counts(self):
        self.assertTrue(ModerationBot._contains_filterable_link(MESSAGE_LINK))

    def test_gifbox_rule_unchanged(self):
        self.assertFalse(self.filterable("https://gifbox.me/view/abc", allow_gifs=True))
        self.assertTrue(self.filterable("https://gifbox.me/view/abc"))

    def test_link_filter_keeps_internal_links(self):
        bot = object.__new__(ModerationBot)
        bot._delete_automatic_message = AsyncMock(return_value=True)
        bot.database = SimpleNamespace(get_link_protection=Mock(return_value=True), get_allow_gifs=Mock(return_value=True), add_event=Mock())
        message = SimpleNamespace(id="m", author_id="u", channel_id="c", content=MESSAGE_LINK + " look",
                                  get_server=Mock(return_value=(SimpleNamespace(), SERVER)), get_author_as_user=Mock(return_value=None))
        self.assertFalse(asyncio.run(bot.handle_link_filter(message)))
        bot._delete_automatic_message.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
