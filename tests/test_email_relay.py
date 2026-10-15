import asyncio
import hashlib
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from database import ModerationDatabase
from email_relay import EmailRelayConfig, ProtonEmailRelay


class _Response:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def text(self) -> str:
        return "ok"


class _Session:
    def __init__(self) -> None:
        self.url = ""
        self.kwargs = {}

    def post(self, url: str, **kwargs):
        self.url = url
        self.kwargs = kwargs
        return _Response()


class ProtonEmailRelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = ModerationDatabase(
            Path(self.directory.name, "relay.db")
        )
        self.config = EmailRelayConfig(
            webhook_url="https://stoat.chat/api/webhooks/id/token",
            recipient="admin@modstoat.site",
            imap_host="127.0.0.1",
            imap_port=1143,
            imap_username="bridge-user",
            imap_password="bridge-password",
            imap_mailbox="stoatmod",
            imap_ca_file="bridge.pem",
            smtp_host="127.0.0.1",
            smtp_port=1025,
            smtp_username="bridge-user",
            smtp_password="bridge-password",
            poll_seconds=30,
        )
        self.relay = ProtonEmailRelay(self.database, self.config)

    def tearDown(self) -> None:
        self.database.close()
        self.directory.cleanup()

    def test_only_target_recipient_is_parsed_and_content_is_sanitized(self) -> None:
        raw = (
            b"From: Sender <sender@example.com>\r\n"
            b"To: admin@modstoat.site\r\n"
            b"Subject: Support request\r\n"
            b"Message-ID: <message-one@example.com>\r\n"
            b"Date: Tue, 11 Aug 2026 21:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Hello @everyone, I need help."
        )

        message = self.relay._parse_message(raw)

        self.assertIsNotNone(message)
        assert message is not None
        self.assertEqual(message.subject, "Support request")
        self.assertTrue(message.thread_key)
        self.assertIn("@\u200beveryone", message.body)
        self.assertNotIn("@everyone", message.body)
        self.assertIsNone(
            self.relay._parse_message(
                raw.replace(b"admin@modstoat.site", b"other@example.com")
            )
        )

    def test_webhook_delivery_uses_embed_and_can_be_deduplicated(self) -> None:
        raw = (
            b"From: sender@example.com\r\n"
            b"X-Original-To: admin@modstoat.site\r\n"
            b"Subject: Account help\r\n"
            b"Message-ID: <message-two@example.com>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please help with my account."
        )
        message = self.relay._parse_message(raw)
        assert message is not None
        session = _Session()

        delivered = asyncio.run(self.relay._deliver(session, message))

        self.assertTrue(delivered)
        self.assertEqual(session.url, self.config.webhook_url)
        embed = session.kwargs["json"]["embeds"][0]
        self.assertEqual(embed["title"], "Account help")
        self.assertIn("sender@example.com", embed["description"])
        self.assertFalse(session.kwargs["json"]["mention_everyone"])

        self.database.record_email_webhook_delivery(
            message.message_key, message.message_id, self.config.recipient
        )
        self.assertTrue(
            self.database.has_email_webhook_delivery(message.message_key)
        )

    def test_rejects_non_stoat_webhook_destinations(self) -> None:
        invalid = EmailRelayConfig(
            **{
                **self.config.__dict__,
                "webhook_url": "https://example.com/collect",
            }
        )
        with self.assertRaises(ValueError):
            ProtonEmailRelay(self.database, invalid)

    def test_first_mailbox_scan_is_baselined_without_reposting_history(self) -> None:
        self.assertFalse(
            self.database.is_email_relay_initialized(self.config.recipient)
        )

        self.database.initialize_email_relay(
            self.config.recipient,
            [("existing-key", "<existing@example.com>")],
        )

        self.assertTrue(
            self.database.is_email_relay_initialized(self.config.recipient)
        )
        self.assertTrue(
            self.database.has_email_webhook_delivery("existing-key")
        )

    def test_formatted_email_html_is_safe_and_supports_basic_formatting(self) -> None:
        rendered = self.relay._formatted_email_html(
            "Hello **team** and *friends*\n\n- First item\n- Second item\n"
            "[Support](https://modstoat.site) <script>"
        )
        self.assertIn("<strong>team</strong>", rendered)
        self.assertIn("<em>friends</em>", rendered)
        self.assertIn("<ul><li>First item</li><li>Second item</li></ul>", rendered)
        self.assertIn('href="https://modstoat.site"', rendered)
        self.assertNotIn("<script>", rendered)

    def test_support_compose_and_reply_share_the_canonical_thread(self) -> None:
        support = "support@modstoat.site"
        relay = ProtonEmailRelay(
            self.database,
            EmailRelayConfig(
                **{
                    **self.config.__dict__,
                    "additional_recipients": (support,),
                }
            ),
        )
        queued = self.database.queue_owner_new_email(
            "person@example.com",
            "Account help",
            "Here is the support response.",
            "staffer@modstoat.site",
            cc_addresses=["copy@example.com"],
            bcc_addresses=["blind@example.com"],
            mailbox_address=support,
        )
        sent_messages = []
        sent_envelopes = []

        class FakeSMTP:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            def starttls(self, *, context) -> None:
                self.context = context

            def login(self, _username, _password) -> None:
                pass

            def send_message(self, message, *, to_addrs=None, **_kwargs) -> None:
                sent_messages.append(message)
                sent_envelopes.append(list(to_addrs or []))

            def quit(self) -> None:
                pass

            def close(self) -> None:
                pass

        message_id = "<support-compose@modstoat.site>"
        with (
            patch("email_relay.ssl.create_default_context", return_value=object()),
            patch("email_relay.smtplib.SMTP", FakeSMTP),
            patch("email_relay.make_msgid", return_value=message_id),
        ):
            relay._send_pending_replies()

        self.assertEqual(len(sent_messages), 1)
        self.assertEqual(sent_messages[0]["From"], support)
        self.assertEqual(sent_messages[0]["Cc"], "copy@example.com")
        self.assertIsNone(sent_messages[0]["Bcc"])
        self.assertEqual(
            sent_envelopes[0],
            ["person@example.com", "copy@example.com", "blind@example.com"],
        )
        canonical = hashlib.sha256(
            f"{support}|{message_id.casefold()}".encode()
        ).hexdigest()
        self.assertNotEqual(queued["thread_key"], canonical)
        stored = self.database.get_owner_email_thread(
            canonical, mailbox_address=support
        )
        self.assertIsNotNone(stored)
        self.assertEqual(stored["messages"][0]["message_id"], message_id)
        self.assertEqual(stored["messages"][0]["cc"], ["copy@example.com"])
        self.assertEqual(stored["messages"][0]["bcc"], ["blind@example.com"])

        raw_reply = (
            b"From: Person <person@example.com>\r\n"
            b"To: support@modstoat.site\r\n"
            b"Subject: Re: Account help\r\n"
            b"Message-ID: <support-reply@example.com>\r\n"
            b"In-Reply-To: <support-compose@modstoat.site>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Thank you."
        )
        parsed = relay._parse_message(raw_reply, recipient=support)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.thread_key, canonical)


if __name__ == "__main__":
    unittest.main()


class WebhookOptionalTests(ProtonEmailRelayTests):
    def make_message(self):
        raw = (
            b"From: sender@example.com\r\n"
            b"X-Original-To: admin@modstoat.site\r\n"
            b"Subject: Help\r\n"
            b"Message-ID: <no-webhook@example.com>\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Please help."
        )
        message = self.relay._parse_message(raw)
        assert message is not None
        return message

    def test_without_a_webhook_nothing_is_posted_and_the_relay_still_builds(self) -> None:
        config = EmailRelayConfig(**{**self.config.__dict__, "webhook_url": ""})
        relay = ProtonEmailRelay(self.database, config)
        message = self.make_message()
        session = _Session()

        asyncio.run(relay._deliver_new_messages(session, [message], set()))

        self.assertEqual(session.url, "")
        self.assertFalse(self.database.has_email_webhook_delivery(message.message_key))

    def test_with_a_webhook_new_messages_are_delivered_once(self) -> None:
        message = self.make_message()
        session = _Session()

        asyncio.run(self.relay._deliver_new_messages(session, [message], set()))
        self.assertEqual(session.url, self.config.webhook_url)
        self.assertTrue(self.database.has_email_webhook_delivery(message.message_key))

        session.url = ""
        asyncio.run(self.relay._deliver_new_messages(session, [message], set()))
        self.assertEqual(session.url, "")  # already delivered

    def test_baselined_recipients_are_not_reposted(self) -> None:
        message = self.make_message()
        session = _Session()
        asyncio.run(self.relay._deliver_new_messages(session, [message], {message.recipient}))
        self.assertEqual(session.url, "")
