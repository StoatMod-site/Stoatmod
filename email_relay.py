from __future__ import annotations

import asyncio
import hashlib
import html
from html.parser import HTMLParser
import imaplib
import logging
import smtplib
from dataclasses import dataclass
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, make_msgid, parsedate_to_datetime
import re
import ssl
from urllib.parse import urlparse

import aiohttp

from database import ModerationDatabase


logger = logging.getLogger("stoat_moderator.email_relay")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WHITESPACE = re.compile(r"[ \t]+")
BLANK_LINES = re.compile(r"\n{3,}")
DANGEROUS_MENTION = re.compile(r"@(?=(?:everyone|online)\b)", re.IGNORECASE)
ANGLE_MENTION = re.compile(r"<@(?=[!&]?[A-Z0-9]{20,})", re.IGNORECASE)


@dataclass(frozen=True)
class EmailRelayConfig:
    webhook_url: str
    recipient: str
    imap_host: str
    imap_port: int
    imap_username: str
    imap_password: str
    imap_mailbox: str
    imap_ca_file: str
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    poll_seconds: int
    additional_recipients: tuple[str, ...] = ()

    @property
    def recipients(self) -> tuple[str, ...]:
        values = (self.recipient, *self.additional_recipients)
        return tuple(dict.fromkeys(value.strip().casefold() for value in values if value.strip()))


@dataclass(frozen=True)
class RelayEmail:
    message_key: str
    message_id: str | None
    thread_key: str
    in_reply_to: str | None
    references: tuple[str, ...]
    sender: str
    recipient: str
    subject: str
    date: str
    body: str
    attachments: tuple[str, ...]


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hidden_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "head"}:
            self.hidden_depth += 1
        elif not self.hidden_depth and tag in {"br", "p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "head"} and self.hidden_depth:
            self.hidden_depth -= 1
        elif not self.hidden_depth and tag in {"p", "div", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self.parts.append(data)

    def text(self) -> str:
        return "".join(self.parts)


class ProtonEmailRelay:
    def __init__(self, database: ModerationDatabase, config: EmailRelayConfig) -> None:
        # The webhook only mirrors inbound mail into a Stoat channel. Without one,
        # mail is still recorded for the owner dashboard and replies still send.
        if config.webhook_url:
            parsed_webhook = urlparse(config.webhook_url)
            if parsed_webhook.scheme != "https" or parsed_webhook.hostname != "stoat.chat":
                raise ValueError("EMAIL_RELAY_WEBHOOK_URL must be an HTTPS stoat.chat webhook")
        self.database = database
        self.config = config

    async def run(self) -> None:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            while True:
                try:
                    try:
                        # This method reads and updates the bot's SQLite connection,
                        # which must remain on the thread where it was created.
                        self._send_pending_replies()
                    except Exception:
                        # Sending dashboard replies is independent from receiving
                        # mail. A broken SMTP/reply queue must not prevent inbound
                        # messages from reaching the webhook or owner dashboard.
                        logger.exception("email_reply_processing_failed")
                    messages = await asyncio.to_thread(self._fetch_messages)
                    for message in messages:
                        self.database.record_email_message(
                            message_key=message.message_key,
                            thread_key=message.thread_key,
                            message_id=message.message_id,
                            direction="inbound",
                            sender=message.sender,
                            recipient=message.recipient,
                            subject=message.subject,
                            body=message.body,
                            sent_at=message.date,
                            in_reply_to=message.in_reply_to,
                            references=list(message.references),
                            status="received",
                            mailbox_address=message.recipient,
                        )
                    baselined_recipients: set[str] = set()
                    for recipient in self.config.recipients:
                        if self.database.is_email_relay_initialized(
                            recipient, self.config.imap_mailbox
                        ):
                            continue
                        self.database.initialize_email_relay(
                            recipient,
                            [
                                (message.message_key, message.message_id)
                                for message in messages
                                if message.recipient == recipient
                            ],
                            self.config.imap_mailbox,
                        )
                        baselined_recipients.add(recipient)
                    if baselined_recipients:
                        logger.info(
                            "email_relay_initialized recipients=%s existing_messages=%s",
                            ",".join(sorted(baselined_recipients)),
                            len(messages),
                        )
                    await self._deliver_new_messages(session, messages, baselined_recipients)
                    self._update_heartbeat(True)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._update_heartbeat(False)
                    logger.exception("email_relay_poll_failed")
                await asyncio.sleep(self.config.poll_seconds)

    async def _deliver_new_messages(self, session, messages, baselined_recipients) -> None:
        if not self.config.webhook_url:
            return  # Webhook mirroring is switched off.
        for message in messages:
            if message.recipient in baselined_recipients:
                continue
            if self.database.has_email_webhook_delivery(message.message_key):
                continue
            if await self._deliver(session, message):
                self.database.record_email_webhook_delivery(
                    message.message_key,
                    message.message_id,
                    message.recipient,
                )

    def _update_heartbeat(self, connected: bool) -> None:
        try:
            self.database.update_system_heartbeat(
                "email",
                {
                    "connected": connected,
                    "mailbox": self.config.imap_mailbox,
                    "recipients": list(self.config.recipients),
                },
            )
        except Exception:
            logger.exception("email_relay_heartbeat_failed")

    def _fetch_messages(self) -> list[RelayEmail]:
        context = ssl.create_default_context(cafile=self.config.imap_ca_file)
        client = imaplib.IMAP4(
            self.config.imap_host,
            self.config.imap_port,
            timeout=30,
        )
        try:
            client.starttls(ssl_context=context)
            client.login(
                self.config.imap_username,
                self.config.imap_password,
            )
            status, _data = client.select(self.config.imap_mailbox, readonly=True)
            if status != "OK":
                raise RuntimeError("Proton Bridge mailbox could not be selected")
            # Search recipient headers on the IMAP server instead of examining only
            # the final UIDs in a potentially large mailbox. During Bridge's first
            # synchronization, UID order does not necessarily correspond to message
            # date, which could otherwise cause newly received mail to be missed.
            matching_uids: set[bytes] = set()
            for recipient in self.config.recipients:
                for header in ("To", "Cc", "Bcc", "Delivered-To", "X-Original-To"):
                    status, search_data = client.uid(
                        "SEARCH",
                        None,
                        "HEADER",
                        header,
                        recipient,
                    )
                    if status != "OK" or not search_data:
                        raise RuntimeError("Proton Bridge mailbox search failed")
                    matching_uids.update(search_data[0].split())
            uids = sorted(matching_uids, key=int)[-100:]
            messages: list[RelayEmail] = []
            for uid in uids:
                status, fetch_data = client.uid("FETCH", uid, "(BODY.PEEK[])")
                if status != "OK" or not fetch_data:
                    continue
                raw = next(
                    (
                        item[1]
                        for item in fetch_data
                        if isinstance(item, tuple)
                        and len(item) > 1
                        and isinstance(item[1], bytes)
                    ),
                    None,
                )
                if raw is None:
                    continue
                for recipient in self.config.recipients:
                    parsed = self._parse_message(raw, recipient=recipient)
                    if parsed is not None:
                        messages.append(parsed)
            return messages
        finally:
            try:
                client.logout()
            except Exception:
                client.shutdown()

    def _parse_message(
        self, raw: bytes, *, recipient: str | None = None
    ) -> RelayEmail | None:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        recipients = {
            address.lower()
            for _name, address in getaddresses(
                [
                    str(message.get(name, ""))
                    for name in (
                        "to",
                        "cc",
                        "bcc",
                        "delivered-to",
                        "x-original-to",
                    )
                    if message.get(name)
                ]
            )
            if address
        }
        target_recipient = recipient.strip().casefold() if recipient else next(
            (item for item in self.config.recipients if item in recipients), ""
        )
        if not target_recipient or target_recipient not in recipients:
            return None

        message_id = self._header(message, "message-id") or None
        in_reply_to = self._header(message, "in-reply-to") or None
        references = tuple(
            re.findall(r"<[^>]+>", self._header(message, "references"))
        )
        root_reference = (
            references[0]
            if references
            else in_reply_to
            or message_id
            or "|".join(
                (
                    self._header(message, "from").casefold(),
                    re.sub(
                        r"^(?:(?:re|fw|fwd):\s*)+",
                        "",
                        self._header(message, "subject").casefold(),
                    ),
                )
            )
        )
        # Keep the primary owner mailbox's historical keys stable. Secondary
        # aliases include their address so one message can safely exist in
        # more than one inbox without colliding.
        thread_source = root_reference.strip().casefold()
        if target_recipient != self.config.recipient.strip().casefold():
            thread_source = f"{target_recipient}|{thread_source}"
        thread_key = hashlib.sha256(
            thread_source.encode("utf-8", "replace")
        ).hexdigest()
        message_key_source = (
            f"message-id:{message_id.strip().lower()}" if message_id else raw
        )
        if isinstance(message_key_source, str):
            message_key_source = message_key_source.encode("utf-8", "replace")
        if target_recipient != self.config.recipient.strip().casefold():
            message_key_source = (
                target_recipient.encode("utf-8") + b"|" + message_key_source
            )
        message_key = hashlib.sha256(message_key_source).hexdigest()
        body, attachments = self._content(message)
        raw_date = self._header(message, "date")
        try:
            sent_at = parsedate_to_datetime(raw_date).isoformat(timespec="seconds")
        except (TypeError, ValueError, OverflowError):
            sent_at = raw_date or "Unknown date"
        return RelayEmail(
            message_key=message_key,
            message_id=message_id,
            thread_key=thread_key,
            in_reply_to=in_reply_to,
            references=references,
            sender=self._header(message, "from") or "Unknown sender",
            recipient=target_recipient,
            subject=self._header(message, "subject") or "No subject",
            date=sent_at,
            body=body or "(No readable text body)",
            attachments=tuple(attachments),
        )

    @staticmethod
    def _header(message: EmailMessage, name: str) -> str:
        value = message.get(name, "")
        try:
            return str(make_header(decode_header(str(value)))).strip()
        except Exception:
            return str(value).strip()

    def _content(self, message: EmailMessage) -> tuple[str, list[str]]:
        plain_parts: list[str] = []
        html_parts: list[str] = []
        attachments: list[str] = []
        parts = message.walk() if message.is_multipart() else (message,)
        for part in parts:
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = part.get_content_disposition()
            if filename or disposition == "attachment":
                attachments.append(self._clean(filename or "unnamed attachment", 120))
                continue
            content_type = part.get_content_type()
            if content_type not in {"text/plain", "text/html"}:
                continue
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode(part.get_content_charset() or "utf-8", "replace")
            if not isinstance(content, str):
                content = content.decode("utf-8", "replace")
            if content_type == "text/plain":
                plain_parts.append(content)
            else:
                parser = _HTMLTextExtractor()
                parser.feed(content)
                html_parts.append(parser.text())
        body = "\n\n".join(plain_parts or html_parts)
        return self._clean(body, 1300), attachments[:10]

    @staticmethod
    def _clean(value: str, limit: int) -> str:
        value = CONTROL_CHARACTERS.sub("", value.replace("\r\n", "\n").replace("\r", "\n"))
        value = "\n".join(WHITESPACE.sub(" ", line).strip() for line in value.split("\n"))
        value = BLANK_LINES.sub("\n\n", value).strip()
        value = DANGEROUS_MENTION.sub("@\u200b", value)
        value = ANGLE_MENTION.sub("<@\u200b", value)
        if len(value) > limit:
            value = value[: max(0, limit - 1)].rstrip() + "…"
        return value

    async def _deliver(
        self, session: aiohttp.ClientSession, message: RelayEmail
    ) -> bool:
        attachments = (
            ", ".join(f"`{name}`" for name in message.attachments)
            if message.attachments
            else "None"
        )
        description = (
            f"**From:** {self._clean(message.sender, 220)}\n"
            f"**To:** `{message.recipient}`\n"
            f"**Date:** {self._clean(message.date, 120)}\n"
            f"**Attachments:** {attachments}\n\n"
            f"{message.body}"
        )
        payload = {
            "embeds": [
                {
                    "title": self._clean(message.subject, 100),
                    "description": description[:1800],
                    "colour": "#111111",
                }
            ],
            "mention_everyone": False,
            "mention_online": False,
        }
        try:
            async with session.post(
                self.config.webhook_url,
                json=payload,
                headers={"User-Agent": "Stoatmod-Proton-Relay/1.0"},
            ) as response:
                if 200 <= response.status < 300:
                    logger.info(
                        "email_relay_delivered message_key=%s sender=%s",
                        message.message_key[:12],
                        self._clean(message.sender, 120),
                    )
                    return True
                response_text = await response.text()
                logger.error(
                    "email_relay_webhook_failed status=%s response=%s",
                    response.status,
                    self._clean(response_text, 300),
                )
        except Exception:
            logger.exception("email_relay_webhook_request_failed")
        return False

    def _send_pending_replies(self) -> None:
        replies = self.database.claim_email_replies()
        if not replies:
            return
        context = ssl.create_default_context(cafile=self.config.imap_ca_file)
        try:
            client = smtplib.SMTP(
                self.config.smtp_host, self.config.smtp_port, timeout=30
            )
            client.starttls(context=context)
            client.login(self.config.smtp_username, self.config.smtp_password)
        except Exception as exc:
            for reply in replies:
                self.database.complete_email_reply(reply["id"], error=str(exc))
            logger.exception("email_reply_smtp_connection_failed")
            return
        try:
            for reply in replies:
                try:
                    from_address = str(reply.get("from_address") or "").casefold()
                    if from_address not in self.config.recipients:
                        raise ValueError("Queued email sender is not configured for this relay")
                    message = EmailMessage()
                    message_id = make_msgid(domain="modstoat.site")
                    message["From"] = from_address
                    message["To"] = reply["to_address"]
                    cc_addresses = [
                        str(address) for address in reply.get("cc", []) if address
                    ]
                    bcc_addresses = [
                        str(address) for address in reply.get("bcc", []) if address
                    ]
                    if cc_addresses:
                        message["Cc"] = ", ".join(cc_addresses)
                    message["Subject"] = reply["subject"]
                    message["Message-ID"] = message_id
                    if reply.get("in_reply_to"):
                        message["In-Reply-To"] = reply["in_reply_to"]
                    if reply.get("references"):
                        message["References"] = " ".join(reply["references"])
                    message.set_content(reply["body"])
                    message.add_alternative(
                        self._formatted_email_html(reply["body"]),
                        subtype="html",
                    )
                    for attachment in reply.get("attachments", []):
                        content_type = str(
                            attachment.get("content_type")
                            or "application/octet-stream"
                        )
                        maintype, separator, subtype = content_type.partition("/")
                        if not separator or not maintype or not subtype:
                            maintype, subtype = "application", "octet-stream"
                        message.add_attachment(
                            bytes(attachment["content"]),
                            maintype=maintype,
                            subtype=subtype,
                            filename=str(attachment["filename"]),
                        )
                    # BCC recipients belong only in the SMTP envelope. Omitting a
                    # Bcc header prevents them from being disclosed to recipients.
                    envelope_recipients = list(
                        dict.fromkeys(
                            [reply["to_address"], *cc_addresses, *bcc_addresses]
                        )
                    )
                    client.send_message(message, to_addrs=envelope_recipients)
                    message_key_source = f"message-id:{message_id.casefold()}".encode()
                    root_reference = message_id.strip().casefold()
                    thread_source = root_reference
                    if from_address != self.config.recipient.strip().casefold():
                        message_key_source = (
                            from_address.encode("utf-8") + b"|" + message_key_source
                        )
                        thread_source = f"{from_address}|{root_reference}"
                    message_key = hashlib.sha256(message_key_source).hexdigest()
                    canonical_thread_key = (
                        hashlib.sha256(thread_source.encode("utf-8")).hexdigest()
                        if not reply.get("in_reply_to")
                        else str(reply["thread_key"])
                    )
                    self.database.complete_email_reply(
                        reply["id"],
                        message_key=message_key,
                        message_id=message_id,
                        sender=from_address,
                        thread_key=canonical_thread_key,
                    )
                    logger.info(
                        "email_reply_sent reply_id=%s thread=%s",
                        reply["id"],
                        reply["thread_key"][:12],
                    )
                except Exception as exc:
                    self.database.complete_email_reply(
                        reply["id"], error=str(exc)
                    )
                    logger.exception("email_reply_failed reply_id=%s", reply["id"])
        finally:
            try:
                client.quit()
            except Exception:
                client.close()

    @staticmethod
    def _formatted_email_html(body: str) -> str:
        def inline(value: str) -> str:
            value = html.escape(value)
            value = re.sub(
                r"\[([^\]]+)\]\((https?://[^\s)]+)\)",
                r'<a href="\2" rel="noreferrer">\1</a>',
                value,
            )
            value = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", value)
            value = re.sub(r"(?<!\*)\*([^*\n]+)\*", r"<em>\1</em>", value)
            value = re.sub(r"_([^_\n]+)_", r"<em>\1</em>", value)
            return value

        blocks: list[str] = []
        list_items: list[str] = []
        paragraph: list[str] = []

        def flush_paragraph() -> None:
            if paragraph:
                blocks.append(f"<p>{'<br>'.join(paragraph)}</p>")
                paragraph.clear()

        def flush_list() -> None:
            if list_items:
                blocks.append("<ul>" + "".join(list_items) + "</ul>")
                list_items.clear()

        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith(("- ", "* ")):
                flush_paragraph()
                list_items.append(f"<li>{inline(stripped[2:])}</li>")
            elif not stripped:
                flush_paragraph()
                flush_list()
            else:
                flush_list()
                paragraph.append(inline(line))
        flush_paragraph()
        flush_list()
        content = "".join(blocks) or "<p></p>"
        return (
            '<div style="font-family:Arial,sans-serif;font-size:15px;'
            'line-height:1.6;color:#111">'
            + content
            + "</div>"
        )
