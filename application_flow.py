"""Stoat operations for admission applications; persistence lives in applications.py."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import stoat

from applications import OPEN_STATES, now_iso
from application_embeds import APPLICATION_PRIVACY_VERSION, appearance, embed_title, privacy_embed, question_embeds, submission_embed

logger = logging.getLogger("stoat_moderator")
READ_ONLY = stoat.Permissions(view_channel=True, read_message_history=True).value


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def override_bits(override: Any) -> tuple[int, int]:
    return (override.allow.value, override.deny.value) if override is not None else (0, 0)


def member_rank(server: Any, member: Any) -> float:
    return min((server.roles[r].rank for r in member.role_ids if r in server.roles), default=float("inf"))


def member_channel_bits(server: Any, member: Any, channel: Any, gate: dict[str, Any], *, gated: bool,
                        visible: bool) -> int:
    """Evaluate the gate without a timeout, including roles above the bot."""
    roles = sorted((server.roles[r] for r in member.role_ids if r in server.roles), key=lambda r: r.rank, reverse=True)
    def apply(bits: int, override: Any) -> int:
        allow, deny = override_bits(override)
        return (bits | allow) & ~deny
    bits = 0 if gated else gate["server_default"]
    for role in roles:
        bits = apply(bits, role.permissions)
    category = channel.get_category()
    if category:
        saved = gate.get("categories", {}).get(category.id)
        allow, deny = (saved["allow"], saved["deny"]) if saved else override_bits(category.default_permissions)
        bits = (bits | (0 if gated else allow)) & ~deny
        for role in roles:
            bits = apply(bits, category.role_permissions.get(role.id))
    saved = gate["channels"][channel.id]
    allow = READ_ONLY if visible else 0
    bits = (bits | (allow if gated else saved["allow"])) & ~(saved["deny"] & ~allow if gated else saved["deny"])
    for role in roles:
        bits = apply(bits, channel.role_permissions.get(role.id))
    return bits if bits & stoat.Permissions(view_channel=True).value else 0


class ApplicationFlow:
    def __init__(self, bot: Any):
        self.bot = bot
        self.store = bot.database.applications
        self.locks: dict[str, asyncio.Lock] = {}
        self.last_maintenance = 0.0

    def lock(self, key: str) -> asyncio.Lock:
        return self.locks.setdefault(key, asyncio.Lock())

    async def server(self, server_id: str) -> Any:
        server = await self.bot._resolve_dashboard_server(server_id)
        if server is None:
            raise LookupError("Server is unavailable.")
        return server

    async def member(self, server: Any, app: dict[str, Any]) -> Any | None:
        try:
            member = await server.fetch_member(app["user_id"])
        except stoat.NotFound:
            return None
        # An action for a prior membership must never approve/kick a rejoin.
        return member if iso(member.joined_at) == app["joined_at"] else None

    async def add_roles(self, server: Any, member: Any, role_ids: list[str]) -> Any:
        if not role_ids:
            return member
        joined_at = iso(member.joined_at)
        member = await server.fetch_member(member.id)
        if iso(member.joined_at) != joined_at:
            raise RuntimeError("The member rejoined while roles were being assigned. Review their new application.")
        wanted = list(dict.fromkeys([*member.role_ids, *role_ids]))
        if wanted != member.role_ids:
            if not await self.bot.require_action_permissions(server, "assign_roles"):
                raise PermissionError("Stoatmod needs Assign Roles and a role above the member.")
            await member.edit(roles=wanted)
        confirmed = await server.fetch_member(member.id)
        if iso(confirmed.joined_at) != joined_at:
            raise RuntimeError("The member rejoined while roles were being assigned. Review their new application.")
        if not set(role_ids).issubset(confirmed.role_ids):
            raise RuntimeError("Stoat did not confirm the member roles. Access has not been approved.")
        return confirmed

    async def configure(self, server_id: str) -> None:
        async with self.lock("setup:" + server_id):
            config = self.store.settings(server_id)
            if (not config["enabled"] and not config["access_role_id"]) or config["setup_status"] == "ready":
                return
            server = await self.server(server_id)
            config = self.store.begin_setup(server_id)
            if config is None:
                return
            try:
                bot_member = await server.fetch_member(self.bot.state.my_id)
                permissions = server.permissions_for(bot_member, include_timeout=False)
                for permission in ("manage_permissions", "manage_roles", "assign_roles", "timeout_members", "kick_members"):
                    if not getattr(permissions, permission, False):
                        raise PermissionError(f"Stoatmod needs {permission.replace('_', ' ').title()} to prepare applications.")
                gate = config["gate"]
                if "server_default" not in gate:
                    gate = {"server_default": server.default_permissions.value, "channels": {}, "started_at": now_iso()}
                    self.store.update_setup(server_id, status="configuring", gate=gate)
                channels = [await self.bot.fetch_channel(channel_id) for channel_id in server.channel_ids]
                channels = [c for c in channels if isinstance(c, (stoat.TextChannel, stoat.VoiceChannel))]
                for channel in channels:
                    self.snapshot_channel(server, channel, gate)
                self.store.update_setup(server_id, status="configuring", gate=gate)
                role_id = config["access_role_id"]
                if not role_id:
                    role = await server.create_role(name="Verified member", rank=max((r.rank for r in server.roles.values()), default=0) + 1)
                    role_id = role.id
                    self.store.update_setup(server_id, status="configuring", role_id=role_id)
                await server.set_role_permissions(role_id, allow=stoat.Permissions(gate["server_default"]))
                members = await server.fetch_members()
                elevated = set()
                for member in members:
                    if member.id in {server.owner_id, self.bot.state.my_id} or role_id in member.role_ids:
                        continue
                    if member_rank(server, member) <= member_rank(server, bot_member):
                        for channel in channels:
                            before = member_channel_bits(server, member, channel, gate, gated=False, visible=False)
                            after = member_channel_bits(server, member, channel, gate, gated=True,
                                                        visible=channel.id in config["visible_channel_ids"])
                            if before != after:
                                raise PermissionError(f"Member {member.id} has a role at or above Stoatmod and would lose access. "
                                    "Move Stoatmod above that role, or have the server owner assign Verified member to them, then repair access.")
                        elevated.add(member.id)
                # Give current members the access role BEFORE removing default
                # access. Partial setup can be retried without locking them out.
                for member in members:
                    if member.id == server.owner_id or member.id in elevated:
                        continue
                    app = self.store.current(server_id, member.id)
                    if app and app["joined_at"] == iso(member.joined_at) and app["status"] != "approved":
                        continue
                    await self.add_roles(server, member, [role_id])
                # Remove inherited category grants too; channel defaults alone
                # cannot hide a channel granted by its category. Preserve denies
                # and role overrides so existing staff permissions still work.
                for category_id, saved in gate.get("categories", {}).items():
                    if any(c.get_category() and c.get_category().id == category_id for c in channels):
                        await self.protect_category(server.id, category_id, role_id, saved)
                for channel in channels:
                    await self.protect_channel(server, channel, role_id, gate,
                                               visible=channel.id in config["visible_channel_ids"])
                await server.set_default_permissions(stoat.Permissions.none())
                gate["revision"] = 2
                self.store.update_setup(server_id, status="ready", role_id=role_id, gate=gate)
                await self.bot.send_log(server_id, "✅ Application access updated",
                    "Applicants can read the channels selected in Application settings while awaiting approval. "
                    "Existing members retain access. Review applications in the dashboard.", color="#3BA55D")
            except Exception as exc:
                self.store.update_setup(server_id, status="error", error=str(exc))
                raise

    async def protect_category(self, server_id: str, category_id: str, role_id: str, saved: dict[str, int]) -> None:
        if not saved["allow"]:
            # Legacy Stoat categories are grouping metadata only and have no
            # permission endpoint. There are no inherited grants to remove.
            return
        await self.bot.http.set_category_permissions_for_role(server_id, category_id, role_id,
            allow=stoat.Permissions(saved["allow"]), deny=stoat.Permissions(saved["deny"]))
        confirmed = await self.bot.http.set_default_category_permissions(server_id, category_id,
            allow=stoat.Permissions.none(), deny=stoat.Permissions(saved["deny"]))
        if override_bits(confirmed.default_permissions) != (0, saved["deny"]):
            raise RuntimeError(f"Could not confirm category access for {category_id}.")

    def snapshot_channel(self, server: Any, channel: Any, gate: dict[str, Any]) -> dict[str, Any]:
        category = channel.get_category()
        if category:
            categories = gate.setdefault("categories", {})
            if category.id not in categories:
                allow, deny = override_bits(category.default_permissions)
                categories[category.id] = {"allow": allow, "deny": deny}
        saved = gate["channels"].get(channel.id)
        if saved is None:
            allow, deny = override_bits(channel.default_permissions)
            baseline = gate["server_default"]
            cat_allow, cat_deny = (gate["categories"][category.id]["allow"], gate["categories"][category.id]["deny"]) if category else (0, 0)
            baseline = ((baseline | cat_allow) & ~cat_deny | allow) & ~deny
            saved = {"allow": allow, "deny": deny, "baseline": baseline}
            gate["channels"][channel.id] = saved
            self.store.update_setup(server.id, status=self.store.settings(server.id)["setup_status"], gate=gate)
        return saved

    async def protect_channel(self, server: Any, channel: Any, role_id: str, gate: dict[str, Any], *,
                              visible: bool = False) -> None:
        if not isinstance(channel, (stoat.TextChannel, stoat.VoiceChannel)):
            return
        saved = self.snapshot_channel(server, channel, gate)
        # Lowest-ranked membership role recreates the former default access.
        # Existing higher-ranked channel overrides still decide private access.
        # Explicitly undo any newly granted read access for approved members if
        # this was originally a private channel. Higher roles still override it.
        await channel.set_role_permissions(role_id, allow=stoat.Permissions(saved["allow"]),
                                           deny=stoat.Permissions(saved["deny"] | (READ_ONLY & ~saved["baseline"] if visible else 0)))
        allowed = READ_ONLY if visible else 0
        denied = saved["deny"] & ~allowed
        # A roleless applicant starts with zero server/category grants. Avoid
        # blanket channel denies: those also remove existing staff role grants.
        await channel.set_default_permissions(stoat.PermissionOverride(
            allow=stoat.Permissions(allowed), deny=stoat.Permissions(denied)))
        confirmed = await self.bot.fetch_channel(channel.id)
        allow, deny = override_bits(confirmed.default_permissions)
        if allow != allowed or deny != denied:
            raise RuntimeError(f"Could not confirm applicant access for channel {channel.id}.")

    async def on_channel_create(self, channel: Any) -> None:
        server_id = getattr(channel, "server_id", None)
        if not server_id:
            return
        config = self.store.settings(server_id)
        if config["access_role_id"] and config["gate"].get("server_default") is not None:
            async with self.lock("setup:" + server_id):
                config = self.store.settings(server_id)
                await self.protect_channel(await self.server(server_id), channel, config["access_role_id"], config["gate"],
                                           visible=channel.id in config["visible_channel_ids"])
                category = channel.get_category()
                if category:
                    await self.protect_category(server_id, category.id, config["access_role_id"], config["gate"]["categories"][category.id])

    async def ensure_timeout(self, server: Any, member: Any, app: dict[str, Any]) -> None:
        app = self.store.get(app["id"])
        if not app or app["status"] not in OPEN_STATES:
            return
        target = datetime.fromisoformat(app["expires_at"])
        current = member.timed_out_until
        if current is not None and current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if current is not None and current >= target:
            return
        if not await self.bot.require_action_permissions(server, "timeout_members"):
            raise PermissionError("Stoatmod needs Timeout Members to restrict the applicant.")
        # Store ownership first; retries reconcile the exact timeout value.
        previous = None
        if current is not None and current > datetime.now(timezone.utc):
            _, inherited = self.store.resolve_timeout(app["server_id"], app["user_id"], iso(current))
            _, original = self.store.resolve_timeout(app["server_id"], app["user_id"], app["previous_timeout"])
            moderation = [datetime.fromisoformat(value) for value in (inherited, original) if value]
            previous = iso(max(moderation)) if moderation else None
        self.store.set_timeout(app["id"], iso(target), previous_timeout=previous)
        updated = await member.timeout(target)
        if iso(updated.timed_out_until) != iso(target):
            raise RuntimeError("Stoat did not confirm the application verification timeout.")

    async def on_join(self, server: Any, member: Any, *, screening_required: bool, exempt: bool,
                      user: Any | None = None) -> bool:
        config = self.store.settings(server.id)
        if not config["access_role_id"]:
            return False
        existing = self.store.pending(server.id, member.id)
        if existing and existing["joined_at"] == iso(member.joined_at):
            async with self.lock("user:" + member.id):
                await self.resume(existing)
            return True
        if not config["enabled"] or exempt:
            await self.add_roles(server, member, [config["access_role_id"]])
            return False
        async with self.lock("user:" + member.id):
            app = self.store.create(server.id, member.id, iso(member.joined_at),
                screening_required=screening_required, previous_timeout=iso(member.timed_out_until))
            if app["status"] not in OPEN_STATES:
                return True
            try:
                # Fetch membership once and open the DM concurrently. Both the
                # prompt and timeout use this same membership check; neither can
                # operate on a stale join. Remove access roles before sending.
                member_task = asyncio.create_task(self.prepare_join_member(server, app, config))
                async def restrict():
                    confirmed = await member_task
                    if confirmed is not None:
                        await self.ensure_timeout(server, confirmed, app)
                async def prompt():
                    confirmed, dm = await asyncio.gather(member_task, self.open_dm(app, user=user), return_exceptions=True)
                    if isinstance(confirmed, BaseException):
                        raise confirmed
                    if confirmed is None:
                        return
                    if isinstance(dm, BaseException):
                        raise dm
                    await self.deliver_prompt(app, server, dm=dm)
                results = await asyncio.gather(restrict(), prompt(), return_exceptions=True)
                errors = [str(result) for result in results if isinstance(result, Exception)]
                if errors:
                    raise RuntimeError("; ".join(dict.fromkeys(errors)))
            except Exception as exc:
                delivered = self.store.get(app["id"])
                self.store.update_delivery(app["id"], error=str(exc), prompt_id=delivered["prompt_message_id"],
                    channel_id=delivered["dm_channel_id"], position=delivered["prompt_position"])
                await self.bot.send_log(server.id, "Application needs attention",
                    f"**Applicant:** <@{member.id}>\n**Problem:** {exc}\n"
                    "Check the access setup status and retry from the Applications dashboard.", color="#F59E0B")
            return True

    async def prepare_join_member(self, server: Any, app: dict[str, Any], config: dict[str, Any]) -> Any | None:
        member = await self.member(server, app)
        if member is None:
            self.store.abandon(app["id"])
            return None
        held = set(self.bot.database.list_auto_roles(server.id)) | {config["access_role_id"]}
        kept = [role for role in member.role_ids if role not in held]
        if kept != member.role_ids:
            member = await member.edit(roles=kept)
            if iso(member.joined_at) != app["joined_at"] or any(role in held for role in member.role_ids):
                raise RuntimeError("Stoat did not confirm the applicant's restricted roles.")
        return member

    async def open_dm(self, app: dict[str, Any], *, user: Any | None = None) -> Any:
        async with asyncio.timeout(20):
            user = user or self.bot.get_user(app["user_id"]) or await self.bot.fetch_user(app["user_id"])
            return getattr(user, "dm_channel", None) or await user.open_dm()

    async def send(self, app: dict[str, Any], title: str, description: str, color: str | None = None, *,
                   url: str | None = None, dm: Any | None = None) -> Any:
        async with asyncio.timeout(20):
            dm = dm or await self.open_dm(app)
            payload = {"embeds": [stoat.SendableEmbed(title=embed_title(title), description=description,
                                                    color=color or appearance(app)["color"], url=url)]}
            if url:
                # Some Stoat clients render Markdown embed links as plain text.
                # Keep the actual URL in message content as a clickable/copyable
                # fallback, and also make the embed title link to verification.
                payload["content"] = url
            try:
                sent = await dm.send(**payload)
            except stoat.NotFound:
                # A deleted cached DM can be reopened without slowing healthy
                # conversations with an extra open-DM request for every prompt.
                user = self.bot.get_user(app["user_id"]) or await self.bot.fetch_user(app["user_id"])
                dm = await user.open_dm()
                sent = await dm.send(**payload)
        return sent

    async def resume(self, app: dict[str, Any], *, force: bool = False) -> None:
        app = self.store.get(app["id"])
        if not app or app["status"] not in OPEN_STATES or app["expires_at"] <= now_iso():
            return
        server = await self.server(app["server_id"])
        member = await self.member(server, app)
        if member is None:
            self.store.abandon(app["id"])
            return
        await self.ensure_timeout(server, member, app)
        await self.deliver_prompt(app, server, force=force)

    async def deliver_prompt(self, app: dict[str, Any], server: Any, *, force: bool = False,
                             dm: Any | None = None) -> None:
        app = self.store.get(app["id"])
        if not app or app["status"] not in OPEN_STATES or app["expires_at"] <= now_iso():
            return
        if app["status"] == "submitted":
            await self.send(app, **submission_embed(app, server.name, app["expires_at"]), dm=dm)
            return
        if app["prompt_message_id"] and not force:
            return
        if not app["privacy_accepted_at"] or app["privacy_version"] != APPLICATION_PRIVACY_VERSION:
            url = self.bot.moderation_settings.dashboard_url.rstrip("/") + "/privacy#applications"
            sent = await self.send(app, **privacy_embed(app, server.name, url), url=url, dm=dm)
            position = -2
        elif app["status"] == "screening":
            existing = self.bot.database.get_captcha_challenge(app["server_id"], app["user_id"])
            token = secrets.token_urlsafe(32)
            challenge = self.bot.database.set_web_verification_challenge(app["server_id"], app["user_id"],
                hashlib.sha256(token.encode()).hexdigest(), app["expires_at"])
            if existing and existing.failure_count:
                with self.store.connection:
                    self.store.connection.execute("UPDATE captcha_challenges SET failure_count=? WHERE server_id=? AND user_id=?",
                        (existing.failure_count, app["server_id"], app["user_id"]))
            url = self.bot.moderation_settings.dashboard_url.rstrip("/") + "/verify?token=" + token
            sent = await self.send(app, "🛡️ Verify before applying", f"**{server.name}** requires a browser CAPTCHA "
                f"before the application.\n\n🔗 Open this verification link:\n{url}\n\n"
                "Return to this DM for your questions after the checks pass. "
                f"Your application deadline is **{app['expires_at']}**. Use `~application` to resume.", url=url, dm=dm)
            self.bot.database.add_event(server_id=app["server_id"], event_type="join_captcha_issued", user_id=app["user_id"],
                details={"expires_at": challenge.expires_at, "method": "website", "application_id": app["id"]})
            position = -1
        else:
            position = len(app["answers"])
            for embed in question_embeds(app, server.name, position):
                sent = await self.send(app, **embed, dm=dm)
        self.store.update_delivery(app["id"], error=None, prompt_id=sent.id, channel_id=sent.channel_id, position=position)
        if not app["prompt_message_id"] and position <= 0:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(app["joined_at"])).total_seconds()
            logger.info("application_first_prompt_delivered application_id=%s join_to_dm_seconds=%.3f", app["id"], elapsed)

    async def handle_dm(self, message: Any) -> bool:
        if message.get_server()[1]:
            return False
        content = message.content.strip()
        command = content.split(maxsplit=1)[0].lower() if content else ""
        if command.startswith(("~", "/", "!")) and command != "~application":
            return False
        async with self.lock("user:" + message.author_id):
            apps = self.store.user_applications(message.author_id)
            if not apps:
                return False
            parts = content.split()
            if command == "~application" and len(parts) > 1:
                try:
                    self.store.select(message.author_id, parts[1].upper())
                except ValueError as exc:
                    await message.channel.send(str(exc))
                    return True
            selected = self.store.selected(message.author_id)
            if len(apps) == 1:
                selected = apps[0]
                self.store.select(message.author_id, selected["id"])
            # Explicit reply targets take precedence over the selected server.
            replies = getattr(message, "replies", None) or []
            replied_app = next((app for app in apps if app["prompt_message_id"] in replies), None)
            if replied_app:
                selected = replied_app
            if selected is None or (command == "~application" and len(parts) == 1 and len(apps) > 1):
                lines = []
                for app in apps:
                    name = self.bot.database.get_dashboard_overview(app["server_id"])["server"]["name"]
                    lines.append(f"**{name}**: `~application {app['id']}` ({app['status']})")
                await message.channel.send(embeds=[stoat.SendableEmbed(title="📋 Choose your application",
                    description="\n".join(lines)[:1900], color="#5865F2")])
                return True
            if command == "~application":
                await self.resume(selected, force=True)
                return True
            if not selected["privacy_accepted_at"] or selected["privacy_version"] != APPLICATION_PRIVACY_VERSION:
                if selected["prompt_position"] != -2 or not selected["prompt_message_id"]:
                    await self.resume(selected, force=True)
                elif (not replies or replied_app) and str(message.id) > str(selected["prompt_message_id"]):
                    if content.casefold() not in {"agree", "i agree"}:
                        await message.channel.send("Read the application privacy agreement, then reply **I agree** to continue. Your reply has not been saved as an answer.")
                    else:
                        try:
                            selected = self.store.accept_privacy(selected["id"], message.author_id, APPLICATION_PRIVACY_VERSION, agreed=True)
                        except ValueError as exc:
                            await message.channel.send(str(exc))
                        else:
                            await self.resume(selected)
                return True
            if selected["status"] != "answering":
                if selected["status"] == "screening":
                    await message.channel.send("Complete the verification link first. Use `~application` to request it again.")
                else:
                    await self.resume(selected)
                return True
            if replies and not replied_app:
                await message.channel.send("That question is no longer active. Use `~application` to see your current question.")
                return True
            if not selected["prompt_message_id"]:
                await self.resume(selected)
                return True
            # Ignore messages created before this question was issued, including
            # duplicate gateway delivery or rapid replies to the previous one.
            if str(message.id) <= str(selected["prompt_message_id"]):
                return True
            try:
                updated = self.store.answer(selected["id"], message.author_id, selected["prompt_position"], message.id, content)
            except ValueError as exc:
                await message.channel.send(str(exc))
                return True
            if updated["status"] == "submitted":
                # The durable submission action extends the timeout and sends
                # confirmation/notifications. It also survives a crash here.
                return True
            await self.resume(updated)
            return True

    async def submitted(self, app: dict[str, Any]) -> None:
        # A delayed submission worker must not put the review timeout back
        # after approval has removed it. Use the same lock as resolve/resume.
        async with self.lock("user:" + app["user_id"]):
            app = self.store.get(app["id"])
            if app:
                await self._submitted(app)

    async def _submitted(self, app: dict[str, Any]) -> None:
        if app["status"] != "submitted":
            return
        if app["expires_at"] <= now_iso():
            self.store.expire()
            return
        server = await self.server(app["server_id"])
        member = await self.member(server, app)
        if member is None:
            self.store.abandon(app["id"])
            return
        await self.ensure_timeout(server, member, app)
        app = self.store.get(app["id"])
        if not app or app["status"] != "submitted":
            return
        delivery_failures = []
        if "applicant" not in app["notifications"]:
            try:
                await self.resume(app)
                self.store.mark_notified(app["id"], "applicant")
            except Exception:
                delivery_failures.append("Applicant submission confirmation could not be delivered.")
        url = self.bot.moderation_settings.dashboard_url.rstrip("/") + "/dashboard?view=applications&application=" + app["id"]
        description = f"**Applicant:** <@{app['user_id']}> (`{app['user_id']}`)\n" \
            f"**Deadline:** {app['expires_at']}\n[Check the application in the dashboard]({url}).\n" \
            f"You can also approve in this server with `~approve {app['user_id']}`."
        if "log" not in app["notifications"]:
            try:
                await self.bot.send_log(app["server_id"], "📥 New application awaiting review", description, color="#5865F2", raise_on_error=True)
                self.store.mark_notified(app["id"], "log")
            except Exception:
                delivery_failures.append("The application notice could not be posted to the logs channel.")
        for user_id in self.store.notification_recipients(app["server_id"]):
            if user_id in app["notifications"]:
                continue
            delivered = await self.bot._send_user_dm(user_id, f"📥 New applicant · {server.name}", description,
                server_id=app["server_id"], color="#5865F2")
            if delivered:
                self.store.mark_notified(app["id"], user_id)
            else:
                delivery_failures.append(f"Admin DM could not be delivered to {user_id}.")
        if delivery_failures:
            with self.store.connection:
                self.store.connection.execute("UPDATE join_applications SET error=? WHERE id=?", (" ".join(delivery_failures), app["id"]))
            raise RuntimeError(" ".join(delivery_failures))
        with self.store.connection:
            self.store.connection.execute("UPDATE join_applications SET error=NULL WHERE id=?", (app["id"],))

    async def resolve(self, app: dict[str, Any]) -> None:
        async with self.lock("user:" + app["user_id"]):
            app = self.store.get(app["id"])
            if not app or app["status"] not in {"approved", "denied", "expired"} or app["enforcement_status"] == "applied":
                return
            try:
                server = await self.server(app["server_id"])
                member = await self.member(server, app)
                if member is None:
                    self.store.abandon(app["id"])
                    return
                if app["status"] == "approved":
                    if not app["screening_passed"] or len(app["answers"]) != len(app["questions"]):
                        raise RuntimeError("Required verification or answers are missing.")
                    roles = self.bot.database.list_auto_roles(app["server_id"])
                    # Grant ordinary auto-roles while the timeout still holds;
                    # access is granted only after every role is confirmed.
                    member = await self.add_roles(server, member, roles)
                    member = await self.add_roles(server, member, [app["access_role_id"]])
                    owned, restore = self.store.resolve_timeout(app["server_id"], app["user_id"], iso(member.timed_out_until))
                    if owned:
                        previous = datetime.fromisoformat(restore) if restore else None
                        if previous is not None and previous <= datetime.now(timezone.utc):
                            previous = None
                        await member.timeout(previous)
                        confirmed = await self.member(server, app)
                        if confirmed is None or iso(confirmed.timed_out_until) != iso(previous):
                            raise RuntimeError("Roles were assigned, but the verification timeout could not be removed.")
                else:
                    if not await self.bot.require_action_permissions(server, "kick_members"):
                        raise PermissionError("Stoatmod needs Kick Members to remove this applicant.")
                    await self.bot._kick_member_with_reason(member, app["server_id"], app["user_id"], "Admission application denied",
                        actor_id=app["reviewer_id"] or self.bot.state.my_id)
                self.bot.database.remove_captcha_challenge(app["server_id"], app["user_id"])
                task = self.bot._captcha_tasks.pop((app["server_id"], app["user_id"]), None)
                if task:
                    task.cancel()
                self.store.finish(app["id"])
            except Exception as exc:
                self.store.finish(app["id"], error=str(exc))
                await self.bot.send_log(app["server_id"], "Application action needs attention",
                    f"**Applicant:** <@{app['user_id']}>\n**Problem:** {exc}\nRetry from the Applications dashboard.", color="#F59E0B")
                raise

    async def notify_decision(self, app: dict[str, Any]) -> None:
        app = self.store.get(app["id"])
        if not app:
            return
        if app["enforcement_status"] != "applied" or app["status"] not in {"approved", "denied", "expired"}:
            return
        server = await self.server(app["server_id"])
        color = "#3BA55D" if app["status"] == "approved" else "#ED4245"
        failures = []
        if "decision_event" not in app["notifications"]:
            with self.store.connection:
                self.store.connection.execute("BEGIN IMMEDIATE")
                if not self.store.get(app["id"]):
                    return
                self.bot.database.add_event(server_id=app["server_id"], event_type="application_" + app["status"],
                    user_id=app["user_id"], actor_id=app["reviewer_id"], details={"application_id": app["id"], "reason": app["reason"]})
            self.store.mark_notified(app["id"], "decision_event")
        if "decision_dm" not in app["notifications"]:
            outcome = "Your application was approved. Your member roles have been assigned and your verification restrictions removed." \
                if app["status"] == "approved" else f"You have been removed from the server.\n**Reason:** {app['reason']}"
            if app["status"] == "approved":
                member = await self.member(server, app)
                if member and member.timed_out_until and member.timed_out_until > datetime.now(timezone.utc):
                    owned, _restore = self.store.resolve_timeout(app["server_id"], app["user_id"], iso(member.timed_out_until))
                    if owned:
                        problem = "The application timeout is still active. Retry approval to finish removing it."
                        self.store.finish(app["id"], error=problem)
                        raise RuntimeError(problem)
                    outcome += f" An existing moderation timeout remains until **{iso(member.timed_out_until)}**."
            icon = "✅" if app["status"] == "approved" else "❌" if app["status"] == "denied" else "⌛"
            delivered = await self.bot._send_user_dm(app["user_id"], f"{icon} Application {app['status']} · {server.name}",
                outcome, server_id=app["server_id"], color=color)
            if delivered:
                self.store.mark_notified(app["id"], "decision_dm")
            else:
                failures.append("Applicant decision DM could not be delivered.")
        if "decision_log" not in app["notifications"]:
            try:
                await self.bot.send_log(app["server_id"], "Application " + app["status"],
                    f"**Applicant:** <@{app['user_id']}>\n**Reviewer:** {app['reviewer_id'] or 'Automatic verification'}\n"
                    f"**Reason:** {app['reason'] or 'Approved'}", color=color, raise_on_error=True)
                self.store.mark_notified(app["id"], "decision_log")
            except Exception:
                failures.append("Decision log could not be delivered.")
        with self.store.connection:
            self.store.connection.execute("UPDATE join_applications SET error=? WHERE id=?", (" ".join(failures) or None, app["id"]))
        if failures:
            raise RuntimeError(" ".join(failures))

    async def action(self, action: dict[str, Any]) -> dict[str, Any]:
        if action["action"] == "configure_applications":
            await self.configure(action["server_id"])
            return {"configured": True}
        app = self.store.get(str(action["payload"].get("application_id", "")), action["server_id"])
        if app is None:
            return {"skipped": "Application no longer exists"}
        if action["action"] == "resolve_application":
            await self.resolve(app)
        elif action["action"] == "notify_application_decision":
            await self.notify_decision(app)
        elif action["action"] == "application_submitted":
            await self.submitted(app)
        else:
            async with self.lock("user:" + app["user_id"]):
                await self.resume(app, force=bool(action["payload"].get("force")))
        return {"application_id": app["id"]}

    async def maintenance(self) -> None:
        if time.monotonic() - self.last_maintenance < 60:
            return
        self.last_maintenance = time.monotonic()
        # Erase first: a failed kick must never extend the privacy deadline.
        for denied in self.store.prune():
            try:
                async with self.lock("user:" + denied["user_id"]):
                    server = await self.server(denied["server_id"])
                    member = await self.member(server, denied)
                    if member is not None and await self.bot.require_action_permissions(server, "kick_members"):
                        async with asyncio.timeout(15):
                            await member.kick()
            except Exception:
                # No application content or identifiers survive as a retry record.
                logger.warning("expired_application_removal_failed; access was not granted")
        # Only undelivered questions need startup recovery. Explicitly failed
        # deliveries are visible in the dashboard and can be retried there/DM.
        rows = self.store.connection.execute("""SELECT id FROM join_applications
            WHERE status IN ('screening','answering') AND prompt_message_id IS NULL AND error IS NULL
            AND expires_at>? LIMIT 20""", (now_iso(),)).fetchall()
        for row in rows:
            app = self.store.get(row["id"])
            if app is None:
                continue
            try:
                async with self.lock("user:" + app["user_id"]):
                    await self.resume(app)
            except Exception as exc:
                self.store.update_delivery(app["id"], error=str(exc))
                logger.exception("application_recovery_failed application_id=%s", app["id"])
