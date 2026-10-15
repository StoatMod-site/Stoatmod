"""Apply reaction choices using confirmed member state and durable grant ownership."""
from __future__ import annotations

import asyncio
from collections import defaultdict
import contextlib
import logging
import time

import stoat
from stoat.cache import CacheContextType, UndefinedCacheContext

from application_flow import iso, member_rank
from reaction_roles import emoji_key, panel_embed

logger = logging.getLogger("stoat_moderator")
# A member the bot fetched (or saw join/update on the gateway) stays authoritative
# this long: later changes arrive as gateway events that update the same cache.
# Every gateway reconnect clears the trust, because events may have been missed.
MEMBER_TRUST_SECONDS = 300
PRIVILEGED = stoat.Permissions(manage_channels=True, manage_server=True, manage_permissions=True,
    manage_roles=True, manage_customization=True, kick_members=True, ban_members=True,
    timeout_members=True, assign_roles=True, manage_nicknames=True, remove_avatars=True,
    manage_messages=True, manage_webhooks=True, use_masquerade=True,
    mute_members=True, deafen_members=True, move_members=True).value


class PanelLock:
    """Exclusive for panel-wide work (publish, delete, sweeps); shared for one member's click.

    Clicks from different members run in parallel, while any waiting exclusive
    holder blocks later clicks so panel-wide work cannot be starved."""
    def __init__(self):
        self._gate = asyncio.Lock()
        self._readers = 0
        self._idle = asyncio.Event()
        self._idle.set()

    async def acquire(self):
        await self._gate.acquire()
        try:
            await self._idle.wait()
        except BaseException:
            self._gate.release()
            raise

    def release(self):
        self._gate.release()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *exc):
        self.release()

    @contextlib.asynccontextmanager
    async def shared(self):
        async with self._gate:
            self._readers += 1
            self._idle.clear()
        try:
            yield
        finally:
            self._readers -= 1
            if self._readers == 0:
                self._idle.set()


class ReactionRoleFlow:
    def __init__(self, bot):
        self.bot = bot
        self.store = bot.database.reaction_roles
        self.locks = {}
        self.user_locks = {}
        self.task = None
        self.actions_task = None
        self.runs_actions = False
        self.pending_reactions = {}
        self.member_checked = {}
        self.snapshots = {}

    async def snapshot(self, channel, panel, since):
        """The panel message as read after `since`. Concurrent callers share one read.

        A read that started after a reaction event arrived must include that
        reaction, so the clicks of a burst can verify against the same message."""
        entry = self.snapshots.get(panel["id"])
        if entry is None or entry[0] <= since:
            task = asyncio.ensure_future(channel.fetch_message(panel["message_id"]))
            entry = (time.monotonic(), task)
            self.snapshots[panel["id"]] = entry
            def forget(done, panel_id=panel["id"], entry=entry):
                if not done.cancelled() and done.exception() is not None and self.snapshots.get(panel_id) is entry:
                    del self.snapshots[panel_id]  # Never reuse a failed read.
            task.add_done_callback(forget)
        return await asyncio.shield(entry[1])

    def lock(self, panel_id):
        return self.locks.setdefault(panel_id, PanelLock())

    @contextlib.asynccontextmanager
    async def user_lock(self, panel_id, user_id):
        """Serialise one member's clicks on a panel without blocking other members."""
        key = (panel_id, user_id)
        entry = self.user_locks.setdefault(key, [asyncio.Lock(), 0])
        entry[1] += 1
        try:
            async with entry[0]:
                yield
        finally:
            entry[1] -= 1
            if entry[1] == 0 and self.user_locks.get(key) is entry:
                del self.user_locks[key]

    def connection_reset(self):
        """Gateway (re)connected: events may have been missed, so refetch members before trusting them."""
        self.member_checked.clear()

    def trust_member(self, server_id, user_id):
        """The gateway just delivered this member's complete state (join or full update)."""
        self.member_checked[(server_id, user_id)] = time.monotonic()

    def start(self):
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self.maintenance(), name="reaction-role-recovery")
            self.bot._tasks.add(self.task)
            self.task.add_done_callback(self.bot._tasks.discard)
        if self.actions_task is None or self.actions_task.done():
            self.runs_actions = True  # The general dashboard loop leaves these actions to this runner.
            self.actions_task = asyncio.create_task(self.run_actions(), name="reaction-role-actions")
            self.bot._tasks.add(self.actions_task)
            self.actions_task.add_done_callback(self.bot._tasks.discard)

    async def run_actions(self):
        """Run dashboard reaction-role actions as soon as they are queued.

        The general dashboard loop works through every action type one at a time and
        waits 5 seconds between batches; here a save starts within a fraction of a
        second, and different servers never wait for each other."""
        database = self.bot.database
        while not self.bot._closing:
            try:
                if database.has_pending_dashboard_action("reaction_roles") and await self.run_pending_actions():
                    continue
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("reaction_role_actions_failed")
            await asyncio.sleep(0.4)

    async def run_pending_actions(self):
        claimed = self.bot.database.claim_dashboard_actions(only="reaction_roles", limit=20)
        groups = defaultdict(list)
        for action in claimed:
            groups[action["server_id"]].append(action)
        results = await asyncio.gather(*(self.run_server_actions(items) for items in groups.values()), return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                logger.error("reaction_role_server_actions_failed error=%r", result)
        return len(claimed)

    async def run_server_actions(self, actions):
        """One server's actions keep their order; other servers run alongside."""
        for action in actions:
            success, result = False, {}
            try:
                result = await self.action(action)
                success = True
            except Exception as exc:
                result = {"error": str(exc)}
                logger.exception("dashboard_action_failed action_id=%s action=%s", action["id"], action["action"])
            self.bot.database.finish_dashboard_action(action["id"], success=success, result=result,
                **({"claim_token": action["claim_token"]} if action.get("claim_token") else {}))

    async def context(self, server_id):
        # The gateway maintains role, member and channel permission updates.
        # Refetching every channel for every click exhausts the API buckets.
        get_server = getattr(self.bot, "get_server", None)
        server = get_server(server_id) if get_server else None
        if server is None:
            server = await self.bot.fetch_server(server_id)
        get_member = getattr(server, "get_member", None)
        bot_member = get_member(self.bot.state.my_id) if get_member else None
        if bot_member is None:
            bot_member = await server.fetch_member(self.bot.state.my_id)
        semaphore = asyncio.Semaphore(5)
        async def fetch(channel_id):
            get_channel = getattr(self.bot, "get_channel", None)
            cached = get_channel(channel_id) if get_channel else None
            if cached is not None:
                return cached
            async with semaphore:
                return await self.bot.fetch_channel(channel_id)
        channels = await asyncio.gather(*(fetch(cid) for cid in server.channel_ids))
        return server, bot_member, channels

    def role_error(self, server, bot_member, channels, role_id):
        role = server.roles.get(role_id)
        if role is None: return "Role no longer exists."
        if role_id == self.bot.database.applications.settings(server.id)["access_role_id"]:
            return "Application access roles cannot be self-assigned."
        if role.permissions.allow.value & PRIVILEGED:
            return "Staff permissions cannot be offered for self-selection."
        for channel in channels:
            override = getattr(channel,"role_permissions",{}).get(role_id)
            if override and override.allow.value & PRIVILEGED:
                return "This role has staff permissions in a channel."
        if member_rank(server,bot_member) >= role.rank:
            return "Move Stoatmod above this role."
        if not server.permissions_for(bot_member).assign_roles:
            return "Stoatmod needs Assign Roles."
        return None

    async def directory(self, server_id):
        server, bot_member, channels = await self.context(server_id)
        emojis = await server.fetch_emojis()
        data = {"channels":[{"id":c.id,"name":c.name} for c in channels if isinstance(c,stoat.TextChannel)],
            "roles":[{"id":r.id,"name":r.name,"assignable":not self.role_error(server,bot_member,channels,r.id),
                      "reason":self.role_error(server,bot_member,channels,r.id)} for r in server.roles.values()],
            "emojis":[{"id":e.id,"name":e.name} for e in emojis]}
        self.store.set_directory(server_id,data)
        return data

    async def action(self, action):
        payload = action["payload"]
        if payload["operation"]=="directory":
            await self.directory(action["server_id"])
            return {"refreshed":True}
        panel_id = payload["panel_id"]
        async with self.lock(panel_id):
            panel = self.store.get(panel_id,action["server_id"])
            if not panel or panel["revision"] != payload["revision"] or panel["status"]=="deleted":
                return {"skipped":"superseded"}
            try:
                server = await self.bot.fetch_server(action["server_id"])
                actor = await server.fetch_member(action["actor_id"])
                if not self.bot.database.dashboard_user_has_access(server.id,action["actor_id"],owner_id=server.owner_id,
                        manage_server=server.permissions_for(actor,include_timeout=False).manage_server):
                    raise PermissionError("The reviewer no longer has dashboard access to this server.")
                await self.publish(panel,payload)
            except Exception as exc:
                self.store.update(panel_id,status="error",error=str(exc))
                raise
        return {"panel_id":panel_id,"status":self.store.get(panel_id)["status"]}

    async def publish(self, panel, payload):
        operation=payload["operation"]
        channel_id=panel["published_channel_id"] or panel["config"]["channel_id"]
        channel=await self.bot.fetch_channel(channel_id)
        if getattr(channel,"server_id",None)!=panel["server_id"]:
            raise PermissionError("The message channel does not belong to this server.")
        message=None
        if panel["message_id"]:
            try: message=await channel.fetch_message(panel["message_id"])
            except stoat.NotFound:
                if operation=="pause": raise ValueError("The message was deleted. Publish it again.")
        if operation=="delete":
            if message: await message.delete()
            users={c["user_id"] for c in self.store.choices(panel["id"])}
            users.update(r[0] for r in self.store.connection.execute("SELECT user_id FROM reaction_role_pending_members WHERE panel_id=?",(panel["id"],)))
            for user in users:
                async with self.bot.application_flow.lock("user:"+user):
                    with self.store.connection:
                        if not payload.get("cleanup"):
                            self.store.connection.execute("UPDATE reaction_role_grants SET owned=0 WHERE server_id=? AND user_id=? AND role_id IN (SELECT role_id FROM reaction_role_choices WHERE panel_id=? AND user_id=?)",
                                (panel["server_id"],user,panel["id"],user))
                        self.store.select(panel,user,"",[])
                    await self.apply_member(panel["server_id"],user)
            self.store.update(panel["id"],status="deleted",error=None)
            return
        server, bot_member, channels=await self.context(panel["server_id"])
        for option in panel["config"]["options"]:
            error=self.role_error(server,bot_member,channels,option["role_id"])
            if error: raise PermissionError(error)
        custom=None  # Only look up server emojis when the panel uses one.
        for option in panel["config"]["options"]:
            if len(option["emoji"])==26 and option["emoji"].isascii():
                if custom is None: custom={e.id for e in await server.fetch_emojis()}
                if option["emoji"] not in custom:
                    raise ValueError("A configured server emoji no longer exists.")
        paused=operation=="pause"
        embed=stoat.SendableEmbed(**panel_embed(panel["config"],paused=paused))
        if message:
            await message.edit(embeds=[embed])
        else:
            nonce=f"rr-{panel['id']}-{panel['revision']}"
            # Recover a successfully sent message if the process stopped before saving its ID.
            history=await channel.history(limit=100)
            message=next((m for m in history if m.nonce==nonce and m.author_id==self.bot.state.my_id),None)
            if message is None:
                message=await channel.send(embeds=[embed],nonce=nonce)
        # Stoat supports editing embeds, but its message edit endpoint cannot
        # change interactions. Seed normal reactions so emoji options stay editable.
        self.store.update(panel["id"],message_id=message.id,published_channel_id=channel_id)
        if not paused:
            valid={emoji_key(o["emoji"]) for o in panel["config"]["options"]}
            for emoji in list(message.reactions):
                if emoji_key(emoji) not in valid:
                    await message.unreact(emoji,remove_all=True)
            for option in panel["config"]["options"]:
                if self.bot.state.my_id not in message.reactions.get(option["emoji"],[]):
                    await message.react(option["emoji"])
        self.store.update(panel["id"],message_id=message.id,published_channel_id=channel_id,status="paused" if paused else "active",error=None)
        if not paused: await self.sync(self.store.get(panel["id"]))

    def admission_blocked(self, server_id, member):
        app=self.bot.database.applications.current(server_id,member.id)
        if app and app["joined_at"]==iso(member.joined_at) and (app["status"]!="approved" or app["enforcement_status"]!="applied"):
            return True
        return self.bot.database.get_captcha_challenge(server_id,member.id) is not None

    def remember_member(self, server_id, member):
        cache=getattr(self.bot.state,"cache",None)
        if cache is not None:
            cache.store_server_member(member,UndefinedCacheContext(type=CacheContextType.undefined))
        self.member_checked[(server_id,member.id)]=time.monotonic()
        if len(self.member_checked)>4096:
            cutoff=time.monotonic()-MEMBER_TRUST_SECONDS
            self.member_checked={k:v for k,v in self.member_checked.items() if v>cutoff}

    async def member(self, server, user_id, *, passive=False):
        """The member as the gateway last saw it. Passive readers (sweeps) accept any cached
        member and re-verify before writing; active ones need a recently confirmed member."""
        get_member=getattr(server,"get_member",None)
        cached=get_member(user_id) if get_member else None
        if cached is not None:
            if passive or time.monotonic()-self.member_checked.get((server.id,user_id),-1000)<MEMBER_TRUST_SECONDS:
                return cached  # Gateway updates/removals remain authoritative.
        member=await server.fetch_member(user_id)
        self.remember_member(server.id,member)
        return member

    def forget_pending(self, server_id, user_id):
        with self.store.connection:
            self.store.connection.execute("DELETE FROM reaction_role_pending_members WHERE server_id=? AND user_id=?",(server_id,user_id))

    async def apply_member(self, server_id, user_id, context=None, *, member=None, adopt_roles=(), verified=True):
        """Reconcile one member's roles. Returns the member as last confirmed (None if they left).

        verified=False means `member` came from the gateway cache without a fresh read: it is only
        trusted for deciding that nothing needs to change, and re-read before any write."""
        server, bot_member, channels=context or await self.context(server_id)
        if member is None:
            try: member=await self.member(server,user_id)
            except stoat.NotFound:
                self.forget_pending(server_id,user_id)
                return None
        joined=iso(member.joined_at)
        desired=self.store.desired(server_id,user_id,joined)
        blocked=self.admission_blocked(server_id,member)
        if blocked: desired=set()
        # Prevent a role changed to staff privileges since publication being granted.
        for role_id in desired:
            error=self.role_error(server,bot_member,channels,role_id)
            if error: raise PermissionError(error)
        all_grants=self.store.grants(server_id,user_id)
        grants={g["role_id"]:g for g in all_grants if g["joined_at"]==joined}
        original=set(member.role_ids)
        if any(role_id not in server.roles for role_id in original):
            raise RuntimeError("The member's role list is incomplete. Refresh the server and retry.")
        # An explicit add/remove opts this particular role into reaction control,
        # including a role the member already had. Passive sync does not adopt it.
        adopted=set(adopt_roles) & (original|desired)
        owned={r for r,g in grants.items() if g["owned"]}|adopted
        removed=owned-desired
        target=(original-removed)|desired
        if not verified and target!=original:
            try: fresh=await server.fetch_member(user_id)
            except stoat.NotFound:
                self.forget_pending(server_id,user_id)
                return None
            self.remember_member(server_id,fresh)
            return await self.apply_member(server_id,user_id,(server,bot_member,channels),member=fresh,adopt_roles=adopt_roles)
        if (target==original and not adopted and not (desired-grants.keys()) and not (grants.keys()-desired)
                and len(all_grants)==len(grants)
                and not self.store.connection.execute("SELECT 1 FROM reaction_role_pending_members WHERE server_id=? AND user_id=?",(server_id,user_id)).fetchone()):
            return member  # Nothing to change or to record.
        confirmed=member
        if target!=original:
            if member_rank(server,bot_member)>=member_rank(server,member) or user_id==server.owner_id:
                raise PermissionError("Stoatmod must be above this member to manage their roles.")
            if not server.permissions_for(bot_member).assign_roles:
                raise PermissionError("Stoatmod needs Assign Roles.")
        # Journal ownership before the API call, so retries cannot claim existing roles.
        with self.store.connection:
            self.store.connection.execute("DELETE FROM reaction_role_grants WHERE server_id=? AND user_id=? AND joined_at<>?",(server_id,user_id,joined))
            for role_id in desired-grants.keys():
                self.store.connection.execute("INSERT INTO reaction_role_grants VALUES(?,?,?,?,?)",(server_id,user_id,role_id,joined,int(role_id not in original)))
            for role_id in adopted:
                self.store.connection.execute("INSERT INTO reaction_role_grants VALUES(?,?,?,?,1) ON CONFLICT(server_id,user_id,role_id) DO UPDATE SET joined_at=excluded.joined_at,owned=1",(server_id,user_id,role_id,joined))
        if target!=original:
            # An uncertain write or confirmation must force a fresh read on retry.
            self.member_checked.pop((server_id,user_id),None)
            confirmed=await member.edit(roles=sorted(target))
            # Stoat returns the updated Member in the PATCH response. Avoid a
            # second GET in the same five-requests-per-ten-seconds server bucket.
            if confirmed is None or not hasattr(confirmed,"role_ids"):
                confirmed=await server.fetch_member(user_id)
            if iso(confirmed.joined_at)!=joined or set(confirmed.role_ids)!=target:
                raise RuntimeError("Stoat did not confirm the role change. Retry after checking this member.")
            self.remember_member(server_id,confirmed)
            self.bot.database.add_event(server_id=server_id,event_type="reaction_roles_updated",user_id=user_id,
                details={"added":sorted(target-original),"removed":sorted(original-target)})
        with self.store.connection:
            for role_id in (grants.keys()|adopted)-desired:
                self.store.connection.execute("DELETE FROM reaction_role_grants WHERE server_id=? AND user_id=? AND role_id=?",(server_id,user_id,role_id))
            self.store.connection.execute("DELETE FROM reaction_role_pending_members WHERE server_id=? AND user_id=?",(server_id,user_id))
        return confirmed

    async def remove_user_reaction(self, channel, message, emoji, user):
        # Match normalized emoji for selection, but send the exact stored key
        # back to Stoat (including Unicode variation selectors).
        for actual, users in list(message.reactions.items()):
            if emoji_key(actual) != emoji_key(emoji) or user not in users:
                continue
            try:
                await message.unreact(actual, user=user)
            except stoat.NotFound:
                # A concurrent unreact is success only when confirmed absent.
                # A deleted message or a still-present reaction remains an error.
                current = await channel.fetch_message(message.id)
                if user in current.reactions.get(actual, []):
                    raise

    async def sync(self, panel, *, preferred_user=None, preferred_emoji=None, event_token=None, adopt_roles=(), member_hint=None, since=None):
        since=time.monotonic() if since is None else since
        get_channel = getattr(self.bot, "get_channel", None)
        channel = get_channel(panel["published_channel_id"]) if get_channel else None
        if channel is None:
            channel=await self.bot.fetch_channel(panel["published_channel_id"])
        if getattr(channel,"server_id",None)!=panel["server_id"]: raise PermissionError("Server channel mismatch.")
        message,context=await asyncio.gather(self.snapshot(channel,panel,since),self.context(panel["server_id"]))
        server=context[0]
        passive=preferred_user is None  # Sweeps read the gateway cache and re-verify only before a write.
        options=panel["config"]["options"]
        reactions=defaultdict(set)
        for key, users in message.reactions.items():
            reactions[emoji_key(key)].update(users)
        users={u for o in options for u in reactions.get(emoji_key(o["emoji"]),set())}
        users.update(c["user_id"] for c in self.store.choices(panel["id"]))
        if preferred_user is not None: users={preferred_user}
        failures=[]
        for user in users-{self.bot.state.my_id}:
            try:
                async with self.bot.application_flow.lock("user:"+user):
                    account=self.bot.get_user(user) or await self.bot.fetch_user(user)
                    if member_hint is not None and member_hint.id==user: member=member_hint
                    else:
                        try: member=await self.member(server,user,passive=passive)
                        except stoat.NotFound: continue
                    verified=not passive or time.monotonic()-self.member_checked.get((server.id,user),-1000)<MEMBER_TRUST_SECONDS
                    chosen=[o for o in options if user in reactions.get(emoji_key(o["emoji"]),set())]
                    remove=[]
                    blocked=account.bot is not None or self.admission_blocked(panel["server_id"],member)
                    if blocked:
                        # Do not let a reaction made before approval become a delayed grant.
                        remove=chosen
                        chosen=[]
                    elif panel["config"]["mode"]=="keep":
                        previous={c["emoji"] for c in self.store.choices(panel["id"],user) if c["joined_at"]==iso(member.joined_at)}
                        chosen=[o for o in options if o in chosen or emoji_key(o["emoji"]) in previous]
                    elif panel["config"]["mode"]=="single" and len(chosen)>1:
                        previous=[c["emoji"] for c in self.store.choices(panel["id"],user) if c["joined_at"]==iso(member.joined_at)]
                        key=emoji_key(preferred_emoji) if preferred_emoji and user==preferred_user else (previous[-1] if previous else "")
                        keep=next((o for o in chosen if emoji_key(o["emoji"])==key),chosen[0])
                        remove=[o for o in chosen if o!=keep]
                        chosen=[keep]
                    joined=iso(member.joined_at)
                    stored=self.store.choices(panel["id"],user)
                    unchanged=(passive and len(stored)==len(chosen) and {c["emoji"] for c in stored}=={emoji_key(o["emoji"]) for o in chosen}
                               and all(c["joined_at"]==joined for c in stored))
                    if not unchanged: self.store.select(panel,user,joined,chosen)
                    # Apply the choice before cosmetic reaction cleanup. The
                    # member was read under the shared per-user lock.
                    try:
                        await self.apply_member(panel["server_id"],user,context,member=member,verified=verified,
                            adopt_roles=adopt_roles if user==preferred_user else ())
                    except Exception:
                        if unchanged: self.store.select(panel,user,joined,chosen)  # Keep the retry durable.
                        raise
                    for option in remove:
                        pending=self.pending_reactions.get((panel["id"],user))
                        if not blocked and pending and pending[0] is not event_token and pending[1] and emoji_key(pending[1])==emoji_key(option["emoji"]):
                            continue  # A newer click will be reconciled next.
                        await self.remove_user_reaction(channel,message,option["emoji"],user)
            except Exception as exc:
                failures.append(f"Member {user}: {exc}")
        if failures:
            raise RuntimeError("; ".join(failures[:3]))

    async def quick(self, panel, user_id, deltas, adopt_roles):
        """Apply one member's click at once from the event and their stored choices.

        The message is not read first: sync() verifies the result against it right
        afterwards and corrects anything the events alone could not know."""
        context=await self.context(panel["server_id"])
        server=context[0]
        options=panel["config"]["options"]
        known={emoji_key(o["emoji"]) for o in options}
        mode=panel["config"]["mode"]
        async with self.bot.application_flow.lock("user:"+user_id):
            account=self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
            try: member=await self.member(server,user_id)
            except stoat.NotFound: return None
            joined=iso(member.joined_at)
            keys=[c["emoji"] for c in self.store.choices(panel["id"],user_id) if c["joined_at"]==joined]
            for key,added in deltas:
                if key not in known: continue
                if added:
                    if mode=="single": keys=[key]
                    elif key not in keys: keys.append(key)
                elif mode!="keep" and key in keys:
                    keys.remove(key)
            chosen=[o for o in options if emoji_key(o["emoji"]) in keys]
            if account.bot is not None or self.admission_blocked(panel["server_id"],member): chosen=[]
            self.store.select(panel,user_id,joined,chosen)
            return await self.apply_member(panel["server_id"],user_id,context,member=member,adopt_roles=adopt_roles)

    async def reaction(self,event,*,added):
        arrived=time.monotonic()
        panel=self.store.by_message(event.message_id)
        if not panel: return False
        if event.user_id==self.bot.state.my_id: return True
        if emoji_key(event.emoji) not in {emoji_key(o["emoji"]) for o in panel["config"]["options"]}:
            return True
        key=(panel["id"],event.user_id)
        previous=self.pending_reactions.get(key)
        preferred=event.emoji if added else (previous[1] if previous else None)
        if not added and preferred and emoji_key(preferred)==emoji_key(event.emoji):
            preferred=None
        touched=set(previous[2]) if previous else set()
        touched.update(o["role_id"] for o in panel["config"]["options"] if emoji_key(o["emoji"])==emoji_key(event.emoji))
        # Clicks superseded while queued still count: their changes replay in order.
        deltas=(list(previous[3]) if previous else [])+[(emoji_key(event.emoji),added)]
        token=object()
        self.pending_reactions[key]=(token,preferred,touched,deltas)
        try:
            async with self.lock(panel["id"]).shared(), self.user_lock(panel["id"],event.user_id):
                if self.pending_reactions.get(key,(None,None))[0] is not token:
                    return True  # A later queued event supersedes this request.
                panel=self.store.by_message(event.message_id)
                if not panel: return True
                member=await self.quick(panel,event.user_id,deltas,touched)
                await self.sync(panel,preferred_user=event.user_id,preferred_emoji=preferred,event_token=token,adopt_roles=touched,member_hint=member,since=arrived)
                self.store.update(panel["id"],error=None)
        except Exception as exc:
            self.store.update(panel["id"],error=str(exc))
            logger.warning("reaction_role_change_failed panel_id=%s error=%s",panel["id"],exc)
        finally:
            if self.pending_reactions.get(key,(None,None))[0] is token:
                self.pending_reactions.pop(key,None)
        return True

    async def cleared(self,event):
        panel=self.store.by_message(event.message_id)
        if panel is None: return
        async with self.lock(panel["id"]):
            current=self.store.by_message(event.message_id)
            if current is None: return
            try:
                await self.sync(current)
            except Exception as exc:
                self.store.update(panel["id"],error=str(exc))

    async def maintenance(self):
        checked={}
        while not self.bot._closing:
            pending=list(self.store.connection.execute("SELECT * FROM reaction_role_pending_members LIMIT 50"))
            for row in pending:
                try:
                    async with self.bot.application_flow.lock("user:"+row["user_id"]):
                        await self.apply_member(row["server_id"],row["user_id"])
                except Exception as exc:
                    self.store.update(row["panel_id"],error=str(exc))
            for panel in self.store.panels():
                if panel["status"]!="active" or time.monotonic()-checked.get(panel["id"],-1000)<60: continue
                try:
                    async with self.lock(panel["id"]):
                        current=self.store.get(panel["id"])
                        if current["status"]!="active": continue
                        await self.sync(current)
                        self.store.update(panel["id"],error=None)
                except Exception as exc:
                    self.store.update(panel["id"],error=str(exc))
                checked[panel["id"]]=time.monotonic()
                await asyncio.sleep(0.25)
            await asyncio.sleep(5)
