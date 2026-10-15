import asyncio
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock

import stoat
from database import ModerationDatabase
from application_flow import ApplicationFlow, iso
from reaction_role_flow import ReactionRoleFlow, PanelLock, MEMBER_TRUST_SECONDS
from reaction_roles import panel_embed


class ReactionRoleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=ModerationDatabase(Path(self.temp.name)/"test.db")
        self.store=self.db.reaction_roles
        self.directory={"channels":[{"id":"channel","name":"Roles"}],"roles":[
            {"id":"gaming","name":"Gaming","assignable":True,"reason":None},
            {"id":"art","name":"Art","assignable":True,"reason":None},
            {"id":"staff","name":"Staff","assignable":False,"reason":"Privileged"}],"emojis":[]}
        self.store.set_directory("server",self.directory)
        self.config={"title":"Choose roles","description":"Your interests","footer":"","color":"#5865F2","channel_id":"channel","mode":"multiple", "options":[
            {"emoji":"🎮","role_id":"gaming","label":"Gaming"},{"emoji":"🎨","role_id":"art","label":"Art"}]}
        self.panel=self.store.save("server","admin",self.config)
        self.store.update(self.panel["id"],status="active",message_id="message",published_channel_id="channel")
        self.panel=self.store.get(self.panel["id"])
        self.joined=datetime.now(timezone.utc)
        self.member=NS(id="user",role_ids=[],joined_at=self.joined,timed_out_until=None)
        async def edit(**kwargs): self.member.role_ids=kwargs["roles"];return self.member
        self.member.edit=AsyncMock(side_effect=edit)
        roles={r:NS(id=r,name=r,rank=i+2,permissions=NS(allow=stoat.Permissions())) for i,r in enumerate(["gaming","art","staff","unrelated"])}
        roles["bot"]=NS(id="bot",rank=0,permissions=NS(allow=stoat.Permissions.all()))
        self.bot_member=NS(id="bot",role_ids=["bot"])
        self.server=NS(id="server",owner_id="admin",roles=roles,channel_ids=["channel"],
            permissions_for=Mock(return_value=stoat.Permissions(assign_roles=True,manage_server=True)))
        async def fetch_member(user): return self.bot_member if user=="bot" else self.member
        self.server.fetch_member=AsyncMock(side_effect=fetch_member)
        self.server.fetch_emojis=AsyncMock(return_value=[])
        self.message=NS(id="message",author_id="bot",nonce=None,reactions={})
        async def unreact(emoji,*,user=None,remove_all=False): self.message.reactions[emoji]=[] if remove_all else [u for u in self.message.reactions.get(emoji,[]) if u!=user]
        self.message.unreact=AsyncMock(side_effect=unreact)
        async def edit_message(*,embeds): return self.message
        async def seed(emoji): self.message.reactions.setdefault(emoji,[]).append("bot")
        self.message.edit=AsyncMock(side_effect=edit_message);self.message.delete=AsyncMock()
        self.message.react=AsyncMock(side_effect=seed)
        self.channel=NS(id="channel",server_id="server",role_permissions={},name="Roles",fetch_message=AsyncMock(return_value=self.message),history=AsyncMock(return_value=[]),send=AsyncMock(return_value=self.message))
        self.bot=NS(database=self.db,state=NS(my_id="bot"),fetch_server=AsyncMock(return_value=self.server),fetch_channel=AsyncMock(return_value=self.channel),
            get_user=Mock(return_value=NS(bot=None)),fetch_user=AsyncMock(return_value=NS(bot=None)),_closing=False,_tasks=set())
        self.bot.application_flow=ApplicationFlow(self.bot)
        self.flow=ReactionRoleFlow(self.bot)
        self.context=(self.server,self.bot_member,[self.channel])
        self.flow.context=AsyncMock(return_value=self.context)

    async def asyncTearDown(self):
        self.db.close();self.temp.cleanup()

    async def react(self,emoji="🎮",added=True):
        self.message.reactions[emoji]=["user"] if added else []
        return await self.flow.reaction(NS(message_id="message",user_id="user",emoji=emoji),added=added)

    def mode(self,value):
        self.panel["config"]["mode"]=value
        with self.store.connection:
            import json
            self.store.connection.execute("UPDATE reaction_role_panels SET config_json=? WHERE id=?",(json.dumps(self.panel["config"]),self.panel["id"]))

    async def test_toggle_adds_and_removes_only_panel_role(self):
        self.member.role_ids=["unrelated"]
        await self.react();self.assertEqual(set(self.member.role_ids),{"unrelated","gaming"})
        await self.react(added=False);self.assertEqual(self.member.role_ids,["unrelated"])

    async def test_explicit_toggle_removes_preexisting_role_and_preserves_unrelated(self):
        self.member.role_ids=["gaming","unrelated"]
        await self.react();await self.react(added=False)
        self.assertEqual(self.member.role_ids,["unrelated"])
        self.member.edit.assert_awaited_once_with(roles=["unrelated"])
        self.assertEqual(self.store.grants("server","user"),[])

    async def test_passive_sync_preserves_preexisting_role(self):
        self.member.role_ids=["gaming"]
        self.message.reactions={"🎮":["user"]}
        await self.flow.sync(self.panel)
        self.message.reactions={}
        await self.flow.sync(self.panel)
        self.assertEqual(self.member.role_ids,["gaming"])
        self.member.edit.assert_not_awaited()

    async def test_duplicate_reactions_are_idempotent(self):
        await self.react();await self.react()
        self.member.edit.assert_awaited_once()

    async def test_single_choice_replaces_owned_role_and_removes_old_reaction(self):
        self.mode("single")
        await self.react();await self.react("🎨")
        self.assertEqual(self.member.role_ids,["art"])
        self.assertEqual(self.message.reactions["🎮"],[])

    async def test_keep_mode_survives_unreact(self):
        self.mode("keep");await self.react();await self.react(added=False)
        self.assertEqual(self.member.role_ids,["gaming"])

    async def test_shared_role_retains_other_panel_selection(self):
        other=self.store.save("server","admin",self.config)
        self.store.update(other["id"],status="active")
        self.store.select(other,"user",iso(self.joined),[self.config["options"][0]])
        await self.react();await self.react(added=False)
        self.assertEqual(self.member.role_ids,["gaming"])

    async def test_pending_application_cannot_grant_role(self):
        apps=self.db.applications
        apps.save_settings("server","admin",{"enabled":True,"questions":[{"title":"Rules","prompt":"Agree?","type":"agreement","required":True}]})
        apps.update_setup("server",status="ready",role_id="access")
        apps.create("server","user",iso(self.joined),screening_required=False)
        await self.react()
        self.assertEqual(self.member.role_ids,[])
        self.assertEqual(self.message.reactions["🎮"],[])

    async def test_captcha_cannot_be_bypassed(self):
        self.db.set_web_verification_challenge("server","user","hash",iso(self.joined+timedelta(days=1)))
        await self.react()
        self.assertEqual(self.member.role_ids,[])

    async def test_new_join_does_not_inherit_old_role_ownership(self):
        await self.react()
        self.member.joined_at+=timedelta(hours=1)
        self.message.reactions={}
        await self.flow.sync(self.panel)
        self.assertEqual(self.member.role_ids,["gaming"])
        self.assertEqual(self.store.grants("server","user"),[])
        await self.react();await self.react(added=False)
        self.assertEqual(self.member.role_ids,[])

    async def test_privileged_role_changes_block_grants(self):
        self.server.roles["gaming"].permissions.allow=stoat.Permissions(manage_server=True)
        await self.react()
        self.assertEqual(self.member.role_ids,[])
        self.assertIn("Staff",self.store.get(self.panel["id"])["error"])

    async def test_channel_privilege_and_access_role_are_rejected(self):
        self.channel.role_permissions["gaming"]=NS(allow=stoat.Permissions(manage_webhooks=True))
        self.assertIn("staff",self.flow.role_error(*self.context,"gaming"))
        self.db.applications.update_setup("server",status="ready",role_id="art")
        # An existing form row is needed for application access-role selection.
        self.db.applications.save_settings("server","admin",{"enabled":False,"questions":[]})
        self.db.applications.update_setup("server",status="ready",role_id="art")
        self.assertIn("Application",self.flow.role_error(*self.context,"art"))

    async def test_unconfirmed_api_result_retains_retry_and_does_not_report_success(self):
        self.member.edit.side_effect=None;self.member.edit.return_value=self.member
        await self.react()
        self.assertIn("did not confirm",self.store.get(self.panel["id"])["error"])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM reaction_role_pending_members").fetchone()[0],1)

    async def test_failed_removal_can_be_recovered_without_remaining_reaction(self):
        await self.react()
        edit=self.member.edit.side_effect
        self.member.edit.side_effect=RuntimeError("API unavailable")
        await self.react(added=False)
        self.assertEqual(self.member.role_ids,["gaming"])
        self.member.edit.side_effect=edit
        async with self.bot.application_flow.lock("user:user"):
            await self.flow.apply_member("server","user",self.context)
        self.assertEqual(self.member.role_ids,[])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM reaction_role_pending_members").fetchone()[0],0)

    async def test_restart_reconciles_reactions_added_while_offline(self):
        self.message.reactions={"🎨":["user"]}
        restarted=ReactionRoleFlow(self.bot);restarted.context=AsyncMock(return_value=self.context)
        await restarted.sync(self.panel)
        self.assertEqual(self.member.role_ids,["art"])

    async def test_paused_and_unrelated_messages_do_not_change_roles(self):
        self.store.update(self.panel["id"],status="paused")
        self.assertFalse(await self.react());self.member.edit.assert_not_awaited()
        self.assertFalse(await self.flow.reaction(NS(message_id="poll",user_id="user",emoji="🎮"),added=True))

    async def test_unreadable_message_still_applies_the_click_and_reports_the_error(self):
        # The click itself is applied from the gateway event; verifying it against the
        # message fails afterwards and is reported for the dashboard.
        await self.react()
        self.channel.fetch_message.side_effect=RuntimeError("Message missing")
        await self.react(added=False)
        self.assertEqual(self.member.role_ids,[])
        self.assertIn("Message missing",self.store.get(self.panel["id"])["error"])

    async def test_sweep_with_unreadable_message_never_removes_roles(self):
        await self.react()
        self.channel.fetch_message.side_effect=RuntimeError("Message missing")
        with self.assertRaises(RuntimeError): await self.flow.sync(self.store.get(self.panel["id"]))
        self.assertEqual(self.member.role_ids,["gaming"])

    async def test_delete_preserves_grants_by_default(self):
        await self.react()
        await self.flow.publish(self.store.get(self.panel["id"]),{"operation":"delete","cleanup":False})
        self.assertEqual(self.member.role_ids,["gaming"])
        self.assertEqual(self.store.get(self.panel["id"])["status"],"deleted")

    async def test_delete_cleanup_removes_only_owned_roles(self):
        self.member.role_ids=["art"]
        self.message.reactions={"🎨":["user"]}
        await self.flow.sync(self.panel)
        await self.react()
        await self.flow.publish(self.store.get(self.panel["id"]),{"operation":"delete","cleanup":True})
        self.assertEqual(self.member.role_ids,["art"])

    async def test_cleanup_retry_remembers_cleanup_choice(self):
        operation=self.store.request("server","admin",self.panel["id"],"delete",1,True)
        self.store.update(self.panel["id"],status="error",error="API failure")
        retried=self.store.request("server","admin",self.panel["id"],"retry",operation["revision"])
        self.assertEqual(retried["cleanup"],1)

    async def test_validation_blocks_duplicate_emojis_staff_and_cross_server(self):
        for changes in [{"channel_id":"elsewhere"},{"options":[{"emoji":"🎮","role_id":"staff"}]},
                        {"options":[{"emoji":"☀","role_id":"art"},{"emoji":"☀️","role_id":"gaming"}]}]:
            with self.assertRaises(ValueError): self.store.validate("server",{**self.config,**changes})

    async def test_preview_contains_modes_and_custom_fields_without_sending(self):
        result=panel_embed(self.config)
        self.assertIn("Remove your reaction",result["description"])
        self.assertIn("🎮 — Gaming",result["description"])
        self.channel.send.assert_not_awaited()

    async def test_optimistic_edit_and_tenant_scope(self):
        with self.assertRaises(LookupError): self.store.request("other","admin",self.panel["id"],"delete",1)
        with self.assertRaises(ValueError): self.store.save("server","admin",{**self.config,"revision":0},self.panel["id"])

    async def test_publish_recovers_known_nonce_after_restart(self):
        self.store.update(self.panel["id"],message_id=None,published_channel_id=None)
        self.message.nonce=f"rr-{self.panel['id']}-1"
        self.channel.history.return_value=[self.message]
        await self.flow.publish(self.store.get(self.panel["id"]),{"operation":"publish"})
        self.channel.send.assert_not_awaited()
        self.assertEqual(self.store.get(self.panel["id"])["message_id"],"message")

    async def test_edit_message_uses_supported_sdk_arguments_and_seeds_emojis(self):
        await self.flow.publish(self.panel,{"operation":"publish"})
        self.message.edit.assert_awaited_once()
        self.assertEqual(self.message.react.await_count,2)

    async def test_clear_reactions_removes_owned_roles(self):
        await self.react()
        self.message.reactions={}
        await self.flow.cleared(NS(message_id="message"))
        self.assertEqual(self.member.role_ids,[])

    async def test_one_failed_member_does_not_block_other_reactors(self):
        good=self.member
        bad=NS(id="bad",role_ids=["unknown"],joined_at=self.joined,timed_out_until=None)
        async def fetch(user): return bad if user=="bad" else good
        self.server.fetch_member.side_effect=fetch
        self.message.reactions={"🎮":["bad","user"]}
        with self.assertRaises(RuntimeError): await self.flow.sync(self.panel)
        self.assertEqual(good.role_ids,["gaming"])

    async def test_live_permission_cache_avoids_refetching_every_channel(self):
        self.bot.get_server=Mock(return_value=self.server)
        self.server.get_member=Mock(return_value=self.bot_member)
        self.bot.get_channel=Mock(return_value=self.channel)
        flow=ReactionRoleFlow(self.bot)
        context=await flow.context("server")
        self.assertEqual(context,self.context)
        self.bot.fetch_server.assert_not_awaited()
        self.server.fetch_member.assert_not_awaited()
        self.bot.fetch_channel.assert_not_awaited()
        self.channel.role_permissions["gaming"]=NS(allow=stoat.Permissions(manage_messages=True))
        self.assertIn("staff",flow.role_error(*(await flow.context("server")),"gaming"))

    async def test_missing_channel_metadata_is_not_silently_ignored(self):
        self.bot.get_server=Mock(return_value=self.server)
        self.server.get_member=Mock(return_value=self.bot_member)
        self.bot.get_channel=Mock(return_value=None)
        self.bot.fetch_channel.side_effect=PermissionError("Cannot inspect channel")
        with self.assertRaises(PermissionError):
            await ReactionRoleFlow(self.bot).context("server")

    async def test_single_choice_tolerates_a_confirmed_concurrent_unreact(self):
        self.mode("single")
        await self.react()
        self.message.reactions["🎨"]=["user"]
        async def already_removed(emoji,**kwargs):
            self.message.reactions[emoji]=[]
            raise stoat.NotFound(NS(status=404),{"type":"NotFound"})
        self.message.unreact.side_effect=already_removed
        await self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎨"),added=True)
        self.assertEqual(self.member.role_ids,["art"])
        self.assertIsNone(self.store.get(self.panel["id"])["error"])
        self.assertEqual(self.message.reactions["🎮"],[])

    async def test_unreact_not_found_with_reaction_still_present_is_an_error(self):
        self.message.reactions={"🎮":["user"]}
        self.message.unreact.side_effect=stoat.NotFound(NS(status=404),{"type":"NotFound"})
        with self.assertRaises(stoat.NotFound):
            await self.flow.remove_user_reaction(self.channel,self.message,"🎮","user")

    async def test_unreact_uses_exact_stored_unicode_variant(self):
        self.message.reactions={"☀️":["user"]}
        await self.flow.remove_user_reaction(self.channel,self.message,"☀","user")
        self.message.unreact.assert_awaited_once_with("☀️",user="user")

    async def test_equivalent_emoji_variants_merge_their_reactors(self):
        panel={**self.panel,"config":{**self.panel["config"],"options":[{"emoji":"☀","role_id":"gaming","label":"Sun"}]}}
        self.message.reactions={"☀️":["user"],"☀":["bot"]}
        await self.flow.sync(panel)
        self.assertEqual(self.member.role_ids,["gaming"])

    async def test_burst_of_queued_clicks_only_syncs_latest_choice(self):
        self.mode("single")
        self.message.reactions={"🎮":["user"],"🎨":["user"]}
        lock=self.flow.lock(self.panel["id"])
        await lock.acquire()
        first=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎮"),added=True))
        second=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎨"),added=True))
        await asyncio.sleep(0)
        lock.release()
        await asyncio.gather(first,second)
        self.channel.fetch_message.assert_awaited_once()
        self.member.edit.assert_awaited_once()
        self.assertEqual(self.member.role_ids,["art"])
        self.assertEqual(self.flow.pending_reactions,{})

    async def test_member_is_fetched_once_then_confirmed_by_patch_response(self):
        await self.react()
        self.server.fetch_member.assert_awaited_once_with("user")
        self.server.fetch_member.reset_mock()
        await self.react()
        self.server.fetch_member.assert_awaited_once_with("user")

    def enable_member_cache(self):
        members={}
        self.server.get_member=Mock(side_effect=members.get)
        self.bot.state.cache=NS(store_server_member=lambda member,context: members.update({member.id:member}))
        return members

    async def test_quick_toggle_reuses_gateway_member_and_preserves_gateway_role_update(self):
        members=self.enable_member_cache()
        await self.react()
        self.server.fetch_member.reset_mock()
        updated=NS(**vars(self.member))
        updated.role_ids=["gaming","unrelated"]
        members["user"]=updated  # The gateway replaces members on partial updates.
        await self.react(added=False)
        self.server.fetch_member.assert_not_awaited()
        self.member.edit.assert_awaited_with(roles=["unrelated"])
        self.assertEqual(self.member.role_ids,["unrelated"])

    async def test_expired_or_evicted_member_is_refetched(self):
        members=self.enable_member_cache()
        await self.react()
        self.server.fetch_member.reset_mock()
        self.flow.member_checked[("server","user")]-=MEMBER_TRUST_SECONDS+1
        await self.react(added=False)
        self.server.fetch_member.assert_awaited_once_with("user")
        self.server.fetch_member.reset_mock()
        members.clear()
        await self.react()
        self.server.fetch_member.assert_awaited_once_with("user")

    async def test_unconfirmed_patch_invalidates_member_cache(self):
        self.enable_member_cache()
        self.member.edit.side_effect=None
        self.member.edit.return_value=self.member
        await self.react()
        self.assertNotIn(("server","user"),self.flow.member_checked)
        self.server.fetch_member.reset_mock()
        await self.react()
        self.server.fetch_member.assert_awaited_once_with("user")

    async def test_patch_without_member_response_uses_confirmation_get(self):
        async def edit_without_response(**kwargs):
            self.member.role_ids=kwargs["roles"]
        self.member.edit.side_effect=edit_without_response
        await self.react()
        self.assertEqual(self.server.fetch_member.await_count,2)
        self.assertIsNone(self.store.get(self.panel["id"])["error"])

    async def test_failed_preexisting_role_removal_is_durable_and_recoverable(self):
        self.enable_member_cache()
        self.member.role_ids=["gaming","unrelated"]
        original_edit=self.member.edit.side_effect
        self.member.edit.side_effect=RuntimeError("API unavailable")
        await self.react(added=False)
        self.assertNotIn(("server","user"),self.flow.member_checked)
        self.assertEqual(self.store.grants("server","user")[0]["owned"],1)
        self.member.edit.side_effect=original_edit
        await self.flow.apply_member("server","user",self.context)
        self.assertEqual(self.member.role_ids,["unrelated"])
        self.assertEqual(self.store.grants("server","user"),[])

    async def test_coalesced_add_remove_still_removes_preexisting_role(self):
        self.member.role_ids=["gaming","unrelated"]
        lock=self.flow.lock(self.panel["id"])
        await lock.acquire()
        added=asyncio.create_task(self.react())
        removed=asyncio.create_task(self.react(added=False))
        await asyncio.sleep(0)
        lock.release()
        await asyncio.gather(added,removed)
        self.assertEqual(self.member.role_ids,["unrelated"])
        self.channel.fetch_message.assert_awaited_once()
        self.member.edit.assert_awaited_once_with(roles=["unrelated"])

    async def test_unconfigured_reaction_does_not_make_api_requests(self):
        await self.flow.reaction(NS(message_id="message",user_id="user",emoji="🥐"),added=True)
        self.channel.fetch_message.assert_not_awaited()
        self.member.edit.assert_not_awaited()

    async def test_new_click_during_role_edit_is_not_removed_by_old_cleanup(self):
        self.mode("single")
        self.message.reactions={"🎮":["user"],"🎨":["user"]}
        editing=asyncio.Event()
        finish=asyncio.Event()
        original_edit=self.member.edit.side_effect
        async def slow_edit(**kwargs):
            if not editing.is_set():
                editing.set()
                await finish.wait()
            return await original_edit(**kwargs)
        self.member.edit.side_effect=slow_edit
        first=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎮"),added=True))
        await editing.wait()
        second=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎨"),added=True))
        await asyncio.sleep(0)
        finish.set()
        await asyncio.gather(first,second)
        self.assertEqual(self.member.role_ids,["art"])
        self.assertEqual(self.message.reactions["🎨"],["user"])
        self.message.unreact.assert_awaited_once_with("🎮",user="user")

    async def test_queued_removal_of_old_emoji_preserves_new_click_preference(self):
        self.mode("single")
        self.message.reactions={"🎮":["user"],"🎨":["user"]}
        lock=self.flow.lock(self.panel["id"])
        await lock.acquire()
        added=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎨"),added=True))
        removed=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎮"),added=False))
        await asyncio.sleep(0)
        lock.release()
        await asyncio.gather(added,removed)
        self.assertEqual(self.member.role_ids,["art"])
        self.channel.fetch_message.assert_awaited_once()

    async def test_clicks_from_different_members_do_not_wait_for_each_other(self):
        other=NS(id="other",role_ids=[],joined_at=self.joined,timed_out_until=None)
        async def edit_other(**kwargs): other.role_ids=kwargs["roles"];return other
        other.edit=AsyncMock(side_effect=edit_other)
        started,release=asyncio.Event(),asyncio.Event()
        original=self.member.edit.side_effect
        async def slow(**kwargs):
            started.set();await release.wait();return await original(**kwargs)
        self.member.edit.side_effect=slow
        async def fetch(user): return {"bot":self.bot_member,"user":self.member,"other":other}[user]
        self.server.fetch_member.side_effect=fetch
        self.message.reactions={"🎮":["user","other"]}
        first=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎮"),added=True))
        await started.wait()
        await asyncio.wait_for(self.flow.reaction(NS(message_id="message",user_id="other",emoji="🎮"),added=True),timeout=2)
        self.assertEqual(other.role_ids,["gaming"])
        self.assertEqual(self.member.role_ids,[])
        release.set();await first
        self.assertEqual(self.member.role_ids,["gaming"])

    async def test_click_is_applied_before_the_message_is_read(self):
        seen=[]
        async def fetch_message(message_id):
            seen.append(list(self.member.role_ids));return self.message
        self.channel.fetch_message.side_effect=fetch_message
        await self.react()
        self.assertEqual(seen,[["gaming"]])  # the role was already granted when verification read the message

    async def test_queued_clicks_replay_in_order(self):
        panel=self.store.get(self.panel["id"])
        await self.flow.quick(panel,"user",[("🎮",True),("🎨",True)],set())
        self.assertEqual(set(self.member.role_ids),{"gaming","art"})
        await self.flow.quick(panel,"user",[("🎮",False)],set())
        self.assertEqual(self.member.role_ids,["art"])
        self.mode("single")
        panel=self.store.get(self.panel["id"])
        await self.flow.quick(panel,"user",[("🎮",True),("🎨",True),("🎮",True)],set())
        self.assertEqual(self.member.role_ids,["gaming"])
        self.mode("keep")
        panel=self.store.get(self.panel["id"])
        await self.flow.quick(panel,"user",[("🎨",True),("🎨",False)],set())
        self.assertEqual(set(self.member.role_ids),{"gaming","art"})

    async def test_sweep_uses_gateway_cache_and_makes_no_member_requests(self):
        members=self.enable_member_cache()
        members["user"]=self.member
        self.member.role_ids=["gaming"]
        self.message.reactions={"🎮":["user"]}
        await self.flow.sync(self.panel)
        self.server.fetch_member.reset_mock();self.member.edit.reset_mock()
        await self.flow.sync(self.panel)
        self.server.fetch_member.assert_not_awaited();self.member.edit.assert_not_awaited()

    async def test_sweep_skips_database_writes_when_nothing_changed(self):
        members=self.enable_member_cache()
        members["user"]=self.member
        self.message.reactions={"🎮":["user"]}
        await self.flow.sync(self.panel)
        original=self.store.select
        self.store.select=Mock(side_effect=original)
        await self.flow.sync(self.panel)
        self.store.select.assert_not_called()

    async def test_sweep_rereads_member_before_changing_roles(self):
        members=self.enable_member_cache()
        stale=NS(id="user",role_ids=[],joined_at=self.joined,timed_out_until=None,edit=AsyncMock())
        members["user"]=stale
        self.member.role_ids=["gaming","unrelated"]  # what the API really says
        self.message.reactions={"🎨":["user"]}
        await self.flow.sync(self.panel)
        self.server.fetch_member.assert_awaited_once_with("user")
        stale.edit.assert_not_awaited()
        self.assertEqual(self.member.role_ids,["art","gaming","unrelated"])

    async def test_failed_sweep_write_stays_retryable_when_choices_were_unchanged(self):
        members=self.enable_member_cache()
        members["user"]=self.member
        self.message.reactions={"🎮":["user"]}
        await self.flow.sync(self.panel)
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM reaction_role_pending_members").fetchone()[0],0)
        self.member.role_ids=[]  # someone removed the role behind our back
        self.member.edit.side_effect=RuntimeError("API unavailable")
        with self.assertRaises(RuntimeError): await self.flow.sync(self.panel)
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM reaction_role_pending_members").fetchone()[0],1)

    async def test_gateway_reconnect_forces_a_fresh_read(self):
        self.enable_member_cache()
        await self.react()
        self.server.fetch_member.reset_mock()
        self.flow.connection_reset()
        await self.react(added=False)
        self.server.fetch_member.assert_awaited_once_with("user")

    async def test_gateway_join_or_update_is_trusted_without_a_request(self):
        members=self.enable_member_cache()
        members["user"]=self.member
        self.flow.trust_member("server","user")
        await self.react()
        self.server.fetch_member.assert_not_awaited()
        self.assertEqual(self.member.role_ids,["gaming"])

    async def test_exclusive_panel_work_waits_for_clicks_and_blocks_new_ones(self):
        lock=PanelLock()
        order=[]
        async def click(name,hold):
            async with lock.shared():
                order.append(name+" start");await hold.wait();order.append(name+" end")
        hold1,hold2=asyncio.Event(),asyncio.Event()
        first=asyncio.create_task(click("first",hold1));await asyncio.sleep(0)
        async def sweep():
            async with lock: order.append("sweep")
        sweeping=asyncio.create_task(sweep());await asyncio.sleep(0)
        second=asyncio.create_task(click("second",hold2));await asyncio.sleep(0)
        self.assertEqual(order,["first start"])  # sweep waits for the click, the new click waits for the sweep
        hold1.set()
        # Step the loop rather than sleeping: on Windows a 10 ms sleep can end after a single
        # loop iteration (15.6 ms clock resolution), before the hand-off has finished.
        for _ in range(20):
            if len(order)>=4: break
            await asyncio.sleep(0)
        self.assertEqual(order,["first start","first end","sweep","second start"])
        hold2.set();await asyncio.gather(first,sweeping,second)

    async def test_burst_of_members_shares_message_reads_without_losing_anyone(self):
        users=[f"u{i}" for i in range(20)]
        members={u:NS(id=u,role_ids=[],joined_at=self.joined,timed_out_until=None) for u in users}
        for u,m in members.items():
            async def edit(*,_m=m,**kwargs): _m.role_ids=kwargs["roles"];return _m
            m.edit=AsyncMock(side_effect=edit)
        async def fetch(user): await asyncio.sleep(0.01);return self.bot_member if user=="bot" else members[user]
        self.server.fetch_member.side_effect=fetch
        async def slow_message(message_id):
            await asyncio.sleep(0.05);return self.message
        self.channel.fetch_message.side_effect=slow_message
        self.message.reactions={"🎮":list(users)}
        await asyncio.gather(*(self.flow.reaction(NS(message_id="message",user_id=u,emoji="🎮"),added=True) for u in users))
        self.assertTrue(all(m.role_ids==["gaming"] for m in members.values()))
        self.assertLess(self.channel.fetch_message.await_count,8)
        self.assertEqual(self.flow.snapshots and len(self.flow.snapshots),1)

    async def test_failed_message_read_is_not_reused(self):
        self.channel.fetch_message.side_effect=RuntimeError("temporary")
        await self.react()
        self.assertEqual(self.flow.snapshots,{})
        self.channel.fetch_message.side_effect=None
        self.channel.fetch_message.return_value=self.message
        await self.react(added=False)
        self.assertIsNone(self.store.get(self.panel["id"])["error"])

    async def test_a_click_never_reuses_a_read_that_started_before_it(self):
        reads=[]
        async def message_read(message_id):
            reads.append(dict((k,list(v)) for k,v in self.message.reactions.items()))
            await asyncio.sleep(0.05);return self.message
        self.channel.fetch_message.side_effect=message_read
        self.message.reactions={"🎮":["user"]}
        first=asyncio.create_task(self.flow.reaction(NS(message_id="message",user_id="user",emoji="🎮"),added=True))
        await asyncio.sleep(0.01)  # the first read is in flight and does not contain the next click
        other=NS(id="other",role_ids=[],joined_at=self.joined,timed_out_until=None)
        async def edit_other(**kwargs): other.role_ids=kwargs["roles"];return other
        other.edit=AsyncMock(side_effect=edit_other)
        original=self.server.fetch_member.side_effect
        async def fetch(user): return other if user=="other" else await original(user)
        self.server.fetch_member.side_effect=fetch
        self.message.reactions["🎮"].append("other")
        await self.flow.reaction(NS(message_id="message",user_id="other",emoji="🎮"),added=True)
        await first
        self.assertEqual(len(reads),2)
        self.assertEqual(other.role_ids,["gaming"])

    async def test_publish_without_custom_emojis_skips_the_emoji_lookup(self):
        await self.flow.publish(self.panel,{"operation":"publish"})
        self.server.fetch_emojis.assert_not_awaited()

    def queue_dashboard_action(self,server,action="reaction_roles"):
        with self.store.connection:
            return self.store.connection.execute("INSERT INTO dashboard_actions(server_id,action,actor_id,payload_json,created_at) VALUES(?,?,?,?,?)",
                (server,action,"admin","{}","2026-10-06T00:00:00+00:00")).lastrowid

    async def test_claim_can_select_or_exclude_reaction_role_actions(self):
        self.db.claim_dashboard_actions()  # the fixture queued the initial publish
        self.assertFalse(self.db.has_pending_dashboard_action("reaction_roles"))
        other=self.queue_dashboard_action("server","send_settings_log")
        rr=self.queue_dashboard_action("server")
        self.assertTrue(self.db.has_pending_dashboard_action("reaction_roles"))
        self.assertEqual([a["id"] for a in self.db.claim_dashboard_actions(only="reaction_roles")],[rr])
        self.assertEqual([a["id"] for a in self.db.claim_dashboard_actions(exclude=("reaction_roles",))],[other])
        self.assertFalse(self.db.has_pending_dashboard_action("reaction_roles"))

    async def test_servers_run_in_parallel_and_each_server_keeps_its_order(self):
        order=[];gate=asyncio.Event()
        async def action(item):
            order.append(("start",item["id"]))
            if item["server_id"]=="slow": await gate.wait()
            order.append(("end",item["id"]))
            return {"ok":True}
        self.flow.action=action
        self.db.claim_dashboard_actions()  # the fixture queued the initial publish
        slow1=self.queue_dashboard_action("slow");slow2=self.queue_dashboard_action("slow");fast=self.queue_dashboard_action("fast")
        task=asyncio.create_task(self.flow.run_pending_actions())
        await asyncio.sleep(0.05)
        self.assertIn(("end",fast),order)                      # another server was not held up
        self.assertEqual([e for e in order if e[1]==slow2],[])  # the slow server's second action still waits its turn
        gate.set();self.assertEqual(await task,3)
        self.assertLess(order.index(("end",slow1)),order.index(("start",slow2)))
        done=lambda i:self.db.get_dashboard_action(i)["status"]
        self.assertEqual([done(slow1),done(slow2),done(fast)],["completed"]*3)

    async def test_failed_action_is_recorded_and_does_not_stop_the_others(self):
        async def action(item):
            if item["server_id"]=="bad": raise RuntimeError("Stoat rejected it")
            return {"ok":True}
        self.flow.action=action
        self.db.claim_dashboard_actions()
        bad=self.queue_dashboard_action("bad");good=self.queue_dashboard_action("good")
        await self.flow.run_pending_actions()
        self.assertEqual(self.db.get_dashboard_action(bad)["status"],"failed")
        self.assertEqual(self.db.get_dashboard_action(good)["status"],"completed")
        self.assertEqual(self.db.get_dashboard_action(bad)["result"],{"error":"Stoat rejected it"})

    async def test_runner_picks_up_a_queued_action_within_a_second(self):
        async def action(item): return {"ok":True}
        self.flow.action=action
        self.db.claim_dashboard_actions()
        self.flow.start()
        try:
            self.assertTrue(self.flow.runs_actions)
            identifier=self.queue_dashboard_action("server")
            for _ in range(20):
                await asyncio.sleep(0.1)
                if self.db.get_dashboard_action(identifier)["status"]=="completed": break
            self.assertEqual(self.db.get_dashboard_action(identifier)["status"],"completed")
        finally:
            self.bot._closing=True
            for task in (self.flow.task,self.flow.actions_task): task.cancel()
            await asyncio.gather(self.flow.task,self.flow.actions_task,return_exceptions=True)
