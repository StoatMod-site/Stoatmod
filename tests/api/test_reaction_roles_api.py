import hashlib
import tempfile
import unittest
from pathlib import Path
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer
from api.server import create_app, DATABASE_KEY, CSRF_COOKIE


class ReactionRoleApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.client=TestClient(TestServer(create_app(str(Path(self.temp.name)/"api.db"))),cookie_jar=CookieJar(unsafe=True))
        await self.client.start_server()
        self.db=self.client.app[DATABASE_KEY]
        self.db.update_dashboard_server_snapshot("server","Test",1,[],[],owner_id="admin")
        self.db.create_dashboard_login_code(hashlib.sha256(b"AB12CD34").hexdigest(),"server","admin","2099-01-01T00:00:00+00:00")
        response=await self.client.post("/api/auth/verify",json={"code":"AB12CD34"})
        self.assertEqual(response.status,200)
        self.csrf={"X-CSRF-Token":self.client.session.cookie_jar.filter_cookies(self.client.make_url("/"))[CSRF_COOKIE].value}
        self.directory={"channels":[{"id":"channel","name":"Roles"}],"roles":[{"id":"role","name":"Gaming","assignable":True,"reason":None}],"emojis":[]}
        self.db.reaction_roles.set_directory("server",self.directory)
        self.config={"title":"Choose roles","description":"Select a role","footer":"","color":"#5865F2","channel_id":"channel","mode":"multiple","options":[{"emoji":"🎮","role_id":"role","label":"Gaming"}]}

    async def asyncTearDown(self):
        await self.client.close();self.temp.cleanup()

    async def test_publish_requires_csrf_and_queues_bot_work(self):
        response=await self.client.post("/api/reaction-roles",json=self.config)
        self.assertEqual(response.status,403)
        response=await self.client.post("/api/reaction-roles",json=self.config,headers=self.csrf)
        self.assertEqual(response.status,202)
        panel=(await response.json())["panel"]
        self.assertEqual(panel["status"],"pending")
        action=next(a for a in self.db.claim_dashboard_actions() if a["action"]=="reaction_roles")
        self.assertEqual(action["server_id"],"server")
        self.assertEqual(action["payload"]["panel_id"],panel["id"])

    async def test_preview_is_read_only_and_uses_published_formatter(self):
        before=self.db.connection.execute("SELECT count(*) FROM dashboard_actions").fetchone()[0]
        response=await self.client.post("/api/reaction-roles",json={**self.config,"operation":"preview"},headers=self.csrf)
        self.assertEqual(response.status,200)
        from reaction_roles import panel_embed
        result=await response.json()
        self.assertEqual(result["embed"],panel_embed(self.db.reaction_roles.validate("server",self.config)))
        self.assertIsNone(result["publish_error"])
        self.assertEqual(self.db.reaction_roles.panels("server"),[])
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM dashboard_actions").fetchone()[0],before)

    async def test_unfinished_draft_previews_before_directory_load_without_publishing(self):
        self.db.connection.execute("DELETE FROM reaction_role_directory")
        draft={**self.config,"title":"","channel_id":"","options":[{"emoji":"🎮","role_id":"","label":""}]}
        before=self.db.connection.execute("SELECT count(*) FROM dashboard_actions").fetchone()[0]
        response=await self.client.post("/api/reaction-roles",json={**draft,"operation":"preview"},headers=self.csrf)
        self.assertEqual(response.status,200)
        result=await response.json()
        self.assertEqual(result["embed"]["title"],"Choose your roles")
        self.assertIn("🎮 — Choose a role",result["embed"]["description"])
        self.assertTrue(result["publish_error"])
        response=await self.client.post("/api/reaction-roles",json=draft,headers=self.csrf)
        self.assertEqual(response.status,400)
        self.assertEqual(self.db.reaction_roles.panels("server"),[])
        self.assertEqual(self.db.connection.execute("SELECT count(*) FROM dashboard_actions").fetchone()[0],before)

    async def test_preview_updates_embed_and_reports_duplicate_options_without_hiding_it(self):
        draft={**self.config,"title":"Notifications","color":"#123456","footer":"Pick below","mode":"single","options":self.config["options"]*2}
        response=await self.client.post("/api/reaction-roles",json={**draft,"operation":"preview"},headers=self.csrf)
        self.assertEqual(response.status,200)
        result=await response.json()
        self.assertEqual(result["embed"]["title"],"Notifications")
        self.assertEqual(result["embed"]["color"],"#123456")
        self.assertIn("Choose one role.",result["embed"]["description"])
        self.assertIn("Pick below",result["embed"]["description"])
        self.assertIn("different emoji and role",result["publish_error"])
        response=await self.client.post("/api/reaction-roles",json=draft,headers=self.csrf)
        self.assertEqual(response.status,400)

    async def test_panels_and_directory_are_tenant_scoped(self):
        self.db.reaction_roles.set_directory("other",self.directory)
        other=self.db.reaction_roles.save("other","other-admin",self.config)
        response=await self.client.get("/api/reaction-roles")
        self.assertEqual((await response.json())["panels"],[])
        response=await self.client.post("/api/reaction-roles/"+other["id"],json={"operation":"delete","revision":1},headers=self.csrf)
        self.assertEqual(response.status,404)

    async def test_anonymous_requests_are_denied(self):
        self.client.session.cookie_jar.clear()
        response=await self.client.get("/api/reaction-roles")
        self.assertEqual(response.status,401)

    async def test_invalid_mode_role_and_channel_are_rejected(self):
        for change in [{"mode":"invalid"},{"channel_id":"other"},{"options":[{"emoji":"🎮","role_id":"missing"}]}]:
            response=await self.client.post("/api/reaction-roles",json={**self.config,**change},headers=self.csrf)
            self.assertEqual(response.status,400)

    async def test_pending_panels_cannot_be_overwritten_or_deleted(self):
        panel=self.db.reaction_roles.save("server","admin",self.config)
        response=await self.client.post("/api/reaction-roles/"+panel["id"],json={"operation":"delete","revision":1},headers=self.csrf)
        self.assertEqual(response.status,400)

    async def test_cleanup_flag_requires_a_boolean(self):
        panel=self.db.reaction_roles.save("server","admin",self.config)
        self.db.reaction_roles.update(panel["id"],status="active")
        response=await self.client.post("/api/reaction-roles/"+panel["id"],json={"operation":"delete","revision":1,"cleanup":"false"},headers=self.csrf)
        self.assertEqual(response.status,400)
