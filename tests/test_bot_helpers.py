import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, Mock, PropertyMock, call, patch

import stoat

from bot import (
    CAPTCHA_EXPIRED_KICK_REASON,
    CAPTCHA_FAILED_ATTEMPTS_KICK_REASON,
    GLOBAL_COMMAND_OWNER_ID,
    ModerationBot,
    REPORT_NOTIFICATION_RETRY_DELAYS,
    ReportNotificationDeliveryError,
    SERVER_PERMISSION_REQUIREMENTS,
    ZERO_TOLERANCE_USERNAME_BAN_REASON,
    ZERO_TOLERANCE_USERNAME_SLURS,
    counts_towards_message_statistics,
)
from database import (
    CaptchaChallenge,
    ModerationCaseRecord,
    WarningPolicy,
    WarningRecord,
)
from moderation import ModerationResult
from admin_credentials import verify_password


class ModerationBotHelperTests(unittest.TestCase):
    def test_global_ban_contact_contains_only_the_admin_email(self) -> None:
        instructions = ModerationBot._global_ban_contact_instructions()

        self.assertIn("admin@modstoat.site", instructions)
        self.assertNotIn("appeal", instructions.lower())
        self.assertNotIn("http", instructions.lower())

    def test_retired_alt_detection_actions_cannot_ban_members(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot._pending_ban_attribution = {}
        action = {
            "id": 44,
            "server_id": "server-a",
            "action": "moderate_member",
            "actor_id": "STOATMOD_ALT_DETECTION",
            "payload": {
                "user_id": "joining-user",
                "action": "ban",
                "reason": "alt account of <@known-user>",
                "source": "alt_detection",
                "detection_source": "verification",
                "linked_user_ids": ["known-user"],
                "linked_global_bans": [],
            },
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            add_event=Mock(),
            finish_dashboard_action=Mock(return_value=True),
        )
        target_server = SimpleNamespace(
            id="server-a",
            name="Server A",
            ban=AsyncMock(),
        )
        other_server = SimpleNamespace(
            id="server-b",
            name="Server B",
            ban=AsyncMock(),
        )
        bot._servers = {
            target_server.id: target_server,
            other_server.id: other_server,
        }
        bot._ready_event_servers = {target_server.id: target_server}
        bot.get_server = Mock(return_value=None)
        bot.fetch_server = AsyncMock(
            side_effect=AssertionError("Ready server should be reused")
        )
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._resolve_user_tag = AsyncMock(
            side_effect=lambda user_id, *_args: user_id
        )
        bot.send_log = AsyncMock()
        bot._apply_global_ban_to_servers = AsyncMock()

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        target_server.ban.assert_not_awaited()
        other_server.ban.assert_not_awaited()
        bot._apply_global_ban_to_servers.assert_not_awaited()
        self.assertIn("removed", str(bot.database.finish_dashboard_action.call_args))

    def test_ready_starts_workers_without_initial_api_sweeps(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(
            local_ai_expected_version="test-model"
        )
        bot._ready_reconciliation_task = None
        bot.database = SimpleNamespace(
            backfill_captcha_kick_reasons=Mock(return_value=0),
            remove_external_kick_cases=Mock(return_value=0),
            reconcile_dashboard_server_snapshots=Mock(return_value=[]),
        )
        order: list[str] = []
        bot.start_status_rotation = Mock(
            side_effect=lambda _user: order.append("status")
        )
        def start_dashboard_worker() -> None:
            order.append("dashboard-worker")
            self.assertEqual(
                set(bot._ready_event_servers or {}),
                {"refresh-fails", "continues"},
            )

        bot.start_dashboard_action_worker = Mock(
            side_effect=start_dashboard_worker
        )
        bot.start_global_ban_sync_worker = Mock(
            side_effect=lambda: order.append("global-ban-worker")
        )
        bot.start_dashboard_member_refresh_worker = Mock(
            side_effect=lambda: order.append("member-refresh-worker")
        )
        bot.resume_captcha_challenges = AsyncMock(
            side_effect=lambda: order.append("captcha-resume")
        )

        refresh_fails = SimpleNamespace(id="refresh-fails", name="First")
        continues = SimpleNamespace(id="continues", name="Second")
        blacklisted = SimpleNamespace(id="blacklisted", name="Third")
        check_fails = SimpleNamespace(id="check-fails", name="Fourth")

        async def reject(server: object, *, source: str) -> bool:
            self.assertEqual(source, "ready")
            order.append(f"blacklist:{server.id}")
            if server is check_fails:
                raise RuntimeError("temporary blacklist lookup failure")
            if server is blacklisted:
                bot._track_status_server(server.id, connected=False)
            return server is blacklisted

        bot.reject_blacklisted_server = AsyncMock(side_effect=reject)
        bot.refresh_dashboard_server = AsyncMock()
        bot.announce_server = AsyncMock()
        bot.update_bot_heartbeat = Mock(
            side_effect=lambda _count: order.append("heartbeat")
        )
        bot.sync_global_bans = AsyncMock()
        event = SimpleNamespace(
            me=SimpleNamespace(id="bot-user", tag="stoatmod#0001"),
            servers=[refresh_fails, continues, blacklisted, check_fails],
            channels=[],
        )

        async def run_ready() -> None:
            with patch("bot.logger.exception"):
                await bot.handle_ready(event)
                # The gateway handler must return before network-heavy server
                # reconciliation begins so message events can be dispatched.
                self.assertEqual(order, [])
                await bot._ready_reconciliation_task

        asyncio.run(run_ready())

        last_blacklist_scan = order.index("blacklist:check-fails")
        self.assertGreater(order.index("dashboard-worker"), last_blacklist_scan)
        self.assertGreater(order.index("global-ban-worker"), last_blacklist_scan)
        self.assertGreater(order.index("member-refresh-worker"), last_blacklist_scan)
        bot.refresh_dashboard_server.assert_not_awaited()
        bot.announce_server.assert_not_awaited()
        bot.sync_global_bans.assert_not_awaited()
        bot.update_bot_heartbeat.assert_called_once_with(2)
        self.assertIsNone(bot._ready_event_servers)
        self.assertEqual(bot._status_server_ids, {"refresh-fails", "continues", "check-fails"})

    def test_heartbeat_uses_ready_event_servers_before_client_cache_updates(
        self,
    ) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._status_user = SimpleNamespace(id="bot-user")
        bot._ready_event_servers = {
            f"server-{index}": SimpleNamespace(id=f"server-{index}")
            for index in range(74)
        }
        bot.database = SimpleNamespace(update_system_heartbeat=Mock())

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={},
        ):
            bot.update_bot_heartbeat()

        bot.database.update_system_heartbeat.assert_called_once_with(
            "bot",
            {"connected": True, "server_count": 74},
        )

    def test_server_blacklist_notifies_owner_before_leaving(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        events: list[str] = []

        async def send_dm(*_args, **_kwargs):
            events.append("dm")
            return True

        async def leave(**_kwargs):
            events.append("leave")

        bot._send_user_dm = AsyncMock(side_effect=send_dm)
        server = SimpleNamespace(
            id="server-a",
            name="Unsafe Community",
            owner_id="owner-a",
            leave=AsyncMock(side_effect=leave),
        )
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Repeated safety violations",
        }

        result = asyncio.run(
            bot._enforce_server_blacklist(
                server, blacklist, source="server_create"
            )
        )

        self.assertEqual(events, ["dm", "leave"])
        self.assertTrue(result["owner_notified"])
        self.assertTrue(result["left"])
        server.leave.assert_awaited_once_with(silent=True)
        dm = bot._send_user_dm.await_args
        self.assertEqual(dm.args[0], "owner-a")
        self.assertIn("**Reason:** Repeated safety violations", dm.args[2])
        self.assertIn("admin@modstoat.site", dm.args[2])

    def test_server_blacklist_still_leaves_when_owner_dm_fails(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot._send_user_dm = AsyncMock(return_value=False)
        server = SimpleNamespace(
            id="server-a",
            name="Unsafe Community",
            owner_id="owner-a",
            leave=AsyncMock(),
        )

        result = asyncio.run(
            bot._enforce_server_blacklist(
                server,
                {
                    "server_id": "server-a",
                    "server_name": "Unsafe Community",
                    "owner_id": "owner-a",
                    "reason": "Safety issue",
                },
                source="admin_dashboard",
            )
        )

        self.assertFalse(result["owner_notified"])
        server.leave.assert_awaited_once_with(silent=True)

    def test_blacklisted_reinvite_is_rejected_and_preserves_enforcement(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }
        bot.database = SimpleNamespace(
            get_server_blacklist=Mock(return_value=blacklist),
            purge_server_data=Mock(return_value={"dashboard_server_snapshots": 1}),
            get_public_dashboard_stats=Mock(return_value={"server_count": 0}),
        )
        bot._enforce_server_blacklist = AsyncMock(return_value={"left": True})
        bot.update_bot_heartbeat = Mock()
        server = SimpleNamespace(id="server-a")

        rejected = asyncio.run(
            bot.reject_blacklisted_server(server, source="server_create")
        )

        self.assertTrue(rejected)
        bot._enforce_server_blacklist.assert_awaited_once_with(
            server, blacklist, source="server_create"
        )
        bot.database.purge_server_data.assert_called_once_with("server-a")
        self.assertIs(bot.database.get_server_blacklist("server-a"), blacklist)
        bot.update_bot_heartbeat.assert_called_once_with(0)

    def test_server_create_retries_persistent_blacklist_after_leave_failure(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }
        bot.database = SimpleNamespace(
            get_server_blacklist=Mock(return_value=blacklist),
            purge_server_data=Mock(return_value={"dashboard_server_snapshots": 1}),
            get_public_dashboard_stats=Mock(return_value={"server_count": 0}),
        )
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.update_bot_heartbeat = Mock()
        bot.refresh_dashboard_server = AsyncMock()
        bot.announce_server = AsyncMock()
        server = SimpleNamespace(
            id="server-a",
            name="Unsafe Community",
            owner_id="owner-a",
            leave=AsyncMock(
                side_effect=[RuntimeError("temporary leave failure"), None]
            ),
        )
        event = SimpleNamespace(server=server)

        with patch("bot.logger.exception"):
            asyncio.run(bot.handle_server_create(event))
            asyncio.run(bot.handle_server_create(event))

        self.assertEqual(server.leave.await_count, 2)
        self.assertEqual(bot._send_user_dm.await_count, 2)
        bot.database.purge_server_data.assert_called_once_with("server-a")
        self.assertIs(bot.database.get_server_blacklist("server-a"), blacklist)
        bot.refresh_dashboard_server.assert_not_awaited()
        bot.announce_server.assert_not_awaited()

    def test_blacklist_dashboard_action_finishes_before_server_data_purge(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 401,
            "server_id": "server-a",
            "action": "blacklist_server",
            "actor_id": "admin-a",
            "payload": {"reason": "Safety issue"},
        }
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }
        order: list[str] = []

        def claim_once():
            bot._closing = True
            return [action]

        def finish(*_args, **_kwargs):
            order.append("finish")
            return True

        def purge(*_args, **_kwargs):
            order.append("purge")
            return {"dashboard_server_snapshots": 1}

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_server_blacklist=Mock(return_value=blacklist),
            finish_dashboard_action=Mock(side_effect=finish),
            purge_server_data=Mock(side_effect=purge),
            get_public_dashboard_stats=Mock(return_value={"server_count": 0}),
        )
        server = SimpleNamespace(id="server-a")
        bot._resolve_dashboard_server = AsyncMock(return_value=server)
        bot._enforce_server_blacklist = AsyncMock(
            return_value={"owner_notified": True, "left": True}
        )
        bot.update_bot_heartbeat = Mock()

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        self.assertEqual(order, ["finish", "purge"])
        bot._resolve_dashboard_server.assert_awaited_once_with("server-a")
        bot._enforce_server_blacklist.assert_awaited_once_with(
            server, blacklist, source="admin_dashboard"
        )
        bot.database.finish_dashboard_action.assert_called_once_with(
            401,
            success=True,
            result={"owner_notified": True, "left": True},
        )

    def test_blacklist_dashboard_action_fetches_server_after_cache_miss(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 402,
            "server_id": "server-a",
            "action": "blacklist_server",
            "actor_id": "admin-a",
            "payload": {"reason": "Safety issue"},
        }
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }
        live_server = SimpleNamespace(id="server-a")

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_server_blacklist=Mock(return_value=blacklist),
            finish_dashboard_action=Mock(return_value=True),
            purge_server_data=Mock(return_value={"dashboard_server_snapshots": 1}),
            get_public_dashboard_stats=Mock(return_value={"server_count": 0}),
        )
        bot.get_server = Mock(return_value=None)
        bot.fetch_server = AsyncMock(return_value=live_server)
        bot._enforce_server_blacklist = AsyncMock(
            return_value={"owner_notified": True, "left": True}
        )
        bot.update_bot_heartbeat = Mock()

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot.get_server.assert_called_once_with("server-a")
        bot.fetch_server.assert_awaited_once_with("server-a")
        bot._enforce_server_blacklist.assert_awaited_once_with(
            live_server, blacklist, source="admin_dashboard"
        )
        bot.database.finish_dashboard_action.assert_called_once_with(
            402,
            success=True,
            result={"owner_notified": True, "left": True},
        )
        bot.database.purge_server_data.assert_called_once_with("server-a")

    def test_blacklist_dashboard_action_fails_on_transient_server_lookup(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 403,
            "server_id": "server-a",
            "action": "blacklist_server",
            "actor_id": "admin-a",
            "payload": {"reason": "Safety issue"},
        }
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_server_blacklist=Mock(return_value=blacklist),
            finish_dashboard_action=Mock(return_value=True),
            purge_server_data=Mock(),
        )
        bot._resolve_dashboard_server = AsyncMock(
            side_effect=RuntimeError("temporary Stoat API failure")
        )
        bot._enforce_server_blacklist = AsyncMock()

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot._enforce_server_blacklist.assert_not_awaited()
        bot.database.finish_dashboard_action.assert_called_once_with(
            403,
            success=False,
            result={"error": "temporary Stoat API failure"},
        )
        bot.database.purge_server_data.assert_not_called()

    def test_blacklist_dashboard_action_does_not_accept_unconfirmed_leave(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 404,
            "server_id": "server-a",
            "action": "blacklist_server",
            "actor_id": "admin-a",
            "payload": {"reason": "Safety issue"},
        }
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_server_blacklist=Mock(return_value=blacklist),
            finish_dashboard_action=Mock(return_value=True),
            purge_server_data=Mock(),
        )
        bot._resolve_dashboard_server = AsyncMock(
            return_value=SimpleNamespace(id="server-a")
        )
        bot._enforce_server_blacklist = AsyncMock(
            return_value={"owner_notified": True, "left": False}
        )

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot.database.finish_dashboard_action.assert_called_once_with(
            404,
            success=False,
            result={
                "error": (
                    "Stoat did not confirm that Stoatmod left or was already "
                    "absent from the server."
                )
            },
        )
        bot.database.purge_server_data.assert_not_called()

    def test_blacklist_dashboard_action_accepts_confirmed_already_departed(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 405,
            "server_id": "server-a",
            "action": "blacklist_server",
            "actor_id": "admin-a",
            "payload": {"reason": "Safety issue"},
        }
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_server_blacklist=Mock(return_value=blacklist),
            finish_dashboard_action=Mock(return_value=True),
            purge_server_data=Mock(return_value={"dashboard_server_snapshots": 1}),
            get_public_dashboard_stats=Mock(return_value={"server_count": 0}),
        )
        bot._resolve_dashboard_server = AsyncMock(return_value=None)
        result = {
            "owner_notified": True,
            "left": False,
            "already_departed": True,
        }
        bot._enforce_server_blacklist = AsyncMock(return_value=result)
        bot.update_bot_heartbeat = Mock()

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot._enforce_server_blacklist.assert_awaited_once_with(
            None, blacklist, source="admin_dashboard"
        )
        bot.database.finish_dashboard_action.assert_called_once_with(
            405, success=True, result=result
        )
        bot.database.purge_server_data.assert_called_once_with("server-a")

    def test_server_blacklist_treats_leave_not_found_as_already_departed(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot._send_user_dm = AsyncMock(return_value=True)
        not_found = stoat.NotFound(
            SimpleNamespace(status=404), {"type": "NotFound"}
        )
        server = SimpleNamespace(
            id="server-a",
            name="Unsafe Community",
            owner_id="owner-a",
            leave=AsyncMock(side_effect=not_found),
        )

        result = asyncio.run(
            bot._enforce_server_blacklist(
                server,
                {
                    "server_id": "server-a",
                    "server_name": "Unsafe Community",
                    "owner_id": "owner-a",
                    "reason": "Safety issue",
                },
                source="admin_dashboard",
            )
        )

        self.assertFalse(result["left"])
        self.assertTrue(result["already_departed"])
        bot._send_user_dm.assert_awaited_once()
        server.leave.assert_awaited_once_with(silent=True)

    def test_server_blacklist_notifies_stored_owner_when_already_departed(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._send_user_dm = AsyncMock(return_value=True)

        result = asyncio.run(
            bot._enforce_server_blacklist(
                None,
                {
                    "server_id": "server-a",
                    "server_name": "Unsafe Community",
                    "owner_id": "owner-a",
                    "reason": "Safety issue",
                },
                source="admin_dashboard",
            )
        )

        self.assertFalse(result["left"])
        self.assertTrue(result["already_departed"])
        dm = bot._send_user_dm.await_args
        self.assertEqual(dm.args[0], "owner-a")
        self.assertIn("**Reason:** Safety issue", dm.args[2])

    def test_server_blacklist_propagates_transient_leave_failure(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot._send_user_dm = AsyncMock(return_value=True)
        server = SimpleNamespace(
            id="server-a",
            name="Unsafe Community",
            owner_id="owner-a",
            leave=AsyncMock(side_effect=RuntimeError("temporary leave failure")),
        )

        with self.assertRaisesRegex(RuntimeError, "temporary leave failure"):
            asyncio.run(
                bot._enforce_server_blacklist(
                    server,
                    {
                        "server_id": "server-a",
                        "server_name": "Unsafe Community",
                        "owner_id": "owner-a",
                        "reason": "Safety issue",
                    },
                    source="admin_dashboard",
                )
            )

        bot._send_user_dm.assert_awaited_once()
        server.leave.assert_awaited_once_with(silent=True)

    def test_blacklist_dashboard_action_leave_failure_never_purges(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 406,
            "server_id": "server-a",
            "action": "blacklist_server",
            "actor_id": "admin-a",
            "payload": {"reason": "Safety issue"},
        }
        blacklist = {
            "server_id": "server-a",
            "server_name": "Unsafe Community",
            "owner_id": "owner-a",
            "reason": "Safety issue",
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_server_blacklist=Mock(return_value=blacklist),
            finish_dashboard_action=Mock(return_value=True),
            purge_server_data=Mock(),
        )
        server = SimpleNamespace(
            id="server-a",
            name="Unsafe Community",
            owner_id="owner-a",
            leave=AsyncMock(side_effect=RuntimeError("temporary leave failure")),
        )
        bot.get_server = Mock(return_value=server)
        bot.fetch_server = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        server.leave.assert_awaited_once_with(silent=True)
        bot.database.finish_dashboard_action.assert_called_once_with(
            406,
            success=False,
            result={"error": "temporary leave failure"},
        )
        bot.database.purge_server_data.assert_not_called()
        self.assertIs(bot.database.get_server_blacklist("server-a"), blacklist)

    def test_report_outcome_dm_uses_reporter_and_includes_review_note(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            get_owner_report=Mock(return_value={
                "id": 17,
                "reference_id": "ABCD2345",
                "server_id": "server-a",
                "server_name": "Community Hub",
                "reporter_id": "reporter-id",
                "target_user_id": "target-id",
                "target_username": "target-name#1234",
                "status": "resolved",
                "review_note": "We reviewed the evidence and took action.",
                "reviewed_by": "owner-id",
            }),
            mark_reporter_notification=Mock(return_value=True),
            add_event=Mock(),
        )
        bot._send_user_dm = AsyncMock(return_value=True)

        result = asyncio.run(bot._notify_report_outcome(17))

        self.assertTrue(result["notified"])
        self.assertEqual(result["user_id"], "reporter-id")
        dm = bot._send_user_dm.await_args
        self.assertEqual(dm.args[0], "reporter-id")
        self.assertEqual(dm.args[1], "Your report was resolved")
        self.assertIn("**Report ID:** `ABCD2345`", dm.args[2])
        self.assertIn("**Reported user:** `target-name#1234`", dm.args[2])
        self.assertIn("**Moderator notes:** We reviewed the evidence", dm.args[2])
        self.assertEqual(dm.kwargs["server_id"], "server-a")
        bot.database.mark_reporter_notification.assert_called_once_with(
            17, success=True
        )
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "report_outcome_notified",
        )

    def test_report_outcome_dm_failure_is_recorded(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            get_owner_report=Mock(return_value={
                "server_id": "server-a",
                "reporter_id": "reporter-id",
                "target_user_id": "target-id",
                "status": "dismissed",
                "review_note": "",
                "reviewed_by": "owner-id",
            }),
            mark_reporter_notification=Mock(return_value=True),
            add_event=Mock(),
        )
        bot._send_user_dm = AsyncMock(return_value=False)

        with self.assertRaisesRegex(RuntimeError, "could not be reached"):
            asyncio.run(bot._notify_report_outcome(18))

        bot.database.mark_reporter_notification.assert_not_called()
        bot.database.add_event.assert_not_called()

    def test_report_outcome_worker_reschedules_transient_dm_failure(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 91,
            "server_id": "server-a",
            "action": "notify_report_outcome",
            "actor_id": "owner-id",
            "payload": {"report_id": 18},
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            defer_report_notification_action=Mock(return_value=True),
            mark_reporter_notification=Mock(),
            finish_dashboard_action=Mock(),
        )
        bot._notify_report_outcome = AsyncMock(
            side_effect=ReportNotificationDeliveryError(
                "The reporter could not be reached by direct message."
            )
        )

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot.database.defer_report_notification_action.assert_called_once_with(
            91,
            18,
            payload={"report_id": 18, "retry_count": 1},
            delay_seconds=REPORT_NOTIFICATION_RETRY_DELAYS[0],
            error=(
                "Delivery attempt 1 failed. Automatic retry 1 of "
                f"{len(REPORT_NOTIFICATION_RETRY_DELAYS)} is scheduled."
            ),
        )
        bot.database.mark_reporter_notification.assert_not_called()
        bot.database.finish_dashboard_action.assert_not_called()

    def test_report_outcome_worker_records_failure_after_retry_limit(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 92,
            "server_id": "server-a",
            "action": "notify_report_outcome",
            "actor_id": "owner-id",
            "payload": {
                "report_id": 18,
                "retry_count": len(REPORT_NOTIFICATION_RETRY_DELAYS),
            },
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            defer_report_notification_action=Mock(),
            mark_reporter_notification=Mock(),
            finish_dashboard_action=Mock(),
        )
        error = "The reporter could not be reached by direct message."
        bot._notify_report_outcome = AsyncMock(
            side_effect=ReportNotificationDeliveryError(error)
        )

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot.database.mark_reporter_notification.assert_called_once_with(
            18, success=False, error=error
        )
        bot.database.defer_report_notification_action.assert_not_called()
        bot.database.finish_dashboard_action.assert_called_once_with(
            92, success=False, result={"error": error}
        )

    def test_admin_credential_worker_dms_then_activates_without_persisting_secret(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://modstoat.site"
        )
        action = {
            "id": 301,
            "server_id": "global",
            "action": "deliver_admin_credentials",
            "actor_id": GLOBAL_COMMAND_OWNER_ID,
            "payload": {
                "user_id": "01H00000000000000000000004",
                "password_version": 1,
            },
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_admin_dashboard_account=Mock(return_value={
                "delivery_action_id": 301,
                "password_version": 1,
                "revoked_at": None,
                "active": False,
                "full_username": None,
            }),
            admin_dashboard_delivery_is_current=Mock(return_value=True),
            activate_admin_dashboard_account_credentials=Mock(return_value=True),
            finish_dashboard_action=Mock(),
        )
        user = SimpleNamespace(bot=None)
        bot.get_user = Mock(return_value=user)
        bot.fetch_user = AsyncMock()
        bot._resolve_user_tag = AsyncMock(return_value="staff#1200")
        bot._send_user_dm = AsyncMock(return_value=True)

        with (
            patch("bot.generate_temporary_password", return_value="SM-fixed-secret"),
            patch("bot.asyncio.sleep", new_callable=AsyncMock),
        ):
            asyncio.run(bot._run_dashboard_actions())

        bot._send_user_dm.assert_awaited_once()
        description = bot._send_user_dm.await_args.args[2]
        self.assertIn("https://modstoat.site/admin/login", description)
        self.assertIn("`01H00000000000000000000004`", description)
        self.assertIn("Credential version:** `1`", description)
        self.assertIn("`SM-fixed-secret`", description)
        activation = bot.database.activate_admin_dashboard_account_credentials
        activation.assert_called_once()
        self.assertTrue(verify_password("SM-fixed-secret", activation.call_args.args[3]))
        finish_result = bot.database.finish_dashboard_action.call_args.kwargs["result"]
        self.assertNotIn("SM-fixed-secret", str(finish_result))
        self.assertNotIn("password_hash", finish_result)
        bot.fetch_user.assert_not_awaited()
        self.assertEqual(
            bot.database.admin_dashboard_delivery_is_current.call_count, 2
        )

    def test_admin_credential_worker_stays_inactive_if_recheck_or_dm_fails(self) -> None:
        for label, delivery_states, dm_succeeds in (
            ("replaced_before_dm", [True, False], True),
            ("dm_failed", [True, True], False),
        ):
            with self.subTest(label=label):
                bot = ModerationBot.__new__(ModerationBot)
                bot._closing = False
                bot._last_heartbeat_write = float("inf")
                bot._state = SimpleNamespace(my_id="stoatmod-bot")
                bot.moderation_settings = SimpleNamespace(
                    dashboard_url="https://modstoat.site"
                )
                action = {
                    "id": 303,
                    "server_id": "global",
                    "action": "deliver_admin_credentials",
                    "actor_id": GLOBAL_COMMAND_OWNER_ID,
                    "payload": {
                        "user_id": "01H00000000000000000000006",
                        "password_version": 1,
                    },
                }

                def claim_once():
                    bot._closing = True
                    return [action]

                bot.database = SimpleNamespace(
                    queue_due_admin_password_rotations=Mock(return_value=0),                    claim_dashboard_actions=Mock(side_effect=claim_once),
                    get_admin_dashboard_account=Mock(return_value={
                        "delivery_action_id": 303,
                        "password_version": 1,
                        "revoked_at": None,
                        "active": False,
                        "full_username": None,
                    }),
                    admin_dashboard_delivery_is_current=Mock(
                        side_effect=delivery_states
                    ),
                    activate_admin_dashboard_account_credentials=Mock(
                        return_value=True
                    ),
                    finish_dashboard_action=Mock(),
                )
                user = SimpleNamespace(bot=None)
                bot.get_user = Mock(return_value=user)
                bot.fetch_user = AsyncMock()
                bot._resolve_user_tag = AsyncMock(return_value="staff#1200")
                bot._send_user_dm = AsyncMock(return_value=dm_succeeds)

                with (
                    patch(
                        "bot.generate_temporary_password",
                        return_value="SM-fixed-secret",
                    ),
                    patch("bot.asyncio.sleep", new_callable=AsyncMock),
                ):
                    asyncio.run(bot._run_dashboard_actions())

                bot.database.activate_admin_dashboard_account_credentials.assert_not_called()
                bot.database.finish_dashboard_action.assert_called_once()
                self.assertFalse(
                    bot.database.finish_dashboard_action.call_args.kwargs["success"]
                )
                if label == "replaced_before_dm":
                    bot._send_user_dm.assert_not_awaited()
                else:
                    bot._send_user_dm.assert_awaited_once()

    def test_stale_admin_credential_delivery_never_sends_or_activates(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        action = {
            "id": 302,
            "server_id": "global",
            "action": "deliver_admin_credentials",
            "actor_id": GLOBAL_COMMAND_OWNER_ID,
            "payload": {
                "user_id": "01H00000000000000000000005",
                "password_version": 1,
            },
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_admin_dashboard_account=Mock(return_value={
                "delivery_action_id": 999,
                "password_version": 2,
                "revoked_at": None,
                "active": False,
            }),
            admin_dashboard_delivery_is_current=Mock(),
            activate_admin_dashboard_account_credentials=Mock(),
            finish_dashboard_action=Mock(),
        )
        bot._send_user_dm = AsyncMock()
        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot._send_user_dm.assert_not_awaited()
        bot.database.activate_admin_dashboard_account_credentials.assert_not_called()
        bot.database.finish_dashboard_action.assert_called_once()
        self.assertFalse(bot.database.finish_dashboard_action.call_args.kwargs["success"])

    def test_captcha_kicks_attribute_clear_audit_reasons(self) -> None:
        for reason in (
            CAPTCHA_FAILED_ATTEMPTS_KICK_REASON,
            CAPTCHA_EXPIRED_KICK_REASON,
        ):
            with self.subTest(reason=reason):
                bot = ModerationBot.__new__(ModerationBot)
                bot._state = SimpleNamespace(my_id="bot-user")
                bot._pending_kick_attribution = {}
                member = SimpleNamespace(kick=AsyncMock())

                asyncio.run(
                    bot._kick_member_with_reason(
                        member, "server", "member", reason
                    )
                )

                member.kick.assert_awaited_once_with()
                self.assertEqual(
                    bot._pending_kick_attribution[("server", "member")],
                    ("bot-user", reason),
                )

    def test_failed_captcha_kick_clears_pending_attribution(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot-user")
        bot._pending_kick_attribution = {}
        member = SimpleNamespace(kick=AsyncMock(side_effect=RuntimeError("failed")))

        with self.assertRaises(RuntimeError):
            asyncio.run(
                bot._kick_member_with_reason(
                    member, "server", "member", CAPTCHA_FAILED_ATTEMPTS_KICK_REASON
                )
            )

        self.assertNotIn(("server", "member"), bot._pending_kick_attribution)

    def test_expired_failed_web_verification_uses_recorded_risk_reason(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        challenge = CaptchaChallenge(
            "server", "member", "token-hash", "web", expires_at,
            "2026-08-23T01:10:00+00:00", 0,
        )
        current = CaptchaChallenge(
            "server", "member", "token-hash", "web", expires_at,
            "2026-08-23T01:10:00+00:00", 1,
        )
        member = SimpleNamespace()
        server = SimpleNamespace(
            name="Test server",
            get_member=Mock(return_value=member),
        )
        bot.database = SimpleNamespace(
            get_captcha_challenge=Mock(return_value=current),
            get_latest_captcha_failure_reason=Mock(
                return_value="IP registered to Data Centre"
            ),
            remove_captcha_challenge=Mock(),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=server)
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._kick_member_with_reason = AsyncMock()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot._captcha_tasks = {}

        asyncio.run(bot._expire_captcha(challenge))

        bot.database.get_latest_captcha_failure_reason.assert_called_once_with(
            "server", "member", since=current.created_at
        )
        bot._kick_member_with_reason.assert_awaited_once_with(
            member, "server", "member", "IP registered to Data Centre"
        )
        event = bot.database.add_event.call_args.kwargs
        self.assertEqual(event["details"]["reason"], "IP registered to Data Centre")
        self.assertEqual(
            event["details"]["result"], "kicked_after_failed_verification"
        )
        self.assertNotIn(
            CAPTCHA_EXPIRED_KICK_REASON,
            bot._send_user_dm.await_args.args[2],
        )

    def test_resume_recovers_web_challenge_without_issued_event(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        challenge = CaptchaChallenge(
            "server", "member", "token-hash", "web",
            "2099-01-01T00:30:00+00:00", "2099-01-01T00:00:00+00:00",
        )
        member = SimpleNamespace(timeout=AsyncMock())
        server = SimpleNamespace(
            get_member=Mock(return_value=member),
            fetch_member=AsyncMock(return_value=member),
        )
        bot.database = SimpleNamespace(
            get_join_protection=Mock(return_value=True),
            get_captcha_all_members=Mock(return_value=False),
            list_captcha_challenges=Mock(return_value=[challenge]),
            captcha_challenge_was_issued=Mock(return_value=False),
            remove_captcha_challenge=Mock(return_value=True),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=None)
        bot.fetch_server = AsyncMock(return_value=server)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._schedule_captcha_expiry = Mock()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        asyncio.run(bot.resume_captcha_challenges())

        bot._schedule_captcha_expiry.assert_not_called()
        bot.database.remove_captcha_challenge.assert_called_once_with(
            "server", "member"
        )
        bot.fetch_server.assert_awaited_once_with("server")
        member.timeout.assert_awaited_once_with(None)
        recovered = bot.database.add_event.call_args.kwargs
        self.assertEqual(recovered["event_type"], "join_captcha_recovered_unissued")
        self.assertTrue(recovered["details"]["restriction_removed"])

    def test_resume_schedules_confirmed_web_and_legacy_challenges(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        confirmed = CaptchaChallenge(
            "server", "confirmed", "token-hash", "web",
            "2099-01-01T00:30:00+00:00", "2099-01-01T00:00:00+00:00",
        )
        legacy = CaptchaChallenge(
            "server", "legacy", "answer-hash", "salt",
            "2099-01-01T00:30:00+00:00", "2099-01-01T00:05:00+00:00",
        )
        bot.database = SimpleNamespace(
            get_join_protection=Mock(return_value=True),
            get_captcha_all_members=Mock(return_value=False),
            list_captcha_challenges=Mock(return_value=[confirmed, legacy]),
            captcha_challenge_was_issued=Mock(return_value=True),
        )
        bot._schedule_captcha_expiry = Mock()

        asyncio.run(bot.resume_captcha_challenges())

        self.assertEqual(
            bot._schedule_captcha_expiry.call_args_list,
            [call(confirmed), call(legacy)],
        )
        bot.database.captcha_challenge_was_issued.assert_called_once_with(
            "server", "confirmed", since=confirmed.created_at
        )

    def test_kick_helper_preserves_initiating_moderator_and_reason(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot-user")
        bot._pending_kick_attribution = {}
        member = SimpleNamespace(kick=AsyncMock())

        asyncio.run(
            bot._kick_member_with_reason(
                member, "server", "member", "Repeated spam",
                actor_id="moderator",
            )
        )

        self.assertEqual(
            bot._pending_kick_attribution[("server", "member")],
            ("moderator", "Repeated spam"),
        )

    def test_external_kick_is_explicitly_marked_as_not_stoatmod(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._global_ban_removal_suppressions = set()
        bot._pending_kick_attribution = {}
        bot.database = SimpleNamespace(
            record_daily_member_change=Mock(),
            adjust_dashboard_member_count=Mock(),
            remove_dashboard_member=Mock(),
            add_event=Mock(return_value=7),
        )
        bot._event_case_line = Mock(return_value="")
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        event = SimpleNamespace(
            server_id="server", user_id="member",
            reason=stoat.MemberRemovalIntention.kick,
        )

        asyncio.run(bot.handle_member_remove(event))

        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertFalse(details["stoatmod_initiated"])
        self.assertIn("did not initiate", details["attribution_note"])
        self.assertIn("did not initiate", bot.send_log.await_args.args[2])

    def test_stoatmod_kick_uses_registered_reason(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._global_ban_removal_suppressions = set()
        bot._pending_kick_attribution = {
            ("server", "member"): ("bot-user", "Failed CAPTCHA")
        }
        bot.database = SimpleNamespace(
            record_daily_member_change=Mock(),
            adjust_dashboard_member_count=Mock(),
            remove_dashboard_member=Mock(),
            add_event=Mock(return_value=8),
        )
        bot._event_case_line = Mock(return_value="")
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        event = SimpleNamespace(
            server_id="server", user_id="member",
            reason=stoat.MemberRemovalIntention.kick,
        )

        asyncio.run(bot.handle_member_remove(event))

        call = bot.database.add_event.call_args
        self.assertEqual(call.kwargs["actor_id"], "bot-user")
        self.assertEqual(call.kwargs["details"]["reason"], "Failed CAPTCHA")
        self.assertTrue(call.kwargs["details"]["stoatmod_initiated"])
        self.assertNotIn("did not initiate", bot.send_log.await_args.args[2])

    def test_periodic_global_ban_sync_uses_current_connected_servers(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot.moderation_settings = SimpleNamespace(global_ban_sync_seconds=300)
        first_server = SimpleNamespace(id="one")
        second_server = SimpleNamespace(id="two")

        async def sync_once(servers: list[object]) -> None:
            self.assertEqual(servers, [first_server, second_server])
            bot._closing = True

        bot.sync_global_bans = AsyncMock(side_effect=sync_once)
        with (
            patch.object(
                ModerationBot,
                "servers",
                new_callable=PropertyMock,
                return_value={"one": first_server, "two": second_server},
            ),
            patch("bot.asyncio.sleep", new=AsyncMock(return_value=None)),
        ):
            asyncio.run(bot._run_global_ban_sync())

        bot.sync_global_bans.assert_awaited_once()

    def test_periodic_global_ban_sync_uses_ready_servers_during_startup(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot._closing = False
        bot.moderation_settings = SimpleNamespace(global_ban_sync_seconds=300)
        server = SimpleNamespace(id="often", name="Often Clan")
        bot._ready_event_servers = {server.id: server}

        async def sync_once(servers):
            self.assertEqual(servers, [server])
            bot._closing = True

        bot.sync_global_bans = AsyncMock(side_effect=sync_once)
        with patch.object(ModerationBot, "servers", new_callable=PropertyMock, return_value={}), patch("bot.asyncio.sleep", new=AsyncMock()):
            asyncio.run(bot._run_global_ban_sync())
        bot.sync_global_bans.assert_awaited_once_with([server])

    def test_global_ban_uses_filtered_ready_servers_before_cache_is_populated(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        server = SimpleNamespace(id="often", name="Often Clan", fetch_bans=AsyncMock(return_value=[]), ban=AsyncMock())
        stale = SimpleNamespace(id="blacklisted", name="Excluded server", ban=AsyncMock())
        bot._ready_event_servers = {server.id: server}
        bot._global_ban_removal_suppressions = set()
        bot._server_has_member = AsyncMock(return_value=True)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.database = SimpleNamespace(add_event=Mock())
        bot.send_log = AsyncMock()
        with patch.object(ModerationBot, "servers", new_callable=PropertyMock, return_value={stale.id: stale}):
            result = asyncio.run(bot._apply_global_ban_to_servers("sweet", "scam", reference_id="ABC123"))
            self.assertEqual(result, (["Often Clan"], []))
            server.ban.assert_awaited_once_with("sweet", reason="Global ban ABC123: scam")
            stale.ban.assert_not_awaited()
            bot._ready_event_servers = {}
            self.assertEqual(bot._global_ban_servers(), [])

    def test_global_ban_counts_missing_ban_permission_as_a_failure(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        server = SimpleNamespace(id="server", name="No permission", ban=AsyncMock())
        bot._ready_event_servers = {server.id: server}
        bot._server_has_member = AsyncMock(return_value=True)
        bot.require_action_permissions = AsyncMock(return_value=False)
        result = asyncio.run(bot._apply_global_ban_to_servers("sweet", "scam", reference_id="ABC123"))
        self.assertEqual(result, ([], ["No permission"]))
        server.ban.assert_not_awaited()

    def test_dashboard_keyword_automation_deletes_matching_message(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            list_automation_rules=Mock(return_value=[{
                "id": 1, "name": "Spoiler cleanup", "enabled": True,
                "trigger_type": "keyword", "trigger_value": "spoiler",
                "action_type": "delete_message", "action_config": {},
            }]),
            add_event=Mock(),
        )
        bot.require_action_permissions = AsyncMock(return_value=True)
        server = SimpleNamespace(id="server")
        message = SimpleNamespace(
            content="This contains a SPOILER", author_id="user", id="message",
            channel_id="channel", attachments=[], delete=AsyncMock(),
            get_server=Mock(return_value=(server, "server")),
        )

        deleted = asyncio.run(bot.handle_dashboard_automations(message))

        self.assertTrue(deleted)
        message.delete.assert_awaited_once()
        bot.database.add_event.assert_called_once()

    def test_dashboard_link_automation_allows_gifbox_links(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            list_automation_rules=Mock(return_value=[{
                "id": 1, "name": "Link cleanup", "enabled": True,
                "trigger_type": "contains_link", "trigger_value": "",
                "action_type": "delete_message", "action_config": {},
            }]),
            add_event=Mock(),
            get_allow_gifs=Mock(return_value=True),
        )
        bot.require_action_permissions = AsyncMock(return_value=True)
        message = SimpleNamespace(
            content="Watch https://media.gifbox.me/animation/123", author_id="user",
            id="message", channel_id="channel", attachments=[], delete=AsyncMock(),
            get_server=Mock(return_value=(SimpleNamespace(id="server"), "server")),
        )

        deleted = asyncio.run(bot.handle_dashboard_automations(message))

        self.assertFalse(deleted)
        message.delete.assert_not_awaited()
        bot.database.add_event.assert_not_called()

    def test_dashboard_automation_matches_username_nickname_and_context_conditions(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        user = SimpleNamespace(
            name="GuestAccount", created_at=datetime.now(timezone.utc) - timedelta(days=2)
        )
        member = SimpleNamespace(nick="Fresh Guest", role_ids=["newcomer"])
        server = SimpleNamespace(
            get_member=Mock(return_value=member), fetch_member=AsyncMock(return_value=member)
        )
        message = SimpleNamespace(
            author_id="user", channel_id="welcome", content="hello everyone",
            mentions=["one", "two"], embeds=[object()],
            get_author_as_user=Mock(return_value=user),
        )
        rule = {
            "condition_mode": "all",
            "conditions": [
                {"type": "username_contains", "value": "guest"},
                {"type": "nickname_contains", "value": "fresh"},
                {"type": "role_has", "value": "newcomer"},
                {"type": "channel_is", "value": "welcome"},
                {"type": "message_starts_with", "value": "hello"},
                {"type": "mention_count_min", "value": "2"},
                {"type": "account_age_days_max", "value": "7"},
                {"type": "has_embed", "value": ""},
            ],
        }

        self.assertTrue(asyncio.run(
            bot._automation_conditions_match(message, server, rule)
        ))

    def test_command_response_falls_back_to_text_without_embed_permission(self) -> None:
        bot = object.__new__(ModerationBot)
        channel = SimpleNamespace(
            send=AsyncMock(
                side_effect=[PermissionError("missing Send Embeds"), None]
            )
        )
        message = SimpleNamespace(channel=channel, channel_id="channel-a")

        asyncio.run(
            bot.send_command_response(
                message,
                "Stoatmod setup audit",
                "**Bot permissions**\n❌ Send Embeds\n✅ Send Messages",
            )
        )

        self.assertEqual(channel.send.await_count, 2)
        embed_attempt, text_fallback = channel.send.await_args_list
        self.assertIn("embeds", embed_attempt.kwargs)
        self.assertIn("Bot permissions", text_fallback.kwargs["content"])
        self.assertIn("❌ Send Embeds", text_fallback.kwargs["content"])

    def test_dashboard_member_snapshot_pairs_bulk_user_profiles(self) -> None:
        user = SimpleNamespace(
            id="member-a",
            name="stoat-user",
            display_name="Stoat User",
            discriminator="1234",
            avatar=None,
            created_at=None,
            bot=None,
            online=True,
        )
        member = SimpleNamespace(
            id="member-a",
            get_user=lambda: None,
            server_avatar=None,
            joined_at=None,
            role_ids=["role-a"],
            timed_out_until=None,
        )

        server = SimpleNamespace(
            id="server",
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_server=True)
            ),
        )
        snapshot = ModerationBot._dashboard_member_snapshot(
            [member], [user], server=server
        )

        self.assertEqual(snapshot[0]["username"], "stoat-user")
        self.assertEqual(snapshot[0]["display_name"], "Stoat User")
        self.assertTrue(snapshot[0]["online"])
        self.assertTrue(snapshot[0]["manage_server"])

    def test_member_role_update_refreshes_manage_server_dashboard_access(self) -> None:
        bot = object.__new__(ModerationBot)
        user = SimpleNamespace(
            id="manager",
            name="manager",
            display_name="Manager",
            discriminator="1000",
            avatar=None,
            created_at=None,
            bot=None,
            online=True,
        )
        member = SimpleNamespace(
            id="manager",
            server_id="server",
            get_user=Mock(return_value=user),
            server_avatar=None,
            joined_at=None,
            role_ids=["manager-role"],
            timed_out_until=None,
        )
        server = SimpleNamespace(
            id="server",
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_server=True)
            ),
        )
        bot.get_server = Mock(return_value=server)
        bot.database = SimpleNamespace(upsert_dashboard_member=Mock())
        event = SimpleNamespace(
            member=SimpleNamespace(
                id="manager", server_id="server", nick=stoat.UNDEFINED
            ),
            after=member,
        )

        asyncio.run(bot.handle_member_nickname_update(event))

        saved = bot.database.upsert_dashboard_member.call_args.args[1]
        self.assertTrue(saved["manage_server"])


    def test_user_tag_resolution_uses_recorded_identity_when_live_fetch_fails(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.get_user = Mock(return_value=None)
        bot.fetch_user = AsyncMock(side_effect=LookupError("user unavailable"))
        bot.database = SimpleNamespace(
            get_recorded_user_identity=Mock(
                return_value={"full_username": "remembered-user#9001"}
            )
        )

        tag = asyncio.run(bot._resolve_user_tag("user-id"))

        self.assertEqual(tag, "remembered-user#9001")

    def test_command_like_messages_do_not_count_towards_statistics(self) -> None:
        for content in ("~help", " /ban user", "!ping", "   ~dashboard"):
            self.assertFalse(counts_towards_message_statistics(content))
        for content in ("hello", "a normal message", ""):
            self.assertTrue(counts_towards_message_statistics(content))

    @staticmethod
    def _spam_bot() -> ModerationBot:
        bot = object.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(
            spam_repeat_count=3,
            spam_repeat_window_seconds=30,
            spam_rapid_count=5,
            spam_rapid_window_seconds=10,
        )
        bot._spam_history = {}
        bot._spam_scores = {}
        bot._spam_timeout_until = {}
        return bot

    def test_user_tag_includes_username_and_discriminator(self) -> None:
        user = SimpleNamespace(name="moderator", discriminator="0420")

        self.assertEqual(ModerationBot._format_user_tag(user), "moderator#0420")

    def test_user_tag_uses_username_when_discriminator_is_unavailable(self) -> None:
        user = SimpleNamespace(name="looked-up-user", discriminator=None)

        self.assertEqual(ModerationBot._format_user_tag(user), "looked-up-user")

    def test_unknown_user_is_looked_up_by_user_id(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.get_user = Mock(return_value=None)
        bot.fetch_user = AsyncMock(
            return_value=SimpleNamespace(name="looked-up-user", discriminator=None)
        )

        resolved = asyncio.run(bot._resolve_user_tag("user-id"))

        self.assertEqual(resolved, "looked-up-user")
        bot.fetch_user.assert_awaited_once_with("user-id")

    def test_failed_user_id_lookup_keeps_unknown_user(self) -> None:
        bot = ModerationBot.__new__(ModerationBot)
        bot.get_user = Mock(return_value=None)
        bot.fetch_user = AsyncMock(side_effect=LookupError("not found"))

        resolved = asyncio.run(bot._resolve_user_tag("missing-user-id"))

        self.assertEqual(resolved, "Unknown user")

    def test_rotating_statuses_include_current_server_count(self) -> None:
        bot = object.__new__(ModerationBot)
        visible_servers = {
            "server-a": SimpleNamespace(),
            "server-b": SimpleNamespace(),
        }

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value=visible_servers,
        ):
            self.assertEqual(
                bot.rotating_statuses(),
                (
                    "~help for commands",
                    "monitoring..",
                    "watching over 2 servers",
                ),
            )

    def test_status_count_uses_ready_membership_and_tracks_joins_and_leaves(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._status_server_ids = {"server-a", "server-b"}
        with patch.object(ModerationBot, "servers", new_callable=PropertyMock, return_value={}):
            self.assertEqual(bot.rotating_statuses()[2], "watching over 2 servers")
            bot._track_status_server("server-c", connected=True)
            bot._track_status_server("server-c", connected=True)
            self.assertEqual(bot.rotating_statuses()[2], "watching over 3 servers")
            bot._track_status_server("server-a", connected=False)
            bot._track_status_server("server-a", connected=False)
            self.assertEqual(bot.rotating_statuses()[2], "watching over 2 servers")
            bot._status_server_ids = set()
            self.assertEqual(bot.rotating_statuses()[2], "watching over 0 servers")

    def test_status_rotation_uses_latest_user_after_reconnect(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._status_task = Mock(done=Mock(return_value=False))
        bot._status_user = SimpleNamespace(name="old")
        replacement = SimpleNamespace(name="new")

        bot.start_status_rotation(replacement)

        self.assertIs(bot._status_user, replacement)

    def test_status_update_advances_only_after_success(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._status_index = 0
        bot._status_user = SimpleNamespace(edit=AsyncMock())
        bot.rotating_statuses = Mock(return_value=("first", "second", "third"))

        updated = asyncio.run(bot._update_rotating_status())

        self.assertEqual(updated, "first")
        self.assertEqual(bot._status_index, 1)
        status = bot._status_user.edit.await_args.kwargs["status"]
        self.assertEqual(status.text, "first")
        self.assertIs(status.presence, stoat.Presence.online)

    def test_timed_out_status_update_can_be_retried(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._status_index = 0
        bot._status_user = SimpleNamespace(edit=AsyncMock())
        bot.rotating_statuses = Mock(return_value=("first", "second", "third"))

        with patch("bot.STATUS_UPDATE_TIMEOUT_SECONDS", 0):
            with self.assertRaises(asyncio.TimeoutError):
                asyncio.run(bot._update_rotating_status())
        self.assertEqual(bot._status_index, 0)

        bot._last_status_update_attempt = None
        updated = asyncio.run(bot._update_rotating_status())
        self.assertEqual(updated, "first")
        self.assertEqual(bot._status_index, 1)

    def test_status_updates_enforce_stoat_user_edit_window(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._last_status_update_attempt = 100.0
        bot._status_clock = Mock(side_effect=[105.0, 110.0])

        with patch("bot.asyncio.sleep", new_callable=AsyncMock) as sleep:
            asyncio.run(bot._wait_for_status_edit_slot())

        sleep.assert_awaited_once_with(5.0)
        self.assertEqual(bot._last_status_update_attempt, 110.0)

    def test_stopped_status_task_schedules_automatic_restart(self) -> None:
        bot = object.__new__(ModerationBot)
        task = Mock()
        task.cancelled.return_value = False
        task.exception.return_value = None
        bot._status_task = task
        bot._closing = False
        loop = Mock()

        with patch("bot.asyncio.get_running_loop", return_value=loop):
            bot._status_rotation_stopped(task)

        self.assertIsNone(bot._status_task)
        loop.call_later.assert_called_once_with(
            5, bot._restart_status_rotation
        )

    def test_stopped_dashboard_action_worker_schedules_restart(self) -> None:
        bot = object.__new__(ModerationBot)
        task = Mock()
        task.cancelled.return_value = False
        task.exception.return_value = RuntimeError("worker crashed")
        bot._dashboard_action_task = task
        bot._closing = False
        loop = Mock()

        with (
            patch("bot.asyncio.get_running_loop", return_value=loop),
            patch("bot.logger.error") as log_error,
        ):
            bot._dashboard_action_worker_stopped(task)

        self.assertIsNone(bot._dashboard_action_task)
        log_error.assert_called_once()
        loop.call_later.assert_called_once_with(
            5, bot._restart_dashboard_action_worker
        )

    def test_repeated_consecutive_messages_are_spam(self) -> None:
        bot = self._spam_bot()

        self.assertIsNone(bot._detect_spam("server", "user", "Hello", now=0))
        self.assertIsNone(bot._detect_spam("server", "user", " hello ", now=2))
        reason = bot._detect_spam("server", "user", "HELLO", now=4)

        self.assertIn("repeated the same message", reason or "")

    def test_rapid_messages_are_spam(self) -> None:
        bot = self._spam_bot()

        for index in range(4):
            self.assertIsNone(
                bot._detect_spam("server", "user", str(index), now=float(index))
            )
        reason = bot._detect_spam("server", "user", "four", now=4)

        self.assertIn("sent 5 messages", reason or "")

    def test_spam_detection_uses_per_server_thresholds(self) -> None:
        bot = self._spam_bot()
        custom = {
            "repeat_count": 4,
            "repeat_window_seconds": 12,
            "rapid_count": 20,
            "rapid_window_seconds": 10,
            "score_threshold": 100,
            "score_half_life_seconds": 5,
            "mass_mention_limit": 8,
            "timeout_seconds": 600,
        }
        bot.database = SimpleNamespace(
            get_spam_settings=Mock(return_value=custom)
        )

        for now in (0, 2, 4):
            self.assertIsNone(bot._detect_spam("server", "user", "same", now=now))
        reason = bot._detect_spam("server", "user", "same", now=6)

        self.assertIn("repeated the same message 4 times", reason or "")
        bot.database.get_spam_settings.assert_called_with(
            "server", ANY
        )

    def test_spam_history_is_separate_per_user_and_server(self) -> None:
        bot = self._spam_bot()

        for now in (0, 1):
            bot._detect_spam("server-a", "user-a", "same", now=now)

        self.assertIsNone(bot._detect_spam("server-a", "user-b", "same", now=2))
        self.assertIsNone(bot._detect_spam("server-b", "user-a", "same", now=2))

    def test_near_duplicate_messages_build_a_spam_score(self) -> None:
        bot = self._spam_bot()

        messages = (
            "Limited offer for everyone today",
            "Limited offer for everybody today!",
            "Limited offer for everybody today!!",
            "Limited offer for everybody today!!!",
            "Limited offer for everybody today!!!!",
        )
        reason = None
        for index, content in enumerate(messages):
            reason = bot._detect_spam(
                "server", "user", content, now=float(index * 3)
            )

        self.assertIn("spam score", reason or "")

    def test_mass_mention_detection_counts_unique_users_and_roles(self) -> None:
        bot = self._spam_bot()
        bot.moderation_settings.mass_mention_limit = 5
        message = SimpleNamespace(
            mention_ids=["u1", "u2", "u3", "u3"],
            role_mention_ids=["r1", "r2"],
            raw_flags=0,
        )

        reason = bot._mass_mention_reason(message)

        self.assertIn("mentioned 5 users or roles", reason or "")

    def test_a_single_everyone_mention_is_allowed_but_two_are_a_mass_mention(self) -> None:
        bot = self._spam_bot()
        bot.moderation_settings.mass_mention_limit = 5
        single = SimpleNamespace(
            mention_ids=[], role_mention_ids=[], raw_flags=1 << 1, content="@everyone hi"
        )
        double = SimpleNamespace(
            mention_ids=[], role_mention_ids=[], raw_flags=1 << 1, content="@everyone @everyone hi"
        )

        self.assertIsNone(bot._mass_mention_reason(single))
        self.assertIn("@everyone", bot._mass_mention_reason(double) or "")

    def test_category_lookup_falls_back_to_category_channel_list(self) -> None:
        category = SimpleNamespace(id="category", channels=["channel"])
        server = SimpleNamespace(categories=[category])
        channel = SimpleNamespace(category_id=None)

        self.assertEqual(
            ModerationBot._category_id_for_channel(server, "channel", channel),
            "category",
        )

    def test_mature_nsfw_channels_are_out_of_scope(self) -> None:
        self.assertTrue(
            ModerationBot._channel_is_nsfw(SimpleNamespace(nsfw=True))
        )
        self.assertFalse(
            ModerationBot._channel_is_nsfw(SimpleNamespace(nsfw=False))
        )
        self.assertFalse(ModerationBot._channel_is_nsfw(None))

    def test_channel_mentions_are_normalized(self) -> None:
        self.assertEqual(
            ModerationBot._parse_channel_id("<#01CHANNEL>"), "01CHANNEL"
        )

    def test_case_ids_accept_random_alphanumeric_references(self) -> None:
        self.assertEqual(
            ModerationBot._parse_case_id("CASE-K7M2Q9XA"), "K7M2Q9XA"
        )
        self.assertEqual(
            ModerationBot._parse_case_id("case#k7m2q9xa"), "K7M2Q9XA"
        )
        self.assertEqual(ModerationBot._parse_case_id("K7M2Q9XA"), "K7M2Q9XA")
        self.assertEqual(ModerationBot._parse_case_id("case_k7m2q9xa"), "K7M2Q9XA")
        self.assertEqual(ModerationBot._parse_case_id("case k7m2q9xa"), "K7M2Q9XA")
        self.assertEqual(ModerationBot._parse_case_id("CASE-[42]"), "42")
        self.assertEqual(ModerationBot._parse_case_id("case_00000042"), "00000042")
        self.assertEqual(ModerationBot._parse_case_id("42"), "42")
        self.assertIsNone(ModerationBot._parse_case_id("CASE-ABCDEFGH"))
        self.assertIsNone(ModerationBot._parse_case_id("CASE-too-short"))

    def test_appeal_decisions_accept_common_aliases(self) -> None:
        for value in ("accept", "accepted", "approve", "approved", "[yes]"):
            self.assertEqual(ModerationBot._appeal_decision(value), "approved")
        for value in ("deny", "denied", "reject", "rejected", "[no]"):
            self.assertEqual(ModerationBot._appeal_decision(value), "denied")
        self.assertIsNone(ModerationBot._appeal_decision("maybe"))

    def test_threshold_percentage_parser_accepts_percentage_values(self) -> None:
        self.assertEqual(ModerationBot._parse_threshold_percentage("75%"), 0.75)
        self.assertEqual(ModerationBot._parse_threshold_percentage("82.5"), 0.825)
        self.assertEqual(ModerationBot._parse_threshold_percentage("0"), 0)
        self.assertEqual(ModerationBot._parse_threshold_percentage("100"), 1)
        self.assertIsNone(ModerationBot._parse_threshold_percentage("101"))
        self.assertIsNone(ModerationBot._parse_threshold_percentage("nope"))

    def test_blocked_categories_use_each_servers_threshold(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(threshold=0.7)
        bot.database = SimpleNamespace(
            get_moderation_threshold=Mock(
                side_effect=lambda server_id, default: {
                    "strict": 0.91,
                    "lenient": 0.96,
                }.get(server_id, default)
            ),
            is_moderation_category_disabled=Mock(return_value=False),
        )
        result = ModerationResult(
            flagged=True,
            categories={"illicit": True},
            scores={"illicit": 0.93},
        )

        self.assertEqual(
            [match["category"] for match in bot._moderation_policy_matches("strict", result)], ["illicit"]
        )
        self.assertEqual(
            [match["category"] for match in bot._moderation_policy_matches("lenient", result)], []
        )

    def test_policy_counts_must_be_positive_and_increasing(self) -> None:
        self.assertEqual(ModerationBot._parse_policy_counts("3 5 7"), (3, 5, 7))
        self.assertIsNone(ModerationBot._parse_policy_counts("3 3 7"))
        self.assertIsNone(ModerationBot._parse_policy_counts("0 5 7"))
        self.assertIsNone(ModerationBot._parse_policy_counts("three five seven"))

    def test_mute_durations_use_compact_units_and_limit(self) -> None:
        self.assertEqual(ModerationBot._parse_duration("30m"), 1800)
        self.assertEqual(ModerationBot._parse_duration("2H"), 7200)
        self.assertEqual(ModerationBot._parse_duration("1d"), 86400)
        self.assertEqual(ModerationBot._parse_duration("4w"), 2419200)
        self.assertIsNone(ModerationBot._parse_duration("29d"))
        self.assertIsNone(ModerationBot._parse_duration("forever"))
        self.assertEqual(ModerationBot._format_duration(3600), "1 hour")

    @staticmethod
    def _manual_action_fixture() -> tuple[
        ModerationBot, SimpleNamespace, SimpleNamespace, SimpleNamespace
    ]:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(
            name="target",
            discriminator="0001",
            timeout=AsyncMock(),
        )
        server = SimpleNamespace(
            name="Test server",
            get_member=Mock(return_value=member),
            fetch_member=AsyncMock(return_value=member),
            ban=AsyncMock(),
        )
        message = SimpleNamespace(
            author_id="moderator",
            channel_id="commands",
            get_author_as_user=Mock(
                return_value=SimpleNamespace(
                    name="moderator", discriminator="0002"
                )
            ),
        )
        bot.database = SimpleNamespace(add_event=Mock(return_value=42))
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._member_is_moderator = Mock(return_value=False)
        bot._resolve_user_tag = AsyncMock(
            side_effect=lambda user_id, _user=None: (
                "moderator#0002"
                if user_id == "moderator"
                else "target#0001"
            )
        )
        bot._event_case_line = Mock(return_value="**Case:** CASE42\n")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)
        bot._kick_member_with_reason = AsyncMock()
        bot._pending_kick_attribution = {}
        bot._pending_ban_attribution = {}
        return bot, server, member, message

    def test_manual_unmute_notifies_member_after_success(self) -> None:
        bot, server, member, message = self._manual_action_fixture()

        asyncio.run(bot.handle_timeout_command(
            message, server, "server", "~unmute", ["~unmute", "target", "Appeal accepted"]
        ))

        member.timeout.assert_awaited_once_with(None)
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "manual_unmute",
        )
        bot._send_user_dm.assert_awaited_once_with(
            "target",
            "You have been unmuted",
            "Your mute in **Test server** was removed by a moderator.\n\n**Reason:** Appeal accepted",
            server_id="server",
            user=member,
        )

    def test_manual_mute_notifies_member_with_reason(self) -> None:
        bot, server, member, message = self._manual_action_fixture()

        asyncio.run(bot.handle_timeout_command(
            message, server, "server", "~mute", ["~mute", "target", "30m Repeated spam"]
        ))

        member.timeout.assert_awaited_once_with(timedelta(seconds=1800))
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "manual_mute",
        )
        bot._send_user_dm.assert_awaited_once()
        self.assertEqual(bot._send_user_dm.await_args.args[1], "You have been muted")
        self.assertIn("Repeated spam", bot._send_user_dm.await_args.args[2])

    def test_manual_kick_completes_without_unmute_notification(self) -> None:
        bot, server, member, message = self._manual_action_fixture()

        asyncio.run(bot.handle_kick_ban_command(
            message, server, "server", "~kick",
            ["~kick", "target", "Repeated", "abuse"],
        ))

        bot._kick_member_with_reason.assert_awaited_once_with(
            member,
            "server",
            "target",
            "Repeated abuse",
            actor_id="moderator",
        )
        bot.send_command_response.assert_awaited_once()
        bot._send_user_dm.assert_not_awaited()

    def test_manual_ban_completes_without_unmute_notification(self) -> None:
        bot, server, _member, message = self._manual_action_fixture()

        asyncio.run(bot.handle_kick_ban_command(
            message, server, "server", "~ban",
            ["~ban", "target", "Repeated", "abuse"],
        ))

        server.ban.assert_awaited_once_with(
            "target", reason="Repeated abuse"
        )
        self.assertEqual(
            bot._pending_ban_attribution[("server", "target")],
            ("moderator", "Repeated abuse"),
        )
        bot.send_command_response.assert_awaited_once()
        bot._send_user_dm.assert_not_awaited()

    def test_default_policy_times_out_at_three_warnings(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(
            timeout=AsyncMock(),
            name="member",
            discriminator="1234",
        )
        permissions = SimpleNamespace(
            manage_messages=False,
            kick_members=False,
            ban_members=False,
            manage_server=False,
        )
        server = SimpleNamespace(
            name="Test server",
            get_member=Mock(return_value=member),
            permissions_for=Mock(return_value=permissions),
        )
        database = SimpleNamespace(
            get_warning_policy=Mock(return_value=WarningPolicy()),
            claim_warning_policy_action=Mock(return_value=True),
            release_warning_policy_action=Mock(),
            add_event=Mock(),
        )
        bot.database = database
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)

        asyncio.run(
            bot.enforce_warning_policy(server, "server", "user", 30, 3)
        )

        member.timeout.assert_awaited_once_with(timedelta(hours=1))
        database.claim_warning_policy_action.assert_called_once_with(
            "server", "user", "timeout", 3, 30
        )
        bot._send_user_dm.assert_awaited_once()

    def test_unsafe_nickname_is_restored_warned_and_sent_to_policy(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.moderation_settings = SimpleNamespace(threshold=0.7)
        bot._nickname_reset_suppressions = set()
        user = SimpleNamespace(name="member", discriminator="1234", open_dm=AsyncMock())
        member = SimpleNamespace(
            id="user",
            edit=AsyncMock(),
            get_user=Mock(return_value=user),
        )
        server = SimpleNamespace(id="server", name="Test server")
        result = ModerationResult(
            flagged=True,
            categories={"harassment": True},
            scores={"harassment": 0.95},
        )
        database = SimpleNamespace(
            add_warning=Mock(return_value=44),
            count_warnings=Mock(return_value=1),
            add_event=Mock(),
        )
        bot.database = database
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.enforce_warning_policy = AsyncMock()

        asyncio.run(
            bot._enforce_display_name_violation(
                server,
                member,
                name_kind="nickname",
                previous_value="Safe name",
                new_value="Unsafe name",
                restore_nick="Safe name",
                restore_available=True,
                result=result,
                active_categories=["harassment"],
            )
        )

        member.edit.assert_awaited_once_with(nick="Safe name")
        self.assertEqual(
            database.add_warning.call_args.kwargs["reason"],
            "Automatic nickname moderation: harassment",
        )
        self.assertEqual(
            database.add_warning.call_args.kwargs["original_content"],
            "Unsafe name",
        )
        bot._send_user_dm.assert_awaited_once()
        bot.enforce_warning_policy.assert_awaited_once_with(
            server, "server", "user", 44, 1
        )

    def test_bot_nickname_reset_event_is_suppressed(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._nickname_reset_suppressions = {("server", "user")}
        event = SimpleNamespace(
            member=SimpleNamespace(server_id="server", id="user", nick="safe")
        )

        asyncio.run(bot.handle_member_nickname_update(event))

        self.assertNotIn(("server", "user"), bot._nickname_reset_suppressions)

    def test_timeout_members_permission_is_moderator_exempt(self) -> None:
        permissions = SimpleNamespace(timeout_members=True)
        server = SimpleNamespace(
            permissions_for=Mock(return_value=permissions)
        )

        self.assertTrue(
            ModerationBot._member_is_moderator(server, SimpleNamespace())
        )

    def test_manage_nicknames_permission_is_moderator_exempt(self) -> None:
        server = SimpleNamespace(
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_nicknames=True)
            )
        )

        self.assertTrue(
            ModerationBot._member_is_moderator(server, SimpleNamespace())
        )

    def test_disabled_moderator_exemption_skips_member_lookup(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            get_moderator_exemption=Mock(return_value=False)
        )
        server = SimpleNamespace(get_member=Mock())
        message = SimpleNamespace(
            get_server=Mock(return_value=(server, "server")),
            author_id="moderator",
        )

        exempt = asyncio.run(bot._message_author_is_moderator(message))

        self.assertFalse(exempt)
        server.get_member.assert_not_called()

    def test_moderator_message_is_not_ai_scanned_or_deleted(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._message_author_is_moderator = AsyncMock(return_value=True)
        bot.moderator = SimpleNamespace(classify_text=AsyncMock())
        message = SimpleNamespace(content="unsafe", attachments=[], embeds=[])

        asyncio.run(bot.scan_message(message))

        bot.moderator.classify_text.assert_not_awaited()

    def test_automatic_violation_dms_appeal_and_retries_deletion(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._message_author_is_moderator = AsyncMock(return_value=False)
        bot._state = SimpleNamespace(my_id="bot")
        bot._bot_deleted_ids = set()
        bot.limiter = asyncio.Semaphore(1)
        bot.moderation_settings = SimpleNamespace(
            max_image_bytes=10_000,
            threshold=0.9,
            dashboard_url="https://modstoat.site",
            notification="silent",
        )
        result = ModerationResult(
            flagged=True,
            categories={"harassment": True},
            scores={"harassment": 0.96},
        )
        bot.moderator = SimpleNamespace(classify_text=AsyncMock(return_value=result))
        bot.database = SimpleNamespace(
            get_image_scanning=Mock(return_value=False),
            get_moderation_threshold=Mock(return_value=0.9),
            is_moderation_category_disabled=Mock(return_value=False),
            add_warning=Mock(return_value=42),
            count_warnings=Mock(return_value=1),
            add_event=Mock(),
        )
        bot.log_result = Mock()
        bot._warning_case_reference = Mock(return_value="ABCD2345")
        bot._appeal_instructions = Mock(
            return_value="\n\nAppeal code: `APPEAL2345`\nOpen: https://modstoat.site/appeal"
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.send_log = AsyncMock()
        bot.enforce_warning_policy = AsyncMock()
        user = SimpleNamespace(id="member")
        server = SimpleNamespace(id="server", name="Test server")
        message = SimpleNamespace(
            id="message",
            author_id="member",
            channel_id="channel",
            content="unsafe message",
            attachments=[],
            embeds=[],
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=user),
            delete=AsyncMock(side_effect=[RuntimeError("temporary failure"), None]),
        )

        asyncio.run(bot.scan_message(message))

        self.assertEqual(message.delete.await_count, 2)
        dm_description = bot._send_user_dm.await_args.args[2]
        self.assertIn("ABCD2345", dm_description)
        self.assertIn("APPEAL2345", dm_description)
        self.assertIn("**Warnings in this server:** 1", dm_description)
        bot.enforce_warning_policy.assert_awaited_once()

    def test_protected_high_confidence_content_is_deleted_without_punishment(self) -> None:
        for category, sends_support in (
            ("suicidal-thoughts", True),
            ("credentials", False),
        ):
            with self.subTest(category=category):
                bot = object.__new__(ModerationBot)
                bot._message_author_is_moderator = AsyncMock(return_value=False)
                bot._state = SimpleNamespace(my_id="bot")
                bot._bot_deleted_ids = set()
                bot.limiter = asyncio.Semaphore(1)
                bot.moderation_settings = SimpleNamespace(
                    max_image_bytes=10_000,
                    threshold=0.9,
                    dashboard_url="https://modstoat.site",
                    notification="silent",
                )
                result = ModerationResult(
                    flagged=False,
                    categories={category: True},
                    scores={category: 0.99},
                )
                bot.moderator = SimpleNamespace(
                    classify_text=AsyncMock(return_value=result)
                )
                bot.database = SimpleNamespace(
                    get_image_scanning=Mock(return_value=False),
                    get_moderation_threshold=Mock(return_value=0.9),
                    is_moderation_category_disabled=Mock(return_value=False),
                    add_warning=Mock(),
                    count_warnings=Mock(return_value=0),
                    add_event=Mock(),
                )
                bot.log_result = Mock()
                bot._send_suicidal_thoughts_support = AsyncMock()
                bot._resolve_user_tag = AsyncMock(return_value="member#1234")
                bot.require_action_permissions = AsyncMock(return_value=True)
                bot.send_log = AsyncMock()
                bot.enforce_warning_policy = AsyncMock()
                server = SimpleNamespace(id="server", name="Test server")
                message = SimpleNamespace(
                    id="message",
                    author_id="member",
                    channel_id="channel",
                    content="high confidence protected content",
                    attachments=[],
                    embeds=[],
                    get_server=Mock(return_value=(server, "server")),
                    get_author_as_user=Mock(return_value=SimpleNamespace(id="member")),
                    delete=AsyncMock(),
                )

                asyncio.run(bot.scan_message(message))

                message.delete.assert_awaited_once()
                bot.database.add_warning.assert_not_called()
                bot.enforce_warning_policy.assert_not_awaited()
                if sends_support:
                    bot._send_suicidal_thoughts_support.assert_awaited_once()
                else:
                    bot._send_suicidal_thoughts_support.assert_not_awaited()
                deletion = next(
                    call
                    for call in bot.database.add_event.call_args_list
                    if call.kwargs.get("event_type") == "automatic_deletion"
                )
                self.assertEqual(
                    deletion.kwargs["details"]["categories"], {category: True}
                )
                self.assertEqual(
                    deletion.kwargs["details"]["scores"], {category: 0.99}
                )
                self.assertTrue(deletion.kwargs["details"]["support_only"])
                self.assertEqual(deletion.kwargs["details"]["matched_categories"], [category])
                self.assertEqual(bot.send_log.await_args.args[1], "Deleted for support")
                self.assertEqual(bot.send_log.await_args.kwargs["color"], "#3498DB")

    def test_moderator_nickname_change_is_not_scanned(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot._nickname_reset_suppressions = set()
        member = SimpleNamespace(id="moderator")
        server = SimpleNamespace(
            get_member=Mock(return_value=member),
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_messages=True)
            ),
        )
        bot.get_server = Mock(return_value=server)
        bot.database = SimpleNamespace(
            get_nickname_protection=Mock(return_value=True)
        )
        bot._classify_display_name = AsyncMock()
        event = SimpleNamespace(
            member=SimpleNamespace(
                server_id="server", id="moderator", nick="unsafe"
            ),
            after=member,
            before=SimpleNamespace(nick="safe"),
        )

        asyncio.run(bot.handle_member_nickname_update(event))

        bot._classify_display_name.assert_not_awaited()

    def test_manual_warning_rejects_moderator_target(self) -> None:
        bot = object.__new__(ModerationBot)
        target = SimpleNamespace(id="target")
        server = SimpleNamespace(
            get_member=Mock(return_value=target),
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_messages=True)
            ),
        )
        message = SimpleNamespace(
            content="~warn target reason",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(add_warning=Mock())
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.add_warning.assert_not_called()
        self.assertEqual(
            bot.send_command_response.await_args.args[1], "Moderator exempt"
        )

    def test_successful_spam_timeout_adds_warning(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.moderation_settings = SimpleNamespace(spam_timeout_seconds=3600)
        bot._spam_timeout_until = {}
        bot._detect_spam = Mock(return_value="sent 5 messages within 10 seconds")
        member = SimpleNamespace(timeout=AsyncMock())
        permissions = SimpleNamespace()
        server = SimpleNamespace(
            get_member=Mock(return_value=member),
            permissions_for=Mock(return_value=permissions),
        )
        message = SimpleNamespace(
            author_id="user",
            id="message",
            channel_id="channel",
            content="spam",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_member=Mock(return_value=member),
            get_author_as_user=Mock(return_value=None),
        )
        database = SimpleNamespace(
            add_warning=Mock(return_value=42),
            count_warnings=Mock(return_value=3),
            add_event=Mock(),
            get_warning_policy=Mock(return_value=WarningPolicy()),
            claim_warning_policy_action=Mock(return_value=True),
        )
        bot.database = database
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.enforce_warning_policy = AsyncMock()

        handled = asyncio.run(bot.handle_spam(message))

        self.assertTrue(handled)
        database.add_warning.assert_called_once_with(
            server_id="server",
            user_id="user",
            moderator_id="bot",
            source="automatic",
            reason="Automatic spam detection: sent 5 messages within 10 seconds",
            message_id="message",
            channel_id="channel",
            original_content="spam",
        )
        database.claim_warning_policy_action.assert_called_once_with(
            "server", "user", "timeout", 3, 42
        )
        bot.enforce_warning_policy.assert_awaited_once_with(
            server, "server", "user", 42, 3
        )

    def test_disabled_spam_detection_skips_all_spam_enforcement(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(get_spam_detection=Mock(return_value=False))
        bot._detect_spam = Mock(return_value="spam")
        message = SimpleNamespace(
            get_server=Mock(return_value=(SimpleNamespace(), "server"))
        )

        handled = asyncio.run(bot.handle_spam(message))

        self.assertFalse(handled)
        bot._detect_spam.assert_not_called()

    def test_mass_mention_is_deleted_timed_out_and_warned(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.moderation_settings = SimpleNamespace(
            mass_mention_limit=5,
            spam_timeout_seconds=3600,
        )
        bot._spam_timeout_until = {}
        bot._bot_deleted_ids = set()
        member = SimpleNamespace(timeout=AsyncMock())
        server = SimpleNamespace(
            get_member=Mock(return_value=member),
            permissions_for=Mock(return_value=SimpleNamespace()),
        )
        message = SimpleNamespace(
            author_id="user",
            id="message",
            channel_id="channel",
            content="hello everyone",
            mention_ids=["u1", "u2", "u3", "u4", "u5"],
            role_mention_ids=[],
            raw_flags=0,
            delete=AsyncMock(),
            get_server=Mock(return_value=(server, "server")),
            get_author_as_member=Mock(return_value=member),
            get_author_as_user=Mock(return_value=None),
        )
        database = SimpleNamespace(
            add_warning=Mock(return_value=43),
            count_warnings=Mock(return_value=1),
            add_event=Mock(),
            get_warning_policy=Mock(return_value=WarningPolicy()),
        )
        bot.database = database
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.enforce_warning_policy = AsyncMock()

        handled = asyncio.run(bot.handle_spam(message))

        self.assertTrue(handled)
        message.delete.assert_awaited_once()
        member.timeout.assert_awaited_once_with(timedelta(hours=1))
        self.assertIn(
            "mentioned 5 users or roles",
            database.add_warning.call_args.kwargs["reason"],
        )
        self.assertTrue(database.add_event.call_args.kwargs["details"]["message_deleted"])

    def test_link_filter_deletes_without_adding_a_warning(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot._delete_automatic_message = AsyncMock(return_value=True)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.database = SimpleNamespace(
            add_event=Mock(),
            get_link_protection=Mock(return_value=True),
            record_daily_member_change=Mock(),
        )
        message = SimpleNamespace(
            id="message",
            author_id="user",
            channel_id="channel",
            content="visit https://example.com/path",
            get_server=Mock(return_value=(SimpleNamespace(), "server")),
            get_author_as_user=Mock(return_value=None),
        )

        handled = asyncio.run(bot.handle_link_filter(message))

        self.assertTrue(handled)
        bot._delete_automatic_message.assert_awaited_once_with(message)
        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertFalse(details["warning_added"])
        self.assertFalse(hasattr(bot.database, "add_warning"))

    def test_link_filter_does_nothing_when_disabled(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._delete_automatic_message = AsyncMock(return_value=True)
        bot.database = SimpleNamespace(get_link_protection=Mock(return_value=False))
        message = SimpleNamespace(
            content="https://example.com",
            get_server=Mock(return_value=(SimpleNamespace(), "server")),
        )

        handled = asyncio.run(bot.handle_link_filter(message))

        self.assertFalse(handled)
        bot._delete_automatic_message.assert_not_awaited()

    def test_link_filter_does_not_delete_punctuation_false_positive(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._delete_automatic_message = AsyncMock(return_value=True)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.database = SimpleNamespace(
            get_link_protection=Mock(return_value=True),
            get_allow_gifs=Mock(return_value=False),
        )
        message = SimpleNamespace(
            content=(
                "vc n entende!!! a culpa nao é minha se os.jogos "
                "sexualizam tanto as mulheres"
            ),
            get_server=Mock(return_value=(SimpleNamespace(), "server")),
        )

        handled = asyncio.run(bot.handle_link_filter(message))

        self.assertFalse(handled)
        bot._delete_automatic_message.assert_not_awaited()
        bot.require_action_permissions.assert_not_awaited()

    def test_link_filter_allows_gifbox_domain_and_subdomains(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._delete_automatic_message = AsyncMock(return_value=True)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.database = SimpleNamespace(
            get_link_protection=Mock(return_value=True),
            get_allow_gifs=Mock(return_value=True),
        )
        for content in (
            "https://gifbox.me/example",
            "gifbox.me/example",
            "https://media.gifbox.me/example",
        ):
            message = SimpleNamespace(
                content=content,
                get_server=Mock(return_value=(SimpleNamespace(), "server")),
            )

            handled = asyncio.run(bot.handle_link_filter(message))

            self.assertFalse(handled, content)
        bot._delete_automatic_message.assert_not_awaited()
        bot.require_action_permissions.assert_not_awaited()

    def test_link_filter_still_blocks_other_or_mixed_domains(self) -> None:
        self.assertTrue(
            ModerationBot._contains_filterable_link(
                "https://gifbox.me/example https://example.com",
                allow_gifs=True,
            )
        )
        self.assertTrue(
            ModerationBot._contains_filterable_link(
                "https://gifbox.me.evil.example", allow_gifs=True
            )
        )
        self.assertTrue(
            ModerationBot._contains_filterable_link(
                "https://notgifbox.me/example", allow_gifs=True
            )
        )
        self.assertFalse(
            ModerationBot._contains_filterable_link(
                "https://gifbox.me/example", allow_gifs=True
            )
        )
        self.assertTrue(
            ModerationBot._contains_filterable_link("https://gifbox.me/example")
        )

    def test_link_detection_handles_protocol_bare_domain_and_ip(self) -> None:
        self.assertTrue(ModerationBot._contains_link("https://example.com"))
        self.assertTrue(ModerationBot._contains_link("https://server.internal"))
        self.assertTrue(ModerationBot._contains_link("example.com"))
        self.assertTrue(ModerationBot._contains_link("example.com/path"))
        self.assertTrue(ModerationBot._contains_link("forums.bbc.co.uk"))
        self.assertTrue(ModerationBot._contains_link("example.pt"))
        self.assertTrue(ModerationBot._contains_link("127.0.0.1:8080/test"))
        self.assertFalse(ModerationBot._contains_link("This is ordinary text."))
        self.assertFalse(ModerationBot._contains_link("example.notarealtld"))

    def test_link_detection_ignores_words_joined_by_punctuation(self) -> None:
        content = (
            "vc n entende!!! a culpa nao é minha se os.jogos "
            "sexualizam tanto as mulheres"
        )

        self.assertFalse(ModerationBot._contains_link(content))
        self.assertFalse(
            ModerationBot._contains_filterable_link(content, allow_gifs=True)
        )

    def test_bot_users_are_excluded_from_human_message_statistics(self) -> None:
        self.assertTrue(
            ModerationBot._user_is_bot(SimpleNamespace(bot=SimpleNamespace()))
        )
        self.assertFalse(ModerationBot._user_is_bot(SimpleNamespace(bot=None)))
        self.assertFalse(ModerationBot._user_is_bot(None))

    def test_user_dm_is_sent_as_embed(self) -> None:
        bot = object.__new__(ModerationBot)
        dm = SimpleNamespace(send=AsyncMock())
        user = SimpleNamespace(open_dm=AsyncMock(return_value=dm))

        sent = asyncio.run(
            bot._send_user_dm(
                "user", "Policy action", "You were kicked.", user=user
            )
        )

        self.assertTrue(sent)
        user.open_dm.assert_awaited_once()
        dm.send.assert_awaited_once()
        embed = dm.send.await_args.kwargs["embeds"][0]
        self.assertEqual(embed.title, "🔰 Policy action")
        self.assertEqual(embed.description, "You were kicked.")

    def test_server_scoped_user_dm_uses_selected_language(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(get_server_locale=Mock(return_value="es"))
        dm = SimpleNamespace(send=AsyncMock())
        user = SimpleNamespace(open_dm=AsyncMock(return_value=dm))

        sent = asyncio.run(
            bot._send_user_dm(
                "user",
                "You received a warning",
                "You received a warning in **Servidor**.\n\n"
                "**Reason:** No tocar el contenido",
                server_id="server",
                user=user,
            )
        )

        self.assertTrue(sent)
        embed = dm.send.await_args.kwargs["embeds"][0]
        self.assertIn("Has recibido una advertencia", embed.title or "")
        self.assertIn("**Motivo:** No tocar el contenido", embed.description or "")

    def test_new_member_verification_embed_uses_selected_language(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(get_server_locale=Mock(return_value="pt"))

        embed = bot._localized_embed(
            "server",
            "Complete verification",
            "**Servidor** requires join verification. "
            "You have been temporarily muted for one day.",
            "#F59E0B",
        )

        self.assertIn("Conclua a verificação", embed.title or "")
        self.assertIn("exige verificação de entrada", embed.description or "")
        self.assertIn("suspenso temporariamente", embed.description or "")

    def test_global_references_are_six_characters(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            global_reference_exists=Mock(return_value=False)
        )

        reference_id = bot._new_global_reference()

        self.assertEqual(len(reference_id), 6)
        self.assertTrue(reference_id.isalnum())

    def test_server_announcement_uses_first_sendable_text_channel_once(self) -> None:
        class FakeTextChannel:
            def __init__(self, channel_id: str, *, fails: bool = False) -> None:
                self.id = channel_id
                self.nsfw = False
                self.send = AsyncMock(
                    side_effect=RuntimeError("cannot send") if fails else None
                )

        bot = object.__new__(ModerationBot)
        bot._announcement_locks = {}
        bot.database = SimpleNamespace(
            has_server_announcement=Mock(return_value=False),
            record_server_announcement=Mock(),
        )
        first = FakeTextChannel("first", fails=True)
        second = FakeTextChannel("second")
        server = SimpleNamespace(
            id="server", name="Test server", channels=[first, second]
        )

        with patch.object(stoat, "TextChannel", FakeTextChannel):
            sent = asyncio.run(bot.announce_server(server))

        self.assertTrue(sent)
        first.send.assert_awaited_once()
        second.send.assert_awaited_once()
        announcement = second.send.await_args.kwargs["embeds"][0].description or ""
        self.assertIn("**1 — Permissions come first**", announcement)
        self.assertIn("Run `~setup` now", announcement)
        self.assertIn("**2 — Choose your server language**", announcement)
        self.assertIn("`~language French`", announcement)
        self.assertIn("**4 — Advertise your server with Discovery**", announcement)
        self.assertIn("Dashboard → Discovery", announcement)
        self.assertIn("`~bump` every two hours", announcement)
        bot.database.record_server_announcement.assert_called_once_with(
            "server", "second"
        )

    def test_missing_permissions_are_explained_only_once(self) -> None:
        class FakeTextChannel:
            def __init__(self, channel_id: str) -> None:
                self.id = channel_id
                self.nsfw = False
                self.send = AsyncMock()

        notified: set[str] = set()
        database = SimpleNamespace(
            get_log_channel=Mock(return_value="mod-log"),
            list_server_permission_notices=Mock(
                side_effect=lambda _server_id: set(notified)
            ),
            record_server_permission_notices=Mock(
                side_effect=lambda _server_id, names, _channel_id: notified.update(names)
            ),
        )
        permissions = SimpleNamespace(
            view_channel=True,
            read_message_history=True,
            send_messages=True,
            send_embeds=True,
            manage_messages=False,
            timeout_members=True,
            kick_members=False,
            ban_members=True,
            assign_roles=True,
            manage_roles=True,
            manage_nicknames=True,
        )
        channel = FakeTextChannel("general")
        member = SimpleNamespace(id="bot")
        server = SimpleNamespace(
            id="server",
            name="Test server",
            channels=[channel],
            get_member=Mock(return_value=member),
            fetch_member=AsyncMock(),
            permissions_for=Mock(return_value=permissions),
        )
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = database
        bot.get_channel = Mock(return_value=channel)
        bot._send_embed_pages = AsyncMock()

        with (
            patch.object(stoat, "TextChannel", FakeTextChannel),
            patch.object(
                ModerationBot,
                "state",
                new_callable=PropertyMock,
                return_value=SimpleNamespace(my_id="bot"),
            ),
        ):
            first = asyncio.run(
                bot.require_action_permissions(
                    server, "manage_messages", "kick_members"
                )
            )
            second = asyncio.run(
                bot.require_action_permissions(
                    server, "manage_messages", "kick_members"
                )
            )

        self.assertFalse(first)
        self.assertFalse(second)
        bot._send_embed_pages.assert_awaited_once()
        description = bot._send_embed_pages.await_args.args[2]
        self.assertIn("cannot remove messages", description)
        self.assertIn("cannot kick members", description)
        database.record_server_permission_notices.assert_called_once_with(
            "server", ["manage_messages", "kick_members"], "mod-log"
        )

    def test_missing_permission_notice_dms_owner_when_no_log_channel_exists(self) -> None:
        member = SimpleNamespace(id="bot")
        server = SimpleNamespace(
            id="server",
            name="Test server",
            owner_id="owner",
            channels=[SimpleNamespace(id="general", send=AsyncMock())],
            get_member=Mock(return_value=member),
            get_owner=Mock(return_value=SimpleNamespace(id="owner")),
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_messages=False)
            ),
        )
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = SimpleNamespace(
            get_log_channel=Mock(return_value=None),
            list_server_permission_notices=Mock(return_value=set()),
            record_server_permission_notices=Mock(),
        )
        bot.get_channel = Mock()
        bot._send_embed_pages = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)

        allowed = asyncio.run(
            bot.require_action_permissions(server, "manage_messages")
        )

        self.assertFalse(allowed)
        bot.get_channel.assert_not_called()
        bot._send_embed_pages.assert_not_awaited()
        server.channels[0].send.assert_not_awaited()
        bot._send_user_dm.assert_awaited_once()
        self.assertEqual(bot._send_user_dm.await_args.args[0], "owner")
        bot.database.record_server_permission_notices.assert_called_once_with(
            "server", ["manage_messages"], "dm:owner"
        )

    def test_global_ban_permission_notice_uses_twenty_four_hour_cooldown(self) -> None:
        member = SimpleNamespace(id="bot")
        server = SimpleNamespace(
            id="server",
            name="Test server",
            get_member=Mock(return_value=member),
            permissions_for=Mock(
                return_value=SimpleNamespace(ban_members=False)
            ),
        )
        database = SimpleNamespace(
            get_log_channel=Mock(return_value="mod-log"),
            list_server_permission_notices=Mock(return_value=set()),
            record_server_permission_notices=Mock(),
        )
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = database
        bot.get_channel = Mock(return_value=SimpleNamespace(send=AsyncMock()))
        bot._send_embed_pages = AsyncMock()

        allowed = asyncio.run(
            bot.require_action_permissions(
                server, "ban_members", renotify_after_seconds=86_400
            )
        )

        self.assertFalse(allowed)
        database.list_server_permission_notices.assert_called_once_with(
            "server", within_seconds=86_400
        )
        database.record_server_permission_notices.assert_called_once_with(
            "server", ["ban_members"], "mod-log", refresh_existing=True
        )
        self.assertIn(
            "once every 24 hours", bot._send_embed_pages.await_args.args[2]
        )

    def test_inaccessible_log_channel_falls_back_to_server_owner_dm(self) -> None:
        member = SimpleNamespace(id="bot")
        log_channel = SimpleNamespace(id="mod-log", send=AsyncMock(
            side_effect=RuntimeError("missing ViewChannel")
        ))
        server = SimpleNamespace(
            id="server",
            name="Test server",
            owner_id="owner",
            get_member=Mock(return_value=member),
            get_owner=Mock(return_value=SimpleNamespace(id="owner")),
            permissions_for=Mock(return_value=SimpleNamespace(kick_members=False)),
        )
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = SimpleNamespace(
            get_log_channel=Mock(return_value="mod-log"),
            list_server_permission_notices=Mock(return_value=set()),
            record_server_permission_notices=Mock(),
        )
        bot.get_channel = Mock(return_value=log_channel)
        bot._send_embed_pages = AsyncMock(
            side_effect=RuntimeError("missing ViewChannel")
        )
        bot._send_user_dm = AsyncMock(return_value=True)

        allowed = asyncio.run(
            bot.require_action_permissions(server, "kick_members")
        )

        self.assertFalse(allowed)
        bot._send_embed_pages.assert_awaited_once()
        log_channel.send.assert_awaited_once()
        bot._send_user_dm.assert_awaited_once()
        bot.database.record_server_permission_notices.assert_called_once_with(
            "server", ["kick_members"], "dm:owner"
        )

    def test_global_ban_only_targets_and_logs_servers_containing_user(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._global_ban_removal_suppressions = set()
        bot.send_log = AsyncMock()
        bot.database = SimpleNamespace(add_event=Mock())
        member_server = SimpleNamespace(
            id="member-server",
            name="Member server",
            fetch_bans=AsyncMock(return_value=[]),
            get_member=Mock(return_value=SimpleNamespace(id="user")),
            fetch_member=AsyncMock(),
            ban=AsyncMock(),
        )
        other_server = SimpleNamespace(
            id="other-server",
            name="Other server",
            get_member=Mock(return_value=None),
            fetch_member=AsyncMock(side_effect=LookupError("not a member")),
            ban=AsyncMock(),
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={
                member_server.id: member_server,
                other_server.id: other_server,
            },
        ):
            succeeded, failed = asyncio.run(
                bot._apply_global_ban_to_servers(
                    "user",
                    "serious violation",
                    reference_id="ABC123",
                    actor_id="owner",
                )
            )

        self.assertEqual(succeeded, ["Member server"])
        self.assertEqual(failed, [])
        member_server.ban.assert_awaited_once_with(
            "user", reason="Global ban ABC123: serious violation"
        )
        other_server.ban.assert_not_awaited()
        bot.database.add_event.assert_called_once_with(
            server_id="member-server",
            event_type="global_ban_enforced",
            user_id="user",
            actor_id="owner",
            details={
                "reason": "serious violation",
                "global_reference": "ABC123",
                "enforcement_source": "global_moderation",
            },
        )
        bot.send_log.assert_awaited_once_with(
            "member-server",
            "Global ban enforced",
            "**Reference ID:** `ABC123`\n**User:** <@user>\n**Reason:** serious violation",
            color="#ED4245",
        )

    def test_global_unban_command_does_not_write_to_server_logs(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            add_event=Mock(),
            remove_global_ban=Mock(
                return_value=SimpleNamespace(reference_id="ABC123")
            )
        )
        bot._apply_global_ban_to_servers = AsyncMock(
            return_value=(["Server one"], [])
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()
        bot._send_global_warning_log = AsyncMock()
        message = SimpleNamespace(author_id=GLOBAL_COMMAND_OWNER_ID)

        asyncio.run(
            bot.handle_global_command(
                message, "~global_unban", ["~global_unban", "user", "Reviewed evidence"]
            )
        )

        bot.send_log.assert_not_awaited()
        bot._send_global_warning_log.assert_not_awaited()
        bot._apply_global_ban_to_servers.assert_awaited_once_with(
            "user", "Reviewed evidence", unban=True, reference_id="ABC123",
            actor_id=GLOBAL_COMMAND_OWNER_ID, source="global_command",
        )

    def test_global_unban_preserves_independent_bans(self) -> None:
        for reason, reference, should_unban in [
            ("Local spam ban", "ABC123", False),
            (None, "ABC123", False),
            ("Global ban OTHER: violation", "ABC123", False),
            ("Global ban ABC1234: violation", "ABC123", False),
            ("Global ban ABC123: violation", None, False),
            ("Global ban ABC123: violation", "ABC123", True),
        ]:
            with self.subTest(reason=reason, reference=reference):
                bot = object.__new__(ModerationBot)
                bot._global_ban_removal_suppressions = set()
                bot.require_action_permissions = AsyncMock(return_value=True)
                server = SimpleNamespace(
                    id="server", name="Server",
                    fetch_bans=AsyncMock(return_value=[
                        SimpleNamespace(user_id="user", reason=reason),
                    ]),
                    unban=AsyncMock(),
                )
                with patch.object(ModerationBot, "servers", new_callable=PropertyMock,
                                  return_value={server.id: server}):
                    succeeded, failed = asyncio.run(bot._apply_global_ban_to_servers(
                        "user", "", unban=True, reference_id=reference,
                    ))
                self.assertEqual(failed, [])
                self.assertEqual(succeeded, ["Server"] if should_unban else [])
                self.assertEqual(server.unban.await_count, int(should_unban))

    def test_global_unban_missing_ban_is_success_and_fetch_failure_is_safe(self) -> None:
        for fetch_error in (None, RuntimeError("Cannot read bans")):
            with self.subTest(fetch_error=fetch_error):
                bot = object.__new__(ModerationBot)
                bot._global_ban_removal_suppressions = set()
                bot.require_action_permissions = AsyncMock(return_value=True)
                server = SimpleNamespace(
                    id="server", name="Server",
                    fetch_bans=AsyncMock(return_value=[], side_effect=fetch_error),
                    unban=AsyncMock(),
                )
                with patch.object(ModerationBot, "servers", new_callable=PropertyMock,
                                  return_value={server.id: server}):
                    result = asyncio.run(bot._apply_global_ban_to_servers(
                        "user", "", unban=True, reference_id="ABC123",
                    ))
                self.assertEqual(result, ([], ["Server"]) if fetch_error else (["Server"], []))
                server.unban.assert_not_awaited()

    def test_global_ban_preserves_existing_ban_with_stale_membership(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._global_ban_removal_suppressions = set()
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._server_has_member = AsyncMock(return_value=True)
        server = SimpleNamespace(
            id="server", name="Server",
            fetch_bans=AsyncMock(return_value=[
                SimpleNamespace(user_id="user", reason="Local spam ban"),
            ]),
            ban=AsyncMock(),
        )
        with patch.object(ModerationBot, "servers", new_callable=PropertyMock,
                          return_value={server.id: server}):
            result = asyncio.run(bot._apply_global_ban_to_servers(
                "user", "Global violation", reference_id="ABC123",
            ))
        self.assertEqual(result, ([], []))
        server.ban.assert_not_awaited()

    def test_global_ban_on_join_records_reason_in_dashboard_event(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._global_ban_removal_suppressions = set()
        member = SimpleNamespace(id="user", server_id="server")
        server = SimpleNamespace(id="server", name="Test server", ban=AsyncMock())
        global_ban = SimpleNamespace(
            reference_id="GB1234",
            reason="Coordinated harassment",
            created_by="owner",
        )
        bot.database = SimpleNamespace(
            record_daily_member_change=Mock(),
            get_global_ban=Mock(return_value=global_ban),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=server)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._suppress_global_ban_removal = Mock()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        asyncio.run(bot.handle_member_join(SimpleNamespace(member=member)))

        bot.database.add_event.assert_called_once_with(
            server_id="server",
            event_type="global_ban_enforced_on_join",
            user_id="user",
            actor_id="owner",
            details={
                "reason": "Coordinated harassment",
                "global_reference": "GB1234",
                "enforcement_source": "member_join",
            },
        )
        server.ban.assert_awaited_once_with(
            "user", reason="Global ban GB1234: Coordinated harassment"
        )
        self.assertIn(
            "**Reason:** Coordinated harassment", bot.send_log.await_args.args[2]
        )

    def test_global_ban_member_removal_is_not_server_logged(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._global_ban_removal_suppressions = {("server", "user")}
        bot.database = SimpleNamespace(
            add_event=Mock(),
            get_link_protection=Mock(return_value=True),
            record_daily_member_change=Mock(),
        )
        bot.send_log = AsyncMock()
        event = SimpleNamespace(
            server_id="server",
            user_id="user",
            reason=SimpleNamespace(value="Ban"),
        )

        asyncio.run(bot.handle_member_remove(event))

        bot.database.add_event.assert_not_called()
        bot.send_log.assert_not_awaited()
        self.assertNotIn(
            ("server", "user"), bot._global_ban_removal_suppressions
        )

    def test_server_ban_is_only_reported_in_origin_server(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._pending_ban_attribution = {}
        source_server = SimpleNamespace(id="source", name="Source server")
        bot.get_server = Mock(return_value=source_server)
        bot._fetch_ban_record = AsyncMock(
            return_value=SimpleNamespace(
                user_id="user",
                reason="Repeated harassment",
                user=SimpleNamespace(name="member", discriminator="1234"),
            )
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.database = SimpleNamespace(
            count_warnings=Mock(return_value=4),
            add_event=Mock(),
        )
        bot.send_log = AsyncMock()
        shared_server = SimpleNamespace(
            get_member=Mock(return_value=SimpleNamespace(id="user")),
            fetch_member=AsyncMock(),
        )
        unrelated_server = SimpleNamespace(
            get_member=Mock(return_value=None),
            fetch_member=AsyncMock(side_effect=LookupError),
        )
        event = SimpleNamespace(
            server_id="source", user_id="user", member=None
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={
                "source": source_server,
                "shared": shared_server,
                "unrelated": unrelated_server,
            },
        ):
            asyncio.run(bot.handle_local_ban(event))

        bot.send_log.assert_awaited_once()
        self.assertEqual(bot.send_log.await_args.args[0], "source")
        self.assertEqual(bot.database.add_event.call_args.kwargs["event_type"], "member_ban")
        bot.database.add_event.assert_called_once()
        shared_server.fetch_member.assert_not_awaited()
        unrelated_server.fetch_member.assert_not_awaited()

    def test_stoatmod_removal_is_excluded_from_cross_server_intelligence(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="stoatmod-bot")
        bot._pending_ban_attribution = {
            ("removed-server", "stoatmod-bot"): ("owner", "Bot removed")
        }
        bot._pending_kick_attribution = {}
        bot._global_ban_removal_suppressions = set()
        bot.database = SimpleNamespace(
            record_daily_member_change=Mock(),
            add_event=Mock(),
        )
        bot.send_log = AsyncMock()
        event = SimpleNamespace(
            server_id="removed-server",
            user_id="stoatmod-bot",
            reason=stoat.MemberRemovalIntention.ban,
        )

        asyncio.run(bot.handle_member_remove(event))

        bot.database.record_daily_member_change.assert_not_called()
        bot.database.add_event.assert_not_called()
        bot.send_log.assert_not_awaited()
        self.assertNotIn(
            ("removed-server", "stoatmod-bot"),
            bot._pending_ban_attribution,
        )

    def test_join_log_never_fetches_other_server_history(self) -> None:
        bot = object.__new__(ModerationBot)
        event = SimpleNamespace(
            member=SimpleNamespace(
                id="user",
                server_id="current",
                get_user=Mock(
                    return_value=SimpleNamespace(
                        created_at=datetime.now(timezone.utc) - timedelta(days=30),
                        bot=False,
                    )
                ),
            )
        )
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=None),
            list_auto_roles=Mock(return_value=[]),
            record_daily_member_change=Mock(),
            add_event=Mock(),
        )
        bot.get_server = Mock(
            side_effect=lambda server_id: (
                SimpleNamespace(name="Previous server")
                if server_id == "previous"
                else None
            )
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        asyncio.run(bot.handle_member_join(event))

        description = bot.send_log.await_args.args[2]
        self.assertNotIn("Previous moderation", description)
        self.assertNotIn("other-server", description)

    def test_stoatmod_owner_join_replaces_history_with_verified_marker(self) -> None:
        bot = object.__new__(ModerationBot)
        event = SimpleNamespace(
            member=SimpleNamespace(
                id=GLOBAL_COMMAND_OWNER_ID,
                server_id="current",
                get_user=Mock(
                    return_value=SimpleNamespace(
                        created_at=datetime.now(timezone.utc) - timedelta(days=30),
                        bot=False,
                    )
                ),
            )
        )
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=SimpleNamespace(reason="Stale ban")),
            record_daily_member_change=Mock(),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=None)
        bot._resolve_user_tag = AsyncMock(return_value="stoatmod-owner")
        bot.send_log = AsyncMock()

        asyncio.run(bot.handle_member_join(event))

        bot.database.get_global_ban.assert_not_called()
        bot.send_log.assert_awaited_once()
        title, description = bot.send_log.await_args.args[1:3]
        self.assertEqual(title, "Member joined")
        self.assertIn("✅ **Verified Stoatmod owner**", description)
        self.assertNotIn("Prior Stoatmod history", description)


    def test_join_adds_all_auto_roles_without_replacing_existing_roles(self) -> None:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=["existing-role"],
            edit=AsyncMock(),
            get_user=Mock(
                return_value=SimpleNamespace(
                    created_at=datetime.now(timezone.utc) - timedelta(days=30),
                    bot=False,
                )
            ),
        )

        def edit_roles(*, roles: list[str]) -> SimpleNamespace:
            member.role_ids = list(roles)
            return SimpleNamespace(role_ids=roles)

        member.edit.side_effect = edit_roles
        event = SimpleNamespace(member=member)
        server = SimpleNamespace(
            roles={
                "existing-role": SimpleNamespace(name="Existing"),
                "auto-one": SimpleNamespace(name="First"),
                "auto-two": SimpleNamespace(name="Second"),
            },
            fetch_member=AsyncMock(return_value=member),
        )
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=None),
            list_auto_roles=Mock(return_value=["auto-one", "auto-two"]),
            record_daily_member_change=Mock(),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=server)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        asyncio.run(bot.handle_member_join(event))

        member.edit.assert_awaited_once_with(
            roles=["existing-role", "auto-one", "auto-two"]
        )
        bot.require_action_permissions.assert_awaited_once_with(
            server, "assign_roles"
        )

    def test_auto_role_audit_rejects_an_unconfirmed_edit_response(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=["auto-role"],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["auto-role"])
            ),
        )
        bot_member = SimpleNamespace(
            id="bot", top_role=SimpleNamespace(rank=10)
        )
        fetched_member = SimpleNamespace(
            id="user",
            role_ids=[],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["auto-role"])
            ),
        )
        server = SimpleNamespace(
            id="current",
            roles={"auto-role": SimpleNamespace(name="Member", rank=20)},
            get_member=Mock(return_value=bot_member),
            fetch_member=AsyncMock(return_value=fetched_member),
        )
        bot.database = SimpleNamespace(
            list_auto_roles=Mock(return_value=["auto-role"]),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        with patch("bot.asyncio.sleep", new=AsyncMock(return_value=None)):
            granted_role_ids, failed_role_ids = asyncio.run(
                bot._assign_auto_roles_on_join(server, member)
            )

        self.assertEqual(granted_role_ids, [])
        self.assertEqual(failed_role_ids, ["auto-role"])
        self.assertIsNone(
            ModerationBot._role_ids_after_member_edit(SimpleNamespace())
        )
        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertEqual(details["configured_role_ids"], ["auto-role"])
        self.assertEqual(details["granted_role_ids"], [])
        self.assertEqual(details["failed_role_ids"], ["auto-role"])
        self.assertEqual(details["unavailable_role_ids"], [])
        self.assertEqual(details["hierarchy_blocked_role_ids"], [])
        self.assertFalse(details["permission_blocked"])
        self.assertFalse(details["member_confirmation_unavailable"])
        bot.send_log.assert_awaited_once()

    def test_auto_role_retry_uses_fresh_member_confirmation(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=[],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["auto-role"])
            ),
        )
        bot_member = SimpleNamespace(
            id="bot", top_role=SimpleNamespace(rank=10)
        )
        unconfirmed_member = SimpleNamespace(
            id="user",
            role_ids=[],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["auto-role"])
            ),
        )
        confirmed_member = SimpleNamespace(
            id="user",
            role_ids=["auto-role"],
            edit=AsyncMock(),
        )
        server = SimpleNamespace(
            id="current",
            roles={"auto-role": SimpleNamespace(name="Member", rank=20)},
            get_member=Mock(return_value=bot_member),
            fetch_member=AsyncMock(
                side_effect=[
                    unconfirmed_member,
                    unconfirmed_member,
                    unconfirmed_member,
                    confirmed_member,
                ]
            ),
        )
        bot.database = SimpleNamespace(
            list_auto_roles=Mock(return_value=["auto-role"]),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        granted_role_ids, failed_role_ids = asyncio.run(
            bot._assign_auto_roles_on_join(server, member)
        )

        self.assertEqual(granted_role_ids, ["auto-role"])
        self.assertEqual(failed_role_ids, [])
        self.assertEqual(unconfirmed_member.edit.await_count, 2)
        unconfirmed_member.edit.assert_awaited_with(roles=["auto-role"])
        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertEqual(details["granted_role_ids"], ["auto-role"])
        self.assertEqual(details["failed_role_ids"], [])
        bot.send_log.assert_not_awaited()

    def test_auto_role_retry_replaces_an_older_confirmed_snapshot(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=[],
            edit=AsyncMock(),
        )
        bot_member = SimpleNamespace(
            id="bot", top_role=SimpleNamespace(rank=10)
        )
        initial_member = SimpleNamespace(
            id="user",
            role_ids=[],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["role-a", "role-b"])
            ),
        )
        partially_confirmed_member = SimpleNamespace(
            id="user",
            role_ids=["role-a"],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["role-a", "role-b"])
            ),
        )
        empty_member = SimpleNamespace(
            id="user",
            role_ids=[],
            edit=AsyncMock(
                return_value=SimpleNamespace(role_ids=["role-b"])
            ),
        )
        server = SimpleNamespace(
            id="current",
            roles={
                "role-a": SimpleNamespace(name="First", rank=20),
                "role-b": SimpleNamespace(name="Second", rank=21),
            },
            get_member=Mock(return_value=bot_member),
            fetch_member=AsyncMock(
                side_effect=[
                    initial_member,
                    partially_confirmed_member,
                    empty_member,
                    empty_member,
                    empty_member,
                    empty_member,
                ]
            ),
        )
        bot.database = SimpleNamespace(
            list_auto_roles=Mock(return_value=["role-a", "role-b"]),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        with patch("bot.asyncio.sleep", new=AsyncMock(return_value=None)):
            granted_role_ids, failed_role_ids = asyncio.run(
                bot._assign_auto_roles_on_join(server, member)
            )

        self.assertEqual(granted_role_ids, [])
        self.assertEqual(failed_role_ids, ["role-a", "role-b"])
        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertEqual(details["granted_role_ids"], [])
        self.assertEqual(details["failed_role_ids"], ["role-a", "role-b"])

    def test_auto_role_assignment_requires_a_fresh_member_baseline(self) -> None:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=[],
            edit=AsyncMock(),
        )
        server = SimpleNamespace(
            id="current",
            roles={"auto-role": SimpleNamespace(name="Member")},
        )
        bot.database = SimpleNamespace(
            list_auto_roles=Mock(return_value=["auto-role"]),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        granted_role_ids, failed_role_ids = asyncio.run(
            bot._assign_auto_roles_on_join(server, member)
        )

        self.assertEqual(granted_role_ids, [])
        self.assertEqual(failed_role_ids, ["auto-role"])
        member.edit.assert_not_awaited()
        bot.require_action_permissions.assert_not_awaited()
        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertTrue(details["member_confirmation_unavailable"])

    def test_auto_role_retries_have_a_global_per_join_write_budget(self) -> None:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=[],
            edit=AsyncMock(),
        )
        fetched_member = SimpleNamespace(
            id="user",
            role_ids=[],
            edit=AsyncMock(return_value=SimpleNamespace(role_ids=[])),
        )
        role_ids = [f"role-{index}" for index in range(5)]
        server = SimpleNamespace(
            id="current",
            roles={
                role_id: SimpleNamespace(name=role_id)
                for role_id in role_ids
            },
            fetch_member=AsyncMock(return_value=fetched_member),
        )
        bot.database = SimpleNamespace(
            list_auto_roles=Mock(return_value=role_ids),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        with patch("bot.asyncio.sleep", new=AsyncMock(return_value=None)):
            granted_role_ids, failed_role_ids = asyncio.run(
                bot._assign_auto_roles_on_join(server, member)
            )

        self.assertEqual(granted_role_ids, [])
        self.assertEqual(failed_role_ids, role_ids)
        self.assertEqual(fetched_member.edit.await_count, 9)
        details = bot.database.add_event.call_args.kwargs["details"]
        self.assertEqual(details["retry_edit_attempts"], 8)
        self.assertTrue(details["retry_edit_budget_exhausted"])

    def test_join_skips_hierarchy_blocked_auto_role_and_assigns_the_rest(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=["existing-role"],
            edit=AsyncMock(),
            get_user=Mock(
                return_value=SimpleNamespace(
                    created_at=datetime.now(timezone.utc) - timedelta(days=30),
                    bot=False,
                )
            ),
        )

        def edit_roles(*, roles: list[str]) -> SimpleNamespace:
            member.role_ids = list(roles)
            return SimpleNamespace(role_ids=roles)

        member.edit.side_effect = edit_roles
        bot_member = SimpleNamespace(
            id="bot", top_role=SimpleNamespace(rank=10)
        )
        server = SimpleNamespace(
            roles={
                "existing-role": SimpleNamespace(name="Existing", rank=50),
                "allowed-role": SimpleNamespace(name="Member", rank=20),
                "blocked-role": SimpleNamespace(name="Admin", rank=5),
            },
            get_member=Mock(return_value=bot_member),
            fetch_member=AsyncMock(return_value=member),
        )
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=None),
            list_auto_roles=Mock(return_value=["blocked-role", "allowed-role"]),
            record_daily_member_change=Mock(),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=server)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        asyncio.run(bot.handle_member_join(SimpleNamespace(member=member)))

        member.edit.assert_awaited_once_with(
            roles=["existing-role", "allowed-role"]
        )

    def test_auto_role_assignability_uses_stoat_role_ranking(self) -> None:
        bot_member = SimpleNamespace(top_role=SimpleNamespace(rank=10))

        self.assertTrue(
            ModerationBot._role_is_assignable(
                bot_member, SimpleNamespace(rank=20)
            )
        )
        self.assertFalse(
            ModerationBot._role_is_assignable(
                bot_member, SimpleNamespace(rank=5)
            )
        )
        self.assertIsNone(
            ModerationBot._role_is_assignable(
                SimpleNamespace(top_role=None), SimpleNamespace(rank=20)
            )
        )

    def test_join_retries_auto_roles_individually_after_batch_failure(self) -> None:
        bot = object.__new__(ModerationBot)

        def edit_roles(*, roles: list[str]) -> SimpleNamespace:
            if "bad-role" in roles:
                raise PermissionError("bad role rejected")
            member.role_ids = list(roles)
            return SimpleNamespace(role_ids=roles)

        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=["existing-role"],
            edit=AsyncMock(side_effect=edit_roles),
            get_user=Mock(
                return_value=SimpleNamespace(
                    created_at=datetime.now(timezone.utc) - timedelta(days=30),
                    bot=False,
                )
            ),
        )
        server = SimpleNamespace(
            roles={
                "bad-role": SimpleNamespace(name="Bad"),
                "good-role": SimpleNamespace(name="Good"),
            },
            fetch_member=AsyncMock(side_effect=lambda _user_id: member),
        )
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=None),
            list_auto_roles=Mock(return_value=["bad-role", "good-role"]),
            record_daily_member_change=Mock(),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=server)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)

        with patch("bot.asyncio.sleep", new=AsyncMock(return_value=None)):
            asyncio.run(bot.handle_member_join(SimpleNamespace(member=member)))

        self.assertEqual(
            member.edit.await_args_list,
            [
                call(roles=["existing-role", "bad-role", "good-role"]),
                call(roles=["existing-role", "bad-role"]),
                call(roles=["existing-role", "bad-role"]),
                call(roles=["existing-role", "good-role"]),
            ],
        )
        self.assertEqual(member.role_ids, ["existing-role", "good-role"])

    def test_join_enforces_captcha_before_assigning_auto_role(self) -> None:
        bot = object.__new__(ModerationBot)
        operation_order: list[str] = []

        async def edit_roles(*, roles: list[str]) -> SimpleNamespace:
            operation_order.append("auto-role")
            member.role_ids = list(roles)
            return SimpleNamespace(role_ids=roles)

        async def issue_captcha(_server: object, _member: object) -> bool:
            operation_order.append("captcha")
            return True

        member = SimpleNamespace(
            id="user",
            server_id="current",
            role_ids=[],
            edit=AsyncMock(side_effect=edit_roles),
            get_user=Mock(
                return_value=SimpleNamespace(
                    created_at=datetime.now(timezone.utc) - timedelta(days=1),
                    bot=None,
                )
            ),
        )
        server = SimpleNamespace(
            id="current",
            roles={"member-role": SimpleNamespace(name="Member")},
            fetch_member=AsyncMock(return_value=member),
        )
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=None),
            list_auto_roles=Mock(return_value=["member-role"]),
            record_daily_member_change=Mock(),
            add_event=Mock(),
            get_join_protection=Mock(return_value=True),
            get_captcha_all_members=Mock(return_value=False),
        )
        bot.get_server = Mock(return_value=server)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot.issue_join_captcha = AsyncMock(side_effect=issue_captcha)

        asyncio.run(bot.handle_member_join(SimpleNamespace(member=member)))

        self.assertEqual(operation_order, ["captcha", "auto-role"])
        self.assertEqual(member.role_ids, ["member-role"])
        self.assertIn("**Automatic roles:** <@&member-role>", bot.send_log.await_args.args[2])

    def test_join_captcha_is_enforced_before_dm_delivery(self) -> None:
        bot = object.__new__(ModerationBot)
        operation_order: list[str] = []
        challenge = CaptchaChallenge(
            "server",
            "member",
            "token-hash",
            "web",
            "2099-01-01T00:30:00+00:00",
            "2099-01-01T00:00:00+00:00",
        )

        async def open_dm() -> SimpleNamespace:
            operation_order.append("open-dm")
            return SimpleNamespace(send=AsyncMock(side_effect=send_dm))

        async def send_dm(**_kwargs: object) -> None:
            operation_order.append("send-dm")

        async def timeout(until: object) -> SimpleNamespace:
            operation_order.append("timeout")
            return SimpleNamespace(timed_out_until=until)

        def set_challenge(*_args: object) -> CaptchaChallenge:
            operation_order.append("challenge")
            return challenge

        def schedule_expiry(_challenge: CaptchaChallenge) -> None:
            operation_order.append("expiry")

        member = SimpleNamespace(
            id="member",
            open_dm=AsyncMock(side_effect=open_dm),
            timeout=AsyncMock(side_effect=timeout),
        )
        server = SimpleNamespace(id="server", name="Test server")
        bot.database = SimpleNamespace(
            set_web_verification_challenge=Mock(side_effect=set_challenge),
            remove_captcha_challenge=Mock(),
            add_event=Mock(),
        )
        bot.moderation_settings = SimpleNamespace(dashboard_url="https://example.test")
        bot._captcha_tasks = {}
        bot._moderator_is_exempt = Mock(return_value=False)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._localized_text = Mock(side_effect=lambda _server_id, text: text)
        bot._localized_embed = Mock(return_value=SimpleNamespace())
        bot._schedule_captcha_expiry = Mock(side_effect=schedule_expiry)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        issued = asyncio.run(bot.issue_join_captcha(server, member))

        self.assertTrue(issued)
        self.assertEqual(
            operation_order,
            ["timeout", "challenge", "expiry", "open-dm", "send-dm"],
        )
        timeout_until = member.timeout.await_args.args[0]
        self.assertIsInstance(timeout_until, datetime)
        self.assertIsNotNone(timeout_until.tzinfo)
        issued_event = bot.database.add_event.call_args.kwargs
        self.assertEqual(issued_event["event_type"], "join_captcha_issued")

    def test_join_captcha_does_not_claim_an_unconfirmed_timeout(self) -> None:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(
            id="member",
            open_dm=AsyncMock(),
            timeout=AsyncMock(
                return_value=SimpleNamespace(timed_out_until=None)
            ),
        )
        server = SimpleNamespace(id="server", name="Test server")
        bot.database = SimpleNamespace(
            set_web_verification_challenge=Mock(),
            add_event=Mock(),
        )
        bot.moderation_settings = SimpleNamespace(dashboard_url="https://example.test")
        bot._captcha_tasks = {}
        bot._moderator_is_exempt = Mock(return_value=False)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        issued = asyncio.run(bot.issue_join_captcha(server, member))

        self.assertFalse(issued)
        member.open_dm.assert_not_awaited()
        bot.database.set_web_verification_challenge.assert_not_called()
        failed_event = bot.database.add_event.call_args.kwargs
        self.assertEqual(
            failed_event["event_type"], "join_captcha_restriction_failed"
        )
        bot.send_log.assert_awaited_once()

    def test_join_captcha_dm_error_never_restricts_member(self) -> None:
        bot = object.__new__(ModerationBot)

        async def timeout(until: object) -> SimpleNamespace:
            return SimpleNamespace(timed_out_until=until)

        member = SimpleNamespace(
            id="member",
            open_dm=AsyncMock(side_effect=RuntimeError("DMs disabled")),
            timeout=AsyncMock(side_effect=timeout),
        )
        server = SimpleNamespace(id="server", name="Test server")
        bot.database = SimpleNamespace(
            set_web_verification_challenge=Mock(),
            remove_captcha_challenge=Mock(return_value=True),
            add_event=Mock(),
        )
        bot.moderation_settings = SimpleNamespace(dashboard_url="https://example.test")
        bot._captcha_tasks = {}
        bot._moderator_is_exempt = Mock(return_value=False)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._localized_text = Mock(side_effect=lambda _server_id, text: text)
        bot._localized_embed = Mock(return_value=SimpleNamespace())
        bot._schedule_captcha_expiry = Mock()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        issued = asyncio.run(bot.issue_join_captcha(server, member))

        self.assertFalse(issued)
        self.assertEqual(member.timeout.await_args_list, [call(ANY), call(None)])
        bot.database.set_web_verification_challenge.assert_called_once()
        bot.database.remove_captcha_challenge.assert_called_once_with(
            "server", "member"
        )
        bot._schedule_captcha_expiry.assert_called_once()
        failed_event = bot.database.add_event.call_args.kwargs
        self.assertEqual(failed_event["event_type"], "join_captcha_delivery_failed")
        self.assertFalse(failed_event["details"]["restriction_applied"])
        self.assertTrue(failed_event["details"]["restriction_removed"])

    def test_join_captcha_hanging_dm_times_out_without_restriction(self) -> None:
        bot = object.__new__(ModerationBot)

        async def hang_forever() -> None:
            await asyncio.Event().wait()

        async def timeout(until: object) -> SimpleNamespace:
            return SimpleNamespace(timed_out_until=until)

        member = SimpleNamespace(
            id="member",
            open_dm=AsyncMock(side_effect=hang_forever),
            timeout=AsyncMock(side_effect=timeout),
        )
        server = SimpleNamespace(id="server", name="Test server")
        bot.database = SimpleNamespace(
            set_web_verification_challenge=Mock(),
            remove_captcha_challenge=Mock(return_value=True),
            add_event=Mock(),
        )
        bot.moderation_settings = SimpleNamespace(dashboard_url="https://example.test")
        bot._captcha_tasks = {}
        bot._moderator_is_exempt = Mock(return_value=False)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._localized_text = Mock(side_effect=lambda _server_id, text: text)
        bot._localized_embed = Mock(return_value=SimpleNamespace())
        bot._schedule_captcha_expiry = Mock()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        with patch("bot.CAPTCHA_DELIVERY_TIMEOUT_SECONDS", 0.01):
            issued = asyncio.run(bot.issue_join_captcha(server, member))

        self.assertFalse(issued)
        self.assertEqual(member.timeout.await_args_list, [call(ANY), call(None)])
        bot.database.set_web_verification_challenge.assert_called_once()
        bot.database.remove_captcha_challenge.assert_called_once_with(
            "server", "member"
        )
        bot._schedule_captcha_expiry.assert_called_once()
        failed_event = bot.database.add_event.call_args.kwargs
        self.assertEqual(failed_event["details"]["reason"], "dm_timeout")

    def test_join_captcha_setup_failure_cancels_expiry_and_timeout(self) -> None:
        bot = object.__new__(ModerationBot)
        dm = SimpleNamespace(send=AsyncMock())

        async def timeout(until: object) -> SimpleNamespace:
            return SimpleNamespace(timed_out_until=until)

        member = SimpleNamespace(
            id="member",
            open_dm=AsyncMock(return_value=dm),
            timeout=AsyncMock(side_effect=timeout),
        )
        server = SimpleNamespace(id="server", name="Test server")
        bot.database = SimpleNamespace(
            set_web_verification_challenge=Mock(
                side_effect=RuntimeError("database unavailable")
            ),
            remove_captcha_challenge=Mock(return_value=True),
            add_event=Mock(),
        )
        bot.moderation_settings = SimpleNamespace(dashboard_url="https://example.test")
        bot._captcha_tasks = {}
        bot._moderator_is_exempt = Mock(return_value=False)
        bot.require_action_permissions = AsyncMock(return_value=True)
        bot._localized_text = Mock(side_effect=lambda _server_id, text: text)
        bot._localized_embed = Mock(return_value=SimpleNamespace())
        bot._schedule_captcha_expiry = Mock()
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.send_log = AsyncMock()

        issued = asyncio.run(bot.issue_join_captcha(server, member))

        self.assertFalse(issued)
        self.assertEqual(
            member.timeout.await_args_list,
            [call(ANY), call(None)],
        )
        bot.database.remove_captcha_challenge.assert_not_called()
        failed_event = bot.database.add_event.call_args.kwargs
        self.assertEqual(failed_event["event_type"], "join_captcha_setup_failed")
        self.assertTrue(failed_event["details"]["restriction_removed"])

    def test_captcha_is_unique_png_with_case_insensitive_hash(self) -> None:
        first_answer, first_image = ModerationBot._generate_captcha_image()
        second_answer, second_image = ModerationBot._generate_captcha_image()

        self.assertEqual(len(first_answer), 7)
        self.assertTrue(first_image.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertNotEqual(first_image, second_image)
        self.assertEqual(
            ModerationBot._captcha_hash(first_answer, "salt"),
            ModerationBot._captcha_hash(first_answer.lower(), "salt"),
        )
        self.assertNotEqual(
            ModerationBot._captcha_hash(first_answer, "salt"),
            ModerationBot._captcha_hash(first_answer, "different-salt"),
        )

    def test_incorrect_answer_replacement_preserves_deadline(self) -> None:
        bot = object.__new__(ModerationBot)
        original = CaptchaChallenge(
            "server",
            "user",
            "old-hash",
            "old-salt",
            "2099-01-01T00:00:00+00:00",
            "2026-08-05T00:00:00+00:00",
        )
        replacement = CaptchaChallenge(
            "server",
            "user",
            "new-hash",
            "new-salt",
            original.expires_at,
            "2026-08-05T00:01:00+00:00",
        )
        bot.database = SimpleNamespace(
            set_captcha_challenge=Mock(return_value=replacement)
        )
        bot._generate_captcha_image = Mock(return_value=("NEWCODE", b"png"))
        bot._schedule_captcha_expiry = Mock()
        bot.get_server = Mock(return_value=SimpleNamespace(name="Test server"))
        message = SimpleNamespace(
            channel=SimpleNamespace(send=AsyncMock())
        )

        sent = asyncio.run(bot.replace_captcha(message, original))

        self.assertTrue(sent)
        call = bot.database.set_captcha_challenge.call_args
        self.assertEqual(call.args[4], original.expires_at)
        bot._schedule_captcha_expiry.assert_called_once_with(replacement)
        message.channel.send.assert_awaited_once()

    def test_global_command_is_silently_rejected_for_non_owner(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._send_global_announcement = AsyncMock()
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            content="~global_announce This must not be delivered.",
            author_id="not-the-owner",
        )

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        self.assertNotEqual(message.author_id, GLOBAL_COMMAND_OWNER_ID)
        bot._send_global_announcement.assert_not_awaited()
        bot.send_command_response.assert_not_awaited()

    def test_global_announce_pings_each_server_owner_in_configured_logs(self) -> None:
        bot = object.__new__(ModerationBot)
        first_channel = SimpleNamespace(send=AsyncMock())
        second_channel = SimpleNamespace(send=AsyncMock())
        servers = {
            "server-one": SimpleNamespace(
                id="server-one", name="First server", owner_id="owner-one"
            ),
        }
        targets = [
            {
                "server_id": "server-one",
                "server_name": "First server",
                "owner_id": "owner-one",
                "log_channel_id": "log-one",
            },
            {
                "server_id": "server-two",
                "server_name": "Second server",
                "owner_id": "owner-two",
                "log_channel_id": "log-two",
            },
            {
                "server_id": "server-without-log",
                "server_name": "No log",
                "owner_id": "owner-three",
                "log_channel_id": None,
            },
        ]
        bot.database = SimpleNamespace(
            list_global_announcement_targets=Mock(return_value=targets),
            create_dashboard_announcement=Mock(),
            add_event=Mock(),
        )
        bot.get_channel = Mock(
            side_effect=lambda channel_id: (
                first_channel if channel_id == "log-one" else None
            )
        )
        bot.fetch_channel = AsyncMock(return_value=second_channel)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            content="~global_announce Scheduled maintenance begins at 20:00 UTC.",
            author_id=GLOBAL_COMMAND_OWNER_ID,
            get_server=Mock(return_value=(None, None)),
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value=servers,
        ):
            handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        first_channel.send.assert_awaited_once()
        second_channel.send.assert_awaited_once()
        first_delivery = first_channel.send.await_args.kwargs
        second_delivery = second_channel.send.await_args.kwargs
        self.assertIn("<@owner-one>", first_delivery["content"])
        self.assertIn("<@owner-two>", second_delivery["content"])
        self.assertFalse(first_delivery["mention_everyone"])
        self.assertFalse(first_delivery["mention_online"])
        embed = first_delivery["embeds"][0]
        self.assertEqual(embed.title, "📣 OFFICIAL STOATMOD ANNOUNCEMENT")
        self.assertEqual(embed.color, "#F2C94C")
        self.assertIn("Scheduled maintenance begins at 20:00 UTC.", embed.description)
        self.assertIn("https://stt.gg/PCaYw69F", embed.description)
        self.assertIn("admin@modstoat.site", embed.description)
        summary = bot.send_command_response.await_args.args[2]
        self.assertIn("**Configured log channels:** 2", summary)
        self.assertIn("**Delivered:** 2", summary)
        self.assertIn("**Failed:** 0", summary)
        self.assertEqual(bot.database.create_dashboard_announcement.call_count, 3)
        self.assertEqual(bot.database.add_event.call_count, 3)
        self.assertEqual(
            [
                call.args[0]
                for call in bot.database.create_dashboard_announcement.call_args_list
            ],
            ["server-one", "server-two", "server-without-log"],
        )
        bot.fetch_channel.assert_awaited_once_with("log-two")

    def test_global_announce_continues_after_one_log_delivery_fails(self) -> None:
        bot = object.__new__(ModerationBot)
        failed_channel = SimpleNamespace(
            send=AsyncMock(side_effect=PermissionError("cannot send"))
        )
        working_channel = SimpleNamespace(send=AsyncMock())
        servers = {
            "failed": SimpleNamespace(
                id="failed", name="Failed server", owner_id="failed-owner"
            ),
            "working": SimpleNamespace(
                id="working", name="Working server", owner_id="working-owner"
            ),
        }
        bot.database = SimpleNamespace(
            get_log_channel=Mock(return_value="log"),
            create_dashboard_announcement=Mock(),
            add_event=Mock(),
        )
        bot.get_channel = Mock(
            side_effect=[failed_channel, working_channel]
        )
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            content="~global_announce Important network update.",
            author_id=GLOBAL_COMMAND_OWNER_ID,
            get_server=Mock(return_value=(None, None)),
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value=servers,
        ):
            handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        failed_channel.send.assert_awaited_once()
        working_channel.send.assert_awaited_once()
        summary = bot.send_command_response.await_args.args[2]
        self.assertIn("**Delivered:** 1", summary)
        self.assertIn("**Failed:** 1", summary)
        self.assertEqual(
            bot.send_command_response.await_args.kwargs["color"], "#F59E0B"
        )
        self.assertEqual(bot.database.create_dashboard_announcement.call_count, 2)
        self.assertEqual(bot.database.add_event.call_count, 2)

    def test_global_announce_keeps_dashboard_delivery_for_a_deleted_log(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            list_global_announcement_targets=Mock(
                return_value=[
                    {
                        "server_id": "stale-server",
                        "server_name": "Stale server",
                        "owner_id": "server-owner",
                        "log_channel_id": "deleted-log",
                    }
                ]
            ),
            create_dashboard_announcement=Mock(),
            add_event=Mock(),
        )
        bot.get_channel = Mock(return_value=None)
        bot.fetch_channel = AsyncMock(side_effect=LookupError("channel deleted"))
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            content="~global_announce Important network update.",
            author_id=GLOBAL_COMMAND_OWNER_ID,
            get_server=Mock(return_value=(None, None)),
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={},
        ):
            handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.fetch_channel.assert_awaited_once_with("deleted-log")
        bot.database.create_dashboard_announcement.assert_called_once()
        bot.database.add_event.assert_called_once()
        summary = bot.send_command_response.await_args.args[2]
        self.assertIn("**Configured log channels:** 1", summary)
        self.assertIn("**Delivered:** 0", summary)
        self.assertIn("**Failed:** 1", summary)

    def test_info_alias_shows_server_information_without_moderator_check(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~info",
            get_server=Mock(return_value=(server, "server")),
        )
        bot._server_information_description = AsyncMock(
            return_value="server details"
        )
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot._server_information_description.assert_awaited_once_with(
            server, "server"
        )
        bot.send_command_response.assert_awaited_once()

    def test_dashboard_command_sends_single_use_code_to_moderator_dm(self) -> None:
        bot = object.__new__(ModerationBot)
        member = object()
        server = SimpleNamespace(
            name="Test server",
            owner_id="server-owner",
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_server=True)
            ),
        )
        dm = SimpleNamespace(send=AsyncMock())
        user = SimpleNamespace(open_dm=AsyncMock(return_value=dm))
        message = SimpleNamespace(
            content="~dashboard",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=user),
            get_author_as_member=Mock(return_value=member),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.refresh_dashboard_server = AsyncMock()
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://dashboard.example.com"
        )
        bot.database = SimpleNamespace(
            dashboard_user_has_access=Mock(return_value=True),
            create_dashboard_login_code=Mock(),
            add_event=Mock(),
        )
        bot._embed = Mock(return_value="dashboard-embed")
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.refresh_dashboard_server.assert_awaited_once_with(server)
        bot.database.create_dashboard_login_code.assert_called_once()
        bot.database.dashboard_user_has_access.assert_called_once_with(
            "server",
            "moderator",
            owner_id="server-owner",
            manage_server=True,
        )
        stored_hash = bot.database.create_dashboard_login_code.call_args.args[0]
        self.assertEqual(len(stored_hash), 64)
        dm.send.assert_awaited_once_with(embeds=["dashboard-embed"])
        self.assertIn(
            "https://dashboard.example.com/login", bot._embed.call_args.args[1]
        )

    def test_dashboard_command_recovers_uncached_channel_server_and_member(self) -> None:
        bot = object.__new__(ModerationBot)
        member = object()
        server = SimpleNamespace(
            name="Test server",
            owner_id="server-owner",
            permissions_for=Mock(
                return_value=SimpleNamespace(manage_server=True)
            ),
        )
        dm = SimpleNamespace(send=AsyncMock())
        user = SimpleNamespace(open_dm=AsyncMock(return_value=dm))
        message = SimpleNamespace(
            content="~dashboard",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(None, "")),
            get_author_as_user=Mock(return_value=user),
            get_author_as_member=Mock(return_value=None),
        )
        bot.fetch_channel = AsyncMock(return_value=SimpleNamespace(server_id="server"))
        bot._resolve_dashboard_server = AsyncMock(return_value=server)
        server.fetch_member = AsyncMock(return_value=member)
        bot._is_moderator = Mock(return_value=True)
        bot.refresh_dashboard_server = AsyncMock()
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://dashboard.example.com"
        )
        bot.database = SimpleNamespace(
            dashboard_user_has_access=Mock(return_value=True),
            create_dashboard_login_code=Mock(),
            add_event=Mock(),
        )
        bot._embed = Mock(return_value="dashboard-embed")
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.refresh_dashboard_server.assert_awaited_once_with(server)
        bot.database.create_dashboard_login_code.assert_called_once()
        bot.database.dashboard_user_has_access.assert_called_once_with(
            "server",
            "moderator",
            owner_id="server-owner",
            manage_server=True,
        )
        stored_hash = bot.database.create_dashboard_login_code.call_args.args[0]
        self.assertEqual(len(stored_hash), 64)
        dm.send.assert_awaited_once_with(embeds=["dashboard-embed"])
        self.assertIn(
            "https://dashboard.example.com/login", bot._embed.call_args.args[1]
        )

    def test_dashboard_cache_miss_in_real_dm_stays_server_only(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.fetch_channel = AsyncMock(return_value=SimpleNamespace())
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(content="~dashboard", channel_id="dm", author_id="user", get_server=Mock(return_value=(None, "")))
        asyncio.run(bot.handle_command(message))
        self.assertEqual(bot.send_command_response.await_args.args[1], "Server-only command")

    def test_dashboard_lookup_outage_does_not_claim_channel_is_dm(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.fetch_channel = AsyncMock(side_effect=RuntimeError("temporarily unavailable"))
        bot.send_command_response = AsyncMock()
        bot.database = SimpleNamespace(create_dashboard_login_code=Mock())
        message = SimpleNamespace(content="~dashboard", channel_id="channel", author_id="user", get_server=Mock(return_value=(None, "")))
        asyncio.run(bot.handle_command(message))
        self.assertEqual(bot.send_command_response.await_args.args[1], "Dashboard temporarily unavailable")
        bot.database.create_dashboard_login_code.assert_not_called()

    def test_dashboard_command_requires_owner_granted_access(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(name="Test server", owner_id="server-owner")
        message = SimpleNamespace(
            content="~dashboard",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
        )
        bot.database = SimpleNamespace(
            dashboard_user_has_access=Mock(return_value=False)
        )
        bot._is_moderator = Mock(return_value=True)
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.dashboard_user_has_access.assert_called_once_with(
            "server",
            "moderator",
            owner_id="server-owner",
            manage_server=False,
        )
        bot.send_command_response.assert_awaited_once()
        self.assertEqual(
            bot.send_command_response.call_args.args[1], "Dashboard access denied"
        )

    def test_dashboard_refresh_reconciles_both_complete_member_collections(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(
            id="server",
            name="Test server",
            banner=SimpleNamespace(url=Mock(return_value="https://cdn.stoatusercontent.com/banners/community")),
            members={"cached-bot": object()},
            channels=[],
            categories=[],
            roles={},
            fetch_member_list=AsyncMock(
                return_value=SimpleNamespace(
                    members=[object()] * 5,
                    users=[object()] * 6,
                )
            ),
        )
        bot.database = SimpleNamespace(
            update_dashboard_server_snapshot=Mock()
        )

        asyncio.run(bot.refresh_dashboard_server(server))

        call = bot.database.update_dashboard_server_snapshot.call_args
        self.assertEqual(call.args[2], 6)
        self.assertEqual(call.kwargs["server_banner_url"], "https://cdn.stoatusercontent.com/banners/community")

    def test_dashboard_refresh_can_correct_a_stale_cached_count_downward(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(
            id="server",
            name="Test server",
            members={f"stale-{index}": object() for index in range(12)},
            channels=[],
            categories=[],
            roles={},
            fetch_member_list=AsyncMock(
                return_value=SimpleNamespace(
                    members=[object()] * 5,
                    users=[object()] * 5,
                )
            ),
        )
        bot.database = SimpleNamespace(
            update_dashboard_server_snapshot=Mock()
        )

        asyncio.run(bot.refresh_dashboard_server(server))

        call = bot.database.update_dashboard_server_snapshot.call_args
        self.assertEqual(call.args[2], 5)

    def test_dashboard_refresh_fallback_uses_exact_fetched_count(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(
            id="server",
            name="Test server",
            members={f"stale-{index}": object() for index in range(12)},
            channels=[],
            categories=[],
            roles={},
            fetch_member_list=AsyncMock(side_effect=RuntimeError("unsupported")),
            fetch_members=AsyncMock(return_value=[object()] * 4),
        )
        bot.database = SimpleNamespace(
            update_dashboard_server_snapshot=Mock()
        )

        asyncio.run(bot.refresh_dashboard_server(server))

        call = bot.database.update_dashboard_server_snapshot.call_args
        self.assertEqual(call.args[2], 4)

    def test_dashboard_refresh_preserves_known_count_when_live_fetch_fails(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(
            id="server",
            name="Test server",
            members={"cached-bot": object()},
            channels=[],
            categories=[],
            roles={},
            fetch_member_list=AsyncMock(side_effect=RuntimeError("offline")),
            fetch_members=AsyncMock(side_effect=RuntimeError("offline")),
        )
        bot.database = SimpleNamespace(
            get_dashboard_server_member_count=Mock(return_value=42),
            update_dashboard_server_snapshot=Mock(),
        )

        asyncio.run(bot.refresh_dashboard_server(server))

        call = bot.database.update_dashboard_server_snapshot.call_args
        self.assertEqual(call.args[2], 42)

    def test_periodic_dashboard_member_refresh_repairs_every_server(self) -> None:
        bot = object.__new__(ModerationBot)
        first = SimpleNamespace(id="first")
        second = SimpleNamespace(id="second")
        bot.database = SimpleNamespace(
            update_dashboard_server_member_count=Mock(),
            replace_dashboard_members=Mock(),
        )
        first_members = [SimpleNamespace(id="one"), SimpleNamespace(id="two")]
        second_members = [SimpleNamespace(id="three")]
        bot._fetch_complete_dashboard_members = AsyncMock(
            side_effect=[
                (
                    first_members,
                    [SimpleNamespace(id="one"), SimpleNamespace(id="two")],
                ),
                (second_members, [SimpleNamespace(id="three")]),
            ]
        )
        bot._dashboard_member_snapshot = Mock(return_value=[])

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={"first": first, "second": second},
        ):
            refreshed = asyncio.run(bot.refresh_all_dashboard_member_counts())

        self.assertEqual(refreshed, 2)
        self.assertEqual(
            bot.database.update_dashboard_server_member_count.call_args_list,
            [call("first", 2), call("second", 1)],
        )

    def test_dashboard_refresh_audits_fetched_bot_member_after_restart(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot-user")
        joined_at = datetime(2025, 5, 10, 9, 0, tzinfo=timezone.utc)
        fetched_bot_member = SimpleNamespace(id="bot-user", joined_at=joined_at)
        server = SimpleNamespace(
            id="server",
            name="Test server",
            members={},
            channels=[],
            categories=[],
            roles={},
            fetch_member_list=AsyncMock(
                return_value=SimpleNamespace(
                    members=[fetched_bot_member], users=[]
                )
            ),
        )
        bot.database = SimpleNamespace(update_dashboard_server_snapshot=Mock())
        bot._dashboard_permission_audit = Mock(
            return_value={"available": True, "permissions": [], "missing_count": 0}
        )

        asyncio.run(bot.refresh_dashboard_server(server))

        bot._dashboard_permission_audit.assert_called_once_with(
            server, [], fetched_bot_member, []
        )
        self.assertEqual(
            bot.database.update_dashboard_server_snapshot.call_args.kwargs[
                "bot_joined_at"
            ],
            joined_at.isoformat(),
        )

    def test_dashboard_permission_audit_checks_every_setup_permission(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = SimpleNamespace(get_log_channel=Mock(return_value="mod-log"))
        member = object()
        server_permissions = {
            name: name not in {"manage_messages", "ban_members"}
            for name, _label, _impact in SERVER_PERMISSION_REQUIREMENTS
        }
        channel = SimpleNamespace(
            permissions_for=Mock(return_value=SimpleNamespace(
                view_channel=True, send_messages=False, send_embeds=True
            ))
        )
        server = SimpleNamespace(
            id="server",
            get_member=Mock(return_value=member),
            get_channel=Mock(return_value=channel),
            permissions_for=Mock(return_value=SimpleNamespace(**server_permissions)),
        )

        audit = bot._dashboard_permission_audit(server)

        self.assertTrue(audit["available"])
        self.assertEqual(
            len(audit["permissions"]), len(SERVER_PERMISSION_REQUIREMENTS)
        )
        self.assertEqual(audit["missing_count"], 2)
        self.assertEqual(audit["log_channel"]["missing"], ["Send Messages"])

    def test_dashboard_permission_audit_uses_log_channel_fetched_after_restart(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = SimpleNamespace(get_log_channel=Mock(return_value="mod-log"))
        member = object()
        permissions = {
            name: True for name, _label, _impact in SERVER_PERMISSION_REQUIREMENTS
        }
        log_channel = SimpleNamespace(
            id="mod-log",
            permissions_for=Mock(return_value=SimpleNamespace(
                view_channel=True, send_messages=True, send_embeds=True
            )),
        )
        server = SimpleNamespace(
            id="server",
            channels=[],
            get_member=Mock(return_value=member),
            get_channel=Mock(return_value=None),
            permissions_for=Mock(return_value=SimpleNamespace(**permissions)),
        )

        audit = bot._dashboard_permission_audit(
            server, bot_member=member, resolved_channels=[log_channel]
        )

        self.assertTrue(audit["log_channel"]["accessible"])
        self.assertEqual(audit["log_channel"]["missing"], [])

    def test_dashboard_permission_audit_survives_cold_channel_server_cache(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.database = SimpleNamespace(get_log_channel=Mock(return_value="mod-log"))
        member = object()
        permissions = {
            name: True for name, _label, _impact in SERVER_PERMISSION_REQUIREMENTS
        }
        log_channel = SimpleNamespace(
            id="mod-log",
            permissions_for=Mock(
                side_effect=stoat.NoData(
                    what="server", type="BaseServerChannel.server"
                )
            ),
        )
        server = SimpleNamespace(
            id="server",
            channels=[],
            get_member=Mock(return_value=member),
            get_channel=Mock(return_value=None),
            permissions_for=Mock(return_value=SimpleNamespace(**permissions)),
        )

        audit = bot._dashboard_permission_audit(
            server, bot_member=member, resolved_channels=[log_channel]
        )

        self.assertTrue(audit["available"])
        self.assertEqual(audit["missing_count"], 0)
        self.assertTrue(audit["log_channel"]["configured"])
        self.assertFalse(audit["log_channel"]["accessible"])
        self.assertEqual(
            audit["log_channel"]["missing"],
            ["Unable to verify moderation log channel permissions"],
        )

    def test_setup_audit_survives_cold_channel_server_cache(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://dashboard.example"
        )
        bot.database = SimpleNamespace(
            get_dashboard_overview=Mock(
                return_value={"permission_audit": {"inaccessible_channels": []}}
            ),
            get_log_channel=Mock(return_value="mod-log"),
            list_auto_roles=Mock(return_value=[]),
        )
        member = SimpleNamespace(id="bot", top_role=None)
        permissions = {
            name: True for name, _label, _impact in SERVER_PERMISSION_REQUIREMENTS
        }
        log_channel = SimpleNamespace(
            permissions_for=Mock(
                side_effect=stoat.NoData(
                    what="server", type="BaseServerChannel.server"
                )
            )
        )
        server = SimpleNamespace(
            id="server",
            roles={},
            get_member=Mock(return_value=member),
            get_channel=Mock(return_value=log_channel),
            permissions_for=Mock(return_value=SimpleNamespace(**permissions)),
        )

        description = asyncio.run(bot._setup_audit_description(server))

        self.assertIn("permissions could not be verified yet", description)
        self.assertIn("Found **1** setup issue", description)

    def test_invite_generation_is_not_a_setup_permission(self) -> None:
        permission_names = {
            name for name, _label, _impact in SERVER_PERMISSION_REQUIREMENTS
        }

        self.assertNotIn("create_invites", permission_names)
        self.assertNotIn("manage_server", permission_names)

    def test_owner_support_invite_returns_a_random_active_invite(self) -> None:
        bot = object.__new__(ModerationBot)
        first = SimpleNamespace(code="FIRST", channel_id="general")
        selected = SimpleNamespace(code="SUPPORT1", channel_id="support")
        server = SimpleNamespace(fetch_invites=AsyncMock(return_value=[first, selected]))

        with patch("bot.secrets.choice", return_value=selected) as choice:
            result = asyncio.run(bot._get_owner_server_invite(server))

        self.assertEqual(result["invite_url"], "https://stt.gg/SUPPORT1")
        self.assertEqual(result["channel_id"], "support")
        server.fetch_invites.assert_awaited_once()
        choice.assert_called_once_with([first, selected])

    def test_owner_support_invite_explains_missing_manage_server(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(
            fetch_invites=AsyncMock(
                side_effect=PermissionError(
                    "MissingPermission (raw={'type': 'MissingPermission'})"
                )
            )
        )

        with self.assertRaisesRegex(
            RuntimeError, "does not have Manage Server permission"
        ):
            asyncio.run(bot._get_owner_server_invite(server))

    def test_owner_support_invite_reports_when_none_are_active(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(fetch_invites=AsyncMock(return_value=[]))

        with self.assertRaisesRegex(RuntimeError, "no active invites"):
            asyncio.run(bot._get_owner_server_invite(server))

    def test_poll_delivery_resolves_live_server_after_cache_miss(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 501,
            "server_id": "server-a",
            "action": "publish_poll",
            "actor_id": "owner-a",
            "payload": {"poll_id": 12},
        }

        def claim_once():
            bot._closing = True
            return [action]

        poll = {
            "id": 12,
            "status": "open",
            "message_id": None,
            "channel_id": "poll-channel",
            "question": "Choose one",
            "options": [
                {"emoji": "🍎", "label": "Apple"},
                {"emoji": "🍐", "label": "Pear"},
            ],
            "multiple_choice": False,
            "required_role_id": None,
            "quorum": 0,
            "anonymous": False,
        }
        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_poll=Mock(return_value=poll),
            set_poll_message=Mock(),
            add_event=Mock(),
            finish_dashboard_action=Mock(return_value=True),
        )
        server = SimpleNamespace(id="server-a")
        channel = SimpleNamespace(
            server_id="server-a",
            send=AsyncMock(return_value=SimpleNamespace(id="poll-message")),
        )
        bot._resolve_dashboard_server = AsyncMock(return_value=server)
        bot.get_channel = Mock(return_value=channel)
        bot.fetch_channel = AsyncMock()
        bot._embed = Mock(return_value=SimpleNamespace())

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot._resolve_dashboard_server.assert_awaited_once_with("server-a")
        channel.send.assert_awaited_once()
        bot.database.set_poll_message.assert_called_once_with(12, "poll-message")
        bot.database.finish_dashboard_action.assert_called_once_with(
            501,
            success=True,
            result={"poll_id": 12, "message_id": "poll-message"},
        )

    def test_poll_delivery_retries_transient_send_failure(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 502,
            "server_id": "server-a",
            "action": "publish_poll",
            "actor_id": "owner-a",
            "payload": {"poll_id": 12},
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_poll=Mock(return_value={
                "status": "open",
                "message_id": None,
                "channel_id": "poll-channel",
                "question": "Choose one",
                "options": [
                    {"emoji": "🍎", "label": "Apple"},
                    {"emoji": "🍐", "label": "Pear"},
                ],
                "multiple_choice": False,
                "required_role_id": None,
                "quorum": 0,
                "anonymous": False,
            }),
            defer_dashboard_action=Mock(return_value=True),
            finish_dashboard_action=Mock(),
        )
        channel = SimpleNamespace(
            server_id="server-a",
            send=AsyncMock(side_effect=RuntimeError("temporary send failure")),
        )
        bot._resolve_dashboard_server = AsyncMock(
            return_value=SimpleNamespace(id="server-a")
        )
        bot.get_channel = Mock(return_value=channel)
        bot.fetch_channel = AsyncMock()
        bot._embed = Mock(return_value=SimpleNamespace())

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        retry = bot.database.defer_dashboard_action
        retry.assert_called_once()
        self.assertEqual(retry.call_args.args[0], 502)
        self.assertEqual(retry.call_args.kwargs["payload"]["retry_count"], 1)
        self.assertIn("temporary send failure", retry.call_args.kwargs["error"])
        bot.database.finish_dashboard_action.assert_not_called()

    def test_existing_poll_message_is_not_published_twice(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 503,
            "server_id": "server-a",
            "action": "publish_poll",
            "actor_id": "owner-a",
            "payload": {"poll_id": 12},
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_poll=Mock(return_value={
                "status": "open", "message_id": "existing-message"
            }),
            finish_dashboard_action=Mock(return_value=True),
        )
        bot._resolve_dashboard_server = AsyncMock()

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot._resolve_dashboard_server.assert_not_awaited()
        bot.database.finish_dashboard_action.assert_called_once_with(
            503,
            success=True,
            result={
                "poll_id": 12,
                "message_id": "existing-message",
                "already_published": True,
            },
        )

    def test_local_report_instructions_resolve_live_server(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._closing = False
        bot._last_heartbeat_write = float("inf")
        action = {
            "id": 504,
            "server_id": "server-a",
            "action": "post_local_report_instructions",
            "actor_id": "owner-a",
            "payload": {"channel_id": "reports-channel"},
        }

        def claim_once():
            bot._closing = True
            return [action]

        bot.database = SimpleNamespace(
            queue_due_admin_password_rotations=Mock(return_value=0),            claim_dashboard_actions=Mock(side_effect=claim_once),
            get_local_report_settings=Mock(return_value={
                "enabled": True,
                "channel_id": "reports-channel",
            }),
            set_local_report_instruction_message=Mock(return_value=True),
            finish_dashboard_action=Mock(return_value=True),
        )
        channel = SimpleNamespace(
            server_id="server-a",
            send=AsyncMock(return_value=SimpleNamespace(id="instructions-message")),
        )
        bot._resolve_dashboard_server = AsyncMock(
            return_value=SimpleNamespace(id="server-a")
        )
        bot.get_channel = Mock(return_value=channel)
        bot.fetch_channel = AsyncMock()
        bot._embed = Mock(return_value=SimpleNamespace())

        with patch("bot.asyncio.sleep", new_callable=AsyncMock):
            asyncio.run(bot._run_dashboard_actions())

        bot._resolve_dashboard_server.assert_awaited_once_with("server-a")
        channel.send.assert_awaited_once()
        self.assertIn(
            "any channel in this server",
            bot._embed.call_args.args[1],
        )
        bot.database.set_local_report_instruction_message.assert_called_once_with(
            "server-a", "reports-channel", "instructions-message"
        )
        bot.database.finish_dashboard_action.assert_called_once_with(
            504,
            success=True,
            result={
                "channel_id": "reports-channel",
                "message_id": "instructions-message",
            },
        )

    def test_failed_local_report_dm_removes_the_unused_token(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            list_local_report_servers_for_user=Mock(return_value=[{
                "server_id": "server-a", "server_name": "Server A"
            }]),
            get_local_report_settings=Mock(return_value={"enabled": True}),
            create_report_token=Mock(),
            consume_report_token=Mock(return_value=True),
        )
        server = SimpleNamespace(
            id="server-a",
            name="Server A",
            get_member=Mock(return_value=SimpleNamespace(id="member-a")),
        )
        bot._resolve_dashboard_server = AsyncMock(return_value=server)
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://modstoat.site"
        )
        bot._send_user_dm = AsyncMock(return_value=False)
        bot.send_command_response = AsyncMock()
        user = SimpleNamespace(id="member-a")
        message = SimpleNamespace(
            content="~report",
            author_id="member-a",
            get_server=Mock(return_value=(None, None)),
            get_author_as_user=Mock(return_value=user),
        )

        handled = asyncio.run(bot.handle_report_entry(message))

        self.assertTrue(handled)
        bot.database.create_report_token.assert_called_once()
        created_hash = bot.database.create_report_token.call_args.args[0]
        bot.database.consume_report_token.assert_called_once_with(created_hash)
        bot.send_command_response.assert_awaited_once()

    def test_report_command_works_outside_the_instruction_channel(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            get_local_report_settings=Mock(return_value={
                "enabled": True,
                "channel_id": "report-instructions",
            }),
            create_report_token=Mock(),
        )
        server = SimpleNamespace(id="server-a", name="Server A")
        bot.moderation_settings = SimpleNamespace(
            dashboard_url="https://modstoat.site"
        )
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            id="command-message",
            channel_id="general",
            content="~report",
            author_id="member-a",
            get_server=Mock(return_value=(server, "server-a")),
            get_author_as_user=Mock(return_value=SimpleNamespace(id="member-a")),
            delete=AsyncMock(),
        )

        handled = asyncio.run(bot.handle_report_entry(message))

        self.assertTrue(handled)
        bot.database.get_local_report_settings.assert_called_once_with("server-a")
        bot.database.create_report_token.assert_called_once()
        self.assertEqual(
            bot.database.create_report_token.call_args.kwargs["report_scope"],
            "local",
        )
        bot._send_user_dm.assert_awaited_once()
        message.delete.assert_awaited_once()
        bot.send_command_response.assert_awaited_once()

    def test_owner_invite_server_resolution_falls_back_to_live_api(self) -> None:
        bot = object.__new__(ModerationBot)
        live_server = SimpleNamespace(id="server")
        bot.get_server = Mock(return_value=None)
        bot.fetch_server = AsyncMock(return_value=live_server)

        resolved = asyncio.run(bot._resolve_dashboard_server("server"))

        self.assertIs(resolved, live_server)
        bot.get_server.assert_called_once_with("server")
        bot.fetch_server.assert_awaited_once_with("server")

    def test_dashboard_server_resolution_uses_ready_event_server_without_fetch(
        self,
    ) -> None:
        bot = object.__new__(ModerationBot)
        ready_server = SimpleNamespace(id="server")
        bot._ready_event_servers = {"server": ready_server}
        bot.get_server = Mock(return_value=None)
        bot.fetch_server = AsyncMock(
            side_effect=AssertionError("Ready server should be reused")
        )

        resolved = asyncio.run(bot._resolve_dashboard_server("server"))

        self.assertIs(resolved, ready_server)
        bot.get_server.assert_not_called()
        bot.fetch_server.assert_not_awaited()

    def test_dashboard_server_resolution_only_suppresses_not_found(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.get_server = Mock(return_value=None)
        bot.fetch_server = AsyncMock(
            side_effect=stoat.NotFound(
                SimpleNamespace(status=404), {"type": "NotFound"}
            )
        )

        self.assertIsNone(asyncio.run(bot._resolve_dashboard_server("missing")))

        bot.fetch_server = AsyncMock(
            side_effect=RuntimeError("temporary Stoat API failure")
        )
        with self.assertRaisesRegex(RuntimeError, "temporary Stoat API failure"):
            asyncio.run(bot._resolve_dashboard_server("unavailable"))

    def test_dashboard_snapshot_uses_public_server_icon_url(self) -> None:
        server = SimpleNamespace(
            id="server",
            icon=SimpleNamespace(
                url=Mock(return_value="https://cdn.example/server.png")
            ),
        )

        self.assertEqual(
            ModerationBot._server_icon_url(server),
            "https://cdn.example/server.png",
        )
        self.assertIsNone(
            ModerationBot._server_icon_url(
                SimpleNamespace(id="server-without-icon", icon=None)
            )
        )

    def test_dashboard_refresh_fetches_channels_missing_from_cache(self) -> None:
        class FakeTextChannel:
            def __init__(
                self, channel_id: str, name: str, category_id: str | None
            ) -> None:
                self.id = channel_id
                self.name = name
                self.category_id = category_id
                self.server_id = "server"

        bot = object.__new__(ModerationBot)
        category = SimpleNamespace(
            id="category", title="Public", channels=["general", "staff"]
        )
        cached_channel = FakeTextChannel("general", "general", "category")
        fetched_channel = FakeTextChannel("staff", "staff", "category")
        server = SimpleNamespace(
            id="server",
            name="Test server",
            members={},
            channels=[cached_channel],
            channel_ids=["general", "staff"],
            categories=[category],
            roles={},
            fetch_member_list=AsyncMock(
                return_value=SimpleNamespace(members=[], users=[])
            ),
        )
        bot.fetch_channel = AsyncMock(return_value=fetched_channel)
        bot.database = SimpleNamespace(
            update_dashboard_server_snapshot=Mock()
        )

        with patch.object(stoat, "TextChannel", FakeTextChannel):
            asyncio.run(bot.refresh_dashboard_server(server))

        bot.fetch_channel.assert_awaited_once_with("staff")
        saved_channels = bot.database.update_dashboard_server_snapshot.call_args.args[3]
        self.assertEqual(
            saved_channels,
            [
                ("general", "general", "category"),
                ("staff", "staff", "category"),
            ],
        )

    def test_dashboard_refresh_removes_exemption_deleted_while_offline(self) -> None:
        class FakeTextChannel:
            def __init__(self, channel_id: str, name: str) -> None:
                self.id = channel_id
                self.name = name
                self.category_id = None
                self.server_id = "server"

        bot = object.__new__(ModerationBot)
        cached_channel = FakeTextChannel("general", "general")
        server = SimpleNamespace(
            id="server",
            name="Test server",
            members={},
            channels=[cached_channel],
            channel_ids=["general"],
            categories=[],
            roles={},
            fetch_member_list=AsyncMock(
                return_value=SimpleNamespace(members=[], users=[])
            ),
        )
        bot.fetch_channel = AsyncMock(
            side_effect=stoat.NotFound(
                SimpleNamespace(status=404), {"type": "NotFound"}
            )
        )
        bot.database = SimpleNamespace(
            list_scope_exclusions=Mock(return_value=[{
                "target_id": "deleted-channel", "target_type": "channel"
            }]),
            remove_deleted_channel_reference=Mock(return_value=True),
            update_dashboard_server_snapshot=Mock(),
        )

        with patch.object(stoat, "TextChannel", FakeTextChannel):
            asyncio.run(bot.refresh_dashboard_server(server))

        bot.fetch_channel.assert_awaited_once_with("deleted-channel")
        bot.database.remove_deleted_channel_reference.assert_called_once_with(
            "server", "deleted-channel"
        )

    def test_channel_delete_event_removes_only_confirmed_deleted_exemption(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.fetch_channel = AsyncMock(
            side_effect=stoat.NotFound(
                SimpleNamespace(status=404), {"type": "NotFound"}
            )
        )
        bot.database = SimpleNamespace(
            remove_deleted_channel_reference=Mock(return_value=True)
        )
        event = SimpleNamespace(
            channel_id="deleted-channel",
            channel=SimpleNamespace(server_id="server"),
        )

        asyncio.run(bot.handle_channel_delete(event))

        bot.database.remove_deleted_channel_reference.assert_called_once_with(
            "server", "deleted-channel"
        )

    def test_bypass_command_removes_pending_verification_without_case(self) -> None:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(id="member", timeout=AsyncMock())
        server = SimpleNamespace(
            name="Test server",
            get_member=Mock(return_value=member),
        )
        message = SimpleNamespace(
            content="~bypass member Verified manually",
            author_id="moderator",
            channel_id="staff",
            get_server=Mock(return_value=(server, "server")),
        )
        challenge = CaptchaChallenge(
            "server",
            "member",
            "token-hash",
            "web",
            "2099-01-01T00:00:00+00:00",
            "2026-08-11T00:00:00+00:00",
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_captcha_challenge=Mock(return_value=challenge),
            get_log_channel=Mock(return_value="staff"),
            remove_captcha_challenge=Mock(return_value=True),
            add_event=Mock(),
        )
        bot._captcha_tasks = {}
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot._send_user_dm = AsyncMock(return_value=True)
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        member.timeout.assert_awaited_once_with(None)
        bot.database.remove_captcha_challenge.assert_called_once_with(
            "server", "member"
        )
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "join_captcha_bypassed",
        )
        bot.send_command_response.assert_awaited_once()
        bot.send_log.assert_not_awaited()

    def test_case_lookup_is_scoped_to_current_server(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~case CASE-K7M2Q9XA",
            author_id="moderator",
            get_server=Mock(return_value=(server, "server")),
        )
        record = ModerationCaseRecord(
            id=42,
            reference_id="K7M2Q9XA",
            server_id="server",
            user_id="user",
            action="ban",
            moderator_id="moderator",
            reason="Repeated harassment",
            source_type="event",
            source_id=99,
            status="active",
            created_at="2026-08-09T12:00:00+00:00",
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_moderation_case=Mock(return_value=record)
        )
        bot._resolve_user_tag = AsyncMock(
            side_effect=["member#1234", "moderator#5678"]
        )
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.get_moderation_case.assert_called_once_with(
            "server", "K7M2Q9XA"
        )
        description = bot.send_command_response.await_args.args[2]
        self.assertIn("**Action:** Ban", description)
        self.assertIn("Repeated harassment", description)
        self.assertNotIn("Moderation event", description)
        self.assertNotIn("#99", description)

    def test_appeal_command_accepts_submitted_server_appeal(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~appeal CASE-K7M2Q9XA accept ok",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
        )
        appeal = {
            "id": 14,
            "server_id": "server",
            "user_id": "member",
            "case_kind": "moderation",
            "case_reference": "K7M2Q9XA",
            "status": "submitted",
        }
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_server_appeal_by_case=Mock(return_value=appeal),
            review_appeal=Mock(return_value={**appeal, "status": "approved"}),
            enqueue_dashboard_action=Mock(),
            add_event=Mock(),
        )
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.get_server_appeal_by_case.assert_called_once_with(
            "server", "K7M2Q9XA"
        )
        bot.database.review_appeal.assert_called_once_with(
            14, "moderator", "approved", "ok"
        )
        bot.database.enqueue_dashboard_action.assert_called_once_with(
            "server",
            "resolve_appeal",
            "moderator",
            {"appeal_id": 14, "decision": "approved"},
        )
        response = bot.send_command_response.await_args.args[2]
        self.assertIn("CASE-K7M2Q9XA", response)
        self.assertIn("approved", response)

    def test_appeal_command_resolves_numeric_case_variation(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~appeal case_[14] rejected Policy violation was confirmed",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
        )
        case = ModerationCaseRecord(
            id=14,
            reference_id="K7M2Q9XA",
            server_id="server",
            user_id="member",
            action="warning",
            moderator_id="moderator",
            reason="Scam activity",
            source_type="warning",
            source_id=7,
            status="active",
            created_at="2026-08-09T12:00:00+00:00",
        )
        appeal = {
            "id": 15,
            "server_id": "server",
            "user_id": "member",
            "case_kind": "moderation",
            "case_reference": "K7M2Q9XA",
            "status": "submitted",
        }
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_server_appeal_by_case=Mock(side_effect=[None, appeal]),
            get_moderation_case_by_id=Mock(return_value=case),
            review_appeal=Mock(return_value={**appeal, "status": "denied"}),
            enqueue_dashboard_action=Mock(),
            add_event=Mock(),
        )
        bot.send_command_response = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.get_moderation_case_by_id.assert_called_once_with(
            "server", 14
        )
        self.assertEqual(
            bot.database.get_server_appeal_by_case.call_args_list,
            [call("server", "14"), call("server", "K7M2Q9XA")],
        )
        bot.database.review_appeal.assert_called_once_with(
            15, "moderator", "denied", "Policy violation was confirmed"
        )

    def test_remove_uses_case_id_and_removes_warning_from_active_count(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(name="Test server")
        message = SimpleNamespace(
            content="~remove CASE-K7M2Q9XA",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=SimpleNamespace()),
        )
        case = ModerationCaseRecord(
            id=42,
            reference_id="K7M2Q9XA",
            server_id="server",
            user_id="user",
            action="warning",
            moderator_id="moderator",
            reason="Repeated spam",
            source_type="warning",
            source_id=7,
            status="active",
            created_at="2026-08-09T12:00:00+00:00",
        )
        warning = WarningRecord(
            id=7,
            server_id="server",
            user_id="user",
            moderator_id="moderator",
            source="manual",
            reason="Repeated spam",
            message_id=None,
            channel_id="channel",
            categories={},
            scores={},
            original_content=None,
            created_at="2026-08-09T12:00:00+00:00",
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            remove_moderation_case=Mock(return_value=(case, warning)),
            count_warnings=Mock(return_value=1),
            add_event=Mock(return_value=8),
            get_log_channel=Mock(return_value="channel"),
        )
        bot._resolve_user_tag = AsyncMock(
            side_effect=["member#1234", "moderator#5678"]
        )
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()
        bot._send_user_dm = AsyncMock(return_value=True)

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.remove_moderation_case.assert_called_once_with(
            "server", "K7M2Q9XA"
        )
        description = bot.send_command_response.await_args.args[2]
        self.assertIn("CASE-K7M2Q9XA", description)
        self.assertIn("**Remaining warnings:** 1", description)
        self.assertNotIn("Warning ID", description)
        bot._send_user_dm.assert_awaited_once()

    def test_categories_disable_command_persists_and_logs_change(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~categories disable illicit",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            disable_moderation_category=Mock(),
            is_moderation_category_disabled=Mock(return_value=True),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.disable_moderation_category.assert_called_once_with(
            "server", "illicit", "moderator"
        )
        bot.send_log.assert_awaited_once()

    def test_threshold_set_at_90_or_higher_persists_without_confirmation(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(threshold=0.7)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~threshold set 92.5%",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_moderation_threshold=Mock(return_value=0.7),
            set_moderation_threshold=Mock(),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.set_moderation_threshold.assert_called_once_with(
            "server", 0.925
        )
        event = bot.database.add_event.call_args.kwargs
        self.assertEqual(event["event_type"], "moderation_threshold_updated")
        self.assertEqual(event["details"]["new_threshold"], 0.925)
        description = bot.send_command_response.await_args.args[2]
        self.assertIn("92.5%", description)
        bot.send_log.assert_awaited_once()

    def test_threshold_below_90_is_saved_without_confirmation(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(threshold=0.9)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~threshold set 82.5%",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_moderation_threshold=Mock(return_value=0.9),
            set_moderation_threshold=Mock(),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        first_handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(first_handled)
        bot.database.set_moderation_threshold.assert_called_once_with("server", .825)
        first_response = bot.send_command_response.await_args.args[2]
        self.assertIn("82.5%", first_response)
        message.content = "~threshold confirm 82.5%"
        self.assertTrue(asyncio.run(bot.handle_command(message)))
        bot.database.set_moderation_threshold.assert_called_once_with("server", .825)
        bot.database.add_event.assert_called_once()

    def test_link_protection_disable_command_persists_and_logs_change(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~link-protection disable",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_link_protection=Mock(return_value=True),
            set_link_protection=Mock(),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.set_link_protection.assert_called_once_with("server", False)
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "link_protection_disabled",
        )
        bot.send_log.assert_awaited_once()

    def test_spam_detection_disable_command_persists_and_logs_change(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~spam-detection disable",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_spam_detection=Mock(return_value=True),
            set_spam_detection=Mock(),
            add_event=Mock(),
        )
        bot._spam_history = {("server", "user"): []}
        bot._spam_scores = {("server", "user"): (2.0, 1.0)}
        bot._spam_timeout_until = {("server", "user"): 20.0}
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.set_spam_detection.assert_called_once_with("server", False)
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "spam_detection_disabled",
        )
        self.assertFalse(bot._spam_history)
        self.assertFalse(bot._spam_scores)
        self.assertFalse(bot._spam_timeout_until)
        bot.send_log.assert_awaited_once()

    def test_image_scanning_can_be_disabled_for_one_channel(self) -> None:
        bot = object.__new__(ModerationBot)
        channel = object.__new__(stoat.TextChannel)
        server = SimpleNamespace(get_channel=Mock(return_value=channel))
        message = SimpleNamespace(
            content="~image-scanning disable <#channel-a>",
            author_id="moderator",
            channel_id="command-channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            set_channel_image_scanning=Mock(),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.set_channel_image_scanning.assert_called_once_with(
            "server", "channel-a", False, "moderator"
        )
        bot.send_log.assert_awaited_once()

    def test_moderator_exemption_disable_command_persists_and_logs(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~mod-exemption disable",
            author_id="moderator",
            channel_id="channel",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=None),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_moderator_exemption=Mock(return_value=True),
            set_moderator_exemption=Mock(),
            add_event=Mock(),
        )
        bot._resolve_user_tag = AsyncMock(return_value="moderator#1234")
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.set_moderator_exemption.assert_called_once_with(
            "server", False
        )
        self.assertEqual(
            bot.database.add_event.call_args.kwargs["event_type"],
            "moderator_exemption_disabled",
        )
        bot.send_log.assert_awaited_once()

    def test_disabled_channel_image_scanning_skips_image_only_message(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._message_author_is_moderator = AsyncMock(return_value=False)
        bot.moderation_settings = SimpleNamespace(max_image_bytes=10_000)
        bot.database = SimpleNamespace(
            get_image_scanning=Mock(return_value=False)
        )
        bot.moderator = SimpleNamespace(classify_url=AsyncMock())
        message = SimpleNamespace(
            content="",
            channel_id="channel-a",
            attachments=[
                SimpleNamespace(
                    id="image-a",
                    content_type="image/png",
                    size=100,
                    deleted=False,
                    url=Mock(return_value="https://example.invalid/image.png"),
                )
            ],
            embeds=[],
            get_server=Mock(return_value=(SimpleNamespace(), "server")),
        )

        asyncio.run(bot.scan_message(message))

        bot.database.get_image_scanning.assert_called_once_with(
            "server", "channel-a"
        )
        bot.moderator.classify_url.assert_not_awaited()

    def test_zero_tolerance_username_match_is_literal_and_narrow(self) -> None:
        self.assertEqual(len(ZERO_TOLERANCE_USERNAME_SLURS), 4)
        for term in ZERO_TOLERANCE_USERNAME_SLURS:
            with self.subTest(term=term):
                self.assertTrue(
                    ModerationBot._contains_zero_tolerance_slur(
                        f"prefix{term.upper()}suffix"
                    )
                )
        full_width = "".join(
            chr(ord(character) + 0xFEE0)
            for character in ZERO_TOLERANCE_USERNAME_SLURS[0]
        )
        self.assertTrue(ModerationBot._contains_zero_tolerance_slur(full_width))
        self.assertFalse(ModerationBot._contains_zero_tolerance_slur("bitch"))
        self.assertFalse(ModerationBot._contains_zero_tolerance_slur("fucker"))
        self.assertFalse(ModerationBot._contains_zero_tolerance_slur("f-a-g"))

    def test_zero_tolerance_username_match_creates_one_global_ban(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot._zero_tolerance_username_locks = {}
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=None),
            add_global_ban=Mock(),
        )
        bot._new_global_reference = Mock(return_value="ABC234")
        bot._send_user_dm = AsyncMock(return_value=True)
        bot._apply_global_ban_to_servers = AsyncMock()
        user = SimpleNamespace(bot=stoat.UNDEFINED)

        enforced = asyncio.run(
            bot._enforce_zero_tolerance_username_global_ban(
                "user",
                f"prefix{ZERO_TOLERANCE_USERNAME_SLURS[0]}suffix",
                user=user,
                source_server_id="server",
            )
        )

        self.assertTrue(enforced)
        bot.database.add_global_ban.assert_called_once_with(
            "ABC234",
            "user",
            ZERO_TOLERANCE_USERNAME_BAN_REASON,
            "bot",
        )
        self.assertIn(
            "admin@modstoat.site",
            bot._send_user_dm.await_args.args[2],
        )
        bot._apply_global_ban_to_servers.assert_awaited_once_with(
            "user",
            ZERO_TOLERANCE_USERNAME_BAN_REASON,
            reference_id="ABC234",
            actor_id="bot",
            source="automatic_account_username_slur",
        )

    def test_existing_global_ban_makes_username_rule_idempotent(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot._zero_tolerance_username_locks = {}
        bot.database = SimpleNamespace(
            get_global_ban=Mock(return_value=SimpleNamespace(reference_id="OLD234")),
            add_global_ban=Mock(),
        )
        bot._send_user_dm = AsyncMock()
        bot._apply_global_ban_to_servers = AsyncMock()

        enforced = asyncio.run(
            bot._enforce_zero_tolerance_username_global_ban(
                "user",
                ZERO_TOLERANCE_USERNAME_SLURS[0],
                user=SimpleNamespace(bot=None),
            )
        )

        self.assertTrue(enforced)
        bot.database.add_global_ban.assert_not_called()
        bot._send_user_dm.assert_not_awaited()
        bot._apply_global_ban_to_servers.assert_not_awaited()

    def test_existing_member_scan_applies_only_literal_username_rule(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._enforce_zero_tolerance_username_global_ban = AsyncMock(
            return_value=True
        )
        matching_user = SimpleNamespace(
            id="matching-user",
            name=f"prefix{ZERO_TOLERANCE_USERNAME_SLURS[0]}suffix",
            bot=None,
        )

        enforced = asyncio.run(
            bot._scan_zero_tolerance_usernames(
                [
                    SimpleNamespace(id="safe-user", name="ordinary-name", bot=None),
                    matching_user,
                    matching_user,
                ],
                source_server_id="server",
            )
        )

        self.assertEqual(enforced, 1)
        bot._enforce_zero_tolerance_username_global_ban.assert_awaited_once_with(
            "matching-user",
            matching_user.name,
            user=matching_user,
            source_server_id="server",
        )

    def test_zero_tolerance_username_update_skips_ai_and_server_warning(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        member = SimpleNamespace(id="user")
        server = SimpleNamespace(id="server", get_member=Mock(return_value=member))
        bot.database = SimpleNamespace(record_user_identity=Mock())
        bot._enforce_zero_tolerance_username_global_ban = AsyncMock(return_value=True)
        bot._classify_display_name = AsyncMock()
        bot._enforce_display_name_violation = AsyncMock()
        event = SimpleNamespace(
            user=SimpleNamespace(
                id="user",
                name=f"prefix{ZERO_TOLERANCE_USERNAME_SLURS[0]}suffix",
                discriminator="1234",
                display_name="Display",
                bot=None,
            ),
            before=SimpleNamespace(name="safe"),
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={"server": server},
        ):
            asyncio.run(bot.handle_username_update(event))

        bot._enforce_zero_tolerance_username_global_ban.assert_awaited_once_with(
            "user",
            event.user.name,
            user=event.user,
            source_server_id="server",
        )
        bot._classify_display_name.assert_not_awaited()
        bot._enforce_display_name_violation.assert_not_awaited()

    def test_zero_tolerance_nickname_is_only_warned_and_reset(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot._nickname_reset_suppressions = set()
        member = SimpleNamespace(id="user")
        server = SimpleNamespace(id="server")
        bot.get_server = Mock(return_value=server)
        bot.database = SimpleNamespace(get_nickname_protection=Mock(return_value=False))
        bot._moderator_is_exempt = Mock(return_value=True)
        bot._classify_display_name = AsyncMock()
        bot._enforce_display_name_violation = AsyncMock()
        bot._enforce_zero_tolerance_username_global_ban = AsyncMock()
        event = SimpleNamespace(
            member=SimpleNamespace(
                server_id="server",
                id="user",
                nick=f"prefix{ZERO_TOLERANCE_USERNAME_SLURS[0]}suffix",
            ),
            after=member,
            before=SimpleNamespace(nick="safe"),
        )

        asyncio.run(bot.handle_member_nickname_update(event))

        violation = bot._enforce_display_name_violation.await_args
        self.assertEqual(violation.kwargs["name_kind"], "nickname")
        self.assertEqual(violation.kwargs["restore_nick"], "safe")
        self.assertEqual(violation.kwargs["active_categories"], ["hate"])
        self.assertEqual(violation.kwargs["result"].scores, {"hate": 1.0})
        bot.database.get_nickname_protection.assert_not_called()
        bot._moderator_is_exempt.assert_not_called()
        bot._classify_display_name.assert_not_awaited()
        bot._enforce_zero_tolerance_username_global_ban.assert_not_awaited()

    def test_join_checks_existing_zero_tolerance_username_before_auto_roles(self) -> None:
        bot = object.__new__(ModerationBot)
        member = SimpleNamespace(
            id="user",
            server_id="server",
            get_user=Mock(
                return_value=SimpleNamespace(
                    name=f"prefix{ZERO_TOLERANCE_USERNAME_SLURS[0]}suffix",
                    bot=None,
                    created_at=datetime.now(timezone.utc) - timedelta(days=30),
                )
            ),
        )
        server = SimpleNamespace(id="server")
        bot.database = SimpleNamespace(
            record_daily_member_change=Mock(),
            get_global_ban=Mock(return_value=None),
            add_event=Mock(),
        )
        bot.get_server = Mock(return_value=server)
        bot._enforce_zero_tolerance_username_global_ban = AsyncMock(return_value=True)
        bot._assign_auto_roles_on_join = AsyncMock()

        asyncio.run(bot.handle_member_join(SimpleNamespace(member=member)))

        bot._enforce_zero_tolerance_username_global_ban.assert_awaited_once()
        bot._assign_auto_roles_on_join.assert_not_awaited()
        bot.database.add_event.assert_not_called()

    def test_unsafe_username_is_applied_as_previous_server_nickname(self) -> None:
        bot = object.__new__(ModerationBot)
        bot._state = SimpleNamespace(my_id="bot")
        bot.moderation_settings = SimpleNamespace(threshold=0.7)
        member = SimpleNamespace(id="user")
        server = SimpleNamespace(
            id="server",
            get_member=Mock(return_value=member),
            permissions_for=Mock(return_value=SimpleNamespace()),
        )
        bot.database = SimpleNamespace(
            get_nickname_protection=Mock(return_value=True),
            is_moderation_category_disabled=Mock(return_value=False),
        )
        result = ModerationResult(
            flagged=True,
            categories={"harassment": True},
            scores={"harassment": 0.95},
        )
        bot._classify_display_name = AsyncMock(return_value=result)
        bot._enforce_display_name_violation = AsyncMock()
        event = SimpleNamespace(
            user=SimpleNamespace(id="user", name="unsafe"),
            before=SimpleNamespace(name="safe"),
        )

        with patch.object(
            ModerationBot,
            "servers",
            new_callable=PropertyMock,
            return_value={"server": server},
        ):
            asyncio.run(bot.handle_username_update(event))

        call = bot._enforce_display_name_violation.await_args
        self.assertEqual(call.kwargs["restore_nick"], "safe")
        self.assertEqual(call.kwargs["new_value"], "unsafe")


    def test_disabled_category_is_filtered_but_self_harm_stays_protected(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.moderation_settings = SimpleNamespace(threshold=0.7)
        bot.database = SimpleNamespace(
            is_moderation_category_disabled=Mock(return_value=True)
        )
        result = ModerationResult(
            flagged=True,
            categories={"violence": True, "suicidal-thoughts": True},
            scores={"violence": 0.95, "suicidal-thoughts": 0.9},
        )

        enabled = [match["category"] for match in bot._moderation_policy_matches("server", result)]

        self.assertEqual(enabled, ["suicidal-thoughts"])

    def test_moderation_category_names_are_normalized(self) -> None:
        self.assertEqual(
            ModerationBot._normalize_moderation_category(
                " Self_Harm/Instructions "
            ),
            "self-harm/instructions",
        )

    def test_log_channel_command_aliases(self) -> None:
        channel_id = "01CHANNEL"
        self.assertEqual(
            ModerationBot._log_channel_from_parts(
                "~log", ["~log", channel_id]
            ),
            channel_id,
        )
        self.assertEqual(
            ModerationBot._log_channel_from_parts(
                "~log-channel", ["~log-channel", channel_id]
            ),
            channel_id,
        )
        self.assertEqual(
            ModerationBot._log_channel_from_parts(
                "~log", ["~log", "channel", channel_id]
            ),
            channel_id,
        )

    def test_embed_has_title_description_and_color(self) -> None:
        embed = ModerationBot._embed("Title", "Description", "#ED4245")
        self.assertEqual(embed.title, "✨ Title")
        self.assertEqual(embed.description, "Description")
        self.assertEqual(embed.color, "#ED4245")

    def test_help_and_information_embeds_have_contextual_emojis(self) -> None:
        help_embed = ModerationBot._embed(
            "Stoat Moderator — Help", "Commands", "#5865F2"
        )
        info_embed = ModerationBot._embed(
            "Server information", "Details", "#5865F2"
        )

        self.assertEqual(help_embed.title, "📚 Stoat Moderator — Help")
        self.assertEqual(info_embed.title, "💡 Server information")

    def test_help_command_fits_in_one_embed_page(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(content="~help")

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.send_command_response.assert_awaited_once()
        description = bot.send_command_response.await_args.args[2]
        pages = ModerationBot._split_embed_description(description)
        self.assertEqual(len(pages), 1)
        self.assertLessEqual(len(description.encode("utf-8")), 1800)
        self.assertNotIn("\ufe0f", description)

    def test_misspelled_command_sends_correct_usage_embed(self) -> None:
        bot = object.__new__(ModerationBot)
        channel = SimpleNamespace(send=AsyncMock())
        message = SimpleNamespace(
            content="~polciy set 3 5 7",
            author_id="moderator",
            channel_id="channel",
            channel=channel,
        )

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        channel.send.assert_awaited_once()
        embed = channel.send.await_args.kwargs["embeds"][0]
        self.assertEqual(embed.title, "❌ Invalid command")
        self.assertEqual(embed.color, "#F59E0B")
        self.assertIn("~polciy", embed.description)
        self.assertIn(
            "~policy [show|set TIMEOUT_COUNT KICK_COUNT BAN_COUNT|reset]",
            embed.description,
        )
        self.assertIn("~help", embed.description)

    def test_server_only_command_in_dm_shows_correct_usage(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(
            content="~warn member",
            author_id="moderator",
            get_server=Mock(return_value=(None, None)),
        )

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.send_command_response.assert_awaited_once()
        self.assertEqual(
            bot.send_command_response.await_args.args[1], "Server-only command"
        )
        self.assertIn(
            "~warn USER_ID REASON",
            bot.send_command_response.await_args.args[2],
        )

    def test_missing_command_argument_shows_command_specific_usage(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~warn",
            author_id="moderator",
            get_server=Mock(return_value=(server, "server")),
        )
        bot._is_moderator = Mock(return_value=True)

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.send_command_response.assert_awaited_once()
        self.assertIn(
            "~warn USER_ID",
            bot.send_command_response.await_args.args[2],
        )

    def test_auto_role_remove_without_role_shows_usage_without_clearing(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        bot.database = SimpleNamespace(clear_auto_roles=Mock())
        server = SimpleNamespace()
        message = SimpleNamespace(
            content="~auto-role remove",
            author_id="moderator",
            get_server=Mock(return_value=(server, "server")),
        )
        bot._is_moderator = Mock(return_value=True)

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.clear_auto_roles.assert_not_called()
        bot.send_command_response.assert_awaited_once()
        description = bot.send_command_response.await_args.args[2]
        self.assertIn("~auto-role remove ROLE_ID", description)

    def test_language_command_changes_server_locale(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            get_server_locale=Mock(return_value="en"),
            set_server_locale=Mock(),
            add_event=Mock(),
        )
        server = SimpleNamespace(id="server")
        message = SimpleNamespace(
            content="~language français",
            author_id="moderator",
            get_server=Mock(return_value=(server, "server")),
        )

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.set_server_locale.assert_called_once_with("server", "fr")
        title, description = bot.send_command_response.await_args.args[1:3]
        self.assertEqual(title, "Langue du serveur")
        self.assertIn("Français", description)

    def test_language_status_does_not_require_moderator_permissions(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        bot._is_moderator = Mock()
        bot.database = SimpleNamespace(get_server_locale=Mock(return_value="es"))
        server = SimpleNamespace(id="server")
        message = SimpleNamespace(
            content="~language",
            get_server=Mock(return_value=(server, "server")),
        )

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot._is_moderator.assert_not_called()
        self.assertIn(
            "El idioma del servidor",
            bot.send_command_response.await_args.args[2],
        )

    def test_support_command_returns_official_contact_options(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.send_command_response = AsyncMock()
        message = SimpleNamespace(content="~support")

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        description = bot.send_command_response.await_args.args[2]
        self.assertIn("https://stt.gg/PCaYw69F", description)
        self.assertIn("admin@modstoat.site", description)

    def test_bump_command_promotes_approved_discovery_server(self) -> None:
        bot = object.__new__(ModerationBot)
        server = SimpleNamespace(id="server")
        message = SimpleNamespace(
            content="~bump",
            author_id="moderator",
            get_server=Mock(return_value=(server, "server")),
            get_author_as_user=Mock(return_value=SimpleNamespace()),
        )
        bot._is_moderator = Mock(return_value=True)
        bot.database = SimpleNamespace(
            bump_discovery_server=Mock(return_value={
                "bumped": True,
                "last_bumped_at": "2026-08-18T12:00:00+00:00",
                "next_bump_at": "2026-08-18T14:00:00+00:00",
            }),
            add_event=Mock(),
        )
        bot.send_command_response = AsyncMock()
        bot.send_log = AsyncMock()
        bot._resolve_user_tag = AsyncMock(return_value="moderator#0001")

        handled = asyncio.run(bot.handle_command(message))

        self.assertTrue(handled)
        bot.database.bump_discovery_server.assert_called_once_with(
            "server", "moderator"
        )
        self.assertIn(
            "top of StoatMod Discovery",
            bot.send_command_response.await_args.args[2],
        )
        bot.send_log.assert_awaited_once()

    def test_existing_embed_emoji_is_not_duplicated(self) -> None:
        embed = ModerationBot._embed(
            "✅ Already complete", "Done", "#3BA55D"
        )

        self.assertEqual(embed.title, "✅ Already complete")

    def test_command_response_embed_supports_warning_details(self) -> None:
        scores = ModerationBot._format_scores({"violence": 0.8765})
        embed = ModerationBot._embed(
            "Warning #1",
            f"**Reason:** unsafe content\n**Category scores:**\n{scores}",
            "#ED4245",
        )

        self.assertIn("**Reason:** unsafe content", embed.description or "")
        self.assertIn("**87.65%**", embed.description or "")

    def test_long_embed_description_is_split_without_losing_content(self) -> None:
        content = "start-" + ("x" * 3900) + "-finish"
        description = (
            f"**Original message:**\n{ModerationBot._original_message_text(content)}"
        )

        pages = ModerationBot._split_embed_description(description)

        self.assertGreater(len(pages), 1)
        self.assertTrue(all(len(page.encode("utf-8")) <= 1800 for page in pages))
        self.assertEqual("".join(pages), description)

    def test_embed_description_splits_multibyte_text_by_utf8_size(self) -> None:
        description = "• moderation — enabled\n" * 100

        pages = ModerationBot._split_embed_description(description)

        self.assertGreater(len(pages), 1)
        self.assertTrue(all(len(page.encode("utf-8")) <= 1800 for page in pages))
        self.assertEqual("".join(pages), description)

    def test_long_log_sends_numbered_single_embed_pages(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            get_log_channel=Mock(return_value="log-channel")
        )
        channel = SimpleNamespace(send=AsyncMock())
        bot.get_channel = Mock(return_value=channel)
        description = "Before\n" + ("x" * 2300) + "\nAfter"

        asyncio.run(bot.send_log("server", "Message edited", description))

        self.assertEqual(channel.send.await_count, 2)
        embeds = [call.kwargs["embeds"][0] for call in channel.send.await_args_list]
        self.assertEqual("".join(embed.description or "" for embed in embeds), description)
        self.assertEqual(embeds[0].title, "📝 Message edited (1/2)")
        self.assertEqual(embeds[1].title, "📝 Message edited (2/2)")

    def test_moderation_log_uses_selected_server_language(self) -> None:
        bot = object.__new__(ModerationBot)
        bot.database = SimpleNamespace(
            get_log_channel=Mock(return_value="log-channel"),
            get_server_locale=Mock(return_value="fr"),
        )
        channel = SimpleNamespace(send=AsyncMock())
        bot.get_channel = Mock(return_value=channel)

        asyncio.run(
            bot.send_log(
                "server",
                "Member banned",
                "**User:** `member`\n**Reason:** raison personnalisée",
            )
        )

        embed = channel.send.await_args.kwargs["embeds"][0]
        self.assertIn("Membre banni", embed.title or "")
        self.assertEqual(
            embed.description,
            "**Utilisateur :** `member`\n**Raison :** raison personnalisée",
        )


    def test_non_content_message_updates_are_ignored(self) -> None:
        bot = object.__new__(ModerationBot)
        event = SimpleNamespace(
            message=SimpleNamespace(content=stoat.UNDEFINED)
        )

        asyncio.run(bot.handle_message_update(event))

    def test_edited_message_is_dispatched_for_moderation(self) -> None:
        bot = object.__new__(ModerationBot)
        message = SimpleNamespace(
            id="message",
            author_id="user",
            channel_id="channel",
            content="new unsafe content",
            get_server=Mock(return_value=(SimpleNamespace(), "server")),
            get_author_as_user=Mock(return_value=None),
        )
        event = SimpleNamespace(
            message=SimpleNamespace(
                id="message",
                channel_id="channel",
                content="new unsafe content",
            ),
            before=SimpleNamespace(content="safe content"),
            after=message,
        )
        bot.get_channel = Mock(return_value=SimpleNamespace(server_id="server"))
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.database = SimpleNamespace(
            add_event=Mock(), get_link_protection=Mock(return_value=True)
        )
        bot.send_log = AsyncMock()
        bot.message_is_in_scope = Mock(return_value=True)
        bot._message_author_is_moderator = AsyncMock(return_value=False)
        bot._mass_mention_reason = Mock(return_value=None)
        bot.dispatch_scan = Mock()

        asyncio.run(bot.handle_message_update(event))

        bot.dispatch_scan.assert_called_once_with(message)

    def test_mass_mentions_added_by_edit_use_spam_enforcement(self) -> None:
        bot = object.__new__(ModerationBot)
        message = SimpleNamespace(
            id="message",
            author_id="user",
            channel_id="channel",
            content="edited mass mention",
            get_server=Mock(return_value=(SimpleNamespace(), "server")),
            get_author_as_user=Mock(return_value=None),
        )
        event = SimpleNamespace(
            message=SimpleNamespace(
                id="message",
                channel_id="channel",
                content="edited mass mention",
            ),
            before=SimpleNamespace(content="safe content"),
            after=message,
        )
        bot.get_channel = Mock(return_value=SimpleNamespace(server_id="server"))
        bot._resolve_user_tag = AsyncMock(return_value="member#1234")
        bot.database = SimpleNamespace(
            add_event=Mock(), get_link_protection=Mock(return_value=True)
        )
        bot.send_log = AsyncMock()
        bot.message_is_in_scope = Mock(return_value=True)
        bot._message_author_is_moderator = AsyncMock(return_value=False)
        bot._mass_mention_reason = Mock(return_value="mass mention")
        bot.handle_spam = AsyncMock(return_value=True)
        bot.dispatch_scan = Mock()

        asyncio.run(bot.handle_message_update(event))

        bot.handle_spam.assert_awaited_once_with(message)
        bot.dispatch_scan.assert_not_called()

    def test_warning_history_uses_one_description_with_only_requested_fields(self) -> None:
        records = [
            WarningRecord(
                id=1,
                server_id="server",
                user_id="user",
                moderator_id="moderator",
                source="automatic",
                reason="Automatic content moderation: sexual",
                message_id="message",
                channel_id="channel",
                categories={"sexual": True, "violence": False},
                scores={"sexual": 0.9876, "violence": 0.9999},
                original_content="the complete original message",
                created_at="2026-08-05T12:34:56+00:00",
            )
        ]

        description = ModerationBot._warning_history(
            records, {1: "K7M2Q9XA"}
        )
        embed = ModerationBot._embed("Warnings", description, "#F59E0B")

        self.assertIn("**Reason:** sexual — 98.76%", embed.description or "")
        self.assertIn("**Case ID:** `CASE-K7M2Q9XA`", embed.description or "")
        self.assertNotIn("Warning ID", embed.description or "")
        self.assertIn("the complete original message", embed.description or "")
        self.assertIn("**Date & time:** 2026-08-05T12:34:56+00:00", embed.description or "")
        self.assertNotIn("Moderator", embed.description or "")
        self.assertNotIn("Category scores", embed.description or "")

    def test_scores_are_bulleted_percentages_in_descending_order(self) -> None:
        formatted = ModerationBot._format_scores(
            {"violence": 0.125, "sexual": 0.999675}
        )

        self.assertEqual(
            formatted,
            "• `sexual` — **99.97%**\n• `violence` — **12.50%**",
        )

    def test_aggregate_results_uses_highest_score_and_any_category_flag(self) -> None:
        categories, scores = ModerationBot._aggregate_results(
            [
                (
                    "text",
                    ModerationResult(
                        flagged=True,
                        categories={"violence": True, "sexual": False},
                        scores={"violence": 0.8, "sexual": 0.1},
                    ),
                ),
                (
                    "image",
                    ModerationResult(
                        flagged=True,
                        categories={"violence": False, "sexual": True},
                        scores={"violence": 0.2, "sexual": 0.9},
                    ),
                ),
            ]
        )

        self.assertEqual(categories, {"violence": True, "sexual": True})
        self.assertEqual(scores, {"violence": 0.8, "sexual": 0.9})

    def test_triggered_category_names_lists_only_categories_at_the_action_minimum(self) -> None:
        names = ModerationBot._triggered_category_names(
            [
                {"category": "illicit", "score": 1.0},
                {"category": "hate", "score": 0.93},
                {"category": "scams", "score": 0.5},
                {"category": "suicidal-thoughts", "score": 0.99},
            ]
        )

        self.assertEqual(names, ["hate", "illicit"])

    def test_triggered_category_names_never_lists_every_category(self) -> None:
        names = ModerationBot._triggered_category_names([{"category": "sexual", "score": 0.97}])

        self.assertEqual(names, ["sexual"])

    def test_triggered_category_names_falls_back_to_matched_names_without_scores(self) -> None:
        names = ModerationBot._triggered_category_names([{"category": "hate"}, {"category": "illicit"}])

        self.assertEqual(names, ["hate", "illicit"])


if __name__ == "__main__":
    unittest.main()
