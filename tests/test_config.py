import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config import Settings, load_env_file

VERSION = "stoatguard-test-version"


class LoadEnvFileTests(unittest.TestCase):
    def test_loads_values_and_preserves_existing_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, ".env")
            path.write_text(
                "# comment\nNEW_VALUE=from-file\nQUOTED='quoted value'\nEXISTING=file\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"EXISTING": "shell"}, clear=True):
                load_env_file(path)
                self.assertEqual(os.environ["NEW_VALUE"], "from-file")
                self.assertEqual(os.environ["QUOTED"], "quoted value")
                self.assertEqual(os.environ["EXISTING"], "shell")

    def test_settings_use_the_pinned_model_version(self) -> None:
        with patch.dict(
            os.environ,
            {"STOAT_BOT_TOKEN": "stoat-token", "LOCAL_AI_EXPECTED_VERSION": VERSION},
            clear=True,
        ):
            settings = Settings.from_env()

        self.assertEqual(settings.local_ai_base_url, "http://127.0.0.1:18006")
        self.assertEqual(settings.local_ai_expected_version, VERSION)
        self.assertEqual(settings.local_ai_api_key, "")
        self.assertEqual(settings.global_ban_sync_seconds, 300)

    def test_model_version_is_required(self) -> None:
        with patch.dict(os.environ, {"STOAT_BOT_TOKEN": "stoat-token"}, clear=True):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_email_relay_does_not_need_a_webhook(self) -> None:
        mailbox = {
            "STOAT_BOT_TOKEN": "token",
            "LOCAL_AI_EXPECTED_VERSION": VERSION,
            "EMAIL_RELAY_ENABLED": "true",
            "PROTON_BRIDGE_IMAP_USERNAME": "user",
            "PROTON_BRIDGE_IMAP_PASSWORD": "password",
            "PROTON_BRIDGE_CA_FILE": "/etc/bridge.pem",
        }
        with patch.dict(os.environ, mailbox, clear=True):
            settings = Settings.from_env()
        self.assertTrue(settings.email_relay_enabled)
        self.assertEqual(settings.email_relay_webhook_url, "")
        for name in ("PROTON_BRIDGE_IMAP_USERNAME", "PROTON_BRIDGE_CA_FILE"):
            with patch.dict(os.environ, {k: v for k, v in mailbox.items() if k != name}, clear=True):
                with self.assertRaises(ValueError):
                    Settings.from_env()  # the mailbox settings are still required

    def test_rejects_out_of_range_or_nonfinite_action_threshold(self):
        for value in ['-0.01', '1.01', 'nan', 'inf']:
            with patch.dict(os.environ, {'STOAT_BOT_TOKEN': 'token', 'LOCAL_AI_EXPECTED_VERSION': VERSION, 'MODERATION_THRESHOLD': value}, clear=True):
                with self.assertRaises(ValueError): Settings.from_env()


if __name__ == "__main__":
    unittest.main()
