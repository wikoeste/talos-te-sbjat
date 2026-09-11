import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbjat.common import settings


class SettingsTests(unittest.TestCase):
    def test_environment_alias_precedes_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / ".profile"
            profile.write_text("export JRW_KEY='profile-key'\n", encoding="utf-8")
            with patch.object(settings, "PROFILE_FILE", profile), patch.dict(
                os.environ, {"JIRA_API_KEY": "environment-key"}, clear=False
            ):
                self.assertEqual(
                    settings.get_secret("JIRA_API_KEY", "JRW_KEY"),
                    "environment-key",
                )

    def test_legacy_jrw_key_is_read_from_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / ".profile"
            profile.write_text(
                "# ignored\nexport JRW_KEY='profile-key' # ignored comment\n",
                encoding="utf-8",
            )
            with patch.object(settings, "PROFILE_FILE", profile), patch.dict(
                os.environ, {"JIRA_API_KEY": "", "JRW_KEY": ""}, clear=False
            ):
                self.assertEqual(
                    settings.get_secret("JIRA_API_KEY", "JRW_KEY"),
                    "profile-key",
                )

    def test_sbjat_prefixed_environment_alias_is_supported(self):
        with patch.dict(
            os.environ,
            {"JIRA_API_KEY": "", "JRW_KEY": "", "SBJAT_JRW_KEY": "prefixed-key"},
            clear=False,
        ):
            self.assertEqual(
                settings.get_secret("JIRA_API_KEY", "JRW_KEY"),
                "prefixed-key",
            )

    def test_similar_profile_variable_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / ".profile"
            profile.write_text("NOT_JRW_KEY=wrong\n", encoding="utf-8")
            with patch.object(settings, "PROFILE_FILE", profile), patch.dict(
                os.environ, {"JIRA_API_KEY": "", "JRW_KEY": ""}, clear=False
            ):
                self.assertEqual(settings.get_secret("JIRA_API_KEY", "JRW_KEY"), "")


if __name__ == "__main__":
    unittest.main()
