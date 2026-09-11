import unittest
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sbjat.common import getsbrs


class ExtractionTests(unittest.TestCase):
    def test_extracts_valid_unique_addresses_without_cidr_base(self):
        values = "192.0.2.1, invalid 999.1.1.1, 2001:db8::1 and 198.51.100.0/24"

        self.assertEqual(getsbrs.extract_ips(values), ["192.0.2.1", "2001:db8::1"])
        self.assertEqual(getsbrs.extract_networks(values), ["198.51.100.0/24"])


class TicketDataTests(unittest.TestCase):
    def issue(self, *, summary="SBRS review", description="192.0.2.1"):
        return SimpleNamespace(
            fields=SimpleNamespace(
                description=description,
                summary=summary,
                labels=[],
                customfield_20042=None,
                customfield_20043=None,
                customfield_20380=None,
                status="Open",
            )
        )

    @patch.object(getsbrs.postjira, "resolveclose")
    @patch.object(getsbrs.postjira, "comment", return_value=1)
    @patch.object(getsbrs, "getgeoip", return_value="geo")
    @patch.object(getsbrs, "score", return_value=(-1.0, "--", [], "192.0.2.1", "now"))
    def test_geolocation_ticket_is_never_auto_resolved(
        self, score, getgeoip, comment, resolveclose
    ):
        jira = Mock()
        issue = self.issue(summary="GeoIP country correction")
        jira.issue.return_value = issue

        self.assertEqual(getsbrs.ticketdata("COG-1", jira=jira), 3)

        jira.issue.assert_called_once_with("COG-1", fields=getsbrs.JIRA_FIELDS)
        resolveclose.assert_called_once_with("COG-1", 3, jira=jira, issue=issue)

    @patch.object(getsbrs.postjira, "resolveclose")
    @patch.object(getsbrs, "cidrscore", return_value=1)
    def test_cidr_ticket_has_one_final_transition(self, cidrscore, resolveclose):
        jira = Mock()
        issue = self.issue(description="Analyze 198.51.100.0/24")
        jira.issue.return_value = issue

        self.assertEqual(getsbrs.ticketdata("COG-2", jira=jira), 1)

        cidrscore.assert_called_once_with(
            "198.51.100.0/24", "COG-2", jira=jira, issue=issue
        )
        resolveclose.assert_called_once_with("COG-2", 1, jira=jira, issue=issue)

    def test_jira_read_failure_is_reported(self):
        jira = Mock()
        jira.issue.side_effect = RuntimeError("unavailable")

        with self.assertRaisesRegex(RuntimeError, "Unable to retrieve Jira issue COG-3"):
            getsbrs.ticketdata("COG-3", jira=jira)


class LookupFailureTests(unittest.TestCase):
    @patch.object(getsbrs.subprocess, "run", side_effect=subprocess.TimeoutExpired("dig", 10))
    def test_sbrs_timeout_is_not_treated_as_neutral(self, run):
        getsbrs._score.cache_clear()
        with self.assertRaisesRegex(RuntimeError, "SBRS DNS lookup failed"):
            getsbrs.score("192.0.2.55")


if __name__ == "__main__":
    unittest.main()
