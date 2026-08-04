import unittest
from unittest.mock import Mock, patch

from sbjat import main


class MainTests(unittest.TestCase):
    @patch.object(main.getsbrs, "ticketdata")
    @patch.object(main.postjira, "assign")
    def test_run_uses_issue_keys_and_reuses_client(self, assign, ticketdata):
        jira = Mock()
        jira.search_issues.return_value = [Mock(key="COG-12345"), Mock(key="COG-12346")]

        self.assertEqual(main.run(jira=jira, max_results=10), 2)
        assign.assert_any_call("COG-12345", jira=jira)
        ticketdata.assert_any_call("COG-12346", jira=jira)

    @patch.object(main.getsbrs, "ticketdata")
    @patch.object(main.postjira, "assign")
    def test_run_continues_queue_then_reports_failure(self, assign, ticketdata):
        jira = Mock()
        jira.search_issues.return_value = [Mock(key="COG-1"), Mock(key="COG-2")]
        ticketdata.side_effect = [RuntimeError("bad ticket"), None]

        with self.assertRaisesRegex(RuntimeError, "COG-1"):
            main.run(jira=jira, max_results=10)
        assign.assert_any_call("COG-2", jira=jira)


if __name__ == "__main__":
    unittest.main()
