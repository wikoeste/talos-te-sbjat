import unittest
from unittest.mock import Mock

from sbjat.common import postjira


class PostJiraTests(unittest.TestCase):
    def setUp(self):
        self.issue = Mock()
        self.jira = Mock()
        self.jira.issue.return_value = self.issue

    def comment(self, rules, score):
        return postjira.comment(
            "COG-1", "analysis", rules, score, "192.0.2.1", jira=self.jira
        )

    def test_checks_every_rule_alias(self):
        self.assertEqual(self.comment("RhM", -3), 1)

    def test_private_uridb_comment_includes_ticket_argument(self):
        self.assertEqual(self.comment("Cu", -3), 2)
        self.assertEqual(self.jira.add_comment.call_args_list[-1].args[0], "COG-1")

    def test_unknown_score_is_handled_as_neutral(self):
        self.assertEqual(self.comment("--", "Unknown"), 1)

    def test_labels_are_idempotent(self):
        self.issue.fields.labels = ["te-sbjat"]
        self.issue.fields.status = "Open"

        postjira.resolveclose("COG-1", 1, jira=self.jira)

        labels = self.issue.update.call_args.kwargs["fields"]["labels"]
        self.assertEqual(labels, ["te-sbjat", "te-automation"])


if __name__ == "__main__":
    unittest.main()
