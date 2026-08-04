# Senderbase Jira Automation Tool
# Tool to read, analyze, respond, and resolve jira sbrs case types
import os
import re

from sbjat.common import getsbrs, logdata, postjira, settings

JIRA_SERVER = "https://jira.talos.cisco.com"
DEFAULT_QUERY = (
    "project = COG AND issuetype = SBRS AND created >= -1d "
    "AND assignee in (EMPTY) ORDER BY key ASC"
)


def run(jira=None, max_results=None):
    """Process the current SBRS queue and return the number of tickets found."""
    max_results = max_results or int(os.getenv("SBJAT_MAX_RESULTS", "100"))
    jira = jira or postjira.get_jira()
    query = os.getenv("SBJAT_JQL", DEFAULT_QUERY)
    issues = jira.search_issues(query, maxResults=max_results)
    tickets = []
    for issue in issues:
        ticket = getattr(issue, "key", None)
        if not ticket:
            match = re.search(r"\bCOG-\d+\b", str(issue))
            ticket = match.group(0) if match else None
        if ticket and ticket not in tickets:
            tickets.append(ticket)

    # Keep the existing console output useful for cron logs and manual runs.
    print(issues)
    print(f"Total sbrs cases in last day (24 hours) is {len(tickets)}")
    print(tickets)
    logdata.logger.info("Tickets found: %s", tickets)

    if not tickets:
        print("No valid SBRS Tickets")
        logdata.logger.info("No valid Tickets")
        return 0

    failures = []
    for ticket in tickets:
        try:
            postjira.assign(ticket, jira=jira)
            getsbrs.ticketdata(ticket, jira=jira)
        except Exception as exc:
            # One malformed or transiently failing ticket must not stop the queue.
            logdata.logger.exception("Failed to process %s", ticket)
            failures.append((ticket, exc))
    if failures:
        failed_tickets = ", ".join(ticket for ticket, _ in failures)
        raise RuntimeError(f"Failed to process {len(failures)} ticket(s): {failed_tickets}")
    return len(tickets)

def main():
    logdata.logger.info("Tool run by %s", settings.uname)
    print(f"\n===Senderbase Jira Automation Tool (sbjat)==={settings.version}")
    try:
        run()
        return 0
    except Exception as exc:
        print(f"Jira automation failed for {settings.uname}: {exc}")
        logdata.logger.exception("Jira automation failed")
        return 1

########################
if __name__ == '__main__':
    raise SystemExit(main())
