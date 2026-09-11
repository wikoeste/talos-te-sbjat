# Senderbase Jira Automation Tool
# Tool to read, analyze, respond, and resolve jira sbrs case types
import os
import re
import time

from sbjat.common import getsbrs, logdata, postjira, settings

JIRA_SERVER = "https://jira.talos.cisco.com"
DEFAULT_QUERY = (
    "project = COG AND issuetype = SBRS AND created >= -1d "
    "AND assignee in (EMPTY) ORDER BY key ASC"
)


def run(jira=None, max_results=None):
    """Process the current SBRS queue and return the number of tickets found."""
    if max_results is None:
        raw_max_results = os.getenv("SBJAT_MAX_RESULTS", "100")
        try:
            max_results = int(raw_max_results)
        except ValueError as exc:
            raise ValueError("SBJAT_MAX_RESULTS must be a positive integer") from exc
    if max_results < 1:
        raise ValueError("max_results must be a positive integer")

    started = time.monotonic()
    settings.results.clear()
    jira = jira or postjira.get_jira()
    query = os.getenv("SBJAT_JQL", DEFAULT_QUERY)
    logdata.logger.info("Searching Jira SBRS queue (max_results=%d)", max_results)
    issues = jira.search_issues(query, maxResults=max_results)
    tickets = []
    seen = set()
    for issue in issues:
        ticket = getattr(issue, "key", None)
        if not ticket:
            match = re.search(r"\bCOG-\d+\b", str(issue))
            ticket = match.group(0) if match else None
        if ticket and ticket not in seen:
            seen.add(ticket)
            tickets.append(ticket)

    print(f"Total sbrs cases in last day (24 hours) is {len(tickets)}")
    logdata.logger.info("Tickets found (%d): %s", len(tickets), tickets)

    if not tickets:
        print("No valid SBRS Tickets")
        logdata.logger.info("No valid Tickets")
        return 0

    failures = []
    for ticket in tickets:
        ticket_started = time.monotonic()
        try:
            postjira.assign(ticket, jira=jira)
            getsbrs.ticketdata(ticket, jira=jira)
        except Exception as exc:
            # One malformed or transiently failing ticket must not stop the queue.
            logdata.logger.exception("Failed to process %s", ticket)
            failures.append((ticket, exc))
        else:
            logdata.logger.info(
                "Processed %s in %.2fs", ticket, time.monotonic() - ticket_started
            )
    if failures:
        failed_tickets = ", ".join(ticket for ticket, _ in failures)
        raise RuntimeError(f"Failed to process {len(failures)} ticket(s): {failed_tickets}")
    logdata.logger.info(
        "Completed %d ticket(s) in %.2fs", len(tickets), time.monotonic() - started
    )
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
