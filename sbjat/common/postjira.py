from functools import lru_cache

from jira import JIRA

from sbjat.common import logdata, settings

JIRA_SERVER = "https://jira.talos.cisco.com"
PRIVATE = {"type": "role", "value": "Project Developer"}


@lru_cache(maxsize=1)
def get_jira():
    """Create one Jira client per process instead of reconnecting per action."""
    if not settings.jiraKey:
        raise RuntimeError("Jira API key is missing (set JRW or SBJAT_JRW)")
    return JIRA(
        basic_auth=(settings.uname, settings.jiraKey),
        options={"server": JIRA_SERVER},
    )


def _score_value(score):
    if score is None:
        return 0.0
    if isinstance(score, list):
        values = [float(item) for item in score if item is not None]
        return sum(values) / len(values) if values else 0.0
    try:
        return float(score)
    except (TypeError, ValueError):
        logdata.logger.warning("Unrecognized SBRS score %r; treating as neutral", score)
        return 0.0


def _has_any(rules, *codes):
    return any(code in str(rules) for code in codes)


def assign(ticket, jira=None):
    jira = jira or get_jira()
    jira.assign_issue(ticket, settings.uname)


def comment(ticket, data, rules, scr, ip, jira=None):
    """Post analysis and return the workflow flag for this result."""
    jira = jira or get_jira()
    score = _score_value(scr)
    rules_text = str(rules)

    jira.add_comment(ticket, str(data), visibility=PRIVATE)
    issue = jira.issue(ticket)
    issue.update(fields={"customfield_20380": rules_text})

    if score == 0.0:
        jira.add_comment(ticket, f"{ip}: {settings.boilerplates['none']}")
        return 1
    if _has_any(rules_text, "RsH", "RhM"):
        if score <= -2.0:
            jira.add_comment(ticket, f"{ip}: {settings.boilerplates['iadh']}")
        return 1
    if "Gry" in rules_text and score <= -7.0:
        jira.add_comment(ticket, f"{ip}: {settings.boilerplates['grey']}")
        return 2
    if _has_any(rules_text, "Cbl", "Pbl", "Sbl", "Css"):
        jira.add_comment(ticket, f"{ip}: {settings.boilerplates['spamhaus']}")
        return 1
    if _has_any(rules_text, "psb", "PSB") and score <= -2.0:
        jira.add_comment(ticket, f"{ip}: IP listed in http://psbl.org", visibility=PRIVATE)
        return 2
    if _has_any(rules_text, "Cp1", "Cp2", "Vp1", "Vp2") and score <= -2.0:
        jira.add_comment(ticket, f"{ip}: {settings.boilerplates['cp1']}")
        return 1
    if _has_any(rules_text, "Ivn", "Ivm") and score <= -2.0:
        jira.add_comment(
            ticket,
            f"{ip}: listed on Invaluement: https://www.invaluement.com/",
            visibility=PRIVATE,
        )
        return 2
    if _has_any(rules_text, "Vu", "Cu") and score <= -2.0:
        jira.add_comment(
            ticket,
            f"{ip}: a domain associated with this IP is listed in the URIDB feed.",
            visibility=PRIVATE,
        )
        return 2
    if "Rtm" in rules_text and score <= -2.0:
        jira.add_comment(ticket, f"{ip}: is blocked by a Reptool entry", visibility=PRIVATE)
        logdata.logger.info("%s: %s - blocked by a Reptool entry", ticket, ip)
        return 2
    if score <= -2.0:
        jira.add_comment(
            ticket,
            f"Your IP, {ip} has a malicious score {scr} due to the following known rules: {rules_text}",
            visibility=PRIVATE,
        )
        return 2
    if score > -1.9:
        logdata.logger.info("%s: %s: %s", ticket, ip, settings.boilerplates["recovered"])
        jira.add_comment(ticket, f"{ip}: {settings.boilerplates['recovered']}")
        return 1

    jira.add_comment(ticket, f"{scr},{rules_text}", visibility=PRIVATE)
    return 2


def resolveclose(ticket, flag, jira=None):
    jira = jira or get_jira()
    issue = jira.issue(ticket)
    status = str(issue.fields.status)

    labels = list(issue.fields.labels or [])
    labels.extend(label for label in ("te-sbjat", "te-automation") if label not in labels)
    issue.update(fields={"labels": labels})
    logdata.logger.info("%s labels: %s", ticket, labels)

    if flag == 3:
        jira.add_comment(ticket, "Investigating the reported Geolocation issue. Update to follow")
        logdata.logger.info("%s - %s: investigating geolocation", ticket, settings.uname)
    elif flag == 1:
        transition = "741" if "Investigating" in status else "5"
        jira.transition_issue(issue, transition, resolution={"id": "1"})
        logdata.logger.info("%s - %s: resolved fixed", ticket, settings.uname)
    else:
        jira.add_comment(ticket, "Investigating the issue. Update to follow")
        logdata.logger.info("%s - %s: investigating", ticket, settings.uname)
