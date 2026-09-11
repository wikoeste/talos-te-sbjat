import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from ipaddress import ip_address, ip_network

import requests
from netaddr import IPNetwork
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sbjat.common import juno, logdata, postjira, settings

requests.packages.urllib3.disable_warnings()

HTTP_TIMEOUT = (5, 30)
DNS_TIMEOUT = 10
JIRA_FIELDS = (
    "description,summary,labels,customfield_20042,customfield_20043,"
    "customfield_20380,status"
)
IPV4_PATTERN = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
IPV6_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:.])"
)
NETWORK_PATTERN = re.compile(r"(?<![0-9A-Fa-f:.])([0-9A-Fa-f:.]+/\d{1,3})")

HTTP = requests.Session()
HTTP.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=2,
            backoff_factor=0.25,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
        )
    ),
)


def _listed_on(revip, blacklist):
    try:
        result = subprocess.run(
            ["dig", "+short", f"{revip}.{blacklist}"],
            capture_output=True,
            text=True,
            timeout=DNS_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        logdata.logger.exception("DNS blacklist lookup failed for %s", blacklist)
        return None
    if result.returncode != 0:
        logdata.logger.warning("DNS blacklist lookup returned %d for %s", result.returncode, blacklist)
        return None
    return blacklist if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", result.stdout.strip()) else None


def pbl(revip):
    """Check independent public block lists concurrently."""
    blacklists = (
        "bl.spamcop.net",
        "cbl.abuseat.org",
        "pbl.spamhaus.org",
        "sbl.spamhaus.org",
        "xbl.spamhaus.org",
        "dnsbl.invaluement.com",
    )
    with ThreadPoolExecutor(max_workers=len(blacklists)) as executor:
        return [
            result
            for result in executor.map(lambda blacklist: _listed_on(revip, blacklist), blacklists)
            if result
        ]


@lru_cache(maxsize=1024)
def getgeoip(ip):
    """Return GeoIP text, caching duplicate IP lookups for the current process."""
    endpoint = "https://api-private.thetap.cisco.com/geoip/v1/ip/"
    try:
        response = HTTP.get(endpoint + str(ip), verify=False, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        result = response.json()
        location = result["location"]
        confidence = result["confidence"]
        additional = result["additional"]
        metadata = [
            f"ASN: {additional.get('asn_name', 'Unknown')}",
            f"ISP: {additional.get('isp', 'Unknown')}",
            f"Type: {additional.get('user_type', 'Unknown')}",
        ]
        return (
            "==GEOIP Results=="
            f"\nContinent: {location['continent']['name']}"
            f"\nCountry: {location['country']['name']}"
            f"\nLocale: {location['subdivision']['name']}"
            f"\nTime zone: {location.get('time_zone', 'Unknown')}"
            f"\nMisc: {metadata}"
            "\nConfidence: "
            f"{{'continent': {confidence['continent']}, "
            f"'country': {confidence['country']}, "
            f"'locale': {confidence['subdivision']}}}"
        )
    except requests.RequestException as exc:
        logdata.logger.warning("GeoIP request failed for %s: %s", ip, exc)
        return "==GeoDB API unavailable=="
    except (ValueError, KeyError, TypeError) as exc:
        logdata.logger.warning("Invalid GeoIP response for %s: %s", ip, exc)
        return "==GeoDB API returned invalid data=="


def _as_text(value):
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_as_text(item) for item in value)
    return str(value)


def extract_networks(*values):
    """Extract valid IPv4 and IPv6 networks in deterministic order."""
    networks = []
    seen = set()
    for value in values:
        for candidate in NETWORK_PATTERN.findall(_as_text(value)):
            try:
                network = ip_network(candidate, strict=False)
            except ValueError:
                continue
            normalized = str(network)
            if normalized not in seen:
                seen.add(normalized)
                networks.append(normalized)
    return networks


def extract_ips(*values):
    """Extract and validate standalone IPv4/IPv6 addresses without regex fragments."""
    addresses = []
    seen = set()
    for value in values:
        text = _as_text(value)
        matches = sorted(
            (*IPV4_PATTERN.finditer(text), *IPV6_PATTERN.finditer(text)),
            key=lambda match: match.start(),
        )
        for match in matches:
            if match.end() < len(text) and text[match.end()] == "/":
                continue
            try:
                normalized = str(ip_address(match.group(0)))
            except ValueError:
                continue
            if normalized not in seen:
                seen.add(normalized)
                addresses.append(normalized)
    return addresses


def cidrscore(network_value, ticket, jira=None, issue=None):
    """Analyze a bounded CIDR and return its highest workflow flag."""
    network = IPNetwork(network_value)
    max_addresses = int(os.getenv("SBJAT_MAX_CIDR_ADDRESSES", "256"))
    if max_addresses < 1:
        raise ValueError("SBJAT_MAX_CIDR_ADDRESSES must be a positive integer")
    if network.size > max_addresses:
        raise ValueError(
            f"CIDR {network_value} contains {network.size} addresses; limit is {max_addresses}"
        )

    flags = []
    for address in network:
        score_value, rules, block_lists, analyzed_ip, date = score(address)
        if float(score_value) <= -2.0:
            analysis = (
                "\n===RealTimeThreat Analysis==="
                f"\nDate: {date}"
                f"\nTicket: {ticket}"
                f"\nIP: {analyzed_ip}"
                f"\nScore: {score_value}"
                f"\nRule Hits: {rules}"
                f"\nPublic Block List: {block_lists}"
                f"\n{getgeoip(str(address))}"
            )
            flags.append(
                postjira.comment(
                    ticket,
                    analysis,
                    rules,
                    score_value,
                    str(address),
                    jira=jira,
                    issue=issue,
                )
            )
            logdata.logger.info("%s CIDR analysis completed for %s", ticket, address)
    return max(flags, default=0)


def score(ip):
    """Return cached SBRS DNS data for an IPv4 address."""
    return _score(str(ip))


@lru_cache(maxsize=2048)
def _score(ip):
    date = time.strftime("%Y-%m-%d %H:%M")
    rules, block_lists = "--", []
    try:
        reverse_ip = ip_address(ip).reverse_pointer.removesuffix(".in-addr.arpa")
        query = reverse_ip + ".v1x2s.rf-adfe2ko9.senderbase.org"
        process = subprocess.run(
            ["dig", "+noall", "+answer", "TXT", query],
            capture_output=True,
            text=True,
            timeout=DNS_TIMEOUT,
            check=False,
        )
    except (ValueError, OSError, subprocess.TimeoutExpired):
        logdata.logger.exception("SBRS DNS lookup failed for %s", ip)
        raise RuntimeError(f"SBRS DNS lookup failed for {ip}")

    if process.returncode != 0:
        logdata.logger.warning("SBRS DNS lookup returned %d for %s", process.returncode, ip)
        raise RuntimeError(f"SBRS DNS lookup returned {process.returncode} for {ip}")

    quoted = re.search(r'"([^"]+)"', process.stdout)
    if not quoted:
        return 0.0, rules, block_lists, ip, date
    values = [part.split("=", 1)[-1].strip() for part in quoted.group(1).split("|")]
    if len(values) < 6:
        logdata.logger.warning("Malformed SBRS DNS response for %s", ip)
        return 0.0, rules, block_lists, ip, date

    try:
        score_value = float(values[1])
    except ValueError:
        logdata.logger.warning("Invalid SBRS score %r for %s", values[1], ip)
        score_value = 0.0
    raw_rules = values[5]
    rules = " ".join(raw_rules[index:index + 3] for index in range(0, len(raw_rules), 3))
    block_lists = pbl(reverse_ip)
    return score_value, rules, block_lists, ip, date


def ticketdata(ticket, jira=None):
    """Analyze one Jira ticket and perform exactly one final workflow transition."""
    jira = jira or postjira.get_jira()
    try:
        issue = jira.issue(ticket, fields=JIRA_FIELDS)
    except Exception as exc:
        logdata.logger.exception("Unable to retrieve Jira issue %s", ticket)
        raise RuntimeError(f"Unable to retrieve Jira issue {ticket}") from exc

    fields = issue.fields
    description = _as_text(getattr(fields, "description", ""))
    summary = _as_text(getattr(fields, "summary", ""))
    custom_ip_1 = _as_text(getattr(fields, "customfield_20042", ""))
    custom_ip_2 = _as_text(getattr(fields, "customfield_20043", ""))
    source_values = (custom_ip_1, custom_ip_2, description, summary)
    networks = extract_networks(*source_values)
    addresses = extract_ips(*source_values)
    logdata.logger.info(
        "%s extracted %d address(es) and %d network(s)",
        ticket,
        len(addresses),
        len(networks),
    )

    flags = []
    for network in networks:
        try:
            flags.append(cidrscore(network, ticket, jira=jira, issue=issue))
        except (ValueError, TypeError) as exc:
            logdata.logger.warning("Ignoring CIDR %s in %s: %s", network, ticket, exc)

    for address in addresses:
        parsed = ip_address(address)
        if parsed.version == 6:
            analysis, rules, score_value = juno.getipv6(address)
            analysis += getgeoip(address)
        else:
            score_value, rules, block_lists, _, date = score(address)
            analysis = (
                "\n==SBRS Threat Intel=="
                "\n===RealTime Threat Analysis==="
                f"\nIP Analyzed: {address}"
                f"\nDate: {date}"
                f"\nScore: {score_value}"
                f"\nRule Hits: {rules}"
                f"\nPublic Block List: {block_lists}"
                f"\n{getgeoip(address)}"
            )
        flag = postjira.comment(
            ticket,
            analysis,
            str(rules),
            score_value,
            address,
            jira=jira,
            issue=issue,
        )
        flags.append(flag)
        settings.results.append(
            {
                "ticket": ticket,
                "ip": address,
                "score": score_value,
                "rules": list(rules) if isinstance(rules, list) else str(rules),
            }
        )
        logdata.logger.info("%s analysis completed for %s (flag=%d)", ticket, address, flag)

    if not addresses and not networks:
        logdata.logger.warning("%s contains no valid IPv4, IPv6, or CIDR values", ticket)
        return 0

    searchable_text = f"{summary}\n{description}".casefold()
    is_geolocation = any(
        marker.casefold() in searchable_text for marker in settings.geolocation
    )
    final_flag = 3 if is_geolocation else max(flags, default=0)
    postjira.resolveclose(ticket, final_flag, jira=jira, issue=issue)
    logdata.logger.info("%s final workflow flag: %d", ticket, final_flag)
    return final_flag
