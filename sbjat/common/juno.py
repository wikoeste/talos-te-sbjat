from functools import lru_cache

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sbjat.common import logdata, settings

requests.packages.urllib3.disable_warnings()

HTTP_TIMEOUT = (5, 30)
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


@lru_cache(maxsize=1024)
def getipv6(address):
    """Fetch and cache IPv6 SBRS data for the current automation process."""
    query = {
        "_source": [
            "_id",
            "@timestamp",
            "sbrs.ingest.score",
            "sbrs.ingest.rules",
            "ipas.original.result.ipv6",
            "ipas.original.result.sbrs",
            "ipas.ingest.verdict",
            "ipas.original.result.ipas_score",
        ],
        "query": {"term": {"sender_ip": {"value": address}}},
    }
    scores = []
    rules = []
    try:
        response = HTTP.get(
            settings.juno + "juno_past_6_months/_search",
            json=query,
            auth=(settings.uname, settings.junoKey),
            verify=False,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        result = response.json()
        hits = result.get("hits", {}).get("hits", [])
        for hit in hits:
            source = hit.get("_source", {})
            score = source.get("sbrs.ingest.score")
            if score is not None:
                scores.append(score)
            rules.extend(source.get("sbrs.ingest.rules") or [])
    except requests.RequestException as exc:
        logdata.logger.exception("Unable to reach Juno API for %s", address)
        raise RuntimeError(f"Unable to reach Juno API for {address}") from exc
    except (ValueError, TypeError) as exc:
        logdata.logger.exception("Invalid Juno API response for %s", address)
        raise RuntimeError(f"Juno returned invalid data for {address}") from exc

    if not scores and not rules:
        return (
            f"\n===SBRS IPv6 Threat Intel===\nIP: {address}\nResults: No data found for IP",
            rules,
            scores,
        )
    return (
        f"\n====SBRS IPv6 Threat Intel====\nIP: {address}"
        f"\nScore: {scores}\nRules: {rules}",
        rules,
        scores,
    )
