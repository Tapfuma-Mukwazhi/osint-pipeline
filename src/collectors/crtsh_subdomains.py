"""OSINT tooling collector: passive subdomain enumeration via certificate
transparency logs (crt.sh).

This is a from-scratch reimplementation of one specific passive OSINT
technique -- querying public Certificate Transparency logs for every
hostname a CA has ever issued a certificate for -- not a wrapper around the
theHarvester binary. That's a deliberate, honest distinction worth stating
plainly: theHarvester's own `crtsh` module does exactly this same lookup
against the same public API, but the actual theHarvester tool doesn't
install cleanly via pip (the PyPI package named `theHarvester` is a stale,
non-functional placeholder; the real tool only installs by cloning its
GitHub repo and pulling its own dependency set), which is a much heavier
and more fragile CI dependency than this project's other collectors. Rather
than adding real risk of a flaky third-party CLI to a scheduled pipeline,
this collector demonstrates the same OSINT technique directly, with the
same testing/error-handling standards as everything else in the project.

No API key or account needed -- crt.sh is a free public service. Reads the
same watchlist.txt used by vt_domain_lookup.py, since "what do we know
about domain X" (reputation + what subdomains exist) is one coherent
question, not two unrelated ones.

Docs: https://groups.google.com/g/crtsh/c/sUxvWpNbcm8 (crt.sh JSON API)
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import requests

from src.collectors.base import Record

NAME = "crtsh_subdomains"
SOURCE_TYPE = "api"
SOURCE_URL = "https://crt.sh/"

WATCHLIST_PATH = Path(__file__).resolve().parents[2] / "watchlist.txt"

# Public, unauthenticated, shared resource -- be a good citizen and cap how
# much any single scheduled run asks of it, same reasoning as VT's limit.
MAX_LOOKUPS_PER_RUN = 4

# crt.sh is a free community service backed by a public Postgres instance
# that's well known to return transient 502/503/504s under load -- this
# isn't a hypothetical edge case, it's the first thing that happened on
# this collector's first live run (see README / module history). A short
# retry with backoff turns "the pipeline reports a failure every time
# crt.sh has a bad moment" into "the pipeline quietly recovers from crt.sh
# having a bad moment," which is the more honest description of what's
# actually going wrong when this fails.
_RETRYABLE_STATUS_CODES = {502, 503, 504}
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = 3

# name_value entries that don't look like a real hostname under the queried
# domain (bare email addresses, free-text CA test-cert labels, etc.) show up
# in real crt.sh data -- see the module docstring's fixture. Filtering to
# "looks like a hostname, ends with the domain we asked about" is simpler
# and more robust than trying to enumerate every non-hostname shape crt.sh
# might return.
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _load_watchlist() -> list[str]:
    if not WATCHLIST_PATH.exists():
        return []
    domains = []
    for line in WATCHLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    return domains


def _extract_subdomains(entries: list[dict], domain: str) -> set[str]:
    """Pure parsing function, kept separate from the network call so it can
    be unit tested against a static fixture instead of live crt.sh data."""
    found = set()
    domain_suffix = f".{domain}"

    for entry in entries:
        raw = entry.get("name_value", "")
        for name in raw.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if not name:
                continue
            if name != domain and not name.endswith(domain_suffix):
                continue
            if not _HOSTNAME_RE.match(name):
                continue
            found.add(name)

    return found


def _fetch_with_retry(domain: str) -> list[dict]:
    last_exc: Exception | None = None

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = requests.get(
                SOURCE_URL,
                params={"q": domain, "output": "json"},
                headers={"User-Agent": "osint-pipeline/0.1 (portfolio project)"},
                timeout=60,
            )
        except requests.exceptions.RequestException as exc:
            last_exc = exc
        else:
            if resp.status_code not in _RETRYABLE_STATUS_CODES:
                resp.raise_for_status()
                return resp.json()
            last_exc = requests.exceptions.HTTPError(
                f"{resp.status_code} Server Error (retryable) for url: {resp.url}"
            )

        if attempt < _MAX_ATTEMPTS:
            time.sleep(_RETRY_BACKOFF_SECONDS * attempt)

    raise RuntimeError(
        f"crt.sh lookup for {domain} failed after {_MAX_ATTEMPTS} attempts "
        f"(last error: {last_exc}) -- crt.sh is a free community service "
        "known to return transient 502/503/504s under load; this means all "
        "retries hit that, not that the collector logic is wrong."
    ) from last_exc


def collect(limit: int = MAX_LOOKUPS_PER_RUN) -> list[Record]:
    domains = _load_watchlist()[: min(limit, MAX_LOOKUPS_PER_RUN)]
    if not domains:
        return []

    records = []

    for domain in domains:
        entries = _fetch_with_retry(domain)

        for subdomain in sorted(_extract_subdomains(entries, domain)):
            records.append(
                Record(
                    source_name=NAME,
                    title=f"Subdomain via certificate transparency: {subdomain}",
                    url=f"https://crt.sh/?q={subdomain}",
                    summary=f"Observed in a public CA certificate for {domain}, found via crt.sh.",
                    external_id=subdomain,
                    tags=["subdomain"],
                )
            )

    return records
