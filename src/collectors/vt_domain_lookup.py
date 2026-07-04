"""API collector: VirusTotal domain reputation (gated/authenticated source).

The other three collectors (SANS ISC, NVD, PacketStorm) are all fully open,
no-auth sources. This one requires a real API key obtained by registering
a free VirusTotal account -- it exists specifically to demonstrate handling
an authenticated/rate-limited source, which the JD calls out separately
from open-source collection ("open and closed sources").

Setup: sign up free at https://www.virustotal.com/gui/join-us, grab your
API key from https://www.virustotal.com/gui/my-apikey, then set it as an
environment variable before running the pipeline:

    Windows (PowerShell):  $env:VT_API_KEY = "your-key-here"
    Windows (cmd):         set VT_API_KEY=your-key-here
    macOS/Linux:           export VT_API_KEY=your-key-here

If the key isn't set, this collector raises a clear error that
pipeline.py's per-source error isolation catches -- the run continues
with the other collectors instead of crashing, which is the correct
behavior for an optional/gated source.

The free tier is rate-limited (4 requests/minute, 500/day), so this reads
a small watchlist file (watchlist.txt) rather than an open-ended query,
and caps how many domains it checks per run.
"""

from __future__ import annotations

import os
from pathlib import Path

import requests

from src.collectors.base import Record

NAME = "virustotal"
SOURCE_TYPE = "api"
SOURCE_URL = "https://www.virustotal.com/api/v3/domains/"

WATCHLIST_PATH = Path(__file__).resolve().parents[2] / "watchlist.txt"

# Free-tier VT API allows 4 req/min. Keep well under that per run, since
# this pipeline may run on a schedule alongside other collectors.
MAX_LOOKUPS_PER_RUN = 4


def _load_watchlist() -> list[str]:
    if not WATCHLIST_PATH.exists():
        return []
    domains = []
    for line in WATCHLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            domains.append(line)
    return domains


def _verdict_tags(stats: dict) -> list[str]:
    if stats.get("malicious", 0) > 0:
        return ["malicious"]
    if stats.get("suspicious", 0) > 0:
        return ["suspicious"]
    return ["harmless"]


def collect(limit: int = MAX_LOOKUPS_PER_RUN) -> list[Record]:
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        raise RuntimeError(
            "VT_API_KEY environment variable not set -- sign up free at "
            "https://www.virustotal.com/gui/join-us and set the key before "
            "running this collector. See the module docstring for exact commands."
        )

    domains = _load_watchlist()[: min(limit, MAX_LOOKUPS_PER_RUN)]
    if not domains:
        return []

    headers = {"x-apikey": api_key}
    records = []

    for domain in domains:
        resp = requests.get(SOURCE_URL + domain, headers=headers, timeout=30)
        if resp.status_code == 404:
            continue  # domain not in VT's dataset yet -- not an error
        resp.raise_for_status()

        attributes = resp.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)
        categories = list(attributes.get("categories", {}).values())

        summary = (
            f"VT reputation score: {reputation}. "
            f"Detections -- malicious: {stats.get('malicious', 0)}, "
            f"suspicious: {stats.get('suspicious', 0)}, "
            f"harmless: {stats.get('harmless', 0)}."
        )
        if categories:
            summary += f" Categories: {', '.join(categories)}."

        records.append(
            Record(
                source_name=NAME,
                title=f"VirusTotal domain reputation: {domain}",
                url=f"https://www.virustotal.com/gui/domain/{domain}",
                summary=summary,
                external_id=domain,
                tags=_verdict_tags(stats),
            )
        )

    return records
