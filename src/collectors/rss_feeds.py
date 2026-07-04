"""RSS collector: SANS Internet Storm Center diary feed.

SANS ISC is a long-running, widely-cited CTI source (daily handler diaries
covering active malware, phishing campaigns, scanning activity, etc.).
Public RSS, no auth, no rate-limit games -- a reliable first source to get
the pipeline running end to end.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import feedparser

from src.collectors.base import Record

NAME = "sans_isc"
SOURCE_TYPE = "rss"
SOURCE_URL = "https://isc.sans.edu/rssfeed.xml"

# Cheap keyword tagging so records aren't dumped in untagged. A real
# implementation would use NLP/NER; this is intentionally simple and
# easy to extend with more terms.
KEYWORDS = [
    "phishing", "ransomware", "malware", "botnet", "exploit", "cve",
    "apt", "credential", "scan", "vulnerability", "backdoor", "c2",
    "ddos", "supply chain", "zero-day", "0day",
]


def _struct_time_to_iso(struct_time):
    if not struct_time:
        return None
    return datetime.fromtimestamp(time.mktime(struct_time), tz=timezone.utc).isoformat()


def _extract_tags(text):
    text_lower = text.lower()
    return [kw for kw in KEYWORDS if kw in text_lower]


def collect(limit: int = 20):
    feed = feedparser.parse(SOURCE_URL)

    # feedparser doesn't raise on network/parse failure -- it sets `bozo`
    # and returns zero entries instead. Without this check a failed fetch
    # silently looks identical to "the feed had nothing new," which is
    # exactly the kind of silent failure a collection pipeline shouldn't have.
    if feed.get("bozo") and not feed.entries:
        raise RuntimeError("failed to fetch/parse " + SOURCE_URL + ": " + str(feed.get("bozo_exception")))

    records = []

    for entry in feed.entries[:limit]:
        title = entry.get("title", "").strip()
        summary = entry.get("description", "") or entry.get("summary", "")
        combined_text = title + " " + summary

        record = Record(
            source_name=NAME,
            title=title,
            url=entry.get("link"),
            summary=summary,
            published_at=_struct_time_to_iso(entry.get("published_parsed")),
            external_id=entry.get("guid") or entry.get("link"),
            raw_json=json.dumps(dict(entry), default=str),
            tags=_extract_tags(combined_text),
        )
        records.append(record)

    return records
