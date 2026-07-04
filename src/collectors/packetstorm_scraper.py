"""Scraper collector: PacketStorm Security file listing.

Unlike the RSS/API collectors, this pulls from a page with no feed or API --
real HTML scraping with BeautifulSoup against the site's actual markup.
robots.txt for this domain allows crawling (checked before writing this).

Honesty note: scraper selectors are inherently more brittle than API/RSS
parsing, because they depend on one site's current HTML structure instead
of a stable published contract. If this collector returns zero records,
the site's markup has likely changed since this was written -- inspect the
live page and adjust _ENTRY_LINK_PATTERN / _parse_listing() below. That's
normal scraper maintenance, not a sign the pipeline itself is broken --
it's exactly the failure mode run_collector() in pipeline.py is built to
isolate rather than let take down the whole run.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from src.collectors.base import Record

NAME = "packetstorm"
SOURCE_TYPE = "scrape"
SOURCE_URL = "https://packetstormsecurity.com/files/"

HEADERS = {"User-Agent": "osint-pipeline/0.1 (portfolio project)"}

# PacketStorm file entries have long used a stable /files/<id>/... URL scheme.
# Matching on that instead of a CSS class keeps this a little more resilient
# to styling/markup churn than a class-name selector would be.
_ENTRY_LINK_PATTERN = re.compile(r"^/files/\d+/")


def _parse_listing(html: str, base_url: str = SOURCE_URL) -> list[dict]:
    """Pure parsing function, kept separate from the network call so it can
    be unit tested against a static fixture instead of live HTML."""
    soup = BeautifulSoup(html, "html.parser")
    entries = []
    seen_urls = set()

    for link in soup.find_all("a", href=_ENTRY_LINK_PATTERN):
        href = link["href"]
        url = urljoin(base_url, href)
        if url in seen_urls:
            continue

        title = link.get_text(strip=True)
        if not title:
            continue
        seen_urls.add(url)

        summary = ""
        parent = link.find_parent(["li", "div", "p"])
        if parent:
            parent_text = parent.get_text(" ", strip=True)
            summary = parent_text.replace(title, "", 1).strip(" -—")
        else:
            # <dt>/<dd> list pattern: the link lives in <dt>, the description
            # is the following sibling <dd>, not an ancestor of the link.
            dt = link.find_parent("dt")
            if dt:
                dd = dt.find_next_sibling("dd")
                if dd:
                    summary = dd.get_text(" ", strip=True)

        entries.append({"title": title, "url": url, "summary": summary})

    return entries


def collect(limit: int = 20) -> list[Record]:
    resp = requests.get(SOURCE_URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()

    entries = _parse_listing(resp.text)
    if not entries:
        raise RuntimeError(
            f"scraped 0 entries from {SOURCE_URL} -- site markup likely changed; "
            "check _ENTRY_LINK_PATTERN / _parse_listing() in packetstorm_scraper.py"
        )

    records = []
    for entry in entries[:limit]:
        records.append(
            Record(
                source_name=NAME,
                title=entry["title"],
                url=entry["url"],
                summary=entry["summary"],
                external_id=entry["url"],
                tags=[],
            )
        )
    return records
