"""Scraper collector: PacketStorm Security file listing.

STATUS: DISABLED as of the first live run (see collect() below). This is
NOT the "selector needs updating" case the original docstring warned
about -- PacketStorm now serves a mandatory clickwrap Terms of Service
interstitial in front of all content (dated September 2025), and their
Terms explicitly gate API access behind an individually-issued license
key ("You may not resell or distribute API access to any third party
without our express written permission"). A plain requests.get() call
can't satisfy a consent flow, and writing code to silently bypass a
clickwrap gate would violate both PacketStorm's terms and this project's
own stated scope/ethics policy (README: "only collects where doing so
doesn't violate the source's terms of service"). Confirmed by navigating
to the live URL and observing the ToS interstitial directly, not by
inference.

_parse_listing() below is left intact and still passes its unit tests --
the HTML-parsing logic itself was never the problem, and it's a
reasonable starting point if this source is ever swapped for a
scrapeable one with similar markup (dt/dd or li-based listing).

Next step: replace SOURCE_URL (and likely _parse_listing) with a
different scraping target that doesn't require a consent flow, rather
than patching around this one. See osint-pipeline-project-log.docx for
the fuller writeup of this decision.
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
    # Disabled deliberately -- see module docstring. Raising here (rather
    # than silently returning []) keeps this visible in pipeline logs
    # instead of quietly looking like "the site just had nothing new."
    raise RuntimeError(
        "packetstorm collector disabled: the source now requires clickwrap "
        "ToS agreement for all traffic, which this project won't script "
        "around. Needs a replacement scraping target -- see module docstring."
    )

    resp = requests.get(SOURCE_URL, headers=HEADERS, timeout=30)  # unreachable, kept for when this is re-enabled against a new target
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
