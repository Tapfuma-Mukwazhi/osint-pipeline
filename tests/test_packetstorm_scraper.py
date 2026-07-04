"""Tests for the PacketStorm scraper's parsing logic, against a static
HTML fixture -- no live network in CI. See tests/fixtures/sample_packetstorm.html.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.collectors import packetstorm_scraper

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "sample_packetstorm.html"


@pytest.fixture
def sample_html():
    return FIXTURE_PATH.read_text(encoding="utf-8")


def test_parse_listing_finds_all_entries(sample_html):
    entries = packetstorm_scraper._parse_listing(sample_html)
    assert len(entries) == 3


def test_parse_listing_extracts_title_and_url(sample_html):
    entries = packetstorm_scraper._parse_listing(sample_html)
    first = entries[0]
    assert first["title"] == "Example Vendor Security Advisory 2026-001"
    assert first["url"] == "https://packetstormsecurity.com/files/183201/example-vendor-advisory.html"


def test_parse_listing_extracts_summary(sample_html):
    entries = packetstorm_scraper._parse_listing(sample_html)
    sqli_entry = next(e for e in entries if "SQL Injection" in e["title"])
    assert "SQL injection" in sqli_entry["summary"]


def test_parse_listing_ignores_non_entry_links(sample_html):
    entries = packetstorm_scraper._parse_listing(sample_html)
    urls = [e["url"] for e in entries]
    assert not any("/about" in u or "/tos/" in u for u in urls)


def test_parse_listing_dedupes_repeated_links():
    html = """
    <dl>
      <dt><a href="/files/1/a.html">Same Entry</a></dt><dd>desc</dd>
      <dt><a href="/files/1/a.html">Same Entry</a></dt><dd>desc</dd>
    </dl>
    """
    entries = packetstorm_scraper._parse_listing(html)
    assert len(entries) == 1


def test_collect_raises_on_zero_entries(monkeypatch):
    class FakeResponse:
        text = "<html><body>no matching links here</body></html>"

        def raise_for_status(self):
            pass

    monkeypatch.setattr(
        packetstorm_scraper.requests, "get", lambda *a, **kw: FakeResponse()
    )
    with pytest.raises(RuntimeError):
        packetstorm_scraper.collect()
