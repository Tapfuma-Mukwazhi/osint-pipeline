"""Tests for the SANS ISC RSS collector, using a static fixture feed --
no live network in CI. See tests/fixtures/sample_isc_feed.xml.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import feedparser
import pytest

from src.collectors import rss_feeds

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "sample_isc_feed.xml"


@pytest.fixture
def patch_feed(monkeypatch):
    fixture_bytes = FIXTURE_PATH.read_bytes()
    real_parse = feedparser.parse
    monkeypatch.setattr(feedparser, "parse", lambda url: real_parse(fixture_bytes))


def test_collect_returns_expected_number_of_records(patch_feed):
    records = rss_feeds.collect()
    assert len(records) == 2


def test_collect_tags_security_relevant_entry(patch_feed):
    records = rss_feeds.collect()
    ransomware_story = next(r for r in records if "Ransomware" in r.title)
    assert "phishing" in ransomware_story.tags
    assert "ransomware" in ransomware_story.tags


def test_collect_leaves_irrelevant_entry_untagged(patch_feed):
    records = rss_feeds.collect()
    routine_story = next(r for r in records if "Routine" in r.title)
    assert routine_story.tags == []


def test_collect_raises_on_fetch_failure(monkeypatch):
    class BrokenFeed(dict):
        entries = []

    monkeypatch.setattr(
        feedparser, "parse",
        lambda url: BrokenFeed(bozo=True, bozo_exception=ConnectionError("boom")),
    )
    with pytest.raises(RuntimeError):
        rss_feeds.collect()
