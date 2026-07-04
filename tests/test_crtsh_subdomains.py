"""Tests for the crt.sh certificate-transparency subdomain collector, using
static fixture data modeled on real crt.sh responses -- no live network in CI.

The fixture entries below are deliberately messy in the same ways real
crt.sh data is messy (this was checked against a live query before writing
these tests, not guessed): wildcard entries prefixed with "*.", a bare email
address showing up in name_value, and a free-text CA test-certificate label
that isn't a hostname at all. The parser has to handle all three without
polluting the result set.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.collectors import crtsh_subdomains

# Modeled on a real crt.sh JSON response for "example.com" -- trimmed to the
# handful of entries that exercise each edge case the parser has to handle.
SAMPLE_ENTRIES = [
    {
        "name_value": "*.example.com\nexample.com",
        "id": 26787376238,
    },
    {
        "name_value": "example.com\nwww.example.com",
        "id": 22853418213,
    },
    {
        # Duplicate hostname across a different cert -- must be deduped.
        "name_value": "example.com\nwww.example.com",
        "id": 22853391369,
    },
    {
        # Real crt.sh data includes non-hostname junk like this -- an email
        # address embedded in a cert's name_value field.
        "name_value": "subjectname@example.com",
        "id": 34083306,
    },
    {
        # And free-text CA test-certificate labels that aren't hostnames.
        "name_value": "AS207960 Test Intermediate - example.com",
        "id": 10570508844,
    },
    {
        # A subdomain of a *different* domain shouldn't be pulled in just
        # because it happens to contain "example.com" as a substring.
        "name_value": "example.com.evil-lookalike.test",
        "id": 99999999999,
    },
]


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


@pytest.fixture
def sample_watchlist(tmp_path, monkeypatch):
    watchlist = tmp_path / "watchlist.txt"
    watchlist.write_text("# comment line\nexample.com\nwikipedia.org\n")
    monkeypatch.setattr(crtsh_subdomains, "WATCHLIST_PATH", watchlist)


def test_extract_subdomains_finds_real_hostnames():
    found = crtsh_subdomains._extract_subdomains(SAMPLE_ENTRIES, "example.com")
    assert "example.com" in found
    assert "www.example.com" in found


def test_extract_subdomains_ignores_non_hostname_values():
    found = crtsh_subdomains._extract_subdomains(SAMPLE_ENTRIES, "example.com")
    assert not any("@" in name for name in found)
    assert not any(" " in name for name in found)


def test_extract_subdomains_ignores_lookalike_domains():
    found = crtsh_subdomains._extract_subdomains(SAMPLE_ENTRIES, "example.com")
    assert "example.com.evil-lookalike.test" not in found


def test_extract_subdomains_dedupes_across_multiple_certs():
    found = crtsh_subdomains._extract_subdomains(SAMPLE_ENTRIES, "example.com")
    # www.example.com appears in two separate cert entries above -- a set,
    # not a count, is the right structure, and this pins that down.
    assert isinstance(found, set)
    assert len(found) == 2  # example.com, www.example.com


def test_collect_returns_records_for_watchlist_domains(sample_watchlist, monkeypatch):
    monkeypatch.setattr(
        crtsh_subdomains.requests, "get",
        lambda url, params=None, headers=None, timeout=None: FakeResponse(SAMPLE_ENTRIES),
    )

    records = crtsh_subdomains.collect()
    subdomains = {r.external_id for r in records}
    assert "www.example.com" in subdomains
    assert all(r.source_name == "crtsh_subdomains" for r in records)
    assert all(r.tags == ["subdomain"] for r in records)


def test_collect_returns_empty_for_empty_watchlist(tmp_path, monkeypatch):
    empty_watchlist = tmp_path / "empty.txt"
    empty_watchlist.write_text("# nothing here\n")
    monkeypatch.setattr(crtsh_subdomains, "WATCHLIST_PATH", empty_watchlist)

    records = crtsh_subdomains.collect()
    assert records == []


def test_collect_respects_max_lookups_per_run(sample_watchlist, monkeypatch):
    queried = []

    def fake_get(url, params=None, headers=None, timeout=None):
        queried.append(params["q"])
        return FakeResponse(SAMPLE_ENTRIES)

    monkeypatch.setattr(crtsh_subdomains, "MAX_LOOKUPS_PER_RUN", 1)
    monkeypatch.setattr(crtsh_subdomains.requests, "get", fake_get)

    crtsh_subdomains.collect()
    assert queried == ["example.com"]


# --- Retry behavior -----------------------------------------------------
# crt.sh's first real live run (see README) failed with a 502 -- a known,
# documented characteristic of crt.sh under load, not a bug in this
# collector. These tests pin down the retry behavior added in response to
# that real failure, without actually sleeping in the test suite.

def test_fetch_with_retry_recovers_from_transient_502(monkeypatch):
    monkeypatch.setattr(crtsh_subdomains.time, "sleep", lambda seconds: None)
    responses = iter([FakeResponse({}, status_code=502), FakeResponse(SAMPLE_ENTRIES)])
    monkeypatch.setattr(
        crtsh_subdomains.requests, "get",
        lambda url, params=None, headers=None, timeout=None: next(responses),
    )

    entries = crtsh_subdomains._fetch_with_retry("example.com")
    assert entries == SAMPLE_ENTRIES


def test_fetch_with_retry_raises_after_exhausting_attempts(monkeypatch):
    monkeypatch.setattr(crtsh_subdomains.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        crtsh_subdomains.requests, "get",
        lambda url, params=None, headers=None, timeout=None: FakeResponse({}, status_code=502),
    )

    with pytest.raises(RuntimeError, match="crt.sh lookup"):
        crtsh_subdomains._fetch_with_retry("example.com")
