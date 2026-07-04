"""Tests for the VirusTotal domain reputation collector, using a static
JSON fixture -- no live network, no real API key needed in CI.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.collectors import vt_domain_lookup

MALICIOUS_RESPONSE = {
    "data": {
        "id": "evil-example.test",
        "attributes": {
            "reputation": -15,
            "last_analysis_stats": {"malicious": 12, "suspicious": 2, "harmless": 60, "undetected": 5},
            "categories": {"vendor_a": "phishing"},
        }
    }
}

CLEAN_RESPONSE = {
    "data": {
        "id": "example.com",
        "attributes": {
            "reputation": 40,
            "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5},
            "categories": {},
        }
    }
}


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
def with_api_key(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key-123")


@pytest.fixture
def sample_watchlist(tmp_path, monkeypatch):
    watchlist = tmp_path / "watchlist.txt"
    watchlist.write_text("# comment line\nevil-example.test\nexample.com\n")
    monkeypatch.setattr(vt_domain_lookup, "WATCHLIST_PATH", watchlist)


def test_collect_raises_without_api_key(monkeypatch, sample_watchlist):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="VT_API_KEY"):
        vt_domain_lookup.collect()


def test_collect_tags_malicious_domain(with_api_key, sample_watchlist, monkeypatch):
    responses = {"evil-example.test": MALICIOUS_RESPONSE, "example.com": CLEAN_RESPONSE}

    def fake_get(url, headers=None, timeout=None):
        domain = url.rsplit("/", 1)[-1]
        return FakeResponse(responses[domain])

    monkeypatch.setattr(vt_domain_lookup.requests, "get", fake_get)

    records = vt_domain_lookup.collect()
    evil_record = next(r for r in records if r.external_id == "evil-example.test")
    assert "malicious" in evil_record.tags
    assert "phishing" in evil_record.summary


def test_collect_tags_clean_domain_as_harmless(with_api_key, sample_watchlist, monkeypatch):
    responses = {"evil-example.test": MALICIOUS_RESPONSE, "example.com": CLEAN_RESPONSE}

    def fake_get(url, headers=None, timeout=None):
        domain = url.rsplit("/", 1)[-1]
        return FakeResponse(responses[domain])

    monkeypatch.setattr(vt_domain_lookup.requests, "get", fake_get)

    records = vt_domain_lookup.collect()
    clean_record = next(r for r in records if r.external_id == "example.com")
    assert clean_record.tags == ["harmless"]


def test_collect_skips_domains_not_found(with_api_key, sample_watchlist, monkeypatch):
    monkeypatch.setattr(
        vt_domain_lookup.requests, "get",
        lambda url, headers=None, timeout=None: FakeResponse({}, status_code=404),
    )
    records = vt_domain_lookup.collect()
    assert records == []


def test_collect_returns_empty_for_empty_watchlist(with_api_key, tmp_path, monkeypatch):
    empty_watchlist = tmp_path / "empty.txt"
    empty_watchlist.write_text("# nothing here\n")
    monkeypatch.setattr(vt_domain_lookup, "WATCHLIST_PATH", empty_watchlist)

    records = vt_domain_lookup.collect()
    assert records == []
