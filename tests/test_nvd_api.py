"""Tests for the NVD CVE API collector, using a static JSON fixture --
no live network in CI.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.collectors import nvd_api

SAMPLE_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-12345",
                "published": "2026-07-01T10:00:00.000",
                "descriptions": [{"lang": "en", "value": "A test vulnerability description."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
            }
        }
    ],
}


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


@pytest.fixture
def patch_requests(monkeypatch):
    monkeypatch.setattr(
        nvd_api.requests, "get", lambda *a, **kw: FakeResponse(SAMPLE_RESPONSE)
    )


def test_collect_parses_cve_record(patch_requests):
    records = nvd_api.collect()
    assert len(records) == 1
    record = records[0]
    assert record.title == "CVE-2026-12345"
    assert record.external_id == "CVE-2026-12345"
    assert "cve" in record.tags
    assert "high" in record.tags
    assert record.summary == "A test vulnerability description."


def test_collect_skips_entries_without_cve_id(monkeypatch):
    broken_response = {"vulnerabilities": [{"cve": {"descriptions": []}}]}
    monkeypatch.setattr(
        nvd_api.requests, "get", lambda *a, **kw: FakeResponse(broken_response)
    )
    records = nvd_api.collect()
    assert records == []
