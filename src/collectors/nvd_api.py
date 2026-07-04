"""API collector: NVD CVE 2.0 REST API.

No API key required for light use (rate-limited to ~5 req/30s without one --
fine for a scheduled job that runs a few times a day). Pulls the most
recently published CVEs as a second, API-shaped source alongside the RSS
collector, so the pipeline demonstrates both collection methods.

Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import json

import requests

from src.collectors.base import Record

NAME = "nvd_cve"
SOURCE_TYPE = "api"
SOURCE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {"User-Agent": "osint-pipeline/0.1 (portfolio project)"}


def _severity_tags(cve: dict) -> list[str]:
    metrics = cve.get("metrics", {})
    tags = []
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            severity = metrics[key][0].get("cvssData", {}).get("baseSeverity") or metrics[key][0].get("baseSeverity")
            if severity:
                tags.append(severity.lower())
            break
    return tags


def collect(limit: int = 20) -> list[Record]:
    # NB: NVD's v2.0 API does not support a `sortBy` param -- an earlier
    # version of this collector included one, which caused every live run
    # to fail with a 404 (caught by pipeline.py's per-source error
    # isolation, so it failed silently rather than breaking the whole run).
    # Confirmed by testing the request directly: adding sortBy=publishDate
    # 404s, removing it returns data normally.
    params = {"resultsPerPage": limit}
    resp = requests.get(SOURCE_URL, params=params, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    records: list[Record] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        records.append(
            Record(
                source_name=NAME,
                title=cve_id,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                summary=summary,
                published_at=cve.get("published"),
                external_id=cve_id,
                raw_json=json.dumps(cve, default=str),
                tags=["cve"] + _severity_tags(cve),
            )
        )

    return records
