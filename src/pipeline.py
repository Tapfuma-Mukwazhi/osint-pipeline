"""Pipeline orchestrator: fetch -> normalize -> dedupe -> store.

Run directly:

    python -m src.pipeline

Each collector runs independently and failures are isolated -- one source
timing out or changing its response format shouldn't take down the whole
run. That isolation is the main thing that makes this "automated collection
tooling" rather than a fragile script.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass

from src.collectors import crtsh_subdomains, nvd_api, packetstorm_scraper, rss_feeds, vt_domain_lookup
from src.db.models import get_connection, get_or_create_source, init_db, insert_observation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("pipeline")

# vt_domain_lookup requires VT_API_KEY to be set (see that module's
# docstring for setup). If it's missing, run_collector's per-source error
# isolation logs it and moves on -- the rest of the pipeline still runs.
COLLECTORS = [rss_feeds, nvd_api, packetstorm_scraper, vt_domain_lookup, crtsh_subdomains]


@dataclass
class RunStats:
    source: str
    fetched: int = 0
    new: int = 0
    duplicates: int = 0
    error: str | None = None


def run_collector(conn, collector_module) -> RunStats:
    name = collector_module.NAME
    stats = RunStats(source=name)

    try:
        source_id = get_or_create_source(
            conn, name, collector_module.SOURCE_TYPE, collector_module.SOURCE_URL
        )
        records = collector_module.collect()
        stats.fetched = len(records)

        for record in records:
            _, was_new = insert_observation(conn, source_id, record)
            if was_new:
                stats.new += 1
            else:
                stats.duplicates += 1

        log.info(
            "%s: fetched=%d new=%d duplicates=%d",
            name, stats.fetched, stats.new, stats.duplicates,
        )
    except Exception as exc:  # noqa: BLE001 -- isolate failures per-source
        stats.error = str(exc)
        log.error("%s: collection failed: %s", name, exc)

    return stats


def run() -> list[RunStats]:
    conn = get_connection()
    init_db(conn)

    log.info("Starting pipeline run across %d collector(s)", len(COLLECTORS))
    results = [run_collector(conn, module) for module in COLLECTORS]

    total_new = sum(r.new for r in results)
    total_errors = sum(1 for r in results if r.error)
    log.info(
        "Run complete: %d new record(s) stored, %d/%d source(s) failed",
        total_new, total_errors, len(results),
    )

    conn.close()
    return results


if __name__ == "__main__":
    run()
