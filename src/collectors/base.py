"""Collector interface.

Every collector module exposes:

    NAME: str          -- unique source name, stored in `sources.name`
    SOURCE_TYPE: str    -- 'rss' | 'api' | 'scrape'
    SOURCE_URL: str     -- canonical URL for the source, stored in `sources.url`
    collect(limit=20) -> list[Record]

Keeping every collector to this shape means the orchestrator (pipeline.py)
never needs to know how a given source works internally -- adding a new
source is "write one new file", not "touch the pipeline".
"""

from __future__ import annotations

from src.db.models import Record

__all__ = ["Record"]
