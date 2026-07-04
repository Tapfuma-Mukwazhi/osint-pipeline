"""SQLite access layer for osint-pipeline.

Deliberately raw sqlite3 + hand-written SQL rather than an ORM: the schema
is small, and writing the SQL directly is more transparent for a portfolio
piece meant to demonstrate SQL, not hide it behind an abstraction.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "osint.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


@dataclass
class Record:
    """A single normalized item pulled from a collector, before storage."""

    source_name: str
    title: str
    url: str | None = None
    summary: str | None = None
    published_at: str | None = None
    external_id: str | None = None
    raw_json: str | None = None
    tags: list[str] = field(default_factory=list)


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()


def content_hash(source_name: str, record: Record) -> str:
    """Stable hash for dedupe: prefer external_id, fall back to title+url."""
    basis = record.external_id or f"{record.title}|{record.url or ''}"
    return hashlib.sha256(f"{source_name}|{basis}".encode("utf-8")).hexdigest()


def get_or_create_source(conn: sqlite3.Connection, name: str, source_type: str, url: str) -> int:
    cur = conn.execute("SELECT id FROM sources WHERE name = ?", (name,))
    row = cur.fetchone()
    if row:
        return row[0]
    cur = conn.execute(
        "INSERT INTO sources (name, type, url) VALUES (?, ?, ?)",
        (name, source_type, url),
    )
    conn.commit()
    return cur.lastrowid


def get_or_create_tag(conn: sqlite3.Connection, name: str) -> int:
    cur = conn.execute("SELECT id FROM tags WHERE name = ?", (name,))
    row = cur.fetchone()
    if row:
        return row[0]
    cur = conn.execute("INSERT INTO tags (name) VALUES (?)", (name,))
    conn.commit()
    return cur.lastrowid


def insert_observation(conn: sqlite3.Connection, source_id: int, record: Record) -> tuple[int | None, bool]:
    """Insert a record if it isn't a duplicate. Returns (observation_id, was_new)."""
    chash = content_hash(record.source_name, record)
    existing = conn.execute(
        "SELECT id FROM observations WHERE content_hash = ?", (chash,)
    ).fetchone()
    if existing:
        return existing[0], False

    cur = conn.execute(
        """
        INSERT INTO observations
            (source_id, external_id, title, url, summary, published_at, content_hash, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            record.external_id,
            record.title,
            record.url,
            record.summary,
            record.published_at,
            chash,
            record.raw_json,
        ),
    )
    obs_id = cur.lastrowid

    for tag_name in record.tags:
        tag_id = get_or_create_tag(conn, tag_name)
        conn.execute(
            "INSERT OR IGNORE INTO observation_tags (observation_id, tag_id) VALUES (?, ?)",
            (obs_id, tag_id),
        )

    conn.commit()
    return obs_id, True
