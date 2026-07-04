"""Tests for the DB access layer: schema init, source lookup, dedupe."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from src.db import models


@pytest.fixture
def conn(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    connection = models.get_connection(db_path)
    models.init_db(connection)
    yield connection
    connection.close()


def test_get_or_create_source_is_idempotent(conn):
    id_a = models.get_or_create_source(conn, "test_source", "rss", "https://example.com/feed")
    id_b = models.get_or_create_source(conn, "test_source", "rss", "https://example.com/feed")
    assert id_a == id_b


def test_insert_observation_dedupes_on_content_hash(conn):
    source_id = models.get_or_create_source(conn, "test_source", "rss", "https://example.com/feed")
    record = models.Record(
        source_name="test_source",
        title="Same story reported twice",
        url="https://example.com/story",
        external_id="story-123",
        tags=["phishing"],
    )

    first_id, first_new = models.insert_observation(conn, source_id, record)
    second_id, second_new = models.insert_observation(conn, source_id, record)

    assert first_new is True
    assert second_new is False
    assert first_id == second_id


def test_insert_observation_without_external_id_hashes_on_title_and_url(conn):
    source_id = models.get_or_create_source(conn, "test_source", "rss", "https://example.com/feed")
    record_a = models.Record(source_name="test_source", title="Story A", url="https://example.com/a")
    record_b = models.Record(source_name="test_source", title="Story B", url="https://example.com/b")

    _, new_a = models.insert_observation(conn, source_id, record_a)
    _, new_b = models.insert_observation(conn, source_id, record_b)

    assert new_a is True
    assert new_b is True


def test_insert_observation_stores_tags(conn):
    source_id = models.get_or_create_source(conn, "test_source", "rss", "https://example.com/feed")
    record = models.Record(
        source_name="test_source",
        title="Tagged story",
        url="https://example.com/tagged",
        tags=["ransomware", "phishing"],
    )
    obs_id, _ = models.insert_observation(conn, source_id, record)

    rows = conn.execute(
        """
        SELECT t.name FROM tags t
        JOIN observation_tags ot ON ot.tag_id = t.id
        WHERE ot.observation_id = ?
        """,
        (obs_id,),
    ).fetchall()
    tag_names = {row[0] for row in rows}
    assert tag_names == {"ransomware", "phishing"}
