-- osint-pipeline schema
-- Normalized so it ports to Postgres without rewrites; SQLite for local/dev use.

CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,      -- e.g. 'abuse.ch', 'alienvault_otx'
    type        TEXT NOT NULL,             -- 'rss', 'api', 'scrape'
    url         TEXT NOT NULL,
    added_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS observations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       INTEGER NOT NULL REFERENCES sources(id),
    external_id     TEXT,                  -- source's own entry id/guid, if any
    title           TEXT NOT NULL,
    url             TEXT,
    summary         TEXT,
    published_at    TEXT,                  -- ISO8601, from the source
    collected_at    TEXT NOT NULL DEFAULT (datetime('now')),
    content_hash    TEXT NOT NULL UNIQUE,  -- sha256 of source_id+external_id/title+url, for dedupe
    raw_json        TEXT                   -- original payload, for reprocessing
);

CREATE INDEX IF NOT EXISTS idx_observations_source ON observations(source_id);
CREATE INDEX IF NOT EXISTS idx_observations_published ON observations(published_at);

CREATE TABLE IF NOT EXISTS tags (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name    TEXT NOT NULL UNIQUE            -- keyword, malware family, threat actor, CVE, etc.
);

CREATE TABLE IF NOT EXISTS observation_tags (
    observation_id  INTEGER NOT NULL REFERENCES observations(id),
    tag_id          INTEGER NOT NULL REFERENCES tags(id),
    PRIMARY KEY (observation_id, tag_id)
);

-- Convenience view for EDA / quick queries
CREATE VIEW IF NOT EXISTS v_observations_tagged AS
SELECT
    o.id,
    s.name AS source,
    o.title,
    o.url,
    o.published_at,
    o.collected_at,
    GROUP_CONCAT(t.name, ', ') AS tags
FROM observations o
JOIN sources s ON s.id = o.source_id
LEFT JOIN observation_tags ot ON ot.observation_id = o.id
LEFT JOIN tags t ON t.id = ot.tag_id
GROUP BY o.id;
