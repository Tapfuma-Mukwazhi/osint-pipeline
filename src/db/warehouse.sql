-- Star-schema layer over the normalized OLTP tables in schema.sql.
--
-- Implemented as views, not physical tables, deliberately: this dataset is
-- small enough that materializing and re-syncing copies would add ETL
-- complexity (a refresh job, staleness windows, drift risk) for no real
-- query-speed benefit. Views stay perfectly in sync with the source tables
-- for free, since they're computed at query time from the same rows the
-- pipeline just wrote. If the dataset grows enough that view performance
-- becomes a real problem, these are straightforward to convert into
-- physical tables refreshed by a scheduled job -- the query shape wouldn't
-- change, only where the rows are materialized.
--
-- Grain:
--   fact_observations       -- one row per observation
--   fact_observation_tags   -- one row per (observation, tag) pair -- a
--                              bridge/fact table, since tags are many-to-many
--                              and severity/keyword trend analysis needs to
--                              query at the tag grain, not the observation
--                              grain.

CREATE VIEW IF NOT EXISTS dim_source AS
SELECT
    id      AS source_key,
    name    AS source_name,
    type    AS source_type,
    url     AS source_url,
    added_at
FROM sources;

-- Date dimension, generated from the dates actually present in the data
-- rather than a fixed calendar table -- there's no need to pre-populate
-- years of future dates for a project this size.
CREATE VIEW IF NOT EXISTS dim_date AS
SELECT DISTINCT
    d                                      AS date_key,
    d                                      AS full_date,
    CAST(strftime('%Y', d) AS INTEGER)     AS year,
    CAST(strftime('%m', d) AS INTEGER)     AS month,
    CAST(strftime('%d', d) AS INTEGER)     AS day,
    CAST(strftime('%w', d) AS INTEGER)     AS day_of_week,
    strftime('%Y-%m', d)                   AS year_month
FROM (
    SELECT date(published_at) AS d FROM observations WHERE published_at IS NOT NULL
    UNION
    SELECT date(collected_at) AS d FROM observations WHERE collected_at IS NOT NULL
);

CREATE VIEW IF NOT EXISTS dim_tag AS
SELECT
    id      AS tag_key,
    name    AS tag_name,
    CASE
        WHEN name IN ('low', 'medium', 'high', 'critical')            THEN 'severity'
        WHEN name IN ('malicious', 'suspicious', 'harmless', 'undetected') THEN 'verdict'
        WHEN name = 'cve'                                             THEN 'record_type'
        ELSE 'keyword'
    END AS tag_category
FROM tags;

-- Fact table at observation grain. tag_count is a degenerate measure kept
-- here (rather than requiring a join to fact_observation_tags) so "how
-- tagged is this record" is a single-table query.
CREATE VIEW IF NOT EXISTS fact_observations AS
SELECT
    o.id                    AS observation_key,
    o.source_id             AS source_key,
    date(o.published_at)    AS published_date_key,
    date(o.collected_at)    AS collected_date_key,
    o.title,
    o.url,
    o.external_id,
    (
        SELECT COUNT(*) FROM observation_tags ot
        WHERE ot.observation_id = o.id
    )                       AS tag_count
FROM observations o;

-- Bridge/fact table at (observation, tag) grain -- this is the one to query
-- for tag-level trends (severity over time, keyword frequency over time),
-- since fact_observations alone can't answer "how many CVEs were high
-- severity in June" without re-deriving the tag join every time.
CREATE VIEW IF NOT EXISTS fact_observation_tags AS
SELECT
    ot.observation_id       AS observation_key,
    o.source_id             AS source_key,
    ot.tag_id               AS tag_key,
    date(o.published_at)    AS published_date_key,
    date(o.collected_at)    AS collected_date_key
FROM observation_tags ot
JOIN observations o ON o.id = ot.observation_id;
