-- Example trend queries against the star-schema views in warehouse.sql.
-- These are the kind of questions a normalized OLTP schema makes awkward
-- (multi-table joins repeated in every query) and a star schema makes
-- straightforward (join a fact view to a couple of dimension views).
--
-- Run with: sqlite3 data/osint.db < src/db/trend_queries.sql

-- 1. Collection volume by source, by day.
-- Answers: "which sources are actually producing data, and when."
SELECT
    ds.source_name,
    f.collected_date_key,
    COUNT(*) AS observations
FROM fact_observations f
JOIN dim_source ds ON ds.source_key = f.source_key
GROUP BY ds.source_name, f.collected_date_key
ORDER BY f.collected_date_key, ds.source_name;

-- 2. CVE severity trend by month (published date).
-- Answers: "is severity mix shifting over time." On a single-day snapshot
-- this collapses to one month; the query itself is what matters once the
-- scheduled job has been running long enough to span multiple months.
SELECT
    dd.year_month,
    dt.tag_name AS severity,
    COUNT(*) AS cve_count
FROM fact_observation_tags fot
JOIN dim_tag dt ON dt.tag_key = fot.tag_key AND dt.tag_category = 'severity'
JOIN dim_date dd ON dd.date_key = fot.published_date_key
GROUP BY dd.year_month, dt.tag_name
ORDER BY dd.year_month, dt.tag_name;

-- 3. Top keyword tags overall (phishing, ransomware, malware, c2, etc.),
-- excluding severity/verdict/record-type tags.
-- Answers: "what threat themes show up most often across all sources."
SELECT
    dt.tag_name,
    COUNT(*) AS mentions
FROM fact_observation_tags fot
JOIN dim_tag dt ON dt.tag_key = fot.tag_key AND dt.tag_category = 'keyword'
GROUP BY dt.tag_name
ORDER BY mentions DESC;

-- 4. Source activity over time -- rolling count of new observations per
-- source per collection date, alongside how many carry at least one tag.
-- Answers: "is a source actively contributing, and is what it contributes
-- getting tagged/classified, or just landing untouched."
SELECT
    ds.source_name,
    f.collected_date_key,
    COUNT(*) AS total_observations,
    SUM(CASE WHEN f.tag_count > 0 THEN 1 ELSE 0 END) AS tagged_observations
FROM fact_observations f
JOIN dim_source ds ON ds.source_key = f.source_key
GROUP BY ds.source_name, f.collected_date_key
ORDER BY f.collected_date_key, ds.source_name;

-- 5. VirusTotal verdict breakdown -- the gated-API source's whole point is
-- reputation classification, so this is its dedicated trend view.
--
-- Joins on collected_date_key, not published_date_key: a domain reputation
-- lookup doesn't have a meaningful "publish date" (vt_domain_lookup.py never
-- sets one), so published_date_key is NULL for every VirusTotal row. An
-- earlier version of this query joined on published_date_key and silently
-- returned zero rows for a real, populated source -- caught only by running
-- it against actual data, not by reading the SQL. collected_date_key is the
-- only date dimension that's actually populated for this source.
SELECT
    dd.year_month,
    dt.tag_name AS verdict,
    COUNT(*) AS domains
FROM fact_observation_tags fot
JOIN dim_tag dt ON dt.tag_key = fot.tag_key AND dt.tag_category = 'verdict'
JOIN dim_source ds ON ds.source_key = fot.source_key AND ds.source_name = 'virustotal'
JOIN dim_date dd ON dd.date_key = fot.collected_date_key
GROUP BY dd.year_month, dt.tag_name
ORDER BY dd.year_month, dt.tag_name;
