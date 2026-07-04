# osint-pipeline

Automated collection pipeline for open-source cyber threat intelligence. Pulls structured indicators and reporting from open threat-intel feeds, normalizes them into a local database, and runs on a schedule — built as a portfolio project demonstrating the collection/pipeline skills used in CTI analyst work (source integration, automation, data modeling, exploratory analysis).

## Scope & ethics

This project only collects from public sources, and only where doing so doesn't violate the source's terms of service or robots.txt. Before adding the scraper, I checked packetstormsecurity.com's robots.txt to confirm the files section isn't disallowed. Nothing here accesses non-public or authentication-gated systems without a properly obtained key, and nothing targets or stores personal data about individuals. Any future extension into dark-web collection will follow the same principle: passive, read-only collection from sources that are legally and ethically accessible for security research, with no interaction with active criminal infrastructure.

## Sources

| Collector | Type | Source | Notes |
|---|---|---|---|
| `rss_feeds.py` | RSS | SANS Internet Storm Center | Daily handler diaries; structured, no auth |
| `nvd_api.py` | API | NVD CVE 2.0 REST API | No key required for light/scheduled use |
| `packetstorm_scraper.py` | Scrape | PacketStorm Security file listing | Disabled -- source now requires clickwrap ToS agreement site-wide; see module docstring |
| `vt_domain_lookup.py` | API (gated) | VirusTotal domain reputation | Requires a free API key -- demonstrates authenticated/closed-source handling. Setup in the module docstring. |
| `crtsh_subdomains.py` | API (OSINT tool technique) | crt.sh certificate transparency logs | Passive subdomain enumeration -- reimplements the technique behind theHarvester's `crtsh` module directly, rather than depending on that tool's own installation. See module docstring for why. |

## Architecture

```
osint-pipeline/
├── src/
│   ├── collectors/              # one module per source, each yields normalized records
│   │   ├── rss_feeds.py         # SANS ISC RSS
│   │   ├── nvd_api.py           # NVD CVE REST API
│   │   ├── packetstorm_scraper.py  # HTML scrape, disabled (ToS gate) -- see docstring
│   │   └── crtsh_subdomains.py  # certificate-transparency subdomain enumeration (OSINT technique)
│   ├── db/
│   │   ├── schema.sql          # normalized OLTP storage schema
│   │   ├── warehouse.sql       # star-schema views (dims + facts) over the OLTP tables
│   │   ├── trend_queries.sql   # example trend queries against the star schema
│   │   └── models.py           # DB access layer (SQLite)
│   └── pipeline.py       # orchestrator: fetch -> normalize -> dedupe -> store
├── tests/                # unit tests for parsing/dedupe logic, static fixtures only
├── notebooks/            # exploratory data analysis on collected data
├── .github/workflows/    # scheduled automated runs
└── data/                 # local SQLite DB (tracked -- see .gitignore comment)
```

## Data warehouse layer

`src/db/warehouse.sql` builds a small star schema on top of the normalized tables in `schema.sql`:
three dimensions (`dim_source`, `dim_date`, `dim_tag`) and two fact views (`fact_observations` at
one-row-per-observation grain, `fact_observation_tags` as a bridge table at one-row-per-tag grain,
needed since tags are many-to-many and severity/keyword trends have to query at the tag level).

These are SQL views, not physical tables that get copied and re-synced. For a dataset this size,
materializing copies would mean building a refresh job and accepting a staleness window for no
real query-speed benefit; views stay exactly in sync with the source tables for free, computed
at query time. `init_db()` creates them automatically alongside the base schema, every run.

`src/db/trend_queries.sql` has five example queries against this layer (collection volume by
source/day, CVE severity trend by month, top keyword tags, source activity + tagging rate, and
VirusTotal verdict trend) -- the kind of question that's a multi-table join every time against
the normalized schema directly, and a couple of clean joins against the star schema. Run with:

```bash
sqlite3 data/osint.db < src/db/trend_queries.sql
```

One real bug this caught: the VirusTotal verdict query originally joined on
`published_date_key`, which is `NULL` for every VirusTotal row (a domain reputation lookup has
no meaningful "publish date") -- so it silently returned zero rows for a real, populated source.
Fixed by joining on `collected_date_key` instead, which is the date dimension that's actually
populated for that source. Caught by running the query against real data, not by reading the SQL.

## Why this design

- **Collector interface is pluggable.** Every source implements the same `collect() -> list[Record]` shape, so adding a new source (paste sites, GitHub secret search, Shodan/Censys) means writing one new file, not touching the orchestrator.
- **SQLite to start, Postgres-shaped schema.** Schema is written as plain SQL so it ports to Postgres without a rewrite if the dataset grows.
- **Scheduling via GitHub Actions**, not just a script you remember to run — mirrors "reliable and efficient collection tooling" rather than a one-off scrape.

## AI-assisted development

Built with Claude as a coding partner, used deliberately rather than as an autocomplete. Roughly how the work split:

- **Claude wrote:** the initial scaffolding, collector modules, SQLite schema, dedupe logic, test fixtures, and the GitHub Actions workflow, from a description of what each piece needed to do.
- **I made the calls Claude couldn't:** which sources to target, when a "quick fix" (e.g. scripting around PacketStorm's ToS clickwrap) would cross an ethical line worth just... not crossing, and what actually belonged in a portfolio project versus scope creep.
- **Real bugs were only caught by actually running things, not by code looking plausible.** Two examples that shaped how this project was built: `feedparser` silently returning zero entries on a network failure instead of raising (would've looked like "no news today" during a real outage) and an invalid NVD API parameter that 404'd on every live run while passing every local test, because the tests used static fixtures and never touched the real API. Both were only found by reading actual GitHub Actions logs after a live scheduled run, not by trusting a green checkmark. A job-level "success" can still hide a per-source failure -- that's a real lesson from this project, not a hypothetical one.
- **The EDA notebook surfaced a second bug this way too:** fixing the NVD 404 by removing the bad parameter was correct, but it left results unsorted by recency -- something that only became visible once real data was actually analyzed, not before.

The pattern worth naming: AI-assisted coding sped up the boilerplate, but every real bug in this project was found by testing against live systems and reading actual output, not by code review or by assuming a passing test suite meant the pipeline worked end to end.

## Setup

```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m src.pipeline
```

`vt_domain_lookup.py` is optional -- it requires a free VirusTotal API key (see that module's docstring). If `VT_API_KEY` isn't set, the pipeline logs it as a failed source and continues with everything else; nothing else depends on it.

Data lands in `data/osint.db`. Query it directly with any SQLite client, or open `notebooks/eda.ipynb` for exploratory analysis.

To run the notebook (separate, heavier deps -- not needed for the pipeline itself):

```bash
pip install -r requirements-notebook.txt
jupyter notebook notebooks/eda.ipynb
```

## Roadmap

- [x] RSS collector (SANS ISC)
- [x] API collector (NVD CVE) -- fixed a live-only bug where an invalid `sortBy` param caused every run to 404
- [x] HTML scraper, no feed/API source (PacketStorm) -- disabled after the source added a mandatory ToS clickwrap; a replacement scraping target is still needed
- [x] Gated/authenticated API collector (VirusTotal domain reputation) -- requires your own free API key
- [x] EDA notebook on collected data (`notebooks/eda.ipynb`) -- also surfaced a second real bug: removing the invalid `sortBy` param fixed the 404, but left NVD results unsorted by recency (this run's CVEs were all from 1999-2000). Tracked as a follow-up, not yet fixed.
- [x] Star-schema warehouse layer for trend queries (`src/db/warehouse.sql`, `src/db/trend_queries.sql`) -- caught a real bug where the VirusTotal verdict query silently returned zero rows by joining on a date field that's always NULL for that source
- [x] OSINT tooling wrapper (`crtsh_subdomains.py`) -- passive subdomain enumeration via certificate transparency logs, the same technique theHarvester's `crtsh` module uses. Built from scratch instead of wrapping the actual theHarvester binary, since the PyPI package for it is a stale non-functional placeholder and the real tool isn't designed for headless CI use -- see the module docstring for the full reasoning.
- [ ] Safe Tor-based collector
