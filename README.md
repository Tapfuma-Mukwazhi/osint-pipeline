# osint-pipeline

Automated collection pipeline for open-source cyber threat intelligence. Pulls structured indicators and reporting from open threat-intel feeds, normalizes them into a local database, and runs on a schedule — built as a portfolio project demonstrating the collection/pipeline skills used in CTI analyst work (source integration, automation, data modeling, exploratory analysis).

## Scope & ethics

This project only collects from public sources, and only where doing so doesn't violate the source's terms of service or robots.txt. Before adding the scraper, I checked packetstormsecurity.com's robots.txt to confirm the files section isn't disallowed. Nothing here accesses non-public or authentication-gated systems without a properly obtained key, and nothing targets or stores personal data about individuals. Any future extension into dark-web collection will follow the same principle: passive, read-only collection from sources that are legally and ethically accessible for security research, with no interaction with active criminal infrastructure.

## Sources

| Collector | Type | Source | Notes |
|---|---|---|---|
| `rss_feeds.py` | RSS | SANS Internet Storm Center | Daily handler diaries; structured, no auth |
| `nvd_api.py` | API | NVD CVE 2.0 REST API | No key required for light/scheduled use |
| `packetstorm_scraper.py` | Scrape | PacketStorm Security file listing | No feed/API for this source -- real HTML parsing |
| `vt_domain_lookup.py` | API (gated) | VirusTotal domain reputation | Requires a free API key -- demonstrates authenticated/closed-source handling. Setup in the module docstring. |

## Architecture

```
osint-pipeline/
├── src/
│   ├── collectors/              # one module per source, each yields normalized records
│   │   ├── rss_feeds.py         # SANS ISC RSS
│   │   ├── nvd_api.py           # NVD CVE REST API
│   │   └── packetstorm_scraper.py  # HTML scrape, no feed/API available
│   ├── db/
│   │   ├── schema.sql    # normalized storage schema
│   │   └── models.py     # DB access layer (SQLite)
│   └── pipeline.py       # orchestrator: fetch -> normalize -> dedupe -> store
├── tests/                # unit tests for parsing/dedupe logic, static fixtures only
├── notebooks/            # exploratory data analysis on collected data
├── .github/workflows/    # scheduled automated runs
└── data/                 # local SQLite DB (tracked -- see .gitignore comment)
```

## Why this design

- **Collector interface is pluggable.** Every source implements the same `collect() -> list[Record]` shape, so adding a new source (paste sites, GitHub secret search, Shodan/Censys) means writing one new file, not touching the orchestrator.
- **SQLite to start, Postgres-shaped schema.** Schema is written as plain SQL so it ports to Postgres without a rewrite if the dataset grows.
- **Scheduling via GitHub Actions**, not just a script you remember to run — mirrors "reliable and efficient collection tooling" rather than a one-off scrape.

## Setup

```bash
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m src.pipeline
```

`vt_domain_lookup.py` is optional -- it requires a free VirusTotal API key (see that module's docstring). If `VT_API_KEY` isn't set, the pipeline logs it as a failed source and continues with everything else; nothing else depends on it.

Data lands in `data/osint.db`. Query it directly with any SQLite client, or open `notebooks/eda.ipynb` for exploratory analysis.

## Roadmap

- [x] RSS collector (SANS ISC)
- [x] API collector (NVD CVE)
- [x] HTML scraper, no feed/API source (PacketStorm) -- selectors verified against a static fixture, not yet run against live markup; see the honesty note at the top of `packetstorm_scraper.py`
- [x] Gated/authenticated API collector (VirusTotal domain reputation) -- requires your own free API key
- [ ] EDA notebook on collected data
- [ ] Star-schema warehouse layer for trend queries
- [ ] OSINT tooling wrapper
- [ ] Safe Tor-based collector
