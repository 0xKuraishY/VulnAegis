<div align="center">

# VulnAegis

**Near real-time CVE detection and alerting, built for a SOC analyst.**

![Python](https://img.shields.io/badge/python-3.10%2B-3987e5?style=flat-square)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-0ca30c?style=flat-square)
![Sources](https://img.shields.io/badge/sources-NVD%20%C2%B7%20CISA%20KEV%20%C2%B7%20GHSA%20%C2%B7%20OSV%20%C2%B7%20EPSS-fab219?style=flat-square)
![Frontend](https://img.shields.io/badge/frontend-vanilla%20JS%2C%20no%20build-1f52a3?style=flat-square)
![Status](https://img.shields.io/badge/status-active-6b6b63?style=flat-square)

</div>

VulnAegis continuously aggregates **NVD**, **CISA KEV** and **GitHub
Advisories**, enriches with **OSV**, **Exploit-DB**, **EPSS** and
**AlienVault OTX/MISP**, and runs a dedicated real-time radar against GitHub
for freshly published proof-of-concept exploits. A rules engine (CVSS
threshold, active exploitation, watchlist match, public PoC, imminent
exploitation risk) turns all of that into deduplicated alerts on Slack, email, or any
generic webhook - all surfaced through a dashboard and a full REST API
protected by user accounts (JWT) and revocable API keys.

No Kafka, no Elasticsearch, no Kubernetes cluster to run this: one Python
service, a Postgres/SQLite database, and a documented scaling path for when
that's actually needed (`docs/SCALING.md`).

---

## Contents

- [How it works](#how-it-works)
- [Features](#features)
- [Quickstart](#quickstart)
- [The ingestion pipeline](#the-ingestion-pipeline)
- [Data sources](#data-sources)
- [The rules engine](#the-rules-engine)
- [Alert channels](#alert-channels)
- [The dashboard](#the-dashboard)
- [API reference](#api-reference)
- [Data model](#data-model)
- [Security](#security)
- [Configuration reference](#configuration-reference)
- [Tests](#tests)
- [Deployment](#deployment)
- [Code examples](#code-examples)
- [Project layout](#project-layout)
- [Further reading](#further-reading)

## How it works

```mermaid
flowchart LR
    subgraph Sources
        NVD[NVD API 2.0]
        KEV[CISA KEV JSON]
        GHSA[GitHub Advisories API]
        OSV[OSV.dev]
        GHPOC[GitHub Search API]
        EPSS[EPSS daily CSV]
    end

    SCHED["Main scheduler\npoll every 5-10 min"]
    RADAR["PoC radar\n~4 min, decoupled"]
    INGEST["Ingestion pipeline\nmulti-source upsert"]
    RULES["Rules engine\nCVSS / KEV / PoC / exploitation imminente / watchlist"]
    DB[(PostgreSQL / SQLite)]

    NVD --> SCHED
    KEV --> SCHED
    GHSA --> SCHED
    OSV -.on-demand enrichment.-> INGEST
    EPSS -.daily enrichment.-> INGEST
    GHPOC --> RADAR

    SCHED --> INGEST --> DB
    RADAR --> INGEST
    INGEST --> RULES
    RULES -->|deduplicated| SLACK[Slack]
    RULES -->|deduplicated| SMTP[Email]
    RULES -->|deduplicated| SIEM[SIEM webhook]

    DB --> API[FastAPI REST API]
    API --> DASH[Dashboard]
    Analyst((Analyst)) --> DASH
    Analyst -.automation.-> API
```

**In short**: every few minutes, each connector polls its source, normalizes
the result into a common pivot format (`NormalizedCVE`), the ingestion
pipeline merges it into the database (the same CVE is often seen by several
sources), the rules engine decides whether it's worth an alert and why, and -
unless it's a recent duplicate - pushes a notification to the configured
channels. A separate, faster job scans GitHub for newly published PoC repos
tied to recent CVEs, independent of the main poll so it never waits behind a
slow NVD backfill. The dashboard and API read the same database continuously
to give the analyst an up-to-date view.

## Features

| Category | Details |
|---|---|
| **Sources** | NVD (CVSS/CPE authority), CISA KEV (confirmed active exploitation), GitHub Advisories (open-source ecosystems), OSV (on-demand enrichment), EPSS (exploitation probability, daily) |
| **Real-time PoC radar** | Dedicated GitHub Search poller (~4 min cadence, decoupled from the main poll) that catches new PoC repos for recent CVEs, often before NVD/KEV/GHSA have ingested the CVE at all - creates a provisional ("unconfirmed") CVE record that gets filled in normally once a structured source catches up |
| **Alert rules** | Configurable CVSS threshold, active exploitation (KEV), watchlist match (vendor/product/keyword), public PoC, and a distinct "imminent exploitation risk" reason when a PoC lands on a CVE that's already critical or KEV |
| **Alerting** | Slack, email (SMTP), generic webhook (TheHive, Splunk HEC, QRadar, ...), per-channel deduplication on a rolling window (24h default), automatic escalation if a critical/KEV alert stays unacknowledged |
| **Dashboard - Overview** | Stat tiles (total, KEV, critical, pending alerts, PoC in last 24h, imminent exploitation risk, high EPSS, unconfirmed), 14-day trend, severity breakdown, exploitation-risk trend, EPSS score distribution, top vendors, top CWE weakness types - clickable charts that filter the CVE page directly |
| **Dashboard - CVEs** | Sortable/filterable table (severity, vendor, KEV, PoC, minimum EPSS, watchlist, free text), 50-row pagination, CSV/JSON export |
| **Dashboard - detail panel** | CVSS vector decoded in plain language, EPSS score, CWE weakness type, affected CPEs, categorized references, known PoCs with repo/stars/discovery date, OTX/MISP threat context, CVSS score history, CISA KEV countdown |
| **Dashboard - PoC Radar** | Live feed of PoC discoveries across sources, newest first, with severity/KEV/exploitation-risk badges |
| **Dashboard - command palette** | `Ctrl/Cmd+K`: instant CVE search, page navigation, manual poll trigger, fully keyboard-driven |
| **Dashboard - watchlist** | Full CRUD for monitored assets/keywords, editable live, no restart needed |
| **Dashboard - settings** | Account/API key management, per-source status with manual "sync now" for EPSS and the PoC radar |
| **Bilingual UI** | French/English toggle, persisted, covering every screen and every generated message |
| **Theme** | Light / dark / system, persisted, severity palette validated for contrast in both modes |
| **API** | Full REST surface (FastAPI, interactive OpenAPI docs at `/docs`), CSV/JSON export, `watchlist_only` filter, KEV due-date sort |
| **Security** | Rate-limited login with timing-attack-resistant password checks, hardened response headers (CSP, HSTS, Permissions-Policy), CRLF-safe email headers, scheme-restricted outbound links, non-root container |
| **Ops** | Docker Compose (app + Postgres + Redis reserved for later), unit tests across rules/connectors/routes/security, zero frontend build (vanilla JS, no Node/webpack) |

## Screenshot

### Dashboard

![dashboard](/docs/img/dashboard.png)

### CVEs

![cves](/docs/img/cve.png)

### CVE details

![cve_detail](/docs/img/cve2.png)

### PoC Radar

![poc_radar](/docs/img/poc_radar.png)

### Watchlist

![watchlist](/docs/img/watchlist.png)

### Settings

![settings](/docs/img/settings.png)

## Quickstart

### Docker Compose (recommended)

```bash
cp .env.example .env
# Generate an API key and paste it into .env (see Security):
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

docker compose up --build
```

→ Dashboard: http://localhost:8000
→ Interactive API docs: http://localhost:8000/docs

### Local (Python 3.10+)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

On startup:
1. The database is created if it doesn't exist (`init_db()`, SQLite by
   default) - an additive migration also runs, adding any column a newer
   version of the code introduced without touching existing data.
2. `watchlist.yaml` is loaded into the database, but only if the table is
   empty, so entries added later through the API/dashboard are never
   overwritten.
3. Four scheduled jobs start: the main poll (NVD/KEV/GHSA, every
   `POLL_INTERVAL_MINUTES`, 5 by default), the PoC radar (every
   `GITHUB_POC_INTERVAL_MINUTES`, 4 by default), EPSS enrichment (daily), and
   escalation checks. The main poll and the PoC radar both run once
   immediately at startup.
4. A warning is logged if no authentication is configured (write endpoints
   left open).

## The ingestion pipeline

Key file: `app/ingest.py`, orchestrated by `app/scheduler.py`.

1. **Per-source poll** (`poll_source`): each connector keeps track, in the
   `source_state` table, of the timestamp of its last successful poll and
   only requests the delta since then (`fetch_since(since)`) - except CISA
   KEV, which re-downloads its whole catalog every time (a small file, no
   server-side pagination) and filters client-side on `dateAdded`.
2. **Upsert** (`upsert_cve`): a CVE can be seen by several sources at
   different times. The merge never degrades already-known data with an
   empty value - if NVD already supplied a CVSS score and a later GitHub
   Advisories poll doesn't, the existing score is kept. The `sources` field
   accumulates every connector that has seen this CVE, which is also how the
   dashboard tells a fully confirmed CVE apart from a PoC-radar "stub" one.
3. **Rule evaluation** (`dispatch_alerts` → `app.alerting.rules.evaluate`):
   for every inserted or updated CVE, the rules engine computes whether it
   should alert and why.
4. **Deduplication** (`app.alerting.dedupe`): before sending, checks whether
   an alert was already logged for this (CVE, channel) pair within the
   `ALERT_DEDUPE_HOURS` window (24h default).
5. **Send + log**: every successful send creates an `AlertLog` row (CVE,
   channel, reasons, timestamp) - this table feeds the Alerts page, the
   notification bell, and the escalation mechanism.
6. **Escalation** (`app.alerting.escalation`, its own job every
   `ESCALATION_CHECK_INTERVAL_MINUTES`): any alert left unacknowledged for
   more than `ESCALATION_HOURS` on a critical or KEV CVE triggers a
   notification on a dedicated channel (`ESCALATION_SLACK_WEBHOOK_URL`, or
   the main Slack channel otherwise).

On a source's network error, `last_polled_at` **does not advance** - the next
poll retries the same window instead of silently losing CVEs.

The PoC radar (`app/connectors/github_poc.py`) runs on its own schedule,
deliberately outside this main pipeline: it answers a different question
("has a GitHub repo just appeared for this CVE?") rather than "what are this
CVE's official attributes?". A discovery goes through
`app.ingest.record_poc_discovery`, which deduplicates by URL and creates a
minimal CVE record if the CVE isn't known yet - safe, since the upsert logic
above never lets a later real source be blocked by that stub.

## Data sources

| Source | Role | Cadence | File |
|---|---|---|---|
| **NVD API 2.0** | Official CVSS/CPE reference, plus CWE and full affected-CPE lists parsed from the same response | Poller, sliding `lastModified` window (120-day cap enforced by NVD) | `app/connectors/nvd.py` |
| **CISA KEV** | Catalog of **actively exploited** CVEs - the most actionable signal for a SOC | Poller, full catalog re-downloaded and diffed client-side | `app/connectors/cisa_kev.py` |
| **GitHub Advisories** | Open-source ecosystems (npm, PyPI, Go, Maven, ...), often ahead of NVD for these packages | Poller, RFC 5988 pagination (`Link` header) | `app/connectors/github_advisories.py` |
| **OSV.dev** | Precise affected packages/version ranges per ecosystem | On-demand enrichment by CVE alias (no public "recent" feed) | `app/connectors/osv.py` |
| **GitHub PoC radar** | Detects newly created/updated GitHub repos mentioning a current or previous-year CVE | Dedicated poller, ~4 min cadence, 2 fixed queries per cycle regardless of tuning | `app/connectors/github_poc.py` |
| **Exploit-DB** | Populates `has_poc`/`poc_links` from confirmed public exploits | Enrichment: one public CSV export downloaded per cycle, cross-joined against known CVEs | `app/connectors/exploitdb.py` |
| **EPSS (FIRST.org)** | Predictive exploitation probability + percentile, free, no key | Enrichment, full daily CSV cross-joined against known CVEs | `app/enrichment/epss.py` |
| **AlienVault OTX** | Threat context (related pulses, campaign tags) - informational only, never affects alert rules | Enrichment, capped to the cycle's new CVEs (`OTX_API_KEY` optional) | `app/enrichment/otx.py` |
| **MISP** (optional) | Same as OTX, against a self-hosted MISP instance | Enrichment, no-op unless `MISP_URL`/`MISP_API_KEY` are set | `app/enrichment/misp.py` |

Every connector implements `BaseConnector.fetch_since(since) -> list[NormalizedCVE]`
(`app/connectors/base.py`). Adding a source means writing one class and
registering it in `CONNECTOR_REGISTRY` (`app/connectors/__init__.py`) - the
rest of the pipeline (upsert, rules, alerts, API, dashboard) needs no change.
`NormalizedCVE.cve_id` is validated/normalized (strip, uppercase, regex) on
every source, which matters once a source parses free text (a repo name) for
a CVE ID rather than reading it from a structured field. Details and quotas
in `docs/SOURCES_BENCHMARK.md`.

## The rules engine

File: `app/alerting/rules.py`, function `evaluate(cve, watchlist) -> RuleResult`.

A CVE triggers an alert if **at least one** condition holds; every matching
reason is accumulated (a KEV CVE from a watchlisted vendor shows both):

| Rule | Condition | Configurable via |
|---|---|---|
| Active exploitation | `cve.is_kev == True` (present in the CISA KEV catalog) | - (always on) |
| Severity | `cve.cvss_score >= threshold` | `CVSS_ALERT_THRESHOLD` (default `7.0`) |
| Public PoC | `cve.has_poc == True` | - (populated by Exploit-DB and the GitHub PoC radar) |
| Imminent exploitation risk | Public PoC **and** (`is_kev` or `cvss_score >= 9.0`) | - (distinct, higher-severity reason than the plain PoC one) |
| Watchlist - asset | CVE vendor (and product, if given) contains the watchlist entry | `watchlist.yaml` or the dashboard's Watchlist page |
| Watchlist - keyword | Keyword found in vendor/product/description | same |

Every CVSS score change is logged (`CVSSHistory`, `app/models.py`). A
re-evaluation **upward** bypasses alert deduplication: a CVE already
notified on its previous score re-alerts immediately if it's reassessed as
more severe (`app/ingest.py::upsert_cve` / `dispatch_alerts`).

This same function is used in two places:
- **at ingestion**, to decide whether to notify;
- **at read time** (`GET /api/cves`, `GET /api/cves/{id}`), to expose
  `is_flagged`/`flag_reasons` on every CVE - including ones ingested before
  any notification channel was configured. That's what feeds the "Why this
  CVE is flagged" section of the detail panel.

## Alert channels

| Channel | Trigger | Implementation |
|---|---|---|
| Slack | `SLACK_WEBHOOK_URL` set | `app/alerting/slack.py` - formatted message with severity, CVSS, reasons, KEV link |
| Email | `SMTP_HOST` + `SMTP_FROM` + `SMTP_TO` set | `app/alerting/email.py` - standard SMTP, STARTTLS by default, CRLF-sanitized subject line |
| Generic webhook | `GENERIC_WEBHOOK_URL` set | `app/alerting/webhook.py` - structured JSON payload for TheHive/Splunk HEC/QRadar |
| Escalation (Slack) | `ESCALATION_SLACK_WEBHOOK_URL` (or the main Slack channel) | `app/alerting/escalation.py` |

Without any channel configured, ingestion and the dashboard work normally -
only the outbound send is a no-op (logged at `debug`).

## The dashboard

Served as static files by FastAPI (`app/static/`, vanilla HTML/CSS/JS - **no
build step**, no external CDN calls, fully self-contained for air-gapped or
on-premise use).

- **Overview** - stat tiles (tracked CVEs, KEV, critical, pending alerts,
  PoC in the last 24h, imminent exploitation risk, high EPSS, unconfirmed), a 14-day
  CVE trend, severity breakdown, exploitation-risk trend, EPSS score
  distribution, top vendors, and top CWE weakness types. Clicking a severity
  or vendor bar jumps to the CVE page with the filter already applied.
- **CVEs** - full table with free-text search, filters (severity, vendor,
  KEV only, PoC only, minimum EPSS, watchlist only), column sort (ID, CVSS,
  KEV due date, last seen), 50-row pagination ("Load more"), CSV/JSON export
  that respects the active filters. Each row opens the **detail panel**.
- **CVE detail panel** - full description, decoded CVSS vector (attack
  vector, complexity, privileges required, user interaction, scope, C/I/A
  impact in plain language), EPSS score and percentile, CWE weakness type,
  affected CPEs, references grouped by tag (patch/exploit/advisory), known
  PoCs with repo/stars/discovery date, OTX/MISP threat context, CVSS score
  history, KEV section (date added, remediation due date with a colored
  countdown, known ransomware use), copy-ID button, raw JSON link, quick
  "add to watchlist".
- **PoC Radar** - live feed of PoC discoveries across every source, newest
  first, each row showing the CVE's severity/KEV/exploitation-risk badges.
- **Watchlist** - list of entries (vendor/product asset or keyword), add
  form, one-click delete. Editable without a restart, picked up on the next
  rule evaluation.
- **Alerts** - full history with channel, reasons, acknowledgement status
  and an "Escalated" badge; one-click acknowledge; toggle to also show
  already-acknowledged alerts.
- **Settings** - account and API key management, legacy static key field
  (stored only in the browser's `localStorage`), per-source status (last
  successful poll, CVE count, last error), with a manual "Sync" button next
  to EPSS and the PoC radar so you don't have to wait for their schedule.

**Cross-cutting**:
- **Command palette** (`Ctrl/Cmd+K`) - search a CVE by ID/keyword or
  navigate pages/actions, fully keyboard-driven (arrows + Enter, `Esc` to
  close).
- **Notification bell** in the topbar - preview of pending alerts without
  leaving the current page.
- **Language toggle** (FR/EN) in the sidebar - switches every label, chart,
  toast message and date format instantly, persisted across sessions.
- **Theme** light / dark / system, toggle in the sidebar footer, persisted.
- **Badges**: "New" (first seen under 24h ago), "Watchlist" (matches a
  monitored entry), "Unconfirmed" (seen only by the PoC radar, awaiting a
  structured source), "Imminent exploitation", colored KEV due-date badge (red
  = overdue, amber = ≤ 3 days, neutral = on time).
- All data auto-refreshes every 30 seconds.

## API reference

Full interactive documentation (Swagger UI) at `/docs` once the server is
running - the list below is a summary.

<details>
<summary><strong>CVEs</strong> - <code>/api/cves</code></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/cves` | Filterable/sortable/paginated list. Params: `cvss_min`, `severity`, `vendor`, `product`, `is_kev`, `has_poc`, `epss_min`, `q` (free-text ID/description search), `since_days`, `watchlist_only`, `sort` (`last_seen`\|`cvss_score`\|`published_date`\|`cve_id`\|`kev_due_date`), `direction` (`asc`\|`desc`), `limit` (≤500), `offset` |
| `GET` | `/api/cves/{cve_id}` | Full CVE detail: EPSS, CWE, affected CPEs, categorized references, rich PoC list, threat context, CVSS history, `is_flagged`/`flag_reasons`, `unconfirmed` |
| `GET` | `/api/cves/stats` | Dashboard aggregates: totals, KEV, severity breakdown, 14-day trend, top vendors, top CWE, EPSS distribution, exploitation-risk count and trend, unconfirmed count |
| `GET` | `/api/cves/export?format=csv\|json` | Export honoring the same filters as the list; neutralizes CSV formula injection |
| `POST` | `/api/cves/sync-epss` | Triggers EPSS enrichment immediately (auth required, rate-limited) |

</details>

<details>
<summary><strong>PoC radar</strong> - <code>/api/pocs</code></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/pocs/recent` | Most recently discovered PoCs across all sources, joined with the parent CVE's severity/KEV/CVSS |
| `POST` | `/api/pocs/sync-now` | Triggers a GitHub PoC radar cycle immediately (auth required, rate-limited) |

</details>

<details>
<summary><strong>Auth</strong> - <code>/api/auth</code></summary>

| Method | Route | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Creates an account (`email`, `password`). The very first one becomes `admin`; later ones need an admin JWT in `Authorization` |
| `POST` | `/api/auth/login` | Returns a JWT (`access_token`, `expires_in` in seconds). Rate-limited (10 attempts/5min per IP) |
| `GET` | `/api/auth/me` | Profile of the authenticated user (JWT required) |

</details>

<details>
<summary><strong>API keys</strong> - <code>/api/api-keys</code> (JWT only, not API-key-authenticable - a key shouldn't be able to regenerate itself)</summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/api-keys` | Lists the authenticated user's keys (never the plaintext value) |
| `POST` | `/api/api-keys` | Creates a key (`name`, optional `scopes`, optional `expires_days`). The plaintext value is returned only once, at creation |
| `DELETE` | `/api/api-keys/{id}` | Revokes a key (soft delete, traceable) |

</details>

<details>
<summary><strong>Watchlist</strong> - <code>/api/watchlist</code> (write protected: JWT or API key)</summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/watchlist` | Lists entries |
| `POST` | `/api/watchlist` | Adds an entry (`vendor`, `product`, `keyword`, `note` - at least one of the first three) |
| `DELETE` | `/api/watchlist/{id}` | Deletes an entry |

</details>

<details>
<summary><strong>Alerts</strong> - <code>/api/alerts</code> (write protected: JWT or API key)</summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/alerts` | History, filterable by `acknowledged` |
| `POST` | `/api/alerts/{id}/ack` | Acknowledges an alert |
| `POST` | `/api/alerts/poll-now` | Triggers an immediate ingestion cycle (30s cooldown after the previous cycle ends) |

</details>

<details>
<summary><strong>Status</strong> - <code>/api/status</code></summary>

| Method | Route | Description |
|---|---|---|
| `GET` | `/api/status` | Last poll (timestamp, CVE count, error if any) for every poller and enricher |

</details>

## Data model

File: `app/models.py` (SQLAlchemy).

- **`CVE`** - primary key `cve_id`. Notable fields: `cvss_score`/`cvss_vector`/`severity`,
  `vendor`/`product`, `is_kev`/`kev_date_added`/`kev_due_date`/`kev_ransomware_use`,
  `has_poc`/`poc_links`, `epss_score`/`epss_percentile`, `cwe_ids`, `affected_cpes`,
  `references_meta` (references tagged patch/exploit/advisory), `sources`
  (which connectors have seen this CVE - also drives the "unconfirmed"
  badge), `threat_context` (aggregated OTX/MISP context, informational only),
  `first_seen`/`last_seen`, `raw` (last raw payload received, for audit/debug).
- **`PocLink`** - one row per discovered PoC (`cve_id`, `url` unique,
  `source`, `repo_full_name`, `stars`, `discovered_at`) - powers the PoC
  Radar feed's "most recent first" ordering, kept separate from the legacy
  `CVE.poc_links` list so nothing about Exploit-DB's existing behavior had
  to change.
- **`WatchlistEntry`** - `vendor`/`product`/`keyword`/`note`, all optional
  but at least one required.
- **`AlertLog`** - `cve_id`, `channel`, `reasons`, `sent_at`,
  `acknowledged`/`acknowledged_at`, `escalated`.
- **`SourceState`** - one record per source: `last_polled_at`,
  `last_success_count`, `last_error`. Drives delta-only fetching and the
  Settings page.
- **`CVSSHistory`** - `cve_id`, `cvss_score`, `severity`, `recorded_at`: one
  record per score change, used to detect an upward re-evaluation
  (re-alert).
- **`User`** - `email`, `hashed_password` (bcrypt), `role` (`admin`/`viewer`),
  `is_active`.
- **`APIKey`** - `name`, `prefix` (displayable), `hashed_key` (SHA-256, never
  the plaintext value), `owner_id`, `scopes`, `expires_at`/`revoked_at`.

There's no Alembic in this project. Schema changes are additive-only,
applied by `app/database.py::init_db()` at startup: it creates any missing
table, then adds any missing column on existing tables (and backfills the
model's default for list/dict-typed columns, since a bare `ALTER TABLE ADD
COLUMN` otherwise leaves existing rows at `NULL`). That's a deliberate
trade-off for a project this size - no down-migrations, no column-type
changes - worth replacing with Alembic if the schema keeps growing.

## Security

Covered in this repository:

- **No external data is injected as-is** into the dashboard's HTML (systematic client-side escaping, plus scheme-restricted `href`s so a `javascript:` URL in a reference can't execute) nor into CSV exports (Excel/Sheets formula-injection neutralized).
- **Two authentication mechanisms** on every write endpoint (watchlist, alert acknowledgement, manual poll, account/key management):
  - **Accounts + JWT** (`POST /api/auth/register` then `/login`) - the first account created becomes `admin`; later ones must be created by an admin. Bcrypt-hashed passwords, signed JWTs (`JWT_SECRET_KEY`, `JWT_EXPIRE_MINUTES` expiry).
  - **API keys** (`POST /api/api-keys`, JWT required to create/list/revoke) - SHA-256 hashed at rest (never the plaintext), individually revocable and traceable (`last_used_at`).
  - **Legacy static key** (`API_KEY` in `.env`), kept for backward compatibility, deprecated: neither individually traceable nor revocable.
  - If none of this is configured (no account/key in the database, no `API_KEY`), write endpoints stay open - dev/local mode only, a warning is logged at startup.
- **Login is rate-limited** (`app/rate_limit.py`, in-memory, 10 attempts/5min per IP) against brute-force, and the password check **always runs** (against a dummy hash if the email doesn't exist), so response timing can't be used to enumerate accounts.
- **CORS closed by default** (the dashboard is served same-origin; no external origin is allowed unless explicitly added).
- **Hardened response headers** (CSP with `frame-ancestors 'none'`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security`) on every response outside the Swagger docs (which need CDN-hosted assets).
- **Manual-poll cooldown** (measured from the end of the previous cycle, not its start) so a repeated call can't hammer upstream APIs into a quota block, and a shared lock (`app/ingest.py::acquire_poll_slot`) prevents a concurrent call - including the scheduled job - from overlapping an in-progress cycle.
- **Strict input validation**: `cve_id` normalized and regex-validated both in connectors (`NormalizedCVE`) and on the routes - the same validator protects against duplicate CVE rows from any future free-text source; watchlist field lengths bounded (Pydantic `StringConstraints`).
- **CRLF-safe email headers** (`app/alerting/email.py::_header_safe`): a CVE field containing a newline can't inject an extra header (e.g. `Bcc:`) into an outbound SMTP alert.
- **Parameterized database queries** (SQLAlchemy ORM) - no string-concatenated SQL.
- **Non-root container** (Dockerfile) and **no unnecessary exposed port** (Redis, reserved for later, is no longer published to the host in `docker-compose.yml` since nothing consumes it yet).

Not covered, and left to you before exposing this beyond a local machine:

- **No authentication on read endpoints** (dashboard, API `GET`s) - accounts/API keys only protect writes. Restrict network access (VPN, an authenticating reverse proxy, or an internal network) if the service is exposed beyond `localhost`.
- **`JWT_SECRET_KEY`** should be set explicitly in production: if unset, a random key is generated in memory at startup (tokens are invalidated on every restart, and this breaks a multi-instance deployment).
- Secrets (`SLACK_WEBHOOK_URL`, `SMTP_PASSWORD`, `API_KEY`, `JWT_SECRET_KEY`, ...) live in environment variables: don't commit them, use a secret manager in production.

## Configuration reference

Everything is configured through `.env` (see the fully commented
`.env.example`). Full variable reference (`Settings` class in `app/config.py`):

<details>
<summary>See all variables</summary>

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./vulnaegis.db` | SQLAlchemy connection string. `postgresql://user:pass@host:5432/db` in production |
| `POLL_INTERVAL_MINUTES` | `5` | Main source-polling frequency |
| `GITHUB_POC_INTERVAL_MINUTES` | `4` | PoC radar cadence, deliberately decoupled from the main poll |
| `EPSS_CHECK_INTERVAL_MINUTES` | `1440` | EPSS enrichment frequency (the dataset is republished once a day) |
| `ESCALATION_CHECK_INTERVAL_MINUTES` | `60` | How often pending escalations are checked |
| `ESCALATION_HOURS` | `4` | Delay before escalating an unacknowledged critical/KEV alert |
| `NVD_API_KEY` | _(empty)_ | Optional, raises the NVD quota from 5 to 50 req/30s |
| `GITHUB_TOKEN` | _(empty)_ | Optional, raises the GitHub quota (Advisories and PoC radar search) |
| `CVSS_ALERT_THRESHOLD` | `7.0` | CVSS score that triggers an alert |
| `WATCHLIST_PATH` | `watchlist.yaml` | Initial watchlist seed file |
| `ALERT_DEDUPE_HOURS` | `24` | Anti-duplicate window per (CVE, channel) |
| `SLACK_WEBHOOK_URL` | _(empty)_ | Main Slack channel |
| `ESCALATION_SLACK_WEBHOOK_URL` | _(empty)_ | Dedicated escalation Slack channel (falls back to the main one) |
| `GENERIC_WEBHOOK_URL` | _(empty)_ | Generic JSON webhook (SIEM/SOAR) |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TO` / `SMTP_USE_TLS` | _(empty)_ / `587` / ... / `true` | Email configuration |
| `API_KEY` | _(empty)_ | Legacy: protects write endpoints with a static key. Prefer an account + API key |
| `API_CORS_ORIGINS` | `[]` | Allowed cross-origin origins (empty = none, the dashboard is same-origin) |
| `JWT_SECRET_KEY` | _(randomly generated)_ | JWT signing secret - **set explicitly in production** |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | Validity of a token issued by `/api/auth/login` |
| `OTX_API_KEY` | _(empty)_ | Optional, AlienVault OTX (public endpoint, the key only raises the quota) |
| `MISP_URL` / `MISP_API_KEY` | _(empty)_ | Self-hosted MISP instance - both required together, otherwise this enrichment is skipped |

</details>

`watchlist.yaml` defines the seed entries (loaded into the database only on
first startup):

```yaml
- vendor: microsoft
  product: windows
  note: "Corporate workstations"
- keyword: log4j
```

Editable afterward, live, through the dashboard (Watchlist page) or the API,
without a restart.

## Tests

```bash
pytest tests/ -v
```

94 tests covering the rules engine, every connector and enrichment source
(NVD, CISA KEV, GitHub Advisories, GitHub PoC radar, Exploit-DB, EPSS,
OTX/MISP), the ingestion pipeline (upsert merging, deduplication, stub-CVE
creation), the additive-migration helper, every route (CVEs, PoC radar,
watchlist, alerts, status, auth, API keys), the rate limiter, and the
security headers.

## Deployment

`docker-compose.yml` provides three services: `app` (built locally),
`postgres` (persistence), `redis` (reserved for the scaling path described
in `docs/SCALING.md` - API cache and task broker - not consumed by the
current code, and not published to the host since nothing connects to it
yet). The `Dockerfile` builds a minimal `python:3.12-slim` image and drops
to a non-root user before running.

For a shared deployment (beyond `localhost`):
1. Generate and set `API_KEY`, or create a real account instead.
2. Restrict network access (VPN, an authenticating reverse proxy, or an
   internal network).
3. Point `DATABASE_URL` at Postgres (already the default in
   `docker-compose.yml`).
4. Set `JWT_SECRET_KEY` explicitly.
5. Configure at least one alert channel (`SLACK_WEBHOOK_URL` typically).
6. Override `POSTGRES_PASSWORD` - the default in `docker-compose.yml` is
   meant for zero-config local use only and is visible in that file.

## Code examples

<details>
<summary>Fetch recent CVEs from NVD and filter CVSS ≥ 7.0</summary>

```python
import requests
from datetime import datetime, timedelta, timezone

resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={
        "lastModStartDate": (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "lastModEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "resultsPerPage": 200,
    },
    headers={"Accept": "application/json"},  # + "apiKey": "<your key>" if you have one
    timeout=30,
)
resp.raise_for_status()

high_severity = [
    (item["cve"]["id"], item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"])
    for item in resp.json().get("vulnerabilities", [])
    if item["cve"].get("metrics", {}).get("cvssMetricV31")
    and item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] >= 7.0
]
```

Reusable equivalent in this project: `app.connectors.nvd.NvdConnector().fetch_since(since)`.
</details>

<details>
<summary>Send a Slack alert</summary>

```python
import requests

def send_slack_alert(webhook_url: str, cve_id: str, score: float, reasons: list[str]) -> None:
    text = f"*{cve_id}* - CVSS {score}\nReasons: {', '.join(reasons)}"
    requests.post(webhook_url, json={"text": text}, timeout=10).raise_for_status()
```

Equivalent in this project: `app.alerting.slack.send_slack_alert`.
</details>

<details>
<summary>Query the API for critical CVEs affecting a watchlisted vendor</summary>

```bash
curl "http://localhost:8000/api/cves?cvss_min=7.0&is_kev=true&vendor=cisco&sort=kev_due_date&direction=asc"
```
</details>

<details>
<summary>Query for CVEs with a fresh PoC and a high EPSS score</summary>

```bash
curl "http://localhost:8000/api/cves?has_poc=true&epss_min=0.5&sort=last_seen&direction=desc"
```
</details>

## Project layout

```
app/
  connectors/          # one module per CVE source
    base.py               # BaseConnector interface + CONNECTOR_REGISTRY
    nvd.py                 # NVD API 2.0 (+ CWE, CPE, tagged references)
    cisa_kev.py            # CISA KEV
    github_advisories.py   # GitHub Security Advisories
    github_poc.py          # real-time PoC radar (GitHub Search)
    osv.py                  # OSV.dev (on-demand enrichment)
    exploitdb.py            # Exploit-DB CSV cross-join
  enrichment/           # informational, never affects alert rules
    otx.py / misp.py         # threat context
    epss.py                   # exploitation probability
  alerting/             # rules, dedup, escalation, channels
    rules.py                # rules engine (evaluate)
    dedupe.py               # anti-duplicate by (CVE, channel)
    escalation.py           # escalates unacknowledged alerts
    slack.py / email.py / webhook.py
  api/                  # FastAPI routes
    routes_cves.py          # list, detail, stats, export, EPSS sync
    routes_poc.py            # PoC radar feed, manual sync
    routes_watchlist.py     # watchlist CRUD
    routes_alerts.py        # history, acknowledgement, manual poll
    routes_status.py        # per-source status
    routes_auth.py / routes_api_keys.py
  static/               # dashboard (vanilla HTML/CSS/JS, no build)
    index.html / style.css / dashboard.js
  rate_limit.py         # in-memory rate limiter (login, manual syncs)
  security.py           # API-key/JWT enforcement on write endpoints
  ingest.py             # pipeline: poll -> upsert -> rules -> alerts
  scheduler.py          # APScheduler (poll, PoC radar, EPSS, escalation)
  models.py             # SQLAlchemy ORM (CVE, PocLink, WatchlistEntry, ...)
  schemas.py            # NormalizedCVE (pivot format) + API Pydantic schemas
  config.py             # centralized configuration (.env)
  database.py           # engine + additive migration helper
  watchlist_loader.py   # initial watchlist seed from watchlist.yaml
docs/                  # architecture, roadmap, source benchmark, scaling
tests/                  # unit tests (rules, connectors, ingest, routes, security)
watchlist.yaml          # seed watchlist
docker-compose.yml      # app + Postgres + Redis
```

## Further reading

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - diagrams, technical choices, target architecture at scale
- [`docs/ROADMAP.md`](docs/ROADMAP.md) - what's shipped, what's next
- [`docs/SOURCES_BENCHMARK.md`](docs/SOURCES_BENCHMARK.md) - detailed comparison of CVE sources (latency, completeness, reliability, cost)
- [`docs/SCALING.md`](docs/SCALING.md) - handling 10k req/min, adding a source without a rewrite
