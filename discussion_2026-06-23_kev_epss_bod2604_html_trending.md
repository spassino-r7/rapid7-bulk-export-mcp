# Discussion: KEV/EPSS/BOD 26-04 — HTML Reports & Trending

**Date:** 2026-06-23  
**Repo:** `spassino-r7/metasploit-mcp-server` (metasploit-exploit-mapper)  
**Continues from:** `discussion_2026-06-22_kev_epss_bod2604_metasploit_mcp.md`

---

## What Was Built (This Session)

### 1. VulnCheck KEV Integration Fixed
- Discovered the `/v3/backup/vulncheck-kev` endpoint returns a **signed S3 URL to a ZIP file**, not inline JSON
- Updated `enrichment.py` to download ZIP → extract JSON → load 4,974 entries into DuckDB
- VulnCheck token stored in macOS Keychain: `security add-generic-password -s "vulncheck-api" -a "api-token" -w "TOKEN"`

### 2. BOD 26-04 Compliance Reporting
- **`src/bod2604.py`** — full implementation of CISA BOD 26-04 Table 1 remediation timeline logic
- Four decision variables: In KEV, Publicly Exposed, Automatable, Technical Impact
- SSVC data fetched from NVD API (Vulnrichment program)
- Fallback heuristics when SSVC unavailable (CVSS attack vector/complexity → automatable, CIA impact → technical impact)

### 3. Report Formats (3 options)
- **HTML** (now default) — Chart.js bar chart for timeline distribution, summary cards, full findings table
- **Markdown** — executive summary + condensed all-findings table + detailed per-CVE sections
- **JSON** — structured data for programmatic use

### 4. Historical Trending
- `ReportHistory` class auto-saves every report run to DuckDB
- Tables: `bod2604_report_history` (summary) + `bod2604_finding_history` (per-finding)
- **`bod2604_trend`** tool — HTML output with:
  - Stacked bar chart: timeline bucket distribution over time
  - Line chart: overdue count trend
  - Snapshot history table

### 5. Condensed All-Findings Table
- Added between executive summary and detailed findings
- One row per CVE: `| CVE | Host | Sev | KEV | Auto | Impact | Timeline | Due | EPSS | Overdue |`

---

## MCP Tools (11 total now)

| Tool | Default Format | Description |
|------|----------------|-------------|
| `match_exploits_by_cve` | JSON | Now includes cisa_kev + vulncheck_kev + epss |
| `match_exploits_by_service` | JSON | Service-based module search |
| `search_modules` | JSON | General module search |
| `get_module_detail` | JSON | Full module metadata |
| `refresh_module_cache` | JSON | Refresh Metasploit module cache |
| `get_cache_status` | JSON | Cache statistics |
| `enrich_cves_with_kev_epss` | JSON | Batch CVE enrichment |
| `refresh_kev_catalog` | JSON | Force-refresh CISA + VulnCheck KEV |
| `bod2604_compliance_report` | **HTML** | Full BOD 26-04 report with chart |
| `bod2604_assess_cve` | JSON | Single CVE BOD 26-04 classification |
| `bod2604_trend` | **HTML** | Trending with stacked bar + line charts |

---

## Commits Pushed (This Session)

1. `feat: add CISA KEV, VulnCheck KEV, EPSS enrichment and BOD 26-04 reporting` (PR #1, merged)
2. `feat: add BOD 26-04 report history for trending`
3. `feat: add condensed all-findings table to BOD 26-04 markdown report`
4. `feat: HTML report format with Chart.js bar graphs, default to HTML`

---

## Environment Findings

- **19 vulnerabilities** across 4 assets (ivmcon, mspro, container, alma10)
- **0 overdue**, 0 forensic triage required
- 2 findings at 180-day timeline (libxslt memory corruption + Java AWT — both have total technical impact)
- 17 findings at "Fix on system upgrade"
- **alma10 CVE-2025-61984**: False positive — installed `openssh-9.9p1-23` is already patched (fix was in `-12`)
- No CVEs in CISA or VulnCheck KEV for this environment

---

## Files on Disk

| File | Purpose |
|------|---------|
| `bod2604_compliance_report_2026-06-23.html` | Today's HTML report with chart |
| `bod2604_compliance_report_2026-06-23.md` | Today's markdown report |
| `bod2604_compliance_report_2026-06-22.md` | Yesterday's test report |
| `bod2604_trend_report.html` | Trending HTML with bar/line charts (4 snapshots) |

---

## Follow-up Ideas

- Add unit tests for `enrichment.py` and `bod2604.py`
- Automate daily report generation (cron/hook)
- Wire asset exposure tagging from InsightVM site data (internet-facing sites → publicly_exposed=True)
- Add exception handling for false positives (like alma10 OpenSSH) in the report
- Export trend data to CSV for Power BI ingestion
