# Discussion: CISA KEV, VulnCheck KEV, EPSS & BOD 26-04 — Metasploit MCP Server

**Date:** 2026-06-22  
**Repo:** `spassino-r7/metasploit-mcp-server` (metasploit-exploit-mapper)  
**PR:** #1 (merged to main)

---

## What Was Built

Added threat intelligence enrichment and CISA BOD 26-04 compliance reporting to the Metasploit Exploit Mapper MCP server.

### New Files

| File | Purpose |
|------|---------|
| `src/enrichment.py` | CISA KEV, VulnCheck KEV (ZIP backup API), FIRST EPSS — fetch, cache in DuckDB (24h TTL) |
| `src/bod2604.py` | BOD 26-04 Table 1 remediation timeline logic + markdown report generator |

### Modified Files

| File | Changes |
|------|---------|
| `src/server.py` | 4 new tools, enrichment wired into `match_exploits_by_cve` |
| `src/config.py` | VulnCheck API token resolution (env var + macOS Keychain) |
| `.env.example` | Documents `VULNCHECK_API_TOKEN` |

### New MCP Tools (10 total now)

| Tool | Description |
|------|-------------|
| `enrich_cves_with_kev_epss` | Batch enrichment — CISA KEV + VulnCheck KEV + EPSS |
| `refresh_kev_catalog` | Force-refresh both CISA and VulnCheck KEV catalogs |
| `bod2604_compliance_report` | Full BOD 26-04 report (markdown default, `format="json"` option) |
| `bod2604_assess_cve` | Single-CVE BOD 26-04 classification with all intelligence |

### Enhanced Existing Tools

- `match_exploits_by_cve` now auto-appends `cisa_kev`, `vulncheck_kev`, and `epss` to each CVE result

---

## Key Design Decisions

1. **VulnCheck backup API returns a ZIP** — not inline JSON. The `/v3/backup/vulncheck-kev` endpoint provides a signed S3 URL to a ZIP containing the full catalog JSON. We download, extract, and load into DuckDB.

2. **VulnCheck token stored in macOS Keychain** — same pattern as Metasploit Pro token:
   ```
   security add-generic-password -s "vulncheck-api" -a "api-token" -w "TOKEN"
   ```

3. **BOD 26-04 Table 1 logic** uses 4 decision variables:
   - In KEV (CISA catalog)
   - Publicly Exposed (user-provided per asset)
   - Automatable (from CISA Vulnrichment/NVD SSVC data)
   - Technical Impact: total vs partial (from CVSS v3 if SSVC unavailable)

4. **SSVC fallback heuristics** — for CVEs without Vulnrichment data:
   - Network + Low complexity + No user interaction → automatable=True
   - Confidentiality HIGH or Integrity HIGH → technical_impact=total

5. **VulnCheck KEV is ~3.7x broader than CISA** — 4,974 entries vs ~1,300. Detects exploitation earlier (e.g., Log4Shell: VulnCheck Dec 6 vs CISA Dec 10, 2021).

---

## Current Environment State

- **Bulk export loaded:** 28 vuln findings across 9 assets (35 total assets)
- **Findings on mspro (192.168.1.244):**
  - CVE-2026-34477 (Log4j TLS hostname bypass) — Severe, EPSS 0.004
  - CVE-2026-34480 (Log4j XmlLayout log loss) — Critical, EPSS 0.009
- **BOD 26-04 status:** Both are "Fix on system upgrade" (not in KEV, not exposed, low EPSS)
- **No CVE-2021-44228** (Log4Shell) in environment — previously patched

---

## Data Sources & URLs

| Source | URL | Auth |
|--------|-----|------|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None |
| VulnCheck KEV | `https://api.vulncheck.com/v3/backup/vulncheck-kev` | Bearer token (free Community) |
| FIRST EPSS | `https://api.first.org/data/v1/epss` | None |
| NVD/SSVC | `https://services.nvd.nist.gov/rest/json/cves/2.0` | None |

---

## Tests

- 35 existing unit tests all pass
- Live integration tests verified: CISA KEV, VulnCheck KEV (4,974 entries), EPSS, BOD 26-04 report generation
- No test file added for `enrichment.py` or `bod2604.py` yet (could be a follow-up)

---

## Follow-up Ideas

- Add `test_enrichment.py` with mocked HTTP for KEV/EPSS/VulnCheck
- Add `test_bod2604.py` for timeline logic unit tests
- Wire BOD 26-04 report into the bulk export MCP so it auto-generates after each export
- Add asset exposure tagging from InsightVM site/tag data
- Consider NVD rate limiting (6 req/sec without API key) for large CVE batches
