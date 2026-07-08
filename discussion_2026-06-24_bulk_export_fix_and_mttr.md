# Discussion: Bulk Export Remediation Fix & MTTR Results

**Date:** 2026-06-24  
**Continuation of:** discussion_2026-06-24_bulk_export_remediation_investigation.md

---

## Bug Found & Fixed

**Root cause:** The Rapid7 Bulk Export API returns prefix `"vulnerability_remediation/ivm"` but the MCP's `PREFIX_TABLE_MAP` expected `"vulnerability_remediation"`. The `/ivm` suffix caused a silent skip, loading 0 rows.

**Fix:** Added `_normalize_prefix()` helper to `src/duckdb_loader.py` that strips sub-path suffixes before lookup.

**PR:** https://github.com/rapid7/rapid7-bulk-export-mcp/pull/28  
**Fork:** spassino-r7/rapid7-bulk-export-mcp, branch `fix/remediation-prefix-routing`

---

## MTTR Results (After Fix)

255 remediation records loaded (Mar 1 – Jun 24, 2026):

| Severity | Remediated | Avg Days | Min | Max |
|----------|-----------|----------|-----|-----|
| Critical | 4 | 7.6 | 3.0 | 12.1 |
| High | 150 | 7.0 | 0.1 | 34.0 |
| Medium | 82 | 8.9 | 0.3 | 179.9 |
| Low | 17 | 49.9 | 0.1 | 111.0 |

---

## Console API v3 Findings

- SSH tunnel required to reach console (192.168.1.162:3790 via localhost:3790)
- Credentials: Keychain `insightvm-console` / `api-user` (use single quotes for ! in password)
- alma10 console asset ID: 120
- 47 scans in history showing clear remediation activity

---

## API Key Configuration

| Key | Stored In | Service/Account | Used For |
|-----|-----------|-----------------|----------|
| Insight Platform (user) | Keychain | insight-platform / api-key | v4 integration API |
| Insight Platform (org) | Keychain | insight-platform-org / api-key | GraphQL export endpoint |
| Rapid7 Bulk Export | MCP env var | RAPID7_API_KEY in mcp.json | Bulk export MCP (region: us3) |
| InsightVM Console | Keychain | insightvm-console / api-user | Console API v3 (format: user:pass) |

---

## Outstanding Items

1. **Add post-download validation** to bulk export process — verify each parquet file has rows after download, warn if empty
2. **v4 API asset ID mismatch** — still unresolved. The bulk export composite ID doesn't work with the cloud integration API
3. **Open support case** about the v4 API asset ID format question

---

## Other Topics Covered This Session

- InsightVM remediation framework document: sections 1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 3.1, 4.2, 4.3, 6.1, 6.2 reviewed and updated
- Integration section removed (later-phase activity)
- Ransomware category: not native in InsightVM, use CISA KEV `knownRansomwareCampaignUse` field
- Console SQL for MTTR: limited to last-two-scan comparison
- Office LTSC vs non-LTSC detection: both InsightVM and Tenable struggle, Tenable has slight edge with credentialed scans
- InsightVM date fields: published_date, modified_date, first_found defined
- BOD 26-04 reports generated with new HTML format and trending
- SSVC caching added (7-day TTL) to avoid NVD rate limiting
- Long-chat-reminder hook removed (was adding tokens every message)
