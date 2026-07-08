# Discussion: Bulk Export Remediation Gap + Console API v3 Investigation

**Date:** 2026-06-24

---

## Issue

Bulk Export API remediation export returns 0 rows despite confirmed remediations visible in the InsightVM UI and provable via console API v3.

## Evidence

### Bulk Export Remediation — 0 Rows

- Export type: `remediation`
- Date range: 2026-03-01 to 2026-06-24
- Export ID: `NWZiMDJmN2UtZjY3Ni00MGIzLWJhOWYtMTIxZmE5ZTFiNGU3`
- Status: SUCCEEDED
- Rows loaded: **0**
- Asset tested: alma10 (192.168.1.173), Insight Agent, cloud-connected

### Cloud API v4 — Asset ID Mismatch

- Bulk export asset ID: `8bd28bcb-2c23-420d-b85f-8eee8e07fac2-default-asset-120`
- v4 API returns 404 for this ID format
- No asset search/list endpoint available on v4 to discover correct ID
- The v4 integration API uses a different ID system than the bulk export

### Console API v3 — Confirms Remediations

Connected via SSH tunnel to `localhost:3790`. Asset alma10 has console ID `120`.

**Scan history showing vuln count changes (last 20 scans):**

```
Date        ScanID  Total  Crit  Sev   Mod
--------------------------------------------------
2026-06-02  1331    53     17    32    4
2026-06-03  1333    53     17    32    4
2026-06-04  1336    56     17    35    4
2026-06-05  1338    59     19    35    5
2026-06-07  1341    59     20    33    6
2026-06-08  1343    62     20    36    6
2026-06-09  1345    62     18    38    6
2026-06-10  1347    42     11    25    6    ← 20 remediated
2026-06-11  1349    43     11    26    6
2026-06-12  1351    48     12    29    7
2026-06-14  1356    23     7     14    2    ← 25 remediated
2026-06-15  1358    24     7     15    2
2026-06-16  1361    42     13    27    2    ← content update (new vulns)
2026-06-17  1364    23     7     14    2    ← 19 remediated
2026-06-18  1366    22     8     12    2
2026-06-19  1369    23     8     13    2
2026-06-21  1372    26     8     15    3
2026-06-22  1374    29     8     18    3
2026-06-23  1376    39     14    23    2
2026-06-24  1379    31     11    18    2    ← 8 remediated
```

**Key remediation events:**
- Jun 9→10: 62→42 (20 vulns remediated)
- Jun 12→14: 48→23 (25 vulns remediated)
- Jun 16→17: 42→23 (19 vulns remediated)
- Jun 23→24: 39→31 (8 vulns remediated)

## Support Case Content

**Subject:** Bulk Export Remediation API returns 0 rows despite confirmed remediations

**Details to include:**
- Asset: alma10, 192.168.1.173, Insight Agent (agent ID: 9af75c7cdbf917bfa73d04f078509954)
- Console API v3 confirms 47 scans with vuln count changes showing clear remediation events
- Bulk export ID: `NWZiMDJmN2UtZjY3Ni00MGIzLWJhOWYtMTIxZmE5ZTFiNGU3`
- Date range: 2026-03-01 to 2026-06-24
- Result: SUCCEEDED, 0 rows
- Question: What conditions must be met for remediation events to appear in the bulk export?
- Secondary question: Why does the v4 integration API return 404 for asset IDs from the bulk export?

## API Access Notes

- Console API v3: `https://localhost:3790/api/3/` (via SSH tunnel)
- Auth: Basic auth, credentials in Keychain (`insightvm-console` / `api-user`)
- Console user: steve
- Insight Platform API key in Keychain (`insight-platform` / `api-key`)

## Limitations Discovered

| API | Can get remediation data? | Notes |
|-----|--------------------------|-------|
| Bulk Export (remediation) | ❌ Returns 0 rows | Unknown prerequisite |
| Cloud API v4 | ❌ 404 on asset ID | ID format mismatch |
| Console API v3 | ⚠️ Partial — scan summaries only | Shows vuln count per scan but not which specific vulns were remediated |
| Console SQL (baselineComparison) | ✅ Last two scans only | Can identify specific vulns remediated between last two scans |
| Data Warehouse | ✅ Full history | Requires warehouse connection (password file) |

## Next Steps

1. Open Rapid7 support case with evidence above
2. Consider building a daily script using console API v3 to capture scan-over-scan deltas and store locally for MTTR calculation
3. Reconnect data warehouse for full historical remediation data
