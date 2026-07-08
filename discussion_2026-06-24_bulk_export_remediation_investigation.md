# Discussion: Bulk Export Remediation Investigation

**Date:** 2026-06-24

---

## Issue

Bulk Export API remediation export returns 0 rows despite confirmed remediations visible in the InsightVM console UI and via the console API v3.

## Evidence

**alma10 (192.168.1.173):**
- Agent-based asset (agentId: 9af75c7cdbf917bfa73d04f078509954)
- Console asset ID: 120
- 47 scans in history
- Clear remediation activity visible:

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
2026-06-10  1347    42     11    25    6   ← 20 remediated
2026-06-11  1349    43     11    26    6
2026-06-12  1351    48     12    29    7
2026-06-14  1356    23     7     14    2   ← 25 remediated
2026-06-15  1358    24     7     15    2
2026-06-16  1361    42     13    27    2   ← new content/vulns
2026-06-17  1364    23     7     14    2   ← 19 remediated
2026-06-18  1366    22     8     12    2
2026-06-19  1369    23     8     13    2
2026-06-21  1372    26     8     15    3
2026-06-22  1374    29     8     18    3
2026-06-23  1376    39     14    23    2
2026-06-24  1379    31     11    18    2   ← 8 remediated
```

## What Was Tried

| Method | Result |
|--------|--------|
| Bulk Export API (remediation type, Mar 1 - Jun 24) | 0 rows returned |
| Cloud API v4 (per-asset vuln comparison) | 404 — asset ID format not recognized |
| Console API v3 `/api/3/assets/120/vulnerabilities` | Shows 2 current vulns, no historical data |
| Console API v3 `/api/3/assets/120` + `/api/3/scans/{id}` | ✅ Shows scan history with vuln count changes proving remediation |

## Conclusions

1. **Bulk Export remediation type** appears to require something beyond just "vuln disappeared between scans" — possibly remediation projects or a specific platform-level tracking state. Documentation doesn't clarify this.

2. **Cloud API v4** uses a different asset ID format than the bulk export. The composite ID (`orgId-default-asset-N`) returns 404. No discovery endpoint exists to find the correct v4 ID.

3. **Console API v3** is the only reliable programmatic source for remediation evidence, but only provides scan-level summary counts — not per-vuln remediation dates.

## Recommended Support Case

**Subject:** Bulk Export Remediation API returns 0 rows despite confirmed remediations

**Include:**
- Asset: alma10, 192.168.1.173, agent-based (agentId: 9af75c7cdbf917bfa73d04f078509954)
- Export ID: NWZiMDJmN2UtZjY3Ni00MGIzLWJhOWYtMTIxZmE5ZTFiNGU3
- Date range: 2026-03-01 to 2026-06-24
- Result: SUCCEEDED, 0 rows
- Evidence: Console API shows 47 scans with vuln count decreasing (remediations occurring)
- Question: What conditions must be met for remediation events to appear in the bulk export?

## Workaround Options

1. Console SQL report using `baselineComparison()` — gives last-two-scan remediation data
2. Console API v3 scan-by-scan comparison (what we did above) — programmatic but labor-intensive
3. Daily BOD 26-04 report snapshots — calculates new/remediated delta from bulk export vuln data going forward
