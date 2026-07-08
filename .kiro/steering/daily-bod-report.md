---
inclusion: auto
---

# Daily BOD 26-04 Report Procedure

When the user asks to "run daily bulk export and BOD report" (or similar), follow this procedure:

1. **Start vulnerability bulk export** and wait for completion
2. **Download and load** the export data
3. **Query ALL findings with CVEs** — use: `SELECT v.assetId, a.hostName, a.ip, v.title, v.severity, v.cves, v.firstFoundTimestamp FROM vulnerabilities v JOIN assets a ON v.assetId = a.assetId WHERE array_length(v.cves) > 0`
4. **Run bod2604_compliance_report** with the FULL set of CVE findings (never a subset)
5. **Write the HTML report to disk** as `bod2604_compliance_report_YYYY-MM-DD.html`
6. **Update the trend report** at `bod2604_trend_report.html`

Asset exposure map (all internal): asset-19=False, asset-13=False, asset-61=False, asset-120=False, asset-36=False

Always include every finding — do not subset to avoid NVD timeouts. SSVC caching handles performance.
