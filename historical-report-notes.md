Now I have the correct schema. Here are the corrected queries using the actual InsightVM console SQL schema:

**1. Scan history with risk over time (Dec 2025 – June 2026)**

```sql
SELECT
    ds.name AS site_name,
    dsc.finished AS scan_finished,
    fs.assets AS asset_count,
    fs.vulnerabilities AS vuln_count,
    fs.riskscore AS risk_score
FROM
    dim_site ds
    JOIN dim_site_scan dss USING (site_id)
    JOIN dim_scan dsc USING (scan_id)
    JOIN fact_scan fs USING (scan_id)
WHERE
    dsc.finished BETWEEN '2025-12-01' AND '2026-07-01'
ORDER BY
    dsc.finished DESC
```

**2. Vulnerability count by severity per asset (current state, scoped to asset group)**

```sql
SELECT
    da.ip_address,
    da.host_name,
    fa.critical_vulnerabilities,
    fa.severe_vulnerabilities,
    fa.moderate_vulnerabilities,
    fa.vulnerabilities AS total_vulnerabilities,
    fa.riskscore
FROM
    fact_asset fa
    JOIN dim_asset da USING (asset_id)
    JOIN dim_asset_group_asset daga USING (asset_id)
    JOIN dim_asset_group dag USING (asset_group_id)
WHERE
    dag.name = 'YOUR_ASSET_GROUP_NAME'
ORDER BY
    fa.riskscore DESC
```

**3. Assets ordered by risk for the 54 assets**

```sql
SELECT
    da.asset_id,
    da.host_name,
    da.ip_address,
    fa.riskscore,
    fa.vulnerabilities AS total_vulns,
    fa.malware_kits AS malware_count,
    fa.exploits AS exploit_count
FROM
    fact_asset fa
    JOIN dim_asset da ON da.asset_id = fa.asset_id
    JOIN dim_asset_group_asset daga ON da.asset_id = daga.asset_id
    JOIN dim_asset_group dag ON daga.asset_group_id = dag.asset_group_id
WHERE
    dag.name = 'YOUR_ASSET_GROUP_NAME'
    AND fa.riskscore > 0
ORDER BY
    fa.riskscore DESC
```

**4. 4-week trend adapted for longer range (uses `scanAsOf` function)**

This adapts the official 4-week trend query to cover Dec 2025–June 2026 in monthly intervals:

```sql
WITH timestamps AS (
    SELECT
        date(ts) AS upper_date,
        date(ts - INTERVAL '1 month') AS lower_date
    FROM
        generate_series(
            '2025-12-01'::timestamp,
            '2026-07-01'::timestamp,
            INTERVAL '1 month'
        ) AS ts
),
asset_scans AS (
    SELECT
        da.asset_id,
        ts.upper_date,
        scanAsOf(da.asset_id, ts.upper_date) AS scan_at_date
    FROM
        dim_asset da
        CROSS JOIN timestamps ts
        JOIN dim_asset_group_asset daga ON da.asset_id = daga.asset_id
        JOIN dim_asset_group dag ON daga.asset_group_id = dag.asset_group_id
    WHERE
        dag.name = 'YOUR_ASSET_GROUP_NAME'
),
vuln_counts AS (
    SELECT
        a.upper_date,
        COUNT(*) AS total_vulnerabilities,
        SUM(CASE WHEN dv.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_vulns,
        SUM(CASE WHEN dv.severity = 'Severe' THEN 1 ELSE 0 END) AS severe_vulns,
        SUM(CASE WHEN dv.severity = 'Moderate' THEN 1 ELSE 0 END) AS moderate_vulns
    FROM
        asset_scans a
        JOIN fact_asset_scan_vulnerability_finding fasvf
            ON fasvf.asset_id = a.asset_id AND fasvf.scan_id = a.scan_at_date
        JOIN dim_vulnerability dv USING (vulnerability_id)
    GROUP BY
        a.upper_date
)
SELECT
    upper_date AS month,
    total_vulnerabilities,
    critical_vulns,
    severe_vulns,
    moderate_vulns
FROM
    vuln_counts
ORDER BY
    upper_date
```

**5. All vulns with details for the asset group (exportable for analysis)**

```sql
SELECT
    da.ip_address,
    da.host_name,
    dv.title AS vulnerability,
    dv.severity,
    dv.cvss_score,
    CAST(dv.riskscore AS decimal(10,0)) AS vuln_risk_score,
    dv.exploits,
    dv.malware_kits
FROM
    fact_asset_vulnerability_instance favi
    JOIN dim_asset da ON favi.asset_id = da.asset_id
    JOIN dim_vulnerability dv ON favi.vulnerability_id = dv.vulnerability_id
    JOIN dim_asset_group_asset daga ON da.asset_id = daga.asset_id
    JOIN dim_asset_group dag ON daga.asset_group_id = dag.asset_group_id
WHERE
    dag.name = 'YOUR_ASSET_GROUP_NAME'
ORDER BY
    dv.riskscore DESC, da.host_name
```

**6. New and remediated vulns (between last two scans — built-in function)**

Use the official `New-and-Remediated-Vulns-with-Vuln-details.sql` from the Rapid7 repo as-is. It uses `baselineComparison()`, `previousScan()`, and `lastScan()` functions to compare the last two scans per asset. That one is validated and works out of the box.

---

**Key schema notes:**
- `fact_asset` — current asset metrics (riskscore, vulnerabilities, critical/severe/moderate counts)
- `fact_scan` — per-scan aggregate metrics (riskscore, assets, vulnerabilities)
- `fact_asset_scan_vulnerability_finding` — per-scan per-asset vulnerability presence
- `dim_vulnerability` — vuln metadata (title, severity, cvss_score, riskscore, exploits)
- `dim_asset` — asset metadata (ip_address, host_name, asset_id)
- `scanAsOf(asset_id, date)` — built-in function that returns the scan_id active at a given date
- `baselineComparison(scan_id, scan_id)` — compares two scans, returns 'New', 'Old', 'Same'

Replace `YOUR_ASSET_GROUP_NAME` with their asset group name containing the 54 assets.
