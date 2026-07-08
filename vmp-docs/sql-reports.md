# InsightVM SQL Reports — Vulnerability Management Program

**Program:** Vulnerability Management Program (InsightVM)
**Console path:** Reports → SQL Query Export
**Schedule:** First business day of each month
**Recipients:** Security team distribution list

Copy each query below directly into InsightVM's SQL Query Export console. Save each report with the name shown and schedule for monthly delivery.

---

## Report 1: `VMP-MTTR-Monthly`

**Purpose:** Monthly Mean Time to Remediate (MTTR) by severity tier. Shows the average number of days between vulnerability publication and verified remediation for vulnerabilities closed in the last 30 days.

**Schedule:** First business day of each month  
**Recipients:** Security team DL, Security Program Administrator

```sql
SELECT
    dv.severity,
    COUNT(*) AS remediated_count,
    AVG(
        EXTRACT(EPOCH FROM (fa.scan_finished - dv.date_published)) / 86400
    )::int AS avg_days_to_remediate
FROM dim_vulnerability dv
JOIN fact_asset_vulnerability_finding favf ON dv.vulnerability_id = favf.vulnerability_id
JOIN fact_asset fa ON favf.asset_id = fa.asset_id
WHERE favf.status = 'REMEDIATED'
  AND fa.scan_finished >= NOW() - INTERVAL '30 days'
GROUP BY dv.severity
ORDER BY
    CASE dv.severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        WHEN 'Low'      THEN 4
        ELSE 5
    END;
```

**Expected columns:** `severity`, `remediated_count`, `avg_days_to_remediate`

**How to use:** Compare `avg_days_to_remediate` against SLA targets (Critical=15, High=30, Medium=90, Low=180). An increasing trend month-over-month indicates remediation velocity is declining.

---

## Report 2: `VMP-SLA-Compliance`

**Purpose:** SLA compliance rate by severity tier. Shows the percentage of currently open vulnerabilities that are still within their SLA window.

**Schedule:** First business day of each month  
**Recipients:** Security team DL, Security leadership

```sql
SELECT
    dv.severity,
    COUNT(*) AS total_findings,
    SUM(CASE
        WHEN EXTRACT(EPOCH FROM (NOW() - favf.date_first_found)) / 86400 <=
             CASE dv.severity
                 WHEN 'Critical' THEN 15
                 WHEN 'High'     THEN 30
                 WHEN 'Medium'   THEN 90
                 WHEN 'Low'      THEN 180
                 ELSE 180
             END
        THEN 1 ELSE 0
    END) AS within_sla,
    ROUND(
        100.0 * SUM(CASE
            WHEN EXTRACT(EPOCH FROM (NOW() - favf.date_first_found)) / 86400 <=
                 CASE dv.severity
                     WHEN 'Critical' THEN 15
                     WHEN 'High'     THEN 30
                     WHEN 'Medium'   THEN 90
                     WHEN 'Low'      THEN 180
                     ELSE 180
                 END
            THEN 1 ELSE 0
        END) / NULLIF(COUNT(*), 0), 2
    ) AS sla_compliance_pct
FROM dim_vulnerability dv
JOIN fact_asset_vulnerability_finding favf ON dv.vulnerability_id = favf.vulnerability_id
WHERE favf.status = 'OPEN'
GROUP BY dv.severity
ORDER BY
    CASE dv.severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        WHEN 'Low'      THEN 4
        ELSE 5
    END;
```

**Expected columns:** `severity`, `total_findings`, `within_sla`, `sla_compliance_pct`

**How to use:** Compare `sla_compliance_pct` against Goal targets (Critical ≥ 95%, High ≥ 90%, Medium ≥ 85%, Low ≥ 80%). This report validates the InsightVM Goals & SLAs view with raw data.

---

## Report 3: `VMP-Exploitable-Findings`

**Purpose:** Exploitable findings summary. Returns all open vulnerabilities where `hasExploits = true` OR `epss_score > 0.50`, sorted by CVSS score and EPSS score descending. Limited to 500 rows.

**Schedule:** First business day of each month  
**Recipients:** Security team DL, Security operations team

```sql
SELECT
    da.host_name,
    da.ip_address,
    dv.title,
    dv.cvss_v3_score,
    dv.severity,
    dv.epss_score,
    favf.date_first_found,
    EXTRACT(EPOCH FROM (NOW() - favf.date_first_found)) / 86400 AS age_days
FROM dim_asset da
JOIN fact_asset_vulnerability_finding favf ON da.asset_id = favf.asset_id
JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
WHERE favf.status = 'OPEN'
  AND (dv.exploits > 0 OR dv.epss_score > 0.50)
ORDER BY dv.cvss_v3_score DESC, dv.epss_score DESC
LIMIT 500;
```

**Expected columns:** `host_name`, `ip_address`, `title`, `cvss_v3_score`, `severity`, `epss_score`, `date_first_found`, `age_days`

**How to use:** This is the primary analyst workqueue for exploitable vulnerabilities. Sort by `age_days` to identify exploitable findings approaching SLA deadlines. Any finding with `age_days` approaching the SLA target for its severity should be in an active Remediation Project.

---

## Report 4: `VMP-Exception-Summary`

**Purpose:** Open exception summary. Returns all vulnerabilities currently in exception or false-positive status, sorted by review date ascending so overdue reviews appear first.

**Schedule:** First business day of each month  
**Recipients:** Security team DL, Security Program Administrator

```sql
SELECT
    da.host_name,
    dv.title,
    dv.severity,
    dve.exception_type,
    dve.reason,
    dve.date_created,
    dve.review_date,
    dve.submitter
FROM dim_asset da
JOIN fact_asset_vulnerability_finding favf ON da.asset_id = favf.asset_id
JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
JOIN dim_vulnerability_exception dve ON favf.vulnerability_id = dve.vulnerability_id
WHERE favf.status IN ('EXCEPTION', 'FALSE_POSITIVE')
ORDER BY dve.review_date ASC;
```

**Expected columns:** `host_name`, `title`, `severity`, `exception_type`, `reason`, `date_created`, `review_date`, `submitter`

**How to use:** Review exceptions with `review_date` in the current month. Any exception with `review_date` in the past is overdue and must be escalated. Use this report to populate the monthly exception register in the runbook.

---

## Report 5: `VMP-Scan-Coverage`

**Purpose:** Scan coverage by Site. Shows the percentage of assets in each Site that have been scanned within the last 30 days.

**Schedule:** First business day of each month  
**Recipients:** Security team DL, Security Program Administrator

```sql
SELECT
    ds.name AS site_name,
    COUNT(DISTINCT da.asset_id) AS total_assets,
    SUM(CASE
        WHEN fa.scan_finished >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0
    END) AS scanned_last_30d,
    ROUND(
        100.0 * SUM(CASE
            WHEN fa.scan_finished >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0
        END) / NULLIF(COUNT(DISTINCT da.asset_id), 0), 2
    ) AS coverage_pct
FROM dim_site ds
JOIN dim_asset_site das ON ds.site_id = das.site_id
JOIN dim_asset da ON das.asset_id = da.asset_id
LEFT JOIN fact_asset fa ON da.asset_id = fa.asset_id
GROUP BY ds.name
ORDER BY coverage_pct ASC;
```

**Expected columns:** `site_name`, `total_assets`, `scanned_last_30d`, `coverage_pct`

**How to use:** Any Site with `coverage_pct` below 95% requires investigation. Common causes: scan engine offline, credential failure, new assets added to scope but not yet scanned. If total coverage across all Sites falls below 90%, the Program Administrator must present a remediation plan to security leadership within 5 business days (Requirement 5.5).

---

---

## Report 6: `VMP-BOD-Tier-Classification`

**Purpose:** Classify all open vulnerabilities by BOD 26-04 risk tier. Uses asset tagging (Internet-Facing), exploit availability, and CVSS impact to approximate the 4-factor SSVC model. KEV matching must be done externally via `kev_cross_reference.py` (the Data Warehouse does not natively store KEV status).

**Schedule:** First business day of each month
**Recipients:** Security team DL, Security leadership

```sql
-- BOD 26-04 Risk Tier Approximation
-- Note: This query approximates tier classification using available warehouse data.
-- Full classification requires KEV cross-reference (done via kev_cross_reference.py).
-- Assets must be tagged "Internet-Facing" for exposure classification.
SELECT
    CASE
        WHEN dt.tag_name = 'Internet-Facing'
             AND dv.exploits > 0
             AND dv.cvss_v3_score >= 9.0
        THEN 'Tier 1/2 - Internet-Facing + Exploitable (KEV check needed)'
        WHEN dt.tag_name = 'Internet-Facing'
        THEN 'Tier 2/3 - Internet-Facing (KEV check needed)'
        WHEN dv.exploits > 0 OR dv.epss_score > 0.50
        THEN 'Tier 3/4 - Internal + Exploitable (KEV check needed)'
        ELSE 'Tier 4 - Likely Defer'
    END AS preliminary_tier,
    dv.severity,
    COUNT(*) AS finding_count,
    COUNT(DISTINCT da.asset_id) AS affected_assets
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
JOIN dim_asset da ON favf.asset_id = da.asset_id
LEFT JOIN dim_tag dt ON da.asset_id = dt.asset_id AND dt.tag_name = 'Internet-Facing'
WHERE favf.status = 'OPEN'
GROUP BY preliminary_tier, dv.severity
ORDER BY preliminary_tier, dv.severity;
```

**Expected columns:** `preliminary_tier`, `severity`, `finding_count`, `affected_assets`

**How to use:** This provides a preliminary tier estimate. For definitive classification, combine with the `kev_cross_reference.py` output which matches CVEs against the CISA KEV catalog.

---

## Report 7: `VMP-Exposure-Summary`

**Purpose:** Open vulnerability breakdown by asset exposure status (Internet-Facing vs Internal) and CVSS severity. Requires assets to be tagged with `Internet-Facing` tag.

**Schedule:** First business day of each month
**Recipients:** Security team DL, Security leadership

```sql
SELECT
    CASE
        WHEN dt.tag_name = 'Internet-Facing' THEN 'Internet-Facing'
        ELSE 'Internal'
    END AS exposure_status,
    dv.severity,
    COUNT(*) AS open_findings,
    COUNT(DISTINCT da.asset_id) AS affected_assets,
    ROUND(AVG(dv.cvss_v3_score), 2) AS avg_cvss
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
JOIN dim_asset da ON favf.asset_id = da.asset_id
LEFT JOIN dim_tag dt ON da.asset_id = dt.asset_id AND dt.tag_name = 'Internet-Facing'
WHERE favf.status = 'OPEN'
GROUP BY exposure_status, dv.severity
ORDER BY exposure_status,
    CASE dv.severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        WHEN 'Low'      THEN 4
        ELSE 5
    END;
```

**Expected columns:** `exposure_status`, `severity`, `open_findings`, `affected_assets`, `avg_cvss`

**How to use:** Internet-Facing findings at Critical or High severity should be prioritized as Tier 1/2 candidates. If internet-facing critical findings persist beyond 14 days, escalate to security leadership.

---

## Report 8: `VMP-KEV-Overlap`

**Purpose:** Identify open vulnerabilities whose CVEs match the CISA KEV catalog. This report requires the KEV CVE list to be maintained in a reference table or manually specified.

**Schedule:** Weekly (Monday)
**Recipients:** Security team DL

```sql
-- Note: Replace the KEV CVE list below with current values from kev_cross_reference.py
-- or maintain a reference table. This is a template showing the approach.
-- For production use, the kev_cross_reference.py script is the primary mechanism.
SELECT
    da.host_name,
    da.ip_address,
    dv.title,
    dv.severity,
    dv.cvss_v3_score,
    dv.epss_score,
    favf.date_first_found,
    EXTRACT(EPOCH FROM (NOW() - favf.date_first_found)) / 86400 AS age_days,
    CASE
        WHEN dt.tag_name = 'Internet-Facing' THEN 'Exposed'
        ELSE 'Internal'
    END AS exposure
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
JOIN dim_asset da ON favf.asset_id = da.asset_id
LEFT JOIN dim_tag dt ON da.asset_id = dt.asset_id AND dt.tag_name = 'Internet-Facing'
WHERE favf.status = 'OPEN'
  AND dv.exploits > 0
ORDER BY dv.cvss_v3_score DESC, dv.epss_score DESC;
```

**Expected columns:** `host_name`, `ip_address`, `title`, `severity`, `cvss_v3_score`, `epss_score`, `date_first_found`, `age_days`, `exposure`

**How to use:** This is a workaround until KEV matching is automated in the warehouse. The `kev_cross_reference.py` script provides the definitive KEV match. This report captures exploitable findings (which have significant overlap with KEV) as a proxy.

---

## Setup Instructions

### Creating a Report in InsightVM

1. Navigate to **Reports → SQL Query Export**.
2. Click **Create Report**.
3. Enter the report name (e.g., `VMP-MTTR-Monthly`).
4. Paste the SQL query into the query editor.
5. Click **Run** to validate the query returns results.
6. Under **Schedule**, set recurrence to **Monthly** on the first business day.
7. Under **Recipients**, add the security team distribution list email address.
8. Click **Save**.

### Validating Reports

After creating each report, run it manually once and confirm:
- The query returns non-null results.
- Column names match the expected columns listed above.
- Row counts are reasonable given the current asset and vulnerability inventory.

If a query returns zero rows, verify that:
- The relevant data exists in InsightVM (scans have completed, vulnerabilities are detected).
- The `status` filter values match InsightVM's actual status strings in your environment.
