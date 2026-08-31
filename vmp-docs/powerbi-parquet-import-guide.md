# Power BI Import Guide — Rapid7 Bulk Export Parquet Files

## Overview

The Rapid7 InsightVM Bulk Export API produces Parquet files that can be imported directly into Power BI for dashboards, KPI tracking, and executive reporting. This guide covers how to set up the data model, define relationships, and build useful measures.

## Prerequisites

- Power BI Desktop (October 2022+ for native Parquet support)
- Exported Parquet files from the Bulk Export API (vulnerability, asset, remediation)
- Files stored locally or in a shared location (OneDrive, SharePoint, Azure Blob)

## Step 1: Import Parquet Files

1. **Get Data → More → Parquet**
2. Browse to the folder containing your exported Parquet files
3. Import each file type as a separate table:
   - `asset_*.parquet` → **Assets** table
   - `asset_vulnerability_*.parquet` → **Vulnerabilities** table
   - `vulnerability_remediation_*.parquet` → **Remediation** table
   - `asset_policy_*.parquet` → **Policies** table (optional)

If you have multiple Parquet files per type (the API splits large exports), use **Folder connector** instead:
1. Get Data → Folder
2. Point to the directory
3. Filter by filename prefix in Power Query
4. Combine files into a single table per type

## Step 2: Define the Data Model (Star Schema)

### Dimension Table
- **Assets** — the central dimension (one row per asset)

### Fact Tables
- **Vulnerabilities** — findings linked to assets (many-to-one with Assets)
- **Remediation** — historical remediation events (many-to-one with Assets)
- **Policies** — compliance results (many-to-one with Assets)

### Relationships

In Model View, create these relationships:

| From (Fact) | Column | To (Dimension) | Column | Cardinality |
|---|---|---|---|---|
| Vulnerabilities | assetId | Assets | assetId | Many-to-One |
| Remediation | assetId | Assets | assetId | Many-to-One |
| Policies | assetId | Assets | assetId | Many-to-One |

Set cross-filter direction to **Single** (from dimension to fact) for best performance.

## Step 3: Power Query Transformations

Apply these in Power Query Editor before loading:

### Assets Table
```
- Remove duplicate assetId rows (keep latest)
- Expand the 'tags' column (list → rows or extract tag names)
- Expand the 'sites' column (list → comma-separated text)
- Set data types: riskScore as Decimal, assetId as Text
```

### Vulnerabilities Table
```
- Expand 'cves' column (list → comma-separated or first value)
- Convert firstFoundTimestamp to Date/DateTime
- Add calculated column: Age = Duration.Days(DateTime.LocalNow() - [firstFoundTimestamp])
- Set severity as Text (for slicer use)
- Set cvssV3Score as Decimal
```

### Remediation Table
```
- Convert firstFoundTimestamp and lastRemoved to Date/DateTime
- Add calculated column: DaysToRemediate = Duration.Days([lastRemoved] - [firstFoundTimestamp])
- Map severity from CVSS: 
    - >= 9.0 → Critical
    - >= 7.0 → High  
    - >= 4.0 → Medium
    - < 4.0 → Low
```

## Step 4: DAX Measures

### Core KPIs

```dax
Total Findings = COUNTROWS(Vulnerabilities)

Critical Findings = CALCULATE(COUNTROWS(Vulnerabilities), Vulnerabilities[severity] = "Critical")

Unique Assets Affected = DISTINCTCOUNT(Vulnerabilities[assetId])

Avg CVSS Score = AVERAGE(Vulnerabilities[cvssV3Score])

Findings with Exploits = CALCULATE(COUNTROWS(Vulnerabilities), Vulnerabilities[hasExploits] = TRUE())
```

### SLA Compliance

```dax
SLA Compliance % = 
VAR CriticalSLA = 60
VAR SevereSLA = 90
VAR ModerateSLA = 180
RETURN
DIVIDE(
    CALCULATE(
        COUNTROWS(Vulnerabilities),
        (Vulnerabilities[severity] = "Critical" && Vulnerabilities[Age] <= CriticalSLA) ||
        (Vulnerabilities[severity] = "Severe" && Vulnerabilities[Age] <= SevereSLA) ||
        (Vulnerabilities[severity] = "Moderate" && Vulnerabilities[Age] <= ModerateSLA)
    ),
    COUNTROWS(Vulnerabilities),
    1
)
```

### MTTR (Mean Time to Remediate)

```dax
MTTR Days = AVERAGE(Remediation[DaysToRemediate])

MTTR Critical = CALCULATE(AVERAGE(Remediation[DaysToRemediate]), Remediation[severity_tier] = "Critical")
```

### Risk Score Trend

```dax
Total Risk Score = SUM(Assets[riskScore])
```

## Step 5: Suggested Dashboard Pages

### Page 1: Executive Summary
- Total findings (card)
- Severity distribution (donut chart)
- SLA compliance % (gauge)
- MTTR by severity (bar chart)
- Risk score trend over time (line chart — requires historical snapshots)
- Top 5 riskiest assets (table)

### Page 2: Operational Detail
- Findings by host (matrix: hostName × severity)
- Aging analysis (histogram of finding age)
- Findings by site (bar chart)
- Overdue findings (table with conditional formatting)
- New findings this week vs. remediated this week (KPI cards)

### Page 3: Remediation Tracking
- MTTR trend by month (line chart)
- Remediation volume by severity (stacked bar)
- Open vs. closed findings (area chart)
- Top 10 most common vulnerabilities (table with affected asset count)

### Page 4: Compliance
- Policy pass/fail rates (stacked bar by benchmark)
- Failed rules by criticality (table)
- Compliance trend over time (line chart)

## Step 6: Refresh Strategy

### Manual (Small Environments)
- Re-export Parquet files periodically (weekly/monthly)
- Replace files in the source folder
- Refresh dataset in Power BI Desktop

### Automated (Larger Environments)
- Schedule Bulk Export via API on a cron/timer
- Store Parquet files in Azure Blob Storage or SharePoint
- Configure Power BI Gateway + scheduled refresh
- Dataflow alternative: Power BI Dataflows can read Parquet from Azure Blob directly

## Performance Tips

- **Pre-sort Parquet files by assetId** before importing — Power BI's Vertipaq engine compresses sorted data significantly better (can reduce model size by 30-50%)
- **Remove unused columns** in Power Query before loading — every column costs RAM
- **Disable auto date/time** in Power BI options for timestamp columns (prevents auto-generated date hierarchies that bloat the model)
- **Use Import mode** (not DirectQuery) for Parquet — the files are static snapshots, not live databases
- **Aggregate large datasets** — if you have 500k+ findings, consider summarizing in Power Query (group by asset + severity) rather than loading every row

## Column Reference

### Assets (Dimension)
Key fields: `assetId`, `hostName`, `ip`, `mac`, `osFamily`, `osProduct`, `osVersion`, `riskScore`, `sites`, `tags`

### Vulnerabilities (Fact)
Key fields: `assetId`, `vulnId`, `title`, `severity`, `cvssV3Score`, `cves`, `hasExploits`, `epssscore`, `firstFoundTimestamp`, `port`, `protocol`

### Remediation (Fact)
Key fields: `assetId`, `cveId`, `vulnId`, `cvssV3Score`, `firstFoundTimestamp`, `lastRemoved`, `title`

### Policies (Fact)
Key fields: `assetId`, `benchmarkTitle`, `profileTitle`, `ruleTitle`, `finalStatus`, `lastAssessmentTimestamp`, `source`

## Notes

- Parquet files from the Bulk Export API include nested/list columns (tags, cves, sites). Power BI handles these via "Expand" in Power Query — expand to rows for filtering, or extract as text for display.
- The `assetId` format is a long UUID-style string (e.g., `8bd28bcb-2c23-420d-b85f-8eee8e07fac2-default-asset-19`). Keep as Text type, not converted.
- Historical trending requires keeping past export snapshots. Consider a folder structure like `exports/2026-07/`, `exports/2026-08/` and using a date parameter in Power Query.
