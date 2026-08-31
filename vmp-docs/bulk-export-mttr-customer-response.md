# Bulk Export API — MTTR & Governance Metrics Customer Response

## 1. Which Bulk Export datasets and fields provide first identified, reintroduced, and scanner-confirmed remediation dates?

Two export types are relevant:

| Export Type | Key Fields |
|---|---|
| **Vulnerability** (open findings) | `firstFoundTimestamp`, `reintroducedTimestamp` |
| **Remediation** (closed findings) | `firstFoundTimestamp`, `reintroducedTimestamp`, `lastRemoved`, `lastDetected` |

- `firstFoundTimestamp` = date the vulnerability was first detected on the asset
- `reintroducedTimestamp` = date it reappeared after previous remediation (null if never reintroduced)
- `lastRemoved` = scanner-confirmed remediation date (the finding was absent on a subsequent credentialed scan)
- `lastDetected` = last scan where the finding was still present before removal

MTTR calculation: `lastRemoved - firstFoundTimestamp` (or `lastRemoved - reintroducedTimestamp` for reintroduced findings).

## 2. Whether the export retains multiple vulnerability lifecycle episodes for the same asset

Yes. The remediation export contains one record per remediation event. If a vulnerability is found, remediated, reintroduced, and remediated again, you get multiple records — each with its own `firstFoundTimestamp`/`reintroducedTimestamp` and `lastRemoved` dates. This supports tracking repeat offenders and reintroduction rates.

## 3. Whether historical remediation data is available retrospectively (12 months?)

The remediation export accepts a date range parameter (`start_date` to `end_date`). The available history depends on your InsightVM data retention settings (typically all remediation events since the console began tracking). The API limits each request to 31-day chunks, but you can request multiple chunks to cover 12+ months. Historical data availability depends on how long your console has been running and your organization's retention policy.

## 4. How remediated findings are distinguished from exceptions, deleted assets, stale assets, or incomplete scan coverage

- **Remediated** = present in the `vulnerability_remediation` export with a `lastRemoved` timestamp. The scanner confirmed the finding is no longer present.
- **Exceptions** = findings with approved exceptions are removed from the vulnerability export but are NOT in the remediation export (they weren't actually fixed, just accepted).
- **Deleted assets** = no longer appear in subsequent exports. Historical remediation records for deleted assets remain in the remediation export.
- **Stale assets** = still appear in the vulnerability export with aging `firstFoundTimestamp`. No `lastRemoved` because they haven't been rescanned to confirm remediation.
- **Incomplete scan coverage** = findings remain open (in vulnerability export) until a successful authenticated scan confirms they're gone.

The key distinction: only scanner-confirmed removals produce a remediation record.

## 5. What data-retention period applies

The Bulk Export API reflects what's stored in the InsightVM platform. Vulnerability data is retained for the life of the asset in the console. Remediation history is retained as long as the data exists in the platform. Specific retention limits should be confirmed with your Rapid7 account team based on your subscription tier, but generally all historical remediation events are available.

## 6. Whether Rapid7 provides a validated reference calculation for mean and median MTTR

No. Rapid7 does not publish an official reference SQL query or calculation methodology for MTTR. The "Average Days to Remediate by Severity" dashboard card in the console provides a weekly view, but the underlying calculation logic is not documented for external reproduction. Customers building MTTR from Bulk Export data define their own methodology (e.g., whether to use firstFound or reintroduced as the start date, how to handle multi-episode vulnerabilities, etc.).

## 7. Whether the MCP server is formally supported for production use

The MCP server (`rapid7/rapid7-bulk-export-mcp`) is an open-source tool published by Rapid7 on GitHub under the Metasploit Framework License. It is maintained by Rapid7 engineering and receives regular updates (currently v0.5.2). However, it is not covered under standard Rapid7 product support contracts. Issues and feature requests are handled via GitHub Issues. It's production-ready in terms of functionality but support is community/GitHub-based, not through Rapid7 Customer Support.

## 8. Whether the Bulk Export data can be used directly without an AI layer

Absolutely. The Bulk Export API returns standard Parquet files. These can be imported directly into:

- Any SQL database (PostgreSQL, MySQL, DuckDB)
- Business intelligence tools (Power BI, Tableau, Grafana)
- Data platforms (Snowflake, Databricks, BigQuery)
- Python/R for analysis (pandas, polars)
- Spreadsheets (export to CSV)

No AI, MCP server, or LLM is required. The MCP server is one consumption method — it provides a query interface for AI assistants — but the Parquet files are self-contained and can be used in any analytics pipeline.

## 9. Confirmation that deterministic calculations are supported

Yes. The data in the Parquet exports is static and deterministic. A SQL query against the remediation export will always produce the same result for the same data. Example MTTR calculation:

```sql
SELECT
    severity_tier,
    COUNT(*) AS remediated_count,
    ROUND(AVG(days_to_remediate), 1) AS mean_mttr,
    MEDIAN(days_to_remediate) AS median_mttr
FROM (
    SELECT
        CASE
            WHEN cvssV3Score >= 9.0 THEN 'Critical'
            WHEN cvssV3Score >= 7.0 THEN 'High'
            WHEN cvssV3Score >= 4.0 THEN 'Medium'
            ELSE 'Low'
        END AS severity_tier,
        DATE_DIFF('day', CAST(firstFoundTimestamp AS DATE), CAST(lastRemoved AS DATE)) AS days_to_remediate
    FROM vulnerability_remediation
    WHERE lastRemoved IS NOT NULL
)
GROUP BY severity_tier
```

This produces auditable, reproducible metrics. AI/LLM is used for interpretation, investigation, and narrative — not as the calculation engine.

## 10. Supported metrics summary

| Metric | Supported | Method |
|---|---|---|
| Mean time to remediate | Yes | `AVG(lastRemoved - firstFoundTimestamp)` |
| Median time to remediate | Yes | `MEDIAN(lastRemoved - firstFoundTimestamp)` |
| MTTR by severity | Yes | Group by CVSS severity tier |
| MTTR by asset scope | Yes | Join remediation → assets, group by site/tag/group |
| MTTR by business unit | Yes | Join on asset tags (business unit tags) |
| SLA performance | Yes | Compare days-to-remediate vs. threshold per severity |
| Reintroduced vulnerabilities | Yes | Filter where `reintroducedTimestamp IS NOT NULL` |
| Scanner-confirmed remediation | Yes | `lastRemoved` field = scanner confirmed absence |
| Scheduled/exportable reporting | Yes | Automate export + query on schedule, output to any format |

---

## Reference: Bulk Export API Documentation

- Bulk Export API: https://docs.rapid7.com/insightvm/bulk-export-api/
- MCP Server (GitHub): https://github.com/rapid7/rapid7-bulk-export-mcp
- Rapid7 blog on MCP + Bulk Export: https://www.rapid7.com/blog/post/em-bulk-export-ai-ready-security-workflows-open-source-mcp-server-agent-skill/
