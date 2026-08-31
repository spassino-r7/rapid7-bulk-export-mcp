# DuckDB Optimization Notes — Bulk Export MCP

## Context

The `rapid7-bulk-export-mcp` server loads Parquet files from the InsightVM Bulk Export API into a local DuckDB database. The current loader does a straightforward Parquet → table load with no post-load optimization. This works well at small scale but would benefit from relationship-aware optimizations at larger deployments.

## Current Design

- Tables: `assets`, `vulnerabilities`, `policies`, `vulnerability_remediation`, `asset_software`
- No indexes, no sorting during load
- No pre-built views or relationships
- Snapshot loads drop and recreate tables (except remediation which appends)
- Read-only queries have external filesystem/network access disabled (security hardening)
- Join key: `assetId` shared across vulnerabilities, assets, remediation

## What Would Help at Scale

### 1. Sort Tables on Join Keys After Load

DuckDB is columnar and uses zone maps (min/max metadata per row group) to skip irrelevant data during scans. Sorting tables by their primary join key means row groups contain contiguous `assetId` ranges — JOIN operations can skip entire chunks instead of scanning everything.

```sql
CREATE OR REPLACE TABLE assets AS SELECT * FROM assets ORDER BY assetId;
CREATE OR REPLACE TABLE vulnerabilities AS SELECT * FROM vulnerabilities ORDER BY assetId, severity;
CREATE OR REPLACE TABLE vulnerability_remediation AS SELECT * FROM vulnerability_remediation ORDER BY assetId, firstFoundTimestamp;
```

### 2. Pre-Build a Joined View

Most queries join vulnerabilities + assets. A view avoids repeating the JOIN and gives the query planner a stable execution plan:

```sql
CREATE OR REPLACE VIEW findings AS
SELECT v.*, a.hostName, a.ip, a.osFamily, a.riskScore, a.tags, a.sites
FROM vulnerabilities v
LEFT JOIN assets a ON v.assetId = a.assetId;
```

Users can then query `SELECT * FROM findings WHERE severity = 'Critical'` without writing the join.

### 3. Run ANALYZE After Load

`ANALYZE` collects column statistics (cardinality, null count, min/max) that DuckDB's query planner uses to choose optimal join orders and filter strategies:

```sql
ANALYZE;
```

One command covers all tables. Negligible cost, meaningful benefit on datasets with skewed distributions.

### 4. Partition Remediation by Time

Since remediation data is append-mode and grows over time, time-range queries benefit from a computed partition column:

```sql
ALTER TABLE vulnerability_remediation ADD COLUMN year_month VARCHAR
    GENERATED ALWAYS AS (STRFTIME('%Y-%m', CAST(firstFoundTimestamp AS DATE)));
```

Queries like `WHERE firstFoundTimestamp >= '2026-06-01'` can then leverage zone maps on the sorted time column.

### 5. Secondary Sort on Common Filter Columns

Sorting vulnerabilities by `assetId, severity` means filtering by severity within an asset is nearly free (data is already grouped). For remediation, sorting by `assetId, firstFoundTimestamp` optimizes MTTR calculations.

## Proposed Code Change (Post-Load Block)

Insert after all tables are loaded in `load_parquet_files_by_prefix()`:

```python
# Optimize table layout for query performance
if not append:
    for table_name in tables_touched:
        if table_name == "assets":
            conn.execute("CREATE OR REPLACE TABLE assets AS SELECT * FROM assets ORDER BY assetId")
        elif table_name == "vulnerabilities":
            conn.execute("CREATE OR REPLACE TABLE vulnerabilities AS SELECT * FROM vulnerabilities ORDER BY assetId, severity")
        elif table_name == "vulnerability_remediation":
            conn.execute("CREATE OR REPLACE TABLE vulnerability_remediation AS SELECT * FROM vulnerability_remediation ORDER BY assetId, firstFoundTimestamp")

    # Collect column statistics for query planner
    conn.execute("ANALYZE")

    # Pre-built view for the most common query pattern
    if "vulnerabilities" in tables_touched and "assets" in tables_touched:
        conn.execute("""
            CREATE OR REPLACE VIEW findings AS
            SELECT v.*, a.hostName, a.ip, a.osFamily, a.riskScore, a.tags, a.sites
            FROM vulnerabilities v
            LEFT JOIN assets a ON v.assetId = a.assetId
        """)
```

## Impact Estimate

| Scale | Current Query Time | After Optimization | Improvement |
|---|---|---|---|
| 29 findings (lab) | <10ms | <10ms | Negligible |
| 10k findings | ~50ms | ~25ms | ~2x |
| 100k findings | ~500ms | ~100ms | ~5x |
| 500k+ findings | 2-5s | 300-500ms | ~5-10x |

## Tradeoffs

- **Load time increases slightly** — sorting adds a few seconds on large datasets (one-time cost per export load)
- **DB file size unchanged** — sorting doesn't add data, just reorders it
- **Append mode skipped** — only snapshot loads get the sort optimization (remediation appends stay as-is to avoid re-sorting the entire table on every chunk)
- **View adds no storage** — it's a query alias, not materialized

## When to Implement

- Current lab environment: not needed (data too small to matter)
- First customer with >10k assets: worth adding
- Any deployment with >100k findings: should be standard

## Related Discussion

- Slack thread on DB relationships in bulk export (July 2026)
- DuckDB docs: [Zone Maps and Sorting](https://duckdb.org/docs/guides/performance/indexing)
- Consider as a PR after the Keychain credential fallback lands
