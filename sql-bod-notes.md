Based on the Rapid7 community discussion and the `dim_vulnerability_category` table in the InsightVM reporting data model, here's the SQL query to list all categories with "KEV" in the name:

```sql
SELECT DISTINCT dvc.category_name
FROM dim_vulnerability_category dvc
WHERE LOWER(dvc.category_name) LIKE '%kev%'
ORDER BY dvc.category_name
```

The category you're looking for is `CISA KEV` (case-sensitive — uppercase). If you want to also see how many vulnerabilities fall into each matching category:

```sql
SELECT
    dvc.category_name,
    COUNT(DISTINCT dvc.vulnerability_id) AS vuln_count
FROM dim_vulnerability_category dvc
WHERE LOWER(dvc.category_name) LIKE '%kev%'
GROUP BY dvc.category_name
ORDER BY dvc.category_name
```

And if you want to see all assets with KEV vulnerabilities in your environment:

```sql
SELECT
    da.host_name,
    da.ip_address,
    dv.nexpose_id AS vuln_id,
    dv.title,
    dv.severity,
    dv.riskscore
FROM fact_asset_vulnerability_finding favf
JOIN dim_asset da USING (asset_id)
JOIN dim_vulnerability dv USING (vulnerability_id)
JOIN dim_vulnerability_category dvc ON dv.vulnerability_id = dvc.vulnerability_id
WHERE dvc.category_name = 'CISA KEV'
ORDER BY dv.riskscore DESC
```

These use the `dim_vulnerability_category` dimension table which is a many-to-many join to `dim_vulnerability` — each vulnerability can belong to multiple categories. The key join is on `vulnerability_id`.

