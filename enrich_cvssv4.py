#!/usr/bin/env python3
"""
Enrich InsightVM vulnerability data with CVSS v4.0 scores from NVD.

This script:
1. Extracts unique CVEs from your Rapid7 bulk export DuckDB database
2. Queries the NVD API 2.0 for CVSS v4 scores
3. Stores enrichment data in a local 'cvss_v4_enrichment' table in DuckDB
4. Produces a joined report showing vulns with their v4 scores

Usage:
    python enrich_cvssv4.py

Environment variables:
    NVD_API_KEY  - (optional) NVD API key for higher rate limits
                   Get one free at: https://nvd.nist.gov/developers/request-an-api-key

Output:
    - Updates 'cvss_v4_enrichment' table in rapid7_bulk_export.db
    - Writes cvssv4_enriched_vulns.csv with joined results
"""

import os
import sys
import time
import json
import requests
import duckdb
from pathlib import Path
from datetime import datetime

# --- Configuration ---
DB_PATH = Path(__file__).parent / "rapid7_bulk_export.db"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_CSV = Path(__file__).parent / "cvssv4_enriched_vulns.csv"

# Rate limiting: 50 req/30s with key, 5 req/30s without
RATE_LIMIT_DELAY = 0.6 if NVD_API_KEY else 6.0


def get_unique_cves(con: duckdb.DuckDBPyConnection) -> list[str]:
    """Extract unique CVE IDs from the vulnerabilities table."""
    result = con.execute("""
        WITH exploded AS (
            SELECT DISTINCT unnest(cves) as cve
            FROM vulnerabilities
            WHERE cves IS NOT NULL
        )
        SELECT cve FROM exploded ORDER BY cve
    """).fetchall()
    return [row[0] for row in result]


def fetch_cvss_v4_from_nvd(cve_id: str) -> dict | None:
    """
    Query NVD API for a single CVE and extract CVSS v4 data.
    Returns dict with score, severity, vector or None if not available.
    """
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"  ⚠️  API error for {cve_id}: {e}")
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    metrics = vulns[0].get("cve", {}).get("metrics", {})

    # Check for CVSS v4.0 metrics
    v4_metrics = metrics.get("cvssMetricV40", [])
    if v4_metrics:
        cvss_data = v4_metrics[0].get("cvssData", {})
        return {
            "cve_id": cve_id,
            "cvss_v4_score": cvss_data.get("baseScore"),
            "cvss_v4_severity": cvss_data.get("baseSeverity"),
            "cvss_v4_vector": cvss_data.get("vectorString"),
            "cvss_v4_source": v4_metrics[0].get("source", "NVD"),
        }

    # Also grab v3.1 for comparison if v4 not available
    v31_metrics = metrics.get("cvssMetricV31", [])
    v30_metrics = metrics.get("cvssMetricV30", [])
    v3 = v31_metrics or v30_metrics

    return {
        "cve_id": cve_id,
        "cvss_v4_score": None,
        "cvss_v4_severity": None,
        "cvss_v4_vector": None,
        "cvss_v4_source": None,
        "note": "No CVSS v4 available from NVD" + (
            f" (v3: {v3[0]['cvssData']['baseScore']})" if v3 else ""
        ),
    }


def create_enrichment_table(con: duckdb.DuckDBPyConnection):
    """Create or replace the enrichment table."""
    con.execute("""
        CREATE TABLE IF NOT EXISTS cvss_v4_enrichment (
            cve_id VARCHAR PRIMARY KEY,
            cvss_v4_score DOUBLE,
            cvss_v4_severity VARCHAR,
            cvss_v4_vector VARCHAR,
            cvss_v4_source VARCHAR,
            note VARCHAR,
            fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)


def upsert_enrichment(con: duckdb.DuckDBPyConnection, record: dict):
    """Insert or update a CVE enrichment record."""
    con.execute("""
        INSERT OR REPLACE INTO cvss_v4_enrichment
            (cve_id, cvss_v4_score, cvss_v4_severity, cvss_v4_vector, cvss_v4_source, note, fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [
        record.get("cve_id"),
        record.get("cvss_v4_score"),
        record.get("cvss_v4_severity"),
        record.get("cvss_v4_vector"),
        record.get("cvss_v4_source"),
        record.get("note"),
        datetime.utcnow(),
    ])


def export_enriched_report(con: duckdb.DuckDBPyConnection):
    """Join vulnerabilities with v4 enrichment and export to CSV."""
    query = """
        WITH exploded_vulns AS (
            SELECT
                assetId,
                vulnId,
                title,
                severity,
                cvssScore as cvss_v2_score,
                cvssV3Score as cvss_v3_score,
                cvssV3Severity as cvss_v3_severity,
                unnest(cves) as cve_id
            FROM vulnerabilities
            WHERE cves IS NOT NULL
        )
        SELECT
            v.assetId,
            v.vulnId,
            v.title,
            v.severity,
            v.cvss_v2_score,
            v.cvss_v3_score,
            v.cvss_v3_severity,
            v.cve_id,
            e.cvss_v4_score,
            e.cvss_v4_severity,
            e.cvss_v4_vector,
            e.cvss_v4_source,
            e.note as cvss_v4_note
        FROM exploded_vulns v
        LEFT JOIN cvss_v4_enrichment e ON v.cve_id = e.cve_id
        ORDER BY e.cvss_v4_score DESC NULLS LAST, v.cvss_v3_score DESC NULLS LAST
    """
    con.execute(f"COPY ({query}) TO '{OUTPUT_CSV}' (HEADER, DELIMITER ',')")
    row_count = con.execute(f"SELECT COUNT(*) FROM ({query})").fetchone()[0]
    return row_count


def main():
    print("=" * 60)
    print("CVSS v4 Enrichment Script")
    print("=" * 60)

    if not DB_PATH.exists():
        print(f"❌ Database not found: {DB_PATH}")
        print("   Run a Rapid7 bulk export first to populate the database.")
        sys.exit(1)

    if NVD_API_KEY:
        print(f"✅ NVD API key detected (faster rate limit)")
    else:
        print(f"⚠️  No NVD_API_KEY set — using slower rate limit ({RATE_LIMIT_DELAY}s between requests)")
        print(f"   Set NVD_API_KEY env var for 10x faster lookups")
        print(f"   Get a free key: https://nvd.nist.gov/developers/request-an-api-key")

    print()

    # Connect to DuckDB
    con = duckdb.connect(str(DB_PATH))
    create_enrichment_table(con)

    # Get unique CVEs
    cves = get_unique_cves(con)
    print(f"📋 Found {len(cves)} unique CVEs to enrich")
    print()

    # Check which ones we already have
    existing = con.execute(
        "SELECT cve_id FROM cvss_v4_enrichment"
    ).fetchall()
    existing_ids = {row[0] for row in existing}
    new_cves = [c for c in cves if c not in existing_ids]

    if not new_cves:
        print("✅ All CVEs already enriched. Skipping NVD lookups.")
    else:
        print(f"🔍 Fetching CVSS v4 data for {len(new_cves)} new CVEs...")
        print()

        v4_found = 0
        v4_missing = 0

        for i, cve_id in enumerate(new_cves, 1):
            print(f"  [{i}/{len(new_cves)}] {cve_id}...", end=" ")
            result = fetch_cvss_v4_from_nvd(cve_id)

            if result:
                upsert_enrichment(con, result)
                if result.get("cvss_v4_score"):
                    print(f"✅ v4={result['cvss_v4_score']} ({result['cvss_v4_severity']})")
                    v4_found += 1
                else:
                    print(f"⚠️  No v4 score ({result.get('note', '')})")
                    v4_missing += 1
            else:
                # CVE not found in NVD at all
                upsert_enrichment(con, {
                    "cve_id": cve_id,
                    "note": "CVE not found in NVD"
                })
                print("❌ Not found in NVD")
                v4_missing += 1

            # Rate limit
            if i < len(new_cves):
                time.sleep(RATE_LIMIT_DELAY)

        print()
        print(f"📊 Results: {v4_found} with v4 scores, {v4_missing} without")

    # Export joined report
    print()
    print("📄 Exporting enriched vulnerability report...")
    row_count = export_enriched_report(con)
    print(f"✅ Wrote {row_count} rows to: {OUTPUT_CSV}")

    # Summary
    print()
    print("=" * 60)
    summary = con.execute("""
        SELECT
            COUNT(*) as total,
            COUNT(cvss_v4_score) as has_v4,
            ROUND(AVG(cvss_v4_score), 1) as avg_v4_score
        FROM cvss_v4_enrichment
    """).fetchone()
    print(f"Enrichment table: {summary[0]} CVEs total, {summary[1]} with v4 scores")
    if summary[2]:
        print(f"Average CVSS v4 score: {summary[2]}")
    print("=" * 60)

    con.close()


if __name__ == "__main__":
    main()
