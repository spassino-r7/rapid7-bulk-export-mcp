#!/usr/bin/env python3
"""
CISA KEV + VulnCheck KEV + Rapid7 Critical Cross-Reference Script

Downloads exploitation intelligence from multiple sources and cross-references
against open vulnerabilities in the Rapid7 bulk export database. Classifies
findings by BOD 26-04 risk tier.

Sources:
    1. CISA Known Exploited Vulnerabilities (KEV) catalog
    2. VulnCheck KEV (community API — broader, faster coverage)
    3. Rapid7 "Critical" category vulnerabilities (from InsightVM Data Warehouse)

Usage:
    python kev_cross_reference.py [--output kev_report.json] [--csv kev_report.csv]

Requirements:
    pip install requests duckdb

Environment Variables:
    RAPID7_DB_PATH       - Path to Rapid7 bulk export DuckDB (optional, has default)
    VULNCHECK_API_TOKEN  - VulnCheck API token (optional, skips VulnCheck if not set)

Schedule:
    Run weekly (Monday 06:00) via cron or task scheduler.
"""

import argparse
import json
import os
import sys
from datetime import datetime

import requests

try:
    import duckdb
except ImportError:
    print("ERROR: duckdb package required. Install with: pip install duckdb")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULNCHECK_API = "https://api.vulncheck.com/v3/index/vulncheck-kev"
VULNCHECK_BACKUP_API = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
VULNCHECK_TOKEN = os.environ.get("VULNCHECK_API_TOKEN")

DB_PATH = os.environ.get(
    "RAPID7_DB_PATH",
    os.path.expanduser("~/anothertry/rapid7_bulk_export.db")
)

# EPSS threshold for "automatable" classification
EPSS_AUTOMATABLE_THRESHOLD = 0.50

# CVSS v3 score threshold for "total" impact approximation
CVSS_TOTAL_IMPACT_THRESHOLD = 9.0

# Rapid7 critical category keywords (case-insensitive matching on vuln categories)
RAPID7_CRITICAL_KEYWORDS = ["rapid7 critical", "critical vulnerability"]


# ---------------------------------------------------------------------------
# Source 1: CISA KEV Download
# ---------------------------------------------------------------------------

def download_cisa_kev() -> dict:
    """Download the current CISA KEV catalog."""
    print("=" * 60)
    print("SOURCE 1: CISA KEV Catalog")
    print("=" * 60)
    print(f"  Downloading from {KEV_URL}...")

    try:
        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        count = data.get("count", len(data.get("vulnerabilities", [])))
        print(f"  ✓ KEV catalog version: {data.get('catalogVersion', 'unknown')}")
        print(f"  ✓ Total CISA KEV entries: {count}")
        return data
    except requests.RequestException as e:
        print(f"  ✗ Failed to download CISA KEV: {e}")
        return {"vulnerabilities": []}


def extract_cisa_kev_cves(kev_data: dict) -> dict:
    """Extract CVE IDs and metadata from CISA KEV catalog."""
    kev_map = {}
    for vuln in kev_data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        if cve_id:
            kev_map[cve_id] = {
                "source": "CISA KEV",
                "vendor": vuln.get("vendorProject", ""),
                "product": vuln.get("product", ""),
                "name": vuln.get("vulnerabilityName", ""),
                "date_added": vuln.get("dateAdded", ""),
                "due_date": vuln.get("dueDate", ""),
                "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            }
    return kev_map


# ---------------------------------------------------------------------------
# Source 2: VulnCheck KEV
# ---------------------------------------------------------------------------

def download_vulncheck_kev() -> dict:
    """Download VulnCheck KEV catalog via community API."""
    print()
    print("=" * 60)
    print("SOURCE 2: VulnCheck KEV (Community API)")
    print("=" * 60)

    if not VULNCHECK_TOKEN:
        print("  ⚠ VULNCHECK_API_TOKEN not set — skipping VulnCheck KEV.")
        print("  Set environment variable to enable. Free token at vulncheck.com")
        return {}

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {VULNCHECK_TOKEN}",
    }

    vulncheck_map = {}
    page = 1
    total_fetched = 0

    try:
        print(f"  Fetching VulnCheck KEV (paginated)...")
        while True:
            url = f"{VULNCHECK_API}?page={page}&limit=100"
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            entries = data.get("data", [])
            if not entries:
                break

            for entry in entries:
                cve_id = entry.get("cve", [None])
                if isinstance(cve_id, list):
                    cve_ids = cve_id
                else:
                    cve_ids = [cve_id]

                for cid in cve_ids:
                    if cid and cid not in vulncheck_map:
                        vulncheck_map[cid] = {
                            "source": "VulnCheck KEV",
                            "vendor": entry.get("vendor", ""),
                            "product": entry.get("product", ""),
                            "name": entry.get("name", entry.get("vulnerability_name", "")),
                            "date_added": entry.get("date_added", ""),
                            "due_date": "",
                            "known_ransomware": entry.get("known_ransomware", "Unknown"),
                        }

            total_fetched += len(entries)
            page += 1

            # Safety limit
            if page > 100:
                break

        print(f"  ✓ Total VulnCheck KEV entries: {len(vulncheck_map)}")

    except requests.RequestException as e:
        print(f"  ✗ Failed to fetch VulnCheck KEV: {e}")
        print("  Continuing with CISA KEV only.")

    return vulncheck_map


def query_vulncheck_bulk(cve_list: list) -> dict:
    """
    Bulk-check specific CVEs against VulnCheck KEV.
    More efficient than paginating the full catalog when you have a known CVE list.
    POST up to 1000 CVEs per request.
    """
    if not VULNCHECK_TOKEN:
        return {}

    if not cve_list:
        return {}

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {VULNCHECK_TOKEN}",
        "Content-Type": "application/json",
    }

    vulncheck_matches = {}

    # Chunk into batches of 1000
    for i in range(0, len(cve_list), 1000):
        chunk = cve_list[i:i + 1000]
        try:
            response = requests.post(
                VULNCHECK_API,
                headers=headers,
                json={"cve": chunk},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            for entry in data.get("data", []):
                cve_ids = entry.get("cve", [])
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids]
                for cid in cve_ids:
                    if cid:
                        vulncheck_matches[cid] = {
                            "source": "VulnCheck KEV",
                            "vendor": entry.get("vendor", ""),
                            "product": entry.get("product", ""),
                            "name": entry.get("name", ""),
                            "date_added": entry.get("date_added", ""),
                            "due_date": "",
                            "known_ransomware": entry.get("known_ransomware", "Unknown"),
                        }
        except requests.RequestException:
            pass  # Fall through — CISA KEV still provides coverage

    return vulncheck_matches


# ---------------------------------------------------------------------------
# Source 3: Rapid7 Critical Category
# ---------------------------------------------------------------------------

def query_rapid7_critical(db_path: str) -> set:
    """
    Query vulnerabilities in the 'rapid7 critical' category from the bulk export.
    Returns a set of vulnIds that match.
    """
    print()
    print("=" * 60)
    print("SOURCE 3: Rapid7 'Critical' Category")
    print("=" * 60)

    if not os.path.exists(db_path):
        print(f"  ⚠ Database not found at {db_path} — skipping Rapid7 critical check.")
        return set()

    conn = duckdb.connect(db_path, read_only=True)

    # Check if there's a categories column in the vulnerabilities table
    try:
        columns = conn.execute("DESCRIBE vulnerabilities").fetchall()
        column_names = [col[0].lower() for col in columns]
    except Exception:
        conn.close()
        print("  ⚠ Could not inspect vulnerabilities table schema.")
        return set()

    rapid7_critical_vulns = set()

    # Strategy 1: Check for 'categories' column
    if "categories" in column_names:
        try:
            query = """
            SELECT DISTINCT vulnId
            FROM vulnerabilities
            WHERE LOWER(CAST(categories AS VARCHAR)) LIKE '%rapid7 critical%'
               OR LOWER(CAST(categories AS VARCHAR)) LIKE '%critical vulnerability%'
            """
            results = conn.execute(query).fetchall()
            rapid7_critical_vulns = {row[0] for row in results}
            print(f"  ✓ Found {len(rapid7_critical_vulns)} vulns in Rapid7 Critical category (via categories column)")
        except Exception as e:
            print(f"  ⚠ Query failed on categories column: {e}")

    # Strategy 2: Check for 'severityRank' or similar fields
    if not rapid7_critical_vulns and "severityrank" in column_names:
        try:
            query = """
            SELECT DISTINCT vulnId
            FROM vulnerabilities
            WHERE severityRank = 1
            """
            results = conn.execute(query).fetchall()
            rapid7_critical_vulns = {row[0] for row in results}
            print(f"  ✓ Found {len(rapid7_critical_vulns)} vulns with severityRank=1")
        except Exception as e:
            print(f"  ⚠ Query failed on severityRank: {e}")

    # Strategy 3: Use hasExploits + high CVSS as Rapid7's effective "critical" set
    if not rapid7_critical_vulns:
        try:
            query = """
            SELECT DISTINCT vulnId
            FROM vulnerabilities
            WHERE hasExploits = true AND cvssV3Score >= 9.0
            """
            results = conn.execute(query).fetchall()
            rapid7_critical_vulns = {row[0] for row in results}
            print(f"  ✓ Found {len(rapid7_critical_vulns)} vulns matching hasExploits=true + CVSS≥9.0 (proxy for Rapid7 Critical)")
        except Exception as e:
            print(f"  ⚠ Fallback query failed: {e}")

    conn.close()
    return rapid7_critical_vulns


# ---------------------------------------------------------------------------
# Database Query — Open Vulnerabilities
# ---------------------------------------------------------------------------

def query_open_vulnerabilities(db_path: str) -> list:
    """Query open vulnerabilities from the Rapid7 bulk export database."""
    print()
    print("=" * 60)
    print("OPEN VULNERABILITIES")
    print("=" * 60)

    if not os.path.exists(db_path):
        print(f"ERROR: Database not found at {db_path}")
        print("  Set RAPID7_DB_PATH environment variable or run a bulk export first.")
        sys.exit(1)

    print(f"  Querying from {db_path}...")
    conn = duckdb.connect(db_path, read_only=True)

    query = """
    SELECT
        v.assetId,
        v.vulnId,
        v.title,
        v.severity,
        v.cvssV3Score,
        v.hasExploits,
        v.epssscore,
        v.cves,
        a.hostName,
        a.ip,
        a.osFamily,
        a.tags
    FROM vulnerabilities v
    LEFT JOIN assets a ON v.assetId = a.assetId
    """

    results = conn.execute(query).fetchall()
    columns = [
        "assetId", "vulnId", "title", "severity", "cvssV3Score",
        "hasExploits", "epssscore", "cves", "hostName", "ip",
        "osFamily", "tags"
    ]

    findings = []
    for row in results:
        finding = dict(zip(columns, row))
        findings.append(finding)

    conn.close()
    print(f"  ✓ Total vulnerability findings: {len(findings)}")
    return findings


# ---------------------------------------------------------------------------
# Risk Tier Classification
# ---------------------------------------------------------------------------

def is_internet_facing(finding: dict) -> bool:
    """
    Determine if an asset is internet-facing.
    Checks tags for 'internet-facing', 'dmz', 'external', or 'public'.
    """
    tags = finding.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]

    exposure_keywords = ["internet-facing", "dmz", "external", "public", "exposed"]
    for tag in tags:
        if isinstance(tag, dict):
            tag_str = str(tag.get("name", "")).lower()
        else:
            tag_str = str(tag).lower()
        for keyword in exposure_keywords:
            if keyword in tag_str:
                return True
    return False


def is_automatable(finding: dict) -> bool:
    """Determine if exploitation is automatable."""
    has_exploits = finding.get("hasExploits", False)
    epss = float(finding.get("epssscore") or 0)
    return has_exploits or epss > EPSS_AUTOMATABLE_THRESHOLD


def is_total_impact(finding: dict) -> bool:
    """Determine if exploitation yields total control."""
    cvss = float(finding.get("cvssV3Score") or 0)
    return cvss >= CVSS_TOTAL_IMPACT_THRESHOLD


def classify_risk_tier(finding: dict, is_kev: bool) -> str:
    """Classify a finding into BOD 26-04 risk tiers."""
    exposed = is_internet_facing(finding)
    automatable = is_automatable(finding)
    total_impact = is_total_impact(finding)

    if exposed and is_kev and automatable and total_impact:
        return "Tier 1 - 3 Day"
    elif exposed and is_kev:
        return "Tier 2 - 14 Day"
    elif is_kev or exposed:
        return "Tier 3 - 60 Day"
    else:
        return "Tier 4 - Defer"


# ---------------------------------------------------------------------------
# Cross-Reference (All Sources)
# ---------------------------------------------------------------------------

def cross_reference(findings: list, combined_kev: dict, rapid7_critical: set) -> list:
    """Cross-reference open findings against all exploitation intelligence sources."""
    matches = []

    for finding in findings:
        cves = finding.get("cves") or []
        if isinstance(cves, str):
            cves = [cves]

        vuln_id = finding.get("vulnId", "")
        matched_sources = []

        # Check KEV sources (CISA + VulnCheck)
        kev_info = None
        for cve in cves:
            if cve in combined_kev:
                kev_info = combined_kev[cve]
                matched_sources.append(kev_info["source"])
                break

        # Check Rapid7 Critical category
        is_rapid7_critical = vuln_id in rapid7_critical
        if is_rapid7_critical:
            matched_sources.append("Rapid7 Critical")

        # If matched by any source, include in results
        if matched_sources:
            is_kev = kev_info is not None
            risk_tier = classify_risk_tier(finding, is_kev)

            matches.append({
                "cve": cves[0] if cves else "N/A",
                "vuln_id": vuln_id,
                "title": finding.get("title"),
                "hostname": finding.get("hostName"),
                "ip": finding.get("ip"),
                "severity": finding.get("severity"),
                "cvss_v3": finding.get("cvssV3Score"),
                "has_exploits": finding.get("hasExploits"),
                "epss": finding.get("epssscore"),
                "internet_facing": is_internet_facing(finding),
                "automatable": is_automatable(finding),
                "total_impact": is_total_impact(finding),
                "risk_tier": risk_tier,
                "matched_sources": matched_sources,
                "kev_date_added": kev_info.get("date_added", "") if kev_info else "",
                "kev_due_date": kev_info.get("due_date", "") if kev_info else "",
                "kev_ransomware": kev_info.get("known_ransomware", "") if kev_info else "",
                "rapid7_critical": is_rapid7_critical,
            })

    return matches


def classify_all_findings(findings: list, combined_kev: dict, rapid7_critical: set) -> dict:
    """Classify ALL open findings by risk tier."""
    tier_counts = {
        "Tier 1 - 3 Day": 0,
        "Tier 2 - 14 Day": 0,
        "Tier 3 - 60 Day": 0,
        "Tier 4 - Defer": 0,
    }

    for finding in findings:
        cves = finding.get("cves") or []
        if isinstance(cves, str):
            cves = [cves]

        vuln_id = finding.get("vulnId", "")
        is_kev = any(cve in combined_kev for cve in cves)

        # Rapid7 Critical findings get treated as KEV-equivalent for tier purposes
        if not is_kev and vuln_id in rapid7_critical:
            is_kev = True

        tier = classify_risk_tier(finding, is_kev)
        tier_counts[tier] += 1

    return tier_counts


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_summary(matches: list, tier_counts: dict, total_findings: int,
                  cisa_count: int, vulncheck_count: int, rapid7_critical_count: int):
    """Print summary to console."""
    print()
    print("=" * 70)
    print("EXPLOITATION INTELLIGENCE CROSS-REFERENCE REPORT")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    print(f"\n--- Intelligence Sources ---")
    print(f"  CISA KEV entries:           {cisa_count}")
    print(f"  VulnCheck KEV entries:      {vulncheck_count}")
    print(f"  Rapid7 Critical findings:   {rapid7_critical_count}")

    print(f"\n--- Open Findings Summary ---")
    print(f"  Total open findings:        {total_findings}")
    print(f"  Findings matching sources:  {len(matches)}")

    if matches:
        # Count by source
        source_counts = {}
        for m in matches:
            for src in m["matched_sources"]:
                source_counts[src] = source_counts.get(src, 0) + 1
        print(f"\n  Matches by source:")
        for src, count in sorted(source_counts.items()):
            print(f"    {src}: {count}")

    print(f"\n--- BOD 26-04 Risk Tier Distribution (All Findings) ---")
    for tier, count in tier_counts.items():
        pct = (count / total_findings * 100) if total_findings > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  {tier:<20} {count:>4} ({pct:>5.1f}%) {bar}")

    if matches:
        print(f"\n--- Matched Findings Detail ---")
        print(f"{'CVE':<20} {'Host':<12} {'IP':<16} {'Tier':<18} {'CVSS':<6} {'Sources'}")
        print("-" * 90)
        for m in sorted(matches, key=lambda x: x["risk_tier"]):
            sources = ", ".join(m["matched_sources"])
            print(
                f"{m['cve']:<20} "
                f"{(m['hostname'] or 'N/A'):<12} "
                f"{(m['ip'] or 'N/A'):<16} "
                f"{m['risk_tier']:<18} "
                f"{m['cvss_v3'] or 'N/A':<6} "
                f"{sources}"
            )
    else:
        print("\n✓ No open findings match any exploitation intelligence source.")

    print("\n" + "=" * 70)


def save_json(matches: list, tier_counts: dict, output_path: str,
              cisa_count: int, vulncheck_count: int, rapid7_critical_count: int):
    """Save report as JSON."""
    report = {
        "generated": datetime.now().isoformat(),
        "sources": {
            "cisa_kev_count": cisa_count,
            "vulncheck_kev_count": vulncheck_count,
            "rapid7_critical_count": rapid7_critical_count,
        },
        "matched_findings_count": len(matches),
        "tier_distribution": tier_counts,
        "matched_findings": matches,
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nJSON report saved: {output_path}")


def save_csv(matches: list, output_path: str):
    """Save matched findings as CSV."""
    import csv

    if not matches:
        print("No matches to save as CSV.")
        return

    # Flatten matched_sources list to string for CSV
    rows = []
    for m in matches:
        row = dict(m)
        row["matched_sources"] = "; ".join(row["matched_sources"])
        rows.append(row)

    fieldnames = rows[0].keys()
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV report saved: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cross-reference open vulnerabilities against CISA KEV, VulnCheck KEV, and Rapid7 Critical"
    )
    parser.add_argument(
        "--db", default=DB_PATH,
        help=f"Path to Rapid7 bulk export DuckDB (default: {DB_PATH})"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output JSON report path (optional)"
    )
    parser.add_argument(
        "--csv", default=None,
        help="Output CSV report path (optional)"
    )
    parser.add_argument(
        "--skip-vulncheck", action="store_true",
        help="Skip VulnCheck KEV lookup even if token is set"
    )

    args = parser.parse_args()

    # --- Source 1: CISA KEV ---
    cisa_data = download_cisa_kev()
    cisa_kev = extract_cisa_kev_cves(cisa_data)

    # --- Source 2: VulnCheck KEV ---
    if args.skip_vulncheck:
        vulncheck_kev = {}
        print("\n  ⚠ VulnCheck KEV skipped (--skip-vulncheck flag)")
    else:
        vulncheck_kev = download_vulncheck_kev()

    # Merge KEV sources (VulnCheck supplements CISA; CISA takes precedence on duplicates)
    combined_kev = {}
    combined_kev.update(vulncheck_kev)  # VulnCheck first (lower precedence)
    combined_kev.update(cisa_kev)       # CISA overwrites duplicates (higher precedence)
    print(f"\n  Combined unique KEV CVEs: {len(combined_kev)}")

    # --- Source 3: Rapid7 Critical ---
    rapid7_critical = query_rapid7_critical(args.db)

    # --- Query open findings ---
    findings = query_open_vulnerabilities(args.db)

    # --- Cross-reference ---
    matches = cross_reference(findings, combined_kev, rapid7_critical)

    # --- Classify all by tier ---
    tier_counts = classify_all_findings(findings, combined_kev, rapid7_critical)

    # --- Output ---
    print_summary(
        matches, tier_counts, len(findings),
        len(cisa_kev), len(vulncheck_kev), len(rapid7_critical)
    )

    if args.output:
        save_json(
            matches, tier_counts, args.output,
            len(cisa_kev), len(vulncheck_kev), len(rapid7_critical)
        )

    if args.csv:
        save_csv(matches, args.csv)


if __name__ == "__main__":
    main()
