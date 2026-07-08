#!/usr/bin/env python3
"""
Real-Time BOD 26-04 Report with Cloud API v4 Supplement

This script combines:
1. Bulk Export data (baseline, comprehensive)
2. Cloud API v4 real-time supplement (same-day findings)

It deduplicates on (assetId + vulnId) and produces a merged dataset
that feeds into the BOD 26-04 compliance report.

Requirements:
  pip install requests

Environment variables:
  RAPID7_API_KEY  - Your Rapid7 Insight Platform API key
  RAPID7_REGION   - Your region (e.g., us, us2, us3, eu, ca, au, ap)

Usage:
  python3 realtime_bod_report.py
  python3 realtime_bod_report.py --cloud-only    # Skip bulk export, use only Cloud API
  python3 realtime_bod_report.py --output report.json  # Save merged findings to JSON
"""

import os
import sys
import json
import argparse
import requests
from datetime import datetime, timezone
from typing import Optional


# --- Configuration ---

API_KEY = os.environ.get("RAPID7_API_KEY", "11646e02-04ae-4487-901d-839d604ace6a")
REGION = os.environ.get("RAPID7_REGION", "us3")
BASE_URL = f"https://{REGION}.api.insight.rapid7.com/vm/v4/integration"

HEADERS = {
    "X-Api-Key": API_KEY,
    "Content-Type": "application/json",
}


# --- Cloud API v4 Functions ---

def fetch_all_assets_with_vulns(page_size: int = 50) -> list:
    """
    Fetch all assets from Cloud API v4 with vulnerability details.
    Uses the includeSame=true parameter to get full vuln list per asset.
    """
    all_assets = []
    page = 0

    while True:
        url = f"{BASE_URL}/assets?size={page_size}&page={page}&includeSame=true"
        resp = requests.post(url, headers=HEADERS, json={})

        if resp.status_code != 200:
            print(f"[ERROR] Cloud API returned {resp.status_code}: {resp.text}")
            break

        data = resp.json()
        assets = data.get("data", [])
        if not assets:
            break

        all_assets.extend(assets)
        print(f"  Fetched page {page} — {len(assets)} assets (total: {len(all_assets)})")

        # Check if there are more pages
        metadata = data.get("metadata", {})
        total_pages = metadata.get("total_pages", 1)
        if page >= total_pages - 1:
            break
        page += 1

    return all_assets


def extract_findings_from_cloud_api(assets: list) -> list:
    """
    Extract vulnerability findings from Cloud API asset data.
    Returns a list of normalized finding dicts.
    """
    findings = []

    for asset in assets:
        asset_id = asset.get("id", "")
        hostname = asset.get("host_name", "")
        ip = asset.get("ip", "")
        os_desc = asset.get("os_description", "")

        # "same" contains current vulnerabilities
        vulns = asset.get("same", [])
        # "new" contains newly found vulnerabilities (since last scan)
        new_vulns = asset.get("new", [])

        for vuln in vulns + new_vulns:
            vuln_id = vuln.get("vulnerability_id", "")
            first_found = vuln.get("first_found", "")
            last_found = vuln.get("last_found", "")
            port = vuln.get("port")
            protocol = vuln.get("protocol", "")
            status = vuln.get("status", "")
            solution_summary = vuln.get("solution_summary", "")
            solution_type = vuln.get("solution_type", "")
            proof = vuln.get("proof", "")

            findings.append({
                "source": "cloud_api_v4",
                "asset_id": asset_id,
                "hostname": hostname,
                "ip": ip,
                "os_description": os_desc,
                "vuln_id": vuln_id,
                "first_found": first_found,
                "last_found": last_found,
                "port": port,
                "protocol": protocol,
                "status": status,
                "solution_summary": solution_summary,
                "solution_type": solution_type,
            })

    return findings


def extract_cve_from_vuln_id(vuln_id: str) -> str:
    """
    Extract CVE from vulnerability ID.
    InsightVM vuln IDs follow patterns like:
      - ubuntu-cve-2024-35195
      - azul-zulu-cve-2026-21945
      - apache-log4j-core-cve-2021-44228
      - openbsd-openssh-cve-2025-61984
    """
    import re
    match = re.search(r'cve-(\d{4}-\d+)', vuln_id, re.IGNORECASE)
    if match:
        return f"CVE-{match.group(1)}"
    return ""


def fetch_vulnerability_details(vuln_ids: list) -> dict:
    """
    Build vulnerability metadata from vuln IDs.
    Extracts CVEs from the ID naming convention and fetches details
    from the catalog for enrichment where possible.
    """
    vuln_details = {}

    print(f"\n[*] Resolving CVEs for {len(vuln_ids)} unique vuln IDs...")

    # First pass: extract CVEs from vuln ID naming convention
    for vid in vuln_ids:
        cve = extract_cve_from_vuln_id(vid)
        vuln_details[vid] = {
            "title": vid.replace("-", " ").title(),
            "severity": "",
            "cvss_v3_score": None,
            "cves": cve,
            "risk_score": None,
            "exploits": [],
            "published": "",
        }

    # Second pass: fetch from catalog for those we can find (first few pages)
    resolved = sum(1 for v in vuln_details.values() if v["cves"])
    print(f"  Extracted CVEs from naming convention: {resolved}/{len(vuln_ids)}")

    # Try to enrich from catalog (limited pages to avoid timeout)
    target_ids = set(vuln_ids)
    found_ids = set()
    max_pages = 20  # Limit catalog scan

    for page in range(max_pages):
        url = f"{BASE_URL}/vulnerabilities?size=500&page={page}"
        resp = requests.post(url, headers=HEADERS, json={})

        if resp.status_code != 200:
            break

        data = resp.json()
        vulns = data.get("data", [])
        if not vulns:
            break

        for v in vulns:
            vid = v.get("id", "")
            if vid in target_ids and vid not in found_ids:
                cves_from_catalog = v.get("cves", "")
                vuln_details[vid] = {
                    "title": v.get("title", ""),
                    "severity": v.get("severity", ""),
                    "cvss_v3_score": v.get("cvss_v3_score"),
                    "cves": cves_from_catalog or vuln_details[vid]["cves"],
                    "risk_score": v.get("risk_score"),
                    "exploits": v.get("exploits", []),
                    "published": v.get("published", ""),
                }
                found_ids.add(vid)

        if len(found_ids) == len(target_ids):
            break

        metadata = data.get("metadata", {})
        total_pages = metadata.get("total_pages", 1)
        if page >= total_pages - 1:
            break

    print(f"  Enriched from catalog: {len(found_ids)}/{len(vuln_ids)}")
    return vuln_details


# --- Merge & Deduplicate ---

def merge_with_bulk_export(cloud_findings: list, bulk_export_findings: Optional[list] = None) -> list:
    """
    Merge Cloud API findings with bulk export data.
    Deduplicates on (asset_id, vuln_id) — Cloud API wins for freshness.
    """
    merged = {}

    # Load bulk export baseline first
    if bulk_export_findings:
        for f in bulk_export_findings:
            key = (f.get("asset_id", ""), f.get("vuln_id", ""))
            f["source"] = "bulk_export"
            merged[key] = f

    # Overlay Cloud API findings (overwrites if same key exists)
    for f in cloud_findings:
        key = (f.get("asset_id", ""), f.get("vuln_id", ""))
        merged[key] = f  # Cloud API takes priority (more recent)

    return list(merged.values())


# --- Report Output ---

def generate_bod_input(findings: list, vuln_details: dict) -> list:
    """
    Generate the input format expected by the BOD 26-04 compliance report tool.
    Returns list of dicts with: cve_id, asset_id, hostname, ip, severity, title, first_found
    """
    bod_findings = []

    for f in findings:
        vuln_id = f.get("vuln_id", "")
        details = vuln_details.get(vuln_id, {})

        cves_raw = details.get("cves", "")
        # cves can be comma-separated string or single CVE
        if cves_raw:
            cves = [c.strip() for c in cves_raw.split(",") if c.strip().startswith("CVE-")]
        else:
            cves = []

        if not cves:
            continue  # BOD report requires CVEs

        severity = details.get("severity", f.get("severity", "unknown"))
        title = details.get("title", vuln_id)

        first_found = f.get("first_found", "")
        if first_found:
            # Normalize to date string
            first_found_date = first_found[:10]
        else:
            first_found_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        for cve in cves:
            bod_findings.append({
                "cve_id": cve,
                "asset_id": f.get("asset_id", ""),
                "hostname": f.get("hostname", ""),
                "ip": f.get("ip", ""),
                "severity": severity.capitalize(),
                "title": title,
                "first_found": first_found_date,
            })

    return bod_findings


def print_summary(findings: list, cloud_findings: list, bod_input: list):
    """Print a summary of what was found."""
    cloud_only = [f for f in findings if f.get("source") == "cloud_api_v4"]
    bulk_only = [f for f in findings if f.get("source") == "bulk_export"]

    print("\n" + "=" * 60)
    print("REAL-TIME BOD REPORT — DATA SUMMARY")
    print("=" * 60)
    print(f"  Cloud API v4 findings:  {len(cloud_only)}")
    print(f"  Bulk Export findings:   {len(bulk_only)}")
    print(f"  Merged (deduplicated):  {len(findings)}")
    print(f"  BOD-eligible (w/ CVE):  {len(bod_input)}")
    print(f"  Unique CVEs:            {len(set(f['cve_id'] for f in bod_input))}")
    print(f"  Assets affected:        {len(set(f['asset_id'] for f in bod_input))}")
    print("=" * 60)

    # Show new findings not in bulk export
    cloud_keys = set((f["asset_id"], f["vuln_id"]) for f in cloud_only)
    bulk_keys = set((f.get("asset_id", ""), f.get("vuln_id", "")) for f in bulk_only)
    new_from_cloud = cloud_keys - bulk_keys

    if new_from_cloud:
        print(f"\n[!] {len(new_from_cloud)} NEW findings from Cloud API (not in bulk export):")
        for f in cloud_only:
            key = (f["asset_id"], f["vuln_id"])
            if key in new_from_cloud:
                print(f"    • {f['hostname'] or f['ip']} — {f['vuln_id']} (found {f['first_found'][:10]})")


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Real-Time BOD 26-04 Report with Cloud API v4")
    parser.add_argument("--cloud-only", action="store_true",
                       help="Use only Cloud API data (skip bulk export)")
    parser.add_argument("--output", "-o", type=str, default=None,
                       help="Save BOD findings to JSON file")
    parser.add_argument("--bulk-export-file", type=str, default=None,
                       help="Path to bulk export findings JSON (for merging)")
    args = parser.parse_args()

    print("[*] Real-Time BOD 26-04 Report Generator")
    print(f"    Region: {REGION}")
    print(f"    Cloud API: {BASE_URL}")
    print(f"    Timestamp: {datetime.now(timezone.utc).isoformat()}")

    # Step 1: Fetch Cloud API data
    print("\n[1] Fetching assets from Cloud API v4...")
    assets = fetch_all_assets_with_vulns()
    print(f"    Total assets retrieved: {len(assets)}")

    # Filter to only assets with vulnerabilities
    vuln_assets = [a for a in assets if a.get("total_vulnerabilities", 0) > 0]
    print(f"    Assets with vulnerabilities: {len(vuln_assets)}")

    # Step 2: Extract findings
    print("\n[2] Extracting vulnerability findings...")
    cloud_findings = extract_findings_from_cloud_api(vuln_assets)
    print(f"    Cloud API findings: {len(cloud_findings)}")

    # Step 3: Get unique vuln IDs and fetch details
    unique_vuln_ids = list(set(f["vuln_id"] for f in cloud_findings))
    vuln_details = fetch_vulnerability_details(unique_vuln_ids)

    # Step 4: Merge with bulk export (if available)
    bulk_findings = None
    if args.bulk_export_file and not args.cloud_only:
        print(f"\n[3] Loading bulk export data from {args.bulk_export_file}...")
        with open(args.bulk_export_file) as f:
            bulk_findings = json.load(f)
        print(f"    Bulk export findings: {len(bulk_findings)}")

    print("\n[4] Merging and deduplicating...")
    merged_findings = merge_with_bulk_export(cloud_findings, bulk_findings)

    # Step 5: Generate BOD input
    print("\n[5] Generating BOD 26-04 input...")
    bod_input = generate_bod_input(merged_findings, vuln_details)

    # Step 6: Summary
    print_summary(merged_findings, cloud_findings, bod_input)

    # Step 7: Output
    if args.output:
        output_data = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "source": "cloud_api_v4" if args.cloud_only else "hybrid",
            "region": REGION,
            "summary": {
                "total_findings": len(merged_findings),
                "bod_eligible": len(bod_input),
                "unique_cves": len(set(f["cve_id"] for f in bod_input)),
                "assets_affected": len(set(f["asset_id"] for f in bod_input)),
            },
            "bod_findings": bod_input,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"\n[✓] BOD findings saved to: {args.output}")
    else:
        # Print BOD findings to stdout
        print("\n[✓] BOD 26-04 Findings (ready for enrichment):")
        print(json.dumps(bod_input, indent=2))

    return bod_input


if __name__ == "__main__":
    main()
