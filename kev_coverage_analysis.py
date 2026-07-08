#!/usr/bin/env python3
"""
KEV Gap Detection Guide Generator

Generates an HTML report showing CISA KEV (and optionally VulnCheck KEV)
CVEs that InsightVM cannot detect, with alternative detection methods.

Usage:
  python3 kev_coverage_analysis.py                      # CISA KEV gaps only
  python3 kev_coverage_analysis.py --include-vulncheck  # CISA + VulnCheck gaps

Requirements: requests, psycopg2-binary, duckdb
"""

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

import duckdb
import psycopg2
import requests

# --- Config ---
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DUCKDB_PATH = "/Users/spassino/anothertry/metasploit-exploit-mapper/metasploit_module_cache.db"
DW_HOST = "127.0.0.1"
DW_PORT = 5433
DW_DB = "dhouse"
DW_USER = "mcp_readonly"
KEYCHAIN_SERVICE = "insightvm-warehouse"
KEYCHAIN_ACCOUNT = "mcp_readonly"
OUTPUT_PATH = "/Users/spassino/anothertry/kev_gap_detection_guide.html"


def get_dw_password():
    result = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        print("ERROR: Could not get DW password from Keychain.", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def fetch_cisa_kev():
    """Returns dict: cve_id -> {vendor, product, name, dateAdded, ransomware}"""
    print("[1] Fetching CISA KEV catalog...")
    resp = requests.get(CISA_KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    kev = {}
    for v in data.get("vulnerabilities", []):
        kev[v["cveID"]] = {
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
        }
    print(f"    CISA KEV: {len(kev)} CVEs")
    return kev


def fetch_vulncheck_kev():
    """Returns set of CVE IDs from VulnCheck KEV (DuckDB cache)."""
    print("[*] Loading VulnCheck KEV from DuckDB cache...")
    ddb = duckdb.connect(DUCKDB_PATH, read_only=True)
    rows = ddb.execute("SELECT cve_id FROM vulncheck_kev WHERE cve_id IS NOT NULL").fetchall()
    cves = set(r[0].upper() for r in rows)
    ddb.close()
    print(f"    VulnCheck KEV: {len(cves)} CVEs")
    return cves


def query_ivm_coverage(cve_list):
    """Query DW to find which CVEs IVM has checks for. Returns set of covered CVEs."""
    pw = get_dw_password()
    conn = psycopg2.connect(host=DW_HOST, port=DW_PORT, database=DW_DB, user=DW_USER, password=pw, sslmode="disable")
    cur = conn.cursor()

    covered = set()
    for i in range(0, len(cve_list), 200):
        chunk = cve_list[i:i+200]
        placeholders = ",".join(["%s"] * len(chunk))
        cur.execute(f"SELECT DISTINCT reference FROM dim_vulnerability_reference WHERE source = 'CVE' AND reference IN ({placeholders})", chunk)
        for row in cur.fetchall():
            covered.add(row[0])

    conn.close()
    return covered


def categorize_detection(cve_id, vendor, product):
    """Assign detection category and method based on vendor/product."""
    v = vendor.lower()
    p = product.lower()

    if v in ('samsung', 'qualcomm', 'android', 'arm', 'google', 'meta platforms'):
        return 'Mobile/Chipset', 'MDM/EMM Query', f'Query MDM for {vendor} devices below patched firmware/OS version'
    if v == 'apple':
        return 'Apple/macOS/iOS', 'MDM + Agent', f'MDM query for Apple {product} below security update'
    if v in ('zyxel', 'd-link', 'netgear', 'tenda', 'cisco', 'ubiquiti', 'realtek', 'tp-link', 'draytek'):
        return 'Network Device/Firmware', 'db_nmap Banner Grab', f'db_nmap -sV -p 80,443,8080 --script http-title &lt;subnet&gt;'
    if v in ('gigabyte', 'intel', 'amd'):
        return 'Firmware/BIOS/Driver', 'Software Inventory', f'DW: dim_asset_software WHERE software LIKE \'%{v}%\''
    if v == 'microsoft':
        return 'Windows Kernel/Driver', 'Patch Verification', f'WSUS/SCCM/Intune patch compliance for {cve_id}'
    if v == 'sap':
        return 'Enterprise Application', 'App Version Check', f'db_nmap -sV -p 3200-3299,8000-8099 &lt;sap_hosts&gt;'
    if v in ('reolink', 'hikvision', 'dahua'):
        return 'IoT/Camera', 'RTSP/HTTP Fingerprint', f'db_nmap -sV -p 80,443,554 --script http-title &lt;iot_subnet&gt;'
    if v in ('fortra', 'progress', 'ivanti', 'citrix', 'atlassian', 'vmware'):
        return 'Enterprise Software', 'Version + Software Query', f'db_nmap -sV -p 443,8443 --script http-title,ssl-cert &lt;hosts&gt;'
    return 'Other', 'Service Detection', f'db_nmap -sV &lt;target&gt; + DW software query for {vendor}'


def main():
    parser = argparse.ArgumentParser(description="KEV Gap Detection Guide")
    parser.add_argument("--include-vulncheck", action="store_true", help="Include VulnCheck KEV gaps")
    args = parser.parse_args()

    # Fetch CISA KEV
    cisa_kev = fetch_cisa_kev()
    cisa_cve_set = set(cisa_kev.keys())

    # Check IVM coverage of CISA KEV
    print("[2] Querying IVM coverage of CISA KEV...")
    cisa_covered = query_ivm_coverage(list(cisa_cve_set))
    cisa_gaps = cisa_cve_set - cisa_covered
    print(f"    CISA: {len(cisa_covered)}/{len(cisa_cve_set)} covered ({len(cisa_covered)/len(cisa_cve_set)*100:.1f}%), {len(cisa_gaps)} gaps")

    # Build gap entries for CISA
    gap_entries = []
    for cve in sorted(cisa_gaps):
        info = cisa_kev[cve]
        cat, method, cmd = categorize_detection(cve, info['vendor'], info['product'])
        gap_entries.append({
            'cve_id': cve, 'source': 'CISA KEV',
            'vendor': info['vendor'], 'product': info['product'],
            'name': info['name'], 'date_added': info['date_added'],
            'ransomware': info['ransomware'],
            'category': cat, 'method': method, 'command': cmd,
        })

    # Optionally add VulnCheck
    vc_gaps_count = 0
    vc_total = 0
    if args.include_vulncheck:
        vc_cves = fetch_vulncheck_kev()
        vc_only = vc_cves - cisa_cve_set
        vc_total = len(vc_only)
        print(f"[3] Querying IVM coverage of VulnCheck-only KEV ({len(vc_only)} CVEs)...")
        vc_covered = query_ivm_coverage(list(vc_only))
        vc_gap_set = vc_only - vc_covered
        vc_gaps_count = len(vc_gap_set)
        print(f"    VulnCheck-only: {len(vc_covered)}/{len(vc_only)} covered ({len(vc_covered)/len(vc_only)*100:.1f}%), {vc_gaps_count} gaps")

        # Add VC gap entries (no product detail available from VC, just CVE ID)
        for cve in sorted(vc_gap_set):
            gap_entries.append({
                'cve_id': cve, 'source': 'VulnCheck KEV',
                'vendor': '—', 'product': '—',
                'name': '', 'date_added': '',
                'ransomware': 'Unknown',
                'category': 'Unknown (VulnCheck)', 'method': 'Research Required',
                'command': f'# Look up {cve} in NVD for affected product, then scan accordingly',
            })

    # Stats
    cats = Counter(e['category'] for e in gap_entries)
    total_gaps = len(gap_entries)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scope = "CISA KEV + VulnCheck KEV" if args.include_vulncheck else "CISA KEV Only"

    print(f"\n[*] Total gap entries: {total_gaps}")
    print(f"    Report scope: {scope}")

    # Generate HTML
    # Group CISA entries by category
    cisa_entries = [e for e in gap_entries if e['source'] == 'CISA KEV']
    vc_entries = [e for e in gap_entries if e['source'] == 'VulnCheck KEV']

    cisa_cats = Counter(e['category'] for e in cisa_entries)

    table_rows = ""
    # CISA section
    category_order = ['Network Device/Firmware', 'Enterprise Software', 'Enterprise Application',
                      'Windows Kernel/Driver', 'Firmware/BIOS/Driver', 'IoT/Camera',
                      'Apple/macOS/iOS', 'Mobile/Chipset', 'Other']

    for cat in category_order:
        items = [e for e in cisa_entries if e['category'] == cat]
        if not items:
            continue
        table_rows += f'<tr style="background:#e9ecef;"><td colspan="7"><strong>CISA KEV — {cat} ({len(items)})</strong></td></tr>\n'
        for r in sorted(items, key=lambda x: x['ransomware'] == 'Known', reverse=True):
            rw = "&#9888;&#65039;" if r['ransomware'] == 'Known' else ""
            table_rows += f'<tr><td><code>{r["cve_id"]}</code></td><td>{r["vendor"]}</td><td>{r["product"]}</td><td>{r["method"]}</td><td style="font-size:0.8em;"><code>{r["command"]}</code></td><td>{r["source"]}</td><td>{rw}</td></tr>\n'

    if vc_entries:
        table_rows += f'<tr style="background:#fff3cd;"><td colspan="7"><strong>VulnCheck KEV — Additional Gaps ({len(vc_entries)})</strong></td></tr>\n'
        for r in vc_entries[:100]:  # Limit display
            table_rows += f'<tr><td><code>{r["cve_id"]}</code></td><td>—</td><td>—</td><td>{r["method"]}</td><td style="font-size:0.8em;"><code>{r["command"]}</code></td><td>{r["source"]}</td><td></td></tr>\n'
        if len(vc_entries) > 100:
            table_rows += f'<tr><td colspan="7"><em>... and {len(vc_entries)-100} more VulnCheck-only gaps</em></td></tr>\n'

    vc_summary_row = ""
    if args.include_vulncheck:
        vc_summary_row = f'<tr><td><strong>VulnCheck-only KEV</strong></td><td>{vc_total:,}</td><td>{vc_total - vc_gaps_count:,}</td><td style="color:#dc3545;">{vc_gaps_count:,}</td><td><strong>{(vc_total - vc_gaps_count)/vc_total*100:.1f}%</strong></td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KEV Gap Detection Guide</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }}
    .container {{ max-width: 1600px; margin: 0 auto; }}
    h1 {{ color: #003366; border-bottom: 3px solid #003366; padding-bottom: 10px; }}
    h2 {{ color: #003366; margin-top: 30px; }}
    .meta {{ color: #6c757d; font-size: 0.9em; margin-bottom: 20px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin: 20px 0; }}
    .summary-card {{ background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    .summary-card .value {{ font-size: 2em; font-weight: bold; color: #003366; }}
    .summary-card .label {{ font-size: 0.85em; color: #6c757d; margin-top: 5px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); font-size: 0.8em; }}
    th {{ background: #003366; color: white; padding: 10px 6px; text-align: left; }}
    td {{ padding: 6px; border-bottom: 1px solid #dee2e6; vertical-align: top; }}
    tr:hover {{ background: #f1f3f5; }}
    code {{ background: #e9ecef; padding: 2px 4px; border-radius: 3px; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6; font-size: 0.8em; color: #6c757d; }}
</style>
</head>
<body>
<div class="container">
<h1>KEV Detection Gaps — Alternative Detection Guide</h1>
<p class="meta"><strong>Generated:</strong> {now}<br>
<strong>Scope:</strong> {scope}<br>
<strong>Purpose:</strong> Alternative detection methods for KEV CVEs that InsightVM cannot directly check</p>

<h2>Coverage Summary</h2>
<table>
<thead><tr><th>Catalog</th><th>Total CVEs</th><th>IVM Covers</th><th>Gaps</th><th>Coverage</th></tr></thead>
<tbody>
<tr><td><strong>CISA KEV</strong></td><td>{len(cisa_cve_set):,}</td><td>{len(cisa_covered):,}</td><td style="color:#dc3545;">{len(cisa_gaps)}</td><td><strong>{len(cisa_covered)/len(cisa_cve_set)*100:.1f}%</strong></td></tr>
{vc_summary_row}
</tbody>
</table>

<h2>CISA KEV Gaps by Category</h2>
<div class="summary-grid">
    <div class="summary-card"><div class="value">{len(cisa_gaps)}</div><div class="label">CISA Gaps</div></div>
    <div class="summary-card"><div class="value">{cisa_cats.get('Network Device/Firmware',0)}</div><div class="label">Network Devices</div></div>
    <div class="summary-card"><div class="value">{cisa_cats.get('Mobile/Chipset',0)}</div><div class="label">Mobile/Chipset</div></div>
    <div class="summary-card"><div class="value">{cisa_cats.get('Enterprise Software',0)+cisa_cats.get('Enterprise Application',0)}</div><div class="label">Enterprise Apps</div></div>
    <div class="summary-card"><div class="value">{vc_gaps_count if args.include_vulncheck else '—'}</div><div class="label">VulnCheck-only Gaps</div></div>
</div>

<h2>Detection Guide</h2>
<table>
<thead><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Method</th><th>Command/Query</th><th>Source</th><th>RW</th></tr></thead>
<tbody>
{table_rows}
</tbody>
</table>

<div class="footer">
<p><strong>Scope:</strong> {scope} | <strong>RW:</strong> &#9888;&#65039; = Known ransomware<br>
<strong>Data:</strong> CISA KEV JSON feed, VulnCheck KEV (DuckDB cache), InsightVM Data Warehouse (dim_vulnerability_reference)</p>
</div>
</div>
</body>
</html>"""

    with open(OUTPUT_PATH, 'w') as f:
        f.write(html)
    print(f"\n[OK] Report saved: {OUTPUT_PATH}")
    print(f"     Total gaps: {total_gaps} ({len(cisa_gaps)} CISA + {vc_gaps_count} VulnCheck-only)")


if __name__ == "__main__":
    main()
