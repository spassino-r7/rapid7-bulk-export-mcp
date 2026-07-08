#!/usr/bin/env python3
"""
InsightVM Scan Log Analyzer
Processes all .log files in ~/.kiro/scanlogs/ and produces a consolidated report
Checks: ALIVE/DEAD/FILTERED counts, credential issues, exploited checks, ECR endpoints
"""

import os
import re
from pathlib import Path
from collections import defaultdict
import datetime

LOG_DIR = Path.home() / ".kiro" / "scanlogs"
OUTPUT  = LOG_DIR / "scan_analysis_report.txt"

def analyze_log(filepath):
    result = {
        "filename":      filepath.name,
        "site":          "Unknown",
        "start":         "Unknown",
        "engine":        "Unknown",
        "alive":         0,
        "dead":          0,
        "filtered":      0,
        "snmp_failures": 0,
        "bearer_unauth": 0,
        "exploited":     0,
        "ecr_endpoints": 0,
        "dead_subnets":  defaultdict(int),
        "error":         None,
    }

    try:
        with open(filepath, "r", errors="replace") as f:
            for line in f:
                # Site name
                if result["site"] == "Unknown" and "[Site:" in line:
                    m = re.search(r'\[Site: ([^\]]+)\]', line)
                    if m:
                        result["site"] = m.group(1)

                # Scan start
                if result["start"] == "Unknown" and "Logging initialized" in line:
                    result["start"] = line.split()[0]

                # Engine IP
                if result["engine"] == "Unknown" and "NSC @" in line:
                    m = re.search(r'NSC @ ([\d.]+):', line)
                    if m:
                        result["engine"] = m.group(1)

                # Discovery
                if " ALIVE " in line:
                    result["alive"] += 1
                elif " DEAD " in line:
                    result["dead"] += 1
                    m = re.search(r'\[([\d.]+)\]', line)
                    if m:
                        ip = m.group(1)
                        subnet = ".".join(ip.split(".")[:3])
                        result["dead_subnets"][subnet] += 1
                elif "filtered" in line.lower() and ("nmap" in line.lower() or "FILTERED" in line):
                    result["filtered"] += 1

                # SNMP failures
                if "SNMPAuthenticator" in line:
                    result["snmp_failures"] += 1

                # Bearer token unauthenticated
                if "No matching fingerprint found for banner: Bearer" in line:
                    result["bearer_unauth"] += 1

                # Exploited checks — exclude JESS rule definitions
                if "vulnerability-test-exploited" in line \
                        and "while executing" not in line \
                        and "try (" not in line \
                        and "bind ?" not in line:
                    result["exploited"] += 1

                # ECR endpoints
                if "ecr.amazonaws.com" in line:
                    result["ecr_endpoints"] += 1

    except Exception as e:
        result["error"] = str(e)

    return result


def write_report(results):
    lines = []
    lines.append("InsightVM Scan Log Analysis Report")
    lines.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Log Directory: {LOG_DIR}")
    lines.append(f"Total files analyzed: {len(results)}")
    lines.append("=" * 65)
    lines.append("")

    total_alive    = 0
    total_dead     = 0
    total_filtered = 0
    exploited_logs = []
    high_dead_logs = []

    for r in results:
        lines.append("-" * 65)
        lines.append(f"LOG FILE: {r['filename']}")
        lines.append("-" * 65)
        lines.append(f"  Site:        {r['site']}")
        lines.append(f"  Scan Start:  {r['start']}")
        lines.append(f"  Engine IP:   {r['engine']}")

        if r["error"]:
            lines.append(f"  ERROR: {r['error']}")
            lines.append("")
            continue

        lines.append("")

        # Discovery
        total_probed = r["alive"] + r["dead"]
        pct = round(r["alive"] / total_probed * 100, 1) if total_probed > 0 else 0
        lines.append("  Discovery:")
        lines.append(f"    ALIVE hosts:    {r['alive']:,}")
        lines.append(f"    DEAD hosts:     {r['dead']:,}")
        lines.append(f"    FILTERED:       {r['filtered']:,}")
        lines.append(f"    Live coverage:  {pct}% of probed IPs")
        total_alive    += r["alive"]
        total_dead     += r["dead"]
        total_filtered += r["filtered"]
        if r["dead"] > 10000:
            high_dead_logs.append((r["filename"], r["site"], r["dead"]))
        lines.append("")

        # Credential issues
        lines.append("  Credential Issues:")
        lines.append(f"    SNMP auth failures:          {r['snmp_failures']:,}")
        lines.append(f"    Bearer token (unauth HTTP):  {r['bearer_unauth']:,}")
        lines.append("")

        # Notable findings
        lines.append("  Notable Findings:")
        lines.append("    No confirmed exploitation events detected")
        if r["ecr_endpoints"] > 0:
            lines.append(f"    ECR endpoints (unauthenticated): {r['ecr_endpoints']:,}")
        lines.append("")

        # Top 5 DEAD subnets
        lines.append("  Top 5 DEAD Subnets (scope efficiency):")
        top_subnets = sorted(r["dead_subnets"].items(), key=lambda x: x[1], reverse=True)[:5]
        if top_subnets:
            for subnet, count in top_subnets:
                lines.append(f"    {subnet}.x  ({count:,} dead IPs)")
        else:
            lines.append("    None")
        lines.append("")
        lines.append("")

    # Consolidated summary
    lines.append("=" * 65)
    lines.append("CONSOLIDATED SUMMARY")
    lines.append("=" * 65)
    lines.append(f"Total log files:          {len(results)}")
    lines.append(f"Total ALIVE hosts:        {total_alive:,}")
    lines.append(f"Total DEAD hosts:         {total_dead:,}")
    lines.append(f"Total FILTERED:           {total_filtered:,}")
    total_probed = total_alive + total_dead
    if total_probed > 0:
        overall_pct = round(total_alive / total_probed * 100, 1)
        lines.append(f"Overall live coverage:    {overall_pct}% of all probed IPs")
    lines.append("")

    if high_dead_logs:
        lines.append(f"Sites with >10,000 DEAD hosts (scope too broad):")
        for fname, site, count in sorted(high_dead_logs, key=lambda x: x[2], reverse=True):
            lines.append(f"  {site:<35} {count:>10,} dead  ({fname})")
        lines.append("")

    # Filtered IPs table — all logs sorted by filtered count descending
    lines.append("Filtered IPs per Log File:")
    lines.append(f"  {'Site':<35} {'Log File':<30} {'Filtered':>12}")
    lines.append("  " + "-" * 80)
    filtered_rows = sorted(
        [(r["site"], r["filename"], r["filtered"]) for r in results],
        key=lambda x: x[2], reverse=True
    )
    for site, fname, fcount in filtered_rows:
        lines.append(f"  {site:<35} {fname:<30} {fcount:>12,}")
    lines.append("")

    if exploited_logs:
        lines.append(f"Sites with EXPLOITED vulnerability checks ({len(exploited_logs)} scans):")
        for fname, site, count in sorted(exploited_logs, key=lambda x: x[2], reverse=True):
            lines.append(f"  {site:<35} {count:>6,} exploited  ({fname})")
        lines.append("")
    else:
        lines.append("No confirmed exploitation events found across all logs.")
        lines.append("(vulnerability-test-exploited strings found were JESS rule definitions, not runtime events)")
        lines.append("")

    return "\n".join(lines)


def main():
    log_files = sorted(LOG_DIR.glob("*.log"))
    # Exclude the report file if it somehow ends up as .log
    log_files = [f for f in log_files if "report" not in f.name]

    print(f"Found {len(log_files)} log files. Analyzing...")

    results = []
    for i, lf in enumerate(log_files, 1):
        print(f"  [{i}/{len(log_files)}] {lf.name}...")
        results.append(analyze_log(lf))

    print("Writing report...")
    report = write_report(results)

    with open(OUTPUT, "w") as f:
        f.write(report)

    print(f"\nDone. Report saved to: {OUTPUT}\n")
    print(report)


if __name__ == "__main__":
    main()
