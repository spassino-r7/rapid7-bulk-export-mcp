#!/usr/bin/env python3
"""Generate HTML report for KEV/Metasploit/IVM blind spot analysis."""

import json
from datetime import datetime

with open('kev_msf_ivm_blind_spots.json') as f:
    blind_spots = json.load(f)

print(f"Loaded {len(blind_spots)} blind spots, generating report...")

rows_html = ""
for bs in blind_spots:
    cve = bs['cve_id']
    vendor = bs['kev']['vendor']
    product = bs['kev']['product']
    date_added = bs['kev']['dateAdded']
    modules = bs['modules']
    top_rank = max(m.get('rank', 0) for m in modules)
    rank_name = next((m['rank_name'] for m in modules if m.get('rank') == top_rank), 'Normal')

    if rank_name == 'Excellent':
        rank_class = 'rank-excellent'
    elif rank_name == 'Great':
        rank_class = 'rank-great'
    else:
        rank_class = 'rank-normal'

    mod_html = '<br>'.join(f'<span class="module-path">{m["path"]}</span>' for m in modules)

    rows_html += f"""<tr>
<td><a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a></td>
<td><strong>{vendor}</strong><br>{product}</td>
<td>{mod_html}</td>
<td><span class="{rank_class}">{rank_name}</span></td>
<td>{date_added}</td>
</tr>
"""

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Metasploit vs IVM Blind Spot Analysis — CISA KEV</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #1a1a1a; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ color: #1a1a1a; border-bottom: 3px solid #e63946; padding-bottom: 10px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }}
  .stat-card {{ background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .stat-card .number {{ font-size: 2.2em; font-weight: bold; }}
  .stat-card .label {{ color: #666; margin-top: 4px; font-size: 0.9em; }}
  .blind {{ color: #e63946; }}
  .covered {{ color: #2a9d8f; }}
  .info {{ color: #457b9d; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  th {{ background: #264653; color: white; padding: 12px 16px; text-align: left; font-weight: 600; }}
  td {{ padding: 12px 16px; border-bottom: 1px solid #eee; vertical-align: top; }}
  tr:hover {{ background: #f8f9fa; }}
  .rank-excellent {{ background: #e63946; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
  .rank-great {{ background: #f4a261; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
  .rank-normal {{ background: #6c757d; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
  .module-path {{ font-family: monospace; font-size: 0.85em; color: #457b9d; }}
  .takeaway {{ background: #fff3cd; border-left: 4px solid #f4a261; padding: 16px; margin: 20px 0; border-radius: 0 8px 8px 0; }}
  .summary {{ background: white; border-radius: 8px; padding: 24px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .venn {{ background: white; border-radius: 8px; padding: 24px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .venn-item {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
  .venn-item:last-child {{ border-bottom: none; }}
  .footer {{ margin-top: 30px; padding: 16px; color: #666; font-size: 0.85em; text-align: center; }}
</style>
</head>
<body>
<div class="container">
<h1>Metasploit vs IVM Blind Spot Analysis</h1>
<p style="color:#666;">CISA KEV CVEs with Metasploit exploit modules but no InsightVM detection</p>

<div class="stats">
  <div class="stat-card"><div class="number info">1,661</div><div class="label">CISA KEV CVEs</div></div>
  <div class="stat-card"><div class="number info">434</div><div class="label">KEV with Metasploit</div></div>
  <div class="stat-card"><div class="number covered">426</div><div class="label">Covered by IVM (98.2%)</div></div>
  <div class="stat-card"><div class="number blind">8</div><div class="label">BLIND SPOTS</div></div>
</div>

<div class="takeaway">
<strong>Key Finding:</strong> InsightVM covers 98.2% of CISA KEV CVEs that also have Metasploit exploits (426 of 434). The 8 blind spots are exclusively network device vulnerabilities (D-Link, NETGEAR, Zyxel, Realtek, Palo Alto) and one application server (IBM Planning Analytics) that require firmware-level scanning or network-based detection not available via standard IVM host checks.
</div>

<div class="venn">
<h3>Coverage Breakdown</h3>
<div class="venn-item"><strong>CISA KEV total:</strong> 1,661 known exploited vulnerabilities</div>
<div class="venn-item"><strong>KEV with Metasploit modules:</strong> 434 (26.1%) — weaponized and trivially exploitable</div>
<div class="venn-item"><strong>KEV + Metasploit + IVM detection:</strong> 426 (98.2%) — scanner will catch these</div>
<div class="venn-item"><strong>KEV + Metasploit - IVM detection:</strong> <span class="blind"><strong>8 blind spots</strong></span> — exploitable but invisible to scans</div>
</div>

<h2>Blind Spot Details</h2>
<table>
<thead>
<tr><th>CVE</th><th>Vendor / Product</th><th>Metasploit Module(s)</th><th>Rank</th><th>KEV Added</th></tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>

<h2>Recommendations</h2>
<div class="summary">
<ol>
<li><strong>Network device inventory:</strong> Identify any D-Link, NETGEAR, Zyxel, Realtek SDK, Palo Alto, or IBM Planning Analytics instances in your environment.</li>
<li><strong>Alternative detection:</strong> Use Metasploit auxiliary scanner modules (non-invasive check mode) to validate whether these CVEs are present on your network.</li>
<li><strong>Firmware patching:</strong> Verify firmware versions on affected device types. Many of these are EOL products that should be replaced.</li>
<li><strong>Network segmentation:</strong> Ensure these device types are not directly accessible from untrusted networks.</li>
<li><strong>Compensating controls:</strong> Since IVM cannot detect these, document compensating controls (network ACLs, IPS signatures, firmware management process) for audit and compliance evidence.</li>
</ol>
</div>

<div class="footer">
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Data: CISA KEV (1,661), Metasploit Pro (2,681 exploit modules, 2,518 CVE mappings), InsightVM Data Warehouse (133,817 CVEs)</p>
</div>
</div>
</body>
</html>"""

output_path = 'BOD-Reports/kev_msf_ivm_blind_spot_analysis_2026-08-05.html'
with open(output_path, 'w') as f:
    f.write(html)

print(f"Report saved: {output_path}")
print(f"Size: {len(html):,} bytes")
