#!/usr/bin/env python3
"""
Rapid7 VMMA Report Generator
Reads assessment JSON and produces an HTML report with charts and recommendations.
Usage: python3 generate_report.py assessment_CustomerName_YYYY-MM-DD.json
"""

import json
import sys
import math
from datetime import datetime
from pathlib import Path

LEVELS = {
    1: "Preliminary",
    2: "Initial",
    3: "Managed",
    4: "Standardized",
    5: "Predictable",
    6: "Innovating"
}

LEVEL_COLORS = {
    1: "#dc2626",  # red
    2: "#ea580c",  # orange
    3: "#ca8a04",  # yellow
    4: "#2563eb",  # blue
    5: "#16a34a",  # green
    6: "#7c3aed",  # purple
}

RECOMMENDATIONS = {
    "Governance": [
        "Review all policies and procedures at least annually — organizational risks change rapidly",
        "Ensure VM policies are formally communicated to all business units with training provided",
        "Map all regulatory requirements (SOX, PCI, GDPR) to specific VM controls",
        "Establish formal KPIs and program goals reviewed by leadership quarterly",
    ],
    "Risk Management": [
        "Formally document the organization's risk appetite to guide VM prioritization decisions",
        "Incorporate asset criticality and data classification into the vulnerability risk scoring model",
        "Document data flows and system dependencies as part of network diagrams",
        "Continuously validate security controls — misconfigured settings are a leading cause of breaches",
        "Enforce separation of duties between firewall rule creators and auditors",
    ],
    "Asset Management": [
        "Integrate the CMDB with InsightVM to automate asset discovery and scanning workflows",
        "Classify and tag all assets with criticality, data sensitivity, and owner information",
        "Deploy passive discovery tools to detect rogue/unauthorized devices on the network",
        "Enable port security on network switches to control physical network access",
        "Conduct policy compliance scans to validate baseline configuration settings",
    ],
    "Admin Privileges": [
        "Implement quarterly reviews of all administrator-level accounts — remove unnecessary access",
        "Configure proxy controls to prevent admin accounts from browsing the Internet",
        "Provide role-based security training specifically for users with administrative rights",
        "Ensure all admin account activity is logged and reviewed regularly",
    ],
    "Discovery and Scanning": [
        "Perform discovery scans as part of a robust ITAM program to detect rogue devices",
        "Ensure all scans are credentialed (authenticated) for maximum vulnerability fidelity",
        "Deploy Insight Agents for continuous endpoint assessment independent of scan schedules",
        "Compare scan results cycle-to-cycle to track remediation progress and new findings",
        "Document a formal scanning standard covering frequency, etiquette, and account ownership",
    ],
    "Vulnerability Analysis": [
        "Tie business-critical systems to revenue streams and use InsightVM criticality tags to adjust risk scores",
        "Review compensating controls when determining risk — not all vulnerabilities require immediate patching",
        "Review threat intelligence feeds daily to prioritize emerging threats",
        "Incorporate data classification policy into remediation prioritization decisions",
        "Use Dynamic Asset Groups (DAGs) for targeted scanning in response to high-risk published vulnerabilities",
    ],
    "Remediation": [
        "Align patching SLAs to CISA guidance: Critical=15 days, Moderate=60 days, Low=90 days",
        "Leverage automated workflows between InsightVM and patching/ticketing solutions to reduce manual effort",
        "Extend patching coverage beyond SCCM/Puppet to include all OS types, third-party apps, and firmware",
        "Prioritize vulnerabilities by grouping common remediation steps (e.g., Java, Adobe) for efficiency",
        "Ensure M&A environments are included in the patching program to prevent vulnerability backlogs",
    ],
    "Change Management": [
        "Treat monthly OS patching as a Standard change (pre-approved) to reduce CAB overhead",
        "Ensure all exceptions are tracked within the change management workflow for full visibility",
        "Maintain audit trails for all changes to support compliance and incident response",
        "Communicate change management process improvements to stakeholders regularly",
    ],
    "Reporting": [
        "Develop tiered reporting: Strategic (risk scores), Operational (workqueue), Tactical (SLA/patch rates)",
        "Automate report generation and delivery to reduce manual effort and ensure consistency",
        "Include risk reduction trends over time to demonstrate program effectiveness to leadership",
        "Track and report exception and false positive metrics as part of program health indicators",
    ],
    "Security Program": [
        "Conduct policy compliance scans (CIS Benchmarks, DISA STIG) to validate baseline configurations",
        "Document business justifications for all approved applications in the software inventory",
        "Block unsigned scripts and executables from running in browsers to reduce attack surface",
        "Expand penetration testing to include internal network testing with tools like Metasploit",
        "Establish a third-party supplier security assessment process as part of supply chain risk management",
    ],
}


def radar_chart_svg(domain_scores):
    """Generate an SVG radar chart for domain scores."""
    domains = list(domain_scores.keys())
    scores = [domain_scores[d] for d in domains]
    n = len(domains)
    cx, cy, r = 250, 250, 180
    max_val = 6

    def point(angle, val):
        rad = math.radians(angle - 90)
        x = cx + (r * val / max_val) * math.cos(rad)
        y = cy + (r * val / max_val) * math.sin(rad)
        return x, y

    angles = [i * 360 / n for i in range(n)]

    # Grid lines
    grid_lines = ""
    for level in range(1, 7):
        pts = " ".join(f"{point(a, level)[0]:.1f},{point(a, level)[1]:.1f}" for a in angles)
        grid_lines += f'<polygon points="{pts}" fill="none" stroke="#334155" stroke-width="0.5" opacity="0.5"/>\n'

    # Axis lines
    axis_lines = ""
    for a in angles:
        x, y = point(a, max_val)
        axis_lines += f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="#334155" stroke-width="0.5" opacity="0.5"/>\n'

    # Data polygon
    data_pts = " ".join(f"{point(angles[i], scores[i])[0]:.1f},{point(angles[i], scores[i])[1]:.1f}" for i in range(n))
    data_poly = f'<polygon points="{data_pts}" fill="#3b82f6" fill-opacity="0.3" stroke="#3b82f6" stroke-width="2"/>\n'

    # Data points
    data_dots = ""
    for i in range(n):
        x, y = point(angles[i], scores[i])
        data_dots += f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="#3b82f6"/>\n'

    # Labels
    labels = ""
    for i, domain in enumerate(domains):
        x, y = point(angles[i], max_val + 0.8)
        anchor = "middle"
        if x < cx - 10:
            anchor = "end"
        elif x > cx + 10:
            anchor = "start"
        short = domain[:12] + ".." if len(domain) > 14 else domain
        labels += f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}" font-size="11" fill="#94a3b8">{short}</text>\n'

    # Level labels
    level_labels = ""
    for level in range(1, 7):
        x, y = point(0, level)
        level_labels += f'<text x="{x:.1f}" y="{y - 4:.1f}" text-anchor="middle" font-size="9" fill="#64748b">{level}</text>\n'

    return f'''<svg viewBox="0 0 500 500" xmlns="http://www.w3.org/2000/svg">
{grid_lines}{axis_lines}{data_poly}{data_dots}{labels}{level_labels}
</svg>'''


def generate_html(data):
    customer = data["customer"]
    domains = data["domains"]
    overall = data["overall_score"]
    overall_level = data["overall_level"]
    overall_int = min(6, max(1, round(overall)))
    overall_color = LEVEL_COLORS[overall_int]

    domain_scores = {d: v["score"] for d, v in domains.items()}
    radar = radar_chart_svg(domain_scores)

    # Domain rows
    domain_rows = ""
    for domain, info in domains.items():
        score = info["score"]
        level = info["level"]
        color = LEVEL_COLORS[score]
        bar_width = round(score / 6 * 100)
        yes_count = sum(1 for r in info["responses"] if r["answer"] == "y")
        total_count = sum(1 for r in info["responses"] if r["answer"] != "s")
        pct = round(yes_count / total_count * 100) if total_count > 0 else 0

        domain_rows += f"""
        <tr>
            <td style="padding:12px;font-weight:500;color:#e2e8f0">{domain}</td>
            <td style="padding:12px">
                <div style="background:#1e293b;border-radius:4px;height:8px;width:100%">
                    <div style="background:{color};border-radius:4px;height:8px;width:{bar_width}%"></div>
                </div>
            </td>
            <td style="padding:12px;text-align:center">
                <span style="background:{color}22;color:{color};padding:3px 10px;border-radius:12px;font-size:0.8rem;font-weight:600">{score} - {level}</span>
            </td>
            <td style="padding:12px;text-align:center;color:#94a3b8">{yes_count}/{total_count} ({pct}%)</td>
        </tr>"""

    # Recommendations
    rec_sections = ""
    for domain, info in sorted(domains.items(), key=lambda x: x[1]["score"]):
        if info["score"] < 5:
            recs = RECOMMENDATIONS.get(domain, [])
            score = info["score"]
            color = LEVEL_COLORS[score]
            rec_items = "".join(f"<li style='margin-bottom:6px;color:#cbd5e1'>{r}</li>" for r in recs)
            rec_sections += f"""
            <div style="background:#1e2330;border-radius:8px;padding:20px;margin-bottom:16px;border-left:4px solid {color}">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                    <h3 style="color:#f1f5f9;margin:0">{domain}</h3>
                    <span style="background:{color}22;color:{color};padding:3px 10px;border-radius:12px;font-size:0.8rem">{score} - {info['level']}</span>
                </div>
                <ul style="margin:0;padding-left:20px">{rec_items}</ul>
            </div>"""

    # Gap analysis — questions answered No
    gaps = ""
    for domain, info in sorted(domains.items(), key=lambda x: x[1]["score"]):
        no_answers = [r for r in info["responses"] if r["answer"] == "n"]
        partial_answers = [r for r in info["responses"] if r["answer"] == "p"]
        if no_answers or partial_answers:
            gap_items = "".join(f"<li style='margin-bottom:4px;color:#fca5a5'>✗ {r['question']}</li>" for r in no_answers)
            gap_items += "".join(f"<li style='margin-bottom:4px;color:#fbbf24'>~ {r['question']} <em>(Partial)</em></li>" for r in partial_answers)
            gaps += f"""
            <div style="margin-bottom:16px">
                <h4 style="color:#94a3b8;margin-bottom:8px">{domain}</h4>
                <ul style="margin:0;padding-left:20px">{gap_items}</ul>
            </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VMMA Report — {customer['name']}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; padding: 32px; }}
  h1 {{ font-size: 1.8rem; font-weight: 700; color: #f8fafc; }}
  h2 {{ font-size: 1.2rem; font-weight: 600; color: #f1f5f9; margin-bottom: 16px; }}
  .card {{ background: #1e2330; border-radius: 10px; padding: 24px; border: 1px solid #2d3748; margin-bottom: 24px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 10px 12px; color: #64748b; font-size: 0.75rem; text-transform: uppercase; border-bottom: 1px solid #2d3748; }}
  tr:hover td {{ background: #1a2035; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
  @media (max-width: 768px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>

<div style="margin-bottom:32px">
  <h1>Vulnerability Management Maturity Assessment</h1>
  <p style="color:#94a3b8;margin-top:8px">Prepared for: <strong style="color:#e2e8f0">{customer['name']}</strong> &nbsp;|&nbsp; Industry: {customer['industry']} &nbsp;|&nbsp; Assessor: {customer['assessor']} &nbsp;|&nbsp; Date: {customer['date']}</p>
</div>

<!-- Overall Score -->
<div class="card" style="border-left:4px solid {overall_color}">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <div>
      <p style="color:#94a3b8;font-size:0.875rem;margin-bottom:4px">Overall Maturity Level</p>
      <h1 style="font-size:2.5rem;color:{overall_color}">{overall} / 6.0</h1>
      <p style="color:{overall_color};font-size:1.1rem;font-weight:600;margin-top:4px">{overall_level}</p>
    </div>
    <div style="text-align:right">
      <p style="color:#94a3b8;font-size:0.875rem">Recommended Target</p>
      <p style="color:#60a5fa;font-size:1.1rem;font-weight:600">Predictable (5.0)</p>
    </div>
  </div>
</div>

<!-- Radar + Domain Scores -->
<div class="grid">
  <div class="card">
    <h2>Maturity Radar</h2>
    {radar}
  </div>
  <div class="card">
    <h2>Domain Scores</h2>
    <table>
      <thead><tr><th>Domain</th><th>Score</th><th>Level</th><th>Yes/Total</th></tr></thead>
      <tbody>{domain_rows}</tbody>
    </table>
  </div>
</div>

<!-- Gap Analysis -->
<div class="card">
  <h2>Gap Analysis — Unanswered Controls</h2>
  <p style="color:#94a3b8;margin-bottom:16px;font-size:0.875rem">The following controls were identified as not in place. These represent the highest-priority gaps to address.</p>
  {gaps if gaps else '<p style="color:#4ade80">No gaps identified — all controls answered Yes.</p>'}
</div>

<!-- Recommendations -->
<div class="card">
  <h2>Prioritized Recommendations</h2>
  <p style="color:#94a3b8;margin-bottom:16px;font-size:0.875rem">Domains are ordered from lowest to highest maturity. Address lower-scoring domains first.</p>
  {rec_sections}
</div>

<div style="text-align:center;color:#475569;margin-top:32px;font-size:0.8rem">
  Generated by Rapid7 VMMA Tool &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')}
</div>

</body>
</html>"""

    return html


def main():
    if len(sys.argv) < 2:
        # Find most recent assessment file
        files = sorted(Path(".").glob("assessment_*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            print("Usage: python3 generate_report.py assessment_CustomerName_YYYY-MM-DD.json")
            sys.exit(1)
        json_file = files[0]
        print(f"Using most recent assessment: {json_file}")
    else:
        json_file = Path(sys.argv[1])

    if not json_file.exists():
        print(f"File not found: {json_file}")
        sys.exit(1)

    with open(json_file) as f:
        data = json.load(f)

    html = generate_html(data)

    report_file = json_file.stem + "_report.html"
    with open(report_file, "w") as f:
        f.write(html)

    print(f"Report generated: {report_file}")
    print(f"Open in browser: open {report_file}")


if __name__ == "__main__":
    main()
