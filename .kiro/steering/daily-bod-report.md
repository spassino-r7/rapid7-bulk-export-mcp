---
inclusion: auto
---

# Daily BOD 26-04 Report Procedure

When the user asks to "run daily bulk export and BOD report" (or similar), follow this procedure:

1. **Start vulnerability bulk export** and wait for completion
2. **Download and load** the export data
3. **Query ALL findings with CVEs** — use: `SELECT v.assetId, a.hostName, a.ip, v.title, v.severity, v.cves, v.firstFoundTimestamp FROM vulnerabilities v JOIN assets a ON v.assetId = a.assetId WHERE array_length(v.cves) > 0`
4. **Run bod2604_compliance_report** with the FULL set of CVE findings (never a subset)
5. **Post-process the HTML** — inject the executive summary legend block (see below) after the closing `</div>` of the `.summary-grid` div
6. **Write the HTML report to disk** as `BOD-Reports/bod2604_compliance_report_YYYY-MM-DD.html`
7. **Update the trend report** at `BOD-Reports/bod2604_trend_report.html`

## Executive Summary Legend (inject after summary-grid)

After receiving the HTML from bod2604_compliance_report, insert this block immediately after the `</div>` that closes the `.summary-grid` div:

```html
<div class="summary-legend" style="background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; font-size: 0.85em; line-height: 1.6;">
    <h3 style="margin-top: 0; color: #003366;">Metric Definitions</h3>
    <dl style="margin: 0; display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px;">
        <dt style="font-weight: bold;">Total Findings</dt>
        <dd style="margin: 0;">Number of CVE-linked vulnerabilities evaluated against BOD 26-04</dd>
        <dt style="font-weight: bold;">New Today</dt>
        <dd style="margin: 0;">Findings that appeared for the first time in this report vs. the prior snapshot</dd>
        <dt style="font-weight: bold;">Remediated Today</dt>
        <dd style="margin: 0;">Findings present in the prior snapshot that are no longer detected</dd>
        <dt style="font-weight: bold;">Unique CVEs</dt>
        <dd style="margin: 0;">Distinct CVE identifiers across all findings</dd>
        <dt style="font-weight: bold;">Assets</dt>
        <dd style="margin: 0;">Number of unique hosts/systems with at least one finding</dd>
        <dt style="font-weight: bold;">Overdue</dt>
        <dd style="margin: 0;">Findings past their BOD 26-04 remediation deadline</dd>
        <dt style="font-weight: bold;">Has Exploit Module</dt>
        <dd style="margin: 0;">Findings with a matching Metasploit exploit module available</dd>
        <dt style="font-weight: bold;">Forensic Triage</dt>
        <dd style="margin: 0;">Findings requiring immediate forensic investigation (KEV + exposed + automatable + total impact = 3-day deadline exceeded)</dd>
    </dl>
</div>
```

Asset exposure map (all internal): asset-19=False, asset-13=False, asset-61=False, asset-120=False, asset-36=False, asset-140=False

Always include every finding — do not subset to avoid NVD timeouts. SSVC caching handles performance.

## SSVC Enrichment Coverage Gap (inject before footer)

After the findings table and before the footer, inject an "Enrichment Coverage Gap" section. Calculate these metrics from the BOD report output:

- **Automatable findings** — count findings where Auto = "Yes" vs total. These are invisible to IVM Goals.
- **Total Impact findings** — count findings where Impact = "total" vs total. IVM severity doesn't distinguish total vs partial.
- **Accelerated timeline findings** — count findings in 3d, 14d, or 60d buckets that would be in a *longer* IVM Goal bucket based on severity alone.
- **"Fix on upgrade" findings** — count findings where SSVC determined no hard deadline is needed (not automatable + partial impact). IVM Goals would still assign these a severity-based SLA.

Inject this HTML block:

```html
<h2>SSVC Enrichment Coverage Gap</h2>
<p style="font-size: 0.9em; color: #6c757d;">Risk context only visible through NVD/SSVC enrichment — not available in InsightVM Goals alone.</p>
<div class="summary-grid">
    <div class="summary-card"><div class="value">{automatable_pct}%</div><div class="label">Automatable (invisible to IVM)</div></div>
    <div class="summary-card"><div class="value">{total_impact_pct}%</div><div class="label">Total Impact (not distinguished by IVM)</div></div>
    <div class="summary-card"><div class="value">{accelerated_count}</div><div class="label">Findings with shorter BOD deadline than IVM Goal</div></div>
    <div class="summary-card"><div class="value">{upgrade_pct}%</div><div class="label">No hard deadline (upgrade only)</div></div>
</div>
<div style="background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; font-size: 0.85em; line-height: 1.6;">
    <h3 style="margin-top: 0; color: #003366;">What This Means</h3>
    <ul style="margin: 0; padding-left: 20px;">
        <li><strong>Automatable</strong> — These findings can be exploited at scale with no human interaction. IVM Goals treat them identically to non-automatable findings of the same severity.</li>
        <li><strong>Total Impact</strong> — Exploitation gives the attacker full system control. IVM severity doesn't differentiate this from partial-access vulnerabilities.</li>
        <li><strong>Accelerated timeline</strong> — BOD 26-04 would require faster remediation than the IVM Goal assigns. This happens when KEV + exposure + automatability combine to shorten the deadline.</li>
        <li><strong>No hard deadline</strong> — SSVC determined these are low-urgency (not automatable, partial impact, not in KEV). IVM Goals would still assign a severity-based SLA even though the directive doesn't require one.</li>
    </ul>
</div>
```

Calculate percentages by counting "Yes"/"No" in the Auto column and "total"/"partial" in the Impact column from the report HTML table.
