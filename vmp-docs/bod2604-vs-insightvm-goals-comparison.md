# Prioritizing Vulnerability Remediation: Two Approaches

**Purpose:** Compare using CISA BOD 26-04 compliance reporting (MCP tooling) vs. InsightVM's native Goals & SLAs feature for prioritizing security updates by risk.

**Audience:** Security program administrators evaluating which approach (or combination) fits their environment.

---

## Approach 1: InsightVM Goals & SLAs (Console-Native)

### How It Works

InsightVM's Goals & SLAs feature lets you define remediation targets using criteria available in the console UI:

- **Asset scope:** Filter by tag (e.g., `Business-Crit1`, `Internet-Exposed`)
- **Vulnerability criteria:** CVSS score threshold, exploit availability, severity
- **Remediation window:** Number of days from discovery to required closure
- **Tracking:** Console dashboard shows compliance percentage over time

### Example Configuration

| Goal Name | Asset Scope | Vuln Criteria | SLA (Days) |
|-----------|-------------|---------------|------------|
| Crit Servers — Exploitable High | Tag = `Business-Crit1` | CVSS ≥ 8.0 AND Exploit Available | 30 |
| Crit Servers — All Critical | Tag = `Business-Crit1` | Severity = Critical | 45 |
| Crit Servers — All High | Tag = `Business-Crit1` | Severity = High | 60 |
| All Assets — Exploitable Critical | All | CVSS ≥ 9.0 AND Exploit Available | 14 |
| All Assets — Critical | All | Severity = Critical | 30 |
| All Assets — High | All | Severity = High | 60 |
| All Assets — Medium | All | Severity = Medium | 90 |

### What You Can Filter On

- Severity (Critical, High, Medium, Low)
- CVSS score (v2 or v3 threshold)
- Exploit availability (Metasploit, ExploitDB, or any)
- Asset tags (custom tags you create)
- Asset groups (Dynamic Asset Groups)
- Sites
- Vulnerability category (including "CISA KEV")
- Vulnerability age

### What You Cannot Filter On

- SSVC Automatable (not a native field)
- SSVC Technical Impact (not a native field)
- EPSS score (not available in Goals UI)
- CVSS vector components (Attack Vector, Complexity, User Interaction)
- VulnCheck KEV status
- Combined multi-factor logic (can't do "IF KEV AND exposed AND automatable THEN 3 days")

### Strengths

- Built into the console — no external tooling needed
- Visual dashboard with compliance percentage trending
- Scheduled reports for stakeholders
- Patch teams see goal status without leaving InsightVM
- Tracks historical compliance over time natively
- Can scope to specific sites, tags, or asset groups
- Supports "CISA KEV" as a vulnerability category filter

### Limitations

- Binary logic only: a finding either meets criteria or it doesn't
- Cannot implement the BOD 26-04 4-variable decision tree
- No awareness of "Automatable" or "Technical Impact" (SSVC)
- No EPSS-based prioritization
- SLAs are static — same deadline regardless of context
- Cannot differentiate between "exploitable + exposed + KEV" (3-day) vs. "exploitable + internal" (180-day)

---

## Approach 2: BOD 26-04 Compliance Report (MCP Tooling)

### How It Works

The BOD 26-04 compliance report uses the Bulk Export API + external enrichment to evaluate each vulnerability against CISA's 4-variable decision framework:

1. **In KEV** — Is the CVE in CISA's Known Exploited Vulnerabilities catalog?
2. **Publicly Exposed** — Is the asset tagged `Internet-Exposed`?
3. **Automatable** — Can exploitation be fully automated? (from CISA Vulnrichment/SSVC via NVD)
4. **Technical Impact** — Does exploitation yield total or partial control? (from SSVC)

The combination determines the remediation timeline: 3 days, 14 days, 60 days, 180 days, or fix on upgrade.

### Example Output

| CVE | Host | KEV | Exposed | Auto | Impact | Timeline | Due Date |
|-----|------|-----|---------|------|--------|----------|----------|
| CVE-2024-XXXX | web-prod | Yes | Yes | Yes | Total | **3 days + triage** | 2026-07-13 |
| CVE-2025-YYYY | db-prod | Yes | No | Yes | Partial | **14 days** | 2026-07-24 |
| CVE-2026-ZZZZ | app-int | No | No | Yes | Partial | **180 days** | 2027-01-06 |

### What It Evaluates

- CISA KEV catalog (refreshed daily, cached locally)
- VulnCheck KEV (broader coverage, exploit PoC links)
- CISA Vulnrichment / SSVC (Automatable, Technical Impact)
- EPSS scores (exploitation probability)
- Asset exposure from InsightVM tags (`Internet-Exposed`)
- Business criticality from tags (`Business-Crit1`, `Business-Crit2`) — used for sort priority within buckets
- Metasploit module availability

### Strengths

- Implements the full BOD 26-04 Table 1 decision logic
- Dynamic timelines that change as conditions change (e.g., CVE added to KEV → timeline shortens)
- Enriched with threat intelligence not available in the console (SSVC, VulnCheck, EPSS)
- Trend tracking across report snapshots
- No overdue findings missed — every CVE gets a calculated deadline
- Formal compliance evidence for audits

### Limitations

- Requires MCP tooling setup (API key, server running)
- Not visible in the InsightVM console UI — separate report
- Patch teams need the report delivered to them (not self-service in console)
- Depends on external APIs (NVD, CISA KEV, EPSS) — graceful degradation if unavailable
- No native "goal compliance %" dashboard in InsightVM

---

## Side-by-Side Comparison

| Dimension | InsightVM Goals & SLAs | BOD 26-04 Report (MCP) |
|-----------|----------------------|----------------------|
| **Setup effort** | Low — configure in console UI | Medium — MCP server + API key |
| **Decision variables** | CVSS + exploit + tags | KEV + exposure + automatable + impact |
| **Granularity** | Severity/CVSS threshold | Per-CVE risk-based timeline |
| **Dynamic timelines** | No — static SLA per goal | Yes — timeline changes if CVE enters KEV or asset exposure changes |
| **KEV awareness** | Yes (via category filter) | Yes (plus VulnCheck KEV) |
| **SSVC awareness** | No | Yes (Automatable + Technical Impact) |
| **EPSS awareness** | No | Yes |
| **Visible to patch teams** | Yes — console dashboard | No — delivered as report |
| **Historical trending** | Yes — built-in | Yes — snapshot-based |
| **Audit evidence** | Screenshot/export from console | HTML/JSON report with methodology |
| **Compliance framework alignment** | Custom (org-defined SLAs) | CISA BOD 26-04 (federal standard) |
| **Self-service for analysts** | Yes | Requires running the report |

---

## Recommended: Use Both Together

These approaches are complementary, not competing:

### InsightVM Goals & SLAs → Day-to-Day Operations

Use for patch team workqueues and operational accountability:

```
Goal: "Business-Critical Exploitable — 30 Days"
  Scope: Tag = Business-Crit1
  Criteria: CVSS ≥ 8.0 AND Exploit Available
  SLA: 30 days from discovery
```

This gives patch teams a clear, visible target in the tool they already use. They see red/green compliance in their dashboard without needing external reports.

### BOD 26-04 Report → Governance & Compliance

Use for:
- Monthly leadership reporting
- Audit evidence of risk-based prioritization
- Identifying findings that *should* have shorter timelines but aren't captured by static CVSS rules
- Tracking alignment with federal cybersecurity standards
- Enriched threat intelligence context (which findings have active exploitation, PoC code, ransomware associations)

### How They Map Together

| InsightVM Goal | Approximates BOD Timeline |
|---|---|
| Tag = Internet-Exposed, CVSS ≥ 9, Exploit Available, SLA = 14 days | ~3-day / 14-day bucket (KEV + exposed) |
| Tag = Business-Crit1, CVSS ≥ 8, Exploit Available, SLA = 30 days | ~14-day / 60-day bucket |
| All Assets, Severity = Critical, SLA = 60 days | ~60-day / 180-day bucket |
| All Assets, Severity = High, SLA = 90 days | ~180-day bucket |
| All Assets, Severity = Medium, SLA = 180 days | ~Fix on upgrade |

The InsightVM goals are deliberately *slightly more lenient* than the BOD report's precision — this accounts for the fact that Goals can't evaluate all 4 decision variables. The BOD report catches anything that slips through.

---

## When the BOD Report Catches What Goals Miss

Example scenario:

- A new CVE is added to the CISA KEV catalog
- The affected asset is tagged `Internet-Exposed`
- The vulnerability has a network attack vector, low complexity, no user interaction (automatable)
- Technical impact is total

**InsightVM Goal sees:** CVSS 7.5, exploit available → 30-day SLA (if using the example goal above)

**BOD 26-04 Report sees:** In KEV + Publicly Exposed + Automatable + Total Impact → **3-day deadline + forensic triage required**

The BOD report identifies this as the highest-urgency finding. The InsightVM goal would give it 30 days. The difference matters.

---

## Summary

| Use Case | Best Tool |
|----------|-----------|
| Daily patch team workqueue | InsightVM Goals & SLAs |
| "Are we compliant with BOD 26-04?" | MCP BOD Report |
| Monthly executive summary | Both (Goals for % compliance, BOD for risk context) |
| Audit evidence | MCP BOD Report (documented methodology) |
| Quick "how are we doing?" glance | InsightVM Dashboard |
| Formal threat-informed prioritization | MCP BOD Report |
| Simple severity-based SLAs | InsightVM Goals & SLAs |
| KEV + exposure + automation-aware deadlines | MCP BOD Report |

---

*Document prepared for vulnerability management program planning. Review quarterly as InsightVM features evolve.*
