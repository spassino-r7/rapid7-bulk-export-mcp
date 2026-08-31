# Monthly Vulnerability Management Reporting Cadence

**Program:** Vulnerability Management Program (InsightVM)
**Document Owner:** Security Program Administrator
**Review Cycle:** Semi-annual
**Report Owner:** `[FILL IN — named analyst]`

---

## 1. Purpose

This document defines the monthly reporting cadence for the Vulnerability Management Program, including the report template, data sources, delivery schedule, and roles responsible for producing and reviewing the monthly report.

---

## 2. Monthly Report Schedule

| Activity | Timing | Owner |
|---|---|---|
| SQL reports auto-run in InsightVM | First business day of the month | InsightVM (automated) |
| Report owner compiles monthly VMP report | By the 5th of the month | Report Owner |
| Draft report delivered to Security Team Lead for review | By the 7th of the month | Report Owner |
| Final report delivered to security leadership | By the 10th of the month | Security Team Lead |
| Monthly report review meeting | Third week of the month | Security Team Lead |
| Exception register updated in runbook | By the 5th of the month | Program Administrator |
| Metric snapshot archived (24-month retention) | By the 5th of the month | Program Administrator |

---

## 3. Monthly Report Template

### Section 1: Executive Summary

A 3–5 sentence narrative summarizing the program's posture this month. Include:
- Overall risk trend (improving / stable / degrading)
- Any significant events (new critical vulnerabilities, SLA breaches, coverage gaps)
- Key actions taken or planned

### Section 2: Coverage Rate

| Metric | This Month | Last Month | Trend |
|---|---|---|---|
| Total in-scope assets | | | |
| Assets scanned in last 30 days | | | |
| Coverage rate (%) | | | ↑ / ↓ / → |
| Sites below 95% coverage | | | |

**Data source:** `VMP-Scan-Coverage` SQL report

**Alert threshold:** If coverage < 90%, include a root cause analysis and remediation plan in this section.

### Section 3: Vulnerability Backlog Trend

| Severity | Open This Month | Open Last Month | Change | % Change |
|---|---|---|---|---|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |
| **Total** | | | | |

**Data source:** InsightVM Vulnerabilities view (filter: status = Open)

**Alert threshold:** If total backlog increases ≥ 10% month-over-month, include a written root cause analysis.

### Section 4: BOD 26-04 Risk Tier Distribution

| Risk Tier | SLA | Open Findings | Affected Assets | Within SLA | SLA Compliance % | Status |
|---|---|---|---|---|---|---|
| Tier 1 (3 days) | 3 days | | | | | ✓ / ✗ |
| Tier 2 (14 days) | 14 days | | | | | ✓ / ✗ |
| Tier 3 (60 days) | 60 days | | | | | ✓ / ✗ |
| Tier 4 (Defer) | Next upgrade | | | | | ✓ / ✗ |

**Data source:** `VMP-BOD-Tier-Classification` SQL report

**Key insight:** Expect ~1% Tier 1, ~5-10% Tier 2, ~30% Tier 3, ~60% Tier 4. If Tier 1 count is > 0 for more than 3 days, escalate immediately.

### Section 4a: KEV Overlap

| Metric | This Month | Last Month | Trend |
|---|---|---|---|
| Open vulns matching CISA KEV | | | |
| KEV vulns on internet-facing assets (Tier 1/2) | | | |
| KEV vulns on internal assets (Tier 3) | | | |
| KEV vulns remediated this month | | | |

**Data source:** `VMP-KEV-Overlap` SQL report + `kev_cross_reference.py` output

### Section 4b: SLA Compliance Rate (Legacy — CVSS Based)

| Severity | SLA Target | Compliance This Month | Compliance Last Month | Goal Target | Status |
|---|---|---|---|---|---|
| Critical | 15 days | | | ≥ 95% | ✓ / ✗ |
| High | 30 days | | | ≥ 90% | ✓ / ✗ |
| Medium | 90 days | | | ≥ 85% | ✓ / ✗ |
| Low | 180 days | | | ≥ 80% | ✓ / ✗ |

**Data source:** `VMP-SLA-Compliance` SQL report + InsightVM Goals & SLAs view

> **Note:** Legacy CVSS-based SLAs are retained for continuity during the 90-day transition period. Risk-tier SLAs (Section 4) are the primary compliance measure.

### Section 5: Exposure Summary

| Exposure | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Internet-Facing | | | | | |
| Internal | | | | | |
| **Total** | | | | | |

**Data source:** `VMP-Exposure-Summary` SQL report

**Alert threshold:** Any Critical or High vulnerability on an internet-facing asset that has been open > 14 days requires written explanation.

### Section 6: Mean Time to Remediate (MTTR)

| Risk Tier | MTTR This Month (days) | MTTR Last Month (days) | SLA Target (days) | Status |
|---|---|---|---|---|
| Tier 1 | | | 3 | ✓ / ✗ |
| Tier 2 | | | 14 | ✓ / ✗ |
| Tier 3 | | | 60 | ✓ / ✗ |
| Tier 4 | | | Next upgrade | ✓ / ✗ |

| Severity (Legacy) | MTTR This Month (days) | MTTR Last Month (days) | SLA Target (days) | Status |
|---|---|---|---|---|
| Critical | | | 15 | ✓ / ✗ |
| High | | | 30 | ✓ / ✗ |
| Medium | | | 90 | ✓ / ✗ |
| Low | | | 180 | ✓ / ✗ |

**Data source:** `VMP-MTTR-Monthly` SQL report

### Section 7: Exploitable Findings

| Metric | This Month | Last Month | Trend |
|---|---|---|---|
| Total exploitable findings (hasExploits = true OR EPSS > 0.50) | | | |
| Critical exploitable findings | | | |
| High exploitable findings | | | |
| Exploitable findings in active Remediation Projects | | | |
| Exploitable findings with no Remediation Project | | | |

**Data source:** `VMP-Exploitable-Findings` SQL report

### Section 8: Top 10 Highest-Risk Assets

| Rank | Asset Hostname | IP | Risk Score | Top Vulnerability | Criticality |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |
| 6 | | | | | |
| 7 | | | | | |
| 8 | | | | | |
| 9 | | | | | |
| 10 | | | | | |

**Data source:** InsightVM dashboard card "Top 10 Highest-Risk Assets" (VMP - Executive Risk Overview dashboard)

### Section 8: Exception Summary

| Metric | Count |
|---|---|
| Total open exceptions | |
| Exceptions by severity — Critical | |
| Exceptions by severity — High | |
| Exceptions by severity — Medium | |
| Exceptions by severity — Low | |
| Exceptions due for review this month | |
| Exceptions overdue for review | |
| New exceptions approved this month | |
| Exceptions closed this month | |

**Data source:** `VMP-Exception-Summary` SQL report

### Section 9: Action Items

| # | Action Item | Owner | Due Date | Status |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |

---

## 4. Distribution List

| Audience | Recipients | Format |
|---|---|---|
| Security leadership | CISO, VP Engineering, CTO (as applicable) | PDF or slide deck |
| Security team | All security analysts and engineers | Email with attached report |
| IT Operations | IT Operations lead | Email summary |
| Program Administrator | Internal record | Archived in runbook |

**Distribution list email:** `[FILL IN — security team DL]`

---

## 5. Report Archive

Monthly metric snapshots are retained for a minimum of 24 months to support year-over-year trend analysis. Archive location: `[FILL IN — shared drive path or document management system]`

Archive naming convention: `VMP-Monthly-Report-YYYY-MM.pdf`

---

## 6. Report Owner

The named analyst responsible for compiling and delivering the monthly report:

**Report Owner:** `[FILL IN — name and title]`  
**Backup:** `[FILL IN — name and title]`  
**Escalation:** Security Team Lead

The Report Owner is responsible for:
- Running or confirming all five SQL reports have executed successfully
- Populating the report template with current month data
- Delivering the draft to the Security Team Lead by the 7th of the month
- Archiving the final report

---

## 7. Monthly Review Meeting

A recurring monthly meeting is held with security leadership to review the VMP report.

**Meeting cadence:** Monthly, third week of the month  
**Duration:** 30 minutes  
**Attendees:** CISO (or delegate), Security Team Lead, Program Administrator, Report Owner  
**Agenda:**
1. Coverage rate review (5 min)
2. SLA compliance review (10 min)
3. Top risks and exploitable findings (10 min)
4. Action items review (5 min)

**Calendar event:** Set up a recurring calendar invite titled "VMP Monthly Review" with the security leadership distribution list.

---

## 8. Related Documents

- Vulnerability Prioritization Policy
- Exception Process Procedure
- Vulnerability Management Program Runbook
