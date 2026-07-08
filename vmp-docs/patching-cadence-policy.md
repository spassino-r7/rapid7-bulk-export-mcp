# Patching Cadence Policy

**Program:** Vulnerability Management Program (InsightVM)
**Document Owner:** Security Program Administrator
**Review Cycle:** Annual
**Approval Required:** Security Leadership
**Alignment:** CISA BOD 26-04 (Prioritizing Security Updates Based on Risk)

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | [FILL IN] | [FILL IN] | Initial release |
| 2.0 | June 2026 | [FILL IN] | Aligned to BOD 26-04 risk tier model; added Tier 1-4 patching cadences |

---

## 1. Purpose

This policy defines the patch deployment cadence and maintenance windows for each risk tier. It ensures that vulnerability remediation timelines are operationally achievable and aligned to the SLA targets defined in the Vulnerability Prioritization Policy, which implements a risk-based model derived from CISA BOD 26-04.

---

## 2. Scope

This policy applies to all assets managed within the InsightVM vulnerability management program, including:

- Corporate servers and workstations
- Cloud instances (AWS, Azure, GCP)
- Network devices
- Remote and agent-assessed endpoints

---

## 3. Patch Deployment Cadence — Risk Tier Model (Primary)

### 3.1 Tier 1 — Emergency Patching (3 Calendar Days)

**Trigger:** Vulnerability classified as Tier 1 per the Vulnerability Prioritization Policy:
- Asset is Internet-Facing, AND
- CVE is in CISA KEV catalog, AND
- Exploitation is automatable (`hasExploits = true` OR EPSS > 0.50), AND
- Technical impact is Total (CVSS v3 Impact subscore ≥ 5.9)

| Parameter | Value |
|---|---|
| Target patch deployment | Within **3 calendar days** (72 hours) of detection |
| Maintenance window | Emergency window — any time, coordinated with asset owner |
| Approval required | Security team lead + asset owner |
| Rollback plan | Required before deployment begins |
| Forensic triage | **Required** before patching (see Section 4) |
| Verification | InsightVM scan triggered immediately after patch to confirm closure |

**Process:**
1. Security analyst identifies Tier 1 vulnerability via `ALERT-Tier1-New` automation trigger or KEV cross-reference script.
2. Security team initiates forensic triage (Section 4) within 4 hours of detection.
3. Security team lead notifies asset owner and IT Operations lead within 4 hours.
4. IT Operations deploys patch or applies compensating control within 72 hours.
5. InsightVM scan is triggered manually after patch deployment to verify closure.
6. If patch cannot be deployed within 72 hours, an exception request must be submitted immediately.

**Expected volume:** Based on CISA's analysis, approximately 1% of vulnerabilities fall into Tier 1.

---

### 3.2 Tier 2 — Accelerated Patching (14 Calendar Days)

**Trigger:** Vulnerability classified as Tier 2:
- Asset is Internet-Facing, AND
- CVE is in CISA KEV catalog, AND
- Either exploitation is NOT fully automatable, OR technical impact is Partial

| Parameter | Value |
|---|---|
| Target patch deployment | Within **14 calendar days** of detection |
| Maintenance window | Next available emergency or weekly window |
| Approval required | Security team lead |
| Rollback plan | Required before deployment |
| Forensic triage | Recommended (analyst judgment) |
| Verification | InsightVM scan within 3 business days of patch deployment |

**Process:**
1. Security analyst flags Tier 2 vulnerability and creates a Remediation Project.
2. IT Operations schedules patch for the next available maintenance window within 14 days.
3. If the standard weekly window falls outside the 14-day SLA, an ad-hoc window is coordinated.
4. InsightVM scan verifies closure.

---

### 3.3 Tier 3 — Standard Patching (60 Calendar Days)

**Trigger:** Vulnerability classified as Tier 3:
- Internal asset with CVE in KEV, OR
- Internet-Facing asset with CVE NOT in KEV

| Parameter | Value |
|---|---|
| Target patch deployment | Within **60 calendar days** of detection |
| Patch cycle | Monthly — aligned to the second Tuesday + 1 week (Patch Tuesday cycle) |
| Maintenance window | **Servers:** Saturday 02:00–06:00 local time |
| | **Workstations:** Sunday 08:00–12:00 local time |
| | **Cloud instances:** Saturday 00:00–04:00 UTC |
| Approval required | IT Operations lead |
| Verification | InsightVM scan within 5 business days of patch deployment |

**Process:**
1. IT Operations reviews the Tier 3 vulnerability list on the first Monday of each month.
2. Patches are tested in staging during the first week.
3. Patches are deployed during the designated maintenance window.
4. InsightVM scan verifies closure.

---

### 3.4 Tier 4 — Deferred Patching (Next Scheduled Upgrade)

**Trigger:** Vulnerability classified as Tier 4:
- Internal asset, AND
- CVE is NOT in KEV, AND
- Exploitation is NOT automatable, AND
- Technical impact is Partial

| Parameter | Value |
|---|---|
| Target patch deployment | **Next scheduled system upgrade or quarterly patch cycle** |
| Patch cycle | Quarterly — or aligned to next OS/application upgrade |
| Maintenance window | Coordinated with IT Operations during scheduled maintenance |
| Approval required | IT Operations lead |
| Verification | InsightVM scan within 10 business days of deployment |

**Process:**
1. Tier 4 vulnerabilities are batched and included in the next scheduled system upgrade or quarterly maintenance.
2. No individual remediation projects are required for Tier 4 unless an EPSS score rises above 0.50 (at which point the vulnerability is re-classified).
3. Tier 4 findings are reviewed quarterly to check for tier changes due to new exploit availability or KEV additions.

**Expected volume:** Based on CISA's analysis, approximately 60% of vulnerabilities qualify for Tier 4 deferral.

---

## 4. Forensic Triage Process (Tier 1 Vulnerabilities)

Before patching a Tier 1 vulnerability, the following forensic steps must be completed:

| Step | Action | Tool/Method | Time Budget |
|------|--------|-------------|-------------|
| 1 | Review authentication logs for anomalous access | SIEM / system logs | 30 min |
| 2 | Check for unexpected processes or scheduled tasks | EDR / process listing | 30 min |
| 3 | Review network connections for C2-like activity | EDR / netstat / SIEM | 30 min |
| 4 | Check for file system changes in critical directories | EDR / file integrity monitoring | 30 min |
| 5 | Document findings in remediation ticket | Ticketing system | 15 min |

**Total time budget:** ~2.5 hours. This must be completed within the first 24 hours of the 72-hour SLA window.

**If compromise is suspected:**
1. Escalate immediately to incident response.
2. Do NOT patch — isolate the system instead.
3. Follow incident response procedures.
4. The 3-day SLA is paused during active incident response.

**If no compromise indicators found:**
1. Document negative findings in the remediation ticket.
2. Proceed with patching within the remaining SLA window.

---

## 5. Legacy Patching Cadence (CVSS-Based — Retained for Transition)

The following CVSS-based cadences are retained during the 90-day transition period while dual-tracking SLAs:

| Severity | SLA Target | Maintenance Window | Frequency |
|---|---|---|---|
| Critical (CVSS ≥ 9.0 + hasExploits) | 15 days | Emergency — any time | As needed |
| High (CVSS 7.0–8.9) | 30 days | Saturday 02:00–06:00 (servers) | Monthly |
| Medium (CVSS 4.0–6.9) | 90 days | First Sunday of quarter | Quarterly |
| Low (CVSS 0.1–3.9) | 180 days | June and December | Semi-annual |

After the 90-day transition, the risk-tier model becomes primary and these become informational benchmarks.

---

## 6. Maintenance Window Summary

| Risk Tier | Target SLA | Maintenance Window | Frequency |
|---|---|---|---|
| Tier 1 | 3 days | Emergency — any time | As needed (~1% of vulns) |
| Tier 2 | 14 days | Next available weekly or emergency window | As needed |
| Tier 3 | 60 days | Saturday 02:00–06:00 (servers) / Sunday 08:00–12:00 (workstations) | Monthly |
| Tier 4 | Next upgrade | Quarterly scheduled maintenance | Quarterly |

---

## 7. Patch Verification

All patch deployments must be verified by a follow-up InsightVM scan. Verification is complete when:

1. The vulnerability is no longer detected on the patched asset in InsightVM.
2. The Remediation Project associated with the vulnerability is marked complete.
3. The InsightVM Goal compliance rate for the relevant tier reflects the closure.

If a vulnerability persists after patching, the IT Operations team must investigate within 2 business days and either:
- Re-deploy the patch correctly, or
- Submit an exception request if the vulnerability cannot be remediated.

---

## 8. Tier Re-Classification Triggers

A vulnerability's risk tier may change over time. The following events trigger re-classification:

| Event | Action |
|-------|--------|
| CVE added to CISA KEV | Re-classify upward (Tier 4→3, Tier 3→2, etc.) |
| New exploit module published (hasExploits changes to true) | Re-evaluate automatability factor |
| EPSS score rises above 0.50 | Re-evaluate automatability factor |
| Asset exposure changes (moved to DMZ, public IP added) | Re-evaluate exposure factor |
| Asset exposure removed (moved internal, public IP removed) | Re-evaluate downward |

The KEV cross-reference script runs weekly and flags any tier changes. The security analyst reviews flagged changes within 2 business days.

---

## 9. Exceptions to Patching Cadence

When a patch cannot be deployed within the defined cadence due to operational constraints, the asset owner must:

1. Submit an exception request via the Exception Process Procedure **before** the SLA deadline.
2. Document compensating controls in place during the exception period.
3. Obtain security team lead approval.
4. Set a review date no more than 90 days from exception approval (30 days for Tier 1 and Tier 2 exceptions).

**Tier 1 and Tier 2 exceptions** require CISO-level approval and must include:
- Written justification for why patching cannot occur within the SLA
- Detailed compensating controls (e.g., network isolation, WAF rule, IPS signature)
- Accelerated review date (30 days maximum)

---

## 10. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Security Program Administrator | Maintain this policy; review annually; report SLA compliance monthly |
| Security Analyst | Classify vulnerabilities by risk tier; create Remediation Projects; initiate forensic triage for Tier 1 |
| IT Operations Lead | Own patch deployment execution; coordinate maintenance windows; report patch completion |
| Asset Owner | Approve emergency maintenance windows; submit exception requests when needed |
| Security Team Lead | Approve Tier 1/2 emergency patches; approve exceptions; review monthly SLA compliance |
| CISO | Approve Tier 1/2 exception requests |

---

## 11. Policy Review and Approval

| Review Date | Reviewer | Approver | Changes Made |
|---|---|---|---|
| [FILL IN] | [FILL IN] | [FILL IN] | Initial approval |
| June 2026 | [FILL IN] | [FILL IN] | BOD 26-04 alignment; risk-tier patching cadences adopted |

---

## 12. Related Documents

- Vulnerability Prioritization Policy
- CISA BOD 26-04 Alignment Crosswalk (`vmp-docs/bod-26-04-alignment.md`)
- Exception Process Procedure
- Vulnerability Management Program Runbook
- KEV Cross-Reference Script (`vmp-docs/kev_cross_reference.py`)
- InsightVM Goals & SLAs Configuration
