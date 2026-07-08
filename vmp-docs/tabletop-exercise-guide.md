# Annual Vulnerability Management Tabletop Exercise Guide

**Program:** Vulnerability Management Program (InsightVM)
**Document Owner:** Security Program Administrator
**Frequency:** Annual
**First Exercise Due:** Within 12 months of Phase 6 completion

---

## 1. Purpose

The annual tabletop exercise tests the vulnerability management program's end-to-end process under a realistic scenario. It surfaces gaps that metrics alone cannot reveal — process ambiguities, unclear ownership, communication breakdowns, and untested edge cases. Findings from the exercise feed directly into the program's continuous improvement cycle.

---

## 2. Exercise Format

| Parameter | Value |
|---|---|
| Format | Facilitated discussion (tabletop) — no live system changes |
| Duration | 2–3 hours |
| Frequency | Annual |
| Facilitator | Security Program Administrator (or external facilitator) |
| Participants | See Section 4 |
| Documentation | Findings and action items recorded during the session |

---

## 3. Scenario: Critical Zero-Day on Production Servers

### Background

A critical zero-day vulnerability (CVE-XXXX-YYYY) is published at 09:00 on a Tuesday morning. The vulnerability affects a widely deployed web server software version running on multiple production servers in your environment. The CVSS v3 score is 9.8. Rapid7 has confirmed `hasExploits = true` and the EPSS score is 0.87. Active exploitation in the wild is reported by threat intelligence sources.

### Inject Timeline

Walk through each inject in sequence. Allow 10–15 minutes of discussion per inject before moving to the next.

---

#### Inject 1: Detection (09:00)

The vulnerability is published. InsightVM has not yet run a scan that detects it on your assets.

**Discussion questions:**
1. How does the security team learn about this vulnerability? (Automation trigger? Vendor advisory? Threat intel feed?)
2. Is the `ALERT-Critical-New` automation trigger configured to fire for CVSS ≥ 9.0 AND hasExploits = true? Who receives the alert?
3. How quickly can the team determine which assets in the environment are running the affected software version — before a scan completes?
4. Who is the first person notified? What is the escalation path?

**Expected process:**
- `ALERT-Critical-New` fires within 15 minutes of the next completed scan.
- Security analyst reviews the alert and opens InsightVM.
- Analyst queries the Exploitable Findings dashboard card for the CVE.

---

#### Inject 2: Scope Assessment (10:00)

InsightVM completes a scan of `CORP-Critical-Assets` and detects the vulnerability on 12 production servers. Three of the affected servers are classified as Very High criticality (domain controllers). Nine are classified as High criticality (production app servers).

**Discussion questions:**
1. How does the analyst determine the full scope of affected assets across all Sites?
2. Are all affected assets in the `CORP-Critical-Assets` Site, or could some be in other Sites that haven't scanned yet?
3. How does the team handle assets that haven't been scanned yet but are likely affected?
4. Who is notified of the scope? How is the notification delivered?
5. Is the asset owner tag (`owner`) populated for all 12 affected servers? If not, how is ownership determined?

**Expected process:**
- Analyst filters InsightVM Vulnerabilities view by CVE ID.
- Analyst creates a Remediation Project: `CRIT-[YYYY-MM]-CVE-XXXX-YYYY` with due date 15 days from today.
- Analyst assigns the project to the IT Operations lead.
- Analyst notifies asset owners via the `owner` tag.

---

#### Inject 3: Prioritization Decision (11:00)

The IT Operations lead reports that patching the three domain controllers requires a 4-hour maintenance window and cannot be done until Saturday (3 days away). The nine app servers can be patched tonight.

**Discussion questions:**
1. Is a 3-day delay acceptable for domain controllers given the 15-day SLA and active exploitation in the wild?
2. What compensating controls can be applied immediately to the domain controllers while awaiting the maintenance window? (Network segmentation? WAF rule? Disable the affected service?)
3. Who approves the compensating controls? Is this documented in InsightVM?
4. Does the 3-day delay require an exception request, or is it within the 15-day SLA window?
5. How is the decision documented?

**Expected process:**
- Security Team Lead approves compensating controls for domain controllers.
- Compensating controls are documented in the Remediation Project comments.
- No exception required if patching is scheduled within 15 days.

---

#### Inject 4: Remediation Execution (Day 2)

The nine app servers are patched overnight. IT Operations triggers a manual InsightVM scan of the patched servers. The scan confirms the vulnerability is no longer detected on 7 of the 9 servers. Two servers still show the vulnerability.

**Discussion questions:**
1. How does the analyst verify patch closure in InsightVM?
2. What is the process for the two servers where the patch did not take effect?
3. How is the Remediation Project updated to reflect partial completion?
4. Who is responsible for re-patching the two failed servers, and what is the timeline?
5. Is the SLA clock still running on the two unpatched servers?

**Expected process:**
- Analyst reviews scan results in InsightVM.
- Remediation Project is updated: 7 assets marked remediated, 2 remain open.
- IT Operations investigates the two failed patches within 24 hours.

---

#### Inject 5: Exception Request (Day 10)

On Day 10, IT Operations reports that one of the domain controllers cannot be patched due to a critical business application dependency. The application vendor has not yet released a compatible patch. The server will remain vulnerable for an estimated 45 additional days.

**Discussion questions:**
1. Who submits the exception request?
2. What information is required in the exception request? (Business justification, compensating controls, accepted risk date)
3. Who approves the exception?
4. What compensating controls are acceptable for a domain controller with a CVSS 9.8 vulnerability?
5. What is the review date for this exception? (Must be ≤ 90 days from approval)
6. How is the exception reflected in the monthly SLA compliance report?

**Expected process:**
- IT Operations submits exception via InsightVM: Vulnerabilities → [Vulnerability] → Add Exception → Acceptable Risk.
- Security Team Lead reviews and approves within 5 business days.
- Review date set to 45 days from approval (within the 90-day maximum).
- Exception appears in `VMP-Exception-Summary` SQL report.

---

#### Inject 6: Executive Reporting (Day 15)

The SLA deadline for Critical vulnerabilities is today. The security team must brief the CISO on the status of the CVE-XXXX-YYYY response.

**Discussion questions:**
1. What data does the security team pull from InsightVM for the briefing?
2. How is the exception for the domain controller presented to the CISO?
3. What is the overall SLA compliance rate for Critical vulnerabilities this month, given the exception?
4. Is the Executive Risk Overview dashboard current and accurate for the briefing?
5. What action items come out of the briefing?

**Expected process:**
- Analyst pulls the `VMP-SLA-Compliance` SQL report.
- Analyst reviews the Executive Risk Overview dashboard.
- Security Team Lead presents: 11 of 12 affected assets remediated within SLA; 1 exception approved with compensating controls.

---

## 4. Participants

| Role | Name | Required |
|---|---|---|
| Facilitator | Security Program Administrator | Yes |
| Security Team Lead | [FILL IN] | Yes |
| Security Analyst (primary) | [FILL IN] | Yes |
| IT Operations Lead | [FILL IN] | Yes |
| Asset Owner representative | [FILL IN] | Recommended |
| CISO or delegate | [FILL IN] | Recommended |
| Note-taker | [FILL IN] | Yes |

---

## 5. Exercise Documentation

### Pre-Exercise

- [ ] Schedule the exercise at least 4 weeks in advance.
- [ ] Distribute the scenario to participants 1 week before the exercise (optional — some facilitators prefer a "cold start").
- [ ] Confirm all participants have access to InsightVM for reference during the exercise.
- [ ] Prepare the inject timeline as a slide deck or printed handout.

### During the Exercise

- [ ] Note-taker records all discussion points, decisions, and identified gaps.
- [ ] Facilitator keeps the discussion on track and ensures all injects are covered.
- [ ] Do not resolve gaps during the exercise — document them as action items.

### Post-Exercise

Complete the findings and action items table below within 5 business days of the exercise.

---

## 6. Findings and Action Items

### Exercise Date: `[FILL IN]`
### Facilitator: `[FILL IN]`
### Participants: `[FILL IN]`

| # | Finding | Inject | Severity | Action Item | Owner | Due Date | Status |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | Open |
| 2 | | | | | | | Open |
| 3 | | | | | | | Open |

**Finding severity:**
- High: Process gap that would materially delay response or cause SLA breach
- Medium: Process ambiguity that could cause inconsistent outcomes
- Low: Minor improvement opportunity

---

## 7. Exercise History

| Exercise Date | Facilitator | Participants | # Findings | # Action Items Closed | Notes |
|---|---|---|---|---|---|
| [FILL IN] | | | | | First exercise |

---

## 8. Related Documents

- Vulnerability Management Program Runbook
- Vulnerability Prioritization Policy
- Patching Cadence Policy
- Exception Process Procedure
- Maturity Model
