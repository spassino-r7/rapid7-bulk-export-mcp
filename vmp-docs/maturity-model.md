# Vulnerability Management Program Maturity Model

**Program:** Vulnerability Management Program (InsightVM)
**Document Owner:** Security Program Administrator
**Assessment Cycle:** Annual
**Approval Required:** Security Leadership

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | [FILL IN] | [FILL IN] | Initial release |

---

## 1. Purpose

This document defines the four-level maturity model for the Vulnerability Management Program. It provides a structured framework for assessing program maturity annually, identifying gaps, and planning improvements. The model is aligned to the six phases of the VMP and uses InsightVM's native capabilities as the primary measurement instrument.

---

## 2. Maturity Levels

### Level 1 — Initial

**Characteristics:**
- Vulnerability scanning is ad hoc — scans are run manually when prompted by incidents or audits, not on a defined schedule.
- No formal asset inventory or scope definition. Coverage is unknown.
- Vulnerability findings are not prioritized; all findings are treated equally or ignored.
- No defined remediation process. Fixes are applied reactively without tracking.
- No metrics or reporting. Program effectiveness cannot be measured.
- No documentation. The program depends entirely on individual knowledge.

**Typical indicators:**
- InsightVM is installed but fewer than half of known assets are in Sites.
- No scan schedules configured.
- No Asset Groups, Tags, or criticality assignments.
- No Remediation Projects.
- No dashboards or SQL reports.

---

### Level 2 — Developing

**Characteristics:**
- Scheduled scans are configured for most assets, but coverage may be incomplete (< 90%).
- Basic asset inventory exists. Sites are defined but may not reflect all network segments.
- Vulnerability prioritization is informal — analysts use CVSS scores but without a documented policy.
- Remediation tracking is informal — spreadsheets or ad hoc tickets, not InsightVM Remediation Projects.
- Basic reporting exists but is inconsistent. No defined reporting cadence.
- Some documentation exists but is incomplete or out of date.

**Typical indicators:**
- Scan schedules configured for most Sites.
- Asset criticality partially assigned.
- Some Asset Groups and Tags applied.
- Remediation Projects used occasionally.
- At least one dashboard configured.
- No formal SLA Goals configured.

---

### Level 3 — Defined

**Characteristics:**
- Full asset scan coverage ≥ 95% within each 30-day rolling window.
- All assets have assigned criticality, tags, and Asset Group membership.
- Risk-based prioritization is documented and consistently applied (CVSS v3 + EPSS + criticality + hasExploits).
- SLA Goals configured in InsightVM for all four severity tiers. SLA compliance is tracked and reported.
- Remediation Projects used for all active remediation work. All projects have assigned owners and due dates.
- Three dashboards operational (Executive, Operations, Remediation).
- Five SQL reports scheduled and running monthly.
- Monthly reporting cadence established with a named report owner.
- Exception process documented and in use.
- Program runbook exists and covers all required sections.

**This is the target state for a fully operational VMP.**

---

### Level 4 — Optimizing

**Characteristics:**
- All Level 3 characteristics are met.
- Policy compliance scanning active for all major asset classes (CIS Benchmarks, DISA STIG).
- All five automation triggers operational and tested.
- Annual maturity assessment conducted and documented.
- Annual tabletop exercise conducted and action items tracked.
- Quarterly InsightVM release review process established.
- Program runbook reviewed and updated at least annually.
- Continuous improvement cycle: gaps identified in assessments and tabletop exercises are tracked as action items with owners and due dates.
- Year-over-year metric trends show consistent improvement in MTTR, SLA compliance, and coverage.

---

## 3. Maturity Assessment Scorecard

Assess each program phase on a 1–4 scale using the level definitions above. Score each phase independently, then calculate the overall program level as the lowest phase score (the program is only as mature as its weakest phase).

### Assessment Date: `[FILL IN]`
### Assessed By: `[FILL IN]`
### Approved By: `[FILL IN]`

| Program Phase | Score (1–4) | Evidence | Gaps Identified |
|---|---|---|---|
| Phase 1: Asset Discovery | | | |
| Phase 2: Vulnerability Assessment | | | |
| Phase 3: Prioritization | | | |
| Phase 4: Remediation Workflow | | | |
| Phase 5: Measurement & Reporting | | | |
| Phase 6: Maturity & Policy Compliance | | | |
| **Overall Program Level** | | | |

**Overall program level = lowest individual phase score.**

---

## 4. Phase-Level Scoring Criteria

### Phase 1: Asset Discovery

| Score | Criteria |
|---|---|
| 1 | < 50% of known assets in InsightVM Sites; no scan schedules |
| 2 | 50–89% coverage; Sites defined but incomplete; no cloud integrations |
| 3 | ≥ 95% coverage; all Sites defined; cloud integrations active; Insight Agent deployed; credentials configured |
| 4 | All Level 3 criteria met; quarterly scope review documented; stale asset process defined |

### Phase 2: Vulnerability Assessment

| Score | Criteria |
|---|---|
| 1 | No scan schedules; no asset criticality assigned; no baselines |
| 2 | Scan schedules configured for most Sites; partial criticality assignment; some Asset Groups |
| 3 | All Sites scheduled; all assets have criticality, tags, and Asset Group membership; baselines recorded; 12-month scan history retention |
| 4 | All Level 3 criteria met; credential failure rate < 2%; scan history reviewed quarterly |

### Phase 3: Prioritization

| Score | Criteria |
|---|---|
| 1 | No prioritization framework; CVSS only or no prioritization |
| 2 | CVSS-based prioritization; no EPSS or exploit data used; no SLA Goals |
| 3 | Active Risk Score as default sort; all four SLA Goals configured; prioritization policy documented and approved |
| 4 | All Level 3 criteria met; policy reviewed annually; EPSS threshold reviewed and confirmed |

### Phase 4: Remediation Workflow

| Score | Criteria |
|---|---|
| 1 | No formal remediation tracking; no Remediation Projects |
| 2 | Remediation Projects used occasionally; no consistent naming or ownership |
| 3 | All active remediation in Remediation Projects with owners and due dates; ticketing integration configured; exception process documented; patching cadence policy approved |
| 4 | All Level 3 criteria met; exception review rate 100% on time; patching cadence policy reviewed annually |

### Phase 5: Measurement & Reporting

| Score | Criteria |
|---|---|
| 1 | No dashboards; no reports; no metrics |
| 2 | At least one dashboard; ad hoc reporting; no defined cadence |
| 3 | All three dashboards operational; all five SQL reports scheduled; monthly reporting cadence with named report owner; all five automation triggers active |
| 4 | All Level 3 criteria met; 24-month metric archive maintained; year-over-year trend analysis presented annually |

### Phase 6: Maturity & Policy Compliance

| Score | Criteria |
|---|---|
| 1 | No policy compliance scanning; no maturity assessment |
| 2 | Policy compliance scanning configured for some asset classes; no formal maturity model |
| 3 | Policy compliance scanning for all major asset classes; maturity model documented; first assessment complete; runbook complete |
| 4 | All Level 3 criteria met; annual tabletop exercise conducted; quarterly InsightVM release review; continuous improvement cycle active |

---

## 5. Gap Tracking and Action Items

Document all gaps identified during the assessment and assign owners and due dates.

| Gap | Phase | Priority | Owner | Due Date | Status |
|---|---|---|---|---|---|
| [FILL IN] | | | | | Open |

---

## 6. Assessment History

| Assessment Date | Overall Level | Assessed By | Approved By | Key Findings |
|---|---|---|---|---|
| [FILL IN] | | | | Initial assessment |

---

## 7. Related Documents

- Vulnerability Management Program Runbook
- Vulnerability Prioritization Policy
- Patching Cadence Policy
- Exception Process Procedure
- Monthly Reporting Cadence
