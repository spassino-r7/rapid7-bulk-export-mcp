---
inclusion: manual
---

# [Customer Name] — VMP Progress Tracker

## Overview

- **Company**: 
- **Industry**: 
- **Primary contact**: 
- **Engagement start date**: 
- **Target completion**: *(12 months from start)*

## Contacts

| Name | Role | Email | Notes |
|---|---|---|---|
|  |  |  |  |

## Environment

- **Console version**: 
- **Number of sites**: 
- **Total assets**: 
- **Scan engines deployed**: 
- **Insight Agent coverage**: 
- **Cloud integrations**: AWS / Azure / GCP / None
- **Ticketing system**: Jira / ServiceNow / None
- **Data Warehouse**: Enabled / Not enabled

---

## Quarterly Milestone Tracker

### Q1: Asset Discovery + Vulnerability Assessment (Phases 1–2)

**Target: Months 1–3**

#### Phase 1: Asset Discovery and Inventory

| # | Task | Status | Date Completed | Verified By | Notes |
|---|------|--------|----------------|-------------|-------|
| 1.1 | Deploy and register Scan Engines | ☐ Not Started | | | |
| 1.2 | Create Sites per network segment | ☐ Not Started | | | |
| 1.3 | Deploy Insight Agent to managed endpoints | ☐ Not Started | | | |
| 1.4 | Configure cloud integrations | ☐ Not Started | | | |
| 1.5 | Configure scan credentials | ☐ Not Started | | | |
| 1.6 | **Phase 1 Smoke Test** | ☐ Not Started | | | |

**Phase 1 Smoke Test Checklist:**
- [ ] At least one Site per network segment
- [ ] All Scan Engines show "Active" status
- [ ] Insight Agent deployed; assets appearing in console
- [ ] Cloud integrations show successful last-sync
- [ ] Credentials assigned to all Sites
- [ ] Total asset count documented as baseline

**Console SQL verification queries:**
- `Aggregated-Credential-Status.sql` — confirm credential coverage
- `Asset-Inventory.sql` — confirm total asset count
- `Agent-Versions.sql` — confirm agent deployment

---

#### Phase 2: Vulnerability Assessment

| # | Task | Status | Date Completed | Verified By | Notes |
|---|------|--------|----------------|-------------|-------|
| 2.1 | Create custom scan templates | ☐ Not Started | | | |
| 2.2 | Configure scan schedules | ☐ Not Started | | | |
| 2.3 | Assign asset criticality | ☐ Not Started | | | |
| 2.4 | Create Asset Groups | ☐ Not Started | | | |
| 2.5 | Apply tags to all assets | ☐ Not Started | | | |
| 2.6 | Run initial scans and record baselines | ☐ Not Started | | | |
| 2.7 | **Phase 2 Smoke Test** | ☐ Not Started | | | |

**Phase 2 Smoke Test Checklist:**
- [ ] Scan schedules configured for all Sites
- [ ] Asset criticality assigned (no unclassified assets)
- [ ] All required Asset Groups exist with correct membership
- [ ] All required tags applied across inventory
- [ ] Baselines recorded for all Sites
- [ ] Scan history retention ≥ 12 months

**Console SQL verification queries:**
- `Scan-Duration-Report.sql` — confirm scans running on schedule
- `Assets-With-All-Tags.sql` — confirm tag coverage
- `Asset-Group-Info.sql` — confirm groups exist
- `Baseline-Comparison.sql` — confirm baselines recorded

---

### Q2: Prioritization + Remediation Workflow (Phases 3–4)

**Target: Months 4–6**

#### Phase 3: Vulnerability Prioritization

| # | Task | Status | Date Completed | Verified By | Notes |
|---|------|--------|----------------|-------------|-------|
| 3.1 | Verify Active Risk Score is default sort | ☐ Not Started | | | |
| 3.2 | Configure SLA Goals (4 severity tiers) | ☐ Not Started | | | |
| 3.3 | Document and publish prioritization policy | ☐ Not Started | | | |
| 3.4 | **Phase 3 Smoke Test** | ☐ Not Started | | | |

**Phase 3 Smoke Test Checklist:**
- [ ] All four SLA Goals configured and showing compliance values
- [ ] Active Risk Score is default sort in Vulnerabilities view
- [ ] Prioritization policy approved and stored in runbook
- [ ] Spot-check: CVSS ≥ 9.0 + hasExploits = Critical
- [ ] Spot-check: EPSS > 0.70 escalates one tier

**Console SQL verification queries:**
- `Most-Critical-Vulnerabilities.sql` — confirm risk-based ordering
- `Vuln-Age-by-severity.sql` — SLA compliance baseline
- `Top-50-Vulnerabilities-With-Published-Exploit.sql` — exploitable vuln check

---

#### Phase 4: Remediation Workflow

| # | Task | Status | Date Completed | Verified By | Notes |
|---|------|--------|----------------|-------------|-------|
| 4.1 | Create Remediation Project templates | ☐ Not Started | | | |
| 4.2 | Configure ticketing integration | ☐ Not Started | | | |
| 4.3 | Document patching cadence policy | ☐ Not Started | | | |
| 4.4 | Document exception process | ☐ Not Started | | | |
| 4.5 | *(Optional)* Configure SLA breach alert | ☐ Not Started | | | |
| 4.6 | **Phase 4 Smoke Test** | ☐ Not Started | | | |

**Phase 4 Smoke Test Checklist:**
- [ ] Remediation Project templates documented
- [ ] Ticketing integration configured and tested (or documented as N/A)
- [ ] Patching cadence policy approved
- [ ] Exception process documented and communicated
- [ ] One live Remediation Project created with owner and due date

**Console SQL verification queries:**
- `Remediation-Summary.sql` — confirm projects exist
- `Vulnerability-Exceptions.sql` — confirm exception workflow functional
- `Track-Remediaton.sql` — confirm remediation tracking active

---

### Q3: Measurement and Reporting (Phase 5)

**Target: Months 7–9**

#### Phase 5: Measurement and Reporting

| # | Task | Status | Date Completed | Verified By | Notes |
|---|------|--------|----------------|-------------|-------|
| 5.1 | Create Executive Risk Overview dashboard | ☐ Not Started | | | |
| 5.2 | Create Security Operations dashboard | ☐ Not Started | | | |
| 5.3 | Create Remediation Team View dashboard | ☐ Not Started | | | |
| 5.4 | Create SQL reports for core metrics | ☐ Not Started | | | |
| 5.5 | Establish monthly reporting cadence | ☐ Not Started | | | |
| 5.6 | *(Optional)* Configure automation triggers | ☐ Not Started | | | |
| 5.7 | **Phase 5 Smoke Test** | ☐ Not Started | | | |

**Phase 5 Smoke Test Checklist:**
- [ ] All three dashboards configured and shared with correct audiences
- [ ] All five SQL reports created, scheduled, and run at least once
- [ ] Automation triggers active (or compensating review cadence documented)
- [ ] Monthly reporting cadence documented with assigned report owner
- [ ] Scan coverage ≥ 95% confirmed

**Console SQL verification queries:**
- `Vuln-Coverage.sql` — confirm scan coverage
- `New-and-Remediated-Vulns-with-Vuln-details.sql` — new vs. remediated trend
- `Machines-not-scanned-last-30-days.sql` — coverage gaps
- `Scan-History-Risk.sql` — risk trend data

---

### Q4: Program Maturity (Phase 6)

**Target: Months 10–12**

#### Phase 6: Program Maturity

| # | Task | Status | Date Completed | Verified By | Notes |
|---|------|--------|----------------|-------------|-------|
| 6.1 | Configure policy compliance scans | ☐ Not Started | | | |
| 6.2 | Verify policy compliance reporting | ☐ Not Started | | | |
| 6.3 | Verify Goals/SLA tracking operational | ☐ Not Started | | | |
| 6.4 | Document maturity model | ☐ Not Started | | | |
| 6.5 | Schedule tabletop exercise | ☐ Not Started | | | |
| 6.6 | Complete program runbook | ☐ Not Started | | | |
| 6.7 | Establish quarterly release review | ☐ Not Started | | | |
| 6.8 | **Phase 6 Smoke Test** | ☐ Not Started | | | |

**Phase 6 Smoke Test Checklist:**
- [ ] Policy compliance scans configured and run at least once
- [ ] Automation triggers active (or compensating cadence documented)
- [ ] Maturity model approved; first assessment complete
- [ ] Runbook contains all required sections
- [ ] Tabletop exercise scheduled
- [ ] Quarterly release review scheduled

**Console SQL verification queries:**
- `Policy-Compliance.sql` — confirm policy results exist
- `Policy-Report-With-Details.sql` — per-asset compliance detail
- `Vuln-Age-by-severity.sql` — SLA compliance final state

---

## Program Completion

| Milestone | Status | Date |
|-----------|--------|------|
| All 6 phase smoke tests passed | ☐ | |
| First monthly report delivered | ☐ | |
| All SLA Goals showing live values | ☐ | |
| All dashboards accessible to audiences | ☐ | |
| Runbook complete and approved | ☐ | |
| Security team lead sign-off | ☐ | |

---

## Notes & History

<!-- Chronological notes — newest at top -->

### [YYYY-MM-DD]


