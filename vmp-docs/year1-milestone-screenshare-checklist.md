# Year 1 Milestone — Console Screenshare Verification Checklist

**Purpose:** Walk through this checklist during a screenshare session with the customer to verify all Year 1 VMP milestones are met. No API access required — all checks are visual via the InsightVM console or by asking the customer to show supporting documentation.

**How to use:** Go through each phase in order. Mark Pass/Fail for each check. Note any gaps in the Notes column for follow-up.

---

## Q1: Asset Discovery + Vulnerability Assessment (Phases 1–2)

### Phase 1: Asset Discovery and Inventory

| # | Check | Where to Look | Pass/Fail | Notes |
|---|-------|---------------|-----------|-------|
| 1.1 | At least one Site per network segment | **Sites** tab — verify site list matches known network segments | | |
| 1.2 | All Scan Engines show Active | **Administration → Engines** — status column = "Active" | | |
| 1.3 | Insight Agent deployed to managed endpoints | **Administration → Agents** — count and last-checkin dates | | |
| 1.4 | Cloud integrations configured (if applicable) | **Administration → Cloud Configuration** — last sync status | | |
| 1.5 | Credentials assigned to all Sites | **Site Configuration → Authentication** — for each site, confirm credentials exist | | |
| 1.6 | Asset count documented as baseline | **Assets** tab — total count noted | | |

### Phase 2: Vulnerability Assessment

| # | Check | Where to Look | Pass/Fail | Notes |
|---|-------|---------------|-----------|-------|
| 2.1 | Scan schedules configured for all Sites | **Site Configuration → Schedule** — each site has a recurrence set | | |
| 2.2 | Asset criticality assigned (no unclassified) | **Assets → filter by Criticality = "Default/None"** — should return 0 | | |
| 2.3 | Asset Groups reflect org boundaries | **Asset Groups** tab — groups exist for BU/environment, not just OS type | | |
| 2.4 | Tags applied to all assets | **Assets → any asset → Tags** — spot check 3–5 assets for `env`, `owner`, `os-type` tags | | |
| 2.5 | Baselines recorded for all Sites | **Reports → Baseline Comparison** — each Site has a baseline date | | |
| 2.6 | Scan history retention ≥ 12 months | **Administration → Security Console → Maintenance** — retention setting | | |

**Q1 Pass:** All Phase 1 and Phase 2 checks are ✅

---

## Q2: Prioritization + Remediation Workflow (Phases 3–4)

### Phase 3: Vulnerability Prioritization

| # | Check | Where to Look | Pass/Fail | Notes |
|---|-------|---------------|-----------|-------|
| 3.1 | Active Risk Score is default sort | **Vulnerabilities** tab — sorted by Risk Score descending | | |
| 3.2 | SLA Goals configured (4 severity tiers) | **Goals & SLAs** — verify Critical/15d, High/30d, Medium/90d, Low/180d goals exist | | |
| 3.3 | Prioritization policy documented | Ask customer to show the document (runbook or shared drive) | | |
| 3.4 | Spot-check: CVSS ≥ 9.0 + exploit = Critical | Pick one from vuln list, confirm it's classified Critical priority | | |

### Phase 4: Remediation Workflow

| # | Check | Where to Look | Pass/Fail | Notes |
|---|-------|---------------|-----------|-------|
| 4.1 | Remediation Projects exist with owners | **Remediation → Projects** — at least one active project with assigned owner and due date | | |
| 4.2 | Exception/exclusion process documented | Ask customer to show the process doc; verify it covers False Positive, Compensating Control, and Acceptable Risk types | | |
| 4.3 | Exceptions are separate from SLA breaches | Confirm: exceptions are only for "won't fix" (infeasible, false positive, accepted risk) — NOT for "haven't fixed yet" (SLA miss) | | |
| 4.4 | Patching cadence policy exists | Ask customer to show the policy (defines patch windows per criticality tier) | | |
| 4.5 | At least one exception recorded in console | **Vulnerabilities → Exceptions** — confirm at least one example with justification, type, and review date | | |

**Q2 Pass:** All Phase 3 and Phase 4 checks are ✅

---

## Q3: Measurement and Reporting (Phase 5)

### Phase 5: Measurement and Reporting

| # | Check | Where to Look | Pass/Fail | Notes |
|---|-------|---------------|-----------|-------|
| 5.1 | Executive Risk Overview dashboard exists | **Dashboards** — risk trend, SLA compliance, top risks, coverage gauge | | |
| 5.2 | Security Operations dashboard exists | **Dashboards** — new findings, SLA breaches, analyst workqueue | | |
| 5.3 | Remediation Team View dashboard exists | **Dashboards** — open projects, overdue items, asset-level detail | | |
| 5.4 | Reporting via Bulk Export API configured (5 core metrics) | **Bulk Export API** — MTTR, SLA compliance, exploitable findings, exceptions, coverage via `query_rapid7` | | |
| 5.5 | Monthly reporting cadence established | Ask: who owns the report, when did it last go out, who receives it | | |
| 5.6 | Scan coverage ≥ 95% | Executive dashboard or SQL report — coverage % within last 30 days | | |

**Q3 Pass:** All Phase 5 checks are ✅

---

## Q4: Program Maturity (Phase 6)

### Phase 6: Program Maturity

| # | Check | Where to Look | Pass/Fail | Notes |
|---|-------|---------------|-----------|-------|
| 6.1 | Policy compliance scans configured | **Sites** — at least one site using CIS or STIG policy scan template | | |
| 6.2 | Policy compliance results visible | **Policies** tab — results exist with pass/fail per rule per asset | | |
| 6.3 | Goals showing live compliance values | **Goals & SLAs** — all 4 goals show current compliance % (not "No data") | | |
| 6.4 | Maturity model documented | Ask customer to show the maturity model and their current self-assessment score | | |
| 6.5 | Program runbook complete | Ask customer to show runbook; verify sections for: scans, Asset Groups, tags, Remediation Projects, Goals, dashboards, SQL reports | | |
| 6.6 | Tabletop exercise scheduled | Ask for date or calendar invite — must be within 12 months of Phase 6 completion | | |
| 6.7 | Quarterly release review scheduled | Ask for recurring calendar entry to review InsightVM release notes | | |

**Q4 Pass:** All Phase 6 checks are ✅

---

## Year 1 Pass Criteria

| Quarter | Phases | Status |
|---------|--------|--------|
| Q1 | Phases 1–2: Asset Discovery + Vulnerability Assessment | |
| Q2 | Phases 3–4: Prioritization + Remediation Workflow | |
| Q3 | Phase 5: Measurement and Reporting | |
| Q4 | Phase 6: Program Maturity | |

**Year 1 Complete:** All 4 quarters pass ✅

---

## Session Notes

**Customer:**
**Date:**
**Assessor:**
**Console Version:**

### Gaps Identified

| # | Gap | Phase | Remediation Action | Owner | Target Date |
|---|-----|-------|-------------------|-------|-------------|
| | | | | | |

### Follow-up Items

-

---

*Last updated: June 2026*
