# Vulnerability Management Program Runbook

**Program:** Vulnerability Management Program (InsightVM)
**Document Owner:** Security Program Administrator
**Review Cycle:** Annual
**Last Reviewed:** `[FILL IN]`
**Approved By:** `[FILL IN]`

> This is a living document. Update it whenever a configuration artifact is created, modified, or retired. All `[FILL IN]` placeholders must be completed before the program is considered operational.

---

## Table of Contents

1. [Program Overview](#1-program-overview)
2. [Roles and Contacts](#2-roles-and-contacts)
3. [Scan Configurations](#3-scan-configurations)
4. [Asset Groups](#4-asset-groups)
5. [Tags](#5-tags)
6. [Remediation Project Templates](#6-remediation-project-templates)
7. [Goals and SLA Definitions](#7-goals-and-sla-definitions)
8. [Dashboard Layouts](#8-dashboard-layouts)
9. [SQL Report Definitions](#9-sql-report-definitions)
10. [Policy Compliance Configurations](#10-policy-compliance-configurations)
11. [Automation Trigger Definitions](#11-automation-trigger-definitions)
12. [Exception Process](#12-exception-process)
13. [Maturity Model and Assessment Schedule](#13-maturity-model-and-assessment-schedule)
14. [Program Baseline](#14-program-baseline)
15. [Change Log](#15-change-log)

---

## 1. Program Overview

### Purpose

This runbook documents all configuration artifacts, operational procedures, and reference information for the Vulnerability Management Program (VMP) built on Rapid7 InsightVM. It is the authoritative reference for program staff and must be updated whenever a configuration change is made.

### Program Goals

- Achieve and maintain ≥ 95% asset scan coverage within each 30-day rolling window.
- Remediate Tier 1 vulnerabilities within 3 days, Tier 2 within 14 days, Tier 3 within 60 days, Tier 4 at next scheduled upgrade (aligned to CISA BOD 26-04).
- Maintain legacy CVSS-based SLAs during transition: Critical within 15 days, High within 30 days, Medium within 90 days, Low within 180 days.
- Provide executive, operations, and remediation-team dashboards as the single pane of glass for vulnerability risk.
- Cross-reference open vulnerabilities against CISA KEV catalog weekly.
- Conduct annual maturity assessments and tabletop exercises to drive continuous improvement.
- Continuously identify and tag all internet-facing assets for exposure-based prioritization.

### InsightVM Console URL

`[FILL IN — e.g., https://insightvm.company.internal:3780]`

### Program Start Date

`[FILL IN]`

---

## 2. Roles and Contacts

| Role | Name | Email | Phone |
|---|---|---|---|
| Security Program Administrator | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |
| Security Team Lead | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |
| Security Analyst (primary) | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |
| Security Analyst (backup) | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |
| IT Operations Lead | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |
| Monthly Report Owner | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |
| Security Team DL | N/A | `[FILL IN]` | N/A |
| CISO | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |

---

## 3. Scan Configurations

### 3.1 Scan Engines

| Engine Name | Hostname | IP Address | Network Segment | Status | Registration Date |
|---|---|---|---|---|---|
| `SE-HQ` | `[FILL IN]` | `[FILL IN]` | Corporate HQ | Active | `[FILL IN]` |
| `SE-DMZ` | `[FILL IN]` | `[FILL IN]` | DMZ | Active | `[FILL IN]` |
| `SE-AWS-Prod` | `[FILL IN]` | `[FILL IN]` | AWS Production VPC | Active | `[FILL IN]` |

**Console path:** Administration → Engines

**Connectivity:** All engines communicate with the console on TCP 40814 (outbound from engine to console).

---

### 3.2 Sites

| Site Name | IP Range / Scope | Scan Engine | Scan Template | Schedule | Criticality Tier |
|---|---|---|---|---|---|
| `CORP-HQ-Servers` | `[FILL IN]` | `SE-HQ` | `VMP-Standard-30Day` | Every 30d, Sun 01:00 | Medium |
| `CORP-HQ-Workstations` | `[FILL IN]` | `SE-HQ` | `VMP-Standard-30Day` | Every 30d, Sun 01:00 | Medium |
| `CORP-DMZ` | `[FILL IN]` | `SE-DMZ` | `VMP-Standard-30Day` | Every 30d, Sun 01:00 | Medium |
| `CORP-Critical-Assets` | `[FILL IN]` | `SE-HQ` | `VMP-Critical-7Day` | Every 7d, Sat 02:00 | Very High / High |
| `CLOUD-AWS-Production` | AWS cloud connector | `SE-AWS-Prod` | `VMP-Standard-30Day` | Every 30d, Sun 01:00 | High |
| `CLOUD-AWS-Dev` | AWS cloud connector | `SE-AWS-Prod` | `VMP-Standard-30Day` | Every 30d, Sun 01:00 | Low |
| `CLOUD-Azure-Production` | Azure cloud connector | `[FILL IN]` | `VMP-Standard-30Day` | Every 30d, Sun 01:00 | High |
| `REMOTE-Endpoints` | Agent-assessed | N/A | N/A (continuous) | Continuous | Medium |

**Site naming convention:** `{ENVIRONMENT}-{SEGMENT}-{OPTIONAL_QUALIFIER}`

---

### 3.3 Scan Templates

| Template Name | Base | Throttle | Speed | Timeout | Use Case |
|---|---|---|---|---|---|
| `VMP-Critical-7Day` | Full Audit without Web Spider | Disabled | Maximum | 4 hours | Very High / High criticality assets |
| `VMP-Standard-30Day` | Full Audit without Web Spider | Enabled | Normal | 8 hours | All other assets |
| `CIS-Linux-Policy` | CIS Policy Scan | Enabled | Normal | 4 hours | Linux server compliance |
| `CIS-Windows-Policy` | CIS Policy Scan | Enabled | Normal | 4 hours | Windows server/workstation compliance |
| `DISA-STIG-Policy` | DISA STIG Policy Scan | Enabled | Normal | 4 hours | Network device compliance |

---

### 3.4 Scan Credentials

| Credential Name | Type | Account | Sites Assigned | Rotation Schedule | Last Rotated |
|---|---|---|---|---|---|
| `WIN-Domain-Scan` | Windows (domain) | `svc-insightvm-scan` | All CORP sites | 90 days | `[FILL IN]` |
| `SSH-Key-Scan` | SSH (key-based) | `insightvm-scan` | All Linux sites | 180 days | `[FILL IN]` |
| `SNMP-v3-Scan` | SNMP v3 | `insightvm-snmp` | Network device sites | 180 days | `[FILL IN]` |
| `DB-ReadOnly-Scan` | Database | `insightvm-db` | DB server sites | 90 days | `[FILL IN]` |

**Console path:** Administration → Credentials

---

## 4. Asset Groups

| Group Name | Type | Rule / Scope | Purpose | Created Date |
|---|---|---|---|---|
| `AG-Production` | Dynamic | Tag: `env=production` | Production environment scoping | `[FILL IN]` |
| `AG-Staging` | Dynamic | Tag: `env=staging` | Staging environment scoping | `[FILL IN]` |
| `AG-Development` | Dynamic | Tag: `env=development` | Dev environment scoping | `[FILL IN]` |
| `AG-Lab` | Dynamic | Tag: `env=lab` | Lab environment scoping | `[FILL IN]` |
| `AG-Critical-Assets` | Dynamic | Criticality ≥ 9 | Very High criticality assets | `[FILL IN]` |
| `AG-High-Assets` | Dynamic | Criticality = 8 | High criticality assets | `[FILL IN]` |
| `AG-BU-Finance` | Dynamic | Tag: `bu=finance` | Finance BU scoping | `[FILL IN]` |
| `AG-BU-Engineering` | Dynamic | Tag: `bu=engineering` | Engineering BU scoping | `[FILL IN]` |
| `AG-Windows-Servers` | Dynamic | Tag: `os-type=windows-server` | Windows server scoping | `[FILL IN]` |
| `AG-Linux-Servers` | Dynamic | Tag: `os-type=linux-server` | Linux server scoping | `[FILL IN]` |
| `AG-Workstations` | Dynamic | Tag: `os-type=workstation` | Workstation scoping | `[FILL IN]` |
| `AG-Network-Devices` | Dynamic | Tag: `os-type=network-device` | Network device scoping | `[FILL IN]` |

**Console path:** Asset Groups

---

## 5. Tags

### Tag Schema

| Tag Category | Required Values | Purpose |
|---|---|---|
| `env` | `production`, `staging`, `development`, `lab` | Environment scoping |
| `owner` | `{team-name}` (e.g., `infra-ops`, `cloud-eng`, `app-team`) | Remediation ownership routing |
| `data-class` | `pii`, `pci`, `phi`, `internal`, `public` | Data sensitivity |
| `os-type` | `windows-server`, `linux-server`, `workstation`, `network-device`, `cloud-vm` | Scan template and policy selection |
| `bu` | `{business-unit}` (e.g., `finance`, `hr`, `engineering`) | BU scoping |
| `compliance` | `cis-l1`, `cis-l2`, `disa-stig`, `pci-dss` | Policy compliance scope |
| `exposure` | `internet-facing`, `internal` | BOD 26-04 exposure classification (Tier 1/2 vs Tier 3/4) |

### Tag Assignment Process

1. New assets are tagged within 5 business days of discovery.
2. Tags are applied via **Assets → [Asset] → Tags** or bulk-applied via dynamic Asset Group rules.
3. Tag coverage is verified monthly by filtering **Assets** by each tag category and confirming no untagged assets remain.
4. The Program Administrator reviews tag coverage as part of the monthly reporting cycle.

---

## 6. Remediation Project Templates

### Naming Conventions

| Project Type | Naming Convention | Owner | Due Date Basis |
|---|---|---|---|
| Critical patch sprint | `CRIT-{YYYY-MM}-{DESCRIPTION}` | IT Operations lead | 15 days from detection |
| High monthly patch | `HIGH-{YYYY-MM}-{BU}` | IT Operations / BU owner | 30 days from detection |
| Medium quarterly | `MED-{YYYY-Q#}-{BU}` | IT Operations / BU owner | 90 days from detection |
| Exception tracked | `EXCPT-{YYYY-MM}-{VULN-ID}` | Security team | Exception review date |

### Owner Assignment Process

1. The security analyst creates the Remediation Project in InsightVM.
2. The analyst assigns the owner based on the `owner` tag of the affected assets.
3. If the `owner` tag is not set, the analyst contacts the IT Operations lead to determine ownership.
4. No project may be activated without an assigned owner.

### Ticketing Integration

**System:** `[FILL IN — Jira / ServiceNow / Not applicable]`

| InsightVM Severity | Ticket Priority |
|---|---|
| Critical | P1 |
| High | P2 |
| Medium | P3 |
| Low | P4 |

**Console path:** Administration → Integrations → Ticketing

---

## 7. Goals and SLA Definitions

| Goal Name | Metric | SLA Window | Target | Scope | Status |
|---|---|---|---|---|---|
| `SLA-Tier1-3d` | % remediated within 3 days | 3 calendar days | ≥ 95% | Internet-facing + KEV + Automatable + Total impact | `[FILL IN]` |
| `SLA-Tier2-14d` | % remediated within 14 days | 14 calendar days | ≥ 90% | Internet-facing + KEV | `[FILL IN]` |
| `SLA-Tier3-60d` | % remediated within 60 days | 60 calendar days | ≥ 85% | Internal + KEV, OR Internet-facing + No KEV | `[FILL IN]` |
| `SLA-Tier4-Upgrade` | % remediated at next upgrade | Next scheduled upgrade | ≥ 80% | All other findings | `[FILL IN]` |
| `SLA-Critical-15d` (legacy) | % remediated within 15 days | 15 calendar days | ≥ 95% | All assets | `[FILL IN]` |
| `SLA-High-30d` (legacy) | % remediated within 30 days | 30 calendar days | ≥ 90% | All assets | `[FILL IN]` |
| `SLA-Medium-90d` (legacy) | % remediated within 90 days | 90 calendar days | ≥ 85% | All assets | `[FILL IN]` |
| `SLA-Low-180d` (legacy) | % remediated within 180 days | 180 calendar days | ≥ 80% | All assets | `[FILL IN]` |

**Console path:** Goals & SLAs

**First SLA baseline recorded:** `[FILL IN — date and compliance values]`

---

## 8. Dashboard Layouts

### Dashboard 1: `VMP - Executive Risk Overview`

**Audience:** Security leadership (read-only access)  
**Console path:** Dashboards → VMP - Executive Risk Overview

| Card Name | Type | Configuration |
|---|---|---|
| Risk Score Trend | Line chart | 12-month rolling, all assets |
| SLA Compliance Rate | Gauge | By severity tier, current month; linked to each SLA Goal |
| Top 10 Highest-Risk Assets | Table | Sorted by Active Risk Score |
| Exploitable Findings Count | KPI card | hasExploits = true OR EPSS > 0.50 |
| Coverage Rate | Gauge | % assets scanned in last 30 days |
| Vulnerability Backlog Trend | Bar chart | 6-month rolling, by severity |
| Policy Compliance Summary | Card | Overall pass rate by benchmark (added in Phase 6) |

---

### Dashboard 2: `VMP - Security Operations`

**Audience:** Security operations team  
**Console path:** Dashboards → VMP - Security Operations

| Card Name | Type | Configuration |
|---|---|---|
| New Findings (Last 7 Days) | KPI card | First-found timestamp in last 7 days |
| SLA Breach Count | KPI card | Vulnerabilities past SLA, by severity |
| Analyst Workqueue | Table | Open vulns sorted by Active Risk Score |
| Credential Failure Assets | Table | Assets with auth failures in last scan |
| Critical Vulns Awaiting Patch | Table | CVSS ≥ 9.0 AND hasExploits = true |
| Scan Coverage by Site | Table | Last scan date and coverage % per Site |

---

### Dashboard 3: `VMP - Remediation Team`

**Audience:** Remediation team leads and BU owners  
**Console path:** Dashboards → VMP - Remediation Team

| Card Name | Type | Configuration |
|---|---|---|
| Open Remediation Projects | Table | All active projects with due dates |
| Overdue Projects | KPI card | Projects past due date |
| Asset-Level Vulnerability Detail | Table | Filtered by `owner` tag |
| Patch Compliance by BU | Bar chart | % remediated by business unit |
| Upcoming SLA Deadlines | Table | Vulns expiring in next 14 days |
| Exception Summary | Table | Open exceptions by severity |

---

## 9. SQL Report Definitions

All SQL reports are located in **Reports → SQL Query Export**. Full query text is in `vmp-docs/sql-reports.md`.

| Report Name | Purpose | Schedule | Recipients | Last Run |
|---|---|---|---|---|
| `VMP-MTTR-Monthly` | Monthly MTTR by severity | 1st business day of month | Security team DL | `[FILL IN]` |
| `VMP-SLA-Compliance` | SLA compliance rate by severity | 1st business day of month | Security team DL, leadership | `[FILL IN]` |
| `VMP-Exploitable-Findings` | Exploitable findings (hasExploits OR EPSS > 0.50) | 1st business day of month | Security team DL | `[FILL IN]` |
| `VMP-Exception-Summary` | Open exception summary | 1st business day of month | Security team DL | `[FILL IN]` |
| `VMP-Scan-Coverage` | Scan coverage by Site | 1st business day of month | Security team DL | `[FILL IN]` |
| `VMP-BOD-Tier-Classification` | BOD 26-04 risk tier distribution | 1st business day of month | Security team DL, leadership | `[FILL IN]` |
| `VMP-Exposure-Summary` | Open vulns by exposure status | 1st business day of month | Security team DL, leadership | `[FILL IN]` |
| `VMP-KEV-Overlap` | Exploitable findings (KEV proxy) | Weekly (Monday) | Security team DL | `[FILL IN]` |

---

## 10. Policy Compliance Configurations

| Template Name | Benchmark | Profile | Asset Class | Sites Assigned | Schedule |
|---|---|---|---|---|---|
| `CIS-Linux-Policy` | CIS Benchmarks | CIS Ubuntu 20.04 L1 (or applicable distro) | Linux servers | `CORP-HQ-Servers`, `CLOUD-AWS-Production` | 1st Sunday of month |
| `CIS-Windows-Policy` | CIS Benchmarks | CIS Windows Server 2019 L1 | Windows servers | `CORP-HQ-Servers`, `CORP-Critical-Assets` | 1st Sunday of month |
| `CIS-Workstation-Policy` | CIS Benchmarks | CIS Windows 10/11 L1 | Workstations | `CORP-HQ-Workstations` | 1st Sunday of month |
| `DISA-STIG-Policy` | DISA STIG | Applicable STIG profile | Network devices | `CORP-DMZ` | 1st Sunday of month |

**Console path:** Administration → Scan Templates (policy templates) / Policy Manager (results)

**Tag prerequisite:** Assets must have the `compliance` tag applied before policy compliance scans are run (see Section 5).

---

## 11. Automation Trigger Definitions

All triggers are configured in **Administration → Automation**.

| Trigger Name | Event | Condition | Action | Recipient | Tested Date |
|---|---|---|---|---|---|
| `ALERT-Tier1-New` | New vulnerability found | Internet-Facing + KEV + hasExploits + CVSS ≥ 9.0 | Email alert + page | Security team DL + on-call | `[FILL IN]` |
| `ALERT-Critical-New` | New vulnerability found | CVSS ≥ 9.0 AND hasExploits = true | Email alert | Security team DL | `[FILL IN]` |
| `ALERT-SLA-Breach` | SLA breach | Vulnerability age > SLA target | Email alert | Asset owner + security team | `[FILL IN]` |
| `ALERT-Coverage-Drop` | Scan coverage | Coverage < 90% | Email alert | Program Administrator | `[FILL IN]` |
| `ALERT-Cred-Failure` | Credential failure | Auth failure on any asset | Email alert | Program Administrator | `[FILL IN]` |
| `ALERT-Goal-Breach` | Goal threshold | SLA Goal compliance < target | Email alert | Security team lead | `[FILL IN]` |
| `ALERT-KEV-Match` | Weekly KEV cross-reference | New CVE match found in open findings | Email alert | Security team DL | `[FILL IN]` |

**SLA:** All triggers must deliver notifications within 15 minutes of the triggering event.

---

## 12. Exception Process

See full procedure: `vmp-docs/exception-process-procedure.md`

### Quick Reference

| Step | Action | Owner |
|---|---|---|
| 1. Submit | Vulnerabilities → [Vulnerability] → Add Exception | Requestor |
| 2. Approve | Exceptions → Pending → Approve (enter approver name in comments) | Security Team Lead |
| 3. Record | Confirm review date ≤ 90 days from approval | Program Administrator |
| 4. Review | Monthly — generate VMP-Exception-Summary report; review exceptions due this month | Program Administrator |

### Exception Register

See monthly exception register in the `VMP-Exception-Summary` SQL report output. Archive monthly reports at: `[FILL IN — archive location]`

---

## 13. Maturity Model and Assessment Schedule

See full model: `vmp-docs/maturity-model.md`

### Assessment Schedule

| Assessment # | Scheduled Date | Completed Date | Overall Level | Assessed By |
|---|---|---|---|---|
| 1 | `[FILL IN]` | | | |
| 2 | `[FILL IN — 1 year after #1]` | | | |

### Tabletop Exercise Schedule

See exercise guide: `vmp-docs/tabletop-exercise-guide.md`

| Exercise # | Scheduled Date | Completed Date | # Findings | Facilitator |
|---|---|---|---|---|
| 1 | `[FILL IN]` | | | |
| 2 | `[FILL IN — 1 year after #1]` | | | |

### Quarterly InsightVM Release Review

| Quarter | Review Date | Reviewer | Features Evaluated | Adoption Decision |
|---|---|---|---|---|
| Q1 `[YEAR]` | `[FILL IN]` | | | |
| Q2 `[YEAR]` | `[FILL IN]` | | | |
| Q3 `[YEAR]` | `[FILL IN]` | | | |
| Q4 `[YEAR]` | `[FILL IN]` | | | |

---

## 14. Program Baseline

### Asset Discovery Baseline

| Date | Total Assets Discovered | Sites | Scan Engines |
|---|---|---|---|
| `[FILL IN]` | `[FILL IN]` | `[FILL IN]` | `[FILL IN]` |

### Vulnerability Baseline (First Scan)

| Site | Scan Date | Total Assets | Critical | High | Medium | Low |
|---|---|---|---|---|---|---|
| `CORP-HQ-Servers` | `[FILL IN]` | | | | | |
| `CORP-HQ-Workstations` | `[FILL IN]` | | | | | |
| `CORP-DMZ` | `[FILL IN]` | | | | | |
| `CORP-Critical-Assets` | `[FILL IN]` | | | | | |
| `CLOUD-AWS-Production` | `[FILL IN]` | | | | | |
| `CLOUD-AWS-Dev` | `[FILL IN]` | | | | | |
| `CLOUD-Azure-Production` | `[FILL IN]` | | | | | |

### SLA Baseline (First Goals Reading)

| Goal | Date | Compliance Value |
|---|---|---|
| `SLA-Critical-15d` | `[FILL IN]` | `[FILL IN]` |
| `SLA-High-30d` | `[FILL IN]` | `[FILL IN]` |
| `SLA-Medium-90d` | `[FILL IN]` | `[FILL IN]` |
| `SLA-Low-180d` | `[FILL IN]` | `[FILL IN]` |

---

## 15. Change Log

| Date | Change | Made By | Approved By |
|---|---|---|---|
| `[FILL IN]` | Initial runbook created | `[FILL IN]` | `[FILL IN]` |
