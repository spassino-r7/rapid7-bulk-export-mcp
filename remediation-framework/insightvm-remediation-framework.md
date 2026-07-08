# InsightVM Vulnerability Remediation Framework

## Purpose

This document provides a structured framework for building and operating a vulnerability remediation program using Rapid7 InsightVM. It covers patch scheduling, verification, gap analysis, false positive management, and metrics tracking.

The framework is designed to be adopted incrementally — start with the foundations, then layer in automation and metrics as the program matures.

---

## Table of Contents

1. [Program Foundations](#1-program-foundations)
2. [InsightVM Configuration for Remediation Tracking](#2-insightvm-configuration-for-remediation-tracking)
3. [Patch Scheduling Strategy](#3-patch-scheduling-strategy)
4. [Verification: Confirming Patches Are Applied](#4-verification-confirming-patches-are-applied)
5. [Gap Detection: Finding What's Missing](#5-gap-detection-finding-whats-missing)
6. [False Positive Investigation & Management](#6-false-positive-investigation--management)
7. [Metrics & KPIs](#7-metrics--kpis)
8. [Appendix: SQL Queries & Automation](#8-appendix-sql-queries--automation)

---

## 1. Program Foundations

### 1.1 Asset Inventory & Classification

Before remediating, you must know what you have and how critical it is. Tagging is the single most important foundational step — without consistent, accurate asset classification, every downstream activity (prioritization, SLA tracking, gap detection, reporting) becomes unreliable.

**Why tagging matters:**
- Enables risk-based prioritization — a critical vulnerability on a payment processing server is not the same as one on a dev sandbox
- Drives SLA assignment — different asset classes get different remediation timelines
- Powers reporting — executives want to see compliance by business unit, not by IP address
- Enables automation — remediation projects, scan schedules, and Goals & SLAs all filter by tags
- Supports accountability — tag-based ownership ensures the right team is responsible

**Leveraging a CMDB:**

If your organization maintains a Configuration Management Database (ServiceNow CMDB, Freshservice, Device42, etc.), use it as the authoritative source for asset classification. This avoids manual tagging drift and ensures InsightVM reflects the same reality as your IT operations:

- Sync asset ownership, environment, and criticality from CMDB into InsightVM tags
- Use the InsightVM API or InsightConnect to automate tag assignment based on CMDB records
- Reconcile regularly: assets in InsightVM but not in CMDB = shadow IT; assets in CMDB but not scanned = coverage gaps
- CMDB provides business context (application mappings, data classification, compliance scope) that scanning alone cannot determine

**Asset Tagging Strategy:**

| Tag Type | Purpose | Examples |
|----------|---------|----------|
| Criticality | Business impact if compromised | Critical, High, Medium, Low |
| Environment | Deployment stage | Production, Staging, Development, Test |
| Owner | Responsible team/person | infra-team, app-team, dba-team |
| Patch Group | Patch scheduling cohort | patch-wave-1, patch-wave-2, patch-wave-3 |
| Exposure | Network accessibility | internet-facing, internal-only, dmz |
| OS Type | Platform grouping | windows-server, linux-rhel, network-device |
| Compliance Scope | Regulatory requirement | pci-cde, hipaa, sox, fedramp |
| Application | Business application served | erp-production, web-storefront, email |

**Tags vs. Asset Groups — When to Use Each:**

| | Tags | Asset Groups |
|--|------|--------------|
| **What they are** | Static or dynamic labels attached to individual assets | Collections of assets defined by criteria |
| **How assigned** | Manual, API, CMDB sync, or dynamic (IP range, OS, site) | Static (manual membership) or dynamic (query-based) |
| **Best for** | Classification metadata (criticality, owner, environment, compliance scope) | Operational grouping for scan scope, report scope, remediation project targeting |
| **Persistence** | Stays on the asset regardless of what site it's in | Membership can change if dynamic criteria shift |
| **Use in Goals & SLAs** | ✅ Can filter goals by tag | ✅ Can filter goals by asset group |
| **Use in Remediation Projects** | Indirectly (filter assets by tag, then create project) | ✅ Directly scope a project to an asset group |
| **Use in Reports** | ✅ Filter report scope by tag | ✅ Filter report scope by asset group |
| **Overlap** | Many tags per asset (multi-dimensional) | Asset can be in multiple groups |

**Rule of thumb:**
- Use **Tags** to describe *what an asset is* (metadata, classification, ownership)
- Use **Asset Groups** to define *who needs to act on it* or *what report includes it* (operational scope)

**Example:** A server might have tags `criticality:high`, `env:production`, `owner:dba-team`, `compliance:pci-cde` — and be a member of asset groups "PCI Quarterly Report Scope", "Database Servers - Patch Wave 2", and "DBA Team Remediation Queue."

**Implementation in InsightVM:**
- Configure **Tags** under Administration → Tags (supports custom tag types)
- Create **Asset Groups** under Assets → Asset Groups (static or dynamic)
- Dynamic asset groups auto-update membership based on criteria (OS, software, site, tag, IP range)
- Use **Sites** to organize scan targets by network segment — don't overload sites as an organizational tool

### 1.2 Roles & Responsibilities

Every organization structures its teams differently. The roles below are suggestions — adapt them to match your org chart, team size, and operational model. In smaller organizations, one person may fill multiple roles. In larger environments, these responsibilities may be distributed across several teams or tiers.

The key principle: **every vulnerability finding should have a clear owner, and every remediation action should have someone accountable for completion and verification.**

**Suggested Role Definitions:**

| Role | Responsibility | Typical Team |
|------|---------------|--------------|
| **Vulnerability Management Lead** | Owns the program: defines SLAs, manages scanning infrastructure, produces reports, escalates overdue items, refines processes | Security / GRC |
| **Security Analyst** | Triages findings, investigates potential false positives, creates remediation projects, validates fixes post-patch, manages exceptions | Security Operations |
| **Patch/Remediation Engineer** | Applies patches and configuration changes within SLA, reports blockers, validates system stability post-patch, coordinates maintenance windows | IT Operations / Infrastructure |
| **System/Application Owner** | Approves maintenance windows, accepts risk for exceptions, prioritizes remediation for their systems, provides business context for criticality decisions | Business Unit / Application Teams |
| **Network/Firewall Team** | Remediates network device vulnerabilities, applies compensating controls (ACLs, segmentation), ensures scan engines can reach targets | Network Operations |
| **Database Administrator** | Remediates database-specific vulnerabilities, coordinates patching with application dependencies | DBA Team |
| **Management / CISO** | Reviews metrics and trends, approves risk acceptances beyond threshold, allocates budget for remediation resources, sets program priorities | Executive / Leadership |
| **Compliance/Audit Liaison** | Maps remediation SLAs to regulatory requirements, prepares evidence for auditors, tracks exceptions against compliance frameworks | GRC / Compliance |

**RACI Matrix (Example):**

| Activity | VM Lead | Security Analyst | Patch Engineer | System Owner | Management |
|----------|:-------:|:----------------:|:--------------:|:------------:|:----------:|
| Define SLAs and policy | A/R | C | C | C | A |
| Configure scans & credentials | A | R | C | I | I |
| Triage new findings | I | A/R | I | I | I |
| Investigate false positives | I | A/R | C | C | I |
| Create remediation projects | I | A/R | I | C | I |
| Apply patches | I | I | A/R | C | I |
| Approve maintenance windows | I | I | C | A/R | I |
| Verify remediation (rescan) | I | A/R | I | I | I |
| Approve risk exceptions | C | R | I | R | A |
| Report metrics to leadership | A/R | C | I | I | R |

*R = Responsible, A = Accountable, C = Consulted, I = Informed*

**Adapting to your organization:**

- **Small teams (1-3 security staff):** The VM Lead and Security Analyst may be the same person. Patch Engineers may also be system owners. Focus on clear handoff points rather than strict role separation.
- **Managed service providers (MSPs):** Distinguish between what the MSP handles (scanning, reporting, triage) vs. what the customer owns (patching, risk acceptance, maintenance windows).
- **DevOps / Cloud-native environments:** Remediation ownership often shifts left — development teams own their container images and infrastructure-as-code, security provides tooling and guardrails.
- **Regulated industries:** Add explicit compliance sign-off steps and evidence-retention requirements to the workflow.

**Key success factors regardless of structure:**
- Ownership is explicit and documented — no vulnerability sits in a gray area
- Escalation paths are defined before they're needed
- Patch engineers have visibility into what's expected of them (shared Goals in InsightVM)
- System owners understand they're accountable for risk decisions on their assets

### 1.3 Remediation SLA Definition

Define your remediation timelines based on severity and exposure. Leave specific day counts to your organization's risk appetite.

| Severity | Internet-Facing | Internal (Critical Assets) | Internal (Standard) |
|----------|----------------|---------------------------|---------------------|
| Critical | ___ days | ___ days | ___ days |
| Severe/High | ___ days | ___ days | ___ days |
| Moderate/Medium | ___ days | ___ days | ___ days |
| Low | ___ days | ___ days | ___ days |

**Guidance for setting SLAs:**
- Internet-facing critical: Industry standard ranges from 3–15 days
- Internal critical: Typically 14–30 days
- Standard internal: 30–90 days
- Low severity internal: 90–180 days or next upgrade cycle
- Consider BOD 26-04 timelines as a reference (even if not FCEB)

---

## 2. InsightVM Configuration for Remediation Tracking

### 2.1 Scan Schedule Design

Scanning frequency should match your remediation cadence — you can't verify a fix faster than you scan.

**Scan Types Available:**

InsightVM provides multiple ways to assess assets. Each has different trade-offs:

| Scan Type | How It Works | Best For | Auth Method |
|-----------|-------------|----------|-------------|
| **Authenticated Scan** (engine-based) | Scan engine connects to target using credentials (SSH, WMI, SMB) | Servers, infrastructure with stable credentials and network access from the engine | Service account credentials configured per site |
| **Insight Agent** | Lightweight agent installed on the asset reports findings to the platform | Roaming devices (laptops), remote workers, cloud instances, assets behind NAT/firewalls that engines can't reach | No credentials needed — agent runs locally with system access |
| **Scan Assistant** | Small service installed on the target that brokers the scan engine connection — no persistent credentials stored on the console | Environments with strict credential management policies, jump-box scenarios, assets where storing creds on the console is not permitted | Scan Assistant handles auth locally — engine connects via mutual TLS to the assistant service |
| **Unauthenticated Scan** | Engine probes target externally without logging in | Discovery only, external attack surface perspective, assets where no creds are available (gap detection) | None — misses 60-80% of vulnerabilities |

**When to use each:**

- **Authenticated scan** — Default choice for servers and infrastructure where the scan engine has direct network access and you can manage service account credentials centrally
- **Insight Agent** — Preferred for endpoints (workstations, laptops), cloud VMs that auto-scale, remote/VPN users, and any asset that moves between networks or can't be reliably reached by a scan engine
- **Scan Assistant** — Ideal when security policy prohibits storing credentials on the InsightVM console, when assets are behind jump boxes, or when credential rotation would frequently break scanning. Also useful for one-off assessments of sensitive systems
- **Unauthenticated** — Use only as a supplement for external perspective or to identify assets that lack proper authenticated coverage (never rely on this as your primary method)

**Recommended schedule:**

| Asset Type | Scan Frequency | Scan Type | Notes |
|-----------|----------------|-----------|-------|
| Internet-facing servers | Daily or every 48 hours | Authenticated or Scan Assistant | Highest risk, need near-real-time visibility |
| Internal critical (DB, AD, etc.) | Weekly | Authenticated or Scan Assistant | Business-critical systems |
| Standard servers | Weekly | Authenticated | General infrastructure |
| Workstations/endpoints | Daily (via Agent) | Insight Agent | Agent checks in automatically; no scan window needed |
| Remote/roaming users | Daily (via Agent) | Insight Agent | Only reliable method for off-network devices |
| Cloud instances (auto-scale) | Daily (via Agent) | Insight Agent | Instances may not exist long enough for scheduled scans |
| Network devices | Weekly | Authenticated (SNMP/SSH) | Routers, switches, firewalls |
| Development/Test | Bi-weekly | Authenticated | Lower priority but still tracked |
| Sensitive/regulated systems | Weekly | Scan Assistant | When credential storage policy prevents standard authenticated scans |

**Key principles:**
- Always use **authenticated assessment** (scan, agent, or scan assistant) — unauthenticated scans miss the majority of vulnerabilities
- Schedule engine-based scans **after** patch windows to verify remediation
- Use **Insight Agents** for assets that move between networks or can't be reached by engines
- Use **Scan Assistant** when your security or compliance team won't allow centralized credential storage
- Stagger scan start times to avoid network saturation
- A mix of scan types is normal and expected — most mature programs use all three

### 2.2 Credential Management

Poor credentials = poor data = false sense of security.

**Checklist:**
- [ ] Dedicated scan service accounts per platform (Windows, Linux, network)
- [ ] Service accounts have local admin / root / enable access
- [ ] Credentials tested and validated per site (check credential status reports)
- [ ] Credential rotation process won't break scanning (use service accounts, not personal accounts)
- [ ] SSH key-based auth preferred over passwords for Linux
- [ ] SNMP v3 for network devices (not v1/v2c)

**Monitoring credential health:**
- Review the **Credential Status** report weekly
- Any site with < 90% authentication success needs immediate attention
- Failed credentials mean blind spots — vulns exist but aren't being detected

> **📋 TODO:** Expand this section with specific examples — SQL queries for credential status, API v3 calls to retrieve authentication results per asset, and links to relevant built-in reports. Consider a companion document with step-by-step credential health monitoring procedures.

### 2.3 Goals & SLAs in InsightVM

Configure Goals to track remediation compliance:

1. Navigate to **Goals & SLAs** in the left menu
2. Create goals aligned to your SLA table:
   - "Critical vulns on internet-facing assets remediated within X days"
   - "All high-severity vulns remediated within X days"
   - "90% of moderate vulns remediated within X days"
3. Assign goals to relevant asset groups or tags
4. Share goals with IT operations teams for visibility

> **📋 TODO:** Add links to specific Goals & SLAs documentation, API endpoints for programmatic goal creation/retrieval, and example report templates that track SLA compliance over time.

### 2.4 Remediation Projects

Use Remediation Projects to assign and track work:

1. From vulnerability findings, create a **Remediation Project**
2. Assign to the appropriate team/owner
3. Set a due date aligned with your SLA
4. Track progress as patches are applied and verified by subsequent scans
5. Close projects when verification scan confirms remediation

> **📋 TODO:** Add links to Remediation Projects documentation, API v3 endpoints for creating/updating projects programmatically, integration examples with ServiceNow/Jira, and sample workflows for automated project lifecycle management.

---

## 3. Patch Scheduling Strategy

### 3.1 Patch Wave Design

**Important:** InsightVM does not drive your patching cycle or determine what gets patched — that's the job of your patch management tooling (SCCM, Intune, WSUS, Satellite, Ansible, etc.). InsightVM serves as a **second set of eyes**: it independently verifies that patches were applied successfully and identifies gaps where your patch management process missed assets or failed silently. Think of it as an audit layer on top of your existing patching operations, not a replacement for them.

Divide your environment into waves to limit blast radius and allow validation between groups. The wave structure below is a suggestion — adapt it to your organization's change management process.

Some organizations prefer waves based on environment tiers (Development → Staging → Production) rather than asset type. Either approach works as long as you validate before promoting to the next tier.

**Option A: Wave by asset type/risk**

```
┌─────────────────────────────────────────────────────────┐
│  Patch Tuesday (or vendor release)                       │
│                                                          │
│  Wave 1: Dev/Test (Day 1-3)                             │
│    → Validate patches don't break applications          │
│    → Scan to verify                                     │
│                                                          │
│  Wave 2: Non-critical internal (Day 4-7)                │
│    → Standard servers, workstations                     │
│    → Scan to verify                                     │
│                                                          │
│  Wave 3: Critical internal (Day 8-14)                   │
│    → Database servers, AD, business-critical            │
│    → Scan to verify                                     │
│                                                          │
│  Wave 4: Internet-facing (Day 1-3 for critical CVEs)   │
│    → May bypass wave schedule for emergency patches     │
│    → Scan to verify immediately                         │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Option B: Wave by environment tier**

```
┌─────────────────────────────────────────────────────────┐
│  Patch Tuesday (or vendor release)                       │
│                                                          │
│  Wave 1: Development (Day 1-2)                          │
│    → Lowest risk, fastest feedback                      │
│    → Validate no application breakage                   │
│    → Scan to verify                                     │
│                                                          │
│  Wave 2: Staging / QA (Day 3-5)                         │
│    → Mirrors production, validates compatibility        │
│    → Run integration/regression tests                   │
│    → Scan to verify                                     │
│                                                          │
│  Wave 3: Production (Day 6-14)                          │
│    → Apply with confidence after staging validation     │
│    → Use maintenance windows                            │
│    → Scan to verify                                     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Choose what fits your org:**
- **Option A** works well when asset types have different patch tooling or teams (e.g., network team patches routers, Windows team patches servers)
- **Option B** works well for application-centric organizations where the same app spans dev/staging/prod and you want to validate the patch against the application before production
- **Hybrid** is also common — environment tiers within each asset type wave

**Notes:**
- Internet-facing assets with critical/exploited vulns should patch ASAP, possibly outside the wave schedule
- Emergency patches (zero-days, actively exploited) bypass the wave process
- Each wave should have a verification scan within 24-48 hours of patching

### 3.2 Emergency Patch Process

For vulnerabilities that are:
- In the CISA KEV catalog (actively exploited)
- Have public exploit code AND are on internet-facing assets
- CVSS 9.0+ with network attack vector and no user interaction

**Emergency response:**
1. Identify affected assets immediately (InsightVM query or dashboard)
2. Assess: Is the asset internet-facing? Is the exploit automatable?
3. Mitigate: If patch not available, apply workaround (disable service, firewall rule, WAF rule)
4. Patch: Apply within your emergency SLA (recommend 24-72 hours)
5. Verify: Run targeted scan against affected assets
6. Document: Record the timeline and actions taken

### 3.3 Maintenance Windows

| Asset Group | Suggested Window | Duration |
|-------------|-----------------|----------|
| Dev/Test | Anytime | — |
| Standard servers | Weeknight (Tue-Thu) | 2-4 hours |
| Critical servers | Weekend early morning | 2-4 hours |
| Network devices | Weekend early morning | 1-2 hours |
| Internet-facing | Off-peak hours, ASAP for emergencies | 1-2 hours |

---

## 4. Verification: Confirming Patches Are Applied

Patching without verification is hope-based security.

### 4.1 Post-Patch Scan Strategy

After each patch wave:
1. Wait 1-2 hours for systems to reboot and stabilize
2. Run a **targeted scan** against the patched asset group
3. Compare results — the patched vulnerabilities should disappear
4. Investigate any that persist (failed patch, requires reboot, different component)

**InsightVM configuration:**
- Create a **Scan Template** optimized for verification (skip discovery, focus on vuln checks)
- Schedule verification scans to auto-run after patch windows
- Use the **Scan Differential** report to see what changed

### 4.2 Interpreting Results

| Result | Meaning | Action |
|--------|---------|--------|
| Vuln disappears after patch | Successfully remediated | ✅ Close |
| Vuln persists after patch | Patch didn't take effect | Investigate: reboot needed? Wrong KB? Different component? |
| New vulns appear | Patch introduced new exposure or unmasked previously hidden vulns | Triage as normal |
| Vuln disappears then returns | Regression — patch was rolled back or overwritten | Investigate with IT ops |

> **📋 TODO:** Add links to specific scan differential report templates, example dashboard cards for post-patch verification, and screenshots showing how to interpret baseline comparison results in the UI.

### 4.3 Tracking Remediation Over Time

Use these InsightVM features:
- **Baseline Comparison** reports (New/Same/Old between scans)
- **Goals & SLAs** dashboard cards for trend visualization
- **Remediation Projects** for per-initiative tracking
- **BOD 26-04 Compliance Reports** (if using the MCP tooling) for timeline-based tracking

> **📋 TODO:** Add links to specific dashboard card configurations, Remediation Project settings and lifecycle documentation, baseline comparison report templates, and API endpoints for programmatic tracking of remediation project status.

---

## 5. Gap Detection: Finding What's Missing

### 5.1 Common Gaps in Patch Programs

| Gap Type | How to Detect in InsightVM | Impact |
|----------|---------------------------|--------|
| Assets not being scanned | Compare asset inventory (CMDB) to scanned asset count | Blind spots — vulns exist but unknown |
| Failed authentication | Credential status report | Vulns detected but incomplete (missing local checks) |
| Stale scans | Assets not scanned in > X days | Patched systems still showing old vulns, or new vulns undetected |
| Missed patch scope | Vulns persistent across multiple scan cycles | Patches being deployed but missing certain assets |
| Network segments not covered | Sites with no scan targets or empty results | Entire zones invisible |
| Agent gaps | Assets expected to have agents but don't | Roaming devices unmonitored |

### 5.2 Detection Queries

**Assets not scanned in 30+ days:**
```sql
SELECT da.ip_address, da.host_name, da.last_assessed_for_vulnerabilities
FROM dim_asset da
WHERE da.last_assessed_for_vulnerabilities < CURRENT_DATE - INTERVAL '30 days'
ORDER BY da.last_assessed_for_vulnerabilities ASC
```

**Assets with failed credentials:**
```sql
SELECT
    da.ip_address,
    da.host_name,
    ds.name AS site_name
FROM dim_asset da
JOIN dim_site ds ON ds.site_id = da.site_id
WHERE da.credential_status = 'NO_CREDENTIALS_SUPPLIED'
   OR da.credential_status = 'ALL_CREDENTIALS_FAILED'
ORDER BY ds.name, da.ip_address
```

**Vulnerabilities that persist across 3+ scan cycles (never patched):**
```sql
SELECT
    da.ip_address,
    da.host_name,
    dv.title,
    dv.severity,
    fav.first_discovered,
    CURRENT_DATE - fav.first_discovered AS days_open
FROM fact_asset_vulnerability_finding fav
JOIN dim_asset da ON da.asset_id = fav.asset_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = fav.vulnerability_id
WHERE fav.first_discovered < CURRENT_DATE - INTERVAL '90 days'
  AND dv.severity IN ('Critical', 'Severe')
ORDER BY days_open DESC
```

### 5.3 Regular Gap Review Process

**Weekly:**
- Review credential status — any new failures?
- Check for assets not scanned in 14+ days
- Review remediation project progress

**Monthly:**
- Compare total asset count against CMDB/inventory
- Identify "chronic" vulns that never get patched (90+ days open)
- Review exception backlog — are expired exceptions being re-evaluated?

**Quarterly:**
- Full coverage audit: are all network segments being scanned?
- Review scan templates: are they up to date with current checks?
- Validate that patch tool scope matches InsightVM asset inventory

---

## 6. False Positive Investigation & Management

### 6.1 What Is a False Positive?

A false positive occurs when InsightVM reports a vulnerability that does not actually exist on the asset. Common causes:

| Cause | Example | How to Confirm |
|-------|---------|----------------|
| Backported patches | RPM shows old upstream version but includes the fix (e.g., OpenSSH 9.9p1-23 includes fix from 10.1) | Check `rpm -q --changelog` for CVE |
| Version detection only | Scanner identifies a vulnerable version but does not confirm the vulnerability is actually exploitable — exploitability validation requires manual testing or tools like Metasploit | Verify that the conditions for exploitation exist (exposed service, required config, reachable attack surface) |
| Residual files | Old binaries exist on disk but aren't running/reachable | Verify with `which`, `systemctl`, process list |
| Configuration-dependent | Vuln requires specific config that isn't present | Check config files for vulnerable setting |
| Compensating controls | WAF, IPS, or network segmentation prevents exploitation | Document the control |

### 6.2 Investigation Process

```
┌─────────────────────────────────────────┐
│  1. Review the finding details          │
│     - What check was performed?         │
│     - What proof does InsightVM show?   │
│     - Is it version-based or active?    │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  2. Verify on the asset                 │
│     - Check installed package version   │
│     - Review changelog for CVE fix      │
│     - Check if service is running       │
│     - Test if condition is present      │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  3. Determine: true positive or false?  │
│     - If TRUE: remediate per SLA        │
│     - If FALSE: document & except       │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│  4. Document & apply exception          │
│     - Record evidence (changelog, etc.) │
│     - Apply exception in InsightVM      │
│     - Set expiration for re-review      │
│     - Open support case if confirmed FP │
└─────────────────────────────────────────┘
```

**When opening a support case for a confirmed false positive, include:**
- CVE ID and InsightVM vulnerability check ID (nexpose_id)
- Asset OS, distribution, and version (e.g., AlmaLinux 10.2)
- Installed package name and version (e.g., `openssh-9.9p1-23.el10_2.alma.1`)
- The fix version referenced by the vulnerability check
- Evidence the fix is included (changelog excerpt, vendor advisory link)
- InsightVM console version and content version
- Scan type used (authenticated, agent, scan assistant)

> **📋 TODO:** Add screenshots with examples for each step of the investigation process — showing where to find proof text in InsightVM, how to review the vulnerability check details, and how to apply the exception with proper documentation.

### 6.3 Common Investigation Commands

**Linux (RPM-based):**
```bash
# Check if CVE is addressed in installed package
rpm -q --changelog openssh | grep -i "CVE-2025-61984"

# Check installed version
rpm -q openssh

# Check if advisory is available
dnf updateinfo list --cves CVE-2025-61984
```

**Linux (Debian/Ubuntu):**
```bash
# Check changelog
apt changelog openssh-server 2>/dev/null | grep -i "CVE-2025"

# Check version
dpkg -l openssh-server
```

**Windows:**
```powershell
# Check if KB is installed
Get-HotFix | Where-Object {$_.HotFixID -eq "KB5034441"}

# Check installed software version
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
  Where-Object {$_.DisplayName -like "*Office*"} |
  Select-Object DisplayName, DisplayVersion
```

### 6.4 Exception Management in InsightVM

**Types of exceptions:**
- **Vulnerability Exception** — applies to a specific vuln on a specific asset or globally
- **Asset Exception** — excludes an entire asset from reporting (use sparingly)

**Exception best practices:**
- Always set an **expiration date** (90 days recommended, force re-review)
- Require **evidence** in the exception reason (paste changelog output, config proof)
- Use **"False Positive"** reason code only when truly verified
- Use **"Compensating Control"** when a mitigation exists but vuln technically remains
- Use **"Acceptable Risk"** when business decides not to fix (requires owner sign-off)
- Review expired exceptions monthly — don't let them auto-renew without validation

### 6.5 Reporting False Positives to Rapid7

If you've confirmed a detection is incorrect:
1. Open a support case with Rapid7
2. Include: CVE ID, asset OS/version, installed package version, proof it's fixed
3. Rapid7 may update the vulnerability check in a content update
4. Track the case to confirm the fix is released

> **📋 TODO:** Document the end-to-end process for investigating customer-reported false positives — including how to validate the claim, gather evidence, reproduce the detection, determine if it's truly a false positive vs. a misunderstanding of scope, how to track the outcome (exception applied, support case opened, content update received), and a detailed checklist of what data to collect and include when opening a Rapid7 support case (CVE ID, check ID, asset details, installed versions, proof of patch, scan type, console/content versions, expected vs. actual behavior).

---

## 7. Metrics & KPIs

### 7.1 Operational Metrics (Weekly)

| Metric | Source | Target |
|--------|--------|--------|
| Mean Time to Remediate (MTTR) by severity | Goals & SLAs | Within defined SLA |
| Remediation rate (% fixed within SLA) | Goals & SLAs | > 90% |
| Open critical/high vulns count | Dashboard | Trending down |
| Assets with failed credentials | Credential report | < 5% |
| Scan coverage (% assets scanned this week) | Scan history | > 95% |
| New vulnerabilities introduced this week | Scan differential | Awareness |

### 7.2 Strategic Metrics (Monthly/Quarterly)

| Metric | Source | Purpose |
|--------|--------|---------|
| Risk score trend (org-wide) | InsightVM Dashboard | Overall security posture |
| Chronic vulnerability count (90+ days open) | SQL query | Identifies systemic gaps |
| Exception backlog size | Exception report | Are exceptions growing unchecked? |
| Patch coverage by asset group | Goals & SLAs | Which teams are falling behind? |
| Time from vendor patch release to deployment | Scan data + patch records | Process efficiency |
| BOD 26-04 compliance status | BOD 26-04 report | Regulatory alignment |

### 7.3 Executive Dashboard Recommendations

Build an InsightVM dashboard with these cards:
1. **Risk Score Trend** (30/60/90 day)
2. **SLA Compliance** (% within SLA by severity)
3. **Top 10 Riskiest Assets**
4. **Remediation Velocity** (vulns fixed per week)
5. **Critical Vuln Age Distribution** (< 7d, 7-30d, 30-90d, 90d+)
6. **Scan Coverage** (% of assets scanned in last 7 days)

---

## 8. Appendix: SQL Queries & Automation

### 9.1 Remediation Progress (Last vs Previous Scan)

```sql
WITH assets_vulns AS (
    SELECT
        fasv.asset_id,
        fasv.vulnerability_id,
        baselineComparison(fasv.scan_id, s.current_scan) AS baseline
    FROM fact_asset_scan_vulnerability_instance fasv
    JOIN (
        SELECT asset_id,
               previousScan(asset_id) AS baseline_scan,
               lastScan(asset_id) AS current_scan
        FROM dim_asset
    ) s ON s.asset_id = fasv.asset_id
        AND (fasv.scan_id = s.baseline_scan OR fasv.scan_id = s.current_scan)
    GROUP BY fasv.asset_id, fasv.vulnerability_id, s.current_scan
    HAVING baselineComparison(fasv.scan_id, s.current_scan) IN ('Old', 'New')
)
SELECT
    CASE WHEN baseline = 'Old' THEN 'Remediated' ELSE 'New' END AS status,
    da.ip_address,
    da.host_name,
    dv.title,
    dv.severity,
    dv.cvss_score
FROM assets_vulns av
JOIN dim_asset da ON da.asset_id = av.asset_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = av.vulnerability_id
ORDER BY status DESC, dv.cvss_score DESC
```

### 9.2 SLA Compliance Check

```sql
SELECT
    da.ip_address,
    da.host_name,
    dv.title,
    dv.severity,
    fav.first_discovered,
    CURRENT_DATE - fav.first_discovered AS days_open,
    CASE
        WHEN dv.severity = 'Critical' AND (CURRENT_DATE - fav.first_discovered) > 14 THEN 'OVERDUE'
        WHEN dv.severity = 'Severe' AND (CURRENT_DATE - fav.first_discovered) > 30 THEN 'OVERDUE'
        WHEN dv.severity = 'Moderate' AND (CURRENT_DATE - fav.first_discovered) > 90 THEN 'OVERDUE'
        ELSE 'Within SLA'
    END AS sla_status
FROM fact_asset_vulnerability_finding fav
JOIN dim_asset da ON da.asset_id = fav.asset_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = fav.vulnerability_id
WHERE dv.severity IN ('Critical', 'Severe', 'Moderate')
ORDER BY days_open DESC
```

*Note: Adjust the day thresholds (14, 30, 90) to match your defined SLAs.*

### 9.3 Scan Coverage Report

```sql
SELECT
    ds.name AS site_name,
    COUNT(da.asset_id) AS total_assets,
    SUM(CASE WHEN da.last_assessed_for_vulnerabilities >= CURRENT_DATE - INTERVAL '7 days' THEN 1 ELSE 0 END) AS scanned_last_7d,
    ROUND(
        100.0 * SUM(CASE WHEN da.last_assessed_for_vulnerabilities >= CURRENT_DATE - INTERVAL '7 days' THEN 1 ELSE 0 END)
        / NULLIF(COUNT(da.asset_id), 0), 1
    ) AS coverage_pct
FROM dim_asset da
JOIN dim_site ds ON ds.site_id = da.site_id
GROUP BY ds.name
ORDER BY coverage_pct ASC
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | ___ | ___ | Initial release |

---

*This framework should be reviewed and updated quarterly as the program matures and organizational requirements evolve.*
