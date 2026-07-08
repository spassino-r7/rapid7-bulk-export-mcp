# Implementation Plan: Vulnerability Management Program (InsightVM)

## Overview

This plan organizes the VMP into six sequential phases. Each phase produces durable configuration artifacts in InsightVM that persist and compound as the program matures. Complete each phase's smoke-test checklist before advancing to the next phase. Tasks reference specific InsightVM navigation paths from the design document.

---

## Tasks

- [x] 1. Phase 1: Asset Discovery and Inventory
  - [x] 1.1 Deploy and register Scan Engines
    - Install Scan Engine on a dedicated host (Windows Server or Linux) within each network segment that cannot be reached from the console due to firewall restrictions
    - Register each engine with the InsightVM console: **Administration → Engines → Add Engine** using the pairing key
    - Verify console-to-engine connectivity on TCP 40814 for each registered engine
    - Document each engine's hostname, IP, and assigned network segment in the runbook
    - _Requirements: 1.3_

  - [x] 1.2 Create Sites per network segment and business unit
    - Create one Site per network segment following the naming convention `{ENVIRONMENT}-{SEGMENT}-{OPTIONAL_QUALIFIER}` (e.g., `CORP-HQ-Servers`, `CORP-DMZ`, `CLOUD-AWS-Production`)
    - Recommended initial Sites: `CORP-HQ-Servers`, `CORP-HQ-Workstations`, `CORP-DMZ`, `CORP-Critical-Assets`, `CLOUD-AWS-Production`, `CLOUD-AWS-Dev`, `CLOUD-Azure-Production`, `REMOTE-Endpoints`
    - Assign the appropriate Scan Engine to each Site: **Site Configuration → Engines**
    - Define IP ranges or asset lists for each Site in **Site Configuration → Assets**
    - Document all Sites, their IP ranges, and assigned engines in the runbook
    - _Requirements: 1.1, 1.2, 1.7_

  - [x] 1.3 Deploy Insight Agent to managed endpoints
    - Download the agent installer from **Administration → Agents → Download Agent**
    - Deploy via endpoint management tooling (SCCM, Intune, Ansible, Chef, Puppet, or cloud user-data scripts) to all managed laptops, servers, and cloud VMs
    - Create a dedicated `REMOTE-Endpoints` Site of type "Agent" or confirm agent-assessed assets appear in the default Insight Agent site
    - Verify agent-assessed assets appear in InsightVM within 24 hours of deployment
    - _Requirements: 1.4_

  - [x] 1.4 Configure cloud integrations (AWS, Azure, GCP)
    - AWS: **Administration → Cloud Configuration → AWS** — provide IAM role ARN with read-only EC2/inventory permissions
    - Azure: **Administration → Cloud Configuration → Azure** — provide service principal credentials with Reader role
    - GCP: **Administration → Cloud Configuration → GCP** — provide service account key with Viewer permissions
    - Verify cloud-native assets appear in InsightVM after each integration sync
    - Assign a Scan Engine deployed in the same VPC/VNet to scan discovered cloud assets, or confirm Insight Agent coverage for cloud VMs
    - _Requirements: 1.5_

  - [x] 1.5 Configure scan credentials
    - Create shared scan credentials in **Administration → Credentials**
    - Create credentials for each required type: Windows domain service account (Local Administrators group or WMI/registry read), SSH key-based (non-root with sudo for package manager queries), SNMP v3, database read-only
    - Assign credentials to each Site in **Site Configuration → Authentication**
    - Verify credential assignment by reviewing **Assets → Authentication Status** after the first scan of each Site
    - Document credential types, accounts used, and rotation schedule in the runbook
    - _Requirements: 1.6_

  - [x] 1.6 Phase 1 smoke test — verify discovery completeness
    - Confirm at least one Site exists per network segment
    - Confirm all Scan Engines show status "Active" in **Administration → Engines**
    - Confirm Insight Agent is deployed to all managed endpoints and assets appear in InsightVM
    - Confirm all cloud integrations show a successful last-sync timestamp in **Administration → Cloud Configuration**
    - Confirm credentials are assigned to all Sites
    - Document the total discovered asset count and date in the runbook as the program baseline
    - _Requirements: 1.1, 1.3, 1.4, 1.5, 1.6, 1.10_

- [x] 2. Phase 2: Vulnerability Assessment
  - [x] 2.1 Create custom scan templates
    - In **Scan Templates → Create Template**, create `VMP-Critical-7Day`:
      - Base: Full Audit without Web Spider
      - Throttle: Disabled (scan speed: Maximum)
      - Scan timeout: 4 hours
    - Create `VMP-Standard-30Day`:
      - Base: Full Audit without Web Spider
      - Throttle: Enabled (scan speed: Normal)
      - Scan timeout: 8 hours
    - Document both templates and their settings in the runbook
    - _Requirements: 2.1, 2.2_

  - [x] 2.2 Configure scan schedules for all Sites
    - For `CORP-Critical-Assets` and any Site containing Very High / High criticality assets: set schedule to every 7 days using `VMP-Critical-7Day`, scan window Saturday 02:00–06:00 — **Site Configuration → Schedule**
    - For all remaining Sites (Medium / Low / Very Low criticality): set schedule to every 30 days using `VMP-Standard-30Day`, scan window Sunday 01:00–09:00
    - For `REMOTE-Endpoints` (agent-assessed): no scan schedule required — confirm continuous assessment is active
    - Verify schedules are saved and show a next-run timestamp for each Site
    - _Requirements: 2.1, 2.2_

  - [x] 2.3 Assign asset criticality to all assets and asset groups
    - Define the criticality taxonomy in the runbook:
      - Very High (10): domain controllers, PAM systems, core network infrastructure, production databases with PII/PCI
      - High (8): production app servers, CI/CD systems, identity providers, backup infrastructure
      - Medium (5): dev/staging servers, internal web apps, standard workstations
      - Low (3): test environments, non-production cloud instances, printers
      - Very Low (1): decommissioned assets pending removal, isolated lab systems
    - Assign criticality per asset in **Assets → [Asset] → Edit Criticality** or bulk-assign via **Asset Groups → [Group] → Set Criticality**
    - Confirm no assets remain at the default Medium criticality unless Medium is the correct classification
    - _Requirements: 2.4, 2.5_

  - [x] 2.4 Create Asset Groups reflecting organizational boundaries
    - Create dynamic Asset Groups in **Asset Groups → Create Group** for each organizational boundary:
      - By environment: `AG-Production`, `AG-Staging`, `AG-Development`, `AG-Lab`
      - By criticality tier: `AG-Critical-Assets`, `AG-High-Assets`
      - By business unit: one group per BU (e.g., `AG-BU-Finance`, `AG-BU-Engineering`)
      - By OS type: `AG-Windows-Servers`, `AG-Linux-Servers`, `AG-Workstations`, `AG-Network-Devices`
    - Use dynamic rules (tag-based or IP range-based) where possible to keep groups self-maintaining
    - Document all Asset Group names, rules, and purposes in the runbook
    - _Requirements: 2.6_

  - [x] 2.5 Apply tags to all assets
    - Apply the required tag schema to all assets (individually or via bulk tag in Asset Groups):
      - `env`: `production`, `staging`, `development`, `lab`
      - `owner`: `{team-name}` (e.g., `infra-ops`, `cloud-eng`, `app-team`)
      - `data-class`: `pii`, `pci`, `phi`, `internal`, `public`
      - `os-type`: `windows-server`, `linux-server`, `workstation`, `network-device`, `cloud-vm`
      - `bu`: `{business-unit}` (e.g., `finance`, `hr`, `engineering`)
      - `compliance`: `cis-l1`, `cis-l2`, `disa-stig`, `pci-dss` (where applicable)
    - Apply tags in **Assets → [Asset] → Tags** or bulk-apply via dynamic Asset Group rules
    - Verify tag coverage by filtering **Assets** by each tag category and confirming no untagged assets remain
    - _Requirements: 2.7_

  - [x] 2.6 Run initial scans and record baselines
    - Trigger the first scan for each Site manually via **Site Configuration → Scan Now** to establish baselines
    - Confirm InsightVM records the initial scan result as the baseline for each Site (visible in **Reports → Baseline Comparison**)
    - Document the baseline scan date, total asset count, and total vulnerability count per Site in the runbook
    - Review **Assets → Authentication Status** after each scan and flag any credential failures for resolution within 5 business days
    - _Requirements: 2.3, 2.8, 2.9_

  - [x] 2.7 Phase 2 smoke test — verify assessment completeness
    - Confirm scan schedules are configured for all Sites with correct intervals
    - Confirm asset criticality is assigned to every asset (no unclassified assets in risk reports)
    - Confirm all required Asset Groups exist and contain the correct assets
    - Confirm all required tags are applied across the asset inventory
    - Confirm baselines are recorded for all Sites in **Reports → Baseline Comparison**
    - Confirm InsightVM scan history retention is set to at least 12 months (**Administration → Security Console → Maintenance**)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.6, 2.7, 2.10_

- [x] 3. Phase 3: Vulnerability Prioritization
  - [x] 3.1 Verify Active Risk Score is the default sort order
    - Navigate to **Vulnerabilities** and confirm the default sort is **Risk Score (Descending)**
    - If not set, change the sort to Risk Score (Descending) and confirm it persists across sessions
    - Verify the Active Risk Score formula is active by spot-checking a Critical vulnerability on a Very High criticality asset — its risk score should be higher than the same vulnerability on a Medium criticality asset
    - _Requirements: 3.1, 3.6_

  - [x] 3.2 Configure SLA Goals for all four severity tiers
    - Navigate to **Goals & SLAs → Add Goal** and create the following four Goals:
      - `SLA-Critical-15d`: % vulnerabilities remediated within 15 days, target ≥ 95%, scope: All assets
      - `SLA-High-30d`: % vulnerabilities remediated within 30 days, target ≥ 90%, scope: All assets
      - `SLA-Medium-90d`: % vulnerabilities remediated within 90 days, target ≥ 85%, scope: All assets
      - `SLA-Low-180d`: % vulnerabilities remediated within 180 days, target ≥ 80%, scope: All assets
    - Confirm each Goal shows a current compliance value after saving
    - _Requirements: 3.4, 3.5, 6.3_

  - [x] 3.3 Document and publish the prioritization policy
    - Write the prioritization policy document covering:
      - Multi-factor model: CVSS v3 + EPSS + asset criticality + hasExploits
      - Auto-Critical rule: CVSS ≥ 9.0 AND hasExploits = true → Critical priority regardless of asset criticality
      - EPSS escalation rule: EPSS > 0.70 → escalate one severity tier above CVSS base classification
      - SLA targets: Critical 15d, High 30d, Medium 90d, Low 180d
      - Very High criticality 1.5x risk multiplier (applied natively by InsightVM when criticality = 10)
    - Obtain security leadership approval and record the approval date
    - Store the policy document in the runbook and link it from the InsightVM dashboard
    - _Requirements: 3.4, 3.7, 3.8, 3.10_

  - [x] 3.4 Phase 3 smoke test — verify prioritization configuration
    - Confirm all four SLA Goals are configured and showing compliance values in **Goals & SLAs**
    - Confirm Active Risk Score is the default sort in the Vulnerabilities view
    - Confirm the prioritization policy document is approved and stored in the runbook
    - Spot-check: find a vulnerability with CVSS ≥ 9.0 and hasExploits = true — confirm it is classified Critical
    - Spot-check: find a vulnerability with EPSS > 0.70 — confirm its effective priority tier is one above its CVSS base tier
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 4. Phase 4: Remediation Workflow
  - [x] 4.1 Create Remediation Project templates
    - Navigate to **Remediation → Projects → Create Project** and create template projects for each severity tier following the naming conventions:
      - Critical sprint: `CRIT-{YYYY-MM}-{DESCRIPTION}` — due date 15 days from detection, owner: IT Operations lead
      - High monthly: `HIGH-{YYYY-MM}-{BU}` — due date 30 days from detection, owner: IT Operations / BU owner
      - Medium quarterly: `MED-{YYYY-Q#}-{BU}` — due date 90 days from detection, owner: IT Operations / BU owner
      - Exception tracked: `EXCPT-{YYYY-MM}-{VULN-ID}` — due date = exception review date, owner: Security team
    - Confirm each project template has an assigned owner before activation
    - Document the project naming conventions and owner assignment process in the runbook
    - _Requirements: 4.1, 4.2_

  - [x] 4.2 Configure ticketing system integration
    - Navigate to **Administration → Integrations → Ticketing**
    - Select the organization's ticketing system (Jira or ServiceNow)
    - Provide API credentials and configure project/queue mapping
    - Map InsightVM severity levels to ticket priority levels (Critical → P1, High → P2, Medium → P3, Low → P4)
    - Enable automatic ticket creation on Remediation Project activation
    - Test the integration by activating a test Remediation Project and confirming a ticket is created in the ticketing system
    - If Jira/ServiceNow is not in use, document that InsightVM Remediation Projects serve as the system of record
    - _Requirements: 4.3_

  - [x] 4.3 Document and publish the patching cadence policy
    - Write the patching cadence policy specifying patch deployment windows per criticality tier:
      - Very High / Critical vulnerabilities: emergency patching within 24 hours
      - High: monthly patch cycle, aligned to the 30-day SLA
      - Medium: quarterly patch cycle, aligned to the 90-day SLA
      - Low: semi-annual patch cycle, aligned to the 180-day SLA
    - Define patch deployment windows per asset tier (e.g., Critical assets: Saturday 02:00–04:00 maintenance window)
    - Obtain security leadership approval and record the approval date
    - Store the policy in the runbook
    - _Requirements: 4.5_

  - [x] 4.4 Document and implement the exception process
    - Write the exception process procedure covering:
      - Submission: requestor navigates to **Vulnerabilities → [Vulnerability] → Add Exception**, selects type (False Positive, Compensating Control, or Acceptable Risk), enters business justification, compensating controls description, and accepted risk date
      - Approval: security team lead reviews and approves; approver's name recorded in the comment field
      - Recording: Program Administrator sets review date ≤ 90 days from approval date in InsightVM
      - False positive sub-process: navigate to **Vulnerabilities → [Vulnerability] → Add Exception → False Positive**, document justification and approving analyst name
    - Publish the exception process in the runbook and communicate it to remediation teams
    - _Requirements: 4.7, 4.8, 4.10_

  - [x] 4.5 *(Optional)* Configure the SLA breach alert for Remediation Projects
    - Automation triggers are optional — if not adopting triggers, skip this task and document that SLA breach monitoring will be handled via the Security Operations dashboard and weekly SQL report review
    - If adopting triggers, pre-configure the `ALERT-SLA-Breach` condition: **Administration → Automation → Add Trigger**
      - Event: Vulnerability age > SLA target
      - Action: Email alert to asset owner (via `owner` tag) + security team distribution list
    - Confirm the 7-day pre-deadline alert is configured for Remediation Projects approaching due date
    - _Requirements: 4.4_

  - [x] 4.6 Phase 4 smoke test — verify remediation workflow readiness
    - Confirm Remediation Project naming conventions and templates are documented in the runbook
    - Confirm ticketing integration is configured and tested (or documented as not applicable)
    - Confirm patching cadence policy is approved and published
    - Confirm exception process is documented and communicated to remediation teams
    - Create one live Remediation Project for the highest-priority open vulnerabilities and confirm it has an assigned owner and due date
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 4.7, 4.8, 4.10_

- [x] 5. Phase 5: Measurement and Reporting
  - [x] 5.1 Create the Executive Risk Overview dashboard
    - Navigate to **Dashboards → Create Dashboard**, name it `VMP - Executive Risk Overview`
    - Add the following cards:
      - Risk Score Trend: Line chart, 12-month rolling, all assets
      - SLA Compliance Rate: Gauge, by severity tier, current month (link to each SLA Goal)
      - Top 10 Highest-Risk Assets: Table, sorted by Active Risk Score
      - Exploitable Findings Count: KPI card, filter hasExploits = true OR EPSS > 0.50
      - Coverage Rate: Gauge, % assets scanned in last 30 days
      - Vulnerability Backlog Trend: Bar chart, 6-month rolling, by severity
    - Share the dashboard with security leadership (read-only access)
    - _Requirements: 5.2, 5.4_

  - [x] 5.2 Create the Security Operations Workqueue dashboard
    - Navigate to **Dashboards → Create Dashboard**, name it `VMP - Security Operations`
    - Add the following cards:
      - New Findings (Last 7 Days): KPI card, first-found timestamp in last 7 days
      - SLA Breach Count: KPI card, vulnerabilities past SLA by severity
      - Analyst Workqueue: Table, open vulns sorted by Active Risk Score
      - Credential Failure Assets: Table, assets with auth failures in last scan
      - Critical Vulns Awaiting Patch: Table, CVSS ≥ 9.0 AND hasExploits = true
      - Scan Coverage by Site: Table, last scan date and coverage % per Site
    - Share the dashboard with the security operations team
    - _Requirements: 5.2_

  - [x] 5.3 Create the Remediation Team View dashboard
    - Navigate to **Dashboards → Create Dashboard**, name it `VMP - Remediation Team`
    - Add the following cards:
      - Open Remediation Projects: Table, all active projects with due dates
      - Overdue Projects: KPI card, projects past due date
      - Asset-Level Vulnerability Detail: Table, filtered by `owner` tag
      - Patch Compliance by BU: Bar chart, % remediated by business unit
      - Upcoming SLA Deadlines: Table, vulns expiring in next 14 days
      - Exception Summary: Table, open exceptions by severity
    - Share the dashboard with remediation team leads and BU owners
    - _Requirements: 5.2_

  - [x] 5.4 Create SQL reports for core metrics
    - Navigate to **Reports → SQL Query Export** and create the following five reports, saving each with a descriptive name and scheduling for monthly delivery:
      - `VMP-MTTR-Monthly`: Monthly MTTR by severity (use the SQL query from the design document's "Monthly MTTR by Severity" section)
      - `VMP-SLA-Compliance`: SLA compliance rate by severity (use the "SLA Compliance Rate by Severity" SQL query)
      - `VMP-Exploitable-Findings`: Exploitable findings summary (use the "Exploitable Findings Summary" SQL query — returns only hasExploits = true OR EPSS > 0.50)
      - `VMP-Exception-Summary`: Open exception summary (use the "Open Exception Summary" SQL query)
      - `VMP-Scan-Coverage`: Scan coverage by Site (use the "Scan Coverage Report" SQL query)
    - Schedule each report to run on the first business day of each month and deliver to the security team distribution list
    - _Requirements: 5.1, 5.8, 5.9_

  - [x] 5.5 Establish the monthly reporting cadence
    - Define the monthly vulnerability management report template covering: coverage rate, backlog trend, MTTR trend, SLA compliance rate, and top 10 highest-risk assets
    - Schedule the five SQL reports (from task 5.4) to run on the first business day of each month
    - Assign a named analyst as the monthly report owner responsible for compiling and delivering the report to security leadership
    - Document the reporting cadence, report owner, and distribution list in the runbook
    - Set up a recurring calendar event for the monthly report review meeting with security leadership
    - _Requirements: 5.1, 5.4, 5.6_

  - [x] 5.6 *(Optional)* Configure automation triggers for operational alerts
    - Automation triggers are recommended but not required — teams can rely on dashboard monitoring and scheduled SQL reports as an alternative
    - If adopting triggers, navigate to **Administration → Automation** and create the following:
      - `ALERT-Critical-New`: Event = new vulnerability found, Condition = CVSS ≥ 9.0 AND hasExploits = true, Action = email alert, Recipient = security team DL *(recommended)*
      - `ALERT-SLA-Breach`: Event = SLA breach, Condition = vulnerability age > SLA target, Action = email alert, Recipient = asset owner + security team *(recommended)*
      - `ALERT-Coverage-Drop`: Event = scan coverage, Condition = coverage < 90%, Action = email alert, Recipient = Program Administrator *(optional)*
      - `ALERT-Cred-Failure`: Event = credential failure, Condition = auth failure on any asset, Action = email alert, Recipient = Program Administrator *(optional)*
      - `ALERT-Goal-Breach`: Event = Goal threshold, Condition = SLA Goal compliance < target, Action = email alert, Recipient = security team lead *(optional)*
    - If not configuring triggers, document in the runbook that the Security Operations dashboard and SLA compliance SQL reports will be reviewed on a weekly cadence as the compensating control
    - _Requirements: 5.5, 6.5, 6.6_

  - [x] 5.7 Phase 5 smoke test — verify measurement and reporting completeness
    - Confirm all three dashboards are configured and accessible to the correct audiences
    - Confirm all five SQL reports are created, scheduled, and have been run at least once with non-null results
    - Confirm automation triggers are configured if adopted, or document the compensating dashboard/report review cadence in the runbook
    - Confirm the monthly reporting cadence is documented and a report owner is assigned
    - Run the Scan Coverage SQL report and confirm total coverage ≥ 95% across all Sites
    - _Requirements: 5.1, 5.2, 5.4, 5.5, 5.6, 5.8, 5.9_

- [x] 6. Phase 6: Program Maturity
  - [x] 6.1 Configure policy compliance scans for all major asset classes
    - Create policy compliance scan templates for each asset class:
      - Servers (Linux): CIS Benchmark — navigate to **Scan Templates**, select or create a template based on `CIS Policy Scan`, assign the appropriate CIS Linux profile (e.g., CIS Ubuntu 20.04 L1)
      - Servers (Windows): CIS Benchmark — assign the appropriate CIS Windows Server profile
      - Workstations: CIS Benchmark — assign the CIS Windows 10/11 Workstation profile
      - Network devices: DISA STIG — assign the appropriate STIG profile
      - PCI-scoped assets: add PCI DSS policy checks to the relevant Sites
    - Assign policy compliance scan templates to the corresponding Sites in **Site Configuration → Scan Template**
    - Schedule policy compliance scans monthly on the first Sunday of each month
    - _Requirements: 6.1, 6.2_

  - [x] 6.2 Verify policy compliance reporting
    - After the first policy compliance scan completes, navigate to **Policy Manager** and confirm:
      - Pass/fail rate is reported per benchmark rule
      - Pass/fail rate is reported per asset
      - Results are filterable by the `compliance` tag (e.g., `cis-l1`, `disa-stig`)
    - Add a Policy Compliance summary card to the Executive Risk Overview dashboard showing overall pass rate by benchmark
    - Create a SQL report or use the native Policy Manager view to export per-asset compliance results for audit purposes
    - _Requirements: 6.2_

  - [x] 6.3 Verify Goals and SLA tracking are fully operational
    - Confirm all four SLA Goals (`SLA-Critical-15d`, `SLA-High-30d`, `SLA-Medium-90d`, `SLA-Low-180d`) are showing live compliance values in **Goals & SLAs**
    - Confirm the `ALERT-Goal-Breach` automation trigger is active and has been tested
    - Confirm Goal compliance gauges are visible on the Executive Risk Overview dashboard
    - Review current Goal compliance values and document them as the program's first formal SLA baseline in the runbook
    - _Requirements: 6.3, 6.4_

  - [x] 6.4 Document and publish the maturity model
    - Write the vulnerability management maturity model document with four levels:
      - Level 1 — Initial: Ad hoc scanning, no formal process, limited coverage
      - Level 2 — Developing: Scheduled scans, basic prioritization, informal remediation tracking
      - Level 3 — Defined: Full coverage, risk-based prioritization, SLA Goals configured, dashboards operational, monthly reporting
      - Level 4 — Optimizing: Policy compliance scanning active, automation triggers operational, annual maturity assessments, runbook maintained, continuous improvement cycle
    - Conduct the first formal maturity assessment against the model and record scores per phase (Asset Discovery, Vulnerability Assessment, Prioritization, Remediation Workflow, Measurement, Maturity)
    - Document gaps and action items from the assessment
    - Obtain security leadership sign-off on the maturity model and initial assessment
    - _Requirements: 6.7_

  - [x] 6.5 Schedule and conduct the annual tabletop exercise
    - Define the tabletop exercise scenario (e.g., a critical zero-day affecting production servers is published; walk through detection, prioritization, remediation assignment, exception handling, and executive reporting)
    - Schedule the first tabletop exercise within 12 months of Phase 6 completion
    - Document the exercise format, participants, scenario, findings, and action items in the runbook
    - Assign owners and due dates to all action items identified during the exercise
    - _Requirements: 6.8_

  - [x] 6.6 Complete and publish the program runbook
    - Create or finalize the program runbook document with dedicated sections for all required configuration artifacts:
      - Scan configurations (Sites, Scan Engines, scan templates, schedules, credentials)
      - Asset Groups (names, rules, purposes)
      - Tags (schema, values, assignment process)
      - Remediation Project templates (naming conventions, owner assignment, due date rules)
      - Goals/SLA definitions (Goal names, targets, severity mappings)
      - Dashboard layouts (card names, configurations, audience assignments)
      - SQL report definitions (report names, queries, schedules, recipients)
      - Policy compliance configurations (benchmarks, profiles, asset class mappings)
      - Automation trigger definitions (trigger names, conditions, actions, recipients)
      - Exception process (submission, approval, recording, review)
      - Maturity model and assessment schedule
    - Review the runbook with the security team and obtain sign-off
    - Schedule an annual runbook review on the program calendar
    - _Requirements: 6.9_

  - [x] 6.7 Establish the quarterly InsightVM release review process
    - Schedule a recurring quarterly calendar event for the Program Administrator to review InsightVM release notes
    - Create a runbook entry defining the review process: read release notes, evaluate new native features against current program gaps, document adoption decisions (adopt / defer / decline) with rationale
    - Complete the first release review and document findings in the runbook
    - _Requirements: 6.10_

  - [x] 6.8 Phase 6 smoke test — verify program maturity completeness
    - Confirm policy compliance scans are configured for all major asset classes and have run at least once
    - Confirm all five automation triggers are active and tested, OR confirm the runbook documents the compensating weekly dashboard/report review cadence
    - Confirm the maturity model document is approved and the first assessment is complete
    - Confirm the runbook contains all required sections (scan configs, Asset Groups, Tags, Remediation Project templates, Goals, dashboard layouts, SQL reports)
    - Confirm the tabletop exercise is scheduled
    - Confirm the quarterly InsightVM release review is scheduled
    - _Requirements: 6.1, 6.3, 6.5, 6.7, 6.8, 6.9, 6.10_

- [x] 7. Final checkpoint — program operational
  - Confirm all six phase smoke tests have been completed and documented in the runbook
  - Confirm the first monthly vulnerability management report has been delivered to security leadership
  - Confirm all SLA Goals are showing live compliance values
  - Confirm all three dashboards are accessible to their intended audiences
  - Confirm the program runbook is complete, approved, and stored in a location accessible to all program staff
  - Ask the security team lead to confirm the program is operational before closing Phase 6.

---

## Notes

- Tasks are operational configuration and process steps, not software development tasks. They are executed in the InsightVM web console or via endpoint management tooling.
- Complete each phase's smoke test before advancing to the next phase — later phases depend on earlier configuration artifacts being stable.
- The runbook is a living document. Update it whenever a configuration artifact is created, modified, or retired.
- SQL queries in task 5.4 are provided verbatim in the design document's "SQL Report Queries" section — copy them directly into InsightVM's SQL Query Export console.
- Automation triggers (task 5.6) are a prerequisite for Phase 6 maturity but are configured in Phase 5 to provide operational alerting as early as possible.
- Policy compliance scans (task 6.1) require the `compliance` tag to be applied to assets in Phase 2 (task 2.5) — confirm tag coverage before running compliance scans.
