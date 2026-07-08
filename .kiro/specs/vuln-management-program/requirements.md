# Requirements Document

## Introduction

This document defines the requirements for building a structured, repeatable Vulnerability Management Program (VMP) using Rapid7 InsightVM as the primary platform. The program is organized into six foundational phases: Asset Discovery, Vulnerability Assessment, Prioritization, Remediation, Measurement, and Maturity. Each phase builds on the previous, enabling the organization to progress from basic scanning coverage to a consistent, risk-driven program with executive visibility.

The goal is an actionable, phased plan that a security team can execute incrementally using InsightVM's core capabilities — Sites, Scan Engines, Insight Agent, credentialed scanning, Asset Groups, Tags, Remediation Projects, Goals/SLAs, SQL reports, dashboards, and policy compliance scanning. This is a "getting started" foundational program, not an advanced integration-heavy architecture.

---

## Glossary

- **VMP**: Vulnerability Management Program — the end-to-end process of discovering, assessing, prioritizing, remediating, and measuring vulnerabilities across the organization's asset inventory.
- **InsightVM**: Rapid7's vulnerability risk management platform, used as the primary scanning and reporting engine.
- **Scan Engine**: An InsightVM component deployed on-premises or in the cloud that performs active network scanning.
- **Insight Agent**: A lightweight endpoint agent deployed on assets to provide continuous, authenticated vulnerability data without requiring network-based scans.
- **Site**: An InsightVM logical grouping of assets targeted by a specific scan configuration.
- **Asset Group**: A dynamic or static collection of assets in InsightVM used for scoping reports, dashboards, and remediation projects.
- **Tag**: A label applied to assets in InsightVM to support filtering, grouping, and reporting by custom attributes (e.g., environment, owner, criticality).
- **Credentialed Scan**: A scan that authenticates to target assets to enumerate installed software, patches, and configuration details with higher accuracy than unauthenticated scans.
- **CVSS**: Common Vulnerability Scoring System — an industry-standard framework for rating vulnerability severity (v2 and v3).
- **EPSS**: Exploit Prediction Scoring System — a probability score (0–1) indicating the likelihood a vulnerability will be exploited in the wild within 30 days.
- **Active Risk Score**: InsightVM's composite risk score that incorporates CVSS, EPSS, asset criticality, and exploit availability.
- **SLA**: Service Level Agreement — a defined time target for remediating vulnerabilities based on severity.
- **Goal**: An InsightVM native feature for defining and tracking SLA targets and remediation objectives within the platform.
- **MTTR**: Mean Time to Remediate — the average elapsed time between a vulnerability's first detection and its verified remediation.
- **Remediation Project**: An InsightVM feature that groups vulnerabilities and assets into a tracked remediation workflow with assignees and due dates.
- **Asset Criticality**: A classification (e.g., Very High, High, Medium, Low, Very Low) assigned to assets to weight risk scoring and SLA targets.
- **Baseline**: An initial vulnerability scan result used as a reference point to measure improvement over time.
- **Coverage**: The percentage of known in-scope assets that have been scanned within a defined time window.
- **Backlog**: The total count of open, unresolved vulnerabilities across the asset inventory at a point in time.
- **Policy Compliance**: Assessment of asset configurations against security benchmarks (e.g., CIS, DISA STIG) using InsightVM policy scanning.
- **SQL Report**: A custom InsightVM report built using the platform's built-in SQL query console to extract and format vulnerability and asset data.

---

## Requirements

### Requirement 1: Asset Discovery and Inventory

**User Story:** As a security program manager, I want a complete and continuously updated inventory of all assets in scope, so that the vulnerability management program has accurate coverage and no blind spots.

#### Acceptance Criteria

1. THE Program_Administrator SHALL define at least one InsightVM Site per network segment or business unit before initiating scans.
2. WHEN a new network range is added to scope, THE Program_Administrator SHALL create or update the corresponding Site within 5 business days.
3. THE Scan_Engine SHALL be deployed within each network segment that cannot be reached from a central scan engine due to firewall restrictions.
4. WHERE endpoints are managed (laptops, servers, cloud instances), THE Program_Administrator SHALL deploy the Insight Agent to provide continuous asset visibility independent of network scan schedules.
5. WHERE cloud environments (AWS, Azure, GCP) are in scope, THE Program_Administrator SHALL configure the corresponding InsightVM cloud integration to enumerate cloud-native assets automatically.
6. WHEN a credentialed scan is configured, THE Scan_Engine SHALL authenticate to target assets using service accounts with least-privilege read access to software inventory and patch state.
7. THE Program SHALL maintain a documented list of all in-scope asset ranges, Sites, and scan engines, reviewed and updated at least quarterly.
8. WHEN an asset has not been scanned within 30 days, THE InsightVM_Platform SHALL flag the asset as stale in coverage reporting.
9. IF a scan engine loses connectivity to the InsightVM console, THEN THE Scan_Engine SHALL queue scan results locally and transmit them upon reconnection.
10. THE Program SHALL achieve a minimum asset scan coverage of 95% of all known in-scope assets within each 30-day rolling window.

---

### Requirement 2: Vulnerability Assessment

**User Story:** As a security analyst, I want scheduled, credentialed vulnerability scans with consistent baselines, so that I can accurately measure the organization's vulnerability exposure over time.

#### Acceptance Criteria

1. THE Program_Administrator SHALL configure a recurring scan schedule for each Site, with a maximum interval of 30 days between full scans for standard assets.
2. WHERE assets are classified as Very High or High criticality, THE Program_Administrator SHALL configure scan schedules with a maximum interval of 7 days.
3. WHEN a new Site is created and scanned for the first time, THE InsightVM_Platform SHALL record the initial scan result as the baseline for that Site.
4. THE Program_Administrator SHALL assign an Asset Criticality rating (Very High, High, Medium, Low, or Very Low) to every asset or asset group before the first scan result is used in risk reporting.
5. WHEN asset criticality is not explicitly assigned, THE InsightVM_Platform SHALL apply a default criticality of Medium to unclassified assets.
6. THE Program_Administrator SHALL create Asset Groups that reflect organizational boundaries (e.g., by business unit, environment, or geography) to enable scoped reporting.
7. THE Program_Administrator SHALL apply Tags to assets to capture additional attributes (e.g., owner, environment, data classification) that support filtering and reporting.
8. WHEN a credentialed scan completes, THE InsightVM_Platform SHALL report the authentication status (success or failure) per asset so that unauthenticated results can be identified and remediated.
9. IF a credentialed scan fails authentication on an asset, THEN THE Program_Administrator SHALL investigate and resolve the credential issue within 5 business days.
10. THE InsightVM_Platform SHALL retain scan history for a minimum of 12 months to support trend analysis and audit requirements.
11. WHEN a vulnerability is first detected on an asset, THE InsightVM_Platform SHALL record the first-found timestamp to support MTTR calculation.

---

### Requirement 3: Vulnerability Prioritization

**User Story:** As a security analyst, I want a consistent, risk-based prioritization framework aligned with CISA BOD 26-04 principles, so that remediation effort is focused on the vulnerabilities most likely to cause harm based on real-world exploitation risk rather than severity scores alone.

#### Acceptance Criteria

1. THE Program SHALL use a multi-factor prioritization model loosely aligned with CISA BOD 26-04 that weighs the following risk factors over CVSS severity alone: (a) asset exposure — whether the asset is internet-facing or publicly reachable, (b) known exploitation — whether the vulnerability appears in the CISA KEV catalog or has confirmed exploits (hasExploits = true), (c) exploit automation — whether an adversary can automate exploitation at scale (approximated by EPSS score > 0.70), and (d) technical impact — whether exploitation grants partial or total control of the asset.
2. WHEN a vulnerability is on the CISA KEV catalog AND affects an internet-facing asset AND has automatable exploitation (EPSS > 0.70 or hasExploits = true), THE Program SHALL classify it as the highest priority tier (Act) with a remediation target of 3 calendar days and require forensic triage to assess whether the vulnerability has already been exploited.
3. WHEN a vulnerability is on the CISA KEV catalog AND affects an internet-facing asset but exploitation is not automatable, THE Program SHALL classify it as high priority (Attend) with a remediation target of 14 calendar days.
4. WHEN a vulnerability has confirmed exploits or EPSS > 0.70 but the affected asset is NOT internet-facing, THE Program SHALL classify it as elevated priority (Track*) with a remediation target of 60 calendar days.
5. WHEN a vulnerability does not meet any of the above escalation criteria (not on KEV, no confirmed exploits, EPSS ≤ 0.70, asset not internet-facing), THE Program SHALL classify it as standard priority (Track) with remediation deferred to the next scheduled patching cycle or major system upgrade.
6. THE Program_Administrator SHALL define SLA targets aligned to the risk tiers as follows: Act — 3 calendar days, Attend — 14 calendar days, Track* — 60 calendar days, Track — next patch cycle (not to exceed 180 calendar days).
7. WHEN a vulnerability's age exceeds its SLA target without remediation or an approved exception, THE InsightVM_Platform SHALL flag it as an SLA breach in reporting. SLA breaches are tracked separately from exceptions — a missed SLA does not justify an exception and remediation remains required.
8. THE Program SHALL use InsightVM's Active Risk Score as the default sort order when presenting vulnerability lists to analysts, so that the highest-risk items appear first.
9. WHERE an asset is classified as Very High criticality, THE Program SHALL apply a 1.5x multiplier to the asset's contribution to organizational risk score calculations.
10. THE Program_Administrator SHALL review and confirm the prioritization model parameters (SLA targets, EPSS threshold, KEV alignment, asset exposure definitions) at least annually.
11. WHEN a new vulnerability affecting in-scope assets is added to the CISA KEV catalog, THE InsightVM_Platform SHALL surface it in the analyst dashboard within 24 hours of the next completed scan.
12. THE Program SHALL maintain a documented prioritization policy referencing BOD 26-04 principles that is reviewed and approved by the security leadership team annually.

---

### Requirement 4: Remediation Workflow

**User Story:** As a security program manager, I want a structured remediation workflow with clear ownership and tracking, so that vulnerabilities are assigned, tracked, and resolved within SLA targets.

#### Acceptance Criteria

1. THE Program_Administrator SHALL create InsightVM Remediation Projects to assign vulnerability remediation work to specific teams or individuals with defined due dates aligned to SLA targets.
2. WHEN a Remediation Project is created, THE Program_Administrator SHALL assign an owner from the responsible remediation team (e.g., IT operations, cloud engineering, application team) before the project is activated.
3. THE Program SHALL implement a formal vulnerability exception and exclusion process within InsightVM for vulnerabilities that will not be remediated due to technical infeasibility, false positive determination, or accepted business risk. Exceptions SHALL NOT be used solely because an SLA target was missed — SLA breaches are tracked separately and remediation remains required. WHEN a vulnerability qualifies for exception, THE Requestor SHALL submit an exception request using InsightVM's vulnerability exception workflow, specifying the exception type (False Positive, Compensating Control, or Acceptable Risk), business justification, compensating controls description, and a proposed review date.
4. WHEN a Remediation Project due date is within 7 calendar days and the project is not marked complete, THE InsightVM_Platform SHALL generate an alert to the project owner and the security team.
5. THE Program_Administrator SHALL define a patching cadence policy that specifies patch deployment windows for each asset criticality tier (e.g., emergency patching within 24 hours for Critical, monthly patch cycles for Low).
6. WHEN a remediation action is completed by the remediation team, THE InsightVM_Platform SHALL verify closure by confirming the vulnerability is no longer detected in the next scan of the affected asset.
7. THE Program SHALL support a formal exception process: WHEN a vulnerability cannot be remediated within SLA, THE Requestor SHALL submit a documented exception request including business justification, compensating controls, and an accepted risk date.
8. WHEN an exception is approved, THE Program_Administrator SHALL record the exception in InsightVM and set a review date no more than 90 days from the approval date.
9. THE Program SHALL track and report the total count of open exceptions, grouped by severity and business unit, on a monthly basis.
10. WHEN a vulnerability is marked as a false positive, THE Program_Administrator SHALL document the justification and the analyst who approved the false positive designation within InsightVM.

---

### Requirement 5: Measurement and Reporting

**User Story:** As a security leader, I want consistent metrics and audience-appropriate dashboards, so that I can demonstrate program effectiveness, track SLA compliance, and communicate risk posture to stakeholders.

#### Acceptance Criteria

1. THE Program SHALL track and report the following core metrics on a monthly cadence: MTTR by severity tier, SLA compliance rate by severity tier, total vulnerability backlog count, scan coverage percentage, and count of exploitable findings (hasExploits = true).
2. THE Program_Administrator SHALL configure InsightVM dashboards tailored to three audiences: executive leadership (risk trend, SLA compliance, top risks), security operations (analyst workqueue, new findings, SLA breaches), and remediation teams (open projects, overdue items, asset-level detail).
3. WHEN the monthly risk score trend shows an increase of 10% or more compared to the prior month, THE Security_Team SHALL produce a written root cause analysis and present it to security leadership within 10 business days.
4. THE Program SHALL produce a monthly vulnerability management report delivered to security leadership that includes: coverage rate, backlog trend, MTTR trend, SLA compliance rate, and top 10 highest-risk assets.
5. WHEN scan coverage falls below 90% of in-scope assets in a given month, THE Program_Administrator SHALL identify and document the gap and present a remediation plan to security leadership within 5 business days.
6. THE Program SHALL maintain a historical record of all monthly metric snapshots for a minimum of 24 months to support year-over-year trend analysis.
7. WHEN a new business unit or acquisition is added to scope, THE Program_Administrator SHALL establish a baseline metric snapshot for that scope within 60 days of onboarding.
8. THE Program SHALL report exploitable findings (vulnerabilities where hasExploits = true or EPSS > 0.50) as a separate metric category to distinguish them from the overall backlog.
9. THE Program_Administrator SHALL use InsightVM's built-in SQL report console to create custom reports for metrics and data views not available through native dashboard cards.
10. THE Program_Administrator SHALL review and validate all dashboard configurations and metric definitions at least semi-annually to ensure alignment with current program goals.

---

### Requirement 6: Program Maturity

**User Story:** As a security program manager, I want to progressively mature the program using InsightVM's native capabilities, so that the program becomes more consistent, measurable, and scalable without requiring additional tools.

#### Acceptance Criteria

1. THE Program_Administrator SHALL configure InsightVM policy compliance scans against at least one industry benchmark (e.g., CIS Benchmarks, DISA STIG) for each major asset class (servers, workstations, network devices) within 90 days of completing Phase 2.
2. WHEN a policy compliance scan completes, THE InsightVM_Platform SHALL report the pass/fail rate per benchmark rule and per asset, enabling targeted configuration remediation.
3. THE Program_Administrator SHALL configure InsightVM Goals to define and track SLA targets natively within the platform, so that SLA compliance is visible without manual calculation.
4. WHEN a Goal threshold is breached (e.g., SLA compliance rate falls below the defined target), THE InsightVM_Platform SHALL surface the breach in the relevant dashboard so that the security team can take action.
5. THE Program_Administrator SHOULD configure InsightVM's built-in automation triggers to send notifications for defined events (e.g., new Critical vulnerability detected, SLA breach reached); automation triggers are recommended but not required for program operation.
6. IF automation triggers are configured, THEN THE InsightVM_Platform SHOULD deliver the configured notification (e.g., email alert) to the designated recipient within 15 minutes of the triggering event; teams without automation triggers SHALL rely on dashboard monitoring and scheduled SQL reports for equivalent visibility.
7. THE Program SHALL define and document a formal vulnerability management maturity model with at least four levels (Initial, Developing, Defined, Optimizing) and assess the program against it annually.
8. THE Program SHALL conduct a tabletop exercise or structured review of the vulnerability management process at least annually to identify gaps not visible through metrics alone.
9. THE Program_Administrator SHALL document all scan configurations, Asset Groups, Tags, Remediation Project templates, Goals, dashboard layouts, and SQL reports in a runbook that is reviewed and updated at least annually.
10. THE Program_Administrator SHALL review InsightVM release notes at least quarterly and evaluate new native features for adoption into the program before considering external tool integrations.
