# InsightVM High-Level Walkthrough Checklist

A step-by-step checklist for setting up and using Rapid7 InsightVM for vulnerability management.

---

## 1. Scan Engine Deployment

- [ ] Deploy scan engines in each network segment/zone
- [ ] Pair scan engines with the Security Console
- [ ] Verify network connectivity between engines and target subnets
- [ ] Configure firewall rules to allow scan traffic
- [ ] Deploy the Insight Agent on endpoints for agent-based scanning (optional but recommended)

## 2. Site Configuration

- [ ] Create sites to organize assets by network, location, or business unit
- [ ] Define asset discovery connections (DHCP logs, Active Directory, cloud connectors)
- [ ] Add target IP ranges, hostnames, or CIDR blocks to each site
- [ ] Assign scan engines to sites
- [ ] Configure scan credentials (SSH, SMB/WMI, SNMP, database, etc.)
- [ ] Validate credentials with a test scan on a small asset group

## 3. Scan Templates & Scheduling

- [ ] Select or customize scan templates (Full Audit, Discovery, Web Audit, etc.)
- [ ] Set scan windows (maintenance windows, off-hours)
- [ ] Schedule recurring scans (weekly or daily recommended)
- [ ] Configure scan blackout periods if needed
- [ ] Enable adaptive scanning for dynamic environments

## 4. Running Your First Scan

- [ ] Run a discovery scan to identify live assets
- [ ] Review discovered assets — confirm expected hosts are found
- [ ] Run a full vulnerability scan against a test site
- [ ] Verify scan completes without credential failures or timeouts
- [ ] Review scan logs for errors or incomplete coverage

## 5. Asset Management

- [ ] Review and organize the asset inventory
- [ ] Create asset groups (dynamic or static) by OS, location, criticality, owner
- [ ] Apply tags for business context (criticality, owner, environment, compliance scope)
- [ ] Identify and merge duplicate assets
- [ ] Set up dynamic discovery connections for cloud (AWS, Azure, GCP)

## 6. Vulnerability Review & Prioritization

- [ ] Review the dashboard for overall risk posture
- [ ] Check severity distribution (Critical, Severe, Moderate)
- [ ] Use Active Risk scoring (Real Risk) for prioritization
- [ ] Filter by exploitability — focus on vulns with known exploits
- [ ] Review CVSS scores and attack vectors
- [ ] Identify assets with the highest risk scores
- [ ] Check for vulnerabilities in CISA KEV catalog

## 7. Remediation Planning

- [ ] Create Remediation Projects (Goals → Remediation Projects)
- [ ] Review top remediations ranked by risk reduction
- [ ] Assign solutions to asset owners or teams
- [ ] Set remediation due dates based on SLA/policy
- [ ] Export remediation plans for ticket creation (Jira, ServiceNow, etc.)
- [ ] Track progress as vulns are patched and verified in subsequent scans

## 8. Reporting

- [ ] Set up scheduled reports (Executive Summary, Remediation Plan, PCI, etc.)
- [ ] Configure report distribution lists (email recipients)
- [ ] Generate a baseline report for initial posture documentation
- [ ] Create custom report templates if needed
- [ ] Set up Data Warehouse exports for BI/analytics (optional)

## 9. Dashboards & Monitoring

- [ ] Customize the default dashboard with relevant cards
- [ ] Add cards: Top Remediations, Risk Trend, Exploit Exposure, Asset Coverage
- [ ] Create role-specific dashboards (executive vs. operational)
- [ ] Monitor scan health — ensure scans complete on schedule
- [ ] Set up alerts for new critical vulnerabilities

## 10. Policy Compliance (Optional)

- [ ] Enable policy scanning in scan templates
- [ ] Select benchmarks (CIS, DISA STIG, PCI DSS, etc.)
- [ ] Run policy scans against applicable assets
- [ ] Review pass/fail rates by benchmark and rule
- [ ] Track compliance improvement over time
- [ ] Export policy results for audit evidence

## 11. Integrations

- [ ] Connect to ticketing (Jira, ServiceNow) for automated ticket creation
- [ ] Set up SIEM integration (syslog, InsightConnect)
- [ ] Configure cloud connectors (AWS, Azure, GCP) for dynamic asset discovery
- [ ] Enable Insight Agent for continuous monitoring
- [ ] Connect to InsightConnect for automated workflows/playbooks
- [ ] Set up Bulk Export API for custom reporting pipelines (optional)

## 12. Ongoing Operations

- [ ] Review scan results weekly
- [ ] Track remediation SLA compliance
- [ ] Re-scan after patching to verify fixes
- [ ] Monitor for reintroduced vulnerabilities
- [ ] Update scan credentials when passwords rotate
- [ ] Review and tune scan templates quarterly
- [ ] Archive or remove decommissioned assets
- [ ] Refresh agent deployments as new systems are provisioned

## 13. Maturity Improvements

- [ ] Implement risk-based prioritization (EPSS + exploitability + asset criticality)
- [ ] Automate remediation workflows with InsightConnect
- [ ] Establish vulnerability SLAs by severity tier
- [ ] Build executive reporting cadence (monthly/quarterly)
- [ ] Integrate with CMDB for asset ownership and business context
- [ ] Adopt BOD 22-01 / BOD 26-04 compliance tracking (if applicable)
- [ ] Set up trending dashboards to demonstrate progress over time

---

## Quick Reference — Key Locations in the Console

| Task | Where to Find It |
|------|-----------------|
| Create a site | Administration → Sites → New Site |
| Manage scan engines | Administration → Scan Engines |
| Configure credentials | Site → Authentication |
| View assets | Assets tab |
| View vulnerabilities | Assets → select asset → Vulnerabilities |
| Remediation projects | Goals → Remediation Projects |
| Reports | Reports → Create/Manage |
| Dashboards | Home → Dashboards |
| Policy compliance | Policies tab |
| User management | Administration → Users |
| Scan templates | Administration → Scan Templates |
| Tags | Assets → Tags |

---

*Last updated: 2026-06-30*
