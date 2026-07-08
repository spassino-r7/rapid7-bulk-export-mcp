# CISA BOD 26-04 Alignment Crosswalk

**Program:** Vulnerability Management Program (InsightVM)
**Directive:** CISA Binding Operational Directive 26-04 — "Prioritizing Security Updates Based on Risk"
**Issued:** June 10, 2026
**Document Owner:** Security Program Administrator
**Last Updated:** June 2026

---

## 1. Overview

CISA BOD 26-04 replaces BOD 19-02 and BOD 22-01, mandating that Federal Civilian Executive Branch (FCEB) agencies prioritize vulnerability remediation using a risk-based model (SSVC) rather than CVSS severity scores alone.

While this directive is binding only for federal agencies, our program adopts its principles as a best-practice framework. This document maps BOD 26-04 requirements to our program's implementation.

---

## 2. BOD 26-04 Key Requirements

| Requirement | BOD 26-04 Mandate | Applies To |
|-------------|-------------------|-----------|
| Risk-based prioritization | Use 4-factor SSVC model instead of CVSS alone | All vulnerabilities |
| Remediation timelines | 3 / 14 / 60 days / defer based on risk tier | All open findings |
| Forensic triage | Check for compromise before patching highest-risk vulns | Tier 1 only |
| Asset exposure tagging | Continuously identify and tag internet-facing assets | All assets |
| Asset inventory tagging | Organization, environment, exposure, asset type, IPs | All assets |
| KEV catalog integration | Use CISA KEV as primary exploitation evidence | CVE matching |
| Continuous discovery | Ongoing identification of assets reachable externally | Network perimeter |
| Data submission | Vulnerability data to CISA every 7 days (if no CDM) | Federal only — N/A for us |

---

## 3. Four-Factor Risk Model — Our Implementation

| BOD Factor | BOD Definition | Our Implementation | Data Source |
|-----------|----------------|-------------------|-------------|
| **Exposure** | Asset publicly reachable from internet | Tag: `exposure=internet-facing` applied to DMZ, public IP, cloud-public assets | InsightVM tags + Site membership |
| **Known Exploitation (KEV)** | CVE in CISA KEV catalog | Weekly KEV JSON cross-reference via `kev_cross_reference.py` | CISA KEV feed |
| **Automatability** | Exploitation requires no human interaction | `hasExploits = true` (Metasploit module) OR EPSS > 0.50 | InsightVM + FIRST.org EPSS |
| **Technical Impact** | Exploitation yields total or partial control | CVSS v3 Impact subscore ≥ 5.9 = Total; < 5.9 = Partial | NVD / Rapid7 |

---

## 4. Remediation Timeline Mapping

| BOD Tier | BOD Deadline | Our SLA | Our Goal Name | Compliance Target |
|----------|-------------|---------|---------------|-------------------|
| Tier 1 | 3 days + forensic triage | 3 days + forensic triage | `SLA-Tier1-3d` | ≥ 95% |
| Tier 2 | 14 days | 14 days | `SLA-Tier2-14d` | ≥ 90% |
| Tier 3 | 60 days | 60 days | `SLA-Tier3-60d` | ≥ 85% |
| Tier 4 | Next system upgrade | Next scheduled upgrade / quarterly | `SLA-Tier4-Upgrade` | ≥ 80% |

---

## 5. Requirement-by-Requirement Crosswalk

### 5.1 Risk-Based Prioritization

| BOD Requirement | Status | Our Implementation |
|-----------------|--------|-------------------|
| Agencies must use SSVC-based model for prioritization | ✅ Implemented | 4-factor model in Vulnerability Prioritization Policy v2.0 |
| Drop CVSS as sole prioritization driver | ✅ Implemented | CVSS retained as supplementary input; risk tier is primary |
| Four factors: exposure, KEV, automatability, impact | ✅ Implemented | See Prioritization Policy Section 3 |

### 5.2 Remediation Timelines

| BOD Requirement | Status | Our Implementation |
|-----------------|--------|-------------------|
| Tier 1: Patch within 3 days | ✅ Implemented | Patching Cadence Policy Section 3.1 |
| Tier 1: Forensic triage before patching | ✅ Implemented | Patching Cadence Policy Section 4 |
| Tier 2: Patch within 14 days | ✅ Implemented | Patching Cadence Policy Section 3.2 |
| Tier 3: Patch within 60 days | ✅ Implemented | Patching Cadence Policy Section 3.3 |
| Tier 4: Defer to next upgrade | ✅ Implemented | Patching Cadence Policy Section 3.4 |

### 5.3 Asset Management

| BOD Requirement | Status | Our Implementation |
|-----------------|--------|-------------------|
| Continuously identify internet-facing assets | ⚠️ Partial | Site membership (DMZ) + manual tagging; recommend adding automated external scan |
| Tag assets: organization, environment, exposure, type | ✅ Implemented | Tag schema in Runbook Section 5: env, owner, exposure, os-type, bu |
| Tag all associated IP addresses | ✅ Implemented | InsightVM natively tracks IPs per asset |
| Update exposure tags within 24h of network changes | ⚠️ Process defined | Policy states 24h; operational adherence needs verification |

### 5.4 KEV Integration

| BOD Requirement | Status | Our Implementation |
|-----------------|--------|-------------------|
| Use KEV catalog as exploitation evidence | ✅ Implemented | Weekly KEV cross-reference script |
| Respond to KEV additions within defined timelines | ✅ Implemented | KEV match triggers tier classification |

### 5.5 Reporting

| BOD Requirement | Status | Our Implementation |
|-----------------|--------|-------------------|
| Submit vulnerability data every 7 days (non-CDM) | N/A | Not a federal requirement for us |
| Track compliance per tier | ✅ Implemented | Monthly report Section 4: Risk Tier Distribution |
| Track MTTR per tier | ✅ Implemented | Monthly report Section 6: MTTR |

---

## 6. Gaps and Improvement Roadmap

| Gap | Risk Level | Remediation Plan | Target Date |
|-----|-----------|-----------------|-------------|
| External attack surface discovery is manual | Medium | Evaluate automated ASM tooling (e.g., InsightVM cloud connectors, external scan engine) | Q3 2026 |
| KEV cross-reference is weekly, not real-time | Low | Move to daily KEV pull; add automation trigger on new KEV additions | Q3 2026 |
| SSVC "automatability" is approximated via hasExploits/EPSS | Low | Acceptable approximation per CISA guidance; revisit if CISA Vulnrichment coverage improves | Annual review |
| No automated re-classification when KEV updates | Medium | Add daily KEV diff check; auto-escalate newly-matched CVEs | Q3 2026 |
| Forensic triage process not yet tested via tabletop | Medium | Schedule tabletop exercise for Tier 1 forensic triage scenario | Q3 2026 |

---

## 7. What We Explicitly Do NOT Adopt

Since we are not a federal agency, the following BOD requirements are acknowledged but not implemented:

| BOD Requirement | Reason for Non-Adoption |
|-----------------|------------------------|
| Submit data to CISA every 7 days | Federal reporting requirement only |
| CDM integration | Federal infrastructure only |
| Mandatory CISA compliance audits | Not subject to CISA oversight |
| Policy update "immediately" upon directive issuance | We adopt within 30 days of review |

---

## 8. Expected Impact on Our Program

Based on CISA's analysis of a large federal agency:

| Metric | Expected Value | Implication |
|--------|---------------|-------------|
| % of vulns in Tier 1 | ~1% | Very few require 3-day emergency response |
| % of vulns in Tier 2 | ~5-10% | Manageable accelerated patching load |
| % of vulns in Tier 3 | ~25-30% | Standard monthly patch cycle handles these |
| % of vulns in Tier 4 | ~60% | Majority can be deferred — reduces patch fatigue |

**Key benefit:** By deferring 60% of vulnerabilities to the next upgrade cycle, we free remediation capacity to focus on the 1-10% that actually pose immediate risk. This directly reduces patch fatigue and improves SLA compliance for high-risk findings.

---

## 9. References

- [CISA BOD 26-04 Directive](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA SSVC Guide](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
- [FIRST EPSS Model](https://www.first.org/epss/)
- Vulnerability Prioritization Policy (internal)
- Patching Cadence Policy (internal)

---

## 10. Document History

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | June 2026 | [FILL IN] | Initial crosswalk created |
