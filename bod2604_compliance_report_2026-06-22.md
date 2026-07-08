# BOD 26-04 Vulnerability Remediation Compliance Report

**Directive:** CISA BOD 26-04: Prioritizing Security Updates Based on Risk
**Generated:** 2026-06-22T16:05:03.136231

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | 2 |
| Unique CVEs | 2 |
| Unique Assets | 1 |
| **Overdue** | **0** |
| Requires Forensic Triage | 0 |

### Remediation Timeline Distribution

| Timeline | Count |
|----------|-------|
| Fix on system upgrade | 2 |

## Findings by Remediation Timeline

### Fix on system upgrade

| CVE | Host | Severity | Timeline | Due Date | EPSS | KEV |
|-----|------|----------|----------|----------|------|-----|
| CVE-2026-34480 | mspro (192.168.1.244) | Critical | Fix on system upgrade | — | 0.0086 | — |
| CVE-2026-34477 | mspro (192.168.1.244) | Severe | Fix on system upgrade | — | 0.0040 | — |

## Detailed Findings

### CVE-2026-34480 — Apache Log4j Core: Silent log event loss in XmlLayout

| Field | Value |
|-------|-------|
| Host | mspro (192.168.1.244) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0086 (percentile: 53.71%)
- In VulnCheck KEV: No

---

### CVE-2026-34477 — Apache Log4j Core: verifyHostName attribute silently ignored in TLS configuration

| Field | Value |
|-------|-------|
| Host | mspro (192.168.1.244) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0040 (percentile: 31.15%)
- In VulnCheck KEV: No

---

## Methodology

This report evaluates vulnerabilities against CISA BOD 26-04 Table 1
remediation timelines using four decision variables:

1. **In KEV** — Is the CVE in CISA's Known Exploited Vulnerabilities catalog?
2. **Publicly Exposed** — Is the asset reachable from untrusted networks?
3. **Automatable** — Can an adversary automate all exploit delivery steps?
4. **Technical Impact** — Does exploitation yield total or partial control?

Data sources: CISA KEV, VulnCheck KEV, FIRST EPSS, CISA Vulnrichment (SSVC/NVD)
