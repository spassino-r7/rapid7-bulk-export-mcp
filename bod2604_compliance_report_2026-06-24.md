# BOD 26-04 Vulnerability Remediation Compliance Report

**Directive:** CISA BOD 26-04: Prioritizing Security Updates Based on Risk
**Generated:** 2026-06-24T08:14:05.927528

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | 11 |
| Unique CVEs | 11 |
| Unique Assets | 3 |
| **Overdue** | **0** |
| Requires Forensic Triage | 0 |

### Remediation Timeline Distribution

| Timeline | Count |
|----------|-------|
| 180 days | 8 |
| Fix on system upgrade | 3 |

## All Findings

| CVE | Host | Sev | KEV | Auto | Impact | Timeline | Due | EPSS | Overdue |
|-----|------|-----|-----|------|--------|----------|-----|------|---------|
| CVE-2026-34480 | mspro | Crit | — | Y | total | 180d | 2026-11-10 | 0.009 | — |
| CVE-2025-7425 | ivmcon | Sev | — | N | total | 180d | 2026-09-21 | 0.003 | — |
| CVE-2026-32814 | dhouse | Sev | — | N | total | 180d | 2026-12-20 | 0.003 | — |
| CVE-2026-52859 | dhouse | Crit | — | Y | partial | 180d | 2026-12-20 | 0.003 | — |
| CVE-2026-47162 | dhouse | Crit | — | N | total | 180d | 2026-12-20 | 0.003 | — |
| CVE-2026-21932 | ivmcon | Sev | — | N | total | 180d | 2026-09-21 | 0.003 | — |
| CVE-2026-52860 | dhouse | Sev | — | N | total | 180d | 2026-12-20 | 0.002 | — |
| CVE-2026-52858 | dhouse | Sev | — | N | total | 180d | 2026-12-20 | 0.002 | — |
| CVE-2026-32741 | dhouse | Crit | — | N | partial | Upgrade | — | 0.003 | — |
| CVE-2026-32882 | dhouse | Crit | — | N | partial | Upgrade | — | 0.003 | — |
| CVE-2026-47167 | dhouse | Sev | — | N | partial | Upgrade | — | 0.001 | — |

## Findings by Remediation Timeline

### 180 days

| CVE | Host | Severity | Timeline | Due Date | EPSS | KEV |
|-----|------|----------|----------|----------|------|-----|
| CVE-2026-34480 | mspro (192.168.1.244) | Critical | 180 days | 2026-11-10 | 0.0086 | — |
| CVE-2025-7425 | ivmcon (192.168.1.162) | Severe | 180 days | 2026-09-21 | 0.0034 | — |
| CVE-2026-32814 | dhouse (192.168.1.216) | Severe | 180 days | 2026-12-20 | 0.0030 | — |
| CVE-2026-52859 | dhouse (192.168.1.216) | Critical | 180 days | 2026-12-20 | 0.0030 | — |
| CVE-2026-47162 | dhouse (192.168.1.216) | Critical | 180 days | 2026-12-20 | 0.0027 | — |
| CVE-2026-21932 | ivmcon (192.168.1.162) | Severe | 180 days | 2026-09-21 | 0.0025 | — |
| CVE-2026-52860 | dhouse (192.168.1.216) | Severe | 180 days | 2026-12-20 | 0.0022 | — |
| CVE-2026-52858 | dhouse (192.168.1.216) | Severe | 180 days | 2026-12-20 | 0.0020 | — |

### Fix on system upgrade

| CVE | Host | Severity | Timeline | Due Date | EPSS | KEV |
|-----|------|----------|----------|----------|------|-----|
| CVE-2026-32741 | dhouse (192.168.1.216) | Critical | Fix on system upgrade | — | 0.0028 | — |
| CVE-2026-32882 | dhouse (192.168.1.216) | Critical | Fix on system upgrade | — | 0.0027 | — |
| CVE-2026-47167 | dhouse (192.168.1.216) | Severe | Fix on system upgrade | — | 0.0014 | — |

## Detailed Findings

### CVE-2026-34480 — Log4j: XmlLayout log loss

| Field | Value |
|-------|-------|
| Host | mspro (192.168.1.244) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | Yes |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-11-10 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0086 (percentile: 53.76%)
- In VulnCheck KEV: No

---

### CVE-2025-7425 — Azul Zulu: libxslt Memory Corruption

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-09-21 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0034 (percentile: 25.56%)
- In VulnCheck KEV: No

---

### CVE-2026-32814 — Ubuntu: libheif vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-12-20 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0030 (percentile: 21.75%)
- In VulnCheck KEV: No

---

### CVE-2026-52859 — Ubuntu: Vim vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | Yes |
| Technical Impact | partial |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-12-20 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0030 (percentile: 21.74%)
- In VulnCheck KEV: No

---

### CVE-2026-47162 — Ubuntu: Vim vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-12-20 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0027 (percentile: 18.25%)
- In VulnCheck KEV: No

---

### CVE-2026-21932 — Azul Zulu: Java AWT Integrity

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-09-21 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0025 (percentile: 16.32%)
- In VulnCheck KEV: No

---

### CVE-2026-52860 — Ubuntu: Vim vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-12-20 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0022 (percentile: 12.90%)
- In VulnCheck KEV: No

---

### CVE-2026-52858 — Ubuntu: Vim vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | total |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-12-20 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0020 (percentile: 10.01%)
- In VulnCheck KEV: No

---

### CVE-2026-32741 — Ubuntu: libheif vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | partial |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0028 (percentile: 19.30%)
- In VulnCheck KEV: No

---

### CVE-2026-32882 — Ubuntu: libheif vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | partial |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0027 (percentile: 18.83%)
- In VulnCheck KEV: No

---

### CVE-2026-47167 — Ubuntu: Vim vuln

| Field | Value |
|-------|-------|
| Host | dhouse (192.168.1.216) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | partial |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0014 (percentile: 3.29%)
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
