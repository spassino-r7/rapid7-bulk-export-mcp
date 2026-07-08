# BOD 26-04 Vulnerability Remediation Compliance Report

**Directive:** CISA BOD 26-04: Prioritizing Security Updates Based on Risk
**Generated:** 2026-06-23T08:30:17.247930

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Findings | 19 |
| Unique CVEs | 19 |
| Unique Assets | 4 |
| **Overdue** | **0** |
| Requires Forensic Triage | 0 |

### Remediation Timeline Distribution

| Timeline | Count |
|----------|-------|
| 180 days | 2 |
| Fix on system upgrade | 17 |

## All Findings

| CVE | Host | Sev | KEV | Auto | Impact | Timeline | Due | EPSS | Overdue |
|-----|------|-----|-----|------|--------|----------|-----|------|---------|
| CVE-2025-66471 | container | Crit | — | Y | partial | 180d | 2026-11-29 | 0.005 | — |
| CVE-2026-21933 | ivmcon | Sev | — | N | total | 180d | 2026-09-21 | 0.003 | — |
| CVE-2025-6021 | ivmcon | Crit | — | N | — | Upgrade | — | 0.011 | — |
| CVE-2026-34480 | mspro | Crit | — | N | — | Upgrade | — | 0.009 | — |
| CVE-2025-43368 | ivmcon | Sev | — | N | — | Upgrade | — | 0.007 | — |
| CVE-2025-47219 | ivmcon | Crit | — | N | — | Upgrade | — | 0.006 | — |
| CVE-2026-21945 | ivmcon | Crit | — | N | — | Upgrade | — | 0.006 | — |
| CVE-2025-66418 | container | Crit | — | N | — | Upgrade | — | 0.005 | — |
| CVE-2025-6052 | ivmcon | Sev | — | N | — | Upgrade | — | 0.004 | — |
| CVE-2026-34477 | mspro | Sev | — | N | — | Upgrade | — | 0.004 | — |
| CVE-2023-46316 | container | Sev | — | N | partial | Upgrade | — | 0.004 | — |
| CVE-2026-40393 | container | Crit | — | N | — | Upgrade | — | 0.003 | — |
| CVE-2024-35195 | container | Sev | — | N | — | Upgrade | — | 0.003 | — |
| CVE-2025-7425 | ivmcon | Sev | — | N | — | Upgrade | — | 0.003 | — |
| CVE-2026-21932 | ivmcon | Sev | — | N | — | Upgrade | — | 0.003 | — |
| CVE-2026-21925 | ivmcon | Sev | — | N | partial | Upgrade | — | 0.002 | — |
| CVE-2025-61984 | alma10 | Mod | — | N | — | Upgrade | — | 0.002 | — |
| CVE-2026-21947 | ivmcon | Mod | — | N | — | Upgrade | — | 0.002 | — |
| CVE-2026-50593 | container | Sev | — | N | — | Upgrade | — | 0.001 | — |

## Findings by Remediation Timeline

### 180 days

| CVE | Host | Severity | Timeline | Due Date | EPSS | KEV |
|-----|------|----------|----------|----------|------|-----|
| CVE-2025-66471 | container (192.168.1.163) | Critical | 180 days | 2026-11-29 | 0.0053 | — |
| CVE-2026-21933 | ivmcon (192.168.1.162) | Severe | 180 days | 2026-09-21 | 0.0028 | — |

### Fix on system upgrade

| CVE | Host | Severity | Timeline | Due Date | EPSS | KEV |
|-----|------|----------|----------|----------|------|-----|
| CVE-2025-6021 | ivmcon (192.168.1.162) | Critical | Fix on system upgrade | — | 0.0107 | — |
| CVE-2026-34480 | mspro (192.168.1.244) | Critical | Fix on system upgrade | — | 0.0086 | — |
| CVE-2025-43368 | ivmcon (192.168.1.162) | Severe | Fix on system upgrade | — | 0.0072 | — |
| CVE-2025-47219 | ivmcon (192.168.1.162) | Critical | Fix on system upgrade | — | 0.0058 | — |
| CVE-2026-21945 | ivmcon (192.168.1.162) | Critical | Fix on system upgrade | — | 0.0057 | — |
| CVE-2025-66418 | container (192.168.1.163) | Critical | Fix on system upgrade | — | 0.0053 | — |
| CVE-2025-6052 | ivmcon (192.168.1.162) | Severe | Fix on system upgrade | — | 0.0042 | — |
| CVE-2026-34477 | mspro (192.168.1.244) | Severe | Fix on system upgrade | — | 0.0040 | — |
| CVE-2023-46316 | container (192.168.1.163) | Severe | Fix on system upgrade | — | 0.0037 | — |
| CVE-2026-40393 | container (192.168.1.163) | Critical | Fix on system upgrade | — | 0.0035 | — |
| CVE-2024-35195 | container (192.168.1.163) | Severe | Fix on system upgrade | — | 0.0034 | — |
| CVE-2025-7425 | ivmcon (192.168.1.162) | Severe | Fix on system upgrade | — | 0.0029 | — |
| CVE-2026-21932 | ivmcon (192.168.1.162) | Severe | Fix on system upgrade | — | 0.0028 | — |
| CVE-2026-21925 | ivmcon (192.168.1.162) | Severe | Fix on system upgrade | — | 0.0022 | — |
| CVE-2025-61984 | alma10 (192.168.1.173) | Moderate | Fix on system upgrade | — | 0.0022 | — |
| CVE-2026-21947 | ivmcon (192.168.1.162) | Moderate | Fix on system upgrade | — | 0.0022 | — |
| CVE-2026-50593 | container (192.168.1.163) | Severe | Fix on system upgrade | — | 0.0011 | — |

## Detailed Findings

### CVE-2025-66471 — Ubuntu: urllib3 vulnerabilities

| Field | Value |
|-------|-------|
| Host | container (192.168.1.163) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | Yes |
| Technical Impact | partial |
| **Remediation Timeline** | **180 days** |
| Due Date | 2026-11-29 |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0053 (percentile: 40.67%)
- In VulnCheck KEV: No

---

### CVE-2026-21933 — Azul Zulu: Java Networking Sandbox Escape

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

- EPSS Score: 0.0028 (percentile: 19.21%)
- In VulnCheck KEV: No

---

### CVE-2025-6021 — Azul Zulu: libxml2 Stack Buffer Overflow

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0107 (percentile: 60.36%)
- In VulnCheck KEV: No

---

### CVE-2026-34480 — Apache Log4j Core: XmlLayout log loss

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

### CVE-2025-43368 — Azul Zulu: WebKit Use-After-Free

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0072 (percentile: 48.90%)
- In VulnCheck KEV: No

---

### CVE-2025-47219 — Azul Zulu: GStreamer Heap OOB Read

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0058 (percentile: 42.99%)
- In VulnCheck KEV: No

---

### CVE-2026-21945 — Azul Zulu: Java SE Security DoS

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0057 (percentile: 42.70%)
- In VulnCheck KEV: No

---

### CVE-2025-66418 — Ubuntu: urllib3 vulnerabilities

| Field | Value |
|-------|-------|
| Host | container (192.168.1.163) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0053 (percentile: 40.67%)
- In VulnCheck KEV: No

---

### CVE-2025-6052 — Azul Zulu: GLib GString Integer Overflow

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0042 (percentile: 33.34%)
- In VulnCheck KEV: No

---

### CVE-2026-34477 — Apache Log4j Core: TLS hostname verification bypass

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

### CVE-2023-46316 — Ubuntu: Traceroute vulnerability

| Field | Value |
|-------|-------|
| Host | container (192.168.1.163) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | partial |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0037 (percentile: 28.33%)
- In VulnCheck KEV: No

---

### CVE-2026-40393 — Ubuntu: Mesa vulnerability

| Field | Value |
|-------|-------|
| Host | container (192.168.1.163) |
| Severity | Critical |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0035 (percentile: 26.50%)
- In VulnCheck KEV: No

---

### CVE-2024-35195 — Ubuntu: pip vulnerabilities

| Field | Value |
|-------|-------|
| Host | container (192.168.1.163) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0034 (percentile: 25.63%)
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
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0029 (percentile: 20.12%)
- In VulnCheck KEV: No

---

### CVE-2026-21932 — Azul Zulu: Java AWT/JavaFX UI Integrity Compromise

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0028 (percentile: 19.06%)
- In VulnCheck KEV: No

---

### CVE-2026-21925 — Azul Zulu: Java RMI Confidentiality and Integrity Vulnerability

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | partial |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0022 (percentile: 12.44%)
- In VulnCheck KEV: No

---

### CVE-2025-61984 — OpenSSH Control Character Injection

| Field | Value |
|-------|-------|
| Host | alma10 (192.168.1.173) |
| Severity | Moderate |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0022 (percentile: 12.37%)
- In VulnCheck KEV: No

---

### CVE-2026-21947 — Azul Zulu: JavaFX XSS

| Field | Value |
|-------|-------|
| Host | ivmcon (192.168.1.162) |
| Severity | Moderate |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0022 (percentile: 11.89%)
- In VulnCheck KEV: No

---

### CVE-2026-50593 — Ubuntu: Graphite vulnerability

| Field | Value |
|-------|-------|
| Host | container (192.168.1.163) |
| Severity | Severe |
| In CISA KEV | No |
| Publicly Exposed | No |
| Automatable | No |
| Technical Impact | Unknown |
| **Remediation Timeline** | **Fix on system upgrade** |
| Overdue | No |

**Threat Intelligence:**

- EPSS Score: 0.0011 (percentile: 1.65%)
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
