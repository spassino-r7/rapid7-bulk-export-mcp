# BOD 26-04 Enrichment Demo Results — 2026-07-28

## The Scenario

CVE-2021-44228 (Log4Shell) re-introduced on `container` (192.168.1.163) to demonstrate the value of SSVC/NVD enrichment over InsightVM Goals alone.

## Report Summary

| Metric | Before Log4Shell | After Log4Shell |
|---|---|---|
| Total Findings | 25 | 27 |
| In CISA KEV | 0 | 1 (CISA + VulnCheck) |
| 14-day deadline | 0 | 1 |
| Has Exploit Module | 0 | 1 (3 Metasploit modules) |
| EPSS > 0.9 | 0 | 1 (score: 1.0000) |
| Findings with shorter BOD deadline than IVM Goal | 0 | 1 |

## CVE-2021-44228 — Full Enrichment

| Variable | Value | Source |
|---|---|---|
| Severity | Critical | InsightVM |
| CVSS v3 | 10.0 | NVD |
| In CISA KEV | Yes | CISA KEV catalog |
| In VulnCheck KEV | Yes | VulnCheck KEV catalog |
| Automatable (SSVC) | Yes | CISA Vulnrichment / NVD |
| Technical Impact | Total | CISA Vulnrichment / NVD |
| EPSS Score | 1.0000 (100th percentile) | FIRST EPSS |
| Metasploit Modules | 3 available | Metasploit Pro |
| BOD 26-04 Timeline | **14 days** | Calculated from 4 variables |
| IVM Goal (Critical) | 60 days | Severity-based SLA |
| Deadline gap | **46 days faster** under BOD vs IVM Goal | — |

## SSVC Enrichment Coverage Gap (Full Report)

| Metric | Value | Explanation |
|---|---|---|
| Automatable | 44% (12/27) | IVM Goals can't see this — treats them same as non-automatable |
| Total Impact | 30% (8/27) | IVM severity doesn't distinguish full takeover from partial access |
| Accelerated by BOD | 1 finding | CVE-2021-44228 requires 14 days; IVM would allow 60 |
| No hard deadline | 52% (14/27) | SSVC says upgrade-only; IVM still assigns a severity SLA |

## The Key Takeaway

**Without enrichment:** CVE-2021-44228 is just another "Critical" finding with a 60-day Goal deadline — same priority as 9 other Critical vulns on ivmcon.

**With enrichment:** It's immediately flagged as:
- Actively exploited (KEV)
- Automatable (scriptable at scale)
- Total system compromise if exploited
- EPSS 100% (highest possible exploitation probability)
- 3 ready-to-use Metasploit exploit modules
- **14-day deadline, not 60**

The 46-day gap between what IVM Goals assign and what BOD 26-04 actually requires is completely invisible without the SSVC/NVD enrichment layer.

## How the Two Layers Work

| Layer | What it sees | Where it runs | Who uses it |
|---|---|---|---|
| **InsightVM Goals** (first layer) | Severity, KEV tag, exposure tag, CVSS | Console — daily view | Patch teams |
| **BOD Compliance Report** (second layer) | All 4 SSVC variables + KEV + EPSS + exploit modules | Bulk Export API + MCP enrichment | Security Ops / Governance |

## Timeline Distribution (27 findings)

| BOD Timeline | Count | Description |
|---|---|---|
| 14 days | 1 | KEV + automatable + total impact (Log4Shell) |
| 180 days | 12 | Automatable or total impact, but not in KEV, internal |
| Fix on system upgrade | 14 | Not automatable, partial impact, no hard deadline required |

## Remediation Priority (from this report)

1. **CVE-2021-44228 on container** — 14-day deadline, due 2026-08-05. 3 exploit modules available. Fix immediately.
2. **CVE-2025-6021, CVE-2026-21945 on ivmcon** — 180-day deadline, due 2026-09-21. Automatable. Update Azul Zulu.
3. **Everything else** — 180 days or upgrade-only. Address during normal patching cadence.


## The Story: Use Both Sets of Goals

**Base Goals** = operational hygiene (severity + KEV + exposure). Your patch team uses these daily in the console. They answer: "what needs attention based on what we can see natively?"

**Advanced Goals** (Active Risk, Exploitable+Critical, Exposed+ActiveRisk) = closer approximation to BOD. They catch most of what the directive cares about — weaponized, exploitable, high-risk findings get shorter deadlines. But they still can't see:

- **Automatable** — Active Risk correlates with it but isn't the same thing. A vuln can be automatable without having a public exploit yet.
- **Technical Impact (total vs. partial)** — Active Risk doesn't distinguish "attacker gets full root" from "attacker gets read access." Both could score the same.
- **The exact BOD timeline calculation** — the directive uses a specific decision tree (Table 1) that maps the four variables to 3d/14d/60d/180d. The Advanced Goals approximate the urgency but can't reproduce the exact deadline.

**The full BOD report** (enrichment layer) = actual compliance. It's the only thing that can definitively say "this finding has a 14-day deadline" because it has all four variables from SSVC/NVD.

**The narrative for customers:** Use both sets of Goals to get your team 90% of the way there operationally, and run the enriched report for governance-level compliance confirmation. The Advanced Goals are the early warning system — the full report is the official answer.
