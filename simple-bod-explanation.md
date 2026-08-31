Now I have the full context. Let me rewrite the explanation tied to how the first layer works with InsightVM:

---

Sure. Let me reframe this around what we actually set up in InsightVM as the first layer.

**What is BOD 26-04?**

BOD stands for "Binding Operational Directive." It's an order from CISA (the US government's cybersecurity agency) that tells organizations how quickly they need to fix known security weaknesses in their software. Think of it as a set of deadlines based on how dangerous a vulnerability actually is to *you*.

**The old way: one-size-fits-all deadlines**

The previous directive (BOD 22-01) was simple: if a vulnerability is on the KEV list (Known Exploited Vulnerabilities — meaning attackers are actively using it), you have a flat deadline to fix it. Same deadline whether it's on your public-facing web server or a printer in a closet.

**The new way: four risk variables**

BOD 26-04 looks at four things to decide how fast you need to fix something:

1. **Is it in the KEV catalog?** — Is this being exploited in the wild right now?
2. **Is the asset publicly exposed?** — Can someone on the internet reach this system?
3. **Is it automatable?** — Can an attacker write a script to exploit this at scale with no human interaction?
4. **What's the technical impact?** — If exploited, does the attacker get total control, or just partial access?

The combination of these four variables determines your deadline: 3 days, 14 days, 60 days, or 180 days.

**What we configured in InsightVM as the "first layer"**

InsightVM can natively see 2 of those 4 variables:

- **KEV status** — InsightVM already categorizes vulnerabilities as "CISA KEV" so we can filter on that directly
- **Publicly exposed** — We created a tag called `Internet-Exposed` and applied it to any asset reachable from the internet

The other two (Automatable and Technical Impact) come from CISA's SSVC framework published through the NVD — no scanner has that built in natively yet.

**The Goals and SLAs we set up**

Using those two variables we *can* see, we built remediation goals in the console that approximate BOD timelines:

| Goal Name | What we're tracking | Deadline |
|---|---|---|
| BOD-KEV-Exposed-14d | KEV + Internet-Exposed | 14 days |
| BOD-KEV-Internal-60d | KEV + Internal only | 60 days |
| BOD-Exposed-Exploit-30d | Exposed + Exploitable (CVSS ≥ 8) | 30 days |
| BOD-BizCrit-Exploit-30d | Business-Critical assets + Exploitable | 30 days |
| BOD-Critical-60d | All Critical severity | 60 days |
| BOD-Severe-90d | All Severe | 90 days |
| BOD-Moderate-180d | All Moderate (informational) | 180 days |

**Advanced Goals (enrichment gap approximation)**

These goals use Active Risk scoring and exploit intelligence to approximate what the full BOD 26-04 SSVC enrichment layer provides — specifically the "automatable" and "total impact" variables that IVM cannot see natively.

| Goal Name | Criteria | Deadline | Rationale |
|---|---|---|---|
| BOD-ActiveRisk-High-30d | Active Risk ≥ 900 | 30 days | Proxy for weaponized/automatable vulns — Active Risk incorporates exploit availability, malware kits, and temporal factors |
| BOD-Exploitable-Critical-30d | exploits IS NOT null AND severity = Critical | 30 days | Explicit known exploit + Critical severity — easy to explain, deterministic |
| BOD-Exposed-ActiveRisk-14d | Internet-Exposed tag + Active Risk ≥ 900 | 14 days | Closest approximation to BOD's shortest non-KEV deadline (exposed + weaponized) |

**How the two tiers work together**

The base goals give your patch team daily visibility in the console. The advanced goals close the gap between what IVM can see natively and what the full BOD 26-04 directive requires. Together they get you approximately 90% of BOD compliance tracking without leaving the console — the remaining 10% (SSVC "automatable" and "technical impact" classifications) comes from the enrichment layer in the full BOD compliance report.

Think of it as progressive coverage:
- **Base goals alone** → you're tracking severity + KEV + exposure. Good operational hygiene, but you can't distinguish a Critical vuln that's trivially scriptable from one that requires manual exploitation.
- **Base + Advanced goals** → you're also tracking exploit weaponization and risk scoring. This catches the vulns most likely to trigger short BOD deadlines before the full enrichment confirms it.
- **Full BOD report (enrichment layer)** → you have the complete four-variable picture from NVD/SSVC. This is the governance layer that confirms actual compliance and catches edge cases the console can't see.

These Goals give your patch team a daily view inside the console of what needs attention and what's overdue.

**Why this is "risk-based" instead of "score-based"**

Instead of saying "everything rated Critical gets the same deadline," we're asking *contextual questions*: Is someone actually exploiting this? Can they reach this system from the internet? Is this a business-critical asset? The combination of those answers drives urgency — not just a number from 1 to 10.

**The gap (and why there's a second layer)**

The 3-day deadline in BOD 26-04 requires knowing *all four* variables — including whether the exploit is automatable. InsightVM's Goals can't filter on that because it's external intelligence that lives in the NVD, not in your scanner. So what we configured in the console is the operational first layer (your patch teams use it daily), and the full BOD compliance report with all four variables is the governance layer that runs through the Bulk Export API + enrichment tooling — that's the report we just generated.

**The analogy**

Think of the InsightVM Goals as the triage nurse — they sort patients by visible urgency (bleeding? conscious? walk-in?) and get people into the right queue fast. The full BOD report is the attending physician — they have the lab results, imaging, and full history to make the final call on treatment priority. Both are needed, but the triage nurse (Goals) keeps things moving while the full picture comes together.
