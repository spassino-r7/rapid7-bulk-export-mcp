Here are your talking points:

---

## Meeting: Configuring InsightVM for BOD 26-04 Alignment (30 min)

### Opening (2 min)

- BOD 26-04 replaces BOD 22-01 — shifts from "patch KEV in X days" to a 4-variable risk model
- Goal today: configure what we can natively in IVM, acknowledge what requires supplemental tooling

---

### BOD 26-04 Decision Variables — What IVM Can and Can't See (5 min)

| Variable | IVM Native? | How |
|----------|-------------|-----|
| In KEV | ✅ Yes | Vulnerability category = "CISA KEV" (dim_vulnerability_category) |
| Publicly Exposed | ✅ Yes (with setup) | Asset tag — you define and apply it |
| Automatable | ❌ No | Requires SSVC data from NVD/Vulnrichment — not in console |
| Technical Impact | ❌ No | Same — SSVC only |

**Key point:** IVM gets you 2 of 4 variables natively. The other 2 require external enrichment (Bulk Export + MCP tooling or manual process).

---

### What to Configure Today — Tags (5 min)

**Required tags to create in IVM:**
- `Internet-Exposed` — any asset reachable from untrusted networks
- `Business-Crit1` — highest criticality (revenue, customer data, auth)
- `Business-Crit2` — elevated criticality (production shared services)

**How:** Assets → Tags → Create Tag (custom) → Apply to relevant assets

**BOD 26-04 also requires tagging** (Required Action 7):
- Organization/sub-org
- Environment (prod/dev)
- Exposure (public/internal)
- Asset type (server, application, network device)

---

### What to Configure Today — Goals & SLAs (10 min)

Best approximation using available console filters:

| Goal Name | Scope | Criteria | SLA |
|-----------|-------|----------|-----|
| KEV + Exposed | Tag = Internet-Exposed, Category = CISA KEV | All | 14 days |
| KEV + Internal | Category = CISA KEV (no exposure tag) | All | 60 days |
| Exposed + Exploitable | Tag = Internet-Exposed | CVSS ≥ 8 AND Exploit Available | 30 days |
| Crit Assets — High Risk | Tag = Business-Crit1 | CVSS ≥ 8 AND Exploit Available | 30 days |
| All — Critical Severity | All | Severity = Critical | 60 days |
| All — Severe | All | Severity = Severe | 90 days |
| All — Moderate | All | Severity = Moderate | 180 days |

**Important caveat:** These are approximations. BOD's 3-day timeline for KEV + Exposed + Automatable + Total Impact can't be fully replicated because we can't filter on "Automatable" in Goals.

---

### The Gap — What Goals Can't Do (3 min)

- Can't differentiate 3-day vs 14-day (both require KEV + exposed — but 3-day also needs automatable)
- Can't filter on CVSS vector components (Attack Vector, Complexity, User Interaction)
- Can't use EPSS for prioritization
- Severity labels are Rapid7-proprietary (not straight CVSS cutoffs)

**For full BOD compliance reporting:** Bulk Export API + enrichment tooling produces the actual 3/14/60/180-day classification with all 4 variables. Run alongside Goals as the governance layer.

---

### Quick Wins for the Customer (3 min)

1. **Enable CISA KEV category in reporting** — create a report scoped to vulnerability category = "CISA KEV" and schedule weekly delivery
2. **Tag their internet-facing assets today** — even 80% accuracy is better than none
3. **Set up a "KEV + Exposed" Goal** — immediate visibility into their highest-risk BOD bucket
4. **Data retention** — configure scan data retention to keep console performant (Administration → Maintenance → Data Retention)
5. **Bulk Export API key** — if they want the full BOD report, they need a Platform Admin API key generated today

---

### Closing / Next Steps (2 min)

- Tags + Goals = operational day-to-day (patch teams see this in console)
- BOD compliance report = governance layer (monthly leadership reporting)
- Recommend: start with Goals today, add BOD reporting as phase 2
- Offer to run first BOD report against their data once they have the API key configured

---

### If Asked: "Why can't IVM do all of this natively?"

BOD 26-04 uses CISA's SSVC framework (Automatable, Technical Impact) which is published through the NVD Vulnrichment program — it's external intelligence that no scanner vendor has embedded natively yet. The CVSS vector components in the scan data get you close as a heuristic, but the official SSVC determination requires cross-referencing the NVD API.
