# BOD 26-04 Process Walkthrough

**Purpose:** End-to-end walkthrough of the BOD 26-04 vulnerability prioritization process as implemented in this environment — what is done natively in InsightVM, where enriched data is required, how that data is retrieved and stored, how the compliance and exploit-mapping reports are produced, and how the vulnerability exception workflow keeps the local records and the InsightVM console in sync.

**Audience:** Vulnerability management program administrators and analysts.

**Directive:** CISA Binding Operational Directive 26-04 — "Prioritizing Security Updates Based on Risk" (replaces BOD 22-01 / 19-02). Binding on federal agencies; adopted here as a best-practice framework.

---

## 1. The Big Picture

BOD 26-04 replaces "patch KEV within X days" with a four-variable risk model (SSVC) that produces a remediation timeline per finding:

| Decision variables | Resulting timeline |
|--------------------|--------------------|
| In KEV + Publicly Exposed + Automatable + Total Impact | **3 days + forensic triage** |
| In KEV (most other exposed/automatable combinations) | **14 days** |
| Exploitable / elevated risk, not KEV | **60 days** |
| Everything else with a fix | **180 days** |
| No fix available yet | **Fix on next system upgrade** |

The catch: **InsightVM can natively see only two of the four decision variables.** The other two (Automatable, Technical Impact) come from CISA's SSVC / Vulnrichment program via the NVD — external intelligence no scanner embeds natively today. That gap is the reason this process exists: InsightVM does what it can natively, and a thin enrichment + reporting layer fills the rest.

```
   InsightVM (native)                 Enrichment layer                 Outputs
 ┌─────────────────────┐         ┌────────────────────────┐      ┌──────────────────────┐
 │ Tags, Goals & SLAs  │         │ Bulk Export -> DuckDB   │      │ BOD compliance report│
 │ CISA KEV category   │  ---->  │ KEV / VulnCheck / EPSS  │ ---> │ Exploit mapping report│
 │ Exploit-available   │         │ SSVC (Automatable/Impact)│     │ Trend report          │
 │ Vuln exceptions     │ <-----> │ Metasploit module match │      │ Exception register    │
 └─────────────────────┘         └────────────────────────┘      └──────────────────────┘
        console                     local, scriptable                delivered artifacts
```

---

## 2. What Can Be Done Natively in InsightVM

Start here. Everything in this section is configured in the console UI and requires no external tooling. It covers the operational, day-to-day layer and two of the four BOD variables.

### 2.1 BOD variables InsightVM can see

| BOD variable | Native in InsightVM? | How |
|--------------|----------------------|-----|
| **In KEV** | Yes | Vulnerability category = "CISA KEV" (available as a filter and in the reporting data model) |
| **Publicly Exposed** | Yes (with setup) | Asset tag you define and apply (e.g. `Internet-Exposed`), and/or DMZ site membership |
| **Automatable** | No | Requires SSVC data — not in the console |
| **Technical Impact** | No | Requires SSVC data — not in the console |

> **[SCREENSHOT: InsightVM vulnerability filter showing "CISA KEV" selected as the vulnerability category]**

### 2.2 Asset tagging (foundational)

Tagging is the prerequisite for both native Goals and the enriched BOD report (the exposure variable comes from tags). Create and apply at minimum:

- `Internet-Exposed` — any asset reachable from untrusted networks
- `Business-Crit1` / `Business-Crit2` — criticality tiers (used to sort within BOD buckets)
- BOD-recommended inventory tags: organization/sub-org, environment (prod/dev), exposure (public/internal), asset type (server/app/network device)

**Console path:** Assets → Tags → Create Tag (custom) → apply to assets or asset groups.

> **[SCREENSHOT: Tag creation dialog and a tagged asset showing Internet-Exposed / Business-Crit1]**

### 2.3 Goals & SLAs (native approximation of BOD timelines)

InsightVM's Goals & SLAs feature gives patch teams a visible, in-console compliance target. It is the closest native approximation of BOD timelines. Example configuration:

| Goal Name | Scope | Criteria | SLA |
|-----------|-------|----------|-----|
| KEV + Exposed | Tag = Internet-Exposed, Category = CISA KEV | All | 14 days |
| KEV + Internal | Category = CISA KEV | All | 60 days |
| Exposed + Exploitable | Tag = Internet-Exposed | CVSS ≥ 8 AND Exploit Available | 30 days |
| Crit Assets — High Risk | Tag = Business-Crit1 | CVSS ≥ 8 AND Exploit Available | 30 days |
| All — Critical | All | Severity = Critical | 60 days |
| All — Severe | All | Severity = Severe | 90 days |
| All — Moderate | All | Severity = Moderate | 180 days |

**Console path:** Reports/Management → Goals and SLAs → Create Goal.

> **[SCREENSHOT: Goals & SLAs dashboard showing compliance percentages per goal]**

### 2.4 What Goals & SLAs cannot do

This is exactly the boundary where enrichment becomes necessary:

- Cannot filter on **Automatable** or **Technical Impact** (SSVC) — so cannot distinguish the 3-day bucket from the 14-day bucket
- Cannot use **EPSS** or **VulnCheck KEV**
- Cannot filter on **CVSS vector components** (Attack Vector, Complexity, User Interaction)
- Binary logic only — a finding meets a goal's criteria or it does not; no multi-variable decision tree
- SLAs are static; they do not shorten automatically when a CVE is added to KEV

**Native summary:** InsightVM covers 2 of 4 BOD variables and provides an operational SLA dashboard. Use it as the day-to-day governance layer. For the full four-variable classification, continue to the enrichment layer.

### 2.5 How close does native InsightVM get to BOD 26-04?

Short answer: **native InsightVM gets you a defensible approximation — roughly the right remediation *order* and the two coarsest timeline buckets — but it cannot reproduce the top-tier (3-day) classification and it will systematically under-prioritize a specific, dangerous slice of findings.** It is "good enough to operate, not good enough to certify."

**Coverage scorecard**

| BOD decision variable | Native signal available | Fidelity |
|-----------------------|--------------------------|----------|
| In KEV | CISA KEV category | High — exact match against the CISA KEV catalog |
| Publicly Exposed | Asset tag / DMZ site | High — as accurate as your tagging discipline |
| Automatable (SSVC) | *Proxy only:* Exploit Available, or CVSS Attack Vector/Complexity if read manually | Low — a proxy, not the SSVC determination |
| Technical Impact (SSVC) | *Proxy only:* CVSS v3 impact subscore / severity | Low — a proxy, not the SSVC determination |

So two variables are effectively exact and two can only be *approximated* with CVSS-derived proxies.

**Which BOD timelines are reachable natively**

| BOD timeline | Reachable with native Goals? | Why / caveat |
|--------------|------------------------------|--------------|
| **3 days + forensic triage** (KEV + Exposed + Automatable + Total Impact) | **No** | Requires all four variables; the two SSVC variables are the missing ones. The best a native Goal can do is fold these into a 14-day bucket. |
| **14 days** (KEV, most exposed combinations) | **Approximate** | A "KEV + Internet-Exposed" Goal at 14 days captures this bucket well — but it also silently absorbs everything that *should* have been 3-day. |
| **60 days** (exploitable / elevated, not KEV) | **Approximate** | A "CVSS ≥ 8 AND Exploit Available" Goal is a reasonable stand-in. |
| **180 days** (has a fix, lower risk) | **Good** | Severity-based Goals map cleanly here. |
| **Fix on upgrade** (no fix available) | **Partial** | Not a native concept; usually handled as a long/again-severity SLA. |

**Practical accuracy, in plain terms**

- **Ordering:** native Goals get the broad priority order right most of the time. KEV + exposed rises to the top; low-severity internal findings sink. For day-to-day patch queues this is usually sufficient.
- **The 3-day gap:** the single biggest fidelity loss. Native InsightVM cannot separate "patch in 3 days, and check for compromise first" from ordinary 14-day KEV work, because that separation *is* the two SSVC variables. Any finding that truly belongs in the 3-day tier will be quietly treated as 14-day.
- **Direction of error is (mostly) safe, with one exception:** because the native approximations are deliberately set *slightly stricter* than BOD (e.g. a 14-day KEV+exposed Goal instead of 60), native tends to be conservative — it patches *sooner* than BOD would demand. The unsafe direction is the reverse case: a finding that is automatable + total impact but has only a mid-range CVSS/severity. Native scoring can rate it "medium" and hand it a long SLA, while BOD would put it at 3 days. This is exactly the class of finding the enrichment layer exists to catch.
- **Blind spots native simply cannot see:** EPSS-driven urgency and the SSVC determinations (Automatable, Technical Impact). A CVE with a modest CVSS/severity but a high EPSS and automatable/total-impact profile looks unremarkable to native Goals.

**Rule of thumb:** native InsightVM reproduces about **two of the four BOD variables and three of the five timeline buckets**, gets remediation *order* approximately right, and is safe to run as the operational layer — provided you understand that it cannot produce the 3-day tier and will under-rate the "automatable + high-impact but modest-CVSS" findings. Closing those specific gaps is the entire job of Section 3 onward.

> **[SCREENSHOT: Side-by-side of the same finding — the native InsightVM Goal/SLA classification (e.g. a static 14- or 30-day SLA badge) next to the enriched BOD compliance report row for the same CVE showing its calculated timeline. Illustrates where the native approximation and the four-variable result diverge.]**

---

## 3. When Enhanced Information Is Required

The enriched BOD classification needs data InsightVM does not hold:

| Enrichment | What it provides | Source |
|-----------|------------------|--------|
| **CISA KEV** | Authoritative known-exploited list (also native, but pulled fresh here) | CISA KEV JSON feed |
| **VulnCheck KEV** | Broader exploited-vuln coverage (~3x CISA) + exploit PoC links | VulnCheck |
| **EPSS** | Probability of exploitation in the next 30 days | FIRST.org EPSS |
| **SSVC — Automatable** | Can exploitation be fully automated? (BOD variable 3) | CISA Vulnrichment / NVD |
| **SSVC — Technical Impact** | Total vs. partial control (BOD variable 4) | CISA Vulnrichment / NVD |
| **Metasploit module match** | Is there a working exploit module, and how reliable? | Metasploit module catalog |

### 3.1 Options for retrieving the enriched data

There are two families of retrieval, and this environment uses both:

**A. Pull vulnerability + asset data out of InsightVM**

| Option | Mechanism | When to use |
|--------|-----------|-------------|
| **Bulk Export API** (used here) | Platform API key → export job → Parquet files → loaded into DuckDB | Full nightly dataset; best for complete BOD reporting |
| Reporting Data Warehouse | Postgres export (dimensional model) | If you already run the warehouse; SQL-native analytics |
| Console API v3 (ad hoc) | REST queries against `https://ivmcon:3780/api/3/...` | Targeted lookups, exceptions, small queries |

This environment's primary path is the **Bulk Export API**, driven by the `rapid7-bulk-export-mcp` server, which lands `assets`, `vulnerabilities`, and `vulnerability_remediation` tables in a local DuckDB (`rapid7_bulk_export.db`).

> **[SCREENSHOT: InsightVM Platform API key generation page (Administration → API Keys) — key value redacted]**

**B. Fetch external threat intelligence and map it to the findings**

| Option | Mechanism | Storage |
|--------|-----------|---------|
| **Metasploit Exploit Mapper MCP** (used here) | Local server that caches Metasploit modules + CISA/VulnCheck KEV + EPSS + SSVC and maps CVEs | Local DuckDB module cache |
| Direct API scripts | e.g. `kev_coverage_analysis.py` (CISA KEV), `enrich_cvssv4.py` (NVD) | CSV / DuckDB |

The `metasploit-exploit-mapper` server is what performs KEV/EPSS/SSVC enrichment and the BOD classification math in this environment.

### 3.2 Options for storing the enriched data

| Store | What lives here | Notes |
|-------|-----------------|-------|
| **`rapid7_bulk_export.db`** (DuckDB) | assets, vulnerabilities, remediation | Rewritten by each export; attached **read-only** by the MCP |
| **Metasploit module cache** (DuckDB) | module catalog, CVE→module map, KEV/EPSS caches | Refreshed on a TTL; force-refresh available |
| **`bod_exceptions.db`** (DuckDB) | vulnerability exception register | **Separate, writable** DB (see Section 6) — deliberately isolated so exports never clobber it |
| Report snapshots | per-run BOD trend snapshots | Persisted by the report tool for trending |

**Design rule that matters:** anything the process needs to *write* (exceptions, trend snapshots) must live outside the bulk-export DB, because that file is read-only to the tooling and is fully replaced on every export.

---

## 4. The Daily Pipeline (Export → Enrich → Report)

This is the routine run. Each step names the tool that performs it.

### 4.1 Step 1 — Daily export

Kick off a bulk vulnerability export, wait for completion, and load it into DuckDB.

- Tool: `rapid7-bulk-export-mcp` (`start_rapid7_export` → `check_rapid7_export_status` → `download_rapid7_export`)
- Result: `assets` + `vulnerabilities` tables refreshed locally
- Typical volume in this environment: ~26 assets, ~150 Critical/Severe findings

> **[SCREENSHOT: Export job listed in InsightVM (Administration → Export) or the export status output]**

### 4.2 Step 2 — Refresh enrichment caches

Before classifying, make sure the intelligence is current.

- Refresh KEV catalogs (CISA + VulnCheck) and the Metasploit module cache via the exploit-mapper server
- These are cheap and TTL-guarded; refresh when stale (the tool reports freshness)

### 4.3 Step 3 — Query the findings to classify

Pull the Critical/Severe findings (joined to assets for hostname/IP) from the bulk-export DuckDB. This is the candidate set the BOD logic runs against.

### 4.4 Step 4 — Generate the reports

| Report | Tool | What it shows |
|--------|------|---------------|
| **BOD 26-04 Compliance Report** | exploit-mapper `bod2604_compliance_report` | Per-CVE timeline (3/14/60/180/upgrade), due date, KEV, EPSS, exploit, overdue flag; SSVC-driven |
| **Exploit Mapping Report** | exploit-mapper `exploit_mapping_report` | Which CVEs have Metasploit modules / KEV / high EPSS |
| **Trend Report** | exploit-mapper `bod2604_trend` | Timeline-bucket distribution and overdue count across report runs |

Outputs are saved as dated HTML in `BOD-Reports/` (e.g. `bod2604_compliance_report_YYYY-MM-DD.html`).

**Exposure input:** the compliance report takes an `asset_exposure_map` marking which assets are internet-facing. This is the "Publicly Exposed" BOD variable — sourced from the InsightVM tags described in Section 2.2. Assets marked exposed cascade into shorter SSVC timelines, so this input materially changes results (document the assumption in the report footer).

> **[SCREENSHOT: Rendered BOD compliance report HTML — Executive Summary cards + timeline chart]**

### 4.5 Step 5 — Apply exceptions (see Section 6)

Before or as part of report generation, excepted findings are filtered out of the active timeline/overdue math and listed in a dedicated Exceptions section, so the compliance numbers reflect accepted risk accurately.

---

## 5. Reading the Compliance Report

Key columns and what drives them:

- **Timeline** — the BOD bucket (3/14/60/180 days or fix-on-upgrade), derived from KEV + Exposed + Automatable + Technical Impact.
- **KEV** — `VC` = VulnCheck KEV, blank = not in KEV; CISA KEV shown separately.
- **Auto / Impact** — the SSVC variables (automatable yes/no; total/partial). These are the two InsightVM cannot supply.
- **EPSS** — exploitation probability; used to sort within a bucket.
- **Exploit** — Metasploit module count for the CVE.
- **Overdue** — past its calculated due date.

**Worked example from this environment:** `CVE-2024-47176` (CUPS on host `kali`) is in VulnCheck KEV, EPSS ~0.51 (98th percentile), and has a Metasploit RCE module. With `kali` marked internet-exposed, SSVC classifies it automatable + partial impact → **60-day timeline** and it surfaces as the single highest-priority finding. This is exactly the kind of finding native Goals would under-prioritize (it would see only CVSS + exploit-available), which is the reason the enriched report exists.

---

## 6. The Vulnerability Exception Workflow

Every Critical/Severe finding is either remediated or gets an **exception** (accept risk / compensating control / false positive). Exceptions are recorded locally **and** mirrored to the InsightVM console so the console risk score and the BOD report agree. The workflow is built from a set of scripts around a dedicated database, and begins with a verification step so risk is never accepted on an unverified finding.

### 6.1 Components

| File | Role |
|------|------|
| `exception-process-design.md` | The data model + API v3 field mapping (source of truth for the schema) |
| `create_exceptions_table.py` | Provisions the `vulnerability_exceptions` table in `bod_exceptions.db` (idempotent) |
| `preexception_checklist.py` | **Verification** — generates the pre-exception checklist (advisory, proof, verify commands, remote check) |
| `exceptions.py` | **Write path** — `add_exception()` function + CLI to record an exception locally |
| `sync_exceptions.py` | **Console push** — POSTs pending exceptions to InsightVM API v3, stores the returned console id |
| `apply_exceptions.py` | **Report integration** — partitions findings into active vs. excepted; renders the Exceptions section |
| `reconcile_exceptions.py` | **Reconciliation** — retries failed syncs; pulls console-side state changes back into the local record |

### 6.2 Pre-exception verification (do this first)

An exception accepts risk or declares a finding a false positive — so it must never be filed on an unverified finding. Before recording anything, run the checklist generator:

```
python3 preexception_checklist.py --vuln-id <vulnId> --asset-ip <asset-ip>
# offline / bulk-export only (skip the console API):
python3 preexception_checklist.py --vuln-id <vulnId> --no-api
```

It prints the checklist to the console **and** writes a markdown artifact under `exception-checklists/` (e.g. `preexception_<vulnId>_<date>.md`) for the analyst to complete and attach to the exception record. The checklist has five parts:

1. **Read the vendor advisory** — advisory links pulled from the InsightVM console API v3 (`/api/3/vulnerabilities/{id}/references`), falling back to the NVD CVE page. This is the authoritative "is this actually applicable" source.
2. **Confirm what InsightVM detected** — the raw detection **proof** (from the finding's `proof` field), with the detected package/version and OS parsed out. This is the specific claim the analyst must disprove.
3. **Verify locally on the asset** — OS-aware package/version commands generated from the proof and the vendor solution: `dpkg -l` / `apt-cache policy` / changelog for Debian/Ubuntu, `rpm -q` / `rpm -q --changelog` for RHEL-family, plus a compare-against-fixed-version line. Where the platform can't be determined, a clearly-labeled `[MANUAL STEP]` placeholder is emitted instead of a guess.
4. **Remote check (if available)** — guidance to find and run a Metasploit auxiliary *scanner* module in check mode for the CVE (non-invasive), or a manual placeholder if none exists.
5. **Determination** — the analyst records the outcome (not vulnerable → False Positive; vulnerable but accepted → Acceptable Risk / Compensating Control; still vulnerable → remediate) and the checklist pre-fills the matching `exceptions.py` command.

**Data sources:** console API v3 first (richest — advisory links + solution text), with the bulk-export DuckDB (`proof`, `bestSolutionSummary`) as an offline fallback. Use `--no-api` to force the fallback path.

**Discoverability:** `exceptions.py` prints a reminder pointing back to this checklist whenever an exception is recorded. Pass `--verified` to `exceptions.py` to acknowledge the checklist was completed and suppress the reminder.

> **[SCREENSHOT: A completed pre-exception checklist markdown (e.g. exception-checklists/preexception_unix-cups-cve-2024-47176_*.md) rendered, with advisory links and verification commands filled in]**

### 6.3 The data model (summary)

One exception record carries: a local UUID, the console exception id (once synced), `vuln_id` / `cve_id`, scope (Global / Site / Asset / Asset Group / Instance) and scope id, `reason`, `comment`, optional `expires`, `submitted_by`, `state`, `sync_status`, and BOD context (`bod_original_timeline`, `bod_review_date`). Full field-by-field mapping is in `exception-process-design.md`.

**Two enum casings to be aware of:** the InsightVM console stores `reason` / `state` / `scope.type` in **lowercase** (`false positive`, `approved`, `asset`); the local records use Title Case for readability. `sync_exceptions.py` maps between them.

### 6.4 Authentication

The console API user credential is read from the **macOS Keychain** — never hardcoded:

```
security find-generic-password -s insightvm-console-api -a apiUser -w
```

`sync_exceptions.py` and `reconcile_exceptions.py` read it at runtime (with an `INSIGHTVM_PASSWORD` env fallback) and authenticate to `https://ivmcon:3780` using HTTP Basic auth. To provision the credential once:

```
security add-generic-password -s insightvm-console-api -a apiUser -w
```

(omitting the password makes it prompt interactively, keeping it out of shell history)

> **[SCREENSHOT: InsightVM user/API account used for exceptions (Administration → Users) — showing the account has exception submit rights]**

### 6.5 End-to-end flow

```
 exceptions.py            sync_exceptions.py           InsightVM console
 (record local)     -->   (POST /api/3/               -->  exception created
  state=Under Review       vulnerability_exceptions)        (may auto-approve)
  sync_status=pending      stores console id
                           sync_status=synced
        |                                                        |
        v                                                        v
 apply_exceptions.py  <-----------  reconcile_exceptions.py  <---+
 (filter report:                    (pull state back:
  approved   -> excepted             console approved  -> local Approved
  under review -> annotated          console 404       -> local Deleted)
```

**Submit-only by default:** a new exception lands in the console as *Under Review* and a human approves it there (consistent with the exception procedure). `reconcile_exceptions.py` then pulls the approved state back locally.

> **[SCREENSHOT: InsightVM Vulnerabilities → Exceptions view showing the submitted exception (e.g. CVE-2024-47176 on kali) in Under Review / Approved state]**

### 6.6 How exceptions change the report

- `approved` (or console auto-approved) → finding is **removed** from the active timeline/overdue counts and listed under **Exceptions**.
- `under review` → finding **stays active** but is annotated "exception pending" (still counts toward BOD until approved).
- `expired` / `rejected` / `deleted` (including console-deleted, detected via 404) → ignored; the finding returns to fully active.

Matching is **per-vulnerability + scope**: a Global exception applies everywhere; an Asset exception applies only to that asset (the bulk-export asset id like `...-default-asset-154` resolves to console asset id `154`). An exception on one CVE does not suppress other CVEs on the same host.

### 6.7 Reconciliation and drift

Run `reconcile_exceptions.py` after approvals or on a schedule:

- **Retry** — re-POSTs any `failed` rows.
- **Drift** — for each console-linked row, GETs the console exception and updates local state to match; a console **404** flips the local record to `Deleted` so the report stops suppressing it.
- `--dry-run`, `--retry-only`, `--reconcile-only` flags control scope.

### 6.8 CLI quick reference

```
# 0. Verify first — generate the pre-exception checklist
python3 preexception_checklist.py --vuln-id unix-cups-cve-2024-47176 --asset-ip 192.168.1.188

# Record an exception locally (Asset scope, false positive) after verifying
python3 exceptions.py \
  --vuln-id unix-cups-cve-2024-47176 \
  --scope-type Asset \
  --scope-id 8bd28bcb-...-default-asset-154 \
  --reason "False Positive" \
  --cve-id CVE-2024-47176 \
  --comment "Patch confirmed via changelog; Kali not fully supported by InsightVM" \
  --submitted-by apiUser \
  --verified

# Preview then push pending exceptions to the console
python3 sync_exceptions.py --dry-run
python3 sync_exceptions.py

# Retry failures and reconcile console state
python3 reconcile_exceptions.py
```

---

## 7. Native vs. Enriched — Quick Decision Guide

| Question / use case | Use |
|---------------------|-----|
| Daily patch-team workqueue, visible in console | InsightVM Goals & SLAs (native) |
| Is a CVE in KEV? (quick, in console) | InsightVM vulnerability category = CISA KEV (native) |
| Full BOD 3/14/60/180 classification | Enriched BOD compliance report |
| Does this CVE have a working exploit / high EPSS? | Exploit mapping report (enriched) |
| Are we trending better or worse over time? | BOD trend report (enriched) |
| Accept risk / mark false positive, reflected in console | Exception workflow (Sections 6) |
| Executive / audit evidence with methodology | Enriched reports + exception register |

**Rule of thumb:** native InsightVM is the operational layer (2 of 4 variables, in-console); the enrichment layer is the governance/compliance layer (all 4 variables, delivered as reports). Run both.

---

## 8. File & Tool Reference

**Enrichment / reporting tooling**
- `rapid7-bulk-export-mcp/` — Bulk Export API → DuckDB loader (MCP server)
- `metasploit-exploit-mapper/` — KEV/VulnCheck/EPSS/SSVC + Metasploit mapping and BOD report generation (MCP server)
- `insightvm-warehouse-mcp/` — optional Postgres reporting-warehouse access (MCP server)

**Exception workflow**
- `exception-process-design.md`, `create_exceptions_table.py`, `preexception_checklist.py`, `exceptions.py`, `sync_exceptions.py`, `apply_exceptions.py`, `reconcile_exceptions.py`
- `bod_exceptions.db` — writable exception register (DuckDB)
- `exception-checklists/` — generated pre-exception verification checklists (markdown artifacts)

**Data stores**
- `rapid7_bulk_export.db` — exported assets/vulnerabilities/remediation (read-only to tooling)
- `BOD-Reports/` — dated HTML report artifacts

**Supporting references (already in repo)**
- `vmp-docs/bod-26-04-alignment.md` — requirement-by-requirement crosswalk
- `vmp-docs/bod2604-vs-insightvm-goals-comparison.md` — Goals vs. BOD report comparison
- `vmp-docs/exception-process-procedure.md` — the governance procedure for exceptions
- `bod-ivm-notes.md` — native-configuration talking points

---

## 9. Screenshot Checklist

Add the following where marked above:

1. InsightVM vulnerability filter with "CISA KEV" category selected (§2.1)
2. Tag creation dialog + a tagged asset (§2.2)
3. Goals & SLAs compliance dashboard (§2.3)
4. Native Goal/SLA vs. enriched BOD timeline for the same finding — divergence illustration (§2.5)
5. Platform API key generation page, key redacted (§3.1)
6. Export job / export status (§4.1)
7. Rendered BOD compliance report HTML (§4.4)
8. Completed pre-exception verification checklist markdown (§6.2)
9. InsightVM API user account with exception rights (§6.4)
10. Vulnerabilities → Exceptions view showing a submitted exception (§6.5)

---

## 10. Document History

| Version | Date | Author | Change Summary |
|---------|------|--------|----------------|
| 1.0 | 2026-08-27 | [FILL IN] | Initial end-to-end walkthrough |
