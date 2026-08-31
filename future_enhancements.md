# Future Enhancements — BOD 26-04 & Exploit Mapping Pipeline

## Task: Metasploit vs IVM Blind Spot Analysis (CISA KEV)

**Goal:** Identify CISA KEV CVEs that have Metasploit exploit modules but no corresponding InsightVM detection check.

**Why it matters:** These are exploitable-in-the-wild vulnerabilities that an attacker can weaponize via Metasploit, but IVM won't flag them during a scan. True blind spots.

**Prerequisites:**
- Metasploit Pro SSH tunnel running (`ssh -L 3790:192.168.1.244:3790`)
- Data Warehouse SSH tunnel running (`ssh -L 5433:192.168.1.216:5432`)
- Both should be unnecessary once the firewall case is resolved

**Steps:**
1. `refresh_module_cache()` — pull all 2,653 exploit modules with CVE cross-references
2. Query DW `dim_vulnerability_reference` for all CVEs IVM can detect
3. Cross-reference: CISA KEV ∩ Metasploit exploits − IVM checks = blind spots
4. Generate report with the gap list

**Status:** Blocked — waiting on firewall case resolution to eliminate SSH tunnels. Script logic is proven (tested with 8 cached CVEs, all covered). Need full cache refresh for real results.

---

## Task: MSF Workspace Scan for KEV Gap Products

**Goal:** Instead of per-CVE scanning, run one comprehensive `db_nmap -sV` across the environment, then query the Metasploit workspace for products matching KEV gap vendors.

**Why it's better:** One scan covers all 26 network device gaps (Zyxel, D-Link, NETGEAR, Ubiquiti, Tenda, Cisco, Realtek) simultaneously rather than 26 individual targeted scans.

**Steps:**
1. Run `db_nmap -sV -p 1-10000 --script http-title,http-server-header,ssl-cert 192.168.1.0/24` in Metasploit workspace
2. Build a script that extracts vendor/product keywords from the 26 network device KEV gaps
3. Query MSF workspace: `services -S "<vendor>"` for each
4. Cross-reference matches against specific CVE affected versions
5. Output: "Host X is running Zyxel firmware → potentially affected by CVE-YYYY-NNNNN"

**Prerequisites:**
- Metasploit Pro SSH tunnel (or direct access post-firewall fix)
- Completed `db_nmap` scan of the environment
- KEV gap product list (already generated in `kev_gap_detection_guide.html`)

**Status:** Not started — save for after firewall case resolution.

---

## Planned: Google Threat Intelligence MCP for Forensic Triage

**Goal:** Automate the forensic investigation step when BOD 26-04 flags a finding as "3 days + forensic triage required."

**Problem:** When a KEV vuln is found on a publicly-exposed asset, BOD 26-04 requires assuming compromise and investigating for indicators of exploitation *before* remediation. Currently this is manual.

**Solution:** Integrate Google Threat Intelligence (GTI) MCP server to:
1. Pull known IoCs (C2 IPs, callback domains, payload hashes) for the CVE
2. Provide exploitation timeline (when attacks started in the wild)
3. List TTPs/MITRE ATT&CK techniques to search for in logs
4. Feed IoCs into InsightIDR or Chronicle for historical log search
5. Generate a forensic triage report: compromised or clean

**MCP Server:** `github.com/google/mcp-threat-intelligence`
- Access to VirusTotal, Mandiant threat intel, Google threat data
- Query by CVE, IP, domain, file hash
- Returns structured IoC data

**Integration flow:**
```
BOD report flags CVE with "forensic triage required"
    ↓
GTI MCP: get_iocs_for_cve("CVE-XXXX-XXXXX")
    → Known C2 IPs, callback domains, payload hashes, TTPs
    ↓
InsightIDR/Chronicle: search logs for those IoCs
    ↓
Generate forensic triage report: compromised or not
    ↓
Attach to BOD compliance evidence
```

**Prerequisites:**
- Google Threat Intelligence API access (may require VirusTotal Enterprise or Mandiant subscription)
- InsightIDR or Chronicle integration for log correlation
- SSH tunnel or network access for log queries

**Status:** Not started — saved for future implementation.

---

## Monitoring: Rapid7 Bulk Export — Best Solution Data

**Goal:** Add support for "best solution" data once Rapid7 ships it in the Bulk Export API.

**Background:** Rapid7 announced that bulk exports will include best-solution/remediation-step data. As of July 2026, this has not yet landed in the API or the official `rapid7/rapid7-bulk-export-mcp` GitHub repo (checked July 10, 2026). The upstream MCP server currently supports only `vulnerability`, `policy`, and `remediation` export types.

**What to monitor:**
- Rapid7 Bulk Export API docs: https://docs.rapid7.com/insightvm/bulk-export-api/
- GitHub repo: https://github.com/rapid7/rapid7-bulk-export-mcp (commits, PRs)
- Rapid7 release notes / changelog for InsightVM

**When it lands, implementation plan:**
1. Determine if it's a new export type (`solution`) or new columns in the existing vulnerability Parquet schema
2. Add the new mutation/query to `export_manager.py`
3. Create a `solutions` table in DuckDB with appropriate schema
4. Add a `start_rapid7_export(export_type="solution")` path
5. Enable queries like: "What's the fix for CVE-XXXX on this asset?"
6. Integrate solution data into BOD 26-04 reports (show fix steps alongside findings)

**Value:** Currently, solution data is only available via the InsightVM console UI or APIv3 per-vulnerability lookup. Bulk solution data would allow reporting like "top 5 patches that fix the most findings" at scale.

**Status:** Monitoring — feature not yet available in API or MCP server.

---

## Task: InsightVM Remote Check Catalog for External ASM Scan Template

**Goal:** Build a catalog of all InsightVM vulnerability checks that run in "remote" (unauthenticated) mode, along with their target service/port. Use this to create an optimized external attack surface management scan template.

**Why it matters:** InsightVM doesn't expose check type (remote vs. authenticated) in the API v3 structured responses. Without this data, you can't know which checks fire during an unauthenticated external scan or identify coverage gaps in your ASM scanning.

**Approach:**

1. Pull distinct vulnerability IDs from your environment:
   ```sql
   SELECT DISTINCT vulnerability_id, title FROM dim_vulnerability dv
   JOIN fact_asset_vulnerability_finding favf ON dv.vulnerability_id = favf.vulnerability_id
   ```

2. For each vuln ID, call the console administration command endpoint:
   ```
   POST /api/3/administration/commands
   Body: "show vuln <vulnerability_id>"
   ```

3. Parse the text response — look for check entries that indicate "Remote" type

4. Build output catalog:
   - vuln_id, title, check_type (remote/local), target_service, target_port
   - Filter to remote-only checks

5. From the remote check catalog:
   - Identify all target ports → build optimal ASM port list
   - Cross-reference with KEV → find remotely-exploitable KEV CVEs you can detect
   - Identify gaps → KEV CVEs that are remotely exploitable but have no remote check

**Estimated effort:**
- ~500–2,000 API calls (scoped to vulns in your environment)
- ~5-10 minutes runtime at moderate rate limiting
- One-time collection (re-run quarterly after content updates)

**Output:**
- `remote_check_catalog.json` — full list of remote checks with service/port mapping
- `asm_scan_template_guide.md` — recommended scan template configuration
- Port list optimized for external scanning

**Prerequisites:**
- Console API v3 access (direct or via SSH tunnel)
- Console administration command permissions

**Status:** Not started — waiting on firewall/SSH tunnel resolution.

---

## Task: BOD 26-04 Exception Process Integration

**Goal:** Add a formal exception/risk acceptance mechanism to the BOD 26-04 compliance report that stays in sync with InsightVM's native Vulnerability Exceptions feature.

**Why it matters:** Currently the BOD report flags overdue findings with no way to document accepted risks. Findings like CVE-2024-6387 on `mspro` show as compliance failures even if the organization has formally accepted the risk with compensating controls. The exception should exist in both places — InsightVM (for console visibility) and the BOD report (for compliance reporting).

**Design:**

1. **DuckDB `exceptions` table:**
   ```sql
   CREATE TABLE bod_exceptions (
       cve_id VARCHAR,
       asset_id VARCHAR,
       hostname VARCHAR,
       exception_type VARCHAR,  -- risk_acceptance, compensating_control, false_positive, eol_deferral
       reason TEXT,
       compensating_control TEXT,
       approver VARCHAR,
       approval_date DATE,
       expiration_date DATE,
       ivm_exception_id VARCHAR,  -- links to InsightVM exception for traceability
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   )
   ```

2. **Sync with InsightVM:**
   - When an exception is created in our tooling, also create it in InsightVM via API v3:
     `POST /api/3/vulnerabilities/{vulnId}/exceptions`
   - When pulling exceptions from InsightVM (via console or API), mirror them into the DuckDB table
   - Single source of truth: exception exists in BOTH systems or neither

3. **BOD report behavior:**
   - Check `bod_exceptions` before flagging a finding as overdue
   - If a valid (non-expired) exception exists: show as "Exception (expires YYYY-MM-DD)" with the reason
   - If exception is expired: revert to overdue status, flag for re-review
   - Summary section: "X findings excepted, Y exceptions expiring within 30 days"

4. **MCP tool additions:**
   - `create_bod_exception(cve_id, asset_id, type, reason, expiration, approver)` — creates in both DuckDB and IVM
   - `list_bod_exceptions()` — shows all active exceptions with expiration status
   - `expire_bod_exceptions()` — flags expired exceptions and returns them for review
   - `sync_ivm_exceptions()` — pulls IVM exceptions and reconciles with local table

5. **Exception lifecycle:**
   ```
   Create exception (MCP tool or manual)
     → Stored in DuckDB bod_exceptions table
     → Created in InsightVM via API v3
     → BOD report shows "Excepted" instead of "Overdue"
     → Monthly review: list expiring exceptions
     → On expiration: reverts to overdue, triggers alert
     → Renewal: create new exception with fresh approval
   ```

**Prerequisites:**
- Console API v3 access (for creating IVM exceptions programmatically)
- Define approval authority matrix (who can approve by severity)
- Define expiration policy (Critical: 30 days, High: 90 days, etc.)

**Status:** Not started — design documented, ready to implement.

---

*Last updated: 2026-07-21*
