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

*Last updated: 2026-07-01*
