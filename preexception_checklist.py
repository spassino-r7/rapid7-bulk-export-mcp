#!/usr/bin/env python3
"""
Pre-Exception Verification Checklist.

Before an analyst records a vulnerability exception (via exceptions.py), they should
confirm the finding is genuinely not-applicable / already-remediated. This module
produces a per-finding verification checklist:

  1. Vendor advisory link(s)      - so the analyst reads the authoritative source
  2. The InsightVM proof/detection- exactly what the scanner keyed on (the thing to disprove)
  3. Local verification commands   - OS-aware package/version checks to run on the asset
  4. Remote check (if available)   - a Metasploit auxiliary scanner (check mode) or safe probe

Data sources (in priority order), matching the rest of the exception tooling:
  - InsightVM console API v3 (references / solutions / vuln detail) -- richest
  - Bulk-export DuckDB `proof` / `bestSolutionSummary` -- offline fallback

Where the data cannot produce a concrete step, a clearly-labeled MANUAL step
placeholder is emitted rather than guessing.

Output: prints the checklist to the console AND writes a markdown artifact under
exception-checklists/ that the analyst can fill in and attach to the exception.

Usage:
    python3 preexception_checklist.py --vuln-id unix-cups-cve-2024-47176 --asset-ip 192.168.1.188
    python3 preexception_checklist.py --vuln-id postgres-cve-2026-2005 --no-api   # offline / bulk-export only
"""

import os
import re
import sys
import html
import argparse
import subprocess
from datetime import datetime, timezone

import duckdb

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BULK_EXPORT_DB = os.path.join(BASE_DIR, "rapid7_bulk_export.db")
OUT_DIR = os.path.join(BASE_DIR, "exception-checklists")

DEFAULT_CONSOLE = os.environ.get("INSIGHTVM_CONSOLE", "https://ivmcon:3780")
KEYCHAIN_SERVICE = "insightvm-console-api"
DEFAULT_USER = "apiUser"

MANUAL = "[MANUAL STEP] "


# ---------------------------------------------------------------------------
# Auth / session (mirrors sync_exceptions.py)
# ---------------------------------------------------------------------------

def get_console_password(user):
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", user, "-w"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return os.environ.get("INSIGHTVM_PASSWORD", "") or None


def make_session(user, password):
    s = requests.Session()
    s.verify = False
    s.auth = (user, password)
    s.headers.update({"Accept": "application/json"})
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_html(s):
    if not s:
        return ""
    text = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _cve_from_vuln_id(vuln_id):
    m = re.search(r"(cve-\d{4}-\d+)", vuln_id, re.IGNORECASE)
    return m.group(1).upper() if m else None


def parse_proof(proof_html):
    """Extract OS and 'package version' from an InsightVM proof blob."""
    text = _strip_html(proof_html)
    os_match = re.search(r"Vulnerable OS:\s*([^<]+?)(?:Vulnerable|$)", text, re.IGNORECASE)
    sw_match = re.search(r"Vulnerable software installed:\s*(.+)$", text, re.IGNORECASE)
    vuln_os = os_match.group(1).strip() if os_match else None
    sw = sw_match.group(1).strip() if sw_match else None
    pkg = version = distro = None
    if sw:
        # e.g. "Ubuntu openjdk-11-jre-headless 11.0.31+11-1ubuntu1~22.04.2"
        #      "Postgres 18"
        parts = sw.split()
        if parts and parts[0] in ("Ubuntu", "Debian", "Red", "CentOS", "SUSE", "Postgres"):
            if parts[0] in ("Ubuntu", "Debian"):
                distro = parts[0]
                if len(parts) >= 3:
                    pkg, version = parts[1], " ".join(parts[2:])
                elif len(parts) == 2:
                    pkg = parts[1]
            else:
                pkg = parts[0]
                version = " ".join(parts[1:]) if len(parts) > 1 else None
        else:
            pkg = parts[0] if parts else None
            version = " ".join(parts[1:]) if len(parts) > 1 else None
    return {"vuln_os": vuln_os, "software": sw, "package": pkg, "version": version, "distro": distro}


def verification_commands(os_family, distro, package, fixed_summary):
    """Return OS-aware local verification commands, or a manual placeholder."""
    cmds = []
    fam = (os_family or "").lower()
    dist = (distro or "").lower()

    if "debian" in dist or "ubuntu" in dist or "linux" in fam:
        if package:
            if dist in ("ubuntu", "debian") or "debian" in dist or "ubuntu" in dist:
                cmds.append(f"dpkg -l {package}                 # installed version")
                cmds.append(f"apt-cache policy {package}        # installed vs. candidate")
                cmds.append(f"zcat /usr/share/doc/{package}/changelog.Debian.gz | head -40   # confirm the fix landed in the changelog")
            else:
                cmds.append(f"rpm -q {package}                  # installed version (RPM-based)")
                cmds.append(f"rpm -q --changelog {package} | head -40   # confirm the CVE fix in the changelog")
        else:
            cmds.append(MANUAL + "Identify the package from the advisory, then run `dpkg -l <pkg>` (Debian/Ubuntu) or `rpm -q <pkg>` (RHEL/SUSE).")
    else:
        cmds.append(MANUAL + f"OS family '{os_family or 'unknown'}' — determine the correct package-query command for this platform and confirm the installed version.")

    if fixed_summary:
        cmds.append(f"# Compare the installed version against the fixed target: {fixed_summary}")
    else:
        cmds.append(MANUAL + "No vendor-fixed version in InsightVM data — confirm the not-vulnerable condition from the vendor advisory.")
    return cmds


# ---------------------------------------------------------------------------
# Data gathering
# ---------------------------------------------------------------------------

def gather_from_api(session, console, vuln_id):
    """Return dict with title, severity, advisories[], solution_text, or None on failure."""
    out = {"advisories": [], "solution_text": None, "title": None, "severity": None, "source": "api"}
    try:
        d = session.get(f"{console}/api/3/vulnerabilities/{vuln_id}", timeout=20)
        if d.status_code != 200:
            return None
        vj = d.json()
        out["title"] = vj.get("title")
        out["severity"] = vj.get("severity")

        refs = session.get(f"{console}/api/3/vulnerabilities/{vuln_id}/references?size=50", timeout=20)
        if refs.status_code == 200:
            for r in refs.json().get("resources", []):
                adv = r.get("advisory", {})
                href = adv.get("href")
                if href:
                    out["advisories"].append({"ref": r.get("reference"), "source": r.get("source"), "href": href})

        sols = session.get(f"{console}/api/3/vulnerabilities/{vuln_id}/solutions", timeout=20)
        if sols.status_code == 200:
            texts = []
            for sid in sols.json().get("resources", []):
                sd = session.get(f"{console}/api/3/solutions/{sid}", timeout=20)
                if sd.status_code == 200:
                    steps = sd.json().get("steps", {})
                    txt = steps.get("text") or sd.json().get("summary", {}).get("text")
                    if txt:
                        texts.append(txt)
            out["solution_text"] = " | ".join(texts) if texts else None
        return out
    except Exception:
        return None


def gather_from_bulk(vuln_id, asset_ip=None):
    """Fallback: pull proof/solution/OS from the bulk-export DuckDB."""
    if not os.path.exists(BULK_EXPORT_DB):
        return None
    try:
        con = duckdb.connect(BULK_EXPORT_DB, read_only=True)
    except Exception:
        return None
    try:
        # The on-disk export schema can lag the MCP's live schema (columns like
        # bestSolutionSummary may be absent). Select only columns that exist.
        vcols = {r[0] for r in con.execute("PRAGMA table_info('vulnerabilities')").fetchall()}
        acols = {r[0] for r in con.execute("PRAGMA table_info('assets')").fetchall()}

        # If the on-disk schema doesn't even carry vulnId, it's unusable here.
        if "vulnId" not in vcols:
            return None

        want_v = [c for c in ["vulnId", "title", "severity", "port", "protocol",
                              "proof", "bestSolutionSummary", "bestSolutionFix"] if c in vcols]
        want_a = [c for c in ["hostName", "ip", "osProduct", "osFamily"] if c in acols]
        select = ", ".join([f"v.{c}" for c in want_v] + [f"a.{c}" for c in want_a])

        where = "v.vulnId = ?"
        params = [vuln_id]
        if asset_ip and "ip" in acols:
            where += " AND a.ip = ?"
            params.append(asset_ip)

        row = con.execute(
            f"SELECT {select} FROM vulnerabilities v LEFT JOIN assets a ON v.assetId=a.assetId "
            f"WHERE {where} LIMIT 1",
            params,
        ).fetchone()
        if not row:
            return None
        cols = [d[0] for d in con.description]
        return dict(zip(cols, row)) | {"source": "bulk"}
    finally:
        con.close()


def find_remote_check(vuln_id):
    """Best-effort hint for a remote verification path. The Metasploit exploit-mapper
    MCP can enumerate auxiliary scanner modules for a CVE; here we emit guidance and a
    manual placeholder rather than call it directly (keeps this script dependency-light)."""
    cve = _cve_from_vuln_id(vuln_id)
    lines = []
    if cve:
        lines.append(f"Search Metasploit for an auxiliary *scanner* module for {cve} and run it in CHECK mode:")
        lines.append(f"  msfconsole -q -x 'search {cve}; exit'   # look for auxiliary/scanner/... entries")
        lines.append("  # If a scanner exists: use <module>; set RHOSTS <asset>; set RPORT <port>; run   (check-only, non-invasive)")
        lines.append("  # Or use the metasploit-exploit-mapper: match_exploits_by_cve / search_modules to confirm a check module exists.")
    else:
        lines.append(MANUAL + "No CVE parsed from the vuln id — determine whether a safe remote check (nmap script, vendor tool) exists.")
    lines.append(MANUAL + "If no remote check exists, rely on the local verification commands above plus the vendor advisory.")
    return lines


# ---------------------------------------------------------------------------
# Checklist assembly
# ---------------------------------------------------------------------------

def build_checklist(vuln_id, asset_ip=None, use_api=True, console=DEFAULT_CONSOLE, user=DEFAULT_USER):
    cve = _cve_from_vuln_id(vuln_id)
    api_data = None
    if use_api and _HAVE_REQUESTS:
        pw = get_console_password(user)
        if pw:
            api_data = gather_from_api(make_session(user, pw), console, vuln_id)

    bulk = gather_from_bulk(vuln_id, asset_ip)

    # Merge: prefer API for advisory/solution/title; bulk for proof/OS/asset context.
    title = (api_data or {}).get("title") or (bulk or {}).get("title") or vuln_id
    severity = (api_data or {}).get("severity") or (bulk or {}).get("severity")
    advisories = (api_data or {}).get("advisories") or []
    solution_text = (api_data or {}).get("solution_text") or (bulk or {}).get("bestSolutionSummary")

    proof_html = (bulk or {}).get("proof")
    parsed = parse_proof(proof_html) if proof_html else {"vuln_os": None, "software": None, "package": None, "version": None, "distro": None}
    os_family = (bulk or {}).get("osFamily") or (bulk or {}).get("osProduct")
    host = (bulk or {}).get("hostName")
    ip = (bulk or {}).get("ip") or asset_ip
    port = (bulk or {}).get("port")

    # Advisory fallbacks if API returned none.
    if not advisories:
        if cve:
            advisories.append({"ref": cve, "source": "nvd-fallback",
                               "href": f"https://nvd.nist.gov/vuln/detail/{cve}"})
        else:
            advisories.append({"ref": None, "source": "manual",
                               "href": MANUAL + "Locate the vendor advisory for this vulnerability."})

    cmds = verification_commands(os_family, parsed.get("distro"), parsed.get("package"), solution_text)
    remote = find_remote_check(vuln_id)

    return {
        "vuln_id": vuln_id, "cve": cve, "title": title, "severity": severity,
        "host": host, "ip": ip, "port": port,
        "advisories": advisories, "solution_text": solution_text,
        "proof_text": _strip_html(proof_html) if proof_html else None,
        "parsed": parsed, "os_family": os_family,
        "commands": cmds, "remote": remote,
        "sources": [s for s in [("api" if api_data else None), ("bulk" if bulk else None)] if s],
    }


def render_markdown(c):
    L = []
    L.append(f"# Pre-Exception Verification Checklist — {c['vuln_id']}")
    L.append("")
    L.append(f"- **Title:** {c['title']}")
    if c["cve"]:
        L.append(f"- **CVE:** {c['cve']}")
    if c["severity"]:
        L.append(f"- **Severity:** {c['severity']}")
    if c["host"] or c["ip"]:
        L.append(f"- **Asset:** {c['host'] or ''} {('(' + c['ip'] + ')') if c['ip'] else ''}".strip())
    if c["port"]:
        L.append(f"- **Port:** {c['port']}")
    L.append(f"- **Data sources used:** {', '.join(c['sources']) or 'none (offline)'}")
    L.append(f"- **Generated:** {datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}Z")
    L.append("")
    L.append("Complete every step before recording an exception. Attach this file to the exception record.")
    L.append("")

    L.append("## 1. Read the vendor advisory")
    for a in c["advisories"]:
        ref = f" ({a['ref']})" if a.get("ref") else ""
        L.append(f"- [ ] [{a['source']}{ref}]({a['href']})" if a['href'].startswith("http")
                 else f"- [ ] {a['href']}")
    L.append("")

    L.append("## 2. Confirm what InsightVM detected (the claim to disprove)")
    if c["proof_text"]:
        L.append(f"> {c['proof_text']}")
        if c["parsed"].get("package"):
            L.append("")
            L.append(f"- Detected package: `{c['parsed']['package']}`"
                     + (f"  version `{c['parsed']['version']}`" if c['parsed'].get('version') else ""))
        if c["parsed"].get("vuln_os"):
            L.append(f"- Detected OS: `{c['parsed']['vuln_os']}`")
    else:
        L.append("- " + MANUAL + "Proof not available in bulk export — open the finding in the InsightVM console and record the detection proof here.")
    L.append("")

    L.append("## 3. Verify locally on the asset")
    if c["solution_text"]:
        L.append(f"_Vendor solution / fixed target:_ {c['solution_text']}")
        L.append("")
    L.append("```bash")
    for cmd in c["commands"]:
        L.append(cmd)
    L.append("```")
    L.append("- [ ] Installed version confirms the fix is present (or the component is not installed / not applicable)")
    L.append("")

    L.append("## 4. Remote check (if available)")
    for line in c["remote"]:
        L.append(f"- {line}" if not line.startswith("  ") else f"  {line.strip()}")
    L.append("")

    L.append("## 5. Determination")
    L.append("- [ ] Verified NOT vulnerable — proceed to record exception (reason: False Positive)")
    L.append("- [ ] Vulnerable but accepting risk — proceed with reason: Acceptable Risk / Compensating Control (document controls)")
    L.append("- [ ] Still vulnerable, no exception — remediate instead")
    L.append("")
    L.append("**Verifier:** ______________________   **Date:** ____________")
    L.append("")
    L.append("_Suggested next command once verified:_")
    scope = f"--scope-type Asset --scope-id <console-asset-id>" if c["ip"] else "--scope-type Global"
    L.append("```bash")
    L.append(f"python3 exceptions.py --vuln-id {c['vuln_id']} {scope} \\")
    L.append(f"  --reason \"False Positive\" --cve-id {c['cve'] or '<CVE>'} \\")
    L.append("  --comment \"<verification summary + advisory link>\" --submitted-by <you>")
    L.append("```")
    return "\n".join(L)


def main(argv=None):
    p = argparse.ArgumentParser(description="Generate a pre-exception verification checklist for a finding.")
    p.add_argument("--vuln-id", required=True, help="Rapid7 vulnId (e.g. unix-cups-cve-2024-47176)")
    p.add_argument("--asset-ip", help="Asset IP, to pull that asset's proof/OS from the bulk export")
    p.add_argument("--no-api", action="store_true", help="Skip the console API; use bulk-export data only")
    p.add_argument("--console", default=DEFAULT_CONSOLE)
    p.add_argument("--user", default=DEFAULT_USER)
    p.add_argument("--out-dir", default=OUT_DIR)
    args = p.parse_args(argv)

    c = build_checklist(args.vuln_id, asset_ip=args.asset_ip, use_api=not args.no_api,
                        console=args.console, user=args.user)
    md = render_markdown(c)

    # console output
    print(md)

    # markdown artifact
    os.makedirs(args.out_dir, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", args.vuln_id)
    stamp = datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(args.out_dir, f"preexception_{safe}_{stamp}.md")
    with open(path, "w") as fh:
        fh.write(md + "\n")
    print(f"\n---\nChecklist written to: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
