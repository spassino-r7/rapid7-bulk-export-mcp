#!/usr/bin/env python3
"""
Task #5 — Reflect exceptions in the BOD compliance report.

The BOD 26-04 compliance report is generated from a list of findings (one dict per
CVE/asset). This module partitions that list against the local exception registry
(bod_exceptions.db) so the report:

  - EXCLUDES approved exceptions from the timeline / overdue math, and
  - lists them in a dedicated "Exceptions" section, while
  - ANNOTATING findings whose exception is still "under review" (they still count
    toward BOD until approved).

State rules (state values are stored Title Case locally; compared case-insensitively):
  approved       -> finding is EXCEPTED (removed from active findings, shown in Exceptions)
  under review   -> finding stays ACTIVE but annotated exception_pending=True
  expired/rejected/deleted / anything else -> ignored (finding fully active)

Matching a finding to an exception:
  - vuln_id must match, AND
  - scope: Global matches any asset; Asset matches when the finding's asset resolves
    to the same console asset id (trailing integer of the bulk-export assetId).

Usage (import):
    from apply_exceptions import partition_findings
    active, excepted, pending_ids = partition_findings(findings)

Usage (CLI, for inspection):
    python3 apply_exceptions.py --findings findings.json
"""

import os
import re
import sys
import json
import argparse

import duckdb

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEPTIONS_DB = os.path.join(BASE_DIR, "bod_exceptions.db")

STATE_APPROVED = "approved"
STATE_UNDER_REVIEW = "under review"
# States that suppress a finding entirely.
SUPPRESSING_STATES = {STATE_APPROVED}
# States that annotate but do not suppress.
PENDING_STATES = {STATE_UNDER_REVIEW}


def _console_asset_id(value):
    """Resolve a bulk-export assetId or raw id to the console integer asset id
    (trailing integer). Returns str for stable comparison, or None."""
    if value is None:
        return None
    s = str(value).strip()
    if s.isdigit():
        return s
    m = re.search(r"(\d+)$", s)
    return m.group(1) if m else None


def load_active_exceptions(db_path=EXCEPTIONS_DB):
    """Return exception rows that are approved or under review.
    Skips expired/rejected/deleted. Returns list of dicts."""
    if not os.path.exists(db_path):
        return []
    con = duckdb.connect(db_path, read_only=True)
    try:
        rows = con.execute(
            """
            SELECT local_exception_id, console_exception_id, vuln_id, cve_id,
                   scope_type, scope_id, reason, comment, expires, state,
                   sync_status, bod_review_date
            FROM vulnerability_exceptions
            WHERE lower(state) IN ('approved', 'under review')
            """
        ).fetchall()
        cols = [d[0] for d in con.description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        con.close()


def _exception_matches(exc, finding):
    """Does this exception apply to this finding?"""
    # vuln_id / cve_id match — findings may carry either a Rapid7 vulnId or a CVE.
    f_vuln = str(finding.get("vuln_id") or finding.get("vulnId") or "").strip()
    f_cve = str(finding.get("cve_id") or finding.get("cve") or "").strip()
    e_vuln = str(exc.get("vuln_id") or "").strip()
    e_cve = str(exc.get("cve_id") or "").strip()

    id_match = (
        (e_vuln and e_vuln == f_vuln)
        or (e_cve and (e_cve == f_cve or e_cve == f_vuln))
        or (e_vuln and e_vuln == f_cve)
    )
    if not id_match:
        return False

    scope_type = (exc.get("scope_type") or "").strip().lower()
    if scope_type == "global":
        return True
    if scope_type == "asset":
        want = _console_asset_id(exc.get("scope_id"))
        have = _console_asset_id(finding.get("asset_id") or finding.get("assetId"))
        return want is not None and want == have
    # Site / Asset Group / Instance: without site/group membership data in the
    # findings, we conservatively match on vuln id + a provided scope id if present.
    if scope_type in ("site", "asset group", "instance"):
        want = _console_asset_id(exc.get("scope_id"))
        have = _console_asset_id(finding.get("asset_id") or finding.get("assetId"))
        # Only suppress when we can positively tie it to the same id; otherwise
        # leave the finding active to avoid over-suppression.
        return want is not None and want == have
    return False


def partition_findings(findings, db_path=EXCEPTIONS_DB):
    """Split findings into (active, excepted, pending_local_ids).

    active   : findings that remain in the BOD timeline/overdue math. Findings with
               an under-review exception are included here with exception_pending=True
               and exception_ref set.
    excepted : list of {"finding": <finding>, "exception": <exc>} for approved
               exceptions, for the report's Exceptions section.
    pending_local_ids : set of local_exception_id that matched an active finding
               (used by callers/annotation).
    """
    exceptions = load_active_exceptions(db_path)
    approved = [e for e in exceptions if (e.get("state") or "").lower() in SUPPRESSING_STATES]
    pending = [e for e in exceptions if (e.get("state") or "").lower() in PENDING_STATES]

    active = []
    excepted = []
    pending_ids = set()

    for finding in findings:
        # Approved exception suppresses the finding.
        matched_approved = next((e for e in approved if _exception_matches(e, finding)), None)
        if matched_approved is not None:
            excepted.append({"finding": finding, "exception": matched_approved})
            continue

        # Under-review exception annotates but keeps the finding active.
        matched_pending = next((e for e in pending if _exception_matches(e, finding)), None)
        if matched_pending is not None:
            f = dict(finding)
            f["exception_pending"] = True
            f["exception_ref"] = matched_pending.get("local_exception_id")
            pending_ids.add(matched_pending.get("local_exception_id"))
            active.append(f)
        else:
            active.append(finding)

    return active, excepted, pending_ids


def render_exceptions_section(excepted):
    """Return an HTML fragment listing excepted (approved) findings, or '' if none."""
    if not excepted:
        return ""
    rows = []
    for item in excepted:
        f = item["finding"]
        e = item["exception"]
        cve = f.get("cve_id") or f.get("cve") or f.get("vuln_id") or ""
        host = f.get("hostname") or f.get("host") or ""
        ip = f.get("ip") or ""
        reason = e.get("reason") or ""
        expires = e.get("expires")
        expires_s = "" if expires in (None, "") else str(expires).split(" ")[0]
        console_id = e.get("console_exception_id")
        sync = e.get("sync_status") or ""
        console_disp = f"#{console_id}" if console_id is not None else "(not synced)"
        rows.append(
            "<tr>"
            f"<td>{cve}</td><td>{host}</td><td>{ip}</td>"
            f"<td>{reason}</td><td>{expires_s}</td>"
            f"<td>{console_disp}</td><td>{sync}</td>"
            "</tr>"
        )
    return (
        '<h2>Exceptions (excluded from timeline &amp; overdue counts)</h2>\n'
        '<table>\n<thead><tr>'
        '<th>CVE / Vuln</th><th>Host</th><th>IP</th><th>Reason</th>'
        '<th>Expires</th><th>Console ID</th><th>Sync</th>'
        '</tr></thead>\n<tbody>\n' + "\n".join(rows) + '\n</tbody>\n</table>'
    )


def main(argv=None):
    p = argparse.ArgumentParser(description="Partition BOD findings against local exceptions (Task #5).")
    p.add_argument("--findings", help="Path to a JSON file: list of finding dicts. If omitted, prints active exceptions only.")
    p.add_argument("--db-path", default=EXCEPTIONS_DB)
    args = p.parse_args(argv)

    if not args.findings:
        exc = load_active_exceptions(args.db_path)
        print(f"Active exceptions (approved + under review): {len(exc)}")
        for e in exc:
            print(f"  {e['state']:<12} {e['vuln_id']:<34} scope={e['scope_type']}"
                  + (f"/{e['scope_id']}" if e['scope_id'] else "")
                  + f" console={e['console_exception_id']}")
        return 0

    with open(args.findings) as fh:
        findings = json.load(fh)
    active, excepted, pending_ids = partition_findings(findings, args.db_path)
    print(f"Input findings : {len(findings)}")
    print(f"Active (counted): {len(active)}  (of which pending-exception: {len(pending_ids)})")
    print(f"Excepted        : {len(excepted)}")
    if excepted:
        print("Excepted findings:")
        for item in excepted:
            f = item["finding"]; e = item["exception"]
            print(f"  {f.get('cve_id') or f.get('vuln_id')} on {f.get('hostname') or f.get('ip')}"
                  f" -> {e['reason']} (console #{e['console_exception_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
