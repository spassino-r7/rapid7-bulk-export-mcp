#!/usr/bin/env python3
"""
Task #4 — Push local exceptions to the InsightVM console via API v3.

Reads rows from bod_exceptions.db with sync_status='pending', submits each to
POST /api/3/vulnerability_exceptions on the console, and on a confirmed 2xx stores
the returned console exception id and flips sync_status to 'synced'. Submit-only:
we do not call a separate approval step (the console may auto-approve based on the
API user's rights, and we record whatever state it returns via reconciliation).

Auth: the console password is read from the macOS Keychain, matching the pattern
used elsewhere in this repo (build_cve_map.py):
    security find-generic-password -s insightvm-console-api -a apiUser -w
An INSIGHTVM_PASSWORD env var is honored as a fallback. No secrets are stored in code.

Console contract (verified against the live ivmcon API):
  - reason / state / scope.type are LOWERCASE (e.g. "acceptable risk", "asset group").
  - Response body `id` is the console exception id.
  - Asset scope needs the console integer asset id; the bulk-export assetId
    (e.g. "8bd28bcb-...-default-asset-154") ends in that integer, which we extract.

Usage:
    # Preview what would be sent, without calling the API:
    python3 sync_exceptions.py --dry-run

    # Sync all pending rows:
    python3 sync_exceptions.py

    # Sync a single row:
    python3 sync_exceptions.py --local-id <uuid>
"""

import os
import re
import sys
import json
import argparse
import subprocess
from datetime import datetime, timezone

import duckdb

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    print("ERROR: this script requires the 'requests' package.", file=sys.stderr)
    raise

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEPTIONS_DB = os.path.join(BASE_DIR, "bod_exceptions.db")

DEFAULT_CONSOLE = os.environ.get("INSIGHTVM_CONSOLE", "https://ivmcon:3780")
KEYCHAIN_SERVICE = "insightvm-console-api"
DEFAULT_USER = "apiUser"

# Map our stored (design-doc, Title Case) enums to the API's lowercase values.
REASON_TO_API = {
    "False Positive": "false positive",
    "Compensating Control": "compensating control",
    "Acceptable Use": "acceptable use",
    "Acceptable Risk": "acceptable risk",
    "Other": "other",
}
SCOPE_TYPE_TO_API = {
    "Global": "global",
    "Site": "site",
    "Asset": "asset",
    "Asset Group": "asset group",
    "Instance": "instance",
}


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def get_console_password(user):
    """Read the console password from Keychain, with an env-var fallback."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", user, "-w"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    env_pw = os.environ.get("INSIGHTVM_PASSWORD", "")
    if env_pw:
        return env_pw
    raise SystemExit(
        f"ERROR: no console password found in Keychain "
        f"(service={KEYCHAIN_SERVICE!r}, account={user!r}) or INSIGHTVM_PASSWORD env."
    )


def make_session(user, password):
    s = requests.Session()
    s.verify = False
    s.auth = (user, password)
    s.headers.update({"Content-Type": "application/json", "Accept": "application/json"})
    return s


# ---------------------------------------------------------------------------
# Scope / payload mapping
# ---------------------------------------------------------------------------

def resolve_asset_scope_id(scope_id):
    """The bulk-export assetId ends with the console integer asset id
    (e.g. '...-default-asset-154' -> 154). If scope_id is already an integer
    string, use it as-is."""
    if scope_id is None:
        return None
    s = str(scope_id).strip()
    if s.isdigit():
        return int(s)
    m = re.search(r"(\d+)$", s)
    if m:
        return int(m.group(1))
    raise ValueError(f"could not resolve a console asset id from scope_id {scope_id!r}")


def build_payload(row):
    """Map a DuckDB exception row (dict) to the v3 request body."""
    reason_api = REASON_TO_API.get(row["reason"])
    if reason_api is None:
        raise ValueError(f"unknown reason {row['reason']!r}")
    scope_api = SCOPE_TYPE_TO_API.get(row["scope_type"])
    if scope_api is None:
        raise ValueError(f"unknown scope_type {row['scope_type']!r}")

    scope = {"type": scope_api, "vulnerability": row["vuln_id"]}
    if row["scope_type"] != "Global":
        if scope_api == "asset":
            scope["id"] = resolve_asset_scope_id(row["scope_id"])
        else:
            sid = str(row["scope_id"]).strip()
            scope["id"] = int(sid) if sid.isdigit() else sid
        if row.get("scope_key"):
            scope["key"] = row["scope_key"]
        if row.get("port") is not None:
            scope["port"] = row["port"]

    submit = {"reason": reason_api, "comment": row.get("comment") or ""}

    payload = {"scope": scope, "state": "under review", "submit": submit}

    expires = row.get("expires")
    if expires is not None:
        if isinstance(expires, datetime):
            payload["expires"] = expires.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z") \
                if expires.tzinfo is None else expires.isoformat()
        else:
            payload["expires"] = str(expires)
    return payload


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def fetch_pending(con, local_id=None):
    if local_id:
        q = "SELECT * FROM vulnerability_exceptions WHERE local_exception_id = ? AND sync_status = 'pending'"
        rows = con.execute(q, [local_id]).fetchall()
    else:
        q = "SELECT * FROM vulnerability_exceptions WHERE sync_status = 'pending' ORDER BY created_at"
        rows = con.execute(q).fetchall()
    cols = [d[0] for d in con.description]
    return [dict(zip(cols, r)) for r in rows]


def mark_synced(con, local_id, console_id):
    con.execute(
        """UPDATE vulnerability_exceptions
           SET console_exception_id = ?, sync_status = 'synced', updated_at = ?
           WHERE local_exception_id = ?""",
        [console_id, datetime.now(timezone.utc).replace(tzinfo=None), local_id],
    )


def mark_failed(con, local_id):
    con.execute(
        """UPDATE vulnerability_exceptions
           SET sync_status = 'failed', updated_at = ?
           WHERE local_exception_id = ?""",
        [datetime.now(timezone.utc).replace(tzinfo=None), local_id],
    )


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------

def parse_console_id(resp):
    """Extract the created exception id from a POST response (body id or Location link)."""
    try:
        body = resp.json()
        if isinstance(body, dict):
            if isinstance(body.get("id"), int):
                return body["id"]
            for link in body.get("links", []):
                if link.get("rel") == "self" and "href" in link:
                    m = re.search(r"/vulnerability_exceptions/(\d+)", link["href"])
                    if m:
                        return int(m.group(1))
    except Exception:
        pass
    loc = resp.headers.get("Location", "")
    m = re.search(r"/vulnerability_exceptions/(\d+)", loc)
    return int(m.group(1)) if m else None


def sync(local_id=None, dry_run=False, console=DEFAULT_CONSOLE, user=DEFAULT_USER):
    con = duckdb.connect(EXCEPTIONS_DB)
    try:
        pending = fetch_pending(con, local_id)
        if not pending:
            print("No pending exceptions to sync.")
            return 0

        print(f"{len(pending)} pending exception(s) to sync -> {console}")

        session = None
        if not dry_run:
            password = get_console_password(user)
            session = make_session(user, password)

        ok = fail = 0
        for row in pending:
            lid = row["local_exception_id"]
            try:
                payload = build_payload(row)
            except ValueError as e:
                print(f"  [SKIP] {lid}: {e}")
                fail += 1
                continue

            if dry_run:
                print(f"  [DRY-RUN] {lid} ({row['vuln_id']}):")
                print("            POST /api/3/vulnerability_exceptions")
                print("            " + json.dumps(payload))
                continue

            try:
                resp = session.post(
                    f"{console}/api/3/vulnerability_exceptions",
                    json=payload, timeout=30,
                )
            except requests.RequestException as e:
                print(f"  [FAIL] {lid}: request error {e}")
                mark_failed(con, lid)
                fail += 1
                continue

            if resp.status_code in (200, 201):
                console_id = parse_console_id(resp)
                if console_id is None:
                    print(f"  [FAIL] {lid}: 2xx but no console id in response")
                    mark_failed(con, lid)
                    fail += 1
                    continue
                mark_synced(con, lid, console_id)
                print(f"  [OK]   {lid} -> console id {console_id} ({row['vuln_id']})")
                ok += 1
            else:
                body = resp.text[:300].replace("\n", " ")
                print(f"  [FAIL] {lid}: HTTP {resp.status_code} {body}")
                mark_failed(con, lid)
                fail += 1

        if not dry_run:
            print(f"Done. synced={ok} failed={fail}")
        return 0 if fail == 0 else 1
    finally:
        con.close()


def main(argv=None):
    p = argparse.ArgumentParser(description="Sync pending local exceptions to the InsightVM console (Task #4).")
    p.add_argument("--dry-run", action="store_true", help="Print the exact request(s) without calling the API")
    p.add_argument("--local-id", help="Sync only this local_exception_id")
    p.add_argument("--console", default=DEFAULT_CONSOLE, help="Console base URL (default https://ivmcon:3780)")
    p.add_argument("--user", default=DEFAULT_USER, help="Console API username (default apiUser)")
    args = p.parse_args(argv)
    return sync(local_id=args.local_id, dry_run=args.dry_run, console=args.console, user=args.user)


if __name__ == "__main__":
    raise SystemExit(main())
