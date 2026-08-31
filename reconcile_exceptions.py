#!/usr/bin/env python3
"""
Task #6 — Sync failure handling & reconciliation.

Two jobs, both safe to run repeatedly:

  1. RETRY failed syncs
     Re-POST rows with sync_status='failed' (same submit path as sync_exceptions).
     On 2xx -> sync_status='synced' + console id; otherwise they stay 'failed'.

  2. RECONCILE drift (pull console -> local)
     For rows that have a console_exception_id, GET the console exception and
     bring the local record into agreement:
       - console state differs from local -> update local `state` (mapped to our
         Title Case), so the report reflects reality (e.g. approved/expired/rejected).
       - console returns 404 (deleted/revoked in console) -> local state='Deleted'
         so apply_exceptions.py stops suppressing/annotating it.
       - local expiry passed but console still active -> report only (console owns expiry).

Auth, session, and payload construction are reused from sync_exceptions.py.

Usage:
    python3 reconcile_exceptions.py --dry-run      # report actions, no writes/calls that change state
    python3 reconcile_exceptions.py                # retry failed + reconcile drift
    python3 reconcile_exceptions.py --retry-only
    python3 reconcile_exceptions.py --reconcile-only
"""

import os
import sys
import argparse
from datetime import datetime, timezone

import duckdb

import sync_exceptions as sx  # reuse auth/session/payload/console-id helpers

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEPTIONS_DB = sx.EXCEPTIONS_DB

# Map the console's lowercase state back to our stored Title Case.
API_STATE_TO_LOCAL = {
    "under review": "Under Review",
    "approved": "Approved",
    "rejected": "Rejected",
    "deleted": "Deleted",
    "expired": "Expired",
}


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Retry failed
# ---------------------------------------------------------------------------

def retry_failed(con, session, dry_run):
    rows = con.execute(
        "SELECT * FROM vulnerability_exceptions WHERE sync_status = 'failed' ORDER BY created_at"
    ).fetchall()
    cols = [d[0] for d in con.description]
    failed = [dict(zip(cols, r)) for r in rows]

    if not failed:
        print("Retry: no failed rows.")
        return 0, 0

    print(f"Retry: {len(failed)} failed row(s).")
    ok = still_failed = 0
    for row in failed:
        lid = row["local_exception_id"]
        try:
            payload = sx.build_payload(row)
        except ValueError as e:
            print(f"  [SKIP] {lid}: {e}")
            still_failed += 1
            continue

        if dry_run:
            print(f"  [DRY-RUN] would re-POST {lid} ({row['vuln_id']})")
            continue

        try:
            resp = session.post(
                f"{sx.DEFAULT_CONSOLE}/api/3/vulnerability_exceptions",
                json=payload, timeout=30,
            )
        except Exception as e:
            print(f"  [FAIL] {lid}: request error {e}")
            still_failed += 1
            continue

        if resp.status_code in (200, 201):
            console_id = sx.parse_console_id(resp)
            if console_id is None:
                print(f"  [FAIL] {lid}: 2xx but no console id")
                still_failed += 1
                continue
            con.execute(
                "UPDATE vulnerability_exceptions SET console_exception_id=?, sync_status='synced', updated_at=? WHERE local_exception_id=?",
                [console_id, _now(), lid],
            )
            print(f"  [OK]   {lid} -> console id {console_id}")
            ok += 1
        else:
            print(f"  [FAIL] {lid}: HTTP {resp.status_code} {resp.text[:200]}")
            still_failed += 1

    return ok, still_failed


# ---------------------------------------------------------------------------
# Reconcile drift
# ---------------------------------------------------------------------------

def reconcile_drift(con, session, dry_run):
    rows = con.execute(
        "SELECT * FROM vulnerability_exceptions WHERE console_exception_id IS NOT NULL"
    ).fetchall()
    cols = [d[0] for d in con.description]
    synced = [dict(zip(cols, r)) for r in rows]

    if not synced:
        print("Reconcile: no rows with a console id.")
        return 0

    print(f"Reconcile: checking {len(synced)} console-linked row(s).")
    changes = 0
    for row in synced:
        lid = row["local_exception_id"]
        cid = row["console_exception_id"]
        local_state = (row.get("state") or "").strip()

        try:
            resp = session.get(
                f"{sx.DEFAULT_CONSOLE}/api/3/vulnerability_exceptions/{cid}", timeout=30
            )
        except Exception as e:
            print(f"  [WARN] {lid} (console #{cid}): GET error {e}")
            continue

        if resp.status_code == 404:
            # Deleted/revoked in console.
            if local_state.lower() == "deleted":
                continue
            print(f"  [DRIFT] {lid} (console #{cid}): 404 in console -> local state 'Deleted'")
            if not dry_run:
                con.execute(
                    "UPDATE vulnerability_exceptions SET state='Deleted', updated_at=? WHERE local_exception_id=?",
                    [_now(), lid],
                )
            changes += 1
            continue

        if resp.status_code != 200:
            print(f"  [WARN] {lid} (console #{cid}): HTTP {resp.status_code}")
            continue

        body = resp.json()
        console_state_raw = (body.get("state") or "").strip().lower()
        mapped = API_STATE_TO_LOCAL.get(console_state_raw)
        if mapped is None:
            print(f"  [WARN] {lid} (console #{cid}): unknown console state {console_state_raw!r}")
            continue

        # Expiry note: console owns expiry; if local expiry passed but console still active, report.
        expires = row.get("expires")
        if expires is not None and console_state_raw in ("approved", "under review"):
            try:
                exp_dt = expires if isinstance(expires, datetime) else datetime.fromisoformat(str(expires))
                if exp_dt <= _now():
                    print(f"  [NOTE] {lid} (console #{cid}): local expiry {exp_dt.date()} passed but console still {console_state_raw}")
            except Exception:
                pass

        if mapped != local_state:
            print(f"  [DRIFT] {lid} (console #{cid}): state {local_state!r} -> {mapped!r}")
            if not dry_run:
                con.execute(
                    "UPDATE vulnerability_exceptions SET state=?, updated_at=? WHERE local_exception_id=?",
                    [mapped, _now(), lid],
                )
            changes += 1

    return changes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(description="Retry failed syncs and reconcile console/local drift (Task #6).")
    p.add_argument("--dry-run", action="store_true", help="Report actions without changing local or console state")
    p.add_argument("--retry-only", action="store_true", help="Only retry failed rows")
    p.add_argument("--reconcile-only", action="store_true", help="Only reconcile drift")
    p.add_argument("--console", default=sx.DEFAULT_CONSOLE)
    p.add_argument("--user", default=sx.DEFAULT_USER)
    args = p.parse_args(argv)

    # Point the reused module at the requested console/user.
    sx.DEFAULT_CONSOLE = args.console

    do_retry = not args.reconcile_only
    do_reconcile = not args.retry_only

    con = duckdb.connect(EXCEPTIONS_DB)
    try:
        # A session is needed for any live call (retry POST or reconcile GET).
        need_session = (do_retry or do_reconcile)
        session = None
        if need_session and not args.dry_run:
            password = sx.get_console_password(args.user)
            session = sx.make_session(args.user, password)
        elif need_session and args.dry_run and do_reconcile:
            # Reconcile needs GETs even in dry-run to detect drift (read-only, no state change).
            password = sx.get_console_password(args.user)
            session = sx.make_session(args.user, password)

        if do_retry:
            ok, sf = retry_failed(con, session, args.dry_run)
            print(f"Retry summary: resynced={ok} still_failed={sf}")
        if do_reconcile:
            changes = reconcile_drift(con, session, args.dry_run)
            print(f"Reconcile summary: {'would change' if args.dry_run else 'changed'} {changes} row(s)")
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
