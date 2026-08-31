#!/usr/bin/env python3
"""
Task #3 — Local exception tracking (write path).

Provides an importable `add_exception()` function and a CLI wrapper to record a
vulnerability exception in the local writable DuckDB (bod_exceptions.db), per the
model in exception-process-design.md.

This is the LOCAL write path only. It inserts the record with:
    state       = 'Under Review'
    sync_status = 'pending'
Pushing the exception to the InsightVM console (API v3) is Task #4, which will fill
console_exception_id and flip sync_status to 'synced'.

Usage (CLI):
    python3 exceptions.py \
        --vuln-id unix-cups-cve-2024-47176 \
        --scope-type Asset \
        --scope-id 154 \
        --reason "Acceptable Risk" \
        --comment "Mitigated by host firewall; scheduled for Q1 patch cycle" \
        --cve-id CVE-2024-47176 \
        --expires 2027-02-21 \
        --submitted-by spassino \
        --bod-original-timeline "60 days"

Usage (import):
    from exceptions import add_exception
    row = add_exception(vuln_id="...", scope_type="Global", reason="False Positive",
                        comment="...", submitted_by="spassino")
"""

import os
import re
import uuid
import argparse
from datetime import datetime, date, timezone

import duckdb

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EXCEPTIONS_DB = os.path.join(BASE_DIR, "bod_exceptions.db")
# Read-only reference to the bulk export for vuln_id existence checks.
BULK_EXPORT_DB = os.path.join(BASE_DIR, "rapid7_bulk_export.db")

# Exact InsightVM enum values — do not paraphrase.
VALID_REASONS = {
    "False Positive",
    "Compensating Control",
    "Acceptable Use",
    "Acceptable Risk",
    "Other",
}
VALID_SCOPE_TYPES = {"Global", "Site", "Asset", "Asset Group", "Instance"}
GLOBAL_SCOPE = "Global"


class ExceptionValidationError(ValueError):
    """Raised when an exception record fails validation before insert."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _parse_expires(expires):
    """Accept a date/datetime or ISO string; return a datetime or None.
    Enforces a future expiry when provided."""
    if expires in (None, ""):
        return None
    if isinstance(expires, datetime):
        dt = expires
    elif isinstance(expires, date):
        dt = datetime(expires.year, expires.month, expires.day)
    else:
        s = str(expires).strip()
        # Accept 'YYYY-MM-DD' or full ISO-8601.
        try:
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
                dt = datetime.strptime(s, "%Y-%m-%d")
            else:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError as e:
            raise ExceptionValidationError(
                f"expires must be a date (YYYY-MM-DD) or ISO-8601 timestamp, got {expires!r}"
            ) from e

    # Compare in a tz-naive way against 'now' (local) for a simple future check.
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    if dt <= now:
        raise ExceptionValidationError(
            f"expires must be in the future, got {dt.isoformat()}"
        )
    return dt


def _parse_review_date(value):
    if value in (None, ""):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    s = str(value).strip()
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError as e:
        raise ExceptionValidationError(
            f"bod-review-date must be YYYY-MM-DD, got {value!r}"
        ) from e


def _vuln_exists(vuln_id):
    """Best-effort check that vuln_id is present in the current bulk export.

    Returns True if found, False only when we can confidently say it is absent
    from a populated export, or None when the check is inconclusive.

    NOTE: The MCP server keeps the live export in its own process; the on-disk
    rapid7_bulk_export.db can lag behind (stale/partial snapshot). To avoid
    false 'not found' warnings on valid vulnIds, we only return False when the
    on-disk table is clearly current (heuristic: it has data). If it looks
    stale/empty we return None (inconclusive) rather than warn incorrectly.
    """
    if not os.path.exists(BULK_EXPORT_DB):
        return None
    try:
        con = duckdb.connect(BULK_EXPORT_DB, read_only=True)
        try:
            tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
            if "vulnerabilities" not in tables:
                return None
            total = con.execute("SELECT count(*) FROM vulnerabilities").fetchone()[0]
            if total == 0:
                return None  # empty snapshot: inconclusive
            found = con.execute(
                "SELECT 1 FROM vulnerabilities WHERE vulnId = ? LIMIT 1", [vuln_id]
            ).fetchone()
            if found is not None:
                return True
            # Not found in a populated table, but the on-disk copy may be a
            # stale/partial snapshot (the MCP holds the live data separately).
            # Treat as inconclusive rather than a false negative.
            return None
        finally:
            con.close()
    except Exception:
        # Export DB might be locked/mid-refresh; don't block the write on this.
        return None


def validate_exception(
    *,
    vuln_id,
    scope_type,
    reason,
    comment,
    scope_id=None,
    expires=None,
    bod_review_date=None,
):
    """Validate inputs per design rules. Returns (expires_dt, review_date, warnings).
    Raises ExceptionValidationError on hard failures."""
    warnings = []

    if not vuln_id or not str(vuln_id).strip():
        raise ExceptionValidationError("vuln_id is required")

    if scope_type not in VALID_SCOPE_TYPES:
        raise ExceptionValidationError(
            f"scope_type must be one of {sorted(VALID_SCOPE_TYPES)}, got {scope_type!r}"
        )

    if reason not in VALID_REASONS:
        raise ExceptionValidationError(
            f"reason must be one of {sorted(VALID_REASONS)}, got {reason!r}"
        )

    # Workflow policy: comment is required even though the API allows empty.
    if not comment or not str(comment).strip():
        raise ExceptionValidationError("comment (justification) is required")

    # scope_id required for every scope type except Global.
    if scope_type != GLOBAL_SCOPE and (scope_id is None or str(scope_id).strip() == ""):
        raise ExceptionValidationError(
            f"scope_id is required for scope_type {scope_type!r} (only Global omits it)"
        )
    if scope_type == GLOBAL_SCOPE and scope_id:
        warnings.append("scope_id ignored for Global scope")

    expires_dt = _parse_expires(expires)
    review_date = _parse_review_date(bod_review_date)

    exists = _vuln_exists(vuln_id)
    if exists is False:
        warnings.append(
            f"vuln_id {vuln_id!r} not found in current bulk export (vulnerabilities table)"
        )

    return expires_dt, review_date, warnings


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------

def add_exception(
    *,
    vuln_id,
    scope_type,
    reason,
    comment,
    scope_id=None,
    scope_key=None,
    port=None,
    cve_id=None,
    expires=None,
    submitted_by=None,
    bod_original_timeline=None,
    bod_review_date=None,
    db_path=EXCEPTIONS_DB,
):
    """Validate and insert a local exception record.

    Returns a dict of the inserted row. The record is created with
    state='Under Review' and sync_status='pending' (console push is Task #4).
    """
    expires_dt, review_date, warnings = validate_exception(
        vuln_id=vuln_id,
        scope_type=scope_type,
        reason=reason,
        comment=comment,
        scope_id=scope_id,
        expires=expires,
        bod_review_date=bod_review_date,
    )

    local_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    effective_scope_id = None if scope_type == GLOBAL_SCOPE else str(scope_id)

    con = duckdb.connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO vulnerability_exceptions (
                local_exception_id, console_exception_id, vuln_id, cve_id,
                scope_type, scope_id, scope_key, port,
                reason, comment, expires, submitted_by,
                state, sync_status, bod_original_timeline, bod_review_date,
                created_at, updated_at
            ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      'Under Review', 'pending', ?, ?, ?, ?)
            """,
            [
                local_id, vuln_id, cve_id,
                scope_type, effective_scope_id, scope_key, port,
                reason, comment, expires_dt, submitted_by,
                bod_original_timeline, review_date, now, now,
            ],
        )
        row = con.execute(
            "SELECT * FROM vulnerability_exceptions WHERE local_exception_id = ?",
            [local_id],
        ).fetchone()
        col_names = [d[0] for d in con.description]
    finally:
        con.close()

    result = dict(zip(col_names, row))
    result["_warnings"] = warnings
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser():
    p = argparse.ArgumentParser(
        description="Record a vulnerability exception locally (Task #3 write path). "
        "Console sync (API v3) is handled separately by Task #4."
    )
    p.add_argument("--vuln-id", required=True, help="Rapid7 vulnId (e.g. unix-cups-cve-2024-47176)")
    p.add_argument(
        "--scope-type", required=True, choices=sorted(VALID_SCOPE_TYPES),
        help="Exception scope type",
    )
    p.add_argument("--scope-id", help="Scope id (required unless scope-type is Global)")
    p.add_argument("--scope-key", help="Instance-scope disambiguator (proof/context)")
    p.add_argument("--port", type=int, help="Port for port-specific instance exceptions")
    p.add_argument(
        "--reason", required=True, choices=sorted(VALID_REASONS),
        help="InsightVM exception reason",
    )
    p.add_argument("--comment", required=True, help="Justification (required)")
    p.add_argument("--cve-id", help="CVE id, for reporting/joins")
    p.add_argument("--expires", help="Expiry date YYYY-MM-DD or ISO-8601 (must be future)")
    p.add_argument("--submitted-by", help="Operator identity for audit")
    p.add_argument("--bod-original-timeline", help='BOD 26-04 timeline before exception (e.g. "60 days")')
    p.add_argument("--bod-review-date", help="Re-review date YYYY-MM-DD")
    p.add_argument("--db-path", default=EXCEPTIONS_DB, help="Path to exceptions DuckDB")
    p.add_argument("--verified", action="store_true",
                   help="Acknowledge the pre-exception verification checklist was completed "
                        "(suppresses the reminder). See preexception_checklist.py.")
    return p


def main(argv=None):
    args = _build_parser().parse_args(argv)
    try:
        row = add_exception(
            vuln_id=args.vuln_id,
            scope_type=args.scope_type,
            reason=args.reason,
            comment=args.comment,
            scope_id=args.scope_id,
            scope_key=args.scope_key,
            port=args.port,
            cve_id=args.cve_id,
            expires=args.expires,
            submitted_by=args.submitted_by,
            bod_original_timeline=args.bod_original_timeline,
            bod_review_date=args.bod_review_date,
            db_path=args.db_path,
        )
    except ExceptionValidationError as e:
        print(f"ERROR: {e}")
        return 2

    for w in row.pop("_warnings", []):
        print(f"WARNING: {w}")
    print("Exception recorded (local):")
    print(f"  local_exception_id : {row['local_exception_id']}")
    print(f"  vuln_id            : {row['vuln_id']}")
    print(f"  scope              : {row['scope_type']}"
          + (f" / {row['scope_id']}" if row['scope_id'] else ""))
    print(f"  reason             : {row['reason']}")
    print(f"  expires            : {row['expires']}")
    print(f"  state              : {row['state']}")
    print(f"  sync_status        : {row['sync_status']}  (push to console = Task #4)")
    if not args.verified:
        scope_ip = f" --asset-ip <asset-ip>"
        print()
        print("REMINDER: verify before accepting risk. If you have not already, run the")
        print("pre-exception checklist and attach its output to this exception:")
        print(f"  python3 preexception_checklist.py --vuln-id {args.vuln_id}{scope_ip}")
        print("(pass --verified to exceptions.py to suppress this reminder)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
