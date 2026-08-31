#!/usr/bin/env python3
"""
Task #2 — Create the vulnerability_exceptions table.

The Rapid7 bulk-export DuckDB (rapid7_bulk_export.db) is attached read-only by the
MCP server and is fully rewritten on each daily export, so exception records cannot
live there. This script provisions a separate, writable DuckDB (bod_exceptions.db)
that holds the exceptions table defined in exception-process-design.md.

Idempotent: safe to run repeatedly. Uses CREATE TABLE IF NOT EXISTS so it never
clobbers existing exception rows.
"""

import os
import duckdb

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bod_exceptions.db")

DDL = """
CREATE TABLE IF NOT EXISTS vulnerability_exceptions (
    local_exception_id     VARCHAR PRIMARY KEY,
    console_exception_id   INTEGER,
    vuln_id                VARCHAR NOT NULL,
    cve_id                 VARCHAR,
    scope_type             VARCHAR NOT NULL,
    scope_id               VARCHAR,
    scope_key              VARCHAR,
    port                   INTEGER,
    reason                 VARCHAR NOT NULL,
    comment                VARCHAR,
    expires                TIMESTAMP,
    submitted_by           VARCHAR,
    state                  VARCHAR NOT NULL DEFAULT 'Under Review',
    sync_status            VARCHAR NOT NULL DEFAULT 'pending',
    bod_original_timeline  VARCHAR,
    bod_review_date        DATE,
    created_at             TIMESTAMP NOT NULL DEFAULT now(),
    updated_at             TIMESTAMP NOT NULL DEFAULT now()
);
"""

# Index to speed up report joins on vuln/scope, and reconciliation on console id.
INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_vex_vuln ON vulnerability_exceptions(vuln_id);",
    "CREATE INDEX IF NOT EXISTS idx_vex_scope ON vulnerability_exceptions(scope_type, scope_id);",
    "CREATE INDEX IF NOT EXISTS idx_vex_console ON vulnerability_exceptions(console_exception_id);",
    "CREATE INDEX IF NOT EXISTS idx_vex_sync ON vulnerability_exceptions(sync_status);",
]


def main():
    con = duckdb.connect(DB_PATH)
    try:
        con.execute(DDL)
        for stmt in INDEXES:
            con.execute(stmt)

        cols = con.execute(
            """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'vulnerability_exceptions'
            ORDER BY ordinal_position
            """
        ).fetchall()
        row_count = con.execute(
            "SELECT count(*) FROM vulnerability_exceptions"
        ).fetchone()[0]
    finally:
        con.close()

    print(f"Database: {DB_PATH}")
    print(f"Table 'vulnerability_exceptions' ready. Existing rows: {row_count}")
    print(f"Columns ({len(cols)}):")
    for name, dtype in cols:
        print(f"  - {name}: {dtype}")


if __name__ == "__main__":
    main()
