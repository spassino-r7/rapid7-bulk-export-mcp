#!/usr/bin/env python3
"""
InsightVM Data Warehouse MCP Server

Connects directly to the InsightVM/Nexpose PostgreSQL Data Warehouse
and exposes read-only SQL query capabilities via MCP.
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

import psycopg2
import psycopg2.extras
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

# Initialize FastMCP server
mcp = FastMCP("insightvm-warehouse")

# Global connection
_conn: Optional[psycopg2.extensions.connection] = None


def get_connection() -> psycopg2.extensions.connection:
    """Get or create a database connection."""
    global _conn

    if _conn is not None and not _conn.closed:
        return _conn

    host = os.environ.get("DW_HOST", "localhost")
    port = os.environ.get("DW_PORT", "5432")
    user = os.environ.get("DW_USER", "mcp_readonly")
    password = os.environ.get("DW_PASSWORD", "")
    database = os.environ.get("DW_DATABASE", "nexpose_warehouse")
    sslmode = os.environ.get("DW_SSLMODE", "prefer")
    password_file = os.environ.get("DW_PASSWORD_FILE", "")
    keychain_service = os.environ.get("DW_KEYCHAIN_SERVICE", "insightvm-warehouse")
    keychain_account = os.environ.get("DW_KEYCHAIN_ACCOUNT", "mcp_readonly")

    # Priority 1: DW_PASSWORD env var
    # Priority 2: DW_PASSWORD_FILE
    if not password and password_file:
        try:
            password = Path(password_file).read_text().strip()
        except Exception as e:
            raise ValueError(f"Could not read password from {password_file}: {e}")

    # Priority 3: macOS Keychain
    if not password:
        try:
            import subprocess
            result = subprocess.run(
                ["security", "find-generic-password",
                 "-s", keychain_service,
                 "-a", keychain_account,
                 "-w"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                password = result.stdout.strip()
        except Exception:
            pass

    if not password:
        raise ValueError(
            "Database password not found. Set one of:\n"
            "  1. DW_PASSWORD environment variable\n"
            "  2. DW_PASSWORD_FILE pointing to a password file\n"
            "  3. macOS Keychain: security add-generic-password "
            f'-s "{keychain_service}" -a "{keychain_account}" -w "PASSWORD"'
        )

    _conn = psycopg2.connect(
        host=host,
        port=int(port),
        user=user,
        password=password,
        dbname=database,
        sslmode=sslmode,
        options="-c statement_timeout=30000",  # 30s query timeout
    )
    _conn.set_session(readonly=True, autocommit=True)
    print(f"Connected to warehouse: {host}:{port}/{database}", file=sys.stderr)
    return _conn


def execute_query(sql: str, max_rows: int = 500) -> list[dict]:
    """Execute a read-only SQL query and return results as list of dicts."""
    conn = get_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql)
        if cur.description is None:
            return []
        rows = cur.fetchmany(max_rows)
        return [dict(row) for row in rows]


@mcp.tool(
    annotations=ToolAnnotations(
        title="Query InsightVM Warehouse",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def query_warehouse(sql: str) -> str:
    """Execute a read-only SQL query against the InsightVM Data Warehouse.

    The warehouse uses a dimensional model with fact and dimension tables.
    Key tables for vulnerability reporting:

    **Core Facts:**
    - fact_asset — current asset state (vuln counts, risk score, PCI status)
    - fact_asset_date — daily asset snapshots for trending
    - fact_asset_vulnerability_finding — one row per vuln per asset (the workhorse)
    - fact_asset_vulnerability_instance — instance-level detail (port, proof, service)
    - fact_asset_vulnerability_finding_remediation — solution impact per vuln per asset
    - fact_asset_vulnerability_remediation_date — tracks when vulns were remediated
    - fact_scan — scan summary (asset count, vuln counts)
    - fact_site / fact_site_date — site-level rollups
    - fact_asset_group / fact_asset_group_date — group-level rollups
    - fact_asset_policy / fact_asset_policy_rule — policy compliance

    **Core Dimensions:**
    - dim_asset — asset metadata (IP, hostname, OS, risk modifier)
    - dim_vulnerability — vuln metadata (title, severity, CVSS, exploits)
    - dim_solution — remediation steps (patch name, type, URL, fix text)
    - dim_site — site info (name, scan engine, template)
    - dim_tag — tags (criticality, owner, location, custom)
    - dim_scan — scan history (start, finish, status)
    - dim_asset_group — asset group definitions

    **Utility:**
    - periods — ETL export dates (when warehouse was refreshed)

    Examples:
    - SELECT * FROM fact_asset ORDER BY risk_score DESC LIMIT 10
    - SELECT severity, COUNT(*) FROM dim_vulnerability GROUP BY severity
    - SELECT MAX(day) FROM periods

    Args:
        sql: SQL query (SELECT only, 30s timeout, max 500 rows returned)

    Returns:
        Query results as JSON
    """
    # Basic safety check — only allow SELECT/WITH statements
    stripped = sql.strip().upper()
    if not (stripped.startswith("SELECT") or stripped.startswith("WITH")):
        return "✗ Only SELECT queries are allowed. The warehouse connection is read-only."

    try:
        results = execute_query(sql)
        result_text = json.dumps(results, indent=2, default=str)
        return f"Query executed successfully. {len(results)} rows returned.\n\n{result_text}"
    except psycopg2.Error as e:
        return f"✗ Database error: {e.pgerror or str(e)}"
    except Exception as e:
        return f"✗ Error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Warehouse Schema",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_warehouse_schema(table_name: str = "") -> str:
    """Get the schema of warehouse tables.

    Returns column names and data types. If table_name is provided,
    returns schema for that specific table. Otherwise returns a summary
    of all tables.

    Args:
        table_name: Optional specific table name (e.g., 'dim_asset', 'fact_asset')

    Returns:
        Table schema information as formatted text
    """
    try:
        if table_name:
            sql = """
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = %s
                ORDER BY ordinal_position
            """
            conn = get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (table_name,))
                columns = [dict(row) for row in cur.fetchall()]

            if not columns:
                return f"✗ Table '{table_name}' not found in the warehouse."

            result = f"Schema for: {table_name}\n"
            result += f"{'Column':<40} {'Type':<25} {'Nullable'}\n"
            result += "-" * 75 + "\n"
            for col in columns:
                result += f"{col['column_name']:<40} {col['data_type']:<25} {col['is_nullable']}\n"
            return result
        else:
            sql = """
                SELECT table_name, COUNT(*) as column_count
                FROM information_schema.columns
                WHERE table_schema = 'public'
                GROUP BY table_name
                ORDER BY table_name
            """
            results = execute_query(sql)
            result_text = json.dumps(results, indent=2, default=str)
            return f"Warehouse tables ({len(results)} total):\n\n{result_text}"

    except Exception as e:
        return f"✗ Error getting schema: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Warehouse Statistics",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_warehouse_stats() -> str:
    """Get summary statistics from the InsightVM Data Warehouse.

    Returns key metrics including:
    - Total assets, vulnerabilities, and sites
    - Severity distribution
    - Last ETL refresh date
    - Risk score summary
    - Scan coverage

    Returns:
        Summary statistics as formatted JSON
    """
    try:
        stats = {}

        # Last ETL date
        result = execute_query("SELECT MAX(day) as last_etl FROM periods")
        stats["last_etl_date"] = result[0]["last_etl"] if result else None

        # Asset summary from fact_asset
        result = execute_query("""
            SELECT
                COUNT(*) as total_assets,
                SUM(vulnerabilities) as total_vuln_findings,
                SUM(critical_vulnerabilities) as critical,
                SUM(severe_vulnerabilities) as severe,
                SUM(moderate_vulnerabilities) as moderate,
                SUM(exploits) as total_exploits,
                ROUND(AVG(risk_score)::numeric, 2) as avg_risk_score,
                MAX(risk_score) as max_risk_score
            FROM fact_asset
        """)
        if result:
            stats["assets"] = result[0]

        # Site count
        result = execute_query("SELECT COUNT(*) as total_sites FROM dim_site")
        if result:
            stats["total_sites"] = result[0]["total_sites"]

        # Scan info
        result = execute_query("""
            SELECT COUNT(*) as total_scans,
                   MAX(finished) as last_scan_completed
            FROM dim_scan
            WHERE status = 'Successful'
        """)
        if result:
            stats["scans"] = result[0]

        # Vulnerability catalog size
        result = execute_query("""
            SELECT COUNT(*) as total_vulns_in_catalog,
                   SUM(CASE WHEN exploits > 0 THEN 1 ELSE 0 END) as with_exploits
            FROM dim_vulnerability
        """)
        if result:
            stats["vulnerability_catalog"] = result[0]

        # PCI status
        result = execute_query("""
            SELECT pci_status, COUNT(*) as asset_count
            FROM fact_asset
            GROUP BY pci_status
        """)
        if result:
            stats["pci_compliance"] = {r["pci_status"]: r["asset_count"] for r in result}

        return f"Warehouse Statistics:\n\n{json.dumps(stats, indent=2, default=str)}"

    except Exception as e:
        return f"✗ Error getting statistics: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Warehouse Tables",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_warehouse_tables() -> str:
    """List all warehouse tables grouped by category.

    Returns tables organized into:
    - Fact tables (measured data, metrics)
    - Dimension tables (context, metadata)
    - Utility tables (ETL tracking)

    Returns:
        Categorized table listing
    """
    try:
        results = execute_query("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
            ORDER BY table_name
        """)

        facts = []
        dims = []
        other = []

        for row in results:
            name = row["table_name"]
            if name.startswith("fact_"):
                facts.append(name)
            elif name.startswith("dim_"):
                dims.append(name)
            else:
                other.append(name)

        output = f"InsightVM Data Warehouse — {len(results)} tables\n\n"
        output += f"═══ Fact Tables ({len(facts)}) ═══\n"
        for t in facts:
            output += f"  • {t}\n"
        output += f"\n═══ Dimension Tables ({len(dims)}) ═══\n"
        for t in dims:
            output += f"  • {t}\n"
        output += f"\n═══ Utility Tables ({len(other)}) ═══\n"
        for t in other:
            output += f"  • {t}\n"

        return output

    except Exception as e:
        return f"✗ Error listing tables: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Suggest Warehouse Query",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def suggest_warehouse_query(use_case: str = "") -> str:
    """Get example SQL queries for common vulnerability reporting use cases.

    Provides ready-to-run queries for the InsightVM dimensional warehouse.

    Args:
        use_case: Optional description of what you want to report on

    Returns:
        Example SQL queries with descriptions
    """
    queries = """
═══ Vulnerability Age & SLA Tracking ═══

-- Criticals older than 30 days (SLA breach)
SELECT da.host_name, da.ip_address, dv.title, dv.severity,
       favf.date AS first_found,
       CURRENT_DATE - favf.date::date AS age_days
FROM fact_asset_vulnerability_finding favf
JOIN dim_asset da ON da.asset_id = favf.asset_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = favf.vulnerability_id
WHERE dv.severity = 'Critical'
  AND CURRENT_DATE - favf.date::date > 30
ORDER BY age_days DESC;

═══ Top 10 Riskiest Assets ═══

SELECT da.host_name, da.ip_address, da.os_description,
       fa.risk_score, fa.vulnerabilities, fa.critical_vulnerabilities,
       fa.exploits
FROM fact_asset fa
JOIN dim_asset da ON da.asset_id = fa.asset_id
ORDER BY fa.risk_score DESC
LIMIT 10;

═══ Remediation Impact — Best Patches to Apply ═══

SELECT ds.summary AS solution, ds.solution_type,
       COUNT(DISTINCT fr.asset_id) AS assets_fixed,
       COUNT(DISTINCT fr.vulnerability_id) AS vulns_fixed,
       SUM(fr.risk_score) AS total_risk_reduced
FROM fact_asset_vulnerability_finding_remediation fr
JOIN dim_solution ds ON ds.solution_id = fr.solution_id
GROUP BY ds.summary, ds.solution_type
ORDER BY total_risk_reduced DESC
LIMIT 15;

═══ Risk Trend Over Time (last 30 days) ═══

SELECT day, assets, vulnerabilities, critical_vulnerabilities,
       risk_score
FROM fact_all_date
WHERE day >= CURRENT_DATE - INTERVAL '30 days'
ORDER BY day;

═══ Exploitable Vulnerabilities ═══

SELECT da.host_name, da.ip_address, dv.title, dv.cvss_score,
       dve.title AS exploit_name, dve.skill_level, dve.source
FROM fact_asset_vulnerability_finding_exploit fex
JOIN dim_asset da ON da.asset_id = fex.asset_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = fex.vulnerability_id
JOIN dim_vulnerability_exploit dve ON dve.exploit_id = fex.exploit_id
ORDER BY dv.cvss_score DESC
LIMIT 20;

═══ Scan Coverage — Assets Not Scanned in 14+ Days ═══

SELECT da.host_name, da.ip_address, da.os_description,
       da.last_assessed_for_vulnerabilities
FROM dim_asset da
WHERE da.last_assessed_for_vulnerabilities < CURRENT_TIMESTAMP - INTERVAL '14 days'
ORDER BY da.last_assessed_for_vulnerabilities ASC;

═══ Policy Compliance Summary ═══

SELECT dp.title AS policy_name,
       fp.compliant_assets, fp.noncompliant_assets, fp.total_assets,
       ROUND(fp.asset_compliance * 100, 1) AS compliance_pct
FROM fact_policy fp
JOIN dim_policy dp ON dp.policy_id = fp.policy_id
ORDER BY fp.asset_compliance ASC;

═══ Vulnerability Remediation Rate (last 7 days) ═══

SELECT day, COUNT(*) AS vulns_remediated
FROM fact_asset_vulnerability_remediation_date
WHERE day >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY day
ORDER BY day;

═══ Assets by Tag (Criticality) ═══

SELECT dt.name AS tag_name, dt.type AS tag_type,
       ft.assets, ft.critical_vulnerabilities, ft.risk_score
FROM fact_tag ft
JOIN dim_tag dt ON dt.tag_id = ft.tag_id
WHERE dt.type = 'CRITICALITY'
ORDER BY ft.risk_score DESC;

═══ Reintroduced Vulnerabilities (regression) ═══

SELECT da.host_name, dv.title, dv.severity,
       favf.date AS original_found,
       favf.reintroduced_date
FROM fact_asset_vulnerability_finding favf
JOIN dim_asset da ON da.asset_id = favf.asset_id
JOIN dim_vulnerability dv ON dv.vulnerability_id = favf.vulnerability_id
WHERE favf.reintroduced_date IS NOT NULL
ORDER BY favf.reintroduced_date DESC
LIMIT 20;
"""

    if use_case:
        return f"Suggested queries for: {use_case}\n\n{queries}"
    return queries


def main():
    """Entry point for the MCP server."""
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
        print("InsightVM Data Warehouse MCP Server")
        print()
        print("Connects to the InsightVM/Nexpose PostgreSQL Data Warehouse")
        print("and exposes read-only SQL query capabilities via MCP.")
        print()
        print("Environment Variables (required):")
        print("  DW_HOST       Warehouse hostname or IP")
        print("  DW_PORT       PostgreSQL port (default: 5432)")
        print("  DW_USER       Database username (should be read-only)")
        print("  DW_PASSWORD   Database password")
        print("  DW_DATABASE   Database name (default: nexpose_warehouse)")
        print("  DW_SSLMODE    SSL mode: disable, prefer, require (default: prefer)")
        print()
        print("Security:")
        print("  - Only SELECT queries are permitted")
        print("  - Connection is set to read-only mode")
        print("  - 30-second query timeout enforced")
        print("  - Max 500 rows returned per query")
        print()
        print("Usage:")
        print("  Configure in ~/.kiro/settings/mcp.json")
        print("  See README.md for full setup instructions.")
        sys.exit(0)

    # Validate required env vars early
    required_vars = ["DW_HOST"]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        print(f"Error: Missing required environment variables: {', '.join(missing)}", file=sys.stderr)
        print("Set these in your mcp.json env block or shell environment.", file=sys.stderr)
        sys.exit(1)

    if not os.environ.get("DW_PASSWORD") and not os.environ.get("DW_PASSWORD_FILE"):
        print("Error: Either DW_PASSWORD or DW_PASSWORD_FILE must be set.", file=sys.stderr)
        sys.exit(1)

    # Test connection on startup
    try:
        get_connection()
        print("Warehouse connection verified.", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Could not connect to warehouse: {e}", file=sys.stderr)
        print("Connection will be retried on first query.", file=sys.stderr)

    # Run the MCP server
    mcp.run()


if __name__ == "__main__":
    main()
