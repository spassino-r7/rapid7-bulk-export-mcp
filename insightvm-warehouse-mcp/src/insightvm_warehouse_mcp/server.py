"""InsightVM Data Warehouse MCP Server.

Provides tools for querying the InsightVM data warehouse (PostgreSQL)
including assets, vulnerabilities, policies, and schema introspection.
"""

import json
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import db, queries, schema

# Create MCP server
mcp = FastMCP(
    "InsightVM Data Warehouse",
    instructions="Query the InsightVM Data Warehouse (PostgreSQL) for assets, vulnerabilities, and policy compliance data.",
)


def _serialize(obj: Any) -> Any:
    """JSON-serialize objects that aren't natively serializable."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


def _format_result(result: dict) -> str:
    """Format a query result dict as readable text."""
    if not result.get("rows"):
        return "No results returned."

    rows = result["rows"]
    row_count = result["row_count"]
    truncated = result.get("truncated", False)

    output = json.dumps(rows, indent=2, default=_serialize)

    footer = f"\n\n--- {row_count} row(s) returned"
    if truncated:
        footer += " (truncated — more rows available, increase limit)"
    footer += " ---"

    return output + footer


def _sanitize_sql(sql: str) -> str | None:
    """
    Validate and sanitize a SQL query string.

    Returns None if the query is safe, or an error message if rejected.
    """
    # Strip SQL comments (block and line) to prevent keyword hiding
    cleaned = re.sub(r'/\*.*?\*/', ' ', sql, flags=re.DOTALL)  # block comments
    cleaned = re.sub(r'--[^\n]*', ' ', cleaned)  # line comments

    # Block multiple statements (semicolons)
    if ';' in cleaned.strip().rstrip(';'):
        return "Error: Multiple statements (semicolons) are not allowed."

    # Normalize whitespace for keyword detection
    sql_upper = ' '.join(cleaned.upper().split())

    # Must start with SELECT or WITH (CTE)
    if not sql_upper.startswith("SELECT") and not sql_upper.startswith("WITH"):
        return "Error: Only SELECT and WITH (CTE) queries are allowed."

    # Block dangerous keywords using word boundary matching
    dangerous_keywords = [
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "TRUNCATE", "GRANT", "REVOKE", "COPY", "EXECUTE", "CALL",
        "DO", "SET", "RESET", "LOAD", "IMPORT",
    ]
    for kw in dangerous_keywords:
        # Match as a whole word (not inside identifiers/strings)
        if re.search(rf'\b{kw}\b', sql_upper):
            return f"Error: {kw} statements are not allowed. This is a read-only connection."

    return None


# --- Tools ---


@mcp.tool(
    annotations=ToolAnnotations(
        title="Query Data Warehouse",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def query_warehouse(sql: str, row_limit: int = 500) -> str:
    """
    Execute a read-only SQL query against the InsightVM data warehouse.

    The database is PostgreSQL and contains the InsightVM Reporting Data Model
    with dimension tables (dim_*) and fact tables (fact_*).

    Key tables:
    - dim_asset: Asset inventory (ip_address, host_name, operating_system_id)
    - dim_vulnerability: Vulnerability definitions (title, severity, cvss_score, exploits)
    - dim_policy: Policy benchmarks (DISA STIG, CIS)
    - dim_policy_rule: Individual policy rules
    - dim_site: Scan sites
    - dim_operating_system: OS details
    - fact_asset: Current asset risk/vuln summary
    - fact_asset_vulnerability_finding: Current vuln findings per asset
    - fact_asset_policy: Policy compliance per asset
    - fact_asset_vulnerability_age: Vulnerability age tracking

    Args:
        sql: SQL query to execute (read-only, SELECT statements only)
        row_limit: Maximum rows to return (default 500, max 5000)
    """
    # Validate SQL
    error = _sanitize_sql(sql)
    if error:
        return error

    if row_limit > 5000:
        row_limit = 5000

    try:
        result = db.execute_query(sql, row_limit=row_limit)
        return _format_result(result)
    except Exception as e:
        return f"Query error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Warehouse Schema",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_warehouse_schema(table_name: str = None, search: str = None) -> str:
    """
    Get schema information from the InsightVM data warehouse.

    With no arguments: returns all tables in the database.
    With table_name: returns column details for that table.
    With search: finds tables matching the search pattern.

    Args:
        table_name: Specific table to describe (e.g. 'dim_asset')
        search: Search pattern for table names (e.g. 'vuln', 'policy')
    """
    try:
        if table_name:
            result = schema.get_table_schema(table_name)
            if not result["rows"]:
                return f"Table '{table_name}' not found. Try searching with search parameter."
            header = f"Schema for: {table_name}\n{'=' * 40}\n"
            return header + _format_result(result)
        elif search:
            result = schema.search_tables(search)
            return _format_result(result)
        else:
            result = schema.get_all_tables()
            return _format_result(result)
    except Exception as e:
        return f"Schema query error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Search Columns",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def search_columns(pattern: str) -> str:
    """
    Search for columns matching a pattern across all tables.

    Useful for finding where specific data lives in the data model.

    Args:
        pattern: Column name pattern to search for (e.g. 'cvss', 'risk', 'hostname')
    """
    try:
        result = schema.search_columns(pattern)
        return _format_result(result)
    except Exception as e:
        return f"Column search error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Assets",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_assets(
    ip: str = None,
    hostname: str = None,
    os_family: str = None,
    site: str = None,
    limit: int = 100,
) -> str:
    """
    Query assets from the InsightVM data warehouse.

    Returns asset details including IP, hostname, OS, risk score, and vuln counts.

    Args:
        ip: Filter by IP address (partial match)
        hostname: Filter by hostname (case-insensitive partial match)
        os_family: Filter by OS family (e.g. 'Linux', 'Windows')
        site: Filter by site name (partial match)
        limit: Max results (default 100)
    """
    try:
        result = queries.get_assets(ip=ip, hostname=hostname, os_family=os_family, site=site, limit=limit)
        return _format_result(result)
    except Exception as e:
        return f"Asset query error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Vulnerabilities",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_vulnerabilities(
    severity: str = None,
    cve: str = None,
    asset_ip: str = None,
    asset_hostname: str = None,
    exploitable: bool = None,
    limit: int = 100,
) -> str:
    """
    Query vulnerability findings from the InsightVM data warehouse.

    Returns vulnerability details with asset context, sorted by CVSS score.

    Args:
        severity: Filter by severity (e.g. 'Critical', 'Severe', 'Moderate')
        cve: Filter by CVE ID or vulnerability title (partial match)
        asset_ip: Filter by asset IP (partial match)
        asset_hostname: Filter by asset hostname (partial match)
        exploitable: Filter to only exploitable vulns (True) or non-exploitable (False)
        limit: Max results (default 100)
    """
    try:
        result = queries.get_vulnerabilities(
            severity=severity, cve=cve, asset_ip=asset_ip,
            asset_hostname=asset_hostname, exploitable=exploitable, limit=limit
        )
        return _format_result(result)
    except Exception as e:
        return f"Vulnerability query error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Policies",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_policies(
    benchmark: str = None,
    status: str = None,
    asset_hostname: str = None,
    current_only: bool = True,
    limit: int = 100,
) -> str:
    """
    Query policy compliance data from the InsightVM data warehouse.

    Returns policy assessment results including pass/fail counts per asset.

    Args:
        benchmark: Filter by benchmark name (e.g. 'DISA STIG', 'CIS', 'Windows')
        status: Filter by compliance status
        asset_hostname: Filter by asset hostname (partial match)
        current_only: Exclude deprecated policies (default True)
        limit: Max results (default 100)
    """
    try:
        result = queries.get_policies(
            benchmark=benchmark, status=status,
            asset_hostname=asset_hostname, current_only=current_only, limit=limit
        )
        return _format_result(result)
    except Exception as e:
        return f"Policy query error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Warehouse Stats",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_warehouse_stats() -> str:
    """
    Get summary statistics from the InsightVM data warehouse.

    Returns high-level counts: total assets, vulnerabilities by severity,
    policy counts (DISA/CIS), and site count.
    """
    try:
        stats = queries.get_summary_stats()
        return json.dumps(stats, indent=2, default=_serialize)
    except Exception as e:
        return f"Stats query error: {str(e)}"


@mcp.tool(
    annotations=ToolAnnotations(
        title="Get Key Tables",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
)
def get_key_tables() -> str:
    """
    Get row counts for the key tables in the InsightVM data model.

    Useful for understanding data freshness and coverage.
    """
    try:
        results = schema.get_key_tables_summary()
        return json.dumps(results, indent=2, default=_serialize)
    except Exception as e:
        return f"Key tables query error: {str(e)}"


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
