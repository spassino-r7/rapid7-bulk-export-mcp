"""Pre-built query templates for common InsightVM data warehouse queries."""

from .db import execute_query


def get_assets(
    ip: str = None,
    hostname: str = None,
    os_family: str = None,
    site: str = None,
    limit: int = 100,
) -> dict:
    """Query assets with optional filters."""
    conditions = []
    params = []

    if ip:
        conditions.append("da.ip_address::text LIKE %s")
        params.append(f"%{ip}%")
    if hostname:
        conditions.append("da.host_name ILIKE %s")
        params.append(f"%{hostname}%")
    if os_family:
        conditions.append("da.os_family ILIKE %s")
        params.append(f"%{os_family}%")
    if site:
        conditions.append("da.sites ILIKE %s")
        params.append(f"%{site}%")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    sql = f"""
        SELECT
            da.asset_id,
            da.ip_address,
            da.host_name,
            da.mac_address,
            da.os_description,
            da.os_family,
            da.os_name,
            da.os_version,
            da.sites,
            fa.risk_score,
            fa.vulnerabilities AS vuln_count,
            fa.critical_vulnerabilities,
            fa.severe_vulnerabilities,
            fa.moderate_vulnerabilities
        FROM dim_asset da
        LEFT JOIN fact_asset fa ON da.asset_id = fa.asset_id
        {where_clause}
        ORDER BY fa.risk_score DESC NULLS LAST
        LIMIT {limit}
    """
    return execute_query(sql, params=tuple(params) if params else None, row_limit=limit)


def get_vulnerabilities(
    severity: str = None,
    cve: str = None,
    asset_ip: str = None,
    asset_hostname: str = None,
    exploitable: bool = None,
    limit: int = 100,
) -> dict:
    """Query vulnerability findings with optional filters."""
    conditions = []
    params = []

    if severity:
        conditions.append("dv.severity ILIKE %s")
        params.append(f"%{severity}%")
    if cve:
        conditions.append("dv.nexpose_id ILIKE %s OR dv.title ILIKE %s")
        params.append(f"%{cve}%")
        params.append(f"%{cve}%")
    if asset_ip:
        conditions.append("da.ip_address::text LIKE %s")
        params.append(f"%{asset_ip}%")
    if asset_hostname:
        conditions.append("da.host_name ILIKE %s")
        params.append(f"%{asset_hostname}%")
    if exploitable is not None:
        conditions.append("dv.exploits > 0" if exploitable else "dv.exploits = 0")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    sql = f"""
        SELECT
            da.ip_address,
            da.host_name,
            dv.nexpose_id AS vuln_id,
            dv.title,
            dv.severity,
            dv.cvss_score,
            dv.cvss_v3_score,
            dv.exploits,
            dv.date_published,
            favf.date AS first_found
        FROM fact_asset_vulnerability_finding favf
        JOIN dim_asset da ON favf.asset_id = da.asset_id
        JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
        {where_clause}
        ORDER BY dv.cvss_v3_score DESC NULLS LAST, dv.cvss_score DESC NULLS LAST
        LIMIT {limit}
    """
    return execute_query(sql, params=tuple(params) if params else None, row_limit=limit)


def get_policies(
    benchmark: str = None,
    status: str = None,
    asset_hostname: str = None,
    current_only: bool = True,
    limit: int = 100,
) -> dict:
    """Query policy compliance data with optional filters."""
    conditions = []
    params = []

    if benchmark:
        conditions.append("dp.title ILIKE %s")
        params.append(f"%{benchmark}%")
    if current_only:
        conditions.append("dp.title NOT LIKE '%%(deprecated)%%'")
    if status:
        # Filter by rule_compliance percentage (e.g., "pass" -> >= 1.0, "fail" -> < 1.0)
        if status.lower() in ("pass", "compliant"):
            conditions.append("fap.rule_compliance = 1.0")
        elif status.lower() in ("fail", "noncompliant"):
            conditions.append("fap.rule_compliance < 1.0")
    if asset_hostname:
        conditions.append("da.host_name ILIKE %s")
        params.append(f"%{asset_hostname}%")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    sql = f"""
        SELECT
            dp.title AS policy_title,
            dp.policy_id,
            da.host_name,
            da.ip_address,
            fap.rule_compliance,
            fap.compliant_rules,
            fap.noncompliant_rules,
            fap.not_applicable_rules,
            fap.date_tested
        FROM fact_asset_policy fap
        JOIN dim_policy dp ON fap.policy_id = dp.policy_id
        JOIN dim_asset da ON fap.asset_id = da.asset_id
        {where_clause}
        ORDER BY dp.title, da.host_name
        LIMIT {limit}
    """
    return execute_query(sql, params=tuple(params) if params else None, row_limit=limit)


def get_summary_stats() -> dict:
    """Get high-level summary statistics from the data warehouse."""
    stats = {}

    # Asset count
    result = execute_query("SELECT COUNT(*) as total FROM dim_asset", row_limit=1)
    stats["total_assets"] = result["rows"][0]["total"] if result["rows"] else 0

    # Vulnerability counts by severity
    result = execute_query("""
        SELECT
            dv.severity,
            COUNT(DISTINCT dv.vulnerability_id) AS unique_vulns,
            COUNT(*) AS total_findings
        FROM fact_asset_vulnerability_finding favf
        JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
        GROUP BY dv.severity
        ORDER BY dv.severity
    """, row_limit=20)
    stats["vulnerabilities_by_severity"] = result["rows"]

    # Policy count
    result = execute_query("""
        SELECT
            COUNT(*) FILTER (WHERE title LIKE 'DISA STIG%%' AND title NOT LIKE '%%(deprecated)%%') AS disa_current,
            COUNT(*) FILTER (WHERE title LIKE 'CIS%%' AND title NOT LIKE '%%(deprecated)%%') AS cis_current,
            COUNT(*) AS total_policies
        FROM dim_policy
    """, row_limit=1)
    stats["policies"] = result["rows"][0] if result["rows"] else {}

    # Sites
    result = execute_query("SELECT COUNT(*) as total FROM dim_site", row_limit=1)
    stats["total_sites"] = result["rows"][0]["total"] if result["rows"] else 0

    return stats
