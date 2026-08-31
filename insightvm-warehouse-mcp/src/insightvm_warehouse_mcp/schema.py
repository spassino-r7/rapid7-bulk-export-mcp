"""Schema introspection helpers for the InsightVM Data Warehouse."""

from .db import execute_query

# Key tables in the InsightVM reporting data model
KEY_TABLES = [
    # Dimensions
    "dim_asset",
    "dim_asset_group",
    "dim_asset_group_asset",
    "dim_host",
    "dim_operating_system",
    "dim_policy",
    "dim_policy_rule",
    "dim_scan",
    "dim_site",
    "dim_site_asset",
    "dim_software",
    "dim_tag",
    "dim_asset_tag",
    "dim_vulnerability",
    # Facts
    "fact_asset",
    "fact_asset_date",
    "fact_asset_policy",
    "fact_asset_vulnerability_age",
    "fact_asset_vulnerability_finding",
    "fact_asset_vulnerability_instance",
]


def get_all_tables() -> dict:
    """Return all tables/views in the public schema."""
    sql = """
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = 'public'
        ORDER BY table_name
    """
    return execute_query(sql, row_limit=1000)


def get_table_schema(table_name: str) -> dict:
    """Return column details for a specific table."""
    sql = """
        SELECT
            column_name,
            data_type,
            is_nullable,
            column_default,
            character_maximum_length
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        ORDER BY ordinal_position
    """
    return execute_query(sql, params=(table_name,), row_limit=500)


def get_key_tables_summary() -> dict:
    """Return row counts for key tables in the data model."""
    results = {}
    for table in KEY_TABLES:
        try:
            sql = f"SELECT COUNT(*) as row_count FROM {table}"
            result = execute_query(sql, row_limit=1)
            if result["rows"]:
                results[table] = result["rows"][0]["row_count"]
        except Exception as e:
            results[table] = f"error: {str(e)}"
    return results


def search_tables(pattern: str) -> dict:
    """Search for tables matching a pattern."""
    sql = """
        SELECT table_name, table_type
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name ILIKE %s
        ORDER BY table_name
    """
    return execute_query(sql, params=(f"%{pattern}%",), row_limit=200)


def search_columns(pattern: str) -> dict:
    """Search for columns matching a pattern across all tables."""
    sql = """
        SELECT table_name, column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND column_name ILIKE %s
        ORDER BY table_name, column_name
    """
    return execute_query(sql, params=(f"%{pattern}%",), row_limit=200)
