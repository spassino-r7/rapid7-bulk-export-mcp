"""Database connection management for InsightVM Data Warehouse."""

import os
import subprocess
import sys

import psycopg2
import psycopg2.extras

# Defaults (override via environment variables)
DEFAULT_HOST = "192.168.1.216"
DEFAULT_PORT = 5432
DEFAULT_DB = "dhouse"
DEFAULT_USER = "mcp_readonly"
DEFAULT_KEYCHAIN_SERVICE = "insightvm-warehouse"
DEFAULT_KEYCHAIN_ACCOUNT = "mcp_readonly"
DEFAULT_STATEMENT_TIMEOUT = 30000  # ms
DEFAULT_ROW_LIMIT = 500


def get_config():
    """Load connection config from environment variables with defaults."""
    return {
        "host": os.environ.get("IVM_DW_HOST", DEFAULT_HOST),
        "port": int(os.environ.get("IVM_DW_PORT", DEFAULT_PORT)),
        "dbname": os.environ.get("IVM_DW_DB", DEFAULT_DB),
        "user": os.environ.get("IVM_DW_USER", DEFAULT_USER),
        "auth_method": os.environ.get("IVM_DW_AUTH_METHOD", "keychain"),
        "keychain_service": os.environ.get("IVM_DW_KEYCHAIN_SERVICE", DEFAULT_KEYCHAIN_SERVICE),
        "keychain_account": os.environ.get("IVM_DW_KEYCHAIN_ACCOUNT", DEFAULT_KEYCHAIN_ACCOUNT),
        "password": os.environ.get("IVM_DW_PASSWORD", ""),
        "statement_timeout": int(os.environ.get("IVM_DW_STATEMENT_TIMEOUT", DEFAULT_STATEMENT_TIMEOUT)),
        "row_limit": int(os.environ.get("IVM_DW_ROW_LIMIT", DEFAULT_ROW_LIMIT)),
    }


def get_password(config: dict) -> str:
    """Retrieve password from macOS Keychain or environment variable."""
    if config["auth_method"] == "keychain":
        try:
            result = subprocess.run(
                [
                    "security", "find-generic-password",
                    "-s", config["keychain_service"],
                    "-a", config["keychain_account"],
                    "-w",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Keychain lookup failed for service='{config['keychain_service']}' "
                    f"account='{config['keychain_account']}': {result.stderr.strip()}"
                )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError("Keychain lookup timed out")
    elif config["auth_method"] == "env":
        pw = config["password"]
        if not pw:
            raise RuntimeError("IVM_DW_PASSWORD environment variable not set")
        return pw
    else:
        raise RuntimeError(f"Unknown auth method: {config['auth_method']}")


def get_connection(config: dict = None):
    """Create a read-only PostgreSQL connection to the data warehouse."""
    if config is None:
        config = get_config()

    password = get_password(config)

    conn = psycopg2.connect(
        host=config["host"],
        port=config["port"],
        dbname=config["dbname"],
        user=config["user"],
        password=password,
        connect_timeout=10,
        options=f"-c statement_timeout={config['statement_timeout']}",
    )
    # Set read-only at session level for safety
    conn.set_session(readonly=True, autocommit=True)
    return conn


def execute_query(sql: str, params: tuple = None, row_limit: int = None, config: dict = None) -> dict:
    """
    Execute a read-only SQL query and return results as a dict.

    Returns:
        {
            "columns": ["col1", "col2", ...],
            "rows": [{"col1": val, "col2": val}, ...],
            "row_count": int,
            "truncated": bool
        }
    """
    if config is None:
        config = get_config()

    if row_limit is None:
        row_limit = config["row_limit"]

    conn = get_connection(config)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params)

        columns = [desc[0] for desc in cur.description] if cur.description else []

        rows = cur.fetchmany(row_limit + 1)
        truncated = len(rows) > row_limit
        if truncated:
            rows = rows[:row_limit]

        # Convert to plain dicts (RealDictRow -> dict) for JSON serialization
        rows = [dict(row) for row in rows]

        return {
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "truncated": truncated,
        }
    finally:
        conn.close()
