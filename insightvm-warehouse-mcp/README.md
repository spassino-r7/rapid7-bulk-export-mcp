# InsightVM Data Warehouse MCP Server

An MCP server that connects directly to the InsightVM/Nexpose PostgreSQL Data Warehouse,
enabling AI assistants to query vulnerability, asset, policy, and remediation data instantly.

## Why This Exists

The Bulk Export MCP requires 3-10 minutes per export. This server connects directly to
the data warehouse for instant SQL queries against the full dimensional model (76 tables),
including historical trending data.

## Setup

### 1. Create a read-only database user

```sql
CREATE ROLE mcp_readonly WITH LOGIN PASSWORD 'your_secure_password'
  CONNECTION LIMIT 3;
GRANT CONNECT ON DATABASE nexpose_warehouse TO mcp_readonly;
GRANT USAGE ON SCHEMA public TO mcp_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT ON TABLES TO mcp_readonly;
```

### 2. Configure environment variables

```bash
export DW_HOST="insightvm-console.internal"
export DW_PORT="5432"
export DW_USER="mcp_readonly"
export DW_PASSWORD="your_secure_password"
export DW_DATABASE="nexpose_warehouse"
export DW_SSLMODE="require"  # optional, defaults to "prefer"
```

### 3. Install dependencies

```bash
cd insightvm-warehouse-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure in Kiro

Add to `~/.kiro/settings/mcp.json`:

```json
{
  "mcpServers": {
    "insightvm-warehouse": {
      "command": "/path/to/insightvm-warehouse-mcp/.venv/bin/python3",
      "args": ["/path/to/insightvm-warehouse-mcp/server.py"],
      "env": {
        "DW_HOST": "insightvm-console.internal",
        "DW_PORT": "5432",
        "DW_USER": "mcp_readonly",
        "DW_PASSWORD": "your_secure_password",
        "DW_DATABASE": "nexpose_warehouse",
        "DW_SSLMODE": "require"
      }
    }
  }
}
```

## Tools Provided

| Tool | Description |
|------|-------------|
| `query_warehouse` | Execute read-only SQL against the warehouse |
| `get_warehouse_schema` | List all tables and columns |
| `get_warehouse_stats` | Summary metrics (asset counts, vuln counts, last ETL) |
| `get_warehouse_tables` | List tables grouped by category (fact/dim) |
| `suggest_warehouse_query` | Get example queries for common use cases |

## Security

- Read-only PostgreSQL role (SELECT only)
- Connection limit enforced at DB level
- SSL/TLS for connections
- Credentials via environment variables (never in code)
- No write, update, or delete operations possible
