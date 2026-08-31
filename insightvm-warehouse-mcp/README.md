# InsightVM Data Warehouse MCP Server

An MCP (Model Context Protocol) server that connects to the Rapid7 InsightVM Data Warehouse (PostgreSQL) and exposes tools for querying assets, vulnerabilities, policy compliance, and schema metadata.

## Tools

| Tool | Description |
|------|-------------|
| `query_warehouse` | Execute arbitrary read-only SQL against the data warehouse |
| `get_warehouse_schema` | Get table listings or column details for a specific table |
| `search_columns` | Find columns matching a pattern across all tables |
| `get_assets` | Query assets with filters (IP, hostname, OS, site) |
| `get_vulnerabilities` | Query vulnerability findings with filters (severity, CVE, asset, exploitable) |
| `get_policies` | Query policy compliance data (DISA STIG, CIS benchmarks) |
| `get_warehouse_stats` | Summary statistics (asset count, vuln severity breakdown, policy counts) |
| `get_key_tables` | Row counts for key dimension and fact tables |

## Prerequisites

- Python 3.10+
- InsightVM Data Warehouse configured and exporting to PostgreSQL
- A read-only PostgreSQL user with access to the warehouse database
- macOS Keychain entry for the database password (or set via environment variable)

## Setup

### 1. Store password in macOS Keychain

```bash
security add-generic-password \
  -s "insightvm-warehouse" \
  -a "mcp_readonly" \
  -w "YOUR_PASSWORD_HERE"
```

### 2. Install

```bash
cd insightvm-warehouse-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Configure environment (optional)

Copy `.env.example` to `.env` and modify if your warehouse differs from defaults:

```bash
cp .env.example .env
```

Defaults:
- Host: `192.168.1.216`
- Port: `5432`
- Database: `dhouse`
- User: `mcp_readonly`
- Auth: macOS Keychain (`insightvm-warehouse` / `mcp_readonly`)

## MCP Configuration

Add to your Kiro MCP config (`.kiro/settings/mcp.json`):

```json
{
  "mcpServers": {
    "insightvm-warehouse": {
      "command": "/path/to/insightvm-warehouse-mcp/.venv/bin/python",
      "args": ["-m", "insightvm_warehouse_mcp.server"],
      "cwd": "/path/to/insightvm-warehouse-mcp",
      "env": {
        "PYTHONPATH": "/path/to/insightvm-warehouse-mcp/src"
      }
    }
  }
}
```

Or if using environment-based auth instead of Keychain:

```json
{
  "mcpServers": {
    "insightvm-warehouse": {
      "command": "/path/to/insightvm-warehouse-mcp/.venv/bin/python",
      "args": ["-m", "insightvm_warehouse_mcp.server"],
      "cwd": "/path/to/insightvm-warehouse-mcp",
      "env": {
        "PYTHONPATH": "/path/to/insightvm-warehouse-mcp/src",
        "IVM_DW_AUTH_METHOD": "env",
        "IVM_DW_PASSWORD": "your_password"
      }
    }
  }
}
```

## Example Usage

Once configured, you can ask questions like:

- "Show me all assets with critical vulnerabilities"
- "What DISA STIG policies are available for RHEL 8?"
- "Query the warehouse for the top 10 riskiest assets"
- "What columns are in the dim_vulnerability table?"
- "How many assets are being scanned?"

### Direct SQL examples via `query_warehouse`:

```sql
-- Top 10 riskiest assets
SELECT da.host_name, da.ip_address, fa.risk_score, fa.critical_vulnerabilities
FROM dim_asset da
JOIN fact_asset fa ON da.asset_id = fa.asset_id
ORDER BY fa.risk_score DESC
LIMIT 10

-- DISA STIG policies (current, non-deprecated)
SELECT title, policy_id
FROM dim_policy
WHERE title LIKE 'DISA STIG%' AND title NOT LIKE '%(deprecated)%'
ORDER BY title

-- Vulnerability age analysis
SELECT dv.title, dv.severity, dv.cvss_v3_score, favf.date AS first_found
FROM fact_asset_vulnerability_finding favf
JOIN dim_vulnerability dv ON favf.vulnerability_id = dv.vulnerability_id
WHERE dv.severity = 'Critical'
ORDER BY favf.date ASC
LIMIT 20
```

## Data Model

The InsightVM Data Warehouse uses a dimensional model:

**Key Dimension Tables:**
- `dim_asset` — Asset inventory (IP, hostname, OS, risk modifier)
- `dim_vulnerability` — Vulnerability definitions (title, severity, CVSS, exploits)
- `dim_policy` — Policy benchmarks (DISA STIG, CIS)
- `dim_policy_rule` — Individual policy check rules
- `dim_site` — Scan sites
- `dim_scan` — Scan history

**Key Fact Tables:**
- `fact_asset` — Current asset risk/vuln summary
- `fact_asset_vulnerability_finding` — Active vulnerability findings per asset
- `fact_asset_policy` — Policy compliance results per asset
- `fact_asset_date` — Historical asset snapshots (date-partitioned)

Use the `get_warehouse_schema` and `search_columns` tools to explore the full schema interactively.

## Safety

- All connections are read-only (enforced at session level)
- Only SELECT/WITH statements are allowed
- Statement timeout: 30 seconds (configurable)
- Row limit: 500 default, 5000 max
- No credentials stored in code — Keychain or env vars only

## License

MIT
