#!/usr/bin/env python3
"""
Daily Rapid7 Vulnerability Bulk Export

Runs as a cron job to:
1. Start a vulnerability export via Rapid7 GraphQL API
2. Poll until complete
3. Download Parquet files
4. Load into DuckDB

Requires environment variables:
  RAPID7_API_KEY  - Your Rapid7 Insight Platform API key
  RAPID7_REGION   - Region (us, us2, us3, eu, ca, au, ap). Defaults to 'us'.

Usage:
  python3 /Users/spassino/anothertry/daily_vuln_export.py
"""

import json
import os
import sys
import tempfile
import time
from datetime import datetime

# Add the MCP server source to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "rapid7-bulk-export-mcp"))

from src.config import load_config
from src.download import download_all_files
from src.duckdb_loader import VulnerabilityDatabase
from src.export_manager import create_vulnerability_export, poll_until_complete

# Where to store the DuckDB database
DB_PATH = os.path.join(os.path.dirname(__file__), "rapid7_bulk_export.db")
LOG_FILE = os.path.join(os.path.dirname(__file__), "daily_vuln_export.log")

POLL_INTERVAL = 30  # seconds between status checks


def log(message: str):
    """Log a timestamped message to both stderr and the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line, file=sys.stderr)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def main():
    log("=== Daily Rapid7 Vulnerability Export Starting ===")

    # Step 1: Load configuration
    try:
        config = load_config()
        log(f"Configuration loaded (region: {config['region']})")
    except ValueError as e:
        log(f"ERROR: Configuration failed: {e}")
        sys.exit(1)

    # Step 2: Start the export
    try:
        export_id = create_vulnerability_export(config)
        log(f"Export started: {export_id}")
    except Exception as e:
        log(f"ERROR: Failed to start export: {e}")
        sys.exit(1)

    # Step 3: Poll until complete
    try:
        parquet_urls = poll_until_complete(config, export_id, interval=POLL_INTERVAL)
        log(f"Export complete: {len(parquet_urls)} file(s) ready")
    except ValueError as e:
        log(f"ERROR: Export failed: {e}")
        sys.exit(1)

    # Step 4: Download Parquet files
    try:
        file_contents = download_all_files(parquet_urls, config["api_key"])
        log(f"Downloaded {len(file_contents)} file(s)")
    except Exception as e:
        log(f"ERROR: Download failed: {e}")
        sys.exit(1)

    # Step 5: Save to temp files and load into DuckDB
    try:
        temp_paths = []
        for i, content in enumerate(file_contents):
            tmp = tempfile.NamedTemporaryFile(suffix=".parquet", delete=False)
            tmp.write(content)
            tmp.close()
            temp_paths.append(tmp.name)

        db = VulnerabilityDatabase(db_path=DB_PATH)
        total_rows = db.load_parquet_files(temp_paths)
        stats = db.get_stats()
        db.close()

        log(f"Loaded {total_rows} rows into {DB_PATH}")
        log(f"Stats: {json.dumps(stats, indent=2, default=str)}")

        # Cleanup temp files
        for path in temp_paths:
            os.unlink(path)

    except Exception as e:
        log(f"ERROR: DuckDB load failed: {e}")
        sys.exit(1)

    log("=== Daily Rapid7 Vulnerability Export Complete ===")


if __name__ == "__main__":
    main()
