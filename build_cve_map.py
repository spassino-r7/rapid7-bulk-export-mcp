#!/usr/bin/env python3
"""
Build CVE-to-Module map by enriching the Metasploit module cache.

Iterates through all cached exploit modules and fetches CVE references
from the Metasploit Pro API (module.info calls). Populates the
cve_module_map table in the DuckDB cache.

Usage:
    python3 build_cve_map.py
"""

import json
import sys
import time
from datetime import datetime

import duckdb
import httpx
import msgpack

# Config
MSF_HOST = "https://192.168.1.244:3790"
CACHE_DB = "metasploit-exploit-mapper/metasploit_module_cache.db"

# Get API token from keychain
import subprocess
result = subprocess.run(
    ["security", "find-generic-password", "-s", "metasploit-pro-api", "-a", "api-token", "-w"],
    capture_output=True, text=True, timeout=5
)
if result.returncode != 0:
    # Try env var
    import os
    MSF_TOKEN = os.environ.get("MSF_API_TOKEN", "")
    if not MSF_TOKEN:
        print("ERROR: No API token found in Keychain or env", file=sys.stderr)
        sys.exit(1)
else:
    MSF_TOKEN = result.stdout.strip()


def rpc_call(client, method, *args):
    payload = msgpack.packb([method, MSF_TOKEN, *args])
    resp = client.post(
        f"{MSF_HOST}/api/1.0",
        content=payload,
        headers={"Content-Type": "binary/message-pack"},
    )
    resp.raise_for_status()
    return msgpack.unpackb(resp.content, raw=False, strict_map_key=False)


def decode_value(v):
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    elif isinstance(v, dict):
        return {decode_value(k): decode_value(val) for k, val in v.items()}
    elif isinstance(v, list):
        return [decode_value(item) for item in v]
    return v


def extract_cves(references):
    cves = []
    for ref in references:
        if isinstance(ref, list) and len(ref) >= 2:
            rtype = ref[0] if isinstance(ref[0], str) else ref[0].decode() if isinstance(ref[0], bytes) else ""
            rval = ref[1] if isinstance(ref[1], str) else ref[1].decode() if isinstance(ref[1], bytes) else ""
            if rtype.upper() == "CVE":
                cves.append(f"CVE-{rval}")
        elif isinstance(ref, str) and ref.upper().startswith("CVE-"):
            cves.append(ref.upper())
    return cves


def main():
    # Get all exploit module paths from cache
    db = duckdb.connect(CACHE_DB)
    modules = db.execute(
        "SELECT module_path FROM module_cache WHERE module_type = 'exploit'"
    ).fetchall()
    db.close()

    total = len(modules)
    print(f"Total exploit modules to enrich: {total}")

    client = httpx.Client(verify=False, timeout=30.0)

    enriched = 0
    cve_mappings_added = 0
    errors = 0
    batch = []
    batch_size = 50

    for i, (path,) in enumerate(modules):
        # Strip type prefix for info call
        info_path = path
        if path.startswith("exploit/"):
            info_path = path[len("exploit/"):]

        try:
            result = rpc_call(client, "module.info", "exploit", info_path)
            if isinstance(result, dict):
                result = decode_value(result)
                refs = result.get("references", [])
                cves = extract_cves(refs)

                if cves:
                    for cve in cves:
                        batch.append((cve, path))
                    enriched += 1
                    cve_mappings_added += len(cves)

        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  Error on {path}: {e}", file=sys.stderr)

        # Progress
        if (i + 1) % 100 == 0:
            # Flush batch to DB
            if batch:
                db = duckdb.connect(CACHE_DB)
                for cve_id, mod_path in batch:
                    db.execute(
                        "INSERT OR IGNORE INTO cve_module_map (cve_id, module_path) VALUES (?, ?)",
                        [cve_id, mod_path]
                    )
                db.close()
                batch = []

            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            eta = (total - i - 1) / rate if rate > 0 else 0
            print(f"  [{i+1}/{total}] enriched={enriched} cves={cve_mappings_added} errors={errors} ({rate:.1f}/s, ETA {eta:.0f}s)")

        # Small delay to not overwhelm the API
        time.sleep(0.05)

    # Final batch flush
    if batch:
        db = duckdb.connect(CACHE_DB)
        for cve_id, mod_path in batch:
            db.execute(
                "INSERT OR IGNORE INTO cve_module_map (cve_id, module_path) VALUES (?, ?)",
                [cve_id, mod_path]
            )
        db.close()

    client.close()

    print(f"\nDone!")
    print(f"  Modules enriched with CVEs: {enriched}/{total}")
    print(f"  CVE mappings added: {cve_mappings_added}")
    print(f"  Errors: {errors}")

    # Final stats
    db = duckdb.connect(CACHE_DB, read_only=True)
    total_map = db.execute("SELECT COUNT(*) FROM cve_module_map").fetchone()[0]
    unique_cves = db.execute("SELECT COUNT(DISTINCT cve_id) FROM cve_module_map").fetchone()[0]
    db.close()
    print(f"  Total CVE map entries: {total_map}")
    print(f"  Unique CVEs mapped: {unique_cves}")


if __name__ == "__main__":
    start_time = time.time()
    main()
