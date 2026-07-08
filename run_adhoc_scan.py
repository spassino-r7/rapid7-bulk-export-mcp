#!/usr/bin/env python3
"""
Run an ad-hoc InsightVM scan against a single asset using the v4 Cloud Integrations API.

Usage:
    python run_adhoc_scan.py --asset-id <ASSET_ID> [--region us] [--name "My Scan"]

Requirements:
    - pip install requests
    - Set environment variable: RAPID7_API_KEY

API Reference:
    POST https://{region}.api.insight.rapid7.com/vm/v4/integration/scan
"""

import argparse
import os
import sys
import time

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REGIONS = ["us", "us2", "us3", "eu", "ca", "au", "ap", "aps2", "me1"]
DEFAULT_REGION = "us3"
POLL_INTERVAL_SECONDS = 30


def get_api_key():
    """Retrieve the Rapid7 Insight Platform API key from environment."""
    key = os.environ.get("RAPID7_API_KEY")
    if not key:
        print("ERROR: RAPID7_API_KEY environment variable is not set.")
        print("Generate one at: https://insight.rapid7.com -> API Keys")
        sys.exit(1)
    return key


def build_base_url(region: str) -> str:
    """Construct the base URL for the given region."""
    return f"https://{region}.api.insight.rapid7.com/vm/v4/integration"


def start_scan(region: str, api_key: str, asset_id: str, scan_name: str = None,
               engine_id: str = None, site_name: str = None) -> dict:
    """
    Start an ad-hoc scan against one asset.

    Parameters
    ----------
    region : str
        Insight Platform region (us, eu, etc.)
    api_key : str
        Insight Platform API key.
    asset_id : str
        The asset identifier to scan (UUID format from InsightVM).
    scan_name : str, optional
        A friendly name for the scan.
    engine_id : str, optional
        Specific scan engine to use. If omitted, the platform picks one.
    site_name : str, optional
        Site name on the console to pull credentials from and ingest results into.

    Returns
    -------
    dict
        API response containing scan ID(s) and any unscanned assets.
    """
    url = f"{build_base_url(region)}/scan"

    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "asset_ids": [asset_id],
    }

    if scan_name:
        payload["name"] = scan_name
    if engine_id:
        payload["engine_ids"] = [engine_id]
    if site_name:
        payload["credential_sources"] = [site_name]
        payload["result_consumer"] = site_name

    print(f"Starting scan against asset: {asset_id}")
    print(f"  Region: {region}")
    print(f"  URL: {url}")
    print(f"  Payload: {payload}")
    print()

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code in (200, 201, 202):
        data = response.json()
        print("Scan started successfully!")
        print(f"  Response: {data}")
        return data
    else:
        print(f"ERROR: API returned status {response.status_code}")
        print(f"  Response: {response.text}")
        sys.exit(1)


def get_scan_status(region: str, api_key: str, scan_id: str) -> dict:
    """Check the status of a running scan."""
    url = f"{build_base_url(region)}/scan/{scan_id}"

    headers = {
        "X-Api-Key": api_key,
        "Accept": "application/json",
    }

    response = requests.get(url, headers=headers, params={"includeDetails": "true"})

    if response.status_code == 200:
        return response.json()
    else:
        print(f"WARNING: Could not get scan status (HTTP {response.status_code})")
        return None


def poll_scan_completion(region: str, api_key: str, scan_id: str):
    """Poll until the scan completes or fails."""
    print(f"\nPolling scan {scan_id} every {POLL_INTERVAL_SECONDS}s...")
    terminal_statuses = {"Success", "Failed", "Stopped", "Completed", "Aborted"}

    while True:
        status_data = get_scan_status(region, api_key, scan_id)
        if status_data:
            status = status_data.get("status", "Unknown")
            print(f"  [{time.strftime('%H:%M:%S')}] Scan status: {status}")

            if status in terminal_statuses:
                print(f"\nScan finished with status: {status}")
                return status_data
        else:
            print(f"  [{time.strftime('%H:%M:%S')}] Unable to retrieve status, retrying...")

        time.sleep(POLL_INTERVAL_SECONDS)


def main():
    parser = argparse.ArgumentParser(
        description="Run an ad-hoc InsightVM scan against a single asset via the v4 API."
    )
    parser.add_argument(
        "--asset-id", required=True,
        help="The asset ID to scan (UUID from InsightVM, e.g. '12344375-34a7-40d3-9821-90db0b5cc90e-default-asset-7912')"
    )
    parser.add_argument(
        "--region", default=DEFAULT_REGION, choices=REGIONS,
        help=f"Insight Platform region (default: {DEFAULT_REGION})"
    )
    parser.add_argument(
        "--name", default=None,
        help="Optional friendly name for the scan"
    )
    parser.add_argument(
        "--engine-id", default=None,
        help="Optional scan engine ID to use"
    )
    parser.add_argument(
        "--site", required=True,
        help="Site name for credentials and result ingestion (required)"
    )
    parser.add_argument(
        "--wait", action="store_true",
        help="Poll and wait for the scan to complete"
    )

    args = parser.parse_args()
    api_key = get_api_key()

    # Start the scan
    result = start_scan(
        region=args.region,
        api_key=api_key,
        asset_id=args.asset_id,
        scan_name=args.name,
        engine_id=args.engine_id,
        site_name=args.site,
    )

    # Optionally wait for completion
    if args.wait and result:
        scans = result.get("scans", [])
        if scans:
            scan_id = scans[0].get("id")
            if scan_id:
                poll_scan_completion(args.region, api_key, scan_id)
            else:
                print("No scan ID returned; cannot poll.")
        else:
            print("No scans returned in response; cannot poll.")

    # Report any unscanned assets
    unscanned = result.get("unscanned_assets", [])
    if unscanned:
        print(f"\nWARNING: {len(unscanned)} asset(s) could not be scanned:")
        for item in unscanned:
            print(f"  - {item}")


if __name__ == "__main__":
    main()
