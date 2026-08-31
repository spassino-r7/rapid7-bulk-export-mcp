#!/usr/bin/env python3
"""
copy_and_customize_policy.py

Copies a CIS policy in InsightVM, disables specified rules,
and saves the customized copy.

Requires: requests
Usage:
  python3 copy_and_customize_policy.py \
    --console https://ivmcon:3780 \
    --user nxadmin \
    --password 'yourpass' \
    --policy-id 3292 \
    --new-name "CIS RHEL 8 - Custom (No SSH Rules)" \
    --disable-rules SV-12345,SV-67890,2.1.1,2.1.2
"""

import argparse
import json
import sys

import requests
import urllib3

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_session(console_url, username, password):
    """Authenticate and return a session."""
    session = requests.Session()
    session.verify = False
    session.auth = (username, password)
    session.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    # Test connection
    resp = session.get(f"{console_url}/api/3/policies?size=1")
    resp.raise_for_status()
    return session


def get_policy(session, console_url, policy_id):
    """Get policy details."""
    resp = session.get(f"{console_url}/api/3/policies/{policy_id}")
    resp.raise_for_status()
    return resp.json()


def get_policy_rules(session, console_url, policy_id):
    """Get all rules for a policy."""
    rules = []
    page = 0
    while True:
        resp = session.get(
            f"{console_url}/api/3/policies/{policy_id}/rules",
            params={"page": page, "size": 500}
        )
        resp.raise_for_status()
        data = resp.json()
        rules.extend(data.get("resources", []))
        if page >= data.get("page", {}).get("totalPages", 1) - 1:
            break
        page += 1
    return rules


def copy_policy(session, console_url, policy_id):
    """
    Copy a policy via the console's internal policy editor endpoints.
    Tries multiple known paths and payload formats. Returns the new policy ID.
    """
    attempts = [
        # /data/policy/editor/copy with different payload formats
        ("POST", f"{console_url}/data/policy/editor/copy",
         {"id": policy_id}),
        ("POST", f"{console_url}/data/policy/editor/copy",
         {"policy_id": policy_id}),
        ("POST", f"{console_url}/data/policy/editor/copy",
         {"sourceId": policy_id}),
        ("POST", f"{console_url}/data/policy/editor/copy",
         policy_id),  # plain integer body
        # /data/policy/copy with different formats
        ("POST", f"{console_url}/data/policy/copy",
         {"id": policy_id}),
        ("POST", f"{console_url}/data/policy/copy",
         {"sourceId": policy_id}),
        # form-encoded instead of JSON
        ("FORM", f"{console_url}/data/policy/editor/copy",
         {"policyId": str(policy_id)}),
        ("FORM", f"{console_url}/data/policy/copy",
         {"policyId": str(policy_id)}),
    ]

    for method, url, payload in attempts:
        try:
            if method == "FORM":
                resp = session.post(url, data=payload,
                                    headers={**session.headers, "Content-Type": "application/x-www-form-urlencoded"})
            else:
                resp = session.post(url, json=payload)

            if resp.status_code in (404, 405, 406):
                continue
            if resp.status_code == 400:
                print(f"  {url} (payload: {payload}) -> 400: {resp.text[:150]}")
                continue
            if resp.status_code >= 500:
                print(f"  {url} (payload: {payload}) -> {resp.status_code}: {resp.text[:150]}")
                continue

            resp.raise_for_status()
            data = resp.json() if resp.content else {}
            new_id = (data.get("id") or data.get("policyId") or
                      data.get("policy_id") or data.get("newPolicyId"))
            if data.get("resources"):
                new_id = data["resources"][0].get("id")
            if new_id:
                print(f"  Success via {url}")
                return new_id

            if resp.text.strip().isdigit():
                return int(resp.text.strip())

            print(f"  200 from {url} but can't parse ID: {resp.text[:200]}")

        except requests.exceptions.HTTPError:
            continue

    return None


def rename_policy(session, console_url, policy_id, new_name):
    """Rename a copied policy."""
    resp = session.put(
        f"{console_url}/api/3/policies/{policy_id}",
        json={"title": new_name}
    )
    if resp.status_code == 405:
        # Try internal endpoint
        resp = session.post(
            f"{console_url}/data/policy/{policy_id}/name",
            json={"name": new_name}
        )
    resp.raise_for_status()


def disable_rules(session, console_url, policy_id, rule_ids_to_disable, all_rules):
    """Disable specified rules in the copied policy."""
    disabled_count = 0
    for rule in all_rules:
        rule_id = rule.get("id") or rule.get("ruleId")
        rule_title = rule.get("title", "")
        rule_name = rule.get("name", "")

        # Match by rule ID, title substring, or name
        should_disable = False
        for target in rule_ids_to_disable:
            if (str(rule_id) == target or
                target.lower() in rule_title.lower() or
                target.lower() in rule_name.lower()):
                should_disable = True
                break

        if should_disable:
            # Try multiple approaches to disable the rule
            success = False

            # Approach 1: PATCH with enabled=false on v3 API
            resp = session.patch(
                f"{console_url}/api/3/policies/{policy_id}/rules/{rule_id}",
                json={"enabled": False}
            )
            if resp.ok:
                success = True

            # Approach 2: PUT with enabled=false
            if not success:
                resp = session.put(
                    f"{console_url}/api/3/policies/{policy_id}/rules/{rule_id}",
                    json={"enabled": False}
                )
                if resp.ok:
                    success = True

            # Approach 3: Internal data endpoint with form post
            if not success:
                resp = session.post(
                    f"{console_url}/data/policy/rules/disable",
                    json={"policyId": policy_id, "ruleId": rule_id}
                )
                if resp.ok:
                    success = True

            # Approach 4: Internal endpoint with rule status
            if not success:
                resp = session.post(
                    f"{console_url}/data/policy/{policy_id}/rules/{rule_id}/status",
                    json={"enabled": False, "status": "disabled"}
                )
                if resp.ok:
                    success = True

            # Approach 5: URL-encoded rule ID (in case special chars are the issue)
            if not success:
                import urllib.parse
                encoded_rule_id = urllib.parse.quote(str(rule_id), safe='')
                resp = session.put(
                    f"{console_url}/api/3/policies/{policy_id}/rules/{encoded_rule_id}",
                    json={"enabled": False}
                )
                if resp.ok:
                    success = True

            if success:
                print(f"  Disabled: {rule_title} (ID: {rule_id})")
                disabled_count += 1
            else:
                print(f"  FAILED to disable: {rule_title} - {resp.status_code}: {resp.text[:100]}")

    return disabled_count


def main():
    parser = argparse.ArgumentParser(description="Copy and customize an InsightVM CIS policy")
    parser.add_argument("--console", required=True, help="Console URL (e.g., https://ivmcon:3780)")
    parser.add_argument("--user", required=True, help="Console username")
    parser.add_argument("--password", required=True, help="Console password")
    parser.add_argument("--policy-id", required=True, type=int, help="Source policy ID to copy (or target policy if --skip-copy)")
    parser.add_argument("--new-name", default=None, help="Name for the copied policy (not needed with --skip-copy)")
    parser.add_argument("--disable-rules", required=True,
                        help="Comma-separated list of rule IDs or title substrings to disable")
    parser.add_argument("--skip-copy", action="store_true",
                        help="Skip the copy step — disable rules directly on the specified policy ID")

    args = parser.parse_args()
    rules_to_disable = [r.strip() for r in args.disable_rules.split(",")]

    print(f"Connecting to {args.console}...")
    session = get_session(args.console, args.user, args.password)

    print(f"Getting source policy {args.policy_id}...")
    policy = get_policy(session, args.console, args.policy_id)
    print(f"  Source: {policy.get('title', 'Unknown')}")

    if args.skip_copy:
        target_policy_id = args.policy_id
        print(f"Skipping copy — working directly on policy {target_policy_id}")
    else:
        if not args.new_name:
            print("ERROR: --new-name is required when copying a policy")
            sys.exit(1)
        print("Copying policy...")
        target_policy_id = copy_policy(session, args.console, args.policy_id)
        if not target_policy_id:
            print("ERROR: Failed to copy policy. The copy endpoint may not be available.")
            print("")
            print("Workaround:")
            print("  1. Copy the policy manually in the UI (Policies > Scan Engine Policy > Copy)")
            print("  2. Note the new policy ID")
            print(f"  3. Re-run with: --policy-id <new_id> --skip-copy --disable-rules \"{args.disable_rules}\"")
            sys.exit(1)
        print(f"  New policy ID: {target_policy_id}")
        print(f"Renaming to: {args.new_name}")
        rename_policy(session, args.console, target_policy_id, args.new_name)

    print("Getting rules from policy...")
    all_rules = get_policy_rules(session, args.console, target_policy_id)
    print(f"  Total rules: {len(all_rules)}")

    print(f"Disabling {len(rules_to_disable)} rule pattern(s)...")
    disabled = disable_rules(session, args.console, target_policy_id, rules_to_disable, all_rules)
    policy_name = args.new_name or policy.get('title', 'Unknown')
    print(f"\nDone. Disabled {disabled} rule(s) in policy '{policy_name}' (ID: {target_policy_id})")


if __name__ == "__main__":
    main()
