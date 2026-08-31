#!/usr/bin/env python3
"""
customize_xccdf_policy.py

Modifies an exported InsightVM XCCDF policy file to disable specified rules
and optionally rename the policy. The output file can be re-uploaded to
InsightVM as a new custom policy.

Usage:
  python3 customize_xccdf_policy.py \
    --input exported-policy-xccdf.xml \
    --output custom-policy-xccdf.xml \
    --new-name "CIS Ubuntu 24.04 - Custom (No SSH)" \
    --disable-rules "2.1.1,2.1.2,5.2.4,Ensure SSH root login"

  # List all rules in the policy:
  python3 customize_xccdf_policy.py --input exported-policy-xccdf.xml --list-rules

Upload the output file to InsightVM:
  Security Console → Policies → Scan Engine Policy → Upload
  (File must end with -xccdf.xml)
"""

import argparse
import re
import sys
import xml.etree.ElementTree as ET


# XCCDF namespaces
NAMESPACES = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xccdf11": "http://checklists.nist.gov/xccdf/1.1",
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
}

# Register namespaces to preserve them in output
for prefix, uri in NAMESPACES.items():
    ET.register_namespace(prefix, uri)
# Also register common namespaces found in SCAP content
ET.register_namespace("", "http://checklists.nist.gov/xccdf/1.2")  # default namespace
ET.register_namespace("cpe", "http://cpe.mitre.org/language/2.0")
ET.register_namespace("dc", "http://purl.org/dc/elements/1.1/")
ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
ET.register_namespace("scap", "http://scap.nist.gov/schema/scap/source/1.2")
ET.register_namespace("catalog", "urn:oasis:names:tc:entity:xmlns:xml:catalog")
ET.register_namespace("xlink", "http://www.w3.org/1999/xlink")


def detect_namespace(tree):
    """Detect which XCCDF namespace version the file uses."""
    root = tree.getroot()
    tag = root.tag

    if "xccdf/1.2" in tag:
        return "http://checklists.nist.gov/xccdf/1.2"
    elif "xccdf/1.1" in tag:
        return "http://checklists.nist.gov/xccdf/1.1"
    elif "scap/source/1.2" in tag:
        # SCAP 1.2 datastream — XCCDF is embedded inside
        return "http://checklists.nist.gov/xccdf/1.2"
    else:
        # Try to find it in root attributes or default namespace
        for key, val in root.attrib.items():
            if "xccdf" in val:
                return val
    # Default to 1.2
    return "http://checklists.nist.gov/xccdf/1.2"


def find_rules(tree, ns):
    """Find all Rule elements in the XCCDF tree (handles datastream wrapper)."""
    rules = []
    # Search for Rule elements at any depth (works for both plain XCCDF and datastream)
    for rule in tree.iter(f"{{{ns}}}Rule"):
        rule_id = rule.get("id", "")
        title_elem = rule.find(f"{{{ns}}}title")
        title = title_elem.text if title_elem is not None else ""
        selected = rule.get("selected", "true")
        rules.append({
            "element": rule,
            "id": rule_id,
            "title": title,
            "selected": selected,
        })

    # Also search without namespace prefix (some files use default namespace)
    if not rules:
        for rule in tree.iter("Rule"):
            rule_id = rule.get("id", "")
            title_elem = rule.find("title")
            title = title_elem.text if title_elem is not None else ""
            selected = rule.get("selected", "true")
            rules.append({
                "element": rule,
                "id": rule_id,
                "title": title,
                "selected": selected,
            })

    return rules


def find_selects_in_profiles(tree, ns):
    """Find all select elements within Profile elements (handles datastream)."""
    selects = []

    # Search with namespace
    for profile in tree.iter(f"{{{ns}}}Profile"):
        profile_id = profile.get("id", "")
        for select in profile.findall(f"{{{ns}}}select"):
            selects.append({
                "element": select,
                "profile_id": profile_id,
                "idref": select.get("idref", ""),
                "selected": select.get("selected", "true"),
            })

    # Search without namespace (default ns in datastream files)
    if not selects:
        for profile in tree.iter("Profile"):
            profile_id = profile.get("id", "")
            for select in profile.findall("select"):
                selects.append({
                    "element": select,
                    "profile_id": profile_id,
                    "idref": select.get("idref", ""),
                    "selected": select.get("selected", "true"),
                })

    return selects


def match_rule(rule_id, rule_title, targets):
    """Check if a rule matches any of the disable targets."""
    for target in targets:
        target_lower = target.lower().strip()
        # Match by exact rule ID
        if target_lower == rule_id.lower():
            return True
        # Match by rule number pattern in ID (e.g., "2.1.1" matches "rule_2.1.1_Ensure...")
        if f"_{target_lower}_" in rule_id.lower() or rule_id.lower().endswith(f"_{target_lower}"):
            return True
        # Match by title substring
        if target_lower in rule_title.lower():
            return True
        # Match by rule number at start of title (e.g., "2.1.1" matches "2.1.1 Ensure chargen...")
        if rule_title.lower().startswith(target_lower + " "):
            return True
        if rule_title.lower().startswith(target_lower + "\t"):
            return True
    return False


def list_rules(input_file):
    """List all rules in the XCCDF file."""
    tree = ET.parse(input_file)
    ns = detect_namespace(tree)
    rules = find_rules(tree, ns)

    print(f"Policy file: {input_file}")
    print(f"Namespace: {ns}")
    print(f"Total rules: {len(rules)}")
    print(f"{'Selected':<10} {'Title':<70} {'ID (abbreviated)'}")
    print("-" * 120)

    for rule in rules:
        sel = rule["selected"]
        title = rule["title"][:70]
        # Abbreviate long IDs
        rule_id = rule["id"]
        if len(rule_id) > 40:
            rule_id = "..." + rule_id[-37:]
        print(f"{sel:<10} {title:<70} {rule_id}")


def customize_policy(input_file, output_file, new_name, disable_targets):
    """Disable specified rules and optionally rename the policy."""
    tree = ET.parse(input_file)
    ns = detect_namespace(tree)
    root = tree.getroot()

    # Rename the benchmark if requested
    if new_name:
        # Change the benchmark title
        title_elem = root.find(f"{{{ns}}}title")
        if title_elem is not None:
            old_title = title_elem.text
            title_elem.text = new_name
            print(f"Renamed: '{old_title}' → '{new_name}'")

        # Change the benchmark ID to avoid conflicts — must be globally unique
        # Find the Benchmark element (may be nested in datastream)
        for benchmark in tree.iter(f"{{{ns}}}Benchmark"):
            old_id = benchmark.get("id", "")
            if old_id:
                import time
                timestamp = str(int(time.time()))
                new_id = old_id + "_custom_" + timestamp
                benchmark.set("id", new_id)
                print(f"New benchmark ID: {new_id}")
                break
        else:
            # Try without namespace
            for benchmark in tree.iter("Benchmark"):
                old_id = benchmark.get("id", "")
                if old_id:
                    import time
                    timestamp = str(int(time.time()))
                    new_id = old_id + "_custom_" + timestamp
                    benchmark.set("id", new_id)
                    print(f"New benchmark ID: {new_id}")
                    break

    # Disable rules at the Rule element level
    rules = find_rules(tree, ns)
    disabled_count = 0

    for rule in rules:
        if match_rule(rule["id"], rule["title"], disable_targets):
            rule["element"].set("selected", "false")
            print(f"  Disabled Rule: {rule['title']}")
            disabled_count += 1

    # Also disable in Profile select elements
    selects = find_selects_in_profiles(tree, ns)
    profile_disabled = 0

    for sel in selects:
        # Extract a readable rule reference from the idref
        idref = sel["idref"]
        # Check if this select references a rule we want to disable
        for rule in rules:
            if rule["id"] == idref and rule["element"].get("selected") == "false":
                sel["element"].set("selected", "false")
                profile_disabled += 1
                break

    print(f"\nDisabled {disabled_count} Rule element(s)")
    if profile_disabled:
        print(f"Disabled {profile_disabled} Profile select reference(s)")

    # Ensure output filename ends with -xccdf.xml for InsightVM compatibility
    if not output_file.endswith("-xccdf.xml"):
        print(f"\nWARNING: Output filename should end with '-xccdf.xml' for InsightVM upload.")
        print(f"  Current: {output_file}")
        suggested = output_file.replace(".xml", "-xccdf.xml")
        print(f"  Suggested: {suggested}")

    # Write output
    tree.write(output_file, xml_declaration=True, encoding="UTF-8")
    print(f"\nOutput written to: {output_file}")
    print(f"\nTo upload: Security Console → Policies → Scan Engine Policy → Upload")

    return disabled_count


def main():
    parser = argparse.ArgumentParser(
        description="Customize an exported InsightVM XCCDF policy by disabling rules"
    )
    parser.add_argument("--input", required=True, help="Input XCCDF XML file (exported from InsightVM)")
    parser.add_argument("--output", help="Output XCCDF XML file (for re-upload)")
    parser.add_argument("--new-name", help="New name/title for the policy")
    parser.add_argument("--disable-rules",
                        help="Comma-separated list of rule numbers or title substrings to disable")
    parser.add_argument("--list-rules", action="store_true",
                        help="List all rules in the policy and exit")

    args = parser.parse_args()

    if args.list_rules:
        list_rules(args.input)
        return

    if not args.disable_rules:
        print("ERROR: --disable-rules is required (or use --list-rules to see available rules)")
        sys.exit(1)

    if not args.output:
        # Auto-generate output filename
        args.output = args.input.replace(".xml", "-custom-xccdf.xml")
        if args.output == args.input:
            args.output = args.input + ".custom-xccdf.xml"

    disable_targets = [r.strip() for r in args.disable_rules.split(",")]

    print(f"Input:  {args.input}")
    print(f"Output: {args.output}")
    print(f"Rules to disable: {disable_targets}")
    print()

    disabled = customize_policy(args.input, args.output, args.new_name, disable_targets)

    if disabled == 0:
        print("\nWARNING: No rules matched your disable patterns.")
        print("Use --list-rules to see available rule titles and IDs.")
        sys.exit(1)


if __name__ == "__main__":
    main()
