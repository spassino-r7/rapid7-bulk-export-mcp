# InsightVM Custom Policy Guide

## Overview

This guide walks through customizing a CIS benchmark policy in InsightVM by disabling specific rules that don't apply to your environment. The result is a tailored policy you can scan against without generating false findings for controls you've accepted risk on or that aren't applicable.

## Prerequisites

- InsightVM Security Console access (Global Administrator)
- Python 3 installed on a workstation
- The `customize_xccdf_policy.py` script

## Process

### Step 1: Copy the Source Policy

1. Log into the InsightVM Security Console
2. Navigate to **Policies > Scan Engine Policy**
3. Select the policy you want to customize (e.g., "CIS Ubuntu Linux 24.04 LTS Level One - Server v1.0.0")
4. Click **Copy Policy**
5. A copy will appear in the policy list with "Copy of" prepended to the name

### Step 2: Export the Copied Policy

1. Select the copied policy
2. Click **Export**
3. Save the downloaded XML file to your workstation
4. Note: The filename will be long — this is normal (it contains the benchmark ID)

### Step 3: List Available Rules

Run the script to see all rules in the policy:

```bash
python3 customize_xccdf_policy.py --input exported-policy-file.xml --list-rules
```

This displays all rules with their current status (selected true/false), title, and abbreviated ID. Review this list to identify rules you want to disable.

### Step 4: Disable Rules and Rename

Run the script with your list of rules to disable:

```bash
python3 customize_xccdf_policy.py \
  --input exported-policy-file.xml \
  --output my-custom-policy-xccdf.xml \
  --new-name "CIS Ubuntu 24.04 L1 - Custom (Org Name)" \
  --disable-rules "2.1.1,2.1.2,5.2.4,Ensure SSH root login"
```

**Parameters:**
- `--input` — The exported XML file from Step 2
- `--output` — Filename for the modified policy (must end in `-xccdf.xml`)
- `--new-name` — A descriptive name for your customized policy
- `--disable-rules` — Comma-separated list of rule numbers or title keywords to disable

**Rule matching:** The script matches rules by:
- Rule number (e.g., "2.1.1" matches "2.1.1 Ensure chargen services are not enabled")
- Title keyword (e.g., "Ensure SSH root login" matches "5.2.8 Ensure SSH root login is disabled")

The script will confirm which rules were disabled:

```
  Disabled Rule: 2.1.1 Ensure chargen services are not enabled
  Disabled Rule: 2.1.2 Ensure daytime services are not enabled
  Disabled Rule: 5.2.4 Ensure SSH X11 forwarding is disabled
  Disabled Rule: 5.2.8 Ensure SSH root login is disabled

Disabled 4 Rule element(s)
Output written to: my-custom-policy-xccdf.xml
```

### Step 5: Remove the Temporary Copy

1. Back in the Security Console, go to **Policies > Scan Engine Policy**
2. Delete the "Copy of..." policy created in Step 1 (it shares the same benchmark ID and will conflict with the upload)

### Step 6: Upload the Custom Policy

1. Go to **Policies > Scan Engine Policy**
2. Click **Upload**
3. Select the output file from Step 4 (e.g., `my-custom-policy-xccdf.xml`)
4. The policy will appear in the list with the custom name you specified

### Step 7: Assign to Scan Template

1. Go to **Administration > Scan Templates** (or edit your site's scan template)
2. Navigate to the **Policy Manager** section
3. Enable your new custom policy for scanning
4. Save the template

Scans using this template will now evaluate the custom policy with your disabled rules excluded from findings.

## Tips

- **Naming convention:** Include the original benchmark name, version, and what was customized. Example: "CIS RHEL 9 L1 v1.0.0 - Custom (No Partition Rules)"
- **Document exceptions:** Keep a record of which rules were disabled and why (risk acceptance, compensating control, etc.)
- **Version updates:** When CIS releases a new benchmark version, you'll need to repeat this process against the updated policy
- **Output filename:** Must end with `-xccdf.xml` for InsightVM to accept the upload
- **Multiple profiles:** If the policy contains multiple profiles (e.g., Level 1 and Level 2), the script disables matching rules across all profiles

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "benchmark with this id already exists" on upload | Delete the copy from Step 1 before uploading, or re-run the script (it generates a unique timestamp in the ID) |
| No rules matched | Use `--list-rules` to check exact rule titles, then adjust your `--disable-rules` patterns |
| Upload fails with format error | Ensure output filename ends with `-xccdf.xml` |
| Policy shows 0 rules after upload | The XML may have been corrupted — re-export and try again |
