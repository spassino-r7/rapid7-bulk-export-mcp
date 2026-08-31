# False Positive Verification Guide

**Purpose:** Walk through the steps to determine if a vulnerability finding is a false positive, collect the necessary evidence, and file a support case with Rapid7 if needed.

**When to use this:** A finding appears on an asset but the team believes the vulnerable software/version isn't actually present, or the configuration makes exploitation impossible.

---

## Step 1: Understand the Finding

Before declaring a false positive, confirm you understand what InsightVM is reporting.

**Collect from the console:**
- Vulnerability title and ID
- CVE ID(s) associated
- Affected asset (hostname, IP)
- Scan date and scan template used
- **Proof** — the "Proof" section on the vulnerability detail page (this shows exactly what InsightVM detected that triggered the finding)

**Key question:** Does the proof show a version match, banner grab, or authenticated check? This determines the reliability of the detection.

---

## Step 2: Verify on the Asset

Log into the affected asset and confirm the actual state:

### For software version checks:
```bash
# Linux — check installed package version
dpkg -l | grep <package_name>
rpm -qa | grep <package_name>

# Windows — check installed programs
wmic product get name,version | findstr /i "<software>"

# Or check the binary directly
<binary> --version
```

### For service/port-based checks:
```bash
# What's actually listening on the reported port?
ss -tlnp | grep <port>
netstat -tlnp | grep <port>

# What version is the service reporting?
curl -I http://localhost:<port>
openssl s_client -connect localhost:<port> 2>/dev/null | head -5
```

### For web application checks:
```bash
# Check actual response headers
curl -sI https://<host>/<path> | grep -i "server\|x-powered-by\|version"

# Check if the reported endpoint exists
curl -s -o /dev/null -w "%{http_code}" https://<host>/<reported_path>
```

**Document:** Screenshot or save the output showing the *actual* version/state on the asset.

---

## Step 3: Compare Proof vs Reality

| If... | Then... |
|-------|---------|
| Proof shows version X, asset has version Y (patched) | Likely false positive — scan may have used cached/stale data, or banner wasn't updated |
| Proof shows banner detection, actual software is different | False positive — misidentification |
| Proof shows authenticated check confirming version | Less likely false positive — double-check package manager output |
| Proof shows "vulnerable configuration" but config has been changed | May be false positive — verify the specific config line |
| You can't reproduce what the proof claims | Likely false positive |

---

## Step 4: Collect Evidence for Support Case

If you've confirmed it's a false positive, gather this before contacting Rapid7:

### Required information:

1. **Vulnerability details:**
   - Vulnerability ID (from InsightVM)
   - CVE ID
   - Full title
   - Severity / CVSS score

2. **Asset details:**
   - Hostname and IP
   - Operating system (exact version)
   - Scan engine that found it
   - Scan template used

3. **Scan proof:**
   - Copy the "Proof" section from the vulnerability detail page (verbatim)
   - Note whether the check was remote or authenticated

4. **Your evidence showing it's false:**
   - Package manager output showing actual installed version
   - Configuration file showing the feature is disabled
   - Screenshot of the application version page
   - Any other evidence that contradicts the scan proof

5. **Scan logs (if requested):**
   - Location: `<engine_install>/nse/scanlogs/`
   - Find the scan log for the specific scan that found the issue
   - Grep for the asset IP and vulnerability check name

### Optional but helpful:

6. **Re-scan results:**
   - Run an ad-hoc scan against just that asset with verbose logging
   - Compare: does it still appear?

7. **Patch evidence:**
   - If you patched and the finding persists: show patch install date, reboot confirmation, and scan date (scan must be AFTER reboot)

---

## Step 5: File the Support Case

### Rapid7 Support Portal
- URL: https://www.rapid7.com/for-customers/
- Case type: **Vulnerability Content — False Positive**

### Case template:

```
Subject: False Positive — [CVE-ID] on [hostname]

Product: InsightVM
Component: Vulnerability Content
Console version: [version]
Content version: [version from Administration > Updates]

VULNERABILITY:
- Title: [full title]
- Vuln ID: [InsightVM vulnerability ID]
- CVE: [CVE-XXXX-XXXXX]
- Check type: [Remote / Authenticated]

ASSET:
- Hostname: [hostname]
- IP: [ip]
- OS: [full OS description]
- Scan engine: [engine name/IP]
- Last scan date: [date]

PROOF (from console):
[paste the proof section verbatim]

EVIDENCE (why this is false):
[paste your package manager output, config, or screenshots]

EXPECTED BEHAVIOR:
This asset should not be flagged for [CVE-ID] because [reason — e.g., 
"the installed version is X.Y.Z which is patched per vendor advisory ABC"].

ADDITIONAL CONTEXT:
[anything else relevant — was it previously accurate? did a patch 
change things? is the banner misleading?]
```

---

## Step 6: Interim Exception

While waiting for Rapid7 to confirm and update their content:

1. **Create a vulnerability exception in InsightVM:**
   - Vulnerability Exceptions page → Submit Exception
   - Type: **False Positive**
   - Scope: This specific asset + vulnerability
   - Reason: "Pending Rapid7 support case #[number] — actual version is [X]"
   - Expiration: 90 days (re-evaluate if case isn't resolved by then)

2. **Create matching BOD exception** (once the exception process is implemented):
   - Type: `false_positive`
   - Reason: Same as above
   - Link support case number

3. **Track the case:**
   - Set a reminder to check case status at 30 days
   - If Rapid7 confirms FP: they'll update the check in a content update
   - After content update: re-scan and verify the finding no longer appears
   - Remove the exception once the content fix is confirmed

---

## Common False Positive Scenarios

| Scenario | What to check |
|----------|---------------|
| Patched but still showing | Was the service restarted after patching? Was a scan run AFTER the restart? |
| Banner shows old version but software is updated | Some services (Apache, Nginx) don't update banners after package update — check actual binary version |
| Vulnerability in component that's present but unused | Verify the component can't be reached/invoked — document compensating control instead |
| Backported patch (RHEL/Ubuntu) | Package version looks old but includes the fix — check distro security advisory to confirm backport |
| Detection by installed package but feature is disabled | Document the disabled config — this may be "risk accepted" rather than false positive |

---

## Decision Tree

```
Finding appears on asset
    │
    ├─ Can you verify the vulnerable version/config on the asset?
    │   ├─ YES → Not a false positive. Patch or accept risk.
    │   └─ NO → Continue below
    │
    ├─ Does the scan proof match what you see on the asset?
    │   ├─ YES → Not a false positive (even if you think it should be patched)
    │   └─ NO → Likely false positive. Collect evidence.
    │
    ├─ Is this a backported patch scenario (RHEL/Ubuntu)?
    │   ├─ YES → Check vendor advisory. If backport confirmed, file as FP.
    │   └─ NO → Continue below
    │
    └─ File support case with evidence.
        Create interim exception while waiting.
```

---

*Document prepared for vulnerability management program operations. Review annually or when scan content processes change.*
