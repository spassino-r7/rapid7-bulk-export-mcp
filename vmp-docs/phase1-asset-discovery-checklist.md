# Phase 1: Asset Discovery and Inventory — Setup Checklist

**Program:** Vulnerability Management Program (InsightVM)
**Phase:** 1 of 6
**Prerequisite:** InsightVM console is installed, licensed, and accessible.

---

## 1.1 Deploy and Register Scan Engines

**Console path:** Administration → Engines → Add Engine

### Steps

1. Provision a dedicated host per network segment that cannot be reached from the console:
   - Minimum spec: 4 vCPU, 8 GB RAM, 100 GB disk
   - Supported OS: Windows Server 2016/2019/2022 or RHEL/CentOS/Ubuntu LTS
2. Download the Scan Engine installer from the InsightVM console.
3. Run the installer on the dedicated host.
4. In the console, navigate to **Administration → Engines → Add Engine** and copy the pairing key.
5. Enter the pairing key in the engine installer to register the engine.
6. Verify the engine appears as **Active** in **Administration → Engines**.
7. Confirm TCP 40814 is open outbound from the engine host to the console IP.

### Runbook entries required

| Field | Value |
|---|---|
| Engine hostname | `[FILL IN]` |
| Engine IP | `[FILL IN]` |
| Network segment served | `[FILL IN]` |
| Registration date | `[FILL IN]` |
| Console connectivity verified | ☐ Yes |

Repeat for each network segment.

---

## 1.2 Create Sites per Network Segment and Business Unit

**Console path:** Administration → Sites → Create Site

### Recommended initial Sites

| Site Name | IP Range / Scope | Scan Engine | Notes |
|---|---|---|---|
| `CORP-HQ-Servers` | 192.168.1.0/24 – 192.168.10.0/24 | HQ Scan Engine | |
| `CORP-HQ-Workstations` | 192.168.50.0/24 – 192.168.60.0/24 | HQ Scan Engine | |
| `CORP-DMZ` | 10.10.0.0/24 | DMZ Scan Engine | |
| `CORP-Critical-Assets` | Subset — DCs, PAM, core infra | HQ Scan Engine | 7-day scan cadence |
| `CLOUD-AWS-Production` | AWS cloud connector | AWS VPC Scan Engine | |
| `CLOUD-AWS-Dev` | AWS cloud connector | AWS VPC Scan Engine | |
| `CLOUD-Azure-Production` | Azure cloud connector | Azure Scan Engine | |
| `REMOTE-Endpoints` | Agent-assessed only | N/A (agent) | No IP range needed |

### Steps

1. Navigate to **Administration → Sites → Create Site**.
2. Enter the Site name following the convention `{ENVIRONMENT}-{SEGMENT}-{OPTIONAL_QUALIFIER}`.
3. Under **Assets**, enter the IP ranges or upload an asset list.
4. Under **Engines**, assign the appropriate Scan Engine.
5. Save the Site.
6. Repeat for each Site in the table above.

---

## 1.3 Deploy Insight Agent to Managed Endpoints

**Console path:** Administration → Agents → Download Agent

### Steps

1. Download the agent installer (Windows MSI or Linux DEB/RPM) from **Administration → Agents → Download Agent**.
2. Deploy via your endpoint management tooling:
   - **Windows (SCCM/Intune):** Deploy the MSI silently: `msiexec /i InsightAgent.msi /quiet`
   - **Linux (Ansible):** Use the `r7insight_agent` role or run the shell installer.
   - **Cloud (AWS/Azure user-data):** Embed the installer script in the instance launch template.
3. Verify agent-assessed assets appear in InsightVM within 24 hours.
4. Confirm assets appear in the `REMOTE-Endpoints` Site or the default Insight Agent site.

### Verification

- Navigate to **Assets** and filter by Site = `REMOTE-Endpoints`.
- Confirm asset count matches expected managed endpoint count ± 5%.

---

## 1.4 Configure Cloud Integrations (AWS, Azure, GCP)

### AWS

**Console path:** Administration → Cloud Configuration → AWS

1. Create an IAM role in AWS with the following read-only permissions:
   - `ec2:DescribeInstances`
   - `ec2:DescribeImages`
   - `ec2:DescribeRegions`
   - `ec2:DescribeSecurityGroups`
2. Note the IAM role ARN.
3. In InsightVM, navigate to **Administration → Cloud Configuration → AWS**.
4. Enter the IAM role ARN and AWS region(s).
5. Save and verify the integration shows a successful sync timestamp.

### Azure

**Console path:** Administration → Cloud Configuration → Azure

1. Create a service principal in Azure AD with the **Reader** role on the target subscription(s).
2. Note the tenant ID, client ID, and client secret.
3. In InsightVM, navigate to **Administration → Cloud Configuration → Azure**.
4. Enter the tenant ID, client ID, and client secret.
5. Save and verify the integration shows a successful sync timestamp.

### GCP

**Console path:** Administration → Cloud Configuration → GCP

1. Create a service account in GCP with the **Viewer** role on the target project(s).
2. Download the service account JSON key file.
3. In InsightVM, navigate to **Administration → Cloud Configuration → GCP**.
4. Upload the service account key file.
5. Save and verify the integration shows a successful sync timestamp.

---

## 1.5 Configure Scan Credentials

**Console path:** Administration → Credentials

### Credential types to create

| Type | Account | Permissions Required |
|---|---|---|
| Windows (domain) | `svc-insightvm-scan` | Local Administrators group OR WMI/registry read |
| SSH (key-based) | `insightvm-scan` | Non-root; sudo access to package manager |
| SNMP v3 | `insightvm-snmp` | Read-only community |
| Database (read-only) | `insightvm-db` | SELECT on system tables |

### Steps

1. Navigate to **Administration → Credentials → Add Credential**.
2. Select the credential type and enter the account details.
3. Save the credential.
4. Assign the credential to each Site: **Site Configuration → Authentication → Add Credential**.
5. After the first scan, verify credential success in **Assets → Authentication Status**.

### Runbook entries required

| Credential Name | Type | Account | Sites Assigned | Rotation Schedule |
|---|---|---|---|---|
| `WIN-Domain-Scan` | Windows | `svc-insightvm-scan` | All CORP sites | 90 days |
| `SSH-Key-Scan` | SSH | `insightvm-scan` | All Linux sites | 180 days |
| `SNMP-v3-Scan` | SNMP v3 | `insightvm-snmp` | Network device sites | 180 days |
| `DB-ReadOnly-Scan` | Database | `insightvm-db` | DB server sites | 90 days |

---

## 1.6 Phase 1 Smoke Test — Verify Discovery Completeness

Complete all items before advancing to Phase 2.

| Check | Status | Notes |
|---|---|---|
| At least one Site exists per network segment | ☐ | |
| All Scan Engines show status "Active" in Administration → Engines | ☐ | |
| Insight Agent deployed to all managed endpoints; assets visible in InsightVM | ☐ | |
| All cloud integrations show successful last-sync timestamp | ☐ | |
| Credentials assigned to all Sites | ☐ | |
| Total discovered asset count documented in runbook | ☐ | Count: `[FILL IN]` |
| Baseline date documented in runbook | ☐ | Date: `[FILL IN]` |

**Phase 1 sign-off:** `[Program Administrator name]` — Date: `[FILL IN]`
