# Vulnerability Exception Process Procedure

**Program:** Vulnerability Management Program (InsightVM)
**Document Owner:** Security Program Administrator
**Review Cycle:** Annual
**Approval Required:** Security Team Lead

| Version | Date | Author | Change Summary |
|---|---|---|---|
| 1.0 | [FILL IN] | [FILL IN] | Initial release |

---

## 1. Purpose

This procedure defines the process for requesting, approving, recording, and reviewing exceptions to the standard vulnerability remediation SLA targets. An exception is appropriate when a vulnerability cannot be remediated within the defined SLA due to operational, technical, or business constraints.

---

## 2. Scope

This procedure applies to all open vulnerabilities tracked within InsightVM that cannot be remediated within the SLA targets defined in the Vulnerability Prioritization Policy.

---

## 3. Exception Types

InsightVM supports three exception types. Select the type that most accurately describes the situation:

| Exception Type | When to Use |
|---|---|
| **Acceptable Risk** | The vulnerability is real and exploitable, but the organization accepts the risk due to compensating controls, business constraints, or low likelihood of exploitation in the specific environment. |
| **Compensating Control** | A technical or administrative control is in place that reduces the risk of exploitation to an acceptable level (e.g., network segmentation, WAF rule, MFA enforcement). |
| **False Positive** | The vulnerability detection is incorrect — the asset is not actually affected by the vulnerability (e.g., vendor-confirmed not applicable to this OS version, detection based on version string only). |

---

## 4. Exception Submission Process

### 4.1 Who Can Submit

Any member of the remediation team, asset owner, or IT Operations staff may submit an exception request. The requestor is responsible for providing accurate and complete information.

### 4.2 Submission Steps

1. Navigate to **Vulnerabilities** in InsightVM and locate the vulnerability requiring an exception.
2. Click on the vulnerability to open the detail view.
3. Click **Add Exception**.
4. Select the exception type: **Acceptable Risk**, **Compensating Control**, or **False Positive**.
5. Complete all required fields:

| Field | Required | Description |
|---|---|---|
| Exception Type | Yes | Select from: Acceptable Risk, Compensating Control, False Positive |
| Business Justification | Yes | Explain why the vulnerability cannot be remediated within SLA. Be specific — reference the operational constraint, system dependency, or vendor limitation. |
| Compensating Controls | Yes (for Acceptable Risk and Compensating Control) | Describe the controls in place that reduce exploitation risk (e.g., "Asset is isolated on VLAN 100 with no inbound internet access; firewall rule blocks all external traffic to this host"). |
| Accepted Risk Date | Yes | The date the requestor acknowledges and accepts the residual risk. |
| Review Date | Yes | Must be no more than 90 calendar days from the approval date. |
| Requestor Name | Yes | Full name of the person submitting the exception. |
| Comments | Recommended | Any additional context, links to change tickets, or vendor advisories. |

6. Submit the exception request. The status will show as **Pending Approval** until reviewed.

---

## 5. Exception Approval Process

### 5.1 Approver

All exception requests must be reviewed and approved by the **Security Team Lead** (or designated security analyst with approval authority).

### 5.2 Approval Steps

1. The Security Team Lead reviews the pending exception in InsightVM (**Vulnerabilities → Exceptions → Pending**).
2. Evaluate the exception against the following criteria:
   - Is the business justification specific and credible?
   - Are the compensating controls adequate to reduce exploitation risk?
   - Is the accepted risk date reasonable?
   - Is the review date ≤ 90 days from today?
3. If approved:
   - Click **Approve** in InsightVM.
   - Enter the approver's full name in the **Comment** field (required for audit trail).
   - Confirm the review date is set correctly.
4. If rejected:
   - Click **Reject** and enter the reason in the comment field.
   - Notify the requestor and work with IT Operations to identify an alternative remediation path.

### 5.3 Approval Authority Matrix

| Vulnerability Severity | Approver |
|---|---|
| Critical | Security Team Lead + CISO (or delegate) |
| High | Security Team Lead |
| Medium | Security Team Lead |
| Low | Security Analyst (senior) |

---

## 6. False Positive Sub-Process

False positives follow the same submission flow but require additional documentation:

1. Navigate to **Vulnerabilities → [Vulnerability] → Add Exception → False Positive**.
2. In the **Business Justification** field, document:
   - Why the detection is incorrect (e.g., "Vendor advisory CVE-2024-XXXX confirms this CVE does not affect versions prior to 3.2.1; this asset runs version 2.9.4").
   - The source of the determination (vendor advisory URL, internal testing result, etc.).
3. In the **Comments** field, record the name of the analyst who verified the false positive.
4. The Security Team Lead approves the false positive exception.
5. After approval, the vulnerability is excluded from vulnerability counts and risk scores in InsightVM.

**Important:** False positives must be re-evaluated if the asset's software version changes or if new vendor information becomes available.

---

## 7. Exception Recording and Tracking

After an exception is approved, the Program Administrator must:

1. Confirm the exception is recorded in InsightVM with all required fields populated.
2. Confirm the review date is set to no more than 90 calendar days from the approval date.
3. Add the exception to the monthly exception summary report (SQL report `VMP-Exception-Summary`).

### Exception Register

The Program Administrator maintains an exception register in the program runbook. Update the register monthly:

| Vulnerability ID | Asset | Severity | Exception Type | Requestor | Approver | Approval Date | Review Date | Status |
|---|---|---|---|---|---|---|---|---|
| [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | [FILL IN] | Open |

---

## 8. Exception Review Process

All approved exceptions must be reviewed on or before their review date.

### Review Steps

1. The Program Administrator generates the `VMP-Exception-Summary` SQL report at the start of each month.
2. Identify exceptions with review dates in the current month.
3. For each exception due for review:
   - Has the underlying vulnerability been remediated? If yes, close the exception.
   - Is the compensating control still in place and effective? If no, escalate to the Security Team Lead.
   - Has the business justification changed? If yes, update the exception or initiate remediation.
   - Is an extension needed? If yes, submit a new exception request (extensions are not automatic).
4. Document the review outcome in the InsightVM exception comment field.

### Escalation

If an exception is not reviewed by its review date, the Program Administrator must:
1. Notify the asset owner and Security Team Lead within 2 business days.
2. Either close the exception (if the vulnerability is remediated) or submit a new exception request.
3. Document the escalation in the program runbook.

---

## 9. Monthly Exception Reporting

The Program Administrator reports the following exception metrics to security leadership monthly:

| Metric | Source |
|---|---|
| Total open exceptions by severity | `VMP-Exception-Summary` SQL report |
| Total open exceptions by business unit | `VMP-Exception-Summary` SQL report (filter by `bu` tag) |
| Exceptions approaching review date (next 14 days) | `VMP-Exception-Summary` SQL report |
| Exceptions overdue for review | `VMP-Exception-Summary` SQL report |
| New exceptions approved this month | InsightVM Exceptions view |
| Exceptions closed this month | InsightVM Exceptions view |

---

## 10. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Requestor (asset owner / IT Operations) | Submit exception with complete and accurate information before SLA deadline |
| Security Team Lead | Review and approve/reject exceptions within 5 business days of submission |
| Program Administrator | Record exceptions; set review dates; generate monthly exception report; track overdue reviews |
| Security Analyst | Verify false positive determinations; assist requestors with submission |

---

## 11. Policy Review and Approval

| Review Date | Reviewer | Approver | Changes Made |
|---|---|---|---|
| [FILL IN] | [FILL IN] | [FILL IN] | Initial approval |

---

## 12. Related Documents

- Vulnerability Prioritization Policy
- Patching Cadence Policy
- Vulnerability Management Program Runbook
- InsightVM Exceptions view: Vulnerabilities → Exceptions
