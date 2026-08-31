# Vulnerability Exception Process — Data Model Design

Task #1 of the exception process. This document defines the exception data model:
what a single exception record captures, how the fields map to the InsightVM API v3
`vulnerability_exceptions` endpoint, and how they map to the local DuckDB table.
Field names and enums are aligned so a local record maps 1:1 to a console record.

## 1. Concept

Every Critical/Severe finding in the BOD workflow has two possible dispositions:
remediate it, or file an **exception** (accept the risk / mark false positive / note a
compensating control). An exception suppresses the finding's contribution to risk in
InsightVM and, in our workflow, removes or flags it in the BOD 26-04 compliance report.

An exception is recorded in two places that must stay in sync:
1. **Local DuckDB** (`vulnerability_exceptions` table) — source of truth for the BOD workflow.
2. **InsightVM console** via `POST /api/3/vulnerability_exceptions` — so the console risk
   score and the platform reflect the same decision.

## 2. InsightVM API v3 reference (target contract)

Endpoint: `POST /api/3/vulnerability_exceptions`

Request body shape (the console contract we must satisfy):

```json
{
  "vulnerability": "<vulnId>",
  "scope": {
    "type": "Global | Site | Asset | Asset Group | Instance",
    "id": "<scope id, required for all scopes except Global>",
    "vulnerability": "<vulnId>",
    "key": "<optional instance key, e.g. port/proof context>",
    "port": <optional integer>
  },
  "submit": {
    "reason": "False Positive | Compensating Control | Acceptable Use | Acceptable Risk | Other",
    "comment": "<justification text>"
  },
  "expires": "2027-02-21T00:00:00Z"
}
```

Confirmed behaviors from Rapid7 docs/community:
- `submit.reason` is **required**; the five reason values above are the valid enum.
- All scope types **except Global** require a scope `id`.
- `expires` is an ISO-8601 date; optional (no expiry = permanent until revoked).
- Creation and **approval are separate steps** — a new exception is `Under Review`
  until a reviewer approves it (`Approved`), so state must be tracked, not assumed.

## 3. Exception data model (canonical fields)

These are the logical fields for one exception. The "InsightVM mapping" column shows
where each goes in the API payload; the "DuckDB column" column is defined in Task #2.

| Field | Type | Required | InsightVM mapping | Notes |
|-------|------|----------|-------------------|-------|
| `local_exception_id` | UUID/VARCHAR | yes | — (local only) | Primary key, generated locally |
| `console_exception_id` | INTEGER | no | response `id` | Null until synced; filled from API response |
| `vuln_id` | VARCHAR | yes | `vulnerability` + `scope.vulnerability` | Rapid7 vulnId (e.g. `unix-cups-cve-2024-47176`) |
| `cve_id` | VARCHAR | no | — | Convenience field for reporting/joins; not sent to API |
| `scope_type` | ENUM | yes | `scope.type` | Global, Site, Asset, Asset Group, Instance |
| `scope_id` | VARCHAR | conditional | `scope.id` | Required for all scope types except Global |
| `scope_key` | VARCHAR | no | `scope.key` | Instance-scope disambiguator (proof/context) |
| `port` | INTEGER | no | `scope.port` | For port-specific instance exceptions |
| `reason` | ENUM | yes | `submit.reason` | False Positive / Compensating Control / Acceptable Use / Acceptable Risk / Other |
| `comment` | VARCHAR | yes (policy) | `submit.comment` | Justification; API allows empty but our workflow requires it |
| `expires` | TIMESTAMP | no | `expires` | ISO-8601; null = permanent |
| `submitted_by` | VARCHAR | yes (policy) | — (audit) | Local operator identity |
| `state` | ENUM | yes | derived from API | Under Review, Approved, Rejected, Deleted, Expired |
| `sync_status` | ENUM | yes | — (local only) | pending, synced, failed |
| `bod_original_timeline` | VARCHAR | no | — | BOD 26-04 timeline the finding had before exception (e.g. "60 days") |
| `bod_review_date` | DATE | no | — | When this exception should be re-reviewed for BOD purposes |
| `created_at` | TIMESTAMP | yes | — | Local insert time |
| `updated_at` | TIMESTAMP | yes | — | Last local modification / last sync attempt |

### Enums

**scope_type** (mirrors InsightVM):
`Global`, `Site`, `Asset`, `Asset Group`, `Instance`

**reason** (exact InsightVM values — do not paraphrase):
`False Positive`, `Compensating Control`, `Acceptable Use`, `Acceptable Risk`, `Other`

**state** (mirrors InsightVM exception lifecycle):
`Under Review`, `Approved`, `Rejected`, `Deleted`, `Expired`

**sync_status** (local-only, drives Task #6 reconciliation):
`pending` (not yet sent), `synced` (console id stored), `failed` (API error, retry needed)

## 4. Scope resolution rules

- `scope_type = Global` → omit `scope.id`. Applies the exception to the vuln everywhere.
- `scope_type = Asset` → `scope_id` = InsightVM asset id. Note the bulk-export `assetId`
  (e.g. `8bd28bcb-...-default-asset-154`) is **not** the console integer asset id; Task #4
  must resolve export asset ids to console asset ids before submitting.
- `scope_type = Instance` → `scope_id` + optional `scope_key`/`port` to pin a single
  finding instance (e.g. one port on one asset).
- `scope_type = Site` / `Asset Group` → `scope_id` = that object's console id.

## 5. Validation rules (enforced on write, Task #3)

1. `reason` must be one of the five enum values.
2. `scope_id` required unless `scope_type = Global`.
3. `expires`, if present, must be a future date.
4. `comment` non-empty (workflow policy, stricter than the API).
5. `vuln_id` must exist in the current `vulnerabilities` export (warn if not).

## 6. Relationship to the BOD compliance report (Task #5)

- Join key: `vuln_id` (+ `scope_id` when asset-scoped) against the report's findings.
- An `Approved` exception → finding is flagged/excluded and drops out of overdue/timeline
  counts. `Under Review` → shown but annotated "exception pending".
- The report gains an Exceptions section listing reason, expires, state, and `sync_status`.

## 7. Open decisions (need confirmation before Task #3/#4 build)

1. **Console auth**: how are API credentials provided (env vars, config file, secrets manager)?
2. **Asset id resolution**: confirm the source for mapping export `assetId` → console asset id
   (a lookup via `GET /api/3/assets`, or a stored mapping).
3. **Auto-approve**: should the workflow only submit (leaving `Under Review` for a human),
   or also call the approval step? Default assumption: submit only.
```
