# Bulk Export API — A Beginner's Walkthrough

## What is it?

The Bulk Export API lets you pull large datasets out of InsightVM — your vulnerability findings, asset inventory, policy compliance results, and remediation history. The data comes out as downloadable files (Parquet format) that you can open in tools like Excel, Power BI, Snowflake, or Python.

Think of it as: "Give me a big spreadsheet of all my vulnerability data."

---

## What can you export?

There are three types of exports:

| Export Type | What you get |
|-------------|-------------|
| **Vulnerabilities** | All current open vulnerabilities + the assets they were found on |
| **Policies** | Policy compliance results (CIS benchmarks, etc.) + the assets assessed |
| **Remediations** | Vulnerabilities that were found and later fixed, with timestamps showing when |

---

## Before you start — What you'll need

### 1. An API Key

This is like a password that proves you're allowed to request this data.

- Log into the Insight Platform (insight.rapid7.com)
- Go to **Administration > API Keys**
- Generate a new **Organization Key** (or use a User key with Platform Admin permissions)
- Copy it and save it somewhere safe — you'll use it in every request

### 2. Your Region URL

Rapid7 hosts data in different regions. Pick the one that matches your account:

| Region | URL |
|--------|-----|
| United States - 1 | `https://us.api.insight.rapid7.com/export/graphql` |
| United States - 2 | `https://us2.api.insight.rapid7.com/export/graphql` |
| United States - 3 | `https://us3.api.insight.rapid7.com/export/graphql` |
| Europe | `https://eu.api.insight.rapid7.com/export/graphql` |
| Canada | `https://ca.api.insight.rapid7.com/export/graphql` |
| Australia | `https://au.api.insight.rapid7.com/export/graphql` |
| Japan | `https://ap.api.insight.rapid7.com/export/graphql` |

Not sure which region you're in? Check the URL when you log into the Insight Platform — it usually starts with `us`, `us2`, `us3`, `eu`, etc.

### 3. A tool to make API requests

You don't need to write code. **Postman** is a free tool with a visual interface that lets you send API requests by filling in fields — no scripting required.

Download it at: https://www.postman.com/downloads/

---

## The Process (4 Steps)

Here's the big picture of what happens:

```
Step 1: "Hey Rapid7, start preparing my data"     → You get back a Job ID
Step 2: "Is my data ready yet?"                    → You check until status = SUCCEEDED
Step 3: "Give me the download links"               → You get back file URLs
Step 4: Download the files                         → You have your data
```

The reason it's not instant: you may have thousands of assets and millions of findings. Rapid7 needs a few minutes to package that into files for you.

---

## Step 1: Start the Export

This is where you tell Rapid7 "I want my data."

In Postman:

1. Create a new request
2. Set the method to **POST**
3. Paste your region URL in the address bar
4. Under the **Headers** tab, add:
   - Key: `X-Api-Key`
   - Value: *(paste your API key)*
5. Under the **Body** tab:
   - Select **GraphQL**
   - Paste the appropriate mutation (see below)
6. Click **Send**

### Which mutation to paste (pick one):

**For vulnerabilities + assets:**
```graphql
mutation CreateVulnerabilityExport {
  createVulnerabilityExport {
    id
  }
}
```

**For policies + assets:**
```graphql
mutation CreatePolicyExport {
  createPolicyExport {
    id
  }
}
```

**For remediation data (requires date range):**
```graphql
mutation CreateRemediationExport {
  createRemediationExport(startDate: "2026-05-01", endDate: "2026-06-01") {
    id
  }
}
```

### What you'll get back:

```json
{
  "data": {
    "createVulnerabilityExport": {
      "id": "ABC123XYZ..."
    }
  }
}
```

**Save that ID** — you'll need it for the next step.

---

## Step 2: Check if it's ready

The export takes a few minutes to process. You need to check on it.

In Postman:

1. Create another new request (or modify the existing one)
2. Same method: **POST**
3. Same region URL
4. Same **X-Api-Key** header
5. Under **Body > GraphQL**, paste:

```graphql
query GetExport {
  export(id: "YOUR-EXPORT-ID-HERE") {
    id
    status
    dataset
    timestamp
    result {
      prefix
      urls
    }
  }
}
```

Replace `YOUR-EXPORT-ID-HERE` with the ID from Step 1.

6. Click **Send**

### What you'll see:

- `"status": "IN_PROGRESS"` — not ready yet, wait 30-60 seconds and try again
- `"status": "SUCCEEDED"` — ready! Move to Step 3

---

## Step 3: Get the download URLs

Once the status is `SUCCEEDED`, the response from Step 2 will include download URLs:

```json
{
  "result": {
    "prefix": "asset_vulnerability",
    "urls": [
      "https://some-long-url.parquet",
      "https://another-long-url.parquet"
    ]
  }
}
```

You may see multiple URLs and multiple prefixes:
- `"prefix": "asset"` — your asset inventory data
- `"prefix": "asset_vulnerability"` — the vulnerability findings

---

## Step 4: Download the files

Copy each URL from the response and paste it into your web browser — the file will download automatically.

**Important notes about the URLs:**
- They expire after **15 minutes** (you can regenerate them by re-running Step 2)
- The export data is retained for **30 days** after the initial request
- Files are in **Parquet** format

---

## What is Parquet and how do I open it?

Parquet is a compressed data format — think of it like a very efficient spreadsheet file. You can open it with:

| Tool | How |
|------|-----|
| **Python (pandas)** | `pd.read_parquet("file.parquet")` |
| **Excel** | Use a plugin or convert to CSV first |
| **Power BI** | Native Parquet support — just import |
| **DBeaver** | Can query Parquet files directly |
| **Snowflake / BigQuery** | Upload and query natively |

---

## Things to know

- **Data refreshes once daily** — making multiple export requests in a day will return the same data
- **Don't over-request** — excessive calls may get throttled
- **Remediation exports are limited to 31 days per request** — for longer ranges, make multiple requests with consecutive date windows
- **This is read-only** — you're just pulling data out, you can't change anything via this API

---

## Quick Reference

| What | Where to find it |
|------|-----------------|
| API Key | Insight Platform > Administration > API Keys |
| Region | Look at your login URL (us, us2, us3, eu, ca, au, ap) |
| Postman | https://www.postman.com/downloads/ |
| Rapid7 Docs | https://docs.rapid7.com/insightvm/bulk-export-api/ |

---

*Last updated: June 2026*
