# Greensky — InsightVM Troubleshooting Report

**Customer:** Greensky  
**Date:** June 2, 2026  
**Prepared by:** Security Operations

---

## Table of Contents

1. [Phantom Asset — MySQL on Unassigned IP](#1-phantom-asset--mysql-on-unassigned-ip)
2. [Scan Template Recommendations](#2-scan-template-recommendations)
3. [Scan Engine Out of Memory Failures](#3-scan-engine-out-of-memory-failures)
4. [Scan Log Analysis — Consolidated Summary](#4-scan-log-analysis--consolidated-summary)
5. [Sites with Overly Broad Scope](#5-sites-with-overly-broad-scope)
6. [Filtered Ports by Site](#6-filtered-ports-by-site)
7. [Bearer Token Findings](#7-bearer-token-findings)
8. [Scan Schedule Overlap Analysis](#8-scan-schedule-overlap-analysis)

---

## 1. Phantom Asset — MySQL on Unassigned IP

### Problem

An asset at `10.227.50.75` appears weekly with MySQL vulnerabilities on port 3306, but no device is actually assigned to that IP. The asset record shows:

| Field | Value |
|-------|-------|
| IP Address | 10.227.50.75 |
| Hardware | Unknown |
| OS | Unknown |
| Host Type | Unknown |
| Site | E1/E2 Non-CDE Networks |
| Engine | 44 |
| Risk Score | 48,817 |
| Tags | E1/E2/C1 Devops hosts, R7 - AWS Assets |
| Last Scan | May 7, 2026 |

### Root Cause Analysis

Scan log evidence shows only port 3306 is open — all other ports report as FILTERED:

```
2026-05-07T07:08:29 [INFO] [Thread: Scan 44:nmap:stdin] [Site: E1/E2 Non-CDE Networks]
[10.227.50.75:3306/TCP] OPEN    (reason=syn-ack:TTL=0)
[10.227.50.75:765/TCP]  FILTERED (reason=no-response)
[10.227.50.75:592/TCP]  FILTERED (reason=no-response)
[10.227.50.75:892/TCP]  FILTERED (reason=no-response)
[10.227.50.75:5958/TCP] FILTERED (reason=no-response)
```

**Key observations:**

- `FILTERED` = something is silently blocking access (firewall between engine and asset, or host-based firewall)
- `OPEN` on 3306 = the engine successfully communicated with a running MySQL service
- `TTL=0` on the SYN-ACK is abnormal — indicates a **firewall or load balancer is intercepting traffic** destined for 10.227.50.75:3306 and forwarding it to another machine running the actual MySQL service
- 589 other assets in this site also show FILTERED ports

### Resolution Options

| Option | Description | Effort |
|--------|-------------|--------|
| **A** | Whitelist the scan engine on all firewalls between it and the IP ranges in the site | Medium |
| **B** | Deploy scan engines behind the firewalls for direct communication to target assets | Higher |

---

## 2. Scan Template Recommendations

### Issues Found

| Issue | Detail | Impact |
|-------|--------|--------|
| Enhanced logging enabled | Template `a-greensky-full-audit-without-web-spider-_-16g` has enhanced logging on | Creates very large log files; should only be used when instructed by support |
| Excessive UDP scanning | Multiple UDP ports being scanned unnecessarily | Extends scan duration; most vulns are TCP-based |
| Agent skip not verified | Customer uses Insight Agents — verify "Skip checks with Insight Agent" is enabled on all scan templates | Redundant work if disabled; wastes engine time on already-assessed assets |

### Recommendations

1. **Disable enhanced logging** unless actively troubleshooting with Rapid7 support
2. **Reduce UDP ports** — remove all except Scan Assistant port (if using Scan Assistant)
3. **Verify "Skip checks with Insight Agent" is enabled** on all scan templates since customer uses agents

---

## 3. Scan Engine Out of Memory Failures

### Problem

Multiple scans failed with: `"Paused by 'System': Not enough memory to complete scan"`

### Affected Scans

| Site | Type | Started | Duration | Status |
|------|------|---------|----------|--------|
| Azure Environment | Scheduled | 5/19/2026 1:00 AM | 9h 1m | Paused — scan duration met |
| E1/E2 Non-CDE Networks | Manual | 4/27/2026 4:16 PM | 8 min | Failed — out of memory |
| E1/E2 Non-CDE Networks | Manual | 4/27/2026 4:19 PM | 2 min | Failed — out of memory |
| WVD asset pool | Scheduled | 7/13/2025 3:35 AM | 2 min | Failed — out of memory |

### Root Causes

1. **Unknown engine specs** — Need to verify if engines have sufficient RAM for this concurrency
2. **Simultaneous asset count may be too high** — Templates configured to scan **250 assets simultaneously**, which may exceed engine memory depending on engine specs
3. **Multiple concurrent site scans** — An engine running multiple site scans at the same time compounds memory pressure

### Action Items

| # | Question / Action |
|---|-------------------|
| 1 | What instance type is each engine running on? (determines the RAM ceiling) |
| 2 | How much of that RAM is allocated to the InsightVM engine's JVM heap? |

*Note: All engines are deployed in AWS/Azure. Both cloud providers allocate dedicated (not shared) memory per instance, so memory contention is not a factor — the question is whether the instance type has enough RAM for the configured concurrency.*

### Recommendation

- Reduce simultaneous assets from 250 to **50-100** until engine capacity is confirmed
- Stagger scan schedules so each engine runs **one site scan at a time**

---

## 4. Scan Log Analysis — Consolidated Summary

Analysis of 24 scan log files across all sites:

| Metric | Count |
|--------|-------|
| Total log files analyzed | 24 |
| Total ALIVE hosts | 2,744 |
| Total DEAD hosts | 690,265 |
| Total FILTERED ports | 1,453,085 |

**Key insight:** The environment is scanning ~693K IPs but only 2,744 are alive. That's a **0.4% hit rate** — 99.6% of scan effort is wasted probing empty address space.

---

## 5. Sites with Overly Broad Scope

Sites with more than 10,000 DEAD hosts indicate scope is far larger than the actual asset footprint:

| Site | Dead IPs | Engine Log |
|------|----------|-----------|
| E1/E2 Non-CDE Networks | 198,945 | 44.44 |
| Azure Environment | 196,503 | 45.17 |
| DC3 - COLO - Network | 63,979 | 44.9 |
| CH1 - COLO - Network | 61,418 | 44.15 |
| AT1 - COLO - Network | 61,413 | 44.10 |
| AWS - Non-Prod | 30,394 | 44.14 |
| VPE Networks | 23,927 | 45.10 |
| ATL | 12,240 | 45.20 |

### Why So Many DEAD Hosts?

| Cause | Description |
|-------|-------------|
| **IP not in use** (most common) | Site scope includes large CIDR blocks (e.g., `10.184.0.0/16`) but only a fraction are allocated |
| **Host powered off** | VMs in stopped/deallocated state (common in AWS/Azure) |
| **Blocking all probes** | Hardened hosts blocking ICMP and TCP SYN — indistinguishable from empty IPs |
| **Routing issue** | No route from scan engine to that subnet; packets dropped at a router |

### Recommendation

Tighten site scopes to match actual allocated address space, or migrate cloud sites to use **Azure/AWS Discovery Connections** which dynamically track only active instances.

---

## 6. Filtered Ports by Site

| Site | Engine Log | Filtered Count |
|------|-----------|---------------|
| E1/E2 Non-CDE Networks | 44.44 | **805,454** |
| AWS - Non-Prod | 44.14 | **408,964** |
| AWS - CDE | 47.7 | **181,360** |
| Azure Environment | 45.17 | 50,491 |
| Public External | 42.24820 | 4,102 |
| WVD asset pool | 44.3 | 2,714 |
| All others | — | 0 |

### What FILTERED Means

When nmap reports a port as `FILTERED`, the probe was sent but no response came back — something is silently dropping packets. This is distinct from `CLOSED` where the host responds with RST.

### Typical Causes (in order of likelihood)

| # | Cause | Detail |
|---|-------|--------|
| 1 | **Host-based firewall** | Security groups, NACLs, Windows Firewall, iptables — host is alive but port is blocked |
| 2 | **Network firewall/ACL** | Perimeter firewall or router ACL between engine and target |
| 3 | **Cloud security groups** | AWS/Azure default deny-all inbound; engine IP not in allowed rules |
| 4 | **IDS/IPS dropping traffic** | Intrusion prevention detects scan patterns and drops packets mid-scan |

### Recommendation

Investigate using **Azure and AWS Discovery Connections** in place of scanning large IP ranges for cloud sites. Discovery connections dynamically identify active instances without probing empty address space.

---

## 7. Bearer Token Findings

| Site | Log File | Bearer Token Count |
|------|----------|-------------------|
| E1/E2 Non-CDE Networks | 44.44.scan.0.log | **199** |
| AWS - Non-Prod | 44.14.scan.0.log | **104** |
| AWS - CDE | 47.7.scan.0.log | 1 |
| All other 21 logs | — | 0 |

### Analysis

These are likely **Kubernetes API servers, microservices, or container orchestration endpoints** running on port 8080 that require Bearer token authentication. InsightVM can detect the services but cannot perform deep assessment without valid tokens.

### Recommendation

These service types are better examined by a **cloud-focused tool like InsightCloudSec (ICS)** which understands container and Kubernetes contexts natively.

---

## 8. Scan Schedule Overlap Analysis

*Reviewed: June 2, 2026*

### Overlap 1 — June 3 at 01:00 EDT (exact same time)

| Scan | Site | Frequency | Engine |
|------|------|-----------|--------|
| AWS - CDE | SiteID 20 | Daily | **47** |
| Azure Environment | SiteID 27 | Daily | **45** |

**Verdict:** Different engines — **no engine contention**. Time overlap is cosmetic only.

---

### Overlap 2 — June 3, 09:00–09:30 EDT ⚠️

| Scan | Start | Frequency | Engine |
|------|-------|-----------|--------|
| DC3 - COLO - Network | 09:00 | Every 2 days | **44** |
| AT1 - COLO - Network | 09:30 | Every 2 days | **44** |

**Verdict: SAME ENGINE (44)** — 30-minute gap is insufficient for network scans. DC3 will likely still be running when AT1 kicks off, causing memory pressure on engine 44.

**Recommendation:** Stagger AT1 to **12:00 EDT** (+3 hours).

---

### Overlap 3 — June 4 at 01:00 EDT (exact same time)

| Scan | Site | Frequency | Engine |
|------|------|-----------|--------|
| Public External | SiteID 19 | Weekly | **42** |
| VPE Networks | SiteID 37 | Every 2 days | **45** |

**Verdict:** Different engines — **no engine contention**.

---

### Overlap 4 — June 7 at ~03:30 EDT

| Scan | Start | Frequency | Engine |
|------|-------|-----------|--------|
| WVD CDE Assets | 03:30 | Weekly | **47** |
| WVD asset pool | 03:33 | Weekly | **44** |

**Verdict:** Different engines — **no engine contention**. 3-minute gap is fine since they're on separate engines.

---

### Overlap 5 — VPN Workstations Double-Scheduled

| Scan | Start | Day |
|------|-------|-----|
| VPN Workstations | 17:30 | Tuesday |
| VPN Workstations | 17:45 | Wednesday |

**Verdict:** Same site (SiteID 28) scanned twice in ~24 hours. Not overlapping, but possibly redundant. Confirm if intentional (e.g., split scan windows for large asset counts).

---

### Schedule Recommendations Summary

| Issue | Recommendation | Priority |
|-------|---------------|----------|
| DC3 + AT1 on same engine | Stagger AT1 to 12:00 EDT | **High** |
| VPN Workstations double-schedule | Confirm intentional or consolidate | Medium |
| AWS-CDE + Azure same time | No action needed (different engines) | Low |
| Public External + VPE same time | No action needed (different engines) | Low |
| WVD CDE + WVD Pool same time | No action needed (different engines) | Low |

---

## Summary of All Recommendations

| # | Category | Recommendation | Impact |
|---|----------|---------------|--------|
| 1 | Scope | Tighten site scopes — remove unused CIDR blocks or use discovery connections | Reduces 690K dead host probes |
| 2 | Scope | Use AWS/Azure discovery connections for cloud sites | Eliminates broad IP scanning |
| 3 | Template | Disable enhanced logging | Reduces log file size |
| 4 | Template | Reduce UDP ports (keep only Scan Assistant if applicable) | Reduces scan duration |
| 5 | Template | Verify "Skip checks with Insight Agent" is enabled | Eliminates redundant assessment |
| 6 | Engine | Reduce simultaneous assets from 250 to 50-100 | Prevents OOM failures |
| 7 | Engine | Verify engine RAM and virtual vs. physical | Capacity planning |
| 8 | Schedule | Stagger DC3/AT1 COLO scans (same engine 44) | Prevents memory contention |
| 9 | Schedule | Confirm VPN Workstations double-schedule intent | Avoid wasted engine time |
| 10 | Firewall | Whitelist engine IPs on firewalls or deploy engines behind them | Fixes filtered port issue |
| 11 | Cloud | Use ICS or equivalent tool for Kubernetes/Bearer token services | Better container visibility |
