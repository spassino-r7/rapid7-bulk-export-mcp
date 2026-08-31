# InsightVM Scan Engine Connectivity Troubleshooting Report

**Engine:** 192.168.17.50  
**Console:** 52.39.156.42:40815 (Rapid7 Cloud-hosted InsightVM)  
**Issue:** Recurring loss of connectivity between distributed scan engine and cloud console  
**Analysis Period:** July 29, 2025 – December 3, 2025  
**Logs Reviewed:** nse.log, nse.log.0, nse.log.1 (~1.5 GB total)  
**Report Date:** July 10, 2026

---

## Executive Summary

The scan engine at 192.168.17.50 is experiencing recurring SSL connection failures to the cloud console at 52.39.156.42:40815. The pattern is consistent across five months of log data and is characteristic of a **network-layer device (firewall, NAT, or proxy) terminating long-lived TLS sessions** between the engine and the console.

The engine self-recovers via automatic restart each time, but connectivity is interrupted during the failure/restart cycle, causing missed heartbeats and temporary loss of console visibility.

---

## Findings

### Pattern 1: SSL Connection Failure (Primary Issue)

**Frequency:** 9 occurrences across 5 months (approximately every 1–2 weeks)

**Log Evidence:**

```
2025-12-03T12:24:57 [ERROR] [Thread: NSC @ 192.168.17.50:46096->52.39.156.42:40815]
  Error encountered during remote operation
2025-12-03T12:24:57 [ERROR] [Thread: NSC @ 192.168.17.50:46096->52.39.156.42:40815]
  NSC FAILURE => javax.net.ssl.SSLException
```

**Dates observed:**
- 2025-07-29 14:07
- 2025-08-01 23:02
- 2025-08-12 12:34
- 2025-09-01 17:51
- 2025-09-05 17:59
- 2025-09-23 06:04
- 2025-10-24 06:45
- 2025-12-03 12:24 (multiple in sequence)

**Technical Detail:**

The `javax.net.ssl.SSLException: null` occurs during `SSLSocketInputRecord.readHeader` — the engine is reading from the TLS socket and the remote end has already closed or reset the connection. The full stack trace shows:

```
at java.base/sun.security.ssl.SSLSocketInputRecord.read
at java.base/sun.security.ssl.SSLSocketInputRecord.readHeader
at java.base/sun.security.ssl.SSLSocketInputRecord.bytesInCompletePacket
at java.base/sun.security.ssl.SSLSocketImpl.readApplicationRecord
```

This is not a certificate issue, cipher mismatch, or authentication failure. The TLS handshake completes successfully — the connection is established and then **abruptly terminated mid-session by an external factor**.

### Supporting Evidence: Excessive TLS Renegotiation

Prior to each failure, the log shows SSL handshakes completing every ~90 seconds for hours:

```
2025-12-03T08:52:11 [INFO] SSL handshake complete.
2025-12-03T08:52:23 [INFO] SSL handshake complete.
2025-12-03T08:53:55 [INFO] SSL handshake complete.
...repeating every 90 seconds...
```

A persistent TLS connection should not need to renegotiate this frequently. This indicates the connection is being **forcibly closed at regular intervals**, requiring the engine to reconnect each time. The eventual SSLException occurs when this reconnection cycle fails entirely.

---

### Pattern 2: Read Timeout (Secondary Issue)

**Frequency:** 2 occurrences (Aug 1, Aug 11)

```
2025-08-01T23:02:37 [ERROR] NSC FAILURE => Read timed out
2025-08-11T07:57:06 [ERROR] NSC FAILURE => Read timed out
```

The console did not respond within the engine's socket timeout. This may indicate console-side load or a network path disruption that recovered before a full SSL failure.

---

### Pattern 3: Stuck Auto-Update Restart (One-Time Issue)

**Date:** October 6–7, 2025

The engine received an auto-update command on Oct 6 at 12:38 but was running an active scan. It waited for the scan to complete before restarting. The scan ran for **over 12 hours**, during which the console repeatedly attempted communication and received:

```
NSC FAILURE => Scan engine is restarting. Unable to save update table.
```

This repeated every 2 hours for 12+ hours until the scan finished at Oct 7 12:52. This is expected behavior — the engine protects in-progress scans — but the extended duration suggests an unusually long-running scan (possibly a very large site or a scan that hung on a target).

---

## Root Cause Assessment

The primary issue is **not** with the scan engine or the InsightVM console software. The evidence points to a **network-layer device between the engine (192.168.17.50) and the internet** that is:

1. **Terminating TCP sessions** after an idle timeout, forcing the engine to re-establish the TLS connection every 90 seconds
2. **Occasionally failing to allow reconnection**, causing the full SSLException and engine restart

Common causes:

| Possible Cause | Likelihood | Evidence |
|---|---|---|
| Stateful firewall TCP session timeout (60–120 sec) | **High** | Explains the 90-second renegotiation pattern |
| SSL/TLS deep packet inspection (DPI) | Medium | DPI proxies can cause intermittent SSL failures on long-lived connections |
| NAT table entry expiration | Medium | Engine is on RFC 1918 address; NAT timeout could expire the mapping |
| Load balancer session limit | Low | Console is a single AWS IP, not load-balanced from the engine's perspective |

---

## Recommendations

### Immediate Actions

1. **Identify the firewall/network device** between 192.168.17.50 and the internet gateway
2. **Review TCP session timeout settings** for outbound connections on port 40815 — increase to at least **3600 seconds (1 hour)**
3. **Whitelist 52.39.156.42:40815** from SSL inspection / deep packet inspection
4. **Verify NAT timeout** on the device performing NAT for 192.168.17.50 — should be at least 3600 seconds for established TCP connections

### Validation

After making changes, monitor the nse.log for:
- Reduced frequency of "SSL handshake complete" messages (should be infrequent, not every 90 seconds)
- Absence of `NSC FAILURE => javax.net.ssl.SSLException` entries
- Engine uptime visible in the console Administration → Engines page without unexpected drops

### Additional Consideration

For the stuck auto-update issue (Oct 6–7): review scan configurations for the "Italy Region" site. If scans routinely exceed 12 hours, consider splitting into smaller sites or setting a maximum scan duration to prevent update delays.

---

## Environment Details

| Component | Detail |
|---|---|
| Engine IP | 192.168.17.50 |
| Console IP | 52.39.156.42 |
| Console Port | 40815 |
| Engine Communication | Outbound TLS from engine to console |
| Hosting Model | Cloud-hosted InsightVM console (AWS us-west-2) |
| Scan Sites | "Italy Region" (192.168.11.x, 192.168.17.x, 192.168.18.x subnets) |

---

*Report prepared from scan engine log analysis. No credentials or sensitive configuration data were accessed during this review.*
