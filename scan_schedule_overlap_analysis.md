# InsightVM Scan Schedule Overlap Analysis

**Date:** June 2, 2026  
**Prepared by:** Security Operations  
**Source:** InsightVM Console — `scan schedules` command output

---

## Executive Summary

Analysis of the current InsightVM scan schedule identified **5 overlap conditions** where scans either start at the same time or within a window likely to cause resource contention on shared scan engines. Overlapping scans can result in:

- Extended scan durations (engine CPU/memory contention)
- Incomplete scans hitting the scan window timeout
- Missed assets due to throttled network probes
- Inaccurate scan-to-scan comparison metrics

---

## Overlap Findings

### 1. AWS-CDE + Azure Environment — Exact Same Start Time

| Field | AWS - CDE (Site 20) | Azure Environment (Site 27) |
|-------|---------------------|----------------------------|
| Start Time | 01:00 EDT | 01:00 EDT |
| Frequency | Daily | Daily |
| Repeats | Every day since Mar 2021 | Every day since Jan 2021 |

**Risk:** High — these collide every single day. If using the same scan engine or engine pool, both scans compete for the same resources 365 days/year.

**Recommendation:** Move Azure Environment to **03:00 EDT** to allow AWS-CDE to complete first (~2 hour buffer for cloud asset scanning).

---

### 2. DC3-COLO + AT1-COLO — 30-Minute Gap

| Field | DC3 - COLO (Site 30) | AT1 - COLO (Site 29) |
|-------|---------------------|---------------------|
| Start Time | 09:00 EDT | 09:30 EDT |
| Frequency | Every 2 days | Every 2 days |
| Same cycle | Yes (both started Dec 22, 2021) | Yes (both started Dec 22, 2021) |

**Risk:** Medium-High — network infrastructure scans (COLO sites) typically run 1-4 hours depending on asset count. DC3 will almost certainly still be running when AT1 starts 30 minutes later.

**Recommendation:** Move AT1-COLO to **12:00 EDT** (3-hour gap) or to an alternating day cycle if scan engine capacity is limited.

---

### 3. Public External + VPE Networks — Same Start Time (Periodic Collision)

| Field | Public External (Site 19) | VPE Networks (Site 37) |
|-------|--------------------------|----------------------|
| Start Time | 01:00 EDT | 01:00 EDT |
| Frequency | Weekly (Wednesday night) | Every 2 days |
| Collision Days | Every 2 weeks when cycles align | — |

**Risk:** Medium — these don't collide daily, but when VPE's bi-daily rotation lands on the same night as the weekly external scan, both fire simultaneously at 01:00.

**Recommendation:** Move VPE Networks to **04:00 EDT** to avoid collision with both this scan and the AWS-CDE/Azure scans that also run at 01:00.

---

### 4. WVD CDE Assets + WVD Asset Pool — 3-Minute Gap

| Field | WVD CDE Assets (Site 41) | WVD Asset Pool (Site 40) |
|-------|--------------------------|--------------------------|
| Start Time | 03:30 EDT | 03:33 EDT |
| Frequency | Weekly (Sunday) | Weekly (Sunday) |
| Behavior | Stop on window end | Continue until complete |

**Risk:** Medium — these are essentially concurrent. The 3-minute offset provides no meaningful separation. Both target WVD (Windows Virtual Desktop) assets and likely share significant IP overlap.

**Recommendation:**  
- Option A: **Combine into a single scan** if the asset scope overlaps significantly
- Option B: Move WVD Asset Pool to **06:00 EDT** (2.5-hour gap) to let CDE complete first
- Note: CDE is set to "stop" (hard window), Pool is set to "continue" — ensure the CDE scan has enough time to complete before it's cut off

---

### 5. VPN Workstations — Double Schedule on Same Site

| Field | Schedule 1 | Schedule 2 |
|-------|-----------|-----------|
| Site | VPN Workstations (Site 28) | VPN Workstations (Site 28) |
| Start Time | Tuesday 17:30 EDT | Wednesday 17:45 EDT |
| Frequency | Weekly | Weekly |

**Risk:** Low (no time overlap) — but this is **the same site scanned twice in 24 hours**. This may be intentional (e.g., split asset coverage or different scan templates), but if not, it's redundant and wastes engine capacity.

**Recommendation:** Confirm whether both schedules are intentional. If the same template and target scope:
- Remove one schedule
- Or consolidate into a single scan at an off-peak time

---

## Current Schedule Heat Map

```
Time (EDT)     Mon    Tue    Wed    Thu    Fri    Sat    Sun
─────────────────────────────────────────────────────────────
01:00          AWS    AWS    AWS    AWS    AWS    AWS    AWS
               AZU    AZU    AZU    AZU    AZU    AZU    AZU
                             PUB
                      VPE          VPE          VPE
03:30                                                   WVD-CDE
03:33                                                   WVD-Pool
04:00                             E2/C1        E2/C1
09:00                 DC3          DC3          DC3
09:30                 AT1          AT1          AT1
16:00          GLR          GLR          GLR
               ALP                 ALP                 ALP
17:30                 VPN
17:45                        VPN
19:00          HNV          HNV          HNV
               ATL                 ATL                 ATL
23:00                 E1/E2        E1/E2        E1/E2
─────────────────────────────────────────────────────────────
```

*Note: Bi-daily scans shown on approximate cycle days*

---

## Recommended Revised Schedule

| Scan | Current | Proposed | Change |
|------|---------|----------|--------|
| Azure Environment | 01:00 | **03:00** | +2 hours |
| AT1-COLO Network | 09:30 | **12:00** | +2.5 hours |
| VPE Networks | 01:00 | **04:00** | +3 hours |
| WVD Asset Pool | 03:33 | **06:00** | +2.5 hours |
| VPN Workstations (Wed) | 17:45 | **Review/Remove** | Confirm need |

---

## Impact Assessment

| Metric | Before | After (Proposed) |
|--------|--------|-----------------|
| Daily collisions at 01:00 | 2-4 scans | 1 scan |
| Engine contention events/week | ~14+ | ~2 |
| Scans with <30min separation | 4 pairs | 0 pairs |
| Minimum gap between scans on same engine | 0 min | 120 min |

---

## Next Steps

1. Identify which scan engine(s) are assigned to each site
2. Confirm VPN Workstations double-schedule is intentional
3. Validate WVD CDE/Pool asset overlap percentage
4. Implement revised schedule during next change window
5. Monitor scan durations for 2 weeks post-change to confirm improvement
