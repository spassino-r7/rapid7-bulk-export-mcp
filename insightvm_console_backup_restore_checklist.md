# InsightVM Console Backup & Restore Checklist

A step-by-step checklist for migrating an InsightVM Security Console to a new host when the console hostname will change.

> **Scenario**: You are moving the console to a new server with a different hostname/IP.  
> **Impact**: Scan engines will need to be re-paired, and the Insight Platform management entry must be updated.

---

## Important: Version Matching

Both consoles (old and new) must be on the **same product version** at the time of backup and restore. The recommended approach:

1. Update the old console to the latest product version
2. Install the same version on the new console
3. Run the backup on the old console
4. Run the restore on the new console

Mismatched versions between backup and restore can cause failures or data issues.

---

## Phase 1: Pre-Backup (Old Console)

- [ ] **Update console to the latest product version**  
  Administration → Updates → check for and apply any pending updates. Note the exact version number (e.g., 6.6.XXX).

- [ ] **Upgrade PostgreSQL if needed**  
  If your console is older than version 6.6.230, complete the [PostgreSQL database migration](https://docs.rapid7.com/insightvm/postgresql-database-migration-guide/) first. Backups from pre-migration databases cannot be restored on new installs.

- [ ] **Stop all running scans**  
  Confirm ALL engines (local and distributed) are idle. No scans should be in progress.

- [ ] **Note your keystore password**  
  Find it in `creds.kspw`:
  - Linux: `/opt/rapid7/nexpose/shared/conf/creds.kspw`
  - Windows: `C:\Program Files\Rapid7\nexpose\shared\conf\creds.kspw`
  
  You'll need this during restore to recover scan credentials.

- [ ] **Record your current engine pairing info**  
  For each distributed engine, note:
  - Engine name
  - Engine IP/hostname
  - Pairing method (Console-to-Engine or Engine-to-Console)
  - Which sites use each engine

- [ ] **Record the current console hostname/IP**  
  You'll need this to know what to change in engine configs later.

---

## Phase 2: Create the Backup (Old Console)

- [ ] **Navigate to**: Administration → Database → Backup and Retention → Backup/Restore tab

- [ ] **Create a Platform-Independent backup**  
  - Enter a description (e.g., "Migration to new-server-name YYYY-MM-DD")
  - ✅ Check **Platform-independent** (required for cross-host restore)
  - ✅ Check **Validate constraints** (recommended — fixes index issues)
  - Click **Start Backup** → confirm **Backup System**

- [ ] **Wait for backup to complete**  
  Console enters maintenance mode. Global Admins can log in to watch progress. Console auto-restarts when done.

- [ ] **Copy backup to external media**  
  Backup location:
  - Linux: `/opt/rapid7/nexpose/nsc/backups/`
  - Windows: `C:\Program Files\Rapid7\nexpose\nsc\backups\`
  
  Copy the backup file(s) to a USB drive, network share, or SCP to the new server.

- [ ] **Shut down the old console**  
  Stop the Nexpose/InsightVM service on the old server to prevent it from communicating with the Insight Platform.
  - Linux: `sudo systemctl stop nexposeconsole.service`
  - Windows: Stop the "Rapid7 Security Console" service

---

## Phase 3: Prepare the New Console

- [ ] **Install a fresh Security Console on the new host**  
  Download from [Rapid7](https://docs.rapid7.com/insightvm/download/). Install the **same version** that is running on the old console.

- [ ] **Verify the version matches the old console**  
  Log in and check Administration → Updates. The version should match exactly what you noted in Phase 1.

- [ ] **Do NOT activate any license keys**  
  ⚠️ **CRITICAL**: Do not request or activate any new or temporary license keys during installation. Your existing license will transfer automatically as part of the restore.

- [ ] **Do NOT activate on the Insight Platform**  
  ⚠️ **CRITICAL**: Skip any Insight Platform activation prompts. The backup already contains the activation data. Re-activating causes sync issues.

- [ ] **Create the `backups` directory on the new host (if it does not already exist)**  
  This directory does not exist on fresh installs — you must create it manually:
  - Linux: `mkdir -p /opt/rapid7/nexpose/nsc/backups`
  - Windows: Create `C:\Program Files\Rapid7\nexpose\nsc\backups\`

- [ ] **Transfer backup files into the `backups` directory created above**

---

## Phase 4: Restore (New Console)

- [ ] **Log in to the new console web UI**

- [ ] **Navigate to**: Administration → Database → Backup and Retention → Backup/Restore tab

- [ ] **Locate your backup** in the "Restore Local Backup" table

- [ ] **Click the Restore icon** next to your backup → confirm **Restore System**

- [ ] **If prompted for keystore password**: Enter the password from `creds.kspw` (noted in Phase 1)
  - If you don't have it, click "Restore (No Password)" — but scan credentials will NOT be restored

- [ ] **Wait for restore to complete**  
  Console enters maintenance mode. Auto-restarts when successful.
  
  ❌ If restore fails or console doesn't restart → contact [Rapid7 Support](https://www.rapid7.com/for-customers/)

---

## Phase 5: Post-Restore Verification (New Console)

- [ ] **Log in and verify restored data**  
  Check that sites, scan templates, users, reports, and asset data are all present.

- [ ] **Reset external authentication** (if applicable):
  - **LDAP**: Restart the console to re-establish LDAP communication
  - **SAML**: Update Base Entity URL, reimport IdP metadata, restart console
  - **CyberArk AIM**: Reinstall on the new host

---

## Phase 6: Re-Pair Scan Engines

Since the console hostname/IP changed, engines need to be updated.

### Engines paired Console-to-Engine (console initiates connection)
- [ ] These should reconnect automatically **IF** firewall rules allow the new console IP to reach the engine
- [ ] Update firewall rules to allow new console IP → engine communication (port 40814)

### Engines paired Engine-to-Console (engine initiates connection)
- [ ] On each engine, edit `consoles.xml`:
  - Linux: `/opt/rapid7/nexpose/nse/conf/consoles.xml`
  - Windows: `C:\Program Files\Rapid7\NeXpose\nse\conf\consoles.xml`
- [ ] Change the `lastAddress=` value to the new console IP or hostname
- [ ] Restart each engine after editing

### Verify all engines
- [ ] In the console UI, go to Administration → Scan Engines
- [ ] Confirm each engine shows status **Active** or **Healthy**

---

## Phase 7: Update Insight Platform Management Entry

Since the console hostname changed, the Insight Platform needs to know the new address.

- [ ] **Log in to** [insight.rapid7.com](https://insight.rapid7.com)
- [ ] **Navigate to**: Settings → Platform Management (or Data Collection Management)
- [ ] **Find your Security Console** in the list
- [ ] **Update the hostname/IP** to reflect the new console address
- [ ] **Verify connectivity** — confirm the console shows as connected/active in the platform

---

## Phase 8: Final Cleanup

- [ ] **De-provision the old console server**  
  ⚠️ Do this to prevent accidental duplicate sync. The old server should never connect to the internet again.

- [ ] **Run a test scan** from the new console to confirm end-to-end functionality

- [ ] **Verify cloud sync**  
  Check that scan results from the new console appear in the Insight Platform (InsightVM cloud view)

- [ ] **Update any automation/scripts** that reference the old console hostname
  - API scripts
  - Scheduled tasks or cron jobs
  - DNS entries or load balancer configs

---

## Quick Reference

| Item | Linux Path | Windows Path |
|------|-----------|--------------|
| Backups | `/opt/rapid7/nexpose/nsc/backups/` | `C:\Program Files\Rapid7\nexpose\nsc\backups\` |
| Keystore password | `/opt/rapid7/nexpose/shared/conf/creds.kspw` | `C:\Program Files\Rapid7\nexpose\shared\conf\creds.kspw` |
| Engine consoles.xml | `/opt/rapid7/nexpose/nse/conf/consoles.xml` | `C:\Program Files\Rapid7\NeXpose\nse\conf\consoles.xml` |

---

## Common Pitfalls

| Mistake | Consequence |
|---------|-------------|
| Activating new console on Insight Platform | Sync issues; unnecessary since backup contains activation |
| Forgetting keystore password | Scan credentials won't restore (you'll have to re-enter them all) |
| Not upgrading PostgreSQL before backup | Backup won't restore on the new install |
| Leaving old server running | Risk of accidental reconnection and data corruption |

---

*Sources: [Migrate a backup to a new Security Console host](https://docs.rapid7.com/insightvm/migrate-backup-to-new-security-console-host/), [Database Backup, Restore, and Data Retention](https://docs.rapid7.com/insightvm/database-backuprestore-and-data-retention/)*
