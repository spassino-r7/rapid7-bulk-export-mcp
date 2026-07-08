# Firewall Exception Request — Mac to Lab VLAN

## Issue

My corporate Mac cannot reach hosts on the 192.168.1.0/24 VLAN from within the **Kiro IDE terminal**. Connections fail with "No route to host."

**Key finding:** The same connections succeed from a regular macOS Terminal.app session. This means it's NOT a network-level firewall rule — it's an **application-level restriction** that blocks the Kiro process (or its child processes) from making outbound network connections while allowing Terminal.app.

This is likely caused by:
- macOS Application Firewall blocking unsigned/unrecognized app processes
- MDM endpoint security software (CrowdStrike, SentinelOne, Jamf Protect, etc.) with per-application network policies
- A code-signing or app allowlist that doesn't include Kiro/Electron-based IDE processes

## What I Need

Allow the Kiro IDE application (and its child processes) to make outbound TCP connections to the 192.168.1.0/24 subnet, matching the same access that Terminal.app already has.

Specific destinations needed:

| Destination | Port | Service | Purpose |
|-------------|------|---------|---------|
| 192.168.1.162 | 3790 | InsightVM Security Console (HTTPS API) | Vulnerability management API access |
| 192.168.1.244 | 3790 | Metasploit Pro (HTTPS API) | Exploit module mapping |
| 192.168.1.0/24 | 22 | SSH | General lab access |

Ideally, allow all outbound TCP to 192.168.1.0/24 — these are all internal lab/security assets I manage.

## Current Workaround

Using an SSH tunnel through a jump host that CAN reach the VLAN:

```bash
# Tunnel InsightVM console to localhost
ssh -L 3790:192.168.1.162:3790 <jump-host> -N
```

Then connecting to `https://localhost:3790` instead of `https://192.168.1.162:3790`.

This works but adds operational overhead — a new tunnel must be established for each session, and any tool that needs direct connectivity (MCP servers, scripts) must be reconfigured to use localhost.

## Verification

Once the exception is applied, I should be able to run:
```bash
curl -k https://192.168.1.162:3790/api/3/info
```

And get a response from the InsightVM console without needing the SSH tunnel.

## Impact if Not Resolved

- Daily security reporting workflows require manual tunnel setup
- Automated tooling (MCP servers for vulnerability enrichment) cannot reach the console directly
- Increases friction for all InsightVM API operations
