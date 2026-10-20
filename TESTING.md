# GeniaFirewall public testing guide

[Русская версия](TESTING_RU.md)

Real Windows testing is one of the most valuable contributions to GeniaFirewall.

## Safety

Use a non-critical test machine when possible. Firewall policy can interrupt network access, VPN/TUN traffic, LAN services, remote administration, and update processes.

Before reporting a defect, record:

- GeniaFirewall version/build;
- Windows version;
- active backend;
- global mode;
- application rule profile;
- connection direction and protocol.

Do not publish credentials, private keys, personal paths, or unrelated private network data.

## Core smoke test

1. Start GeniaFirewall and confirm the service/backend status.
2. Use **Normal** mode.
3. Test one ordinary outbound application.
4. Test a LAN application with a TCP listener.
5. Set the application to **Allow all** and verify connections in both directions.
6. Change to **Outgoing only** and verify inbound is blocked.
7. Change to **Incoming only** and verify outbound is blocked.
8. Return to **Allow all** and confirm normal bidirectional operation.
9. Restart GeniaFirewall and verify the saved profile remains unchanged.
10. Reboot Windows and repeat the key connection test.

Example TCP reachability check:

```powershell
Test-NetConnection <peer-IP> -Port <port>
```

## Backend switching

When switching between GeniaFirewall WFP and Windows Firewall Compatibility:

- WFP deactivation must be confirmed before Compatibility is considered active;
- GeniaFirewall runtime filters should be zero after WFP shutdown;
- switching back to WFP should rebuild policy cleanly.

Remember that Windows Firewall Compatibility is not expected to provide the full inbound/outbound semantics of the WFP backend.

## Block all

In Block all mode, expected behavior is global blocking regardless of per-app Allow rules. Saved application rules must remain intact and become effective again after leaving Block all.

## VPN / TUN

Useful tests include connect/disconnect/reconnect cycles, sleep/resume, backend switching with the tunnel active, and normal application traffic through and outside the tunnel.

## What to attach to a bug

Prefer the smallest relevant diagnostic excerpt. Include timestamps around the failure and the application path only when needed. Redact usernames, credentials, unrelated endpoints, and private paths.

If the issue may be a vulnerability, stop and use [SECURITY.md](SECURITY.md) instead of a public issue.
