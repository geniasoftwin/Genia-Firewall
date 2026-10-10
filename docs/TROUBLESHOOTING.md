# Troubleshooting and diagnostics

[Русский](TROUBLESHOOTING_RU.md) · [VPN/TUN testing](VPN_TUN.md)

Record the GeniaFirewall build, Windows version, backend, global mode, app profile, TCP/UDP, inbound/outbound direction, and the time of failure **before** changing settings.

## Application is blocked unexpectedly

1. Check whether global **Block all** is active; it overrides per-app permissions.
2. Confirm protection/backend status. Full inbound app rules require **GeniaFirewall WFP**.
3. Inspect the exact app profile: **Allow all**, **Outgoing only**, **Incoming only**, **Block**, **Ask**.
4. If the application's EXE has changed after an update, re-evaluate the profile rather than trusting the previous binary.
5. For WFP, inspect the matching **WFP BLOCK** event (layer, reason, matched rule) at the failure time.
6. For LAN, inspect the receiving computer's inbound rule as well as the sending computer's outbound rule.

~~~powershell
Test-NetConnection <peer-IP> -Port <TCP-port>
Get-Service -Name GeniaFirewallService -ErrorAction SilentlyContinue
~~~

Test-NetConnection only checks the chosen TCP direction/port. It cannot prove UDP discovery or an application's own authentication succeeds.

## VPN/TUN or backend switching

Compare behavior with the tunnel disconnected and connected. Capture interface/route context and DNS/UDP failures. Check GeniaFirewall WFP filter cleanup before declaring Compatibility active. Do **not** manually remove unrelated WFP filters or protected binaries.

## Where are diagnostics?

- Portable UI settings and logs are kept locally beside the EXE under its `Data` directory for the applicable build.
- Privileged service state/logs are under `%ProgramData%\GeniaFirewall`.
- The UI's Settings/Diagnostics area shows backend status, rule counts, and relevant WFP events (names may vary by version).

Share only relevant redacted timestamps/lines. Remove usernames, internal hostnames, passwords, personal paths, and unrelated IPs.

## Reports

Use [GitHub Issues](https://github.com/geniasoftwin/Genia-Firewall/issues/new/choose) for normal reproducible bugs. Report suspected security vulnerabilities privately using [SECURITY.md](../SECURITY.md).
