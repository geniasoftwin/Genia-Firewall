# GeniaFirewall 0.7.3 Stable

Licensed under GPL-3.0-only. See `LICENSE`.

Stable Windows 10/11 portable application firewall built with WPF/.NET 10 and a standalone WFP backend hosted by `GeniaFirewall.Service`.

The final release promotes the Windows-accepted RC1 without policy or WFP logic changes. It keeps the dynamic-session lifecycle verification, TUN-aware physical boundary policy, interface-independent application rules, narrow GeniaProxy readiness permits, and the `PROBE > APP > GLOBAL` weight plan.

Stability hardening:

- correct network-byte-order decoding of IPv4 WFP telemetry;
- UTC timestamp on the last observed BLOCK event;
- readable `not-found (ok)` startup cleanup results;
- a bounded IPC request-read timeout;
- redaction of executable paths, endpoints and internal errors from unprivileged status responses;
- fail-closed portable packaging with published EXE version checks and SHA-256 output.

Run `publish-portable.cmd`. Output:

```text
publish\GeniaFirewall-0.7.3-Stable-win-x64\
publish\GeniaFirewall-0.7.3-Stable-Portable-win-x64.zip
publish\GeniaFirewall-0.7.3-Stable-SHA256.txt
```

Version: UI / Service / Protocol `0.7.3.4`, IPC v13, pipe `GeniaFirewall.Service.v13`.

Run `install-service.cmd` as Administrator from the published directory. The installer copies the privileged service binary to `%ProgramFiles%\GeniaFirewall\Service` and restricts its ACL to `SYSTEM` and local Administrators; the UI remains portable.

## Security

Do not publish suspected vulnerabilities in a public issue. Use the repository's private security-advisory channel. See `SECURITY.md` for the supported version and reporting guidance.

A true kernel pre-connect prompt is not implemented; holding the first connect requires a WFP callout driver.
