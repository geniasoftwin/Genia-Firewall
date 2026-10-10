# GeniaFirewall security model and limitations

[Русский](SECURITY_MODEL_RU.md) · [Private security reporting](../SECURITY.md)

This document describes **design controls**, not a security certification or guarantee that bypasses are impossible.

## Trust boundaries

- **Portable UI:** accepts user choices, holds settings, local application metadata and diagnostic views.
- **GeniaFirewall.Service (LocalSystem):** owns privileged WFP policy operations; the UI communicates through authorized local IPC.
- **Windows WFP/BFE:** performs actual filter evaluation; filter layer, action, weight and direction matter.
- **Other WFP providers:** can coexist and affect effective enforcement.

## Safeguards, especially in the 0.7.4 RC lifecycle

- Embedded service installed under protected Program Files, not executed from the writable portable directory.
- SHA-256 checks for the embedded/installed service payload; protected file and SCM service-object ACLs.
- Verification of service path, LocalSystem configuration, BFE dependency, startup settings and IPC identity.
- Transactional service update with a protected prior-version rollback path.
- Dynamic WFP runtime session and explicit cleanup verification when leaving WFP or deactivating the service.
- Application executable fingerprint/change checks: an updated or replaced EXE should not inherit implicit trust blindly.

These RC-specific lifecycle measures should not be presented as identical to the 0.7.3 Stable manual installer.

## Privacy and artifact integrity

Developer analytics and automatic log uploading are not built in. Portable rules/UI logs are local to the program; privileged service data/diagnostics are under `%ProgramData%\GeniaFirewall`. Optional reverse DNS goes through the Windows-configured resolver and may expose the queried address.

**SHA-256 does not authenticate a publisher.** 0.7.4 RC should be treated as a test build until both service and UI are Authenticode-signed and all release gates are met. See [code signing](../CODE_SIGNING_POLICY.md).

## Limits and responsible use

- No custom kernel callout driver, and thus no guaranteed kernel-held pre-connect Ask.
- Windows Firewall Compatibility does not provide bidirectional app WFP semantics.
- Firewall rules can interrupt RDP, LAN services, DNS, VPN/TUN traffic and other critical activity.
- Report suspected vulnerabilities **privately** via [SECURITY.md](../SECURITY.md); never paste exploit instructions, keys or sensitive logs into a public Issue.
