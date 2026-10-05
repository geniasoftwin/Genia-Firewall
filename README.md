# GeniaFirewall 0.7.4 RC2

Licensed under GPL-3.0-only. See `LICENSE`.

Portable Windows 10/11 application firewall built with WPF/.NET 10 and a standalone WFP backend. Version 0.7.4 RC2 hardens the **Single-EXE Portable** lifecycle with transactional service updates and complete SCM verification before a Stable release.

## One user-facing executable

The portable archive contains only:

```text
GeniaFirewall.exe
```

On first launch, after UAC consent, the UI extracts its embedded service into `%ProgramFiles%\GeniaFirewall\Service`, verifies the payload with SHA-256, restricts the directory, binary, and SCM service object to `SYSTEM` and local Administrators, and verifies the complete SCM configuration plus service IPC identity.

Updates retain the previous protected service as `.previous` until the new payload passes SHA-256, SCM, ACL, startup, and IPC checks. A failed update restores and re-verifies the previous payload.

Settings provide explicit service activation and deactivation. Safe deactivation verifies an empty WFP runtime, synchronizes Windows Firewall Compatibility, then stops and removes the service and protected binary.

After launch, only the portable `Data` directory is created beside the EXE. It holds user settings, application rules, backups, and UI logs.

## Build

Run on Windows with the .NET 10 SDK:

```cmd
publish-portable.cmd
```

Output:

```text
publish\GeniaFirewall-0.7.4-RC2-win-x64\GeniaFirewall.exe
publish\GeniaFirewall-0.7.4-RC2-SingleExe-Portable-win-x64.zip
publish\GeniaFirewall-0.7.4-RC2-SHA256.txt
```

The build fails closed on version mismatch, missing embedded service payload, unexpected portable output files, packaging failure, or SHA-256 failure.

Version: UI / Service / Protocol `0.7.4.0`, IPC v13, pipe `GeniaFirewall.Service.v13`.

## Security

The service executable and service-owned state under Program Files and ProgramData reject reparse points and use exact protected ACLs. SCM verification covers the quoted path, own-process type, LocalSystem account, automatic start, normal error control, BFE dependency, display name, and service-object DACL. Compatibility startup removes persisted WFP policy before service start and then verifies an empty runtime through IPC.

This RC is not Authenticode-signed. SHA-256 verifies extraction integrity but does not establish publisher identity; both the embedded service and UI must be signed before a public Stable release.

Do not publish suspected vulnerabilities in a public issue. Use the repository's private security-advisory channel; see `SECURITY.md`.

A true kernel pre-connect prompt is not implemented; holding the first connect requires a WFP callout driver.
