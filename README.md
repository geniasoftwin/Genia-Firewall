# GeniaFirewall 0.7.4 RC1

Licensed under GPL-3.0-only. See `LICENSE`.

Portable Windows 10/11 application firewall built with WPF/.NET 10 and a standalone WFP backend. Version 0.7.4 RC1 validates the new **Single-EXE Portable** lifecycle before a Stable release.

## One user-facing executable

The portable archive contains only:

```text
GeniaFirewall.exe
```

On first launch, after UAC consent, the UI extracts its embedded service into `%ProgramFiles%\GeniaFirewall\Service`, verifies the written payload with SHA-256, restricts the directory, binary, and SCM service object to `SYSTEM` and local Administrators, registers the quoted service path, and verifies startup plus IPC.

Settings provide explicit service activation and deactivation. Safe deactivation verifies an empty WFP runtime, synchronizes Windows Firewall Compatibility, then stops and removes the service and protected binary.

After launch, only the portable `Data` directory is created beside the EXE. It holds user settings, application rules, backups, and UI logs.

## Build

Run on Windows with the .NET 10 SDK:

```cmd
publish-portable.cmd
```

Output:

```text
publish\GeniaFirewall-0.7.4-RC1-win-x64\GeniaFirewall.exe
publish\GeniaFirewall-0.7.4-RC1-SingleExe-Portable-win-x64.zip
publish\GeniaFirewall-0.7.4-RC1-SHA256.txt
```

The build fails closed on version mismatch, missing embedded service payload, unexpected portable output files, packaging failure, or SHA-256 failure.

Version: UI / Service / Protocol `0.7.4.0`, IPC v13, pipe `GeniaFirewall.Service.v13`.

## Security

The service executable and service-owned state under Program Files and ProgramData reject reparse points and use protected ACLs. Compatibility startup clears and verifies stale WFP policy before proceeding. An incomplete activation stops the dynamic service session.

This RC is not Authenticode-signed. SHA-256 verifies extraction integrity but does not establish publisher identity; signing both the UI and embedded service remains a Stable-release goal.

Do not publish suspected vulnerabilities in a public issue. Use the repository's private security-advisory channel; see `SECURITY.md`.

A true kernel pre-connect prompt is not implemented; holding the first connect requires a WFP callout driver.
