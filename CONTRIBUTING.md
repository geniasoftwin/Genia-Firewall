# Contributing to GeniaFirewall

[Русская версия](CONTRIBUTING_RU.md)

Thank you for helping test or improve GeniaFirewall. Because this is a security-sensitive firewall and Windows service, small policy changes can have system-wide effects. Contributions should be easy to review, reproduce, and roll back.

## You do not need to write code

Useful contributions include:

- reproducing bugs on Windows 10/11;
- testing Ethernet, Wi-Fi, LAN, VPN, and TUN scenarios;
- verifying inbound/outbound application rules;
- improving documentation or translations;
- proposing UI/UX improvements;
- reviewing WFP, service lifecycle, ACL, IPC, and cleanup logic;
- sending focused code fixes.

See [TESTING.md](TESTING.md) for the public test matrix.

## Development environment

- Windows 10/11 x64
- .NET 10 SDK
- Git
- Administrator privileges for service/WFP runtime tests

Basic build:

```cmd
dotnet restore GeniaFirewall.sln
dotnet build GeniaFirewall.sln --configuration Release
```

## Pull request rules

Keep a PR focused. Explain:

- what problem it solves;
- which backend is affected;
- whether WFP layers, filter actions, weights, directions, interface scope, or cleanup behavior change;
- whether service privileges, ACLs, IPC, persistence, installation, or rollback behavior change;
- what you tested on real Windows.

Do not commit publish output, binaries, personal logs, captured traffic, credentials, private paths, certificates, signing material, or machine-specific state.

## Security-sensitive changes

For WFP/service changes, document the security impact. Fail-open behavior must be called out explicitly. Cleanup, rollback, backend handoff, and reboot behavior are part of the change, not afterthoughts.

## Pull request test checklist

At minimum:

- Release build succeeds;
- CI is green;
- CodeQL is green;
- app Allow/Block/Ask behavior is unchanged unless intentionally modified;
- directional rules are tested if policy mapping changed;
- Block all is tested if global filters changed;
- backend switching leaves no GeniaFirewall residual WFP filters;
- reboot behavior is tested when persistence/lifecycle code changed.

## Security reports

Do not report a suspected vulnerability in a public issue or pull request. Follow [SECURITY.md](SECURITY.md) and use GitHub's private security advisory flow.
