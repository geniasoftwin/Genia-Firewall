# GeniaFirewall

[Русский](README_RU.md)

[![CI](https://github.com/geniasoftwin/Genia-Firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/geniasoftwin/Genia-Firewall/actions/workflows/ci.yml)
[![CodeQL](https://github.com/geniasoftwin/Genia-Firewall/actions/workflows/codeql.yml/badge.svg)](https://github.com/geniasoftwin/Genia-Firewall/actions/workflows/codeql.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/License-GPL--3.0--only-blue.svg)](LICENSE)
![Windows 10/11 x64](https://img.shields.io/badge/Windows-10%2F11%20x64-0078D6)

**Open-source application firewall for Windows with transparent per-app network control.**

GeniaFirewall is built for people who want to see which applications use the network and decide what each application may do. The standalone WFP backend supports inbound and outbound policy, LAN/TUN-aware enforcement, diagnostics, and a portable WPF/.NET 10 interface.

![GeniaFirewall overview](docs/images/geniafirewall-overview-bilingual.jpg)

> The image above is an anonymized product overview. It is intended to explain the interface and capabilities, not to represent a specific computer, user, network, or exact build.

## Why GeniaFirewall?

- **Per-application policy:** Allow all, Outgoing only, Incoming only, Ask, or Block.
- **Inbound + outbound WFP enforcement:** TCP/UDP, IPv4/IPv6.
- **LAN-aware visibility:** inspect local and Internet connections without sending telemetry to the developer.
- **TUN/VPN compatibility work:** application rules are designed not to depend on a physical interface index.
- **Global modes:** Normal, Monitor, Allow all, and absolute Block all.
- **Diagnostics:** WFP filter counts, policy state, cleanup verification, blocked-event telemetry, and backend status.
- **Portable-first design:** user state stays local. The 0.7.4 RC line introduces a hardened single-EXE lifecycle with an embedded protected service.
- **Open source:** inspect the code, build it, test it, fork it, report bugs, or send pull requests.

## Current status

| Channel | Status |
| --- | --- |
| Stable | **0.7.3** |
| Current development candidate | **0.7.4 RC3** in [PR #1](https://github.com/geniasoftwin/Genia-Firewall/pull/1) |
| Platforms | Windows 10/11 x64 |
| Framework | WPF / .NET 10 |
| License | GPL-3.0-only |

0.7.4 RC3 is a **testing candidate, not Stable**. The Stable gate still requires the complete Windows validation matrix and Authenticode signing. RC builds may be unsigned; verify published SHA-256 values before testing.

## Firewall backends

| Capability | GeniaFirewall WFP | Windows Firewall Compatibility |
| --- | :---: | :---: |
| Outbound app rules | ✅ | ✅ |
| Inbound app rules | ✅ | — |
| TCP / UDP | ✅ | ✅ |
| IPv4 / IPv6 | ✅ | ✅ |
| Directional app profiles | ✅ | Outbound-oriented |
| WFP runtime diagnostics | ✅ | — |
| Recommended for full GeniaFirewall behavior | ✅ | Compatibility fallback |

**Important:** Windows Firewall Compatibility is intentionally limited compared with the standalone WFP backend. Use **GeniaFirewall WFP** when testing inbound/outbound application semantics.

## Quick start

1. Open [Releases](https://github.com/geniasoftwin/Genia-Firewall/releases).
2. Download the build and its SHA-256 file.
3. Verify the checksum.
4. Run GeniaFirewall and approve UAC when service installation or activation is required.
5. Keep the global mode on **Normal** and assign rules as applications are detected.

For the 0.7.4 RC line, the portable package contains one user-facing `GeniaFirewall.exe`. The embedded privileged service is installed into a protected location and verified before WFP enforcement is activated.

## Build from source

Requirements:

- Windows 10 or Windows 11 x64
- .NET 10 SDK
- Administrator rights for service/WFP runtime testing

Build:

```cmd
dotnet restore GeniaFirewall.sln
dotnet build GeniaFirewall.sln --configuration Release
```

Release packaging is performed by `publish-portable.cmd` on the active release branch.

## Architecture at a glance

```text
Portable UI (WPF)
       |
       | authenticated local IPC
       v
GeniaFirewall.Service (LocalSystem)
       |
       | Windows Filtering Platform policy
       v
ALE_AUTH_CONNECT / ALE_AUTH_RECV_ACCEPT
       |
       v
TCP / UDP · IPv4 / IPv6 · Internet / LAN / TUN
```

The privileged service owns WFP policy. The UI owns user decisions and local configuration. Service installation, ACLs, IPC identity, filter cleanup, and policy handoff are treated as security boundaries.

## Testing is a contribution

You do **not** need to write code to help.

Useful test environments include:

- Windows 10 and Windows 11;
- Ethernet and Wi-Fi;
- LAN client/server applications;
- VPN and TUN software;
- IPv4/IPv6 mixed environments;
- software that opens both outbound connections and inbound listeners.

See [TESTING.md](TESTING.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting bugs

Use the GitHub issue templates and include the GeniaFirewall version, Windows version, backend, global mode, application profile, and reproducible steps. Remove usernames, credentials, private paths, and unrelated IP addresses from logs.

For security vulnerabilities, **do not open a public issue**. Follow [SECURITY.md](SECURITY.md).

## Privacy

GeniaFirewall does not contain developer analytics and does not automatically upload logs. Optional reverse DNS uses the resolver configured in Windows. See [PRIVACY.md](PRIVACY.md).

## Project documents

- [Contributing](CONTRIBUTING.md)
- [Testing guide](TESTING.md)
- [Roadmap](ROADMAP.md)
- [Support](SUPPORT.md)
- [Security policy](SECURITY.md)
- [Privacy policy](PRIVACY.md)
- [Code signing policy](CODE_SIGNING_POLICY.md)
- [Third-party notices](THIRD_PARTY_NOTICES/README.md)

## License

GeniaFirewall source code is licensed under **GPL-3.0-only**. You may use, study, modify, and fork the project under that license. Distributed derivative works must follow the GPL terms. See [LICENSE](LICENSE).

## Known limitations

- Windows 7 is not supported by the current .NET 10 build.
- Windows Firewall Compatibility does not provide the full inbound/outbound semantics of the WFP backend.
- A true kernel-held pre-connect Ask workflow is not implemented; that would require a WFP callout driver.
- Release Candidates are testing builds and should not be treated as Stable.
