# Windows Filtering Platform: a practical introduction

[Русский](WFP_RU.md) · [Microsoft WFP documentation](https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page)

**WFP** is Windows' native network filtering platform. GeniaFirewall uses WFP APIs through a privileged Windows service; it does **not** ship a custom kernel callout driver.

~~~text
Portable WPF UI (settings, choices, diagnostics)
              │ authorized local IPC
              ▼
GeniaFirewall.Service (LocalSystem)
              │ manages product WFP filters
              ▼
Windows Filtering Platform / BFE
    ├─ ALE_AUTH_CONNECT       outbound
    └─ ALE_AUTH_RECV_ACCEPT   inbound
              │
              ▼
TCP / UDP · IPv4 / IPv6 · LAN / Internet
~~~

This is a simplified diagram of the product's primary authorization points, not an illustration of every Windows filter or third-party security provider.

## Application profiles (GeniaFirewall WFP backend)

| Rule | Intended result |
| --- | --- |
| Allow all / EnableAll | App permits in both directions |
| Outgoing only | Only outbound app permission |
| Incoming only | Only inbound app permission |
| Block | Deny app traffic |
| Ask | UI decision flow, subject to implementation limitations |

In **Normal**, an incoming connection may match GeniaFirewall's default inbound blocking boundary if there is no applicable higher-priority inbound app permit. A separate Windows Defender Firewall inbound rule does not necessarily override that WFP filter.

Global **Block all** is intended to supersede per-app Allow; global **Allow all** changes the effective global policy. These modes are distinct from application rule profiles.

**Ask is not a kernel-held pre-connect prompt.** Intercepting and holding the first connect would require a WFP callout driver, which this project currently does not install.

## Two backends are not equivalent

- **GeniaFirewall WFP**: full application inbound/outbound profiles with direct WFP enforcement and runtime diagnostics.
- **Windows Firewall Compatibility**: fallback for Windows Firewall **outbound app rules**; not a substitute for inbound WFP policy.

Runtime filters use dynamic WFP session lifetime and GeniaFirewall checks its own cleanup during backend switching/deactivation. Third-party WFP providers, routes, and Windows policies may still affect connectivity.

[VPN/TUN notes](VPN_TUN.md) · [Security model](SECURITY_MODEL.md)
