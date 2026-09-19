# Архитектура GeniaFirewall 0.7.3

## Цель

Исправить конфликт 0.7.0–0.7.2 с TUN режимами: глобальный inbound default-deny на `ALE_AUTH_RECV_ACCEPT_V4/V6` не должен ломать внутренний data path виртуального TUN-адаптера.

## Схема

```text
Physical Ethernet/Wi-Fi
        ↓
ALE_AUTH_RECV_ACCEPT
        ↓
GeniaFirewall global inbound BLOCK

Virtual/TUN adapter
        ↓
ALE_AUTH_RECV_ACCEPT
        ↓
не попадает под global physical-in block
        ↓
TUN/proxy core может принимать внутренний трафик
```

Явные правила приложения остаются сильнее общей классификации:

```text
DisableAll / Ask
→ app-specific BLOCK IN + OUT
→ блокирует physical + virtual/TUN + loopback
```

## Interface scope

Service получает snapshot сетевых интерфейсов через `System.Net.NetworkInformation.NetworkInterface`.

Virtual/TUN определяется консервативно по характерному имени/описанию адаптера: Wintun, WireGuard, TUN, TAP, VPN, Hyper-V, VMware, VirtualBox, Tailscale, ZeroTier, OpenVPN, Xray, sing-box, GeniaProxy, Docker, WSL и т. п.

Остальные non-loopback интерфейсы считаются physical/external-facing и получают global inbound block по `FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX`.

## WFP conditions

Для inbound interface-scoped filters используется `FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX`, доступный на `ALE_AUTH_RECV_ACCEPT_V4/V6`.

Для app-specific virtual permits в BlockAll outbound-направлении используется `FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX`; для inbound — `FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX`.

## Fail-safe

Если Service не смог получить ни одного physical interface index, Normal Mode не становится fail-open. Он возвращается к 0.7.2-поведению: global external-inbound block с исключением loopback.

## Динамические изменения

`NetworkChange.NetworkAddressChanged` запускает debounce-refresh WFP policy. Транзакция WFP остаётся атомарной: при ошибке предыдущий набор фильтров сохраняется.
