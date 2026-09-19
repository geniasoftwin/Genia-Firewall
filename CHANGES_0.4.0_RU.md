# GeniaFirewall 0.4.0 — первый шаг к собственному WFP backend

0.4.0 намеренно не включает сырые WFP-фильтры в рабочий трафик. Цель релиза — отделить контракт firewall backend от WPF UI и добавить безопасную диагностику Windows Filtering Platform перед переносом enforcement в отдельную службу.

## Архитектура

- Добавлен `IFirewallBackend`: UI больше не привязан напрямую к конкретной реализации firewall.
- Текущий совместимый backend переименован в `WindowsFirewallBackend` и реализует общий контракт.
- Добавлены `FirewallBackendKind`, `FirewallBackendCapabilities` и единая модель диагностики backend.
- В диагностике видно, какой backend активен и какие возможности он реально предоставляет.

## WFP foundation

- Добавлен read-only `WfpPlatformProbeService`.
- Probe открывает policy engine через `FwpmEngineOpen0`, сразу закрывает handle и **не создаёт фильтры**.
- В окне диагностики отображается доступность WFP/BFE и native error code при ошибке.
- Это подготовка к следующему этапу: `GeniaFirewall.Service` + persistent WFP filters.

## Безопасность перехода

- Enforcement 0.4.0 остаётся на проверенном compatibility backend (`HNetCfg.FwPolicy2`).
- Существующие Allow/Block/Block All, Trusted System, временные правила, SHA-256, tray и burst grouping сохранены.
- Windows Defender Firewall нельзя отключать: 0.4.0 ещё не самостоятельный firewall backend.

## Версии

- UI/release: **0.4.0**.
- `Version`, `AssemblyVersion`, `FileVersion`: **0.4.0.0**.
- Embedded manifest `assemblyIdentity`: **0.4.0.0**.
- Publish directory: `publish\\GeniaFirewall-0.4.0-win-x64`.
