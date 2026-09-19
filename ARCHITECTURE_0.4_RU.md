# GeniaFirewall 0.4 — архитектура перехода к WFP

## Сейчас (0.4.0)

```text
GeniaFirewall.exe (WPF, elevated)
    ├─ UI / tray / prompts
    ├─ NetworkWatcher
    ├─ SHA-256 / Authenticode / Trusted System
    └─ IFirewallBackend
          └─ WindowsFirewallBackend
                └─ HNetCfg.FwPolicy2
                      └─ Microsoft Defender Firewall / WFP
```

`WfpPlatformProbeService` только проверяет, что Windows Filtering Platform/Base Filtering Engine доступен. Он не добавляет фильтры и не влияет на трафик.

## Следующий этап

```text
GeniaFirewall.exe (обычный пользователь)
        │
        │ authenticated named-pipe IPC
        ▼
GeniaFirewall.Service.exe (Windows service / SYSTEM)
        ├─ Rule Engine
        ├─ process identity
        ├─ SHA-256 / signer policy
        └─ WFP backend
              ├─ ALE_AUTH_CONNECT_V4
              └─ ALE_AUTH_CONNECT_V6
```

На этом этапе статические Allow/Block правила могут применяться напрямую через WFP в user mode от имени службы. UI перестаёт требовать постоянного elevation.

## Pre-connect Ask

Для настоящего `Ask` до первого пакета потребуется отдельный минимальный WFP callout driver. Он должен быть подписан и проходить отдельный цикл тестирования. До появления драйвера нельзя выдавать post-connect watcher за pre-connect enforcement.

## Принципы

1. Никакого автоматического перехода на новый backend без явной проверки и rollback.
2. Compatibility backend сохраняется как аварийный путь на время миграции.
3. WFP provider/sublayer/filter объекты должны принадлежать GeniaFirewall и удаляться детерминированно.
4. Правило не должно доверять приложению только по имени EXE.
5. UI не принимает security-critical решения, которые служба не может перепроверить самостоятельно.
