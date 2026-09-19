# GeniaFirewall 0.7.1 — WFP Event Telemetry + Process Tree

## Цель

0.7.1 дополняет socket-table polling read-only подпиской на WFP net events. Это нужно для короткоживущих соединений и loopback-трафика, которые могут исчезнуть между опросами `GetExtendedTcpTable`.

## Поток событий

```text
Windows Filtering Platform
        ↓ FWPM_NET_EVENT
GeniaFirewall.Service
        ↓ ring buffer (sequence)
Named Pipe IPC v10
        ↓
GeniaFirewall.exe
        ↓
activity / unknown-app detection
```

Enforcement 0.7.0 не меняется: inbound/outbound правила по-прежнему ставит `WfpSessionManager`. Telemetry только наблюдает.

## WFP telemetry

- Служба открывает отдельный нединамический read-only engine handle.
- Подписка: `FwpmNetEventSubscribe1`.
- Обрабатываются `CLASSIFY_ALLOW` и `CLASSIFY_DROP` для TCP/UDP.
- Из события сохраняются EXE/AppId, локальный/удалённый endpoint, направление, allow/drop и loopback.
- Буфер ограничен 4096 событиями; UI читает его пакетами через IPC.
- При рестарте Service UI распознаёт новый `StartupUtc` и сбрасывает sequence cursor.
- Legacy socket watcher остаётся fallback, если WFP telemetry недоступна.

## Process Tree

При обработке события UI пытается найти живой PID по полному пути EXE и сразу снимает `ProcessSnapshot`:

- PID;
- Parent PID;
- parent name/path;
- command line (best effort).

В главном списке под именем процесса показывается родитель, например:

```text
sing-box
↳ GeniaProxy.exe
```

Правила остаются привязаны к реальному сетевому EXE, а не к родителю.

## Loopback и listener

WFP telemetry больше не отбрасывает loopback. Поэтому короткие обращения GUI к локальному SOCKS/HTTP bridge, например `127.0.0.1:2080`, могут быть видны как `Loopback OUT`.

Socket watcher дополнительно распознаёт TCP LISTEN для уже известных приложений и показывает `Listener · address:port`. Сам факт LISTEN не создаёт новый firewall prompt.

## Безопасность

0.7.1 не является callout-driver pre-connect Ask. WFP net-event telemetry приходит как наблюдение уже произошедшей классификации. Secure Prompt Quarantine и существующие WFP enforcement rules продолжают отвечать за блокировку.
