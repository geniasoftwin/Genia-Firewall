# GeniaFirewall 0.5.1 — WFP TEST enforcement architecture

## Архитектура

```text
GeniaFirewall.exe (WPF, elevated in 0.5.x)
        │
        ├── WindowsFirewallBackend (основной compatibility backend)
        │
        └── Named Pipe IPC v2 (policy snapshot)
                │
                ▼
GeniaFirewall.Service.exe (LocalSystem / console-admin)
        │
        ├── IPC authorization by impersonated client token
        ├── WFP dynamic session
        ├── GeniaFirewall provider
        ├── GeniaFirewall sublayer
        └── transactionally replaced BLOCK filters
                │
                ▼
ALE_AUTH_CONNECT_V4 / V6
        │
        ├── ALE_APP_ID == executable
        ├── IP_PROTOCOL == TCP/UDP
        └── FWP_ACTION_BLOCK
```

## Почему пока только BLOCK

0.5.1 — переходная версия. WFP `PERMIT` не следует трактовать как гарантированное «разрешить вопреки всем остальным policy providers». Microsoft Defender Firewall и другие WFP providers могут иметь собственные filters, и блокирующее решение другого provider всё ещё может остановить соединение.

Поэтому 0.5.1 использует безопасную семантику:

- `Block` → дополнительный WFP veto от GeniaFirewall;
- `Allow` → GeniaFirewall не добавляет WFP block, а рабочее Allow/Block compatibility policy продолжает поддерживать `WindowsFirewallBackend`.

Это позволяет проверить собственный WFP enforcement без ложного обещания независимого Allow engine.

## Dynamic session

Provider, sublayer и traffic filters принадлежат dynamic WFP session службы. Они не persistent/boot-time. Закрытие engine handle или остановка процесса службы удаляет эти объекты.

## Транзакционное обновление

При каждом изменении policy служба:

1. начинает write transaction;
2. удаляет предыдущие tracked filters;
3. строит новый набор filters из policy snapshot;
4. commit;
5. только после успешного commit заменяет внутренний список filter IDs.

При любой ошибке вызывается abort, поэтому предыдущая успешно применённая policy остаётся активной.

## Следующий этап

0.5.1 не является финальным самостоятельным backend. Для этого ещё нужны:

- собственная модель default policy / Allow arbitration;
- inbound ALE_AUTH_RECV_ACCEPT;
- service-side persistent policy storage и recovery;
- автоматический re-sync после рестарта Service;
- защищённый unprivileged UI → Service control plane;
- pre-connect `Ask` через callout/pended classification.
