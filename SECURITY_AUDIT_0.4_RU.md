# GeniaFirewall 0.4.0 — security notes

## Что уже защищено

- EXE identity хранит SHA-256 и метаданные файла.
- Trusted System требует системный путь, доверенную подпись Microsoft и встроенную политику; svchost дополнительно проверяется по службам PID.
- Временные разрешения не импортируются как постоянные.
- Текущие firewall rules принадлежат группе GeniaFirewall.
- WFP probe 0.4.0 read-only: только `FwpmEngineOpen0`/`FwpmEngineClose0`, без фильтров.

## Известные границы 0.4.0

- enforcement всё ещё использует Windows Firewall compatibility backend;
- неизвестное соединение обнаруживается post-connect;
- watcher IPv4;
- UDP remote endpoint watcher не определяет;
- rules пока outbound;
- WPF UI требует elevation;
- отсутствует отдельная SYSTEM-служба и authenticated IPC;
- отсутствует WFP callout driver, поэтому pre-connect `Ask` пока невозможен.

## Требования к следующему WFP этапу

1. Служба должна перепроверять path/hash/signer независимо от UI.
2. IPC должен проверять клиента и не доверять произвольным процессам пользователя.
3. Provider/sublayer/filter GUID должны быть стабильными и принадлежать GeniaFirewall.
4. Нужен аварийный rollback и отдельная команда очистки WFP объектов.
5. Callout driver вводится только после user-mode WFP backend и отдельного test-signing цикла.
