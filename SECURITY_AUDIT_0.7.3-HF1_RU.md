# Security audit notes — GeniaFirewall 0.7.3 HF1

## Улучшения

- отказ от interface-bound app permits уменьшает риск, что уже разрешённое приложение внезапно перестанет совпадать с правилом после появления Wintun/смены маршрута;
- interface scoping остаётся только у low-weight boundary blocks, то есть TUN compatibility не реализована широким allow всего виртуального интерфейса;
- readiness exception ограничен `GeniaProxy.exe`, UDP, двумя IP Cloudflare DNS и port 53;
- backend clear теперь fail-closed по состоянию: UI не подтверждает переключение, если Service не доказала отсутствие собственных runtime filters;
- dynamic session остаётся основным lifecycle механизмом; startup inventory дополнительно очищает stale objects старых запусков;
- исправлен ABI layout `FWPM_FILTER0`, включая 16-byte union контекста;
- BLOCK telemetry показывает filter/reason, что позволяет отличить `DEFAULT_BLOCK`, `APP_BLOCK`, `ASK_BLOCK`, `BLOCK_ALL`, `READINESS_PROBE_ALLOW` и чужие WFP filters.

## Остаточные риски

- interface classification виртуальных адаптеров эвристическая;
- WFP net-event collection зависит от возможностей/настроек Windows и может не дать все allow/drop events;
- PID/interface attribution в telemetry best effort;
- unknown-app Ask пока user-mode quarantine после обнаружения, а не kernel pending classify;
- HF1 требует обязательного теста на реальной Windows, так как P/Invoke/WFP поведение нельзя полноценно провалидировать в Linux build environment.
