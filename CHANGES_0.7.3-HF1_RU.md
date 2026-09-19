# GeniaFirewall 0.7.3 HF1 — TUN/WFP Compatibility

Hotfix после повторного конфликта GeniaProxy TUN с собственным WFP backend.

## Исправлено

- runtime-фильтры по-прежнему живут в dynamic WFP session, а отключение backend/защиты теперь дополнительно проверяет реальное число фильтров нашего provider/sublayer: безопасное состояние подтверждается только при `count=0`;
- при старте Service выполняется best-effort поиск и очистка stale/orphan фильтров старых запусков;
- переход `GeniaFirewall WFP -> Windows Firewall Compatibility` сначала очищает WFP и требует подтверждённый zero-filter state, затем активирует Compatibility. Если проверка не прошла, UI не объявляет WFP отключённым;
- app-specific ALLOW/BLOCK больше не привязываются к `ifIndex`: решение приложения основано на `ALE_APP_ID + direction + protocol`, поэтому смена маршрута Ethernet/Wintun не должна ломать разрешение;
- interface index используется только у низкоприоритетной глобальной physical-inbound границы;
- для явно разрешённого `GeniaProxy.exe` добавлены узкие high-priority readiness permits: UDP `1.1.1.1:53` и `1.0.0.1:53`;
- приоритеты разделены и проверяются runtime invariant: `PROBE(15) > APP(14) > GLOBAL(1)`;
- исправлен native layout `FWPM_FILTER0`: union `rawContext/providerContextKey` теперь имеет корректный размер 16 байт и в enforcement, и в inventory code;
- WFP net-event telemetry теперь сохраняет `filterId`, layer, interface, matched GeniaFirewall filter/reason и пишет диагностическую строку `WFP BLOCK ...`;
- debounce перестроения interface-scoped boundary policy сокращён с 750 до 200 мс для быстрого появления/удаления Wintun;
- IPC обновлён до v13, версия файлов — `0.7.3.1`.

## Не сделано намеренно

- нет универсального allow для всего Wintun/TUN;
- не хардкодится endpoint конкретного профиля Xray/sing-box: явно разрешённое ядро получает обычный interface-agnostic outbound app permit;
- настоящий kernel pre-connect Ask всё ещё требует callout driver.
