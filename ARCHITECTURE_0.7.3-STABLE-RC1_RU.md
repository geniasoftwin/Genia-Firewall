# Архитектура GeniaFirewall 0.7.3 Stable RC1

## Release-инварианты

RC1 не расширяет policy model. Для перехода в stable должны одновременно выполняться следующие инварианты:

1. Любая замена WFP-политики выполняется одной BFE transaction.
2. После commit внутренние filter IDs всегда соответствуют фактическому committed состоянию.
3. Protection OFF, AllowAll и backend clear подтверждаются перечислением owned filters с `residual=0`.
4. Backend clear закрывает dynamic session и отсоединяет provider/sublayer.
5. App filters не зависят от physical/TUN interface index.
6. Normal global inbound boundary применяется только к классифицированным physical interfaces, кроме явно диагностируемого fail-safe fallback.
7. Приоритеты остаются `PROBE(15) > APP(14) > GLOBAL(1)`.

## Telemetry

`FWPM_NET_EVENT_HEADER2` хранит IPv4 как `UINT32` в network byte order. RC1 преобразует значение в четыре сетевых октета до создания `IPAddress`. IPv6 продолжает читаться как исходные 16 байт union.

Последний BLOCK содержит UTC timestamp, layer, filter ID, EXE, protocol, remote endpoint, interface, reason и matched rule. Запись является последним наблюдавшимся событием и не означает, что соответствующее правило всё ещё активно.

## IPC

Named pipe сохраняет IPC v13. Status остаётся read-only, но для непривилегированного клиента из него удаляются пути EXE, endpoint, имена интерфейсов и тексты внутренних ошибок. Полная telemetry и mutations требуют LocalSystem/Administrators. Время получения одной полной команды ограничено пятью секундами; лимит размера остаётся 2 MiB.

## Release packaging

Скрипт publish проверяет исходные version markers, публикует UI и Service self-contained, проверяет `FileVersion=0.7.3.3`, создаёт ZIP и отдельный SHA-256 manifest. Любой сбой этих этапов возвращает ненулевой exit code.
