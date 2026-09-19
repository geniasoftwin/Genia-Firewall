# Архитектура GeniaFirewall 0.7.3 Stable

## Release-инварианты

1. Любая замена WFP-политики выполняется одной BFE transaction.
2. После commit внутренние filter IDs соответствуют фактическому committed состоянию.
3. Protection OFF, AllowAll и backend clear подтверждаются перечислением owned filters с `residual=0`.
4. Backend clear закрывает dynamic session и отсоединяет provider/sublayer.
5. Application filters не зависят от physical/TUN interface index.
6. Normal global inbound boundary применяется только к классифицированным physical interfaces, кроме диагностируемого fail-safe fallback.
7. Приоритеты остаются `PROBE(15) > APP(14) > GLOBAL(1)`.

## TUN

Service классифицирует physical и virtual/TUN interfaces при каждом применении политики. App-level allow/block filters не привязаны к интерфейсу; interface scope используется только для низкоприоритетного Normal inbound boundary. Для разрешённого GeniaProxy readiness permits ограничены AppID, IPv4, UDP, адресами `1.1.1.1`/`1.0.0.1` и портом 53.

## Telemetry

IPv4 из `FWPM_NET_EVENT_HEADER2` декодируется из network byte order. Последний BLOCK содержит UTC timestamp, layer, filter ID, EXE, protocol, remote endpoint, interface, reason и matched rule. `evicted` обозначает вытеснение записи из ring buffer, а не packet drop.

## IPC и persistence

Named pipe сохраняет IPC v13. Mutation-команды разрешены только LocalSystem/Administrators. Непривилегированный status не раскрывает EXE paths, endpoints, interface names и внутренние ошибки. Запрос ограничен 2 MiB и таймаутом чтения пять секунд. Persisted policy проверяет schema, mode, null collections, размер и число приложений до WFP transaction.

## Release packaging

`publish-portable.cmd` проверяет source version markers, публикует UI и Service self-contained, проверяет `FileVersion=0.7.3.4`, создаёт ZIP и отдельный SHA-256 manifest. Сбой publish, проверки версии, упаковки или checksum возвращает ненулевой exit code.
