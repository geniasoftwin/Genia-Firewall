# Архитектура GeniaFirewall 0.7.3 HF1

## Цель HF1

Сохранить строгую WFP-модель 0.7.3, но убрать зависимость app-level решения от жизненного цикла/маршрутизации TUN и сделать отключение backend проверяемым.

## Enforcement

`GeniaFirewall.Service` владеет dynamic WFP session. Основные layers: `ALE_AUTH_CONNECT_V4/V6` и `ALE_AUTH_RECV_ACCEPT_V4/V6`.

App filters строятся из `ALE_APP_ID + IP_PROTOCOL + direction` и, где требуется профилем, loopback condition. Они не получают `ifIndex`/LUID. Это важно для процессов, которые начинают соединение до появления Wintun или переживают смену default route.

Global Normal inbound default-deny остаётся низкоприоритетным и scope-ится по physical arrival interface indexes. Именно boundary filters могут быть interface-scoped; virtual/TUN adapter не получает общий catch-all inbound block.

Weight ranges внутри sublayer:

```text
15  READINESS_PROBE_ALLOW
14  APP_ALLOW / APP_BLOCK / ASK_BLOCK
 1  DEFAULT_BLOCK / BLOCK_ALL
```

## GeniaProxy readiness probe

Для явно разрешённого `GeniaProxy.exe` с outbound-capable профилем создаются только два IPv4 UDP permit:

```text
1.1.1.1:53
1.0.0.1:53
```

Это не общий DNS/TUN bypass. Правила имеют отдельную причину `READINESS_PROBE_ALLOW` для диагностики.

## Lifecycle

При zero-filter policy (backend inactive, protection off, AllowAll/clear):

1. текущий набор удаляется в WFP transaction;
2. transaction commit;
3. provider filters на четырёх owned ALE layers перечисляются повторно;
4. безопасный clear подтверждается только при `residual=0`.

На переключении WFP -> Compatibility UI требует `WfpBackendActive=false`, `ActiveFilterCount=0`, `RuntimeFilterCleanupVerified=true`, `ResidualRuntimeFilterCount=0` до активации Compatibility. После verified clear dynamic enforcement session закрывается; при возврате на WFP она открывается заново по требованию.

При старте отдельный inventory helper пытается удалить stale filters/provider/sublayer, оставшиеся от старых persistent/ошибочных билдов. Текущий runtime всё равно создаётся в dynamic session.

## BLOCK telemetry

Для classify DROP Service пытается записать:

```text
layer
filterId
pid (best effort)
app path
protocol
remote endpoint
local interface index/name (best effort)
reason
matched GeniaFirewall rule
```

`filterId` сопоставляется с descriptor текущего runtime filter set. Если фильтр не наш, reason помечается как `OTHER_WFP_FILTER`.

## Ограничения

Net-event telemetry остаётся post-classification наблюдением. PID и interface name восстанавливаются best effort и могут отсутствовать для очень короткоживущего процесса/динамического адреса. Настоящий hold первого connect до решения пользователя не реализован.
