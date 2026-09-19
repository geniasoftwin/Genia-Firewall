# Архитектура GeniaFirewall 0.7.3 HF2

## Цель

Сделать lifecycle WFP-политики проверяемым на реальной Windows и устранить отказ выключения защиты с `0x80320033`, не меняя TUN-модель HF1.

## Перечисление owned filters

`WfpOwnedFilterInventory` перечисляет фильтры по provider key отдельно на четырёх ALE-слоях. `FWPM_FILTER_ENUM_TEMPLATE0.actionMask` задаётся как `0xFFFFFFFF`, что по контракту WFP отключает фильтрацию по типу action. После перечисления дополнительно проверяется `subLayerKey`, поэтому в результат входят только фильтры GeniaFirewall.

## Commit и post-commit verification

Замена политики остаётся транзакционной. Сразу после успешного `FwpmTransactionCommit0` менеджер принимает список созданных filter ID и соответствующие descriptors как фактическое состояние WFP engine. Только после этого выполняется zero-filter verification для Protection OFF, AllowAll и backend clear.

Такой порядок важен для восстановления: если post-commit проверка сама завершится ошибкой, повторное применение предыдущей политики работает от актуального набора ID, а не от уже удалённого pre-commit списка.

## Границы hotfix

HF2 не меняет веса `PROBE > APP > GLOBAL`, правила TUN/interface scope, IPC v13 и алгоритмы GeniaProxy. Прямой DNS probe GeniaProxy остаётся внешним acceptance-сигналом; единичный timeout без подтверждающего WFP DROP не классифицируется как доказанная блокировка GeniaFirewall.
