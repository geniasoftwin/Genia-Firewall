# Security audit notes — GeniaFirewall 0.7.3 HF2

## Исправленная проблема

Нулевой `actionMask` в `FWPM_FILTER_ENUM_TEMPLATE0` приводил к отказу перечисления фильтров. Транзакция выключения защиты уже могла быть committed, но post-commit verification возвращала ошибку, а внутренний список ID всё ещё описывал предыдущую политику. Это создавало риск кратковременного расхождения между UI, состоянием сервиса и фактическим набором WFP-фильтров.

HF2 устраняет обе части:

- перечисление использует документированное значение `0xFFFFFFFF` для любого action;
- committed filter IDs принимаются до операций, способных завершиться post-commit ошибкой.

## Сохранённые свойства

- Runtime-фильтры, provider и sublayer принадлежат dynamic WFP session.
- Backend clear подтверждается только при `residual=0` и затем закрывает session.
- App-level разрешения не получают общего TUN bypass и остаются привязаны к AppID, направлению и протоколу.
- Права mutation IPC остаются ограничены LocalSystem/Administrators.

## Остаточный риск

WFP P/Invoke и фактическое поведение BFE требуют проверки на Windows. Обязательный тест HF2: несколько циклов `Protection ON -> OFF -> ON`, переход WFP -> Compatibility и проверка отсутствия `0x80320033`/residual filters.
