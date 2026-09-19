# GeniaFirewall 0.7.3 HF2 — WFP Lifecycle Fix

HF2 исправляет ошибку, обнаруженную при первом Windows-тесте HF1.

## Исправлено

- В `FWPM_FILTER_ENUM_TEMPLATE0` поле `actionMask` теперь равно `0xFFFFFFFF`. Нулевое значение не означает «любое действие»: оно создаёт заведомо пустой шаблон и приводит к `FWP_E_NEVER_MATCH (0x80320033)`.
- Startup stale cleanup снова может перечислять project-owned фильтры и подтверждать `residual=0`.
- Выключение защиты, `AllowAll`, очистка WFP backend и переход в Windows Firewall Compatibility снова проходят обязательную zero-filter verification.
- После успешного WFP transaction commit сервис сразу принимает фактические новые filter ID. Если post-commit проверка завершится исключением, последующий rollback больше не пытается удалить уже несуществующие pre-commit ID.

## Без изменений

- TUN/WFP политика HF1 сохранена: app-фильтры не привязаны к интерфейсу, physical interface scope применяется только к Normal inbound boundary filters.
- Узкие readiness permits для разрешённого `GeniaProxy.exe` сохранены.
- IPC остаётся v13; pipe — `GeniaFirewall.Service.v13`.
- GeniaProxy не изменяется.

## Версии

```text
UI / Service / Protocol: 0.7.3.2
IPC: v13
```
