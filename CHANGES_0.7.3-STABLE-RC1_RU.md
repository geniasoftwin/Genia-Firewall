# GeniaFirewall 0.7.3 Stable RC1 — стабилизация

RC1 создан на базе проверенного HF2. Функциональный состав заморожен: изменения направлены на предсказуемость lifecycle, точность диагностики и воспроизводимость release-пакета.

## Исправлено

- IPv4-адреса из `FWPM_NET_EVENT_HEADER2` теперь декодируются из network byte order. Диагностика больше не показывает `127.0.0.1` как `1.0.0.127`.
- В `WFP last BLOCK` добавлено `timeUtc`, поэтому историческое событие можно отличить от текущей блокировки.
- Результаты best-effort удаления отсутствующих provider/sublayer отображаются как `not-found (ok)`. Неожиданные HRESULT по-прежнему показываются как ошибка.
- Чтение одной IPC-команды ограничено пятью секундами. Подключившийся, но не отправивший полную строку клиент больше не удерживает pipe server бесконечно.
- Непривилегированный `status` сохраняет health/capability поля, но больше не раскрывает путь EXE, endpoint, имена интерфейсов и тексты внутренних ошибок. Elevated UI получает полную диагностику.
- Persisted service policy ограничена по размеру, записывается через flush-to-disk temporary file и проверяет schema/mode/null collection до WFP transaction.
- Runtime-описания WFP-фильтров и Windows Firewall rules используют центральную `ServiceProtocol.ProductVersion`, уменьшая риск рассинхронизации версии.
- `publish-portable.cmd` проверяет file version обоих опубликованных EXE, считает SHA-256 ZIP и завершает работу ошибкой, если упаковка или checksum не созданы.
- Счётчик telemetry в UI переименован из неоднозначного `dropped` в `evicted`: он показывает вытеснения из кольцевого буфера, а не WFP packet drops.

## Сохранено из HF2

- `actionMask = 0xFFFFFFFF` при перечислении owned filters;
- принятие committed filter IDs до post-commit verification;
- dynamic WFP session и обязательный `residual=0` при clear/detach;
- TUN-aware Normal inbound boundary и interface-independent app rules;
- веса `PROBE > APP > GLOBAL`;
- IPC v13 и pipe `GeniaFirewall.Service.v13`.

## Версии

```text
UI / Service / Protocol: 0.7.3.3
IPC: v13
```
