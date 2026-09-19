# GeniaFirewall 0.7.3 Stable

Лицензия: GPL-3.0-only. Полный текст — в `LICENSE`.

Стабильная portable-сборка application firewall для Windows 10/11 на WPF/.NET 10 с самостоятельным WFP backend в `GeniaFirewall.Service`.

## Стабильный релиз

Функциональный состав проверенного RC1 заморожен. Финальный релиз меняет только маркировку, версию и release-документацию; policy model и WFP-логика не изменены.

В Stable сохранены исправления HF1/HF2 и hardening RC1:

- dynamic WFP session и проверяемое удаление runtime-фильтров;
- startup cleanup stale/orphan objects;
- app-level правила без привязки к interface index;
- physical interface scope только для низкоприоритетного Normal inbound boundary;
- узкие readiness permits GeniaProxy UDP `1.1.1.1:53` и `1.0.0.1:53`;
- порядок весов `PROBE(15) > APP(14) > GLOBAL(1)`;
- корректный `FWPM_FILTER_ENUM_TEMPLATE0.actionMask = 0xFFFFFFFF`;
- принятие committed filter IDs до post-commit verification.

Дополнительное hardening:

- IPv4 в WFP telemetry декодируется из network byte order, поэтому `127.0.0.1` больше не отображается как `1.0.0.127`;
- `WFP last BLOCK` содержит UTC-время события и не выглядит как безусловно текущая блокировка;
- ожидаемые результаты startup cleanup показываются как `not-found (ok)`, а не как тревожные необъяснённые HRESULT;
- неполный клиент IPC освобождается по таймауту и не может бесконечно удерживать единственный цикл pipe server;
- непривилегированный IPC status не раскрывает пути EXE, endpoint и внутренние ошибки;
- publish проверяет версии готовых EXE, считает SHA-256 и завершает сборку ошибкой при сбое упаковки.

## Portable build

```cmd
publish-portable.cmd
```

Результат:

```text
publish\GeniaFirewall-0.7.3-Stable-win-x64\
publish\GeniaFirewall-0.7.3-Stable-Portable-win-x64.zip
publish\GeniaFirewall-0.7.3-Stable-SHA256.txt
```

Перед обновлением удалить старую службу через `uninstall-service.cmd`, затем установить новую из новой publish-папки через `install-service.cmd` от администратора. Установщик копирует привилегированный Service в `%ProgramFiles%\GeniaFirewall\Service` и ограничивает ACL только `SYSTEM` и локальными администраторами; UI остаётся portable.

## Безопасность

Не публикуйте сведения о предполагаемой уязвимости в обычном Issue. Используйте приватный канал GitHub Security Advisory. Поддерживаемая версия и порядок сообщения описаны в `SECURITY.md`.

## Версии

```text
UI / Service / Protocol: 0.7.3.4
IPC: v13
Pipe: GeniaFirewall.Service.v13
```

## Ограничение

Stable не реализует настоящий kernel pre-connect Ask. Для удержания первого connect до решения пользователя нужен WFP callout driver.
