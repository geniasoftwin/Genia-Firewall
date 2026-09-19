# Security audit notes — GeniaFirewall 0.7.3

## Улучшение

В 0.7.2 global inbound block применялся ко всему non-loopback inbound и мог ломать TUN data plane. В 0.7.3 Normal Mode ограничивает этот глобальный block обнаруженными physical interface indexes.

## Сохраняемые гарантии

- `DisableAll` и `Ask` остаются app-specific hard block для IN/OUT без исключения TUN/loopback.
- WFP policy применяется транзакционно.
- При ошибке interface classification используется fail-safe legacy external-inbound block.
- Virtual/TUN classification отображается в диагностике.

## Остаточный риск

Virtual-adapter detection пока heuristic для Ethernet-like virtual drivers. Неизвестный virtual driver без узнаваемого type/name/description может быть классифицирован как physical и снова получить default inbound block. Обратная ошибка — physical adapter с misleading virtual-like названием — может не получить global inbound default block. Поэтому 0.7.3 остаётся test branch до расширения идентификации через native IP Helper metadata.

## Pre-connect

User-mode watcher/telemetry не гарантирует zero-packet unknown-app hold. Для этого нужен WFP callout driver на ALE authorization layers.
