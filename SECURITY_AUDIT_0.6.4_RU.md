# Security audit notes — GeniaFirewall 0.6.4

## Что не изменилось

- WFP backend самостоятельно контролирует outbound TCP/UDP IPv4/IPv6.
- `Ask` в Normal mode означает app-specific WFP BLOCK до решения.
- Hidden quarantine после `Del` остаётся в Service независимо от строки UI.
- Совершенно новый EXE всё ещё обнаруживается post-connect user-mode watcher-ом; true pre-connect Ask требует callout driver.

## Quick Rules

- `EnableAll` и `OutgoingOnly` в 0.6.4 намеренно имеют одинаковый outbound WFP эффект, потому что inbound backend ещё отсутствует. UI не должен выдавать это за полный двунаправленный доступ.
- `IncomingOnly` нельзя активировать через UI. Импорт повреждённого/ручного `IncomingOnly` нормализуется в `Default`, чтобы не создавать ложное ощущение защиты.
- `DisableAll` остаётся обычным per-app WFP BLOCK.
- `Ask` остаётся quarantine BLOCK.

## Временные правила

- `До закрытия` привязано к текущему PID и не переживает рестарт GeniaFirewall.
- 10-минутное правило валидируется по времени; подозрительно длинные/просроченные значения fail-closed возвращаются в Ask.
- Экспорт временного Allow не должен превращать его в постоянное разрешение.
