# GeniaFirewall 0.6.4 — Quick Rules

0.6.4 не меняет проверенный standalone outbound WFP enforcement из 0.6.3. Релиз делает быстрые правила отдельным, сохраняемым UI-профилем приложения и не смешивает их с базовым состоянием Allow/Block/Ask.

## Профили

- `EnableAll` → базовый `Allow`. Пока backend outbound-only, его сетевой эффект совпадает с `OutgoingOnly`; UI честно сообщает об этом ограничении.
- `OutgoingOnly` → базовый `Allow`, отдельная метка профиля сохраняется в `apps.json`.
- `DisableAll` → базовый `Block`.
- `Ask` → базовый `Ask`, то есть WFP quarantine в Normal mode.
- `IncomingOnly` зарезервирован в модели, но не может быть выбран до появления самостоятельного inbound WFP backend.

`ApplicationRuleProfile` хранится отдельно от `FirewallAccess`. Это позволяет в будущем добавить inbound-фильтры, не ломая существующую portable-базу.

## Временный доступ

Контекстное меню содержит:

- разрешить на 10 минут;
- разрешить до закрытия текущего процесса.

Временное правило не экспортируется как постоянный Allow. После истечения оно возвращается в `Ask`.

## Безопасность

Quick Rules не меняют модель безопасности 0.6.3: `Ask` остаётся fail-closed, `Del` сохраняет hidden runtime quarantine в WFP Service, а совершенно новый EXE всё ещё обнаруживается user-mode watcher-ом. Нулевой первый пакет потребует callout driver.

## Версии

- UI / Service / Protocol / manifests: `0.6.4.0`
- IPC: v7
- pipe: `GeniaFirewall.Service.v7`
