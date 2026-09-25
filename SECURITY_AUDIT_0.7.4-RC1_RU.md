# Security audit — GeniaFirewall 0.7.4 RC1

## Цель

Проверить, что переход от двух EXE и CMD-установщика к single-EXE portable не переносит LocalSystem trust boundary в пользовательскую папку и не создаёт небезопасный update/uninstall lifecycle.

## Реализованные меры

- Service запускается только из `%ProgramFiles%\GeniaFirewall\Service`.
- SCM binary path quoted; аргументы отсутствуют.
- Program Files и ProgramData paths проверяются на reparse point.
- Protected DACL: только `SYSTEM` и локальные Administrators, без `Users`, `Authenticated Users`, `Everyone` и `Interactive`.
- SCM service object получает тот же административный trust boundary.
- Встроенный payload ограничен размером 256 MiB; staging и installed copy проверяются SHA-256 constant-time comparison.
- Update не затрагивает совпадающий Service и останавливает службу до замены отличающегося PE.
- Service policy и logs закрыты от изменения обычным пользователем.
- Удаление не использует recursive delete для каталога с неожиданным содержимым.
- Деактивация требует подтверждённого нулевого WFP runtime до остановки/удаления.
- `ServiceEnabled=false` не позволяет автоматически вернуться на WFP.

## Остаточные риски до Stable

1. RC не подписан Authenticode. Замена самого portable UI в пользовательской папке предотвращается только осознанным запуском/UAC и SHA-проверкой автозагрузки; нужна подпись издателя.
2. Windows smoke-test обязателен: clean install, upgrade поверх 0.7.3, deactivate/reactivate, reboot, TUN и deliberate failure cases.
3. Настоящий pre-connect Ask требует отдельного signed WFP callout driver и не входит в RC.

## Release gate

Не создавать Stable tag до успешного выполнения `RELEASE_CHECKLIST_0.7.4-RC1_RU.md` на Windows 10 и Windows 11.
