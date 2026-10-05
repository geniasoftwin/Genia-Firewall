# Security audit — GeniaFirewall 0.7.4 RC2

## Цель

Проверить, что переход от двух EXE и CMD-установщика к single-EXE portable не переносит LocalSystem trust boundary в пользовательскую папку и не создаёт небезопасный update/uninstall lifecycle.

## Реализованные меры

- Service запускается только из `%ProgramFiles%\GeniaFirewall\Service`.
- SCM binary path quoted; аргументы отсутствуют.
- Program Files и ProgramData paths проверяются на reparse point.
- Protected DACL файлов и каталогов сравнивается с точным ожидаемым ACL: только `SYSTEM` и локальные Administrators.
- SCM service object перечитывается через `QueryServiceObjectSecurity`; допускаются ровно `SYSTEM` и Administrators с полным доступом.
- Встроенный payload ограничен размером 256 MiB; staging и installed copy проверяются SHA-256 constant-time comparison.
- Update не затрагивает совпадающий Service. Отличающийся PE заменяется атомарно с защищённой `.previous`; новая и rollback-копии проверяются SHA-256.
- `.previous` удаляется только после проверки payload, полной SCM-конфигурации, ACL, `SERVICE_RUNNING` и IPC identity; при сбое прежний EXE восстанавливается.
- Проверка SCM требует own-process, LocalSystem, auto-start, normal error-control, единственную зависимость BFE, ожидаемый display name и точный quoted path без аргументов.
- Service policy и logs закрыты от изменения обычным пользователем.
- Удаление не использует recursive delete для каталога с неожиданным содержимым.
- Деактивация требует подтверждённого нулевого WFP runtime до остановки/удаления.
- Compatibility startup удаляет persisted policy до запуска Service и повторно подтверждает нулевой runtime через IPC.
- `ServiceEnabled=false` не позволяет автоматически вернуться на WFP.

## Остаточные риски до Stable

1. RC не подписан Authenticode. Замена самого portable UI в пользовательской папке предотвращается только осознанным запуском/UAC и SHA-проверкой автозагрузки; публичный Stable до подписи запрещён.
2. Windows smoke-test обязателен: clean install, upgrade поверх 0.7.3, deactivate/reactivate, reboot, TUN и deliberate failure cases.
3. Настоящий pre-connect Ask требует отдельного signed WFP callout driver и не входит в RC.

## Release gate

Не создавать Stable tag до успешного выполнения `RELEASE_CHECKLIST_0.7.4-RC2_RU.md` на Windows 10 и Windows 11 и Authenticode-подписи обоих PE.
