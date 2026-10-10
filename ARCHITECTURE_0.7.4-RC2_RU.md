# Архитектура GeniaFirewall 0.7.4 RC2

## Граница portable / privilege

Пользователь переносит один `GeniaFirewall.exe`. Изменяемые пользовательские данные остаются рядом в `Data`; LocalSystem-код никогда не запускается из portable-папки.

```text
Portable folder
  GeniaFirewall.exe
  Data\                         (создаётся при работе)

Machine-protected
  %ProgramFiles%\GeniaFirewall\Service\GeniaFirewall.Service.exe
  %ProgramFiles%\GeniaFirewall\Service\GeniaFirewall.Service.exe.previous  (только незавершённое обновление)
  %ProgramData%\GeniaFirewall\Service\wfp-policy.json
  %ProgramData%\GeniaFirewall\Logs\...
```

## Publish pipeline

1. Service публикуется как self-contained single-file win-x64 во временный staging.
2. Полученный PE добавляется в UI с logical resource name `GeniaFirewall.Payload.GeniaFirewall.Service.exe`.
3. UI публикуется как self-contained single-file win-x64.
4. Проверяются версии обоих PE и то, что output UI содержит ровно `GeniaFirewall.exe`.
5. Staging удаляется; ZIP создаётся из одного EXE.

Обычная solution build не требует готового payload. Publish с `RequireEmbeddedService=true` завершается ошибкой, если ресурс не задан или отсутствует.

## Runtime lifecycle

При `ServiceEnabled=true` UI с административным токеном:

1. создаёт и защищает Program Files paths;
2. отклоняет reparse point;
3. вычисляет SHA-256 встроенного payload;
4. при необходимости останавливает предыдущий Service;
5. пишет `.new` с `WriteThrough`, применяет ACL и проверяет SHA-256;
6. атомарно заменяет целевой PE, сохраняя прежний файл как `.previous`, и повторяет SHA-256 проверку обеих копий;
7. создаёт или исправляет SCM registration: own-process, LocalSystem, quoted binary path, auto-start, normal error-control и зависимость BFE;
8. задаёт recovery actions и закрытый DACL объекта службы;
9. запускает Service и проверяет `SERVICE_RUNNING`, имя службы, IPC v13 и ProductVersion;
10. повторно читает точную SCM-конфигурацию, файловые DACL и DACL объекта службы;
11. только после всех проверок удаляет `.previous`; ошибка запуска или IPC восстанавливает прежний EXE и повторно проверяет его hash.

Если Service запускается при активном Compatibility backend, UI до старта удаляет только ожидаемые `wfp-policy.json` и `.tmp` из проверенного ProgramData path. После IPC startup повторно отправляется `clear-wfp-policy` и проверяются `engine/provider/sublayer=false`, `filters=0`, `cleanup-verified=true`, `residual=0`. Поэтому старая persisted policy не успевает кратко восстановить фильтры.

## Деактивация

Порядок считается частью security contract:

1. при наличии Service запускается только доверенный встроенный payload;
2. IPC `clear-wfp-policy` должен подтвердить закрытый engine/provider/sublayer, `filters=0`, `cleanup-verified=true`, `residual=0`;
3. Compatibility rules синхронизируются из текущей базы;
4. Service останавливается и удаляется из SCM;
5. удаляются только ожидаемые файлы из защищённого каталога; неожиданные файлы не удаляются рекурсивно и приводят к ошибке;
6. сохраняются `BackendMode=WindowsFirewallCompatibility` и `ServiceEnabled=false`.

## Fail-safe

- WFP нельзя выбрать при непроверенной Service installation.
- Compatibility не должен даже кратковременно запускать Service со stale persisted WFP policy.
- Ошибка установки/IPC приводит к остановке dynamic session и выбору Compatibility.
- Авария между заменой Service EXE и health-check оставляет защищённую `.previous`, пригодную для следующей проверки/rollback.
- Ошибка создания Compatibility rules до удаления Service вызывает попытку восстановления прежней WFP policy.
