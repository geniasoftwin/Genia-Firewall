# Архитектура GeniaFirewall 0.7.4 RC1

## Граница portable / privilege

Пользователь переносит один `GeniaFirewall.exe`. Изменяемые пользовательские данные остаются рядом в `Data`; LocalSystem-код никогда не запускается из portable-папки.

```text
Portable folder
  GeniaFirewall.exe
  Data\                         (создаётся при работе)

Machine-protected
  %ProgramFiles%\GeniaFirewall\Service\GeniaFirewall.Service.exe
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
6. заменяет целевой PE в пределах одного каталога и повторяет проверку;
7. создаёт или исправляет SCM registration с quoted binary path, auto-start и зависимостью от BFE;
8. задаёт recovery actions и закрытый DACL объекта службы;
9. запускает Service и ждёт `SERVICE_RUNNING` плюс IPC v13.

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
- Compatibility не должен сосуществовать с восстановленной stale WFP policy.
- Ошибка установки/IPC приводит к остановке dynamic session и выбору Compatibility.
- Ошибка создания Compatibility rules до удаления Service вызывает попытку восстановления прежней WFP policy.
