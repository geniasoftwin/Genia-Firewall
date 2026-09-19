# Security audit notes — GeniaFirewall 0.7.3 Stable

## Проверенные свойства

- Enforcement выполняется привилегированным Service; mutation IPC допускает только LocalSystem/Administrators.
- Runtime WFP objects принадлежат dynamic session и удаляются BFE при закрытии handle.
- Zero-filter verification перечисляет только provider/sublayer GeniaFirewall на используемых ALE layers.
- GeniaProxy readiness permits ограничены AppID, IPv4, UDP, `1.1.1.1`/`1.0.0.1` и портом 53.
- Application allow/block filters не получают общего TUN bypass.
- Непривилегированный status redaction исключает утечку путей EXE, endpoints, interface names и внутренних ошибок.
- Persisted policy ограничена 8 MiB, валидируется до применения и сохраняется атомарно через flushed temporary file.
- Publish завершается ошибкой при несовпадении file version или отсутствии ZIP/checksum.
- Service устанавливается в `%ProgramFiles%\GeniaFirewall\Service`, а ACL каталога и EXE разрешает изменение только `SYSTEM` и локальным администраторам. Регистрация LocalSystem-службы из пользовательской portable-папки исключена.

## Windows acceptance

- lifecycle выдержал повторные policy revisions без накопления фильтров;
- `cleanup-verified=yes`, `residual=0` и clean startup cleanup подтверждены;
- переключения Protection/backend прошли без `0x80320033`;
- TUN-подключение GeniaProxy проверено при активной защите;
- финальный Stable сохраняет тот же enforcement-код, что и принятый RC1; после RC1 изменён только безопасный lifecycle установочных скриптов.

## Остаточные ограничения

- User-mode Ask не удерживает самый первый connect как kernel callout driver.
- Interface classification остаётся эвристической; `fallback=YES` требует отдельного анализа.
- Подпись исполняемых файлов и установщик не входят в portable release process.
- Финальные бинарники `0.7.3.4` требуют smoke-проверки после Windows publish, поскольку среда подготовки Source Ready не содержит Windows/.NET Desktop toolchain.
- Новый защищённый путь установки и ACL требуют отдельной проверки install/update/uninstall на Windows до публикации GitHub Release.
