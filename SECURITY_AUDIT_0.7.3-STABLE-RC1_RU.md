# Security audit notes — GeniaFirewall 0.7.3 Stable RC1

## Проверенные свойства

- Enforcement выполняется привилегированным Service; mutation IPC допускает только LocalSystem/Administrators.
- Runtime WFP objects принадлежат dynamic session и удаляются BFE при закрытии handle.
- Zero-filter verification перечисляет только provider/sublayer GeniaFirewall на используемых ALE layers.
- Узкие GeniaProxy readiness permits ограничены AppID, IPv4, UDP, адресами `1.1.1.1`/`1.0.0.1` и портом 53.
- Application allow/block filters не получают общего TUN bypass.
- IPC request имеет лимит 2 MiB и в RC1 также ограничен по времени чтения.
- Непривилегированный status redaction исключает утечку EXE path, remote endpoint, interface names и внутренних ошибок; elevated UI сохраняет полную диагностику.
- Persisted policy имеет лимит 8 MiB и до применения проходит проверку schema, enum mode, наличия списка и максимального числа приложений.

## Исправления аудита RC1

- Устранена ошибка byte order в IPv4 telemetry. Она не меняла enforcement, но могла вести к неправильной диагностике причины BLOCK.
- Ожидаемые WFP `PROVIDER_NOT_FOUND`/`SUBLAYER_NOT_FOUND` отделены от настоящих ошибок cleanup.
- Publish не сообщает успех при отсутствии ZIP/checksum или несовпадении file version.

## Остаточные ограничения

- User-mode Ask не удерживает самый первый connect так, как kernel callout driver.
- Interface classification остаётся эвристической; `fallback=YES` требует отдельного анализа.
- P/Invoke ABI, BFE transaction semantics, service install/update и TUN matrix должны быть подтверждены на Windows x64 перед снятием RC-метки.
- Подпись исполняемых файлов и установщик не входят в текущий portable release process.
