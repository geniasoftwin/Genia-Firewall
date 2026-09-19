# GeniaFirewall 0.5.0 — Windows Service + WFP policy foundation

## Добавлено

- Новый проект `GeniaFirewall.Service`.
- Новый общий проект `GeniaFirewall.Protocol` для версии IPC и status contract.
- Установка службы через `install-service.cmd`, удаление через `uninstall-service.cmd`.
- `service-console.cmd` для безопасного ручного теста службы из elevated terminal.
- Служба открывает динамическую WFP session (`FWPM_SESSION_FLAG_DYNAMIC`).
- Регистрируются собственные GeniaFirewall WFP provider и sublayer.
- Traffic filters в 0.5.0 намеренно не создаются (`filters=0`).
- Read-only named-pipe IPC: `ping` и `status`.
- Диагностика UI показывает состояние службы, WFP engine, provider, sublayer и filter count.
- Publish-скрипт теперь собирает и UI, и service в одну переносимую папку.

## Безопасность

- IPC 0.5.0 не принимает команды изменения firewall policy.
- WFP objects динамические и автоматически удаляются при закрытии session/завершении service process.
- Реальное сетевое enforcement остаётся на проверенном `WindowsFirewallBackend`.
- Microsoft Defender Firewall пока должен оставаться включённым.

## Версия

- Release: `0.5.0`.
- `Version`, `AssemblyVersion`, `FileVersion`: `0.5.0.0`.
- UI manifest `assemblyIdentity`: `0.5.0.0`.
- Service manifest `assemblyIdentity`: `0.5.0.0`.
- Publish: `publish\\GeniaFirewall-0.5.0-win-x64`.
