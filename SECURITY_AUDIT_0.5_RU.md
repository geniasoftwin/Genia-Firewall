# GeniaFirewall 0.5.0 — security notes

## Положительные изменения

- Привилегированный WFP lifecycle вынесен в отдельный `GeniaFirewall.Service`.
- WFP provider/sublayer принадлежат динамической session и не должны переживать crash/stop службы.
- В IPC пока нет команд, меняющих firewall state: только read-only status.
- UI диагностика явно сообщает, что filters=0 и enforcement остаётся compatibility backend.

## Известные границы

1. WPF UI всё ещё `requireAdministrator`, потому что реальный enforcement 0.5.0 использует `HNetCfg.FwPolicy2` напрямую.
2. Named pipe ещё не является финальным authenticated command channel. Поэтому security-critical команды запрещены на уровне протокола.
3. Служба регистрирует WFP provider/sublayer, но не блокирует и не разрешает трафик напрямую.
4. `Ask` по-прежнему основан на post-connect watcher и не является pre-connect verdict.
5. Callout driver отсутствует.
6. Service binary привязан к пути portable-папки после регистрации SCM. Папку нельзя перемещать до `uninstall-service.cmd` или повторной установки службы.

## Перед включением реальных WFP filters

- Добавить строгий pipe ACL и authenticated/authorized request model.
- Добавить request id, protocol/version negotiation и bounded payloads.
- Все пути и identity перепроверять внутри service, не доверять данным UI.
- Реализовать WFP transaction + deterministic rollback.
- Добавить emergency command для удаления только GeniaFirewall filters.
- Тестировать IPv4/IPv6 и TCP/UDP отдельно.
