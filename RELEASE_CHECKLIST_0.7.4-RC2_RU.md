# Release checklist — GeniaFirewall 0.7.4 RC2

## 1. Package

- [ ] ZIP содержит только `GeniaFirewall.exe`.
- [ ] FileVersion/ProductVersion UI — `0.7.4.0`.
- [ ] SHA-256 ZIP совпадает с `GeniaFirewall-0.7.4-RC2-SHA256.txt`.
- [ ] Первый запуск показывает один ожидаемый UAC prompt.

## 2. Clean install

- [ ] До запуска `sc query GeniaFirewallService` возвращает 1060.
- [ ] После запуска Service имеет `RUNNING`, own-process, LocalSystem, auto-start, normal error-control и единственную зависимость BFE.
- [ ] `sc qc GeniaFirewallService` показывает quoted path `%ProgramFiles%\GeniaFirewall\Service\GeniaFirewall.Service.exe`.
- [ ] В portable-папке не появляется `GeniaFirewall.Service.exe`; допустима только `Data`.
- [ ] Обычный пользователь не может создать/изменить/удалить Service EXE или policy JSON.
- [ ] `sc sdshow GeniaFirewallService` не даёт доступ субъектам, кроме `SYSTEM` и `BUILTIN\Administrators`.
- [ ] Диагностика показывает payload verified, SCM verified, file ACL protected, service ACL protected и IPC OK.

## 3. Upgrade from 0.7.3 Stable

- [ ] Запустить новый UI без ручного uninstall/install CMD.
- [ ] Service обновлён до `0.7.4.0`, правила и настройки сохранены.
- [ ] WFP backend после обновления показывает dynamic session и прежнюю policy.
- [ ] После успешного обновления `GeniaFirewall.Service.exe.previous` отсутствует.
- [ ] Повторный запуск с тем же payload не перезапускает работающую службу без необходимости.

## 4. Deactivate / reactivate

- [ ] В WFP режиме нажать «Деактивировать» и подтвердить.
- [ ] Диагностика до удаления фиксирует `filters=0`, `cleanup-verified=да`, `residual=0`.
- [ ] Активен Windows Firewall Compatibility, приложение сохраняет правила.
- [ ] SCM registration и `%ProgramFiles%\GeniaFirewall\Service\GeniaFirewall.Service.exe` отсутствуют.
- [ ] После перезапуска Service не устанавливается заново.
- [ ] «Активировать» повторно устанавливает защищённую службу; WFP можно выбрать и синхронизировать.
- [ ] Активация в Compatibility показывает `PolicyRestoredOnStartup=false`, `filters=0`, `cleanup-verified=true`, `residual=0`.

## 5. Reboot and failure cases

- [ ] Reboot в WFP режиме восстанавливает policy и IPC.
- [ ] Reboot после деактивации не создаёт Service.
- [ ] Подмена Service EXE/ACL обычным пользователем отклоняется Windows.
- [ ] Дополнительный allow ACE конкретного пользователя в файловом или SCM DACL определяется как `unverified` и исправляется при следующей активации.
- [ ] Reparse-point test для install/data path завершается безопасной ошибкой.
- [ ] Искусственная ошибка Compatibility handoff не удаляет прежнюю WFP policy без попытки rollback.
- [ ] Тестовая сборка с Service, завершающимся до IPC, восстанавливает прежний EXE из `.previous` с исходным SHA-256; при невозможности rollback выполняется fail-safe cleanup.

## 6. Networking regression

- [ ] Normal / Allow all / Block all / Monitor.
- [ ] Allow, Block, Ask, temporary allow, Safe Del quarantine.
- [ ] IPv4/IPv6, TCP/UDP, inbound/outbound.
- [ ] GeniaProxy TUN connect/disconnect и смена backend без residual filters.
- [ ] После завершения Service dynamic WFP provider/sublayer/filters отсутствуют.

## Gate

Stable разрешён только после зелёного CI/CodeQL, ручного Windows smoke-test и Authenticode-подписи Service и UI. До этого сборка остаётся RC2.
