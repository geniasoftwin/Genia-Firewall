# GeniaFirewall 0.5.1 — security notes

## Что стало сильнее

1. Реальные WFP BLOCK filters создаёт отдельная служба, а не WPF UI.
2. WFP objects динамические и исчезают при остановке службы.
3. Замена filter set транзакционная: частично применённая policy не должна оставаться после ошибки.
4. IPC mutation проверяет impersonated token клиента: LocalSystem или Administrators.
5. IPC request имеет ограничение размера, policy — ограничение числа приложений.
6. Service повторно нормализует EXE paths, требует absolute `.exe` path и существующий файл.
7. WFP TEST выключен по умолчанию и не заменяет Microsoft Defender Firewall.
8. Добавлен отдельный emergency stop script.

## Что пока НЕ является security boundary GeniaFirewall 1.0

- UI всё ещё `requireAdministrator`.
- NetworkWatcher остаётся post-connect detector; WFP TEST filters применяются только к уже известным Block rules.
- Unknown/Ask пока не pending до решения пользователя.
- Allow policy всё ещё зависит от Windows Firewall Compatibility.
- Inbound traffic собственными GeniaFirewall WFP filters пока не управляется.
- Service restart снимает dynamic filters; пока UI не выполнит повторную синхронизацию, остаётся только Windows Firewall Compatibility policy.
- IPC authorization основана на локальном admin/System token; отдельной криптографической аутентификации UI binary пока нет.

## Правило тестирования

Во время тестов 0.5.1 Microsoft Defender Firewall должен оставаться включённым. Не тестировать WFP engine на удалённой машине без физического/локального доступа: ошибочная block policy способна разорвать сеть.

Если WFP TEST ведёт себя неожиданно:

1. запустить от администратора `emergency-stop-wfp.cmd`;
2. убедиться, что `GeniaFirewallService` остановлена;
3. WFP TEST dynamic filters должны исчезнуть вместе с session;
4. Microsoft Defender Firewall rules остаются нетронутыми.
