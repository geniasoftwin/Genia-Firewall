# Security audit notes — GeniaFirewall 0.6.1

## Улучшения относительно 0.6.0

- Неизвестное приложение в WFP Normal после первого обнаружения немедленно переводится в app-specific ASK-BLOCK.
- ASK-BLOCK применяется до SHA-256/Authenticode/Trusted System проверки и до открытия prompt.
- `Later` не означает временный доступ: приложение остаётся заблокированным до явного решения.
- `Ask` сохраняется в persisted WFP policy, поэтому quarantine переживает перезапуск службы.
- IPC mutation по-прежнему доступен только LocalSystem/Administrators.

## Fail-closed свойства

- Ошибка сохранения метаданных после успешной установки ASK-BLOCK не снимает карантин.
- Ошибка WFP policy transaction оставляет предыдущий набор фильтров.
- При истечении Temporary Allow запись возвращается в `Ask`, и WFP Normal снова блокирует приложение.

## Оставшиеся ограничения

- Обнаружение нового EXE остаётся post-connect/user-mode. До момента первого обнаружения возможен краткий сетевой обмен.
- Нет inbound enforcement.
- Нет kernel callout и настоящего pending verdict на ALE_AUTH_CONNECT.
- UDP watcher не знает remote endpoint; WFP enforcement при этом всё равно разделяет TCP/UDP и IPv4/IPv6 по приложению.
- UI пока требует elevation.

0.6.1 не следует описывать как zero-leak pre-connect firewall. Корректная формулировка: standalone outbound WFP firewall с prompt quarantine после первого обнаружения неизвестного приложения.
