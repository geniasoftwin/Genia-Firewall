# Security audit notes — GeniaFirewall 0.6.0

## Что уже является security enforcement

WFP backend создаёт реальные фильтры в Base Filtering Engine на ALE_AUTH_CONNECT_V4/V6. BLOCK является WFP block action. Правила приложения используют ALE_APP_ID, полученный через FwpmGetAppIdFromFileName0.

## Защитные меры

- policy mutation IPC только для Administrator/LocalSystem;
- полный policy update выполняется одной WFP-транзакцией;
- при неуспешном commit прежний набор фильтров сохраняется;
- persisted policy записывается только после успешного WFP commit; при ошибке записи runtime пытается вернуть предыдущую policy;
- service EXE исключается из app-specific policy;
- лимит 5000 приложений;
- переход между backend выполняется в безопасном порядке;
- WFP objects dynamic и исчезают при завершении service session.

## Оставшиеся риски/ограничения

- Нет kernel callout и настоящего pending/pre-connect Ask. Unknown EXE может успеть установить первое соединение до решения watcher-а.
- Нет inbound enforcement.
- Persisted policy восстанавливается службой, но между остановкой службы и её повторным запуском dynamic filters отсутствуют.
- Другие WFP-провайдеры могут дополнительно блокировать трафик; GeniaFirewall PERMIT не должен считаться обходом сторонней/системной политики.
- UI пока требует Administrator.
- Не реализованы удалённые IP/port/subnet conditions в rule editor.
