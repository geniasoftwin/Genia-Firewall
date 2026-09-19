# Изменения GeniaFirewall 0.6.3

## Добавлено

- Русский и английский интерфейс.
- Язык `Автоматически / Русский / English` в настройках.
- WPF resource dictionaries для динамической смены основных подписей интерфейса.
- `Позже` и закрытие prompt крестиком оставляют `Ожидает решения` и WFP quarantine.
- Повторный prompt после `Позже/X` подавляется для текущего экземпляра процесса (PID + StartTime + EXE).
- Флажок `Не напоминать об этом приложении` в prompt.
- Контекстные команды для Pending-приложения: `Показать запрос сейчас` и `Не напоминать`.
- True Del: строка действительно удаляется из таблицы, но Service сохраняет скрытый WFP ASK-BLOCK до следующей сетевой активности.
- Скрытые runtime quarantine entries сохраняются локально между перезапусками UI.
- Подготовлено меню Quick Rules: EnableAll, OutgoingOnly, DisableAll; IncomingOnly обозначен как будущая inbound-функция.
- Диагностика показывает язык, число скрытых карантинов и число Pending-приложений с отключёнными напоминаниями.

## Изменено

- Версии UI/Service/Protocol/manifest: `0.6.3.0`.
- IPC protocol: v6 (`GeniaFirewall.Service.v6`).
- При `Del` в безопасном WFP Normal сначала формируется fail-closed policy, затем строка исчезает из UI.
- При повторной сетевой активности скрытый quarantine превращается обратно в видимую запись `Ожидает решения` без временного открытия сети.
- `Allow/Block` снимают Pending suppression и считаются явным решением пользователя.

## Не входит в 0.6.3

- Inbound enforcement.
- Полностью отдельная семантика EnableAll/OutgoingOnly — пока backend outbound-only.
- Kernel pre-connect pending. Для нулевого первого пакета потребуется callout driver.
