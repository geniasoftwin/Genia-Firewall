# GeniaFirewall 0.6.1 — Secure Prompt Quarantine

0.6.1 сохраняет standalone outbound WFP backend 0.6.0 и меняет семантику `Ask` в режиме `Нормальный`.

## Поток неизвестного приложения

```text
EXE начинает сетевую активность
        ↓
user-mode watcher обнаруживает EXE
        ↓
UI создаёт запись Access=Ask
        ↓
полная policy → GeniaFirewall.Service
        ↓
4 app-specific WFP ASK-BLOCK фильтра
        ↓
SHA-256 / Trusted System evaluation
        ↓
prompt
   ├─ Allow → WFP PERMIT
   ├─ Block → WFP BLOCK
   └─ Later → ASK-BLOCK остаётся
```

ASK-BLOCK ставится до дорогой проверки подписи и до показа prompt. Поэтому после момента обнаружения приложение не может продолжать сетевую работу, пока пользователь думает.

## Семантика режимов

- `Normal`: Allow → permit, Block → block, Ask → quarantine block.
- `BlockAll`: явные Allow являются исключениями, остальные блокируются глобальными фильтрами.
- `AllowAll`: enforcing filters не устанавливаются.
- `Monitor`: Ask не превращается в quarantine block; поведение мониторинга 0.6.0 сохранено.

## Почему это ещё не pre-connect

`NetworkWatcherService` остаётся user-mode polling механизмом. Он получает сведения уже после появления сетевой активности в системных таблицах. Поэтому 0.6.1 гарантирует блокировку после обнаружения, но не может гарантировать остановку самого первого пакета.

Для настоящего `Ask before connect` нужен kernel WFP callout на ALE_AUTH_CONNECT с pending/complete verdict. Это отдельный этап 0.7.x.
