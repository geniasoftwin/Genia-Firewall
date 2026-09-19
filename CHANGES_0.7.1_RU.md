# Изменения GeniaFirewall 0.7.1

- Добавлена read-only подписка службы на WFP net events (`FwpmNetEventSubscribe1`).
- Короткие TCP/UDP и loopback события больше не зависят только от polling socket tables.
- Добавлен IPC v10: получение telemetry ring buffer по sequence cursor.
- Диагностика: telemetry active/unavailable, sequence, received, dropped, error.
- Добавлен parent-process subtitle/tool-tip в главной таблице.
- WFP telemetry захватывает process snapshot best effort по живому PID.
- Legacy watcher остаётся fallback.
- Socket watcher распознаёт TCP listener для уже известных приложений; listener сам по себе не вызывает prompt.
- Исправлен telemetry cursor после рестарта GeniaFirewall.Service.
- Версии UI / Service / Protocol / manifests: `0.7.1.0`.
- IPC pipe: `GeniaFirewall.Service.v10`.
