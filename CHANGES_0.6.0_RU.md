# Изменения GeniaFirewall 0.6.0

- Добавлен самостоятельный backend **GeniaFirewall WFP**.
- Убран WFP TEST mirror: backend теперь выбирается явно.
- Allow/Block применяются через GeniaFirewall.Service на ALE_AUTH_CONNECT IPv4/IPv6 TCP/UDP.
- Добавлен BlockAll в WFP: app-specific Allow + глобальные блокирующие фильтры.
- WFP policy сохраняется службой в ProgramData и восстанавливается после рестарта службы.
- IPC поднят до v3.
- Добавлен безопасный handoff между Compatibility и WFP backend.
- При WFP startup failure UI возвращается на Windows Firewall Compatibility.
- `emergency-stop-wfp.cmd` теперь останавливает службу и выводит persisted policy из активного пути, чтобы она не восстановилась автоматически.
- Диагностика показывает активный backend, Allow/Block counts, filter counts, global BlockAll filters, restore status и revision.
- Кнопка «Обновить» в диагностике показывает время последнего обновления.
- Версия UI/Service/Protocol/manifest: 0.6.0.0.
