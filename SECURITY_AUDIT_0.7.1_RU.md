# Security audit notes — GeniaFirewall 0.7.1

## Что улучшено

- Telemetry отделена от enforcement: подписка на net events не изменяет policy.
- Буфер ограничен и имеет счётчик dropped events.
- IPC чтения telemetry доступен через тот же защищённый service pipe; mutation commands остаются привилегированными.
- Unknown inbound net events не создают неожиданные decision prompts.
- Passive TCP LISTEN не трактуется как запрос исходящего доступа.
- Правило всегда относится к реальному EXE; Parent Process используется только как контекст.

## Ограничения

- WFP net event — post-classification telemetry, а не kernel pending/complete pre-connect decision.
- ProcessSnapshot может быть пустым, если короткоживущий процесс уже завершился до сопоставления PID по пути.
- AppId может быть недоступен для части системных/специальных событий; такие события отбрасываются.
- Legacy polling остаётся fallback и в основном IPv4-oriented.
- ICMP не входит в текущий TCP/UDP Quick Rule scope.
- Microsoft Defender Firewall продолжает применять собственные WFP rules параллельно.
