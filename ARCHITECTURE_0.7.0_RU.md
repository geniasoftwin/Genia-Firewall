# GeniaFirewall 0.7.0 — Inbound + Outbound WFP

## Слои WFP

Исходящие новые соединения:
- `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
- `FWPM_LAYER_ALE_AUTH_CONNECT_V6`

Входящие новые соединения / первый входящий non-TCP packet:
- `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`
- `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`

Фильтры привязываются к `FWPM_CONDITION_ALE_APP_ID` и `FWPM_CONDITION_IP_PROTOCOL` (TCP/UDP).

## Normal

- Исходящий global default-block отсутствует: известные приложения получают directional rule, а Unknown после обнаружения переводится в Ask/quarantine.
- Входящий unsolicited TCP/UDP блокируется глобальными IN-фильтрами низкого веса.
- `EnableAll`: OUT permit + IN permit.
- `OutgoingOnly`: OUT permit; IN остаётся под global block.
- `IncomingOnly`: OUT block + IN permit.
- `DisableAll`: OUT block; IN остаётся под global block.
- `Ask`: OUT ASK-BLOCK; IN остаётся под global block.

Ответный трафик для уже авторизованного ALE flow обрабатывается statefully и не является новым unsolicited inbound соединением.

## BlockAll

Устанавливаются 4 global OUT blocks + 4 global IN blocks. App-specific permits имеют больший вес внутри sublayer GeniaFirewall:
- `EnableAll`: OUT + IN permit.
- `OutgoingOnly`: OUT permit.
- `IncomingOnly`: IN permit.
- `DisableAll` / `Ask`: исключений нет.

## Monitor

Global default-deny фильтры не устанавливаются. Постоянные Quick Rules применяются как self-contained directional filters; Ask не карантинируется.

## Совместимость

Windows Firewall Compatibility остаётся outbound-only. При временном переключении с WFP на Compatibility профиль IncomingOnly отправляется в compatibility backend как outbound Block, чтобы не открыть исходящий доступ по ошибке.
