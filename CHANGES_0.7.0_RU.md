# Изменения GeniaFirewall 0.7.0

- Добавлен inbound WFP enforcement на ALE_AUTH_RECV_ACCEPT V4/V6.
- `IncomingOnly` активирован в Quick Rules для GeniaFirewall WFP.
- `EnableAll`, `OutgoingOnly`, `IncomingOnly`, `DisableAll`, `Ask` теперь передаются в Service как отдельный `WfpRuleProfile`.
- Protocol schema поднята до v9 / `GeniaFirewall.Service.v9`.
- WFP policy schema: 2.
- Normal mode получил inbound default-deny.
- BlockAll теперь блокирует оба направления.
- Добавлены отдельные счётчики inbound/outbound/global-in/global-out.
- Compatibility fallback для IncomingOnly безопасно блокирует outbound.
- Версии UI / Service / Protocol / manifests: `0.7.0.0`.
