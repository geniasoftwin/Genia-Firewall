# GeniaFirewall 0.7.2 — Loopback-aware WFP

## Проблема

После появления inbound WFP в 0.7.0 глобальный default-deny на `ALE_AUTH_RECV_ACCEPT_V4/V6` совпадал в том числе с loopback. Это ломало приложения, где локальный клиент подключается к локальному listener, например `Chrome -> 127.0.0.1:2080 -> sing-box`.

## Решение

В Normal mode четыре глобальных inbound BLOCK-фильтра теперь имеют дополнительное условие:

```text
FWPM_CONDITION_FLAGS
FWP_MATCH_FLAGS_NONE_SET
FWP_CONDITION_FLAG_IS_LOOPBACK
```

То есть они блокируют только внешний unsolicited inbound. Loopback не попадает под глобальный inbound default-deny.

## Семантика профилей

- EnableAll: разрешены IN/OUT, включая loopback.
- OutgoingOnly: внешний OUT разрешён; внешний IN попадает под default-deny; loopback разрешён.
- IncomingOnly: внешний OUT блокируется фильтрами с `FLAGS_NONE_SET(IS_LOOPBACK)`; IN разрешён; loopback разрешён.
- DisableAll: IN/OUT BLOCK без loopback-исключения.
- Ask: quarantine IN/OUT BLOCK без loopback-исключения.

В Monitor mode directional block-фильтры `OutgoingOnly` / `IncomingOnly` также исключают loopback.

В BlockAll глобальные IN/OUT BLOCK остаются абсолютными, включая loopback. Для разрешённых OutgoingOnly/IncomingOnly создаются app-specific loopback-only PERMIT в недостающем направлении с более высоким весом.

## WFP layers

- OUT: `ALE_AUTH_CONNECT_V4/V6`
- IN: `ALE_AUTH_RECV_ACCEPT_V4/V6`
- App identity: `FWPM_CONDITION_ALE_APP_ID`
- Protocol: `FWPM_CONDITION_IP_PROTOCOL`
- Loopback scope: `FWPM_CONDITION_FLAGS`
