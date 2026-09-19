# Изменения GeniaFirewall 0.7.2

- Исправлена блокировка localhost глобальным inbound default-deny.
- Добавлено условие WFP `FLAGS_NONE_SET(IS_LOOPBACK)` для Normal global inbound block.
- IncomingOnly теперь блокирует только внешний outbound и сохраняет localhost.
- Monitor directional blocks теперь не режут loopback.
- DisableAll и Ask получили явный inbound app block, поэтому по-прежнему блокируют localhost полностью.
- BlockAll сохраняет строгий глобальный deny, но OutgoingOnly/IncomingOnly получают loopback-only permit в недостающем направлении.
- Добавлен диагностический признак loopback-aware policy.
- UI / Service / Protocol / manifests: `0.7.2.0`.
- IPC pipe: `GeniaFirewall.Service.v11`.
