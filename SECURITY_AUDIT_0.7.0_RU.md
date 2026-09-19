# Security audit notes — GeniaFirewall 0.7.0

## Улучшения

- Unsolicited inbound TCP/UDP IPv4/IPv6 теперь контролируется собственными WFP-фильтрами GeniaFirewall.
- OutgoingOnly и IncomingOnly больше не являются только UI-метками.
- Normal mode inbound — default deny.
- BlockAll — двунаправленный.
- Сохранены transactional replacement, dynamic WFP session и persisted policy recovery.

## Ограничения

- ICMP не входит в Quick Rule enforcement 0.7.0; текущий scope — TCP/UDP.
- Unknown outbound всё ещё определяется user-mode watcher-ом, поэтому 0.7.0 нельзя описывать как zero-leak pre-connect Ask firewall.
- Неизвестный inbound блокируется default-deny, но отдельный inbound prompt до accept пока не реализован.
- Microsoft Defender Firewall и другие WFP providers могут параллельно блокировать трафик. GeniaFirewall permit не является обходом чужого block policy.
- Настоящий synchronous Ask до первого outbound packet требует WFP callout driver / kernel classify path.
