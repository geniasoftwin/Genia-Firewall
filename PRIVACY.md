# Privacy / Конфиденциальность

## English

GeniaFirewall does not include developer analytics, advertising, cloud accounts, remote management, or automatic log uploads. Network metadata and application identities are processed locally to enforce/display firewall decisions.

Portable configuration, rules, backups, and UI diagnostics are stored locally in the portable data directory. Privileged service data and logs are stored under `%ProgramData%\GeniaFirewall`. Sharing an export or report is a user action.

Optional **reverse DNS** requests use the DNS resolver configured in Windows; querying a remote IP may disclose that address to the resolver. Firewall enforcement does not require reverse DNS.

This policy describes GeniaFirewall's behavior, not other applications, Windows, VPN providers or DNS services. Redact personal data before sharing logs.

## Русский

GeniaFirewall не содержит аналитики разработчика, рекламы, облачных аккаунтов, удалённого управления и автоматической отправки логов. Сетевые метаданные и сведения о приложениях обрабатываются локально для применения правил.

Portable-настройки, правила, backups и UI-журналы хранятся локально. Данные привилегированной службы и логи — под `%ProgramData%\GeniaFirewall`. Передача экспортированных настроек или диагностики выполняется по действию пользователя.

Необязательный **reverse DNS** использует resolver, настроенный в Windows; он может получить IP проверяемого адреса. Для WFP enforcement reverse DNS не нужен.

Это описание GeniaFirewall, а не других приложений, Windows, VPN или DNS-провайдеров. Перед публикацией журналов скрывайте личные данные.
