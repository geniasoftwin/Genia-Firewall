# Security audit notes — GeniaFirewall 0.6.5

- Catalog signature fallback закрывает false-negative для системных файлов Windows, но не превращает любой Microsoft-signed host в автоматически доверенное приложение.
- `rundll32.exe`, `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe` и другие host/LOLBIN сценарии не должны получать широкое доверие только по signer/path. Command line и parent показываются как контекст пользователю.
- CompanyName/version info не является security proof.
- Catalog hash и trust проверяются средствами Windows; при ошибке/недоступности API проверка fail-closed и файл не считается trusted.
- Проверка подписи использует cache-only URL retrieval, чтобы сам prompt проверки подписи не инициировал сеть.
- Process snapshot является диагностикой. Ошибка snapshot не должна менять WFP verdict.
- 0.6.5 остаётся outbound-only. Полноценный inbound и kernel pre-connect Ask ещё не реализованы.
