# Изменения GeniaFirewall 0.6.5

## System Identity Hardening

- Исправлена ложная маркировка некоторых системных файлов Windows как «Не подписано».
- Проверка подписи теперь выполняется в два этапа: embedded Authenticode, затем Windows system catalog fallback.
- Для catalog-signed файлов используется Windows catalog database + WinVerifyTrust; источник подписи показывается как `встроенная` или `каталог`.
- Поле CompanyName/Publisher из version info остаётся только информационным и не считается доказательством доверия.
- Trusted System по-прежнему требует успешную криптографическую проверку Windows и Microsoft signer; одного имени EXE или System32 недостаточно.

## Snapshot короткоживущих процессов

- Network watcher захватывает snapshot процесса сразу при обнаружении сетевой активности.
- Snapshot сохраняет PID, время старта, Parent PID/parent image и best-effort command line.
- Prompt показывает Process / Parent / Command line даже если короткоживущий `rundll32.exe` уже завершился к моменту отображения окна.
- Отсутствующие snapshot-поля не ослабляют WFP policy: это только диагностический контекст.

## Совместимость

- UI / Service / Protocol / manifests: `0.6.5.0`.
- IPC protocol: v8 (`GeniaFirewall.Service.v8`) — намеренно новая pipe, чтобы UI 0.6.5 не подключался к старой службе 0.6.4.
- Backend и Quick Rules из 0.6.4 сохранены без изменения enforcement semantics.
