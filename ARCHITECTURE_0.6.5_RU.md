# GeniaFirewall 0.6.5 — System Identity Hardening

0.6.5 укрепляет идентификацию приложения, не меняя standalone outbound WFP enforcement.

## Подписи

`ExecutableMetadataService` сначала проверяет embedded Authenticode через WinVerifyTrust. Если embedded signer отсутствует, выполняется fallback в Windows catalog database: SHA-256 catalog hash → поиск каталога → `WINTRUST_CATALOG_INFO` → WinVerifyTrust. Это важно для системных Windows EXE, подпись которых может храниться в каталоге.

File version metadata (`CompanyName`) используется только для отображения. Trusted System принимает решение только по успешной trust verification и Microsoft signer.

## Process snapshot

Сразу при сетевом событии watcher пытается сохранить:

- PID;
- UTC start time;
- parent PID;
- parent image/name;
- command line текущего процесса.

Snapshot переносится внутри `NetworkConnectionInfo` до prompt. Поэтому UI не зависит от того, жив ли процесс через несколько секунд. Считывание best-effort: protected/быстро завершившийся процесс может дать неполные поля, но это не влияет на WFP block/allow.

## Версии

- UI / Service / Protocol / manifests: `0.6.5.0`
- IPC: v8
- pipe: `GeniaFirewall.Service.v8`
