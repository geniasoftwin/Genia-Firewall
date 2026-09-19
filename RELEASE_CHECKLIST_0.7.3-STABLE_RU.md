# Release checklist — GeniaFirewall 0.7.3 Stable

Функциональная WFP-часть финальной сборки идентична прошедшему Windows acceptance RC1. После смены релизной маркировки требуется только build/smoke-проверка финальных бинарников.

## Acceptance evidence — 2026-09-19

- Повторные применения политики увеличили revision с 5 до 22 без накопления фильтров: осталось ровно 68.
- Распределение осталось согласованным: outbound=60, inbound=8, IPv4=34, IPv6=34, TCP=34, UDP=34.
- `cleanup-verified=yes`, `residual=0`, startup stale cleanup — clean.
- Повторные переключения backend прошли без `0x80320033`.
- GeniaProxy/TUN проверен с включённой защитой без подтверждённой блокировки GeniaFirewall.

## Build gate

- `publish-portable.cmd` завершается с exit code 0.
- `GeniaFirewall.exe` и `GeniaFirewall.Service.exe` имеют file version `0.7.3.4`.
- ZIP и SHA-256 manifest созданы; checksum проходит повторную проверку.
- UI показывает `0.7.3 Stable`, Service — `0.7.3.4 · IPC OK`.
- `sc qc GeniaFirewallService` показывает binary path `%ProgramFiles%\GeniaFirewall\Service\GeniaFirewall.Service.exe`.
- ACL каталога и Service EXE не предоставляет обычным пользователям права записи/изменения.
- Обновление поверх ранее установленной версии и последующий uninstall проходят без оставшегося Service EXE.

## Lifecycle gate

- Пять циклов `Protection ON -> OFF -> ON` без ошибки.
- После каждого OFF: `filters=0`, `cleanup-verified=yes`, `residual=0`.
- Три цикла `WFP -> Compatibility -> WFP` без перезагрузки Windows.
- После остановки/перезапуска Service policy восстанавливается, orphan filters отсутствуют.

## Policy gate

- Normal, BlockAll, AllowAll и Monitor соответствуют `WORK_TEST_PLAN_RU.md`.
- EnableAll, OutgoingOnly, IncomingOnly, DisableAll и Ask проверены минимум на одном TCP и одном UDP приложении.
- LOCAL SOCKS/loopback работает для разрешённого приложения.
- Неожиданный physical inbound остаётся заблокирован.

## TUN gate

- Заведомо рабочий Xray TUN профиль запускается повторно.
- Заведомо рабочий sing-box TUN профиль запускается повторно.
- Ни один подтверждённый сбой не содержит GeniaFirewall DROP для разрешённого core/probe.
- Таймаут XHTTP без соответствующего WFP BLOCK не считается регрессией firewall.

## Diagnostics gate

- `127.0.0.1` отображается без разворота октетов.
- `WFP last BLOCK` содержит `timeUtc`.
- Ожидаемое отсутствие startup objects отображается как `not-found (ok)`.
- `evicted=0` в коротком acceptance-сеансе; ненулевое значение после длительной работы означает ротацию ring buffer, а не WFP packet drop.

Если smoke-проверка финальных бинарников выявит отличие от принятого RC1, релиз отзывается и выпускается новый кандидат.
