# GeniaFirewall 0.7.3 Stable

Финальный релиз создан прямым продвижением прошедшего Windows acceptance кандидата RC1. Между RC1 и Stable не менялись policy model, WFP-фильтры, веса, IPC protocol или алгоритмы совместимости TUN.

## Подтверждено на Windows

- повторные циклы включения/выключения защиты проходят без `0x80320033`;
- переключение `GeniaFirewall WFP -> Compatibility -> GeniaFirewall WFP` проходит без зависших runtime-фильтров;
- после 17 дополнительных применений политики revision выросла с 5 до 22, а количество фильтров осталось 68;
- распределение фильтров осталось согласованным: outbound=60, inbound=8, IPv4=34, IPv6=34, TCP=34, UDP=34;
- `cleanup-verified=yes` и `residual=0` сохраняются;
- GeniaProxy/TUN работает при включённой защите без подтверждённого WFP BLOCK со стороны GeniaFirewall.

## Состав Stable

- dynamic WFP session и проверяемый zero-filter cleanup;
- очистка stale/orphan provider, sublayer и filters при старте;
- interface-independent application rules;
- TUN-aware physical inbound boundary;
- узкие readiness permits GeniaProxy для UDP DNS probe;
- порядок весов `PROBE(15) > APP(14) > GLOBAL(1)`;
- точная BLOCK telemetry с UTC-временем и корректным IPv4 byte order;
- IPC timeout, privilege checks и redaction непривилегированного status;
- проверка версий опубликованных EXE и SHA-256 release ZIP.
- установка LocalSystem-службы в защищённый `%ProgramFiles%\GeniaFirewall\Service` вместо пользовательской portable-папки;
- явный ACL служебного каталога и EXE только для `SYSTEM` и локальных администраторов.

## Релизные изменения относительно RC1

- снята метка RC1 в UI и документации;
- UI, Service и Protocol получили file version `0.7.3.4`;
- выходные каталоги и архивы переименованы в `GeniaFirewall-0.7.3-Stable-*`;
- IPC остаётся v13, pipe — `GeniaFirewall.Service.v13`.
- WFP/runtime-код по-прежнему идентичен принятому RC1; hardening затронул только install/update/uninstall scripts.

## Известное ограничение

Настоящий kernel pre-connect Ask не реализован. Для удержания самого первого connect до решения пользователя требуется WFP callout driver.
