# GeniaFirewall 0.5.1 — первые реальные WFP traffic filters

## Главное

0.5.1 — первый релиз, в котором `GeniaFirewall.Service` может реально влиять на исходящий трафик через Windows Filtering Platform.

Экспериментальный режим **GeniaFirewall WFP — TEST** устанавливает динамические `FWP_ACTION_BLOCK` filters для приложений, которым в GeniaFirewall назначено действие `Block`.

Фильтры создаются на:

- `FWPM_LAYER_ALE_AUTH_CONNECT_V4`;
- `FWPM_LAYER_ALE_AUTH_CONNECT_V6`;
- TCP (`IPPROTO_TCP`);
- UDP (`IPPROTO_UDP`);
- условие приложения: `FWPM_CONDITION_ALE_APP_ID`.

Для одного заблокированного EXE создаётся 4 WFP-фильтра: IPv4/TCP, IPv4/UDP, IPv6/TCP, IPv6/UDP.

## Безопасность перехода

- Microsoft Defender Firewall остаётся основным backend.
- WFP TEST по умолчанию выключен.
- `Allow` в 0.5.1 не пытается обходить/перекрывать блокировки Defender Firewall: отсутствие WFP TEST block означает только отсутствие дополнительного GeniaFirewall WFP veto.
- Обновление набора WFP filters выполняется транзакционно (`FwpmTransactionBegin0/Commit0/Abort0`). При ошибке предыдущий набор filters сохраняется.
- Все filters динамические: при остановке `GeniaFirewall.Service` WFP удаляет их вместе с dynamic session.
- Добавлен `emergency-stop-wfp.cmd`: остановка службы мгновенно снимает WFP TEST policy, не удаляя правила Microsoft Defender Firewall.

## IPC

Протокол поднят до v2 (`GeniaFirewall.Service.v2`).

- `status` остаётся read-only.
- policy mutation (`apply-wfp-test-policy`, `clear-wfp-test-policy`) разрешена только клиенту, который при impersonation является LocalSystem или членом локальной группы Administrators.
- размер IPC request ограничен 2 MiB;
- policy ограничен 5000 приложениями;
- Service повторно валидирует абсолютный EXE path и существование файла.

## Диагностика

UI показывает:

- WFP TEST active;
- blocked apps;
- общий filter count;
- IPv4/IPv6 filter count;
- TCP/UDP filter count;
- policy revision.

## Версии

- Release: `0.5.1`.
- `Version`, `AssemblyVersion`, `FileVersion`: `0.5.1.0`.
- UI manifest: `0.5.1.0`.
- Service manifest: `0.5.1.0`.
- Protocol: `0.5.1.0`, IPC protocol v2.
- Publish: `publish\GeniaFirewall-0.5.1-win-x64`.
