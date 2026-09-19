# GeniaFirewall 0.6.0 — архитектура

0.6.0 вводит два взаимоисключающих backend режима:

1. **Windows Firewall Compatibility** — прежнее управление правилами Microsoft Defender Firewall через HNetCfg.FwPolicy2.
2. **GeniaFirewall WFP** — самостоятельное исходящее enforcement через GeniaFirewall.Service и Windows Filtering Platform.

## WFP backend

UI передаёт полный снимок политики по локальному named pipe v3. Изменяющие команды доступны только LocalSystem/Administrators. Служба проверяет/нормализует пути EXE, транзакционно заменяет динамические WFP-фильтры и после успешного commit сохраняет policy в `%ProgramData%\GeniaFirewall\Service\wfp-policy.json`.

При запуске службы policy читается и повторно устанавливается. Сами WFP provider/sublayer/filter остаются dynamic: при остановке службы они освобождаются автоматически.

Фильтрация 0.6.0 выполняется на `ALE_AUTH_CONNECT_V4` и `ALE_AUTH_CONNECT_V6`, отдельно для TCP и UDP, с `ALE_APP_ID` для правил приложений.

## Режимы

- Normal / Monitor: явные Allow и Block приложений устанавливаются в WFP.
- AllowAll: enforcing-фильтры GeniaFirewall не устанавливаются.
- BlockAll: разрешённые приложения получают app-specific PERMIT с высоким диапазоном веса, затем устанавливаются четыре catch-all BLOCK-фильтра TCP/UDP IPv4/IPv6 с более низким диапазоном веса.

## Безопасное переключение backend

Compatibility -> WFP: сначала служба подтверждает WFP policy, затем удаляются только compatibility-правила группы GeniaFirewall.

WFP -> Compatibility: сначала пересоздаются compatibility-правила, затем служба очищает WFP policy.

При ошибке WFP синхронизации на старте UI выполняет fallback на Compatibility.

## Ограничения 0.6.0

- inbound ещё не реализован;
- неизвестное приложение всё ещё обнаруживается watcher-ом post-connect, настоящий pre-connect Ask требует следующего этапа/callout;
- PERMIT GeniaFirewall не обходит блокировки других WFP-провайдеров;
- WFP policy привязана к абсолютным путям EXE через ALE_APP_ID;
- UI пока запускается elevated.
