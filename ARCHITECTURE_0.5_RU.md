# GeniaFirewall 0.5 — служба и WFP policy host

## Что меняется в 0.5.0

0.5.0 вводит отдельный привилегированный процесс `GeniaFirewall.Service.exe` и общий IPC-контракт `GeniaFirewall.Protocol`.

```text
GeniaFirewall.exe (WPF, пока elevated для compatibility backend)
        │
        │ read-only named-pipe status IPC
        ▼
GeniaFirewall.Service.exe (Windows Service / LocalSystem)
        │
        ├─ dynamic WFP management session
        ├─ GeniaFirewall provider
        └─ GeniaFirewall sublayer
                │
                ▼
       Windows Filtering Platform / BFE
```

Рабочее применение Allow/Block в 0.5.0 по-прежнему выполняется через `WindowsFirewallBackend` (`HNetCfg.FwPolicy2`). Служба ещё **не устанавливает traffic filters**, поэтому `ActiveFilterCount = 0` является ожидаемым состоянием.

## Почему provider/sublayer уже полезны

Служба открывает отдельную `FWPM_SESSION_FLAG_DYNAMIC` сессию и регистрирует собственные WFP provider/sublayer. Это проверяет четыре будущих критических элемента без риска блокировки сети:

1. SCM-служба действительно запускается как отдельный процесс.
2. Служба имеет доступ к BFE/WFP management API.
3. GeniaFirewall получает собственное пространство WFP policy objects.
4. При остановке/краше службы объекты динамической сессии автоматически удаляются BFE.

## IPC в 0.5.0

Named pipe `GeniaFirewall.Service.v1` в этом релизе принимает только `ping`/`status`. Команд изменения firewall policy нет намеренно. До появления ACL/аутентификации/валидации клиента никакие security-critical команды по этому каналу не принимаются.

## Следующий шаг: 0.5.1 / 0.6

```text
UI
 │  authenticated IPC
 ▼
Service
 ├─ Rule Engine
 ├─ Process / signer / hash verification
 └─ WFP filters
      ├─ ALE_AUTH_CONNECT_V4
      ├─ ALE_AUTH_CONNECT_V6
      ├─ ALE_AUTH_RECV_ACCEPT_V4
      └─ ALE_AUTH_RECV_ACCEPT_V6
```

Сначала будут перенесены статические `Allow`/`Block` правила. После проверки rollback UI сможет работать без постоянного elevation. Настоящий `Ask` до первого пакета остаётся отдельным этапом и потребует WFP callout driver.

## Принципы миграции

- Compatibility backend не удаляется, пока WFP backend не проходит тесты.
- Никакой автоматической активации фильтров без явного переключателя и аварийного rollback.
- Provider/sublayer/filter GUID принадлежат только GeniaFirewall.
- WFP management objects в ранней миграции — dynamic, чтобы не оставлять stale policy после crash.
- UI не становится доверенной границей: служба должна перепроверять пути, hash, signer и параметры правил.
