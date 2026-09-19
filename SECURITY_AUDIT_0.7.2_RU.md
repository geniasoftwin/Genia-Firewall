# Security audit notes — GeniaFirewall 0.7.2

- Loopback исключается только из directional/default blocks, где это соответствует профилю. Это не является глобальным bypass.
- `DisableAll` и `Ask` блокируют loopback как IN, так и OUT.
- `BlockAll` по умолчанию блокирует loopback; исключения создаются только для явно разрешённых приложений и только в соответствии с их профилем.
- `FWPM_CONDITION_FLAGS` используется на ALE_AUTH_CONNECT / ALE_AUTH_RECV_ACCEPT, где `FWP_CONDITION_FLAG_IS_LOOPBACK` поддерживается WFP.
- Правила остаются привязанными к `ALE_APP_ID`; разрешение GeniaProxy.exe не переносится автоматически на sing-box.exe/xray.exe.
- 0.7.2 всё ещё не является kernel callout pre-connect Ask. Telemetry наблюдательная, а Secure Prompt Quarantine остаётся user-mode реакцией после обнаружения.
