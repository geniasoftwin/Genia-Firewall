# Изменения GeniaFirewall 0.7.3

- Исправлен regression TUN режима GeniaProxy/Xray/sing-box при включённой защите.
- Normal global inbound default-deny теперь scoped к physical interface indexes.
- Loopback и virtual/TUN interfaces не блокируются глобальным physical inbound rule.
- `DisableAll`/`Ask` продолжают блокировать приложение на всех интерфейсах.
- В BlockAll добавлены точечные virtual-interface permits для directional allow profiles.
- Добавлена автоматическая классификация virtual/TUN adapters.
- При изменении состава/адресов интерфейсов WFP policy переустанавливается после debounce.
- Добавлена диагностика physical interfaces, virtual/TUN interfaces и fail-safe fallback.
- IPC: v12 (`GeniaFirewall.Service.v12`).
- Версии UI/Service/Protocol/manifest: `0.7.3.0`.
