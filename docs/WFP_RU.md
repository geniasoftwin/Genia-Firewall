# Windows Filtering Platform: понятное объяснение

[English](WFP.md) · [Документация Microsoft WFP](https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-start-page)

**WFP** — штатная платформа сетевой фильтрации Windows. GeniaFirewall использует её API через привилегированную Windows-службу и **не устанавливает собственный kernel callout driver**.

~~~text
Portable WPF UI (правила, настройки, диагностика)
              │ авторизованный локальный IPC
              ▼
GeniaFirewall.Service (LocalSystem)
              │ управляет WFP-фильтрами программы
              ▼
Windows Filtering Platform / BFE
    ├─ ALE_AUTH_CONNECT       исходящие
    └─ ALE_AUTH_RECV_ACCEPT   входящие
              │
              ▼
TCP / UDP · IPv4 / IPv6 · LAN / Internet
~~~

Это упрощённая схема основных точек WFP authorization, а не всех фильтров Windows или сторонних защитных программ.

## Профили приложения в GeniaFirewall WFP

| Правило | Ожидаемая политика |
| --- | --- |
| Разрешить всё / EnableAll | Входящие + исходящие app permits |
| Только исходящие | Разрешение только исходящих |
| Только входящие | Разрешение только входящих |
| Запретить | Блокировка приложения |
| Спрашивать | UI-решение, с ограничениями реализации |

В режиме **Нормальный** входящее соединение может попасть под default inbound blocking boundary GeniaFirewall, если нет подходящего inbound app permit с нужным приоритетом. Отдельное inbound-правило Microsoft Defender Firewall не обязательно переопределяет эту WFP-блокировку.

Глобальный **Блокировать всё** имеет приоритет перед app Allow; **Разрешить всё** изменяет общую effective policy. Глобальные режимы и профили приложения — разные уровни управления.

**Ask пока не удерживает первое соединение на уровне ядра.** Для такого pre-connect prompt нужен WFP callout driver, которого программа сейчас не устанавливает.

## Backend не эквивалентны

- **GeniaFirewall WFP**: входящие и исходящие app-профили, прямое WFP enforcement, диагностика.
- **Windows Firewall Compatibility**: fallback с **исходящими app-правилами** Windows Firewall; не замена полноценному inbound WFP.

Runtime-фильтры используют dynamic WFP session; программа проверяет очистку собственных фильтров при деактивации/смене backend. На итог также влияют сторонние WFP-провайдеры, маршруты и политики Windows.

[VPN/TUN](VPN_TUN_RU.md) · [Модель безопасности](SECURITY_MODEL_RU.md)
