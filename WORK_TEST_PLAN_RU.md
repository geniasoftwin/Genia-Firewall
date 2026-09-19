# Регрессионный тест-план GeniaFirewall 0.7.3 Stable

## 1. Чистая сборка и обновление

1. Закрыть GeniaFirewall.
2. В папке ранее установленной версии запустить `uninstall-service.cmd` от администратора.
3. В Stable выполнить `publish-portable.cmd` и убедиться, что он завершился без предупреждений/ошибок.
4. Сверить ZIP с `publish\GeniaFirewall-0.7.3-Stable-SHA256.txt`.
5. Из `publish\GeniaFirewall-0.7.3-Stable-win-x64\` запустить `install-service.cmd` от администратора.
6. Запустить UI, выбрать `GeniaFirewall WFP`, защиту ВКЛ, режим Normal.

## 2. Базовая диагностика

Ожидается:

```text
GeniaFirewall.Service: 0.7.3.4 · IPC OK
WFP session: engine=open · dynamic=да
WFP TUN policy: aware
WFP lifecycle: cleanup-verified=да · residual=0 · weight-plan=PROBE>APP>GLOBAL
WFP startup stale cleanup: removed=0 · residual=0 · clean; ... not-found (ok)
```

При активном TUN проверить `Virtual/TUN interfaces`. `fallback=ДА` считать отдельным диагностическим случаем.

## 3. Lifecycle acceptance

Пять раз подряд выполнить `Защита ВКЛ -> ВЫКЛ -> ВКЛ`.

При каждом выключении ожидается:

```text
engine может оставаться open
filters=0
residual=0
cleanup-verified=да
```

Ошибка `0x80320033` недопустима.

Трижды выполнить `GeniaFirewall WFP -> Windows Firewall Compatibility -> GeniaFirewall WFP` без перезагрузки Windows. После перехода в Compatibility ожидается `engine=closed`, provider/sublayer не зарегистрированы, `filters=0`, `residual=0`.

## 4. TUN acceptance

Правила: `GeniaProxy.exe = EnableAll/OutgoingOnly`, активный core (`xray.exe`/`sing-box.exe`) = `OutgoingOnly`.

Последовательно:

```text
Xray XHTTP TUN             ×5
Xray RAW/REALITY TUN       ×5
sing-box TUN               ×5
```

Каждый успешный запуск должен пройти readiness/connectivity probe без ручного Ask для уже разрешённых EXE. Таймаут приложения без соответствующего `WFP BLOCK` не классифицировать как доказанную блокировку GeniaFirewall.

## 5. Readiness UDP probe

Для разрешённого GeniaProxy UDP `1.1.1.1:53` / `1.0.0.1:53` не должен иметь `reason=DEFAULT_BLOCK` или `ASK_BLOCK`.

Если появляется DROP, сохранить строку:

```text
WFP BLOCK timeUtc=...; layer=...; filterId=...; pid=...; app=...; protocol=UDP; remote=1.1.1.1:53; ifIndex=...; interface=...; reason=...; matchedRule=...
```

## 6. Telemetry accuracy

- loopback должен отображаться как `127.0.0.1`, не `1.0.0.127`;
- `WFP last BLOCK` должен содержать `timeUtc`;
- `evicted=0` в коротком тестовом сеансе; после длительной работы это счётчик ротации ring buffer, не packet drop;
- исторический last BLOCK сверять по времени, а не считать текущей блокировкой автоматически.

## 7. Policy matrix

- `xray.exe`/`sing-box.exe -> DisableAll`: uplink прекращается;
- вернуть `OutgoingOnly`: uplink восстанавливается;
- неизвестный EXE в Normal: Ask/quarantine блокирует до решения;
- EnableAll разрешает inbound/outbound;
- IncomingOnly блокирует обычный non-loopback outbound;
- BlockAll блокирует неразрешённые приложения;
- AllowAll оставляет zero enforcing filters;
- Monitor не создаёт global default-deny.

## 8. LOCAL SOCKS и physical inbound

- `GeniaProxy + sing-box`, localhost `127.0.0.1:2080`: LOCAL SOCKS и проверка 1+20 работают при защите ВКЛ.
- Unsolicited inbound с Ethernet/Wi-Fi остаётся заблокирован Normal boundary policy.

## 9. Restart/recovery

1. При активной WFP policy перезапустить Service.
2. Убедиться, что persisted policy восстановлена и `restored=да`.
3. Остановить Service аварийно и запустить снова.
4. Ожидается startup cleanup `residual=0`, без orphan filters.
5. Повторить запуск UI с недоступной Service и проверить контролируемый fallback в Compatibility.

Полный release gate находится в `RELEASE_CHECKLIST_0.7.3-STABLE_RU.md`.
