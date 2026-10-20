# VPN, TUN and LAN compatibility

[Русский](VPN_TUN_RU.md) · [Testing guide](../TESTING.md)

VPN/TUN tools may create virtual adapters and change routing. Rules can behave differently before, during and after tunneling.

GeniaFirewall's standalone **WFP app rules are intended to be independent of physical interface indices**. The default Normal-mode physical inbound boundary is scoped separately. This design has been tested with GeniaProxy/GeniaLink scenarios, but **compatibility with every VPN, TUN driver, network topology or third-party WFP product is not guaranteed**.

## Reproducible A/B test

1. Keep physical access to the test PC; avoid making changes through VPN/RDP alone.
2. Record Windows version, active backend, global mode, app profile, tunnel product/version and adapter.
3. Use **GeniaFirewall WFP** with **Normal**. Verify the app **without** TUN/VPN.
4. Start the tunnel, wait for adapter/routes to settle, test again. Include DNS, TCP, UDP and LAN as relevant.
5. Disconnect/reconnect; when feasible test sleep/resume and reboot.
6. Compare results with/without GeniaFirewall **only on a safe test machine**; re-enable enforcement afterward.
7. Collect only relevant timestamped WFP BLOCK records; redact credentials, paths and unrelated network data.

## Bidirectional LAN example

A discovery packet may use UDP while the actual transfer uses TCP. **Outgoing only** on the receiving PC does not permit inbound traffic; for a two-way app, set **Allow all** on both ends.

~~~powershell
Test-NetConnection <peer-IP> -Port <listening-TCP-port>
~~~

Run the TCP check **both directions** and then test the real application transfer. A successful TCP test does not by itself prove UDP discovery or app-level authorization.

| Symptom | Inspect first |
| --- | --- |
| UDP discovery works; TCP transfer fails | Inbound profile, listener and destination TCP port |
| Global Allow all works; Normal fails | App profile, matched WFP rule, inbound default block |
| VPN connected but DNS/UDP fails | Tunnel app profile, routes, resolver, WFP BLOCK log |
| Compatibility does not fix inbound | Compatibility app rules are outbound-only |
| Network stays blocked after backend switch | GeniaFirewall cleanup diagnostics; other WFP providers |

[More diagnosis](TROUBLESHOOTING.md)
