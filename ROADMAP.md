# GeniaFirewall roadmap

This roadmap is directional, not a promise of dates.

## 0.7.4 release candidate line

Current goals:

- hardened single-EXE portable service lifecycle;
- verified WFP cleanup and backend handoff;
- consistent per-app profile semantics;
- bidirectional EnableAll regression coverage;
- Windows 10/11 smoke testing;
- Authenticode signing path for public Stable builds.

## Stable gate

A Stable release should not be promoted until:

- CI passes;
- CodeQL passes;
- manual Windows 10/11 validation is complete;
- service lifecycle and reboot tests pass;
- WFP/Compatibility handoff leaves no residual GeniaFirewall filters;
- both privileged service and UI release binaries follow the approved signing process.

## After 0.7.4

Areas worth exploring:

- more automated policy-mapping regression tests;
- broader VPN/TUN compatibility matrix;
- additional UI/localization contributions;
- improved diagnostics and reproducible support bundles with privacy-safe redaction;
- research into a WFP callout design for a true held pre-connect Ask workflow.

Community feedback may change priorities.
