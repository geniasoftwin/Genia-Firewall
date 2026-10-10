# Frequently asked questions

[Русский](FAQ_RU.md)

**Is GeniaFirewall open source?** Yes. Source is under [GPL-3.0-only](../LICENSE); you can review, test, fork and contribute subject to that license.

**Which Windows versions?** Windows 10/11 x64. The current .NET 10/WPF app is not built for Windows 7.

**Why UAC?** The standalone WFP backend uses a privileged Windows service. Installation/activation and protected configuration require administrator approval.

**Is installation the same for Stable and RC?** No. 0.7.3 Stable has manual `install-service.cmd`; 0.7.4 RC has the embedded service in one user-facing EXE. See [Installation](INSTALLATION.md).

**Should I disable Microsoft Defender Firewall?** No. GeniaFirewall uses WFP or Windows Firewall as a backend; Defender Firewall does not need to be disabled.

**Does Allow all open inbound LAN?** The explicit per-app **EnableAll** profile grants inbound+outbound on **GeniaFirewall WFP**. Windows Firewall Compatibility app rules are outbound-only.

**Why did an old rule become Outgoing only?** Legacy/default permissions may be preserved as outbound-only rather than silently widened. Recheck the application's intended access and explicitly select Allow all if needed.

**Is Ask a guaranteed pre-connect dialog?** No. A kernel-held first-connect prompt would require a WFP callout driver.

**Is an RC signed?** Never assume that; inspect signatures and release notes. 0.7.4 Stable requires signing of Service and UI.

**Are logs uploaded?** No automatic developer analytics/log uploading is designed in. Optional reverse DNS can query the Windows-configured resolver. See [Privacy](../PRIVACY.md).

**How do I remove everything?** Deactivate the WFP service first (0.7.4 RC) or use the corresponding uninstall script (0.7.3 Stable), then exit and delete the portable folder. See [Installation and removal](INSTALLATION.md).
