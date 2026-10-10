# Install, first launch and uninstall

[Русская версия](INSTALLATION_RU.md) · [FAQ](FAQ.md)

**Check your build first.** The released **0.7.3 Stable** and development **0.7.4 RC** use different service installation and removal procedures. 0.7.4 RC is not yet Stable.

## Before installation

- Supported: Windows 10/11 x64. For the WFP service, use an administrator account and approve UAC when requested.
- Download from [official Releases](https://github.com/geniasoftwin/Genia-Firewall/releases) or a clearly identified RC test artifact.
- Verify the published SHA-256 for the exact file you downloaded. In PowerShell, substitute the real ZIP filename:

~~~powershell
Get-FileHash -Algorithm SHA256 -LiteralPath ".\GeniaFirewall-release.zip"
~~~

Compare the hash against the value distributed with the release. A matching hash checks integrity **against that published value**; it does not prove publisher identity. RC builds may be unsigned. Do not test a firewall for the first time on a machine reachable only through RDP or VPN.

## Install 0.7.3 Stable — external service

1. Extract the matching Stable archive to a local directory.
2. Find **GeniaFirewall.Service.exe** and **install-service.cmd** in the extracted/published build.
3. Run **install-service.cmd as Administrator**; wait for “Service installed and started.”
4. The script copies the service to `%ProgramFiles%\GeniaFirewall\Service` and configures `GeniaFirewallService` to run as LocalSystem with a BFE dependency.
5. Run **GeniaFirewall.exe** from the portable directory.
6. In **Settings**, select **GeniaFirewall WFP** for app-level inbound and outbound enforcement; verify the backend and service status.
7. Start with **Normal** mode and grant app permissions consciously.

## Install 0.7.4 RC — embedded service / single user-facing EXE

1. Extract the RC package's **GeniaFirewall.exe** to a portable directory. Do not run it inside the ZIP.
2. Run the EXE. When the WFP service is enabled or activated through **Settings → WFP system service**, approve UAC if requested.
3. The app is designed to extract the embedded service to `%ProgramFiles%\GeniaFirewall\Service`; it verifies the payload SHA-256, protected ACLs, SCM configuration and IPC identity before using WFP.
4. Confirm the WFP service is active, select **GeniaFirewall WFP**, and use global **Normal**.
5. For apps that receive and send LAN traffic, choose the explicit **Allow all / EnableAll** app profile. **Outgoing only** does not grant inbound access.
6. Restart UI/Windows and confirm that the backend and rules persist as expected.

0.7.4 RC includes an update/rollback design for the embedded service. Do not follow 0.7.3 external-install scripts for this release line. **Do not promote 0.7.4 Stable without the planned Windows compatibility and Authenticode signing gates.**

## Verify the service

~~~powershell
Get-Service -Name GeniaFirewallService -ErrorAction SilentlyContinue
~~~

A running service alone does not prove that a desired WFP policy was applied. Also check GeniaFirewall diagnostics for backend health and WFP filter state.

## Safe removal: 0.7.4 RC

1. Disable **Start with Windows** in Settings and save, if enabled.
2. Export your configuration if you need the rules later.
3. Go to **Settings → WFP system service → Deactivate**. Wait for successful deactivation, WFP cleanup verification and Compatibility handoff.
4. If the operation fails, **do not forcibly delete the privileged service binary**. Save the diagnostics and investigate.
5. Exit using **tray icon → Exit** (closing the main window can just hide it).
6. Delete the portable folder and its `Data` directory only when you no longer need the settings/backups/logs. After confirming removal, an administrator may delete remaining GeniaFirewall-specific diagnostic/service state under `%ProgramData%\GeniaFirewall` if no longer required.

## Safe removal: 0.7.3 Stable

1. Disable autostart in Settings and exit from the tray menu.
2. Run **uninstall-service.cmd as Administrator** from the matching 0.7.3 package.
3. Wait for the service to stop and be deleted; dynamic WFP filters are released when the service session closes.
4. Check `Get-Service -Name GeniaFirewallService -ErrorAction SilentlyContinue`; after complete removal it should return no service. A pending deletion may require handles to close/reboot.
5. Delete the portable folder when no longer needed. **The 0.7.3 uninstall script does not automatically purge** `%ProgramData%\GeniaFirewall\Service` persisted state; remove it manually only after confirming the service is gone.

**Never delete Microsoft Defender Firewall or unrelated WFP providers** as part of GeniaFirewall removal.

See [Troubleshooting](TROUBLESHOOTING.md) if startup, deactivation or networking fails.
