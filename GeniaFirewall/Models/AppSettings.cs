namespace GeniaFirewall.Models;

public sealed class AppSettings
{
    public bool ProtectionEnabled { get; set; } = true;
    public FirewallMode Mode { get; set; } = FirewallMode.Normal;

    // Portable/runtime behavior.
    public bool StartWithWindows { get; set; }
    public bool PlayDetectionSound { get; set; } = true;
    public bool ShowTrayNotifications { get; set; } = true;
    public bool ConfirmBlockAll { get; set; } = true;
    public bool RemoveMissingOnStartup { get; set; }
    public bool TrustVerifiedSystemProcesses { get; set; } = true;
    public bool ResolveHostNames { get; set; } = true;
    public bool ImmediateQuarantineOnForget { get; set; } = true;
    public UiLanguage UiLanguage { get; set; } = UiLanguage.Auto;
    public List<RuntimeQuarantineEntry> RuntimeQuarantines { get; set; } = [];
    public FirewallBackendMode BackendMode { get; set; } = FirewallBackendMode.WindowsFirewallCompatibility;

    // Window state is optional so settings from older builds remain compatible.
    public double? WindowLeft { get; set; }
    public double? WindowTop { get; set; }
    public double? WindowWidth { get; set; }
    public double? WindowHeight { get; set; }
    public bool WindowMaximized { get; set; }
}
