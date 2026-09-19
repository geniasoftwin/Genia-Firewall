namespace GeniaFirewall.Models;

public sealed class PortableConfiguration
{
    public string Format { get; set; } = "GeniaFirewallPortableConfig";
    public int SchemaVersion { get; set; } = 1;
    public DateTime ExportedAtUtc { get; set; } = DateTime.UtcNow;
    public List<ManagedApplication> Applications { get; set; } = [];
    public PortableConfigurationSettings Settings { get; set; } = new();
}

public sealed class PortableConfigurationSettings
{
    public bool ProtectionEnabled { get; set; } = true;
    public FirewallMode Mode { get; set; } = FirewallMode.Normal;
    public bool PlayDetectionSound { get; set; } = true;
    public bool ShowTrayNotifications { get; set; } = true;
    public bool ResolveHostNames { get; set; } = true;
    public bool ImmediateQuarantineOnForget { get; set; } = true;
    public UiLanguage UiLanguage { get; set; } = UiLanguage.Auto;
    public bool ConfirmBlockAll { get; set; } = true;
    public bool RemoveMissingOnStartup { get; set; }
    public bool TrustVerifiedSystemProcesses { get; set; } = true;
}
