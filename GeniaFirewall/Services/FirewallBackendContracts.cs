using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public enum FirewallBackendKind
{
    WindowsFirewallCompatibility,
    WindowsFilteringPlatform
}

public sealed record FirewallBackendCapabilities(
    bool OutboundRules,
    bool InboundRules,
    bool IPv4,
    bool IPv6,
    bool Tcp,
    bool Udp,
    bool PreConnectDecision,
    bool RequiresKernelCallout);

public readonly record struct FirewallBackendDiagnostics(
    string BackendName,
    string ProfileStatus,
    int GeniaFirewallRuleCount);

public interface IFirewallBackend
{
    FirewallBackendKind Kind { get; }
    string DisplayName { get; }
    FirewallBackendCapabilities Capabilities { get; }

    void ApplyState(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode);
    void SynchronizeState(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode);
    void RemoveRules(Guid applicationId);
    void RemoveAllGeniaFirewallRules();
    FirewallBackendDiagnostics GetDiagnostics();
}
