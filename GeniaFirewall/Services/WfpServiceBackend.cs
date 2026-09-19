using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public sealed class WfpServiceBackend : IFirewallBackend
{
    private readonly GeniaFirewallServiceClient _client;

    public WfpServiceBackend(GeniaFirewallServiceClient client)
    {
        _client = client;
    }

    public FirewallBackendKind Kind => FirewallBackendKind.WindowsFilteringPlatform;
    public string DisplayName => "GeniaFirewall WFP";

    public FirewallBackendCapabilities Capabilities { get; } = new(
        OutboundRules: true,
        InboundRules: true,
        IPv4: true,
        IPv6: true,
        Tcp: true,
        Udp: true,
        PreConnectDecision: false,
        RequiresKernelCallout: false);

    public void ApplyState(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode) =>
        ApplyOrThrow(applications, protectionEnabled, mode);

    public void SynchronizeState(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode) =>
        ApplyOrThrow(applications, protectionEnabled, mode);

    public void RemoveRules(Guid applicationId)
    {
        var result = _client.RemoveWfpApplication(applicationId);
        if (!result.Success)
            throw new InvalidOperationException($"GeniaFirewall.Service did not remove WFP application rule: {result.Description}");
    }

    public void RemoveAllGeniaFirewallRules()
    {
        var result = _client.ClearWfpPolicy();
        if (!result.Success || result.Status is null)
            throw new InvalidOperationException($"GeniaFirewall.Service did not clear WFP policy: {result.Description}");

        var status = result.Status;
        if (status.WfpBackendActive || status.WfpEngineOpen || status.ProviderRegistered || status.SubLayerRegistered ||
            status.ActiveFilterCount != 0 || !status.RuntimeFilterCleanupVerified || status.ResidualRuntimeFilterCount != 0)
        {
            throw new InvalidOperationException(
                $"GeniaFirewall.Service did not verify a zero-filter WFP state: " +
                $"backendActive={status.WfpBackendActive}; engineOpen={status.WfpEngineOpen}; provider={status.ProviderRegistered}; sublayer={status.SubLayerRegistered}; " +
                $"filters={status.ActiveFilterCount}; cleanupVerified={status.RuntimeFilterCleanupVerified}; residual={status.ResidualRuntimeFilterCount}.");
        }
    }

    public FirewallBackendDiagnostics GetDiagnostics()
    {
        var probe = _client.Probe();
        if (!probe.Reachable || probe.Status is not { } status)
            return new FirewallBackendDiagnostics(DisplayName, probe.Description, 0);

        var state = status.WfpBackendActive ? "active" : "inactive";
        return new FirewallBackendDiagnostics(
            DisplayName,
            $"{state} · {status.PolicyMode} · out={status.OutboundFilterCount} · in={status.InboundFilterCount} · filters={status.ActiveFilterCount}",
            status.ActiveFilterCount);
    }

    private void ApplyOrThrow(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode)
    {
        var result = _client.ApplyWfpPolicy(applications, protectionEnabled, mode);
        if (!result.Success)
            throw new InvalidOperationException($"GeniaFirewall.Service did not apply WFP policy: {result.Description}");
    }
}
