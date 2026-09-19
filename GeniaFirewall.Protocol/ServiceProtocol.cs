namespace GeniaFirewall.Protocol;

public static class ServiceProtocol
{
    public const string ServiceName = "GeniaFirewallService";
    public const string DisplayName = "GeniaFirewall Service";
    public const string PipeName = "GeniaFirewall.Service.v13";
    public const string ProtocolVersion = "13";
    public const string ProductVersion = "0.7.3.4";
    public const int MaxPolicyApplications = 5000;
    public const int MaxRequestCharacters = 2 * 1024 * 1024;
    public const int MaxTelemetryEventsPerResponse = 256;
}

public enum WfpPolicyMode
{
    Normal,
    BlockAll,
    AllowAll,
    Monitor
}

public enum WfpRuleAccess
{
    Allow,
    Block,
    Ask
}

public enum WfpRuleProfile
{
    Default,
    EnableAll,
    OutgoingOnly,
    IncomingOnly,
    DisableAll,
    Ask
}

public enum WfpTelemetryDirection
{
    Unknown,
    Inbound,
    Outbound
}

public enum WfpTelemetryAction
{
    Unknown,
    Allow,
    Drop
}

public enum WfpTelemetryScope
{
    Unknown,
    Internet,
    Lan,
    Loopback
}

public sealed record ServiceStatusSnapshot
{
    public string ProtocolVersion { get; init; } = ServiceProtocol.ProtocolVersion;
    public string ProductVersion { get; init; } = ServiceProtocol.ProductVersion;
    public string ServiceName { get; init; } = ServiceProtocol.ServiceName;
    public bool Running { get; init; }
    public bool WfpEngineOpen { get; init; }
    public bool DynamicSession { get; init; }
    public bool ProviderRegistered { get; init; }
    public bool SubLayerRegistered { get; init; }
    public bool WfpBackendActive { get; init; }
    public bool ProtectionEnabled { get; init; }
    public WfpPolicyMode PolicyMode { get; init; } = WfpPolicyMode.Normal;
    public bool PolicyRestoredOnStartup { get; init; }
    public int AllowedApplicationCount { get; init; }
    public int BlockedApplicationCount { get; init; }
    public int PendingApplicationCount { get; init; }
    public int ActiveFilterCount { get; init; }
    public int GlobalBlockFilterCount { get; init; }
    public int IPv4FilterCount { get; init; }
    public int IPv6FilterCount { get; init; }
    public int TcpFilterCount { get; init; }
    public int UdpFilterCount { get; init; }
    public int OutboundFilterCount { get; init; }
    public int InboundFilterCount { get; init; }
    public int GlobalOutboundBlockFilterCount { get; init; }
    public int GlobalInboundBlockFilterCount { get; init; }
    public bool LoopbackAwareDirectionalRules { get; init; }
    public bool TunAwareDirectionalRules { get; init; }
    public int PhysicalInboundInterfaceCount { get; init; }
    public int VirtualTunInterfaceCount { get; init; }
    public bool InterfaceScopeFallback { get; init; }
    public string PhysicalInterfaceSummary { get; init; } = string.Empty;
    public string VirtualTunInterfaceSummary { get; init; } = string.Empty;
    public long PolicyRevision { get; init; }
    public DateTime StartupUtc { get; init; }
    public string LastError { get; init; } = string.Empty;

    // 0.7.1: read-only WFP net-event telemetry. This does not change enforcement.
    public bool NetEventTelemetryAvailable { get; init; }
    public long NetEventTelemetryLastSequence { get; init; }
    public long NetEventTelemetryReceivedCount { get; init; }
    public long NetEventTelemetryDroppedCount { get; init; }
    public string NetEventTelemetryLastError { get; init; } = string.Empty;

    // 0.7.3 HF2: runtime-filter lifecycle verification and stale-object cleanup.
    public bool RuntimeFilterCleanupVerified { get; init; }
    public int ResidualRuntimeFilterCount { get; init; }
    public DateTime? LastFilterCleanupUtc { get; init; }
    public bool StartupStaleCleanupAttempted { get; init; }
    public int StartupStaleFilterRemovedCount { get; init; }
    public int StartupStaleFilterResidualCount { get; init; }
    public string StartupStaleCleanupStatus { get; init; } = string.Empty;
    public bool FilterWeightPlanValid { get; init; }
    public long BlockedEventCount { get; init; }
    public string LastBlockedEventSummary { get; init; } = string.Empty;
}

public sealed record ServiceCommandRequest
{
    public string Command { get; init; } = string.Empty;
    public WfpPolicySnapshot? Policy { get; init; }
    public Guid ApplicationId { get; init; }
    public long AfterEventSequence { get; init; }
    public int MaxEvents { get; init; } = 128;
}

public sealed record ServiceCommandResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public ServiceStatusSnapshot? Status { get; init; }
    public List<WfpNetEventSnapshot>? NetEvents { get; init; }
}

public sealed record WfpNetEventSnapshot
{
    public long Sequence { get; init; }
    public DateTime SeenUtc { get; init; }
    public string ExePath { get; init; } = string.Empty;
    public string Protocol { get; init; } = string.Empty;
    public string LocalAddress { get; init; } = string.Empty;
    public int LocalPort { get; init; }
    public string RemoteAddress { get; init; } = string.Empty;
    public int RemotePort { get; init; }
    public WfpTelemetryDirection Direction { get; init; }
    public WfpTelemetryAction Action { get; init; }
    public WfpTelemetryScope Scope { get; init; }
    public bool IsLoopback { get; init; }
    public ulong FilterId { get; init; }
    public ushort LayerId { get; init; }
    public string LayerName { get; init; } = string.Empty;
    public uint InterfaceIndex { get; init; }
    public string InterfaceName { get; init; } = string.Empty;
    public string MatchedFilterName { get; init; } = string.Empty;
    public string Reason { get; init; } = string.Empty;
}

public sealed record WfpPolicySnapshot
{
    public string SchemaVersion { get; init; } = "2";
    public bool BackendActive { get; init; }
    public bool ProtectionEnabled { get; init; }
    public WfpPolicyMode Mode { get; init; } = WfpPolicyMode.Normal;
    public List<WfpApplicationRule> Applications { get; init; } = [];
}

public sealed record WfpApplicationRule
{
    public Guid ApplicationId { get; init; }
    public string ExePath { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public WfpRuleAccess Access { get; init; }
    public WfpRuleProfile Profile { get; init; } = WfpRuleProfile.Default;
}
