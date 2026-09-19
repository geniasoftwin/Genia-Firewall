using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

internal sealed record WfpFilterDescriptor(ulong FilterId, string Name, string Reason, string AppPath);

/// <summary>
/// Owns the GeniaFirewall dynamic WFP session. 0.7.3 keeps explicit app rules
/// authoritative while making the normal-mode unsolicited-inbound default deny
/// loopback- and TUN/virtual-interface-aware. The broad inbound block is scoped to
/// physical/external-facing interface indexes; explicit DisableAll/Ask still block
/// every interface. The service persists policy separately and replays it after restart.
/// </summary>
internal sealed class WfpSessionManager : IDisposable
{
    private const uint RpcCAuthnWinnt = 10;
    private const uint FwpmSessionFlagDynamic = 0x00000001;
    private const uint FwpEmpty = 0;
    private const uint FwpUint8 = 1;
    private const uint FwpUint16 = 2;
    private const uint FwpUint32 = 3;
    private const uint FwpByteBlobType = 12;
    private const uint FwpMatchEqual = 0;
    private const uint FwpMatchFlagsAnySet = 7;
    private const uint FwpMatchFlagsNoneSet = 8;
    private const uint FwpActionBlock = 0x00001001;
    private const uint FwpActionPermit = 0x00001002;
    private const byte IpProtoTcp = 6;
    private const byte IpProtoUdp = 17;
    private const uint FwpConditionFlagIsLoopback = 0x00000001;
    // Weight ranges are intentionally separated. WFP auto-weights inside a UINT8 range;
    // a higher range always wins over a lower range in this sublayer.
    private const byte ReadinessProbeWeightRange = 15;
    private const byte ApplicationWeightRange = 14;
    private const byte GlobalBlockWeightRange = 1;

    internal static readonly Guid ProviderKey = new("A6EE1C6D-0D49-4B3F-B240-98ED3FFBB1C3");
    internal static readonly Guid SubLayerKey = new("DC5AE30A-AC35-4A21-A730-340BC721A3A9");

    private static readonly Guid LayerAleAuthConnectV4 = new("C38D57D1-05A7-4C33-904F-7FBCEEE60E82");
    private static readonly Guid LayerAleAuthConnectV6 = new("4A72393B-319F-44BC-84C3-BA54DCB3B6B4");
    private static readonly Guid LayerAleAuthRecvAcceptV4 = new("E1CD9FE7-F4B5-4273-96C0-592E487B8650");
    private static readonly Guid LayerAleAuthRecvAcceptV6 = new("A3B42C97-9F04-4672-B87E-CEE9C483257F");
    private static readonly Guid ConditionAleAppId = new("D78E1E87-8644-4EA5-9437-D809ECEFC971");
    private static readonly Guid ConditionIpProtocol = new("3971EF2B-623E-4F9A-8CB1-6E79B806B9A7");
    private static readonly Guid ConditionIpRemoteAddress = new("B235AE9A-1D64-49B8-A44C-5FF3D9095045");
    private static readonly Guid ConditionIpRemotePort = new("C35A604D-D22B-4E1A-91B4-68F674EE674B");
    private static readonly Guid ConditionFlags = new("632CE23B-5167-435C-86D7-E903684AA80C");
    private static readonly Guid ConditionArrivalInterfaceIndex = new("CC088DB3-1792-4A71-B0F9-037D21CD828B");
    private static readonly Guid ConditionNexthopInterfaceIndex = new("138E6888-7AB8-4D65-9EE8-0591BCF6A494");

    private readonly object _sync = new();
    private readonly List<ulong> _activeFilterIds = [];
    private readonly Dictionary<ulong, WfpFilterDescriptor> _activeFilterDescriptors = [];
    private Dictionary<ulong, WfpFilterDescriptor>? _buildingFilterDescriptors;
    private IntPtr _engineHandle;
    private bool _providerRegistered;
    private bool _subLayerRegistered;
    private bool _backendActive;
    private bool _protectionEnabled;
    private WfpPolicyMode _policyMode = WfpPolicyMode.Normal;
    private bool _policyRestoredOnStartup;
    private int _allowedApplicationCount;
    private int _blockedApplicationCount;
    private int _pendingApplicationCount;
    private int _globalBlockFilterCount;
    private int _ipv4FilterCount;
    private int _ipv6FilterCount;
    private int _tcpFilterCount;
    private int _udpFilterCount;
    private int _outboundFilterCount;
    private int _inboundFilterCount;
    private int _globalOutboundBlockFilterCount;
    private int _globalInboundBlockFilterCount;
    private long _policyRevision;
    private bool _tunAwareDirectionalRules = true;
    private int _physicalInboundInterfaceCount;
    private int _virtualTunInterfaceCount;
    private bool _interfaceScopeFallback;
    private string _physicalInterfaceSummary = string.Empty;
    private string _virtualTunInterfaceSummary = string.Empty;
    private string _lastError = string.Empty;
    private bool _runtimeFilterCleanupVerified = true;
    private int _residualRuntimeFilterCount;
    private DateTime? _lastFilterCleanupUtc;
    private bool _startupStaleCleanupAttempted;
    private int _startupStaleFilterRemovedCount;
    private int _startupStaleFilterResidualCount;
    private string _startupStaleCleanupStatus = string.Empty;
    private readonly bool _filterWeightPlanValid = ReadinessProbeWeightRange > ApplicationWeightRange && ApplicationWeightRange > GlobalBlockWeightRange;
    private bool _disposed;

    public void Start()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_engineHandle != IntPtr.Zero)
                return;

            if (!_filterWeightPlanValid)
                throw new InvalidOperationException("Invalid WFP filter-weight plan: PROBE > APP > GLOBAL is required.");

            ServiceLog.Write($"WFP weight plan: PROBE={ReadinessProbeWeightRange}; APP={ApplicationWeightRange}; GLOBAL={GlobalBlockWeightRange}; valid={_filterWeightPlanValid}.");

            var staleCleanup = WfpOwnedFilterInventory.CleanupStaleObjectsBestEffort();
            _startupStaleCleanupAttempted = staleCleanup.Attempted;
            _startupStaleFilterRemovedCount = staleCleanup.RemovedFilterCount;
            _startupStaleFilterResidualCount = staleCleanup.ResidualFilterCount;
            _startupStaleCleanupStatus = staleCleanup.Status;
            _lastFilterCleanupUtc = DateTime.UtcNow;
            _residualRuntimeFilterCount = staleCleanup.ResidualFilterCount;
            _runtimeFilterCleanupVerified = staleCleanup.ResidualFilterCount == 0;
            ServiceLog.Write(
                $"WFP startup stale-object check: removed={staleCleanup.RemovedFilterCount}; " +
                $"residual={staleCleanup.ResidualFilterCount}; {staleCleanup.Status}");

            var session = new FwpmSession0
            {
                SessionKey = Guid.Empty,
                DisplayData = new FwpmDisplayData0
                {
                    Name = $"GeniaFirewall {ServiceProtocol.ProductVersion} WFP session",
                    Description = "Dynamic inbound/outbound policy session owned by GeniaFirewall.Service"
                },
                Flags = FwpmSessionFlagDynamic,
                TxnWaitTimeoutInMSec = 5000,
                ProcessId = 0,
                Sid = IntPtr.Zero,
                Username = IntPtr.Zero,
                KernelMode = 0
            };

            var result = FwpmEngineOpen0(null, RpcCAuthnWinnt, IntPtr.Zero, ref session, out _engineHandle);
            if (result != 0 || _engineHandle == IntPtr.Zero)
            {
                _engineHandle = IntPtr.Zero;
                _lastError = $"FwpmEngineOpen0 failed: 0x{result:X8}";
                throw new InvalidOperationException(_lastError);
            }

            try
            {
                RegisterProvider();
                RegisterSubLayer();
                _lastError = string.Empty;
            }
            catch
            {
                CloseEngineUnsafe();
                throw;
            }
        }
    }

    public void ApplyPolicy(WfpPolicySnapshot requestedPolicy, bool restoredOnStartup = false)
    {
        ArgumentNullException.ThrowIfNull(requestedPolicy);

        lock (_sync)
        {
            ThrowIfDisposed();
            if (_engineHandle == IntPtr.Zero)
                Start();
            EnsureEngineOpen();

            if (!string.Equals(requestedPolicy.SchemaVersion, "2", StringComparison.Ordinal))
                throw new InvalidOperationException($"Unsupported WFP policy schema '{requestedPolicy.SchemaVersion}'.");

            if (!Enum.IsDefined(requestedPolicy.Mode))
                throw new InvalidOperationException($"Unsupported WFP policy mode '{requestedPolicy.Mode}'.");

            var requestedApplications = requestedPolicy.Applications
                ?? throw new InvalidOperationException("WFP policy applications collection is missing.");

            if (requestedApplications.Count > ServiceProtocol.MaxPolicyApplications)
                throw new InvalidOperationException($"Policy contains more than {ServiceProtocol.MaxPolicyApplications} applications.");

            var rules = NormalizeRules(requestedApplications);
            ReplaceFiltersTransactionally(requestedPolicy, rules, restoredOnStartup);
        }
    }

    public ServiceStatusSnapshot CreateSnapshot(DateTime startupUtc, string serviceError = "")
    {
        lock (_sync)
        {
            var error = string.IsNullOrWhiteSpace(serviceError) ? _lastError : serviceError;
            return new ServiceStatusSnapshot
            {
                Running = true,
                WfpEngineOpen = _engineHandle != IntPtr.Zero,
                DynamicSession = _engineHandle != IntPtr.Zero,
                ProviderRegistered = _providerRegistered,
                SubLayerRegistered = _subLayerRegistered,
                WfpBackendActive = _backendActive,
                ProtectionEnabled = _protectionEnabled,
                PolicyMode = _policyMode,
                PolicyRestoredOnStartup = _policyRestoredOnStartup,
                AllowedApplicationCount = _allowedApplicationCount,
                BlockedApplicationCount = _blockedApplicationCount,
                PendingApplicationCount = _pendingApplicationCount,
                ActiveFilterCount = _activeFilterIds.Count,
                GlobalBlockFilterCount = _globalBlockFilterCount,
                IPv4FilterCount = _ipv4FilterCount,
                IPv6FilterCount = _ipv6FilterCount,
                TcpFilterCount = _tcpFilterCount,
                UdpFilterCount = _udpFilterCount,
                OutboundFilterCount = _outboundFilterCount,
                InboundFilterCount = _inboundFilterCount,
                GlobalOutboundBlockFilterCount = _globalOutboundBlockFilterCount,
                GlobalInboundBlockFilterCount = _globalInboundBlockFilterCount,
                LoopbackAwareDirectionalRules = true,
                TunAwareDirectionalRules = _tunAwareDirectionalRules,
                PhysicalInboundInterfaceCount = _physicalInboundInterfaceCount,
                VirtualTunInterfaceCount = _virtualTunInterfaceCount,
                InterfaceScopeFallback = _interfaceScopeFallback,
                PhysicalInterfaceSummary = _physicalInterfaceSummary,
                VirtualTunInterfaceSummary = _virtualTunInterfaceSummary,
                RuntimeFilterCleanupVerified = _runtimeFilterCleanupVerified,
                ResidualRuntimeFilterCount = _residualRuntimeFilterCount,
                LastFilterCleanupUtc = _lastFilterCleanupUtc,
                StartupStaleCleanupAttempted = _startupStaleCleanupAttempted,
                StartupStaleFilterRemovedCount = _startupStaleFilterRemovedCount,
                StartupStaleFilterResidualCount = _startupStaleFilterResidualCount,
                StartupStaleCleanupStatus = _startupStaleCleanupStatus,
                FilterWeightPlanValid = _filterWeightPlanValid,
                PolicyRevision = _policyRevision,
                StartupUtc = startupUtc,
                LastError = error
            };
        }
    }

    internal WfpFilterDescriptor? ResolveFilter(ulong filterId)
    {
        lock (_sync)
            return _activeFilterDescriptors.TryGetValue(filterId, out var descriptor) ? descriptor : null;
    }

    private static List<WfpApplicationRule> NormalizeRules(IEnumerable<WfpApplicationRule> requestedRules)
    {
        var normalized = new List<WfpApplicationRule>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenIds = new HashSet<Guid>();
        var servicePath = Environment.ProcessPath is { Length: > 0 }
            ? Path.GetFullPath(Environment.ProcessPath)
            : string.Empty;

        foreach (var rule in requestedRules)
        {
            if (rule.ApplicationId == Guid.Empty)
                continue;

            if (!seenIds.Add(rule.ApplicationId))
                continue;

            if (string.IsNullOrWhiteSpace(rule.ExePath) || !Path.IsPathFullyQualified(rule.ExePath))
                continue;

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(rule.ExePath);
            }
            catch
            {
                continue;
            }

            if (!fullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(fullPath))
                continue;

            if (!string.IsNullOrWhiteSpace(servicePath) && string.Equals(fullPath, servicePath, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!seenPaths.Add(fullPath))
                continue;

            normalized.Add(rule with
            {
                ExePath = fullPath,
                DisplayName = string.IsNullOrWhiteSpace(rule.DisplayName)
                    ? Path.GetFileName(fullPath)
                    : rule.DisplayName.Trim(),
                Profile = NormalizeProfile(rule)
            });
        }

        return normalized;
    }

    private static WfpRuleProfile NormalizeProfile(WfpApplicationRule rule)
    {
        if (!Enum.IsDefined(rule.Profile))
            return rule.Access switch
            {
                WfpRuleAccess.Allow => WfpRuleProfile.OutgoingOnly,
                WfpRuleAccess.Block => WfpRuleProfile.DisableAll,
                _ => WfpRuleProfile.Ask
            };

        return rule.Access switch
        {
            WfpRuleAccess.Allow when rule.Profile is WfpRuleProfile.EnableAll or WfpRuleProfile.OutgoingOnly or WfpRuleProfile.IncomingOnly => rule.Profile,
            WfpRuleAccess.Allow => WfpRuleProfile.OutgoingOnly,
            WfpRuleAccess.Block => WfpRuleProfile.DisableAll,
            WfpRuleAccess.Ask => WfpRuleProfile.Ask,
            _ => WfpRuleProfile.Ask
        };
    }

    private void ReplaceFiltersTransactionally(
        WfpPolicySnapshot policy,
        IReadOnlyList<WfpApplicationRule> rules,
        bool restoredOnStartup)
    {
        var beginResult = FwpmTransactionBegin0(_engineHandle, 0);
        if (beginResult != 0)
        {
            _lastError = $"FwpmTransactionBegin0 failed: 0x{beginResult:X8}";
            throw new InvalidOperationException(_lastError);
        }

        var interfaceScope = NetworkInterfaceScopeCatalog.Capture();
        var newFilterIds = new List<ulong>();
        _buildingFilterDescriptors = [];
        var ipv4 = 0;
        var ipv6 = 0;
        var tcp = 0;
        var udp = 0;
        var outbound = 0;
        var inbound = 0;
        var globalOutboundBlocks = 0;
        var globalInboundBlocks = 0;
        var transactionOpen = true;

        try
        {
            foreach (var filterId in _activeFilterIds)
            {
                var deleteResult = FwpmFilterDeleteById0(_engineHandle, filterId);
                if (deleteResult != 0)
                    throw new InvalidOperationException($"FwpmFilterDeleteById0({filterId}) failed: 0x{deleteResult:X8}");
            }

            var enforce = policy.BackendActive && policy.ProtectionEnabled;
            if (enforce && policy.Mode == WfpPolicyMode.Normal)
            {
                // Normal mode is stateful default-deny for unsolicited inbound traffic.
                // Existing/authorized outbound flows still receive their return traffic through ALE state.
                foreach (var rule in rules)
                    AddApplicationProfileFilters(rule, WfpPolicyMode.Normal, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);

                globalInboundBlocks = AddGlobalInboundBlockFilters(
                    newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref inbound,
                    excludeLoopback: true,
                    physicalInterfaceIndexes: interfaceScope.PhysicalInterfaceIndexes,
                    failSafeFallback: interfaceScope.UsedFallback,
                    reason: "DEFAULT_BLOCK");
            }
            else if (enforce && policy.Mode == WfpPolicyMode.Monitor)
            {
                // Monitor keeps explicit permanent rules but ASK remains observational and is not quarantined.
                foreach (var rule in rules.Where(rule => rule.Access != WfpRuleAccess.Ask))
                    AddApplicationProfileFilters(rule, WfpPolicyMode.Monitor, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
            }
            else if (enforce && policy.Mode == WfpPolicyMode.BlockAll)
            {
                // Only directional permits are needed above the catch-all blocks.
                foreach (var rule in rules.Where(rule => rule.Access == WfpRuleAccess.Allow))
                    AddApplicationProfileFilters(rule, WfpPolicyMode.BlockAll, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);

                AddGlobalOutboundBlockFilters(newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound);
                globalInboundBlocks = AddGlobalInboundBlockFilters(
                    newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref inbound,
                    excludeLoopback: false,
                    physicalInterfaceIndexes: null,
                    failSafeFallback: true,
                    reason: "BLOCK_ALL");
                globalOutboundBlocks = 4;
            }
            // AllowAll and disabled protection intentionally install no enforcing filters.

            var commitResult = FwpmTransactionCommit0(_engineHandle);
            if (commitResult != 0)
                throw new InvalidOperationException($"FwpmTransactionCommit0 failed: 0x{commitResult:X8}");
            transactionOpen = false;

            // The engine transaction is now authoritative. Adopt the committed IDs before
            // any post-commit verification so a caller can safely restore the previous policy
            // even if verification itself fails. HF1 kept the deleted pre-commit IDs here,
            // which made the UI rollback attempt fail with FILTER_NOT_FOUND after 0x80320033.
            AdoptCommittedFilters(newFilterIds);

            // HF2 lifecycle invariant: whenever a policy intentionally installs zero
            // enforcing filters (Protection OFF / AllowAll / backend clear), enumerate our
            // provider on all owned ALE layers and require the actual engine count to be zero.
            if (newFilterIds.Count == 0)
            {
                _runtimeFilterCleanupVerified = false;
                var residualIds = WfpOwnedFilterInventory.GetOwnedFilterIds(_engineHandle);
                _lastFilterCleanupUtc = DateTime.UtcNow;
                _residualRuntimeFilterCount = residualIds.Count;
                _runtimeFilterCleanupVerified = residualIds.Count == 0;
                if (residualIds.Count != 0)
                {
                    _activeFilterIds.Clear();
                    _activeFilterIds.AddRange(residualIds);
                    _lastError = $"WFP runtime-filter cleanup verification failed: residual={residualIds.Count}; ids={string.Join(',', residualIds.Take(16))}";
                    ServiceLog.Write(_lastError);
                    _buildingFilterDescriptors = null;
                    throw new InvalidOperationException(_lastError);
                }
            }
            else
            {
                // Filters are intentionally active, so the zero-filter cleanup invariant is not applicable.
                _residualRuntimeFilterCount = 0;
            }

            _backendActive = policy.BackendActive;
            _protectionEnabled = policy.ProtectionEnabled;
            _policyMode = policy.Mode;
            _policyRestoredOnStartup = restoredOnStartup;
            _allowedApplicationCount = rules.Count(rule => rule.Access == WfpRuleAccess.Allow);
            _blockedApplicationCount = rules.Count(rule => rule.Access == WfpRuleAccess.Block);
            _pendingApplicationCount = rules.Count(rule => rule.Access == WfpRuleAccess.Ask);
            _globalOutboundBlockFilterCount = globalOutboundBlocks;
            _globalInboundBlockFilterCount = globalInboundBlocks;
            _globalBlockFilterCount = globalOutboundBlocks + globalInboundBlocks;
            _ipv4FilterCount = ipv4;
            _ipv6FilterCount = ipv6;
            _tcpFilterCount = tcp;
            _udpFilterCount = udp;
            _outboundFilterCount = outbound;
            _inboundFilterCount = inbound;
            _tunAwareDirectionalRules = true;
            _physicalInboundInterfaceCount = interfaceScope.PhysicalInterfaceIndexes.Count;
            _virtualTunInterfaceCount = interfaceScope.VirtualInterfaceIndexes.Count;
            _interfaceScopeFallback = interfaceScope.UsedFallback;
            _physicalInterfaceSummary = interfaceScope.PhysicalSummary;
            _virtualTunInterfaceSummary = interfaceScope.VirtualSummary;
            _policyRevision++;
            _lastError = string.Empty;

            ServiceLog.Write(
                $"WFP policy revision {_policyRevision} committed: active={_backendActive}; protection={_protectionEnabled}; " +
                $"mode={_policyMode}; allowApps={_allowedApplicationCount}; blockApps={_blockedApplicationCount}; pendingApps={_pendingApplicationCount}; " +
                $"filters={_activeFilterIds.Count}; outbound={_outboundFilterCount}; inbound={_inboundFilterCount}; globalOut={_globalOutboundBlockFilterCount}; globalIn={_globalInboundBlockFilterCount}; " +
                $"physicalIf={_physicalInboundInterfaceCount}; virtualTunIf={_virtualTunInterfaceCount}; interfaceFallback={_interfaceScopeFallback}.");

            // A backend clear is stronger than Protection OFF: after proving that no
            // project filters remain, close the dynamic enforcement session so provider
            // and sublayer objects are detached as well. ApplyPolicy() re-opens it on demand.
            if (!policy.BackendActive && newFilterIds.Count == 0 && _engineHandle != IntPtr.Zero)
            {
                var detachResult = FwpmEngineClose0(_engineHandle);
                if (detachResult != 0)
                    throw new InvalidOperationException($"FwpmEngineClose0 after verified WFP clear failed: 0x{detachResult:X8}");

                _engineHandle = IntPtr.Zero;
                _providerRegistered = false;
                _subLayerRegistered = false;
                _activeFilterIds.Clear();
                _activeFilterDescriptors.Clear();
                ServiceLog.Write("WFP backend detached after verified zero-filter clear; dynamic provider/sublayer session closed.");
            }
        }
        catch (Exception ex)
        {
            if (transactionOpen)
            {
                try { _ = FwpmTransactionAbort0(_engineHandle); } catch { }
            }

            _buildingFilterDescriptors = null;
            _lastError = ex.Message;
            ServiceLog.WriteException(
                transactionOpen
                    ? "WFP policy transaction failed; previous filter set preserved"
                    : "WFP post-commit verification failed; backend state is not reported as safely disabled",
                ex);
            throw;
        }
    }

    private void AdoptCommittedFilters(IReadOnlyList<ulong> filterIds)
    {
        _activeFilterIds.Clear();
        _activeFilterIds.AddRange(filterIds);
        _activeFilterDescriptors.Clear();
        if (_buildingFilterDescriptors is not null)
        {
            foreach (var pair in _buildingFilterDescriptors)
                _activeFilterDescriptors[pair.Key] = pair.Value;
        }
        _buildingFilterDescriptors = null;
    }

    private enum TrafficDirection
    {
        Outbound,
        Inbound
    }

    private void AddApplicationProfileFilters(
        WfpApplicationRule rule,
        WfpPolicyMode mode,
        List<ulong> newFilterIds,
        ref int ipv4,
        ref int ipv6,
        ref int tcp,
        ref int udp,
        ref int outbound,
        ref int inbound)
    {
        IntPtr appId = IntPtr.Zero;
        var result = FwpmGetAppIdFromFileName0(rule.ExePath, out appId);
        if (result != 0 || appId == IntPtr.Zero)
            throw new InvalidOperationException($"FwpmGetAppIdFromFileName0 failed for '{rule.ExePath}': 0x{result:X8}");

        try
        {
            var profile = rule.Profile;

            // GeniaProxy readiness probe: a narrow, highest-range permit that is present
            // before any global default block can participate. It is installed only for
            // an explicitly allowed GeniaProxy profile that permits outbound traffic.
            if (rule.Access == WfpRuleAccess.Allow &&
                profile is WfpRuleProfile.EnableAll or WfpRuleProfile.OutgoingOnly &&
                IsGeniaProxyExecutable(rule.ExePath))
            {
                AddGeniaProxyReadinessProbeFilters(rule, appId, newFilterIds, ref ipv4, ref udp, ref outbound);
            }

            if (mode == WfpPolicyMode.BlockAll)
            {
                // Catch-all BLOCK is installed separately. Only application permits are required here.
                if (profile is WfpRuleProfile.EnableAll or WfpRuleProfile.OutgoingOnly)
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                if (profile is WfpRuleProfile.EnableAll or WfpRuleProfile.IncomingOnly)
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);

                // In BlockAll the global catch-all filters also match loopback. Preserve the
                // directional profile contract by explicitly permitting localhost in the
                // otherwise blocked direction for OutgoingOnly/IncomingOnly.
                if (profile == WfpRuleProfile.OutgoingOnly)
                {
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound, loopbackOnly: true);
                }
                if (profile == WfpRuleProfile.IncomingOnly)
                {
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound, loopbackOnly: true);
                }
                return;
            }

            if (mode == WfpPolicyMode.Normal)
            {
                // Normal mode has a low-weight global inbound block. Explicit application permits
                // override it; explicit outbound blocks quarantine/disable applications immediately.
                switch (profile)
                {
                    case WfpRuleProfile.EnableAll:
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                        break;
                    case WfpRuleProfile.OutgoingOnly:
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                        break;
                    case WfpRuleProfile.IncomingOnly:
                        // IncomingOnly still allows localhost IPC. Only non-loopback outbound is blocked.
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound, excludeLoopback: true);
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                        break;
                    case WfpRuleProfile.DisableAll:
                    case WfpRuleProfile.Ask:
                    default:
                        // Explicit full block / quarantine is intentionally stronger than the
                        // global external-inbound default and blocks localhost in both directions.
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                        AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                        break;
                }
                return;
            }

            // Monitor mode keeps explicit permanent profiles self-contained and installs no global default-deny filters.
            switch (profile)
            {
                case WfpRuleProfile.EnableAll:
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                    break;
                case WfpRuleProfile.OutgoingOnly:
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound, excludeLoopback: true);
                    break;
                case WfpRuleProfile.IncomingOnly:
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound, excludeLoopback: true);
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionPermit, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                    break;
                case WfpRuleProfile.DisableAll:
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Outbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                    AddApplicationDirectionFilters(rule, appId, TrafficDirection.Inbound, FwpActionBlock, newFilterIds, ref ipv4, ref ipv6, ref tcp, ref udp, ref outbound, ref inbound);
                    break;
            }
        }
        finally
        {
            if (appId != IntPtr.Zero)
                FwpmFreeMemory0(ref appId);
        }
    }

    private void AddApplicationDirectionFilters(
        WfpApplicationRule rule,
        IntPtr appId,
        TrafficDirection direction,
        uint action,
        List<ulong> newFilterIds,
        ref int ipv4,
        ref int ipv6,
        ref int tcp,
        ref int udp,
        ref int outbound,
        ref int inbound,
        bool excludeLoopback = false,
        bool loopbackOnly = false)
    {
        var layerV4 = direction == TrafficDirection.Outbound ? LayerAleAuthConnectV4 : LayerAleAuthRecvAcceptV4;
        var layerV6 = direction == TrafficDirection.Outbound ? LayerAleAuthConnectV6 : LayerAleAuthRecvAcceptV6;

        AddApplicationFilter(rule, appId, direction, action, layerV4, "IPv4", IpProtoTcp, "TCP", newFilterIds, excludeLoopback, loopbackOnly); ipv4++; tcp++;
        AddApplicationFilter(rule, appId, direction, action, layerV4, "IPv4", IpProtoUdp, "UDP", newFilterIds, excludeLoopback, loopbackOnly); ipv4++; udp++;
        AddApplicationFilter(rule, appId, direction, action, layerV6, "IPv6", IpProtoTcp, "TCP", newFilterIds, excludeLoopback, loopbackOnly); ipv6++; tcp++;
        AddApplicationFilter(rule, appId, direction, action, layerV6, "IPv6", IpProtoUdp, "UDP", newFilterIds, excludeLoopback, loopbackOnly); ipv6++; udp++;

        if (direction == TrafficDirection.Outbound)
            outbound += 4;
        else
            inbound += 4;
    }

    private void AddApplicationFilter(
        WfpApplicationRule rule,
        IntPtr appId,
        TrafficDirection direction,
        uint action,
        Guid layerKey,
        string ipVersion,
        byte protocol,
        string protocolName,
        List<ulong> newFilterIds,
        bool excludeLoopback,
        bool loopbackOnly)
    {
        if (excludeLoopback && loopbackOnly)
            throw new ArgumentException("A filter cannot be both loopback-only and loopback-excluding.");

        var conditions = new List<FwpmFilterCondition0>
        {
            new()
            {
                FieldKey = ConditionAleAppId,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromPointer(FwpByteBlobType, appId)
            },
            new()
            {
                FieldKey = ConditionIpProtocol,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromUInt8(protocol)
            }
        };

        if (excludeLoopback || loopbackOnly)
        {
            conditions.Add(new FwpmFilterCondition0
            {
                FieldKey = ConditionFlags,
                MatchType = loopbackOnly ? FwpMatchFlagsAnySet : FwpMatchFlagsNoneSet,
                ConditionValue = FwpConditionValue0.FromUInt32(FwpConditionFlagIsLoopback)
            });
        }


        var actionName = action == FwpActionPermit
            ? "ALLOW"
            : rule.Profile == WfpRuleProfile.Ask
                ? "ASK-BLOCK"
                : "BLOCK";
        var directionName = direction == TrafficDirection.Outbound ? "OUT" : "IN";
        var scopeName = loopbackOnly ? "LOOPBACK" : excludeLoopback ? "EXTERNAL" : "ALL";
        AddFilter(
            conditions.ToArray(),
            layerKey,
            action,
            ApplicationWeightRange,
            $"GeniaFirewall — {actionName} {directionName} {scopeName} — {SafeName(rule.DisplayName)} — {ipVersion}/{protocolName}",
            $"GeniaFirewall {ServiceProtocol.ProductVersion} {actionName} {directionName} {scopeName} for {rule.ExePath}",
            newFilterIds,
            reason: action == FwpActionPermit ? "APP_ALLOW" : rule.Profile == WfpRuleProfile.Ask ? "ASK_BLOCK" : "APP_BLOCK",
            appPath: rule.ExePath);
    }

    private static bool IsGeniaProxyExecutable(string exePath) =>
        string.Equals(Path.GetFileName(exePath), "GeniaProxy.exe", StringComparison.OrdinalIgnoreCase);

    private void AddGeniaProxyReadinessProbeFilters(
        WfpApplicationRule rule,
        IntPtr appId,
        List<ulong> newFilterIds,
        ref int ipv4,
        ref int udp,
        ref int outbound)
    {
        AddReadinessProbeFilter(rule, appId, "1.1.1.1", 53, newFilterIds);
        AddReadinessProbeFilter(rule, appId, "1.0.0.1", 53, newFilterIds);
        ipv4 += 2;
        udp += 2;
        outbound += 2;
    }

    private void AddReadinessProbeFilter(
        WfpApplicationRule rule,
        IntPtr appId,
        string remoteAddress,
        ushort remotePort,
        List<ulong> newFilterIds)
    {
        var address = IPAddress.Parse(remoteAddress).GetAddressBytes();
        var networkOrderAddress = ((uint)address[0] << 24) | ((uint)address[1] << 16) | ((uint)address[2] << 8) | address[3];
        var conditions = new[]
        {
            new FwpmFilterCondition0
            {
                FieldKey = ConditionAleAppId,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromPointer(FwpByteBlobType, appId)
            },
            new FwpmFilterCondition0
            {
                FieldKey = ConditionIpProtocol,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromUInt8(IpProtoUdp)
            },
            new FwpmFilterCondition0
            {
                FieldKey = ConditionIpRemoteAddress,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromUInt32(networkOrderAddress)
            },
            new FwpmFilterCondition0
            {
                FieldKey = ConditionIpRemotePort,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromUInt16(remotePort)
            }
        };

        AddFilter(
            conditions,
            LayerAleAuthConnectV4,
            FwpActionPermit,
            ReadinessProbeWeightRange,
            $"GeniaFirewall — PROBE-ALLOW OUT — GeniaProxy — UDP {remoteAddress}:{remotePort}",
            $"GeniaFirewall {ServiceProtocol.ProductVersion} readiness probe for {rule.ExePath}",
            newFilterIds,
            reason: "READINESS_PROBE_ALLOW",
            appPath: rule.ExePath);
    }

    private void AddGlobalOutboundBlockFilters(
        List<ulong> newFilterIds,
        ref int ipv4,
        ref int ipv6,
        ref int tcp,
        ref int udp,
        ref int outbound)
    {
        AddGlobalBlockFilter(TrafficDirection.Outbound, LayerAleAuthConnectV4, "IPv4", IpProtoTcp, "TCP", newFilterIds); ipv4++; tcp++;
        AddGlobalBlockFilter(TrafficDirection.Outbound, LayerAleAuthConnectV4, "IPv4", IpProtoUdp, "UDP", newFilterIds); ipv4++; udp++;
        AddGlobalBlockFilter(TrafficDirection.Outbound, LayerAleAuthConnectV6, "IPv6", IpProtoTcp, "TCP", newFilterIds); ipv6++; tcp++;
        AddGlobalBlockFilter(TrafficDirection.Outbound, LayerAleAuthConnectV6, "IPv6", IpProtoUdp, "UDP", newFilterIds); ipv6++; udp++;
        outbound += 4;
    }

    private int AddGlobalInboundBlockFilters(
        List<ulong> newFilterIds,
        ref int ipv4,
        ref int ipv6,
        ref int tcp,
        ref int udp,
        ref int inbound,
        bool excludeLoopback,
        IReadOnlyList<uint>? physicalInterfaceIndexes,
        bool failSafeFallback,
        string reason)
    {
        var added = 0;

        if (physicalInterfaceIndexes is { Count: > 0 })
        {
            foreach (var interfaceIndex in physicalInterfaceIndexes)
            {
                AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV4, "IPv4", IpProtoTcp, "TCP", newFilterIds, excludeLoopback, interfaceIndex, reason); ipv4++; tcp++; added++;
                AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV4, "IPv4", IpProtoUdp, "UDP", newFilterIds, excludeLoopback, interfaceIndex, reason); ipv4++; udp++; added++;
                AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV6, "IPv6", IpProtoTcp, "TCP", newFilterIds, excludeLoopback, interfaceIndex, reason); ipv6++; tcp++; added++;
                AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV6, "IPv6", IpProtoUdp, "UDP", newFilterIds, excludeLoopback, interfaceIndex, reason); ipv6++; udp++; added++;
            }

            inbound += added;
            return added;
        }

        if (!failSafeFallback)
            return 0;

        // Fail-safe compatibility path: if interface classification failed, retain the
        // 0.7.3 catch-all external-inbound block rather than silently opening inbound.
        AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV4, "IPv4", IpProtoTcp, "TCP", newFilterIds, excludeLoopback, reason: reason); ipv4++; tcp++;
        AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV4, "IPv4", IpProtoUdp, "UDP", newFilterIds, excludeLoopback, reason: reason); ipv4++; udp++;
        AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV6, "IPv6", IpProtoTcp, "TCP", newFilterIds, excludeLoopback, reason: reason); ipv6++; tcp++;
        AddGlobalBlockFilter(TrafficDirection.Inbound, LayerAleAuthRecvAcceptV6, "IPv6", IpProtoUdp, "UDP", newFilterIds, excludeLoopback, reason: reason); ipv6++; udp++;
        inbound += 4;
        return 4;
    }

    private void AddGlobalBlockFilter(
        TrafficDirection direction,
        Guid layerKey,
        string ipVersion,
        byte protocol,
        string protocolName,
        List<ulong> newFilterIds,
        bool excludeLoopback = false,
        uint? interfaceIndex = null,
        string reason = "BLOCK_ALL")
    {
        var conditions = new List<FwpmFilterCondition0>
        {
            new()
            {
                FieldKey = ConditionIpProtocol,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromUInt8(protocol)
            }
        };

        if (excludeLoopback)
        {
            conditions.Add(new FwpmFilterCondition0
            {
                FieldKey = ConditionFlags,
                MatchType = FwpMatchFlagsNoneSet,
                ConditionValue = FwpConditionValue0.FromUInt32(FwpConditionFlagIsLoopback)
            });
        }

        // Interface scoping belongs only on the low-weight global boundary filters.
        // Application permit/block filters intentionally remain interface-agnostic so
        // route changes through Wintun cannot invalidate an application decision.
        if (interfaceIndex is { } index)
        {
            conditions.Add(new FwpmFilterCondition0
            {
                FieldKey = direction == TrafficDirection.Outbound
                    ? ConditionNexthopInterfaceIndex
                    : ConditionArrivalInterfaceIndex,
                MatchType = FwpMatchEqual,
                ConditionValue = FwpConditionValue0.FromUInt32(index)
            });
        }

        var directionName = direction == TrafficDirection.Outbound ? "OUT" : "IN";
        var scopeName = interfaceIndex is { } indexValue
            ? $"PHYSICAL-IF#{indexValue}"
            : excludeLoopback ? "EXTERNAL" : "ALL";
        AddFilter(
            conditions.ToArray(),
            layerKey,
            FwpActionBlock,
            GlobalBlockWeightRange,
            $"GeniaFirewall — BLOCK ALL {directionName} {scopeName} — {ipVersion}/{protocolName}",
            $"GeniaFirewall {ServiceProtocol.ProductVersion} global {directionName} {scopeName} block filter",
            newFilterIds,
            reason: reason);
    }

    private void AddFilter(
        FwpmFilterCondition0[] conditions,
        Guid layerKey,
        uint action,
        byte weightRange,
        string name,
        string description,
        List<ulong> newFilterIds,
        string reason,
        string appPath = "")
    {
        var conditionSize = Marshal.SizeOf<FwpmFilterCondition0>();
        var conditionsPtr = Marshal.AllocHGlobal(conditionSize * conditions.Length);
        var providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        try
        {
            for (var i = 0; i < conditions.Length; i++)
                Marshal.StructureToPtr(conditions[i], IntPtr.Add(conditionsPtr, i * conditionSize), false);

            Marshal.StructureToPtr(ProviderKey, providerKeyPtr, false);

            var filter = new FwpmFilter0
            {
                FilterKey = Guid.Empty,
                DisplayData = new FwpmDisplayData0 { Name = name, Description = description },
                Flags = 0,
                ProviderKey = providerKeyPtr,
                ProviderData = default,
                LayerKey = layerKey,
                SubLayerKey = SubLayerKey,
                Weight = FwpValue0.FromUInt8(weightRange),
                NumFilterConditions = (uint)conditions.Length,
                FilterCondition = conditionsPtr,
                Action = new FwpmAction0 { Type = action, FilterType = Guid.Empty },
                Context = default,
                Reserved = IntPtr.Zero,
                FilterId = 0,
                EffectiveWeight = FwpValue0.Empty
            };

            var addResult = FwpmFilterAdd0(_engineHandle, ref filter, IntPtr.Zero, out var filterId);
            if (addResult != 0)
                throw new InvalidOperationException($"FwpmFilterAdd0 failed for '{name}': 0x{addResult:X8}");

            newFilterIds.Add(filterId);
            _buildingFilterDescriptors?[filterId] = new WfpFilterDescriptor(filterId, name, reason, appPath);
        }
        finally
        {
            Marshal.FreeHGlobal(providerKeyPtr);
            Marshal.FreeHGlobal(conditionsPtr);
        }
    }

    private static string SafeName(string value) => value.Length <= 100 ? value : value[..100];

    private void RegisterProvider()
    {
        var provider = new FwpmProvider0
        {
            ProviderKey = ProviderKey,
            DisplayData = new FwpmDisplayData0
            {
                Name = "GeniaFirewall",
                Description = "GeniaFirewall user-mode WFP policy provider"
            },
            Flags = 0,
            ProviderData = default,
            ServiceName = ServiceProtocol.ServiceName
        };

        var result = FwpmProviderAdd0(_engineHandle, ref provider, IntPtr.Zero);
        if (result != 0)
        {
            _lastError = $"FwpmProviderAdd0 failed: 0x{result:X8}";
            throw new InvalidOperationException(_lastError);
        }

        _providerRegistered = true;
    }

    private void RegisterSubLayer()
    {
        var providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        try
        {
            Marshal.StructureToPtr(ProviderKey, providerKeyPtr, false);
            var subLayer = new FwpmSubLayer0
            {
                SubLayerKey = SubLayerKey,
                DisplayData = new FwpmDisplayData0
                {
                    Name = "GeniaFirewall",
                    Description = "GeniaFirewall dynamic inbound/outbound filters"
                },
                Flags = 0,
                ProviderKey = providerKeyPtr,
                ProviderData = default,
                Weight = 0x6000
            };

            var result = FwpmSubLayerAdd0(_engineHandle, ref subLayer, IntPtr.Zero);
            if (result != 0)
            {
                _lastError = $"FwpmSubLayerAdd0 failed: 0x{result:X8}";
                throw new InvalidOperationException(_lastError);
            }

            _subLayerRegistered = true;
        }
        finally
        {
            Marshal.FreeHGlobal(providerKeyPtr);
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
                return;

            _disposed = true;
            CloseEngineUnsafe();
        }
    }

    private void CloseEngineUnsafe()
    {
        if (_engineHandle != IntPtr.Zero)
        {
            try { _ = FwpmEngineClose0(_engineHandle); } catch { }
        }

        _engineHandle = IntPtr.Zero;
        _providerRegistered = false;
        _subLayerRegistered = false;
        _activeFilterIds.Clear();
        _activeFilterDescriptors.Clear();
        _buildingFilterDescriptors = null;
        _backendActive = false;
        _protectionEnabled = false;
        _policyMode = WfpPolicyMode.Normal;
        _policyRestoredOnStartup = false;
        _allowedApplicationCount = 0;
        _blockedApplicationCount = 0;
        _pendingApplicationCount = 0;
        _globalBlockFilterCount = 0;
        _ipv4FilterCount = 0;
        _ipv6FilterCount = 0;
        _tcpFilterCount = 0;
        _udpFilterCount = 0;
        _outboundFilterCount = 0;
        _inboundFilterCount = 0;
        _globalOutboundBlockFilterCount = 0;
        _globalInboundBlockFilterCount = 0;
    }

    private void EnsureEngineOpen()
    {
        if (_engineHandle == IntPtr.Zero || !_providerRegistered || !_subLayerRegistered)
            throw new InvalidOperationException("WFP engine/provider/sublayer is not ready.");
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmDisplayData0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob { public uint Size; public IntPtr Data; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmSession0
    {
        public Guid SessionKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public uint TxnWaitTimeoutInMSec;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public int KernelMode;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmProvider0
    {
        public Guid ProviderKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public FwpByteBlob ProviderData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmSubLayer0
    {
        public Guid SubLayerKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public ushort Weight;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpValue0
    {
        [FieldOffset(0)] public uint Type;
        [FieldOffset(8)] public IntPtr Pointer;
        [FieldOffset(8)] public byte UInt8;
        public static FwpValue0 Empty => new() { Type = FwpEmpty, Pointer = IntPtr.Zero };
        public static FwpValue0 FromUInt8(byte value) => new() { Type = FwpUint8, UInt8 = value };
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpConditionValue0
    {
        [FieldOffset(0)] public uint Type;
        [FieldOffset(8)] public IntPtr Pointer;
        [FieldOffset(8)] public byte UInt8;
        [FieldOffset(8)] public uint UInt32;
        public static FwpConditionValue0 FromPointer(uint type, IntPtr pointer) => new() { Type = type, Pointer = pointer };
        [FieldOffset(8)] public ushort UInt16;
        public static FwpConditionValue0 FromUInt8(byte value) => new() { Type = FwpUint8, UInt8 = value };
        public static FwpConditionValue0 FromUInt16(ushort value) => new() { Type = FwpUint16, UInt16 = value };
        public static FwpConditionValue0 FromUInt32(uint value) => new() { Type = FwpUint32, UInt32 = value };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterCondition0
    {
        public Guid FieldKey;
        public uint MatchType;
        public FwpConditionValue0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0 { public uint Type; public Guid FilterType; }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpmFilterContextUnion
    {
        [FieldOffset(0)] public ulong RawContext;
        [FieldOffset(0)] public Guid ProviderContextKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmFilter0
    {
        public Guid FilterKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public FwpValue0 Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public FwpmAction0 Action;
        public FwpmFilterContextUnion Context;
        public IntPtr Reserved;
        public ulong FilterId;
        public FwpValue0 EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, ref FwpmSession0 session, out IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmEngineClose0(IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FwpmProvider0 provider, IntPtr securityDescriptor);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FwpmSubLayer0 subLayer, IntPtr securityDescriptor);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionCommit0(IntPtr engineHandle);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmTransactionAbort0(IntPtr engineHandle);
    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
    [DllImport("fwpuclnt.dll")] private static extern void FwpmFreeMemory0(ref IntPtr pointer);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FwpmFilter0 filter, IntPtr securityDescriptor, out ulong id);
    [DllImport("fwpuclnt.dll")] private static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);
}
