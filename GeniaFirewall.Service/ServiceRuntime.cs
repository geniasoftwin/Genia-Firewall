using System.Net.NetworkInformation;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

internal sealed class ServiceRuntime : IAsyncDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private readonly WfpSessionManager _wfp = new();
    private readonly WfpNetEventMonitor _netEvents;
    private readonly ServicePolicyStore _policyStore = new();
    private readonly DateTime _startupUtc = DateTime.UtcNow;
    private NamedPipeControlServer? _pipeServer;
    private Task? _pipeTask;
    private readonly object _policySync = new();
    private readonly object _interfaceRefreshSync = new();
    private Timer? _interfaceRefreshTimer;
    private string _startupError = string.Empty;
    private bool _stopped;
    private WfpPolicySnapshot _currentPolicy = ServicePolicyStore.DisabledPolicy();

    public ServiceRuntime()
    {
        _netEvents = new WfpNetEventMonitor(_wfp.ResolveFilter);
    }

    public Task StartAsync()
    {
        ServiceLog.Write($"Starting {ServiceProtocol.DisplayName} {ServiceProtocol.ProductVersion}.");

        try
        {
            _wfp.Start();
            ServiceLog.Write("Dynamic WFP session opened; provider and sublayer registered.");

            // Read-only telemetry uses a separate WFP engine handle so short-lived and loopback
            // activity can be observed without changing the enforcement session.
            _netEvents.Start();

            try
            {
                var hadStoredPolicy = _policyStore.Exists;
                _currentPolicy = _policyStore.Load();
                _wfp.ApplyPolicy(_currentPolicy, restoredOnStartup: hadStoredPolicy);
                ServiceLog.Write(hadStoredPolicy
                    ? $"Persisted WFP policy restored from {_policyStore.PolicyPath}."
                    : "No persisted WFP policy found; backend starts inactive.");
            }
            catch (Exception ex)
            {
                _currentPolicy = ServicePolicyStore.DisabledPolicy();
                _startupError = $"Stored policy restore failed: {ex.Message}";
                ServiceLog.WriteException("Stored WFP policy restore failed; service starts with no GeniaFirewall filters", ex);
                try { _wfp.ApplyPolicy(_currentPolicy); } catch { }
            }
        }
        catch (Exception ex)
        {
            _startupError = ex.Message;
            ServiceLog.WriteException("WFP startup failed; service remains available for diagnostics", ex);
        }

        NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;

        _pipeServer = new NamedPipeControlServer(
            CreateSnapshot,
            ApplyPolicy,
            RemoveApplication,
            ClearPolicy,
            ReadNetEvents);

        _pipeTask = Task.Run(() => _pipeServer.RunAsync(_cts.Token));
        return Task.CompletedTask;
    }

    private void ApplyPolicy(WfpPolicySnapshot policy)
    {
        lock (_policySync)
        {
            var previous = _currentPolicy;
            _wfp.ApplyPolicy(policy);

            try
            {
                _policyStore.Save(policy);
                _currentPolicy = policy;
                _startupError = string.Empty;
            }
            catch
            {
                try { _wfp.ApplyPolicy(previous); } catch { }
                throw;
            }
        }
    }

    private void OnNetworkAddressChanged(object? sender, EventArgs e)
    {
        if (_stopped)
            return;

        lock (_interfaceRefreshSync)
        {
            _interfaceRefreshTimer ??= new Timer(
                _ => RefreshInterfaceScopedPolicy(),
                null,
                Timeout.InfiniteTimeSpan,
                Timeout.InfiniteTimeSpan);

            _interfaceRefreshTimer.Change(TimeSpan.FromMilliseconds(200), Timeout.InfiniteTimeSpan);
        }
    }

    private void RefreshInterfaceScopedPolicy()
    {
        if (_stopped)
            return;

        try
        {
            lock (_policySync)
            {
                if (!_currentPolicy.BackendActive || !_currentPolicy.ProtectionEnabled)
                    return;

                _wfp.ApplyPolicy(_currentPolicy);
            }
            ServiceLog.Write("Network-interface change detected; WFP interface-scoped boundary filters refreshed.");
        }
        catch (Exception ex)
        {
            ServiceLog.WriteException("WFP interface-scope refresh failed; previous transaction remains active", ex);
        }
    }

    private void RemoveApplication(Guid applicationId)
    {
        if (applicationId == Guid.Empty)
            return;

        var updated = _currentPolicy with
        {
            Applications = _currentPolicy.Applications
                .Where(rule => rule.ApplicationId != applicationId)
                .ToList()
        };
        ApplyPolicy(updated);
    }

    private void ClearPolicy() => ApplyPolicy(ServicePolicyStore.DisabledPolicy());

    public async Task StopAsync()
    {
        if (_stopped)
            return;

        _stopped = true;
        ServiceLog.Write("Stopping GeniaFirewall Service.");
        _cts.Cancel();

        if (_pipeTask is not null)
        {
            try { await _pipeTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }
        }

        NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        lock (_interfaceRefreshSync)
        {
            _interfaceRefreshTimer?.Dispose();
            _interfaceRefreshTimer = null;
        }

        _netEvents.Dispose();
        _wfp.Dispose();
        ServiceLog.Write("Stopped. Dynamic WFP filters/provider/sublayer released with the session; policy remains persisted for next service start.");
    }

    private IReadOnlyList<WfpNetEventSnapshot> ReadNetEvents(long afterSequence, int maxEvents) =>
        _netEvents.ReadAfter(afterSequence, maxEvents);

    private ServiceStatusSnapshot CreateSnapshot()
    {
        var snapshot = _wfp.CreateSnapshot(_startupUtc, _startupError);
        return snapshot with
        {
            NetEventTelemetryAvailable = _netEvents.Available,
            NetEventTelemetryLastSequence = _netEvents.LastSequence,
            NetEventTelemetryReceivedCount = _netEvents.ReceivedCount,
            NetEventTelemetryDroppedCount = _netEvents.DroppedCount,
            NetEventTelemetryLastError = _netEvents.LastError,
            BlockedEventCount = _netEvents.BlockedEventCount,
            LastBlockedEventSummary = _netEvents.LastBlockedEventSummary
        };
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _cts.Dispose();
    }
}
