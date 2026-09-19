using System.IO;
using GeniaFirewall.Models;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Services;

/// <summary>
/// Polls the privileged service's WFP net-event ring buffer. This complements the legacy
/// socket-table watcher: it can see very short-lived and loopback flows that disappear
/// between table snapshots. The socket watcher remains as a fallback if telemetry is unavailable.
/// </summary>
public sealed class WfpTelemetryWatcherService : IDisposable
{
    private readonly GeniaFirewallServiceClient _client;
    private readonly Func<string, bool> _isHandledApplication;
    private readonly CancellationTokenSource _cts = new();
    private readonly Dictionary<string, DateTime> _nextUnknownNotification = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _nextActivityReport = new(StringComparer.OrdinalIgnoreCase);
    private Task? _worker;
    private long _lastSequence;
    private DateTime _serviceStartupUtc;
    private bool _disposed;

    public event EventHandler<NetworkConnectionInfo>? NetworkActivityDetected;
    public event EventHandler<NetworkConnectionInfo>? UnknownApplicationDetected;
    public event Action<Exception>? Error;

    public WfpTelemetryWatcherService(GeniaFirewallServiceClient client, Func<string, bool> isHandledApplication)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _isHandledApplication = isHandledApplication ?? throw new ArgumentNullException(nameof(isHandledApplication));
    }

    public void Start()
    {
        if (_worker is not null)
            return;

        // Start at the current head so launching the UI does not replay stale traffic from the
        // service's ring buffer. Events that happen after this point are delivered in order.
        try
        {
            var probe = _client.Probe(700);
            if (probe.Status is { } status)
            {
                _lastSequence = Math.Max(0, status.NetEventTelemetryLastSequence);
                _serviceStartupUtc = status.StartupUtc;
            }
        }
        catch
        {
        }

        _worker = Task.Run(() => WatchLoopAsync(_cts.Token));
    }

    private async Task WatchLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(300));

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                var result = _client.ReadNetEvents(_lastSequence, 128, 1000);
                if (!result.Success)
                    continue;

                if (result.Status is { } currentStatus &&
                    currentStatus.StartupUtc != default &&
                    _serviceStartupUtc != default &&
                    currentStatus.StartupUtc != _serviceStartupUtc)
                {
                    // A service restart creates a fresh telemetry ring whose sequence starts at zero.
                    // Reset our cursor so the first short-lived flows after the restart are not skipped.
                    _serviceStartupUtc = currentStatus.StartupUtc;
                    _lastSequence = 0;
                    result = _client.ReadNetEvents(0, 128, 1000);
                    if (!result.Success)
                        continue;
                }
                else if (result.Status is { } firstStatus && _serviceStartupUtc == default)
                {
                    _serviceStartupUtc = firstStatus.StartupUtc;
                }

                foreach (var netEvent in result.Events.OrderBy(item => item.Sequence))
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;

                    _lastSequence = Math.Max(_lastSequence, netEvent.Sequence);
                    var connection = ConvertEvent(netEvent);
                    if (connection is null)
                        continue;

                    if (_isHandledApplication(connection.ExePath))
                    {
                        if (CanReportActivity(connection))
                        {
                            ReserveActivity(connection);
                            NetworkActivityDetected?.Invoke(this, connection);
                        }
                    }
                    else if (!connection.Direction.Equals("Inbound", StringComparison.OrdinalIgnoreCase) &&
                             CanNotifyUnknown(connection.ExePath))
                    {
                        // 0.7.1 keeps unknown-app prompts outbound-oriented. Inbound WFP events still
                        // enrich already managed applications, but unsolicited inbound probes do not
                        // suddenly create new decision dialogs.
                        ReserveUnknown(connection.ExePath);
                        UnknownApplicationDetected?.Invoke(this, connection);
                    }
                }

                if (result.Status is { } status &&
                    result.Events.Count == 0 &&
                    status.NetEventTelemetryLastSequence < _lastSequence)
                {
                    // Defensive fallback for a sequence reset even if StartupUtc could not be compared.
                    _lastSequence = Math.Max(0, status.NetEventTelemetryLastSequence);
                }

                CleanupCooldowns();
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            Error?.Invoke(ex);
        }
    }

    private static NetworkConnectionInfo? ConvertEvent(WfpNetEventSnapshot netEvent)
    {
        if (string.IsNullOrWhiteSpace(netEvent.ExePath) ||
            !netEvent.ExePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            if (!File.Exists(netEvent.ExePath))
                return null;
        }
        catch
        {
            return null;
        }

        var processId = ProcessSnapshotService.TryFindProcessIdByPath(netEvent.ExePath);
        var snapshot = processId > 0
            ? ProcessSnapshotService.Capture(processId)
            : new ProcessSnapshotInfo();

        return new NetworkConnectionInfo(
            processId,
            netEvent.ExePath,
            netEvent.Protocol,
            netEvent.RemoteAddress,
            netEvent.RemotePort,
            netEvent.LocalPort,
            netEvent.SeenUtc.ToLocalTime())
        {
            ProcessSnapshot = snapshot,
            LocalAddress = netEvent.LocalAddress,
            Direction = netEvent.Direction.ToString(),
            NetworkScope = netEvent.Scope.ToString(),
            TelemetryAction = netEvent.Action.ToString(),
            TelemetrySource = "WFP",
            IsLoopback = netEvent.IsLoopback
        };
    }

    private bool CanNotifyUnknown(string exePath)
    {
        lock (_nextUnknownNotification)
            return !_nextUnknownNotification.TryGetValue(exePath, out var next) || next <= DateTime.UtcNow;
    }

    private void ReserveUnknown(string exePath)
    {
        lock (_nextUnknownNotification)
            _nextUnknownNotification[exePath] = DateTime.UtcNow.AddSeconds(30);
    }

    private bool CanReportActivity(NetworkConnectionInfo connection)
    {
        var key = $"{connection.ExePath}|{connection.Protocol}|{connection.NetworkScope}";
        lock (_nextActivityReport)
            return !_nextActivityReport.TryGetValue(key, out var next) || next <= DateTime.UtcNow;
    }

    private void ReserveActivity(NetworkConnectionInfo connection)
    {
        var key = $"{connection.ExePath}|{connection.Protocol}|{connection.NetworkScope}";
        lock (_nextActivityReport)
            _nextActivityReport[key] = DateTime.UtcNow.AddSeconds(2);
    }

    private void CleanupCooldowns()
    {
        var now = DateTime.UtcNow;
        lock (_nextUnknownNotification)
        {
            foreach (var key in _nextUnknownNotification.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToList())
                _nextUnknownNotification.Remove(key);
        }

        lock (_nextActivityReport)
        {
            foreach (var key in _nextActivityReport.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToList())
                _nextActivityReport.Remove(key);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _cts.Cancel();
        try { _worker?.Wait(TimeSpan.FromSeconds(1)); } catch { }
        _cts.Dispose();
    }
}
