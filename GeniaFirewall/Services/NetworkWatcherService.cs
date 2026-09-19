using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public sealed class NetworkWatcherService : IDisposable
{
    private const int AfInet = 2;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint MibTcpStateListen = 2;

    private readonly Func<string, bool> _isHandledApplication;
    private readonly Dictionary<string, DateTime> _nextAllowedNotification = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _nextActivityReport = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();
    private Task? _worker;
    private bool _disposed;
    private DateTime _lastCooldownCleanupUtc = DateTime.UtcNow;

    public event EventHandler<NetworkConnectionInfo>? NetworkActivityDetected;
    public event EventHandler<NetworkConnectionInfo>? UnknownApplicationDetected;
    public event Action<Exception>? Error;

    public NetworkWatcherService(Func<string, bool> isHandledApplication)
    {
        _isHandledApplication = isHandledApplication ?? throw new ArgumentNullException(nameof(isHandledApplication));
    }

    public void Start()
    {
        if (_worker is not null)
            return;

        _worker = Task.Run(() => WatchLoopAsync(_cts.Token));
    }

    public void Snooze(string exePath, TimeSpan duration)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return;

        lock (_nextAllowedNotification)
            _nextAllowedNotification[exePath] = DateTime.UtcNow.Add(duration);
    }

    private async Task WatchLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(500));

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken))
            {
                CleanupExpiredCooldownsIfNeeded();

                var activity = GetNetworkActivity().ToList();
                foreach (var group in activity.GroupBy(connection => connection.ExePath, StringComparer.OrdinalIgnoreCase))
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;

                    var exePath = group.Key;
                    var handled = _isHandledApplication(exePath);
                    if (handled)
                    {
                        foreach (var connection in group)
                        {
                            if (!CanReportActivity(connection))
                                continue;

                            ReserveActivityReport(connection);
                            NetworkActivityDetected?.Invoke(this, connection);
                        }

                        continue;
                    }

                    // A passive listener is useful telemetry for an already managed program, but
                    // listening by itself is not an outbound-access request and must not create a new
                    // firewall prompt. Unknown apps are prompted only for active network traffic.
                    var promptable = group.Where(connection => !connection.IsListener).Take(20).ToList();
                    if (promptable.Count == 0 || !CanNotify(exePath))
                        continue;

                    // One cooldown per executable, but deliver the entire current burst first so the
                    // UI can combine destinations into one decision instead of losing endpoint detail.
                    Snooze(exePath, TimeSpan.FromSeconds(45));
                    foreach (var connection in promptable)
                        UnknownApplicationDetected?.Invoke(this, connection);
                }
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

    private void CleanupExpiredCooldownsIfNeeded()
    {
        var now = DateTime.UtcNow;
        if (now - _lastCooldownCleanupUtc < TimeSpan.FromMinutes(2))
            return;

        lock (_nextAllowedNotification)
        {
            var expired = _nextAllowedNotification
                .Where(pair => pair.Value <= now)
                .Select(pair => pair.Key)
                .ToList();

            foreach (var path in expired)
                _nextAllowedNotification.Remove(path);
        }

        lock (_nextActivityReport)
        {
            var expired = _nextActivityReport
                .Where(pair => pair.Value <= now)
                .Select(pair => pair.Key)
                .ToList();

            foreach (var key in expired)
                _nextActivityReport.Remove(key);
        }

        _lastCooldownCleanupUtc = now;
    }

    private bool CanNotify(string exePath)
    {
        lock (_nextAllowedNotification)
        {
            return !_nextAllowedNotification.TryGetValue(exePath, out var next) || next <= DateTime.UtcNow;
        }
    }

    private bool CanReportActivity(NetworkConnectionInfo connection)
    {
        var key = $"{connection.ExePath}|{connection.Protocol}|{(connection.IsListener ? "LISTEN" : "FLOW")}";
        lock (_nextActivityReport)
            return !_nextActivityReport.TryGetValue(key, out var next) || next <= DateTime.UtcNow;
    }

    private void ReserveActivityReport(NetworkConnectionInfo connection)
    {
        var key = $"{connection.ExePath}|{connection.Protocol}|{(connection.IsListener ? "LISTEN" : "FLOW")}";
        lock (_nextActivityReport)
            _nextActivityReport[key] = DateTime.UtcNow.AddSeconds(4);
    }

    private IEnumerable<NetworkConnectionInfo> GetNetworkActivity()
    {
        var currentPid = Environment.ProcessId;
        var emittedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var emittedPerPath = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var snapshots = new Dictionary<int, ProcessSnapshotInfo>();

        foreach (var row in ReadTcp4Table())
        {
            var pid = unchecked((int)row.OwningPid);
            if (pid <= 4 || pid == currentPid)
                continue;

            var path = TryGetProcessPath(pid);
            if (!IsUsableExecutable(path))
                continue;

            var localAddress = new IPAddress(row.LocalAddr).ToString();
            var localPort = ConvertPort(row.LocalPort);

            if (row.State == MibTcpStateListen && row.RemotePort == 0 && row.RemoteAddr == 0)
            {
                var listenerKey = $"{path}|TCP|LISTEN|{localAddress}|{localPort}";
                if (!emittedKeys.Add(listenerKey))
                    continue;

                if (!snapshots.TryGetValue(pid, out var listenerSnapshot))
                {
                    listenerSnapshot = ProcessSnapshotService.Capture(pid);
                    snapshots[pid] = listenerSnapshot;
                }

                yield return new NetworkConnectionInfo(
                    pid,
                    path!,
                    "TCP",
                    string.Empty,
                    0,
                    localPort,
                    DateTime.Now)
                {
                    ProcessSnapshot = listenerSnapshot,
                    LocalAddress = localAddress,
                    Direction = "Inbound",
                    TelemetrySource = "SocketTable",
                    IsListener = true
                };
                continue;
            }

            if (row.RemotePort == 0 || row.RemoteAddr == 0)
                continue;

            var remoteAddress = new IPAddress(row.RemoteAddr).ToString();
            if (IPAddress.TryParse(remoteAddress, out var ip) && IPAddress.IsLoopback(ip))
                continue;

            var remotePort = ConvertPort(row.RemotePort);
            var endpointKey = $"{path}|TCP|{remoteAddress}|{remotePort}";
            if (!emittedKeys.Add(endpointKey))
                continue;

            emittedPerPath.TryGetValue(path!, out var emittedCount);
            if (emittedCount >= 20)
                continue;
            emittedPerPath[path!] = emittedCount + 1;

            if (!snapshots.TryGetValue(pid, out var snapshot))
            {
                snapshot = ProcessSnapshotService.Capture(pid);
                snapshots[pid] = snapshot;
            }

            yield return new NetworkConnectionInfo(
                pid,
                path!,
                "TCP",
                remoteAddress,
                remotePort,
                localPort,
                DateTime.Now)
            {
                ProcessSnapshot = snapshot,
                LocalAddress = localAddress,
                Direction = "Outbound",
                NetworkScope = "Internet",
                TelemetrySource = "SocketTable"
            };
        }

        // Windows' UDP owner table exposes the owning PID and local endpoint but no remote endpoint.
        // That is still enough to distinguish UDP activity and to show the local port in the UI.
        foreach (var row in ReadUdp4Table())
        {
            var pid = unchecked((int)row.OwningPid);
            if (pid <= 4 || pid == currentPid)
                continue;

            var path = TryGetProcessPath(pid);
            if (!IsUsableExecutable(path))
                continue;

            var localPort = ConvertPort(row.LocalPort);
            if (!emittedKeys.Add($"{path}|UDP|{localPort}"))
                continue;

            emittedPerPath.TryGetValue(path!, out var emittedCount);
            if (emittedCount >= 20)
                continue;
            emittedPerPath[path!] = emittedCount + 1;

            if (!snapshots.TryGetValue(pid, out var snapshot))
            {
                snapshot = ProcessSnapshotService.Capture(pid);
                snapshots[pid] = snapshot;
            }

            yield return new NetworkConnectionInfo(
                pid,
                path!,
                "UDP",
                string.Empty,
                0,
                localPort,
                DateTime.Now)
            {
                ProcessSnapshot = snapshot
            };
        }
    }

    private static bool IsUsableExecutable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        try
        {
            return File.Exists(path) && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string? TryGetProcessPath(int processId)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
            return null;

        try
        {
            var capacity = 32768;
            var builder = new StringBuilder(capacity);
            if (!QueryFullProcessImageName(handle, 0, builder, ref capacity))
                return null;

            return builder.ToString();
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static IReadOnlyList<TcpRow> ReadTcp4Table()
    {
        var size = 0;
        var result = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableClass.OwnerPidAll, 0);
        if (result != ErrorInsufficientBuffer || size <= 0)
            return [];

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableClass.OwnerPidAll, 0);
            if (result != 0)
                return [];

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var cursor = IntPtr.Add(buffer, sizeof(int));
            var rows = new List<TcpRow>(Math.Max(0, count));

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(cursor);
                rows.Add(new TcpRow(row.State, row.LocalAddr, row.LocalPort, row.RemoteAddr, row.RemotePort, row.OwningPid));
                cursor = IntPtr.Add(cursor, rowSize);
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IReadOnlyList<UdpRow> ReadUdp4Table()
    {
        var size = 0;
        var result = GetExtendedUdpTable(IntPtr.Zero, ref size, true, AfInet, UdpTableClass.OwnerPid, 0);
        if (result != ErrorInsufficientBuffer || size <= 0)
            return [];

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            result = GetExtendedUdpTable(buffer, ref size, true, AfInet, UdpTableClass.OwnerPid, 0);
            if (result != 0)
                return [];

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
            var cursor = IntPtr.Add(buffer, sizeof(int));
            var rows = new List<UdpRow>(Math.Max(0, count));

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(cursor);
                rows.Add(new UdpRow(row.LocalPort, row.OwningPid));
                cursor = IntPtr.Add(cursor, rowSize);
            }

            return rows;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int ConvertPort(uint networkOrderPort)
    {
        var raw = unchecked((short)(networkOrderPort & 0xFFFF));
        return unchecked((ushort)IPAddress.NetworkToHostOrder(raw));
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _cts.Cancel();

        try
        {
            _worker?.Wait(TimeSpan.FromSeconds(1));
        }
        catch
        {
        }

        _cts.Dispose();
    }

    private readonly record struct TcpRow(uint State, uint LocalAddr, uint LocalPort, uint RemoteAddr, uint RemotePort, uint OwningPid);
    private readonly record struct UdpRow(uint LocalPort, uint OwningPid);

    private enum TcpTableClass
    {
        BasicListener,
        BasicConnections,
        BasicAll,
        OwnerPidListener,
        OwnerPidConnections,
        OwnerPidAll
    }

    private enum UdpTableClass
    {
        Basic,
        OwnerPid,
        OwnerModule
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int outBufferLength,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        TcpTableClass tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr udpTable,
        ref int outBufferLength,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        UdpTableClass tableClass,
        uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr processHandle, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
