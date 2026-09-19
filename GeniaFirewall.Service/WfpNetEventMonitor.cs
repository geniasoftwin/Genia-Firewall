using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

/// <summary>
/// Read-only WFP net-event telemetry. Enforcement remains owned by WfpSessionManager.
/// This monitor exists so very short-lived and loopback connections are not lost between
/// user-mode socket-table polling intervals. It uses a separate non-dynamic engine handle
/// and gracefully degrades when subscriptions are unavailable.
/// </summary>
internal sealed class WfpNetEventMonitor : IDisposable
{
    private const uint RpcCAuthnWinnt = 10;
    private const int MaxBufferedEvents = 4096;
    private const int MaxPathCharacters = 32768;

    private const uint EventTypeClassifyDrop = 3;
    private const uint EventTypeClassifyAllow = 6;

    private const uint FlagIpProtocolSet = 0x00000001;
    private const uint FlagLocalAddrSet = 0x00000002;
    private const uint FlagRemoteAddrSet = 0x00000004;
    private const uint FlagLocalPortSet = 0x00000008;
    private const uint FlagRemotePortSet = 0x00000010;
    private const uint FlagAppIdSet = 0x00000020;
    private const uint FlagIpVersionSet = 0x00000100;

    private const uint DirectionInbound = 0x00003900;
    private const uint DirectionOutbound = 0x00003901;

    private const int IpVersionV4 = 0;
    private const int IpVersionV6 = 1;

    private readonly object _sync = new();
    private readonly Func<ulong, WfpFilterDescriptor?> _filterResolver;
    private readonly LinkedList<WfpNetEventSnapshot> _events = new();
    private readonly Dictionary<string, DateTime> _dedupe = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _devicePrefixes = new(StringComparer.OrdinalIgnoreCase);
    private FwpmNetEventCallback1? _callback;
    private IntPtr _engineHandle;
    private IntPtr _subscriptionHandle;
    private long _sequence;
    private long _received;
    private long _dropped;
    private long _blockedEventCount;
    private string _lastBlockedEventSummary = string.Empty;
    private DateTime _lastDedupeCleanupUtc = DateTime.UtcNow;
    private bool _available;
    private bool _disposed;
    private string _lastError = string.Empty;

    public WfpNetEventMonitor(Func<ulong, WfpFilterDescriptor?> filterResolver)
    {
        _filterResolver = filterResolver ?? throw new ArgumentNullException(nameof(filterResolver));
    }

    public bool Available
    {
        get { lock (_sync) return _available; }
    }

    public long LastSequence
    {
        get { lock (_sync) return _sequence; }
    }

    public long ReceivedCount
    {
        get { lock (_sync) return _received; }
    }

    public long DroppedCount
    {
        get { lock (_sync) return _dropped; }
    }

    public long BlockedEventCount
    {
        get { lock (_sync) return _blockedEventCount; }
    }

    public string LastBlockedEventSummary
    {
        get { lock (_sync) return _lastBlockedEventSummary; }
    }

    public string LastError
    {
        get { lock (_sync) return _lastError; }
    }

    public void Start()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            if (_engineHandle != IntPtr.Zero)
                return;

            BuildDevicePrefixMap();

            var result = FwpmEngineOpen0(null, RpcCAuthnWinnt, IntPtr.Zero, IntPtr.Zero, out _engineHandle);
            if (result != 0 || _engineHandle == IntPtr.Zero)
            {
                _engineHandle = IntPtr.Zero;
                _lastError = $"FwpmEngineOpen0(telemetry) failed: 0x{result:X8}";
                ServiceLog.Write(_lastError);
                return;
            }

            try
            {
                _callback = OnNetEvent;
                var subscription = new FwpmNetEventSubscription0
                {
                    EnumTemplate = IntPtr.Zero,
                    Flags = 0,
                    SessionKey = Guid.Empty
                };

                result = FwpmNetEventSubscribe1(
                    _engineHandle,
                    ref subscription,
                    _callback,
                    IntPtr.Zero,
                    out _subscriptionHandle);

                if (result != 0 || _subscriptionHandle == IntPtr.Zero)
                {
                    _lastError = $"FwpmNetEventSubscribe1 failed: 0x{result:X8}";
                    ServiceLog.Write(_lastError);
                    CloseUnsafe();
                    return;
                }

                _available = true;
                _lastError = string.Empty;
                ServiceLog.Write("WFP net-event telemetry subscription active (FwpmNetEventSubscribe1).");
            }
            catch (EntryPointNotFoundException ex)
            {
                _lastError = $"WFP net-event subscription API unavailable: {ex.Message}";
                ServiceLog.Write(_lastError);
                CloseUnsafe();
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                ServiceLog.WriteException("WFP net-event telemetry startup failed", ex);
                CloseUnsafe();
            }
        }
    }

    public IReadOnlyList<WfpNetEventSnapshot> ReadAfter(long afterSequence, int maxEvents)
    {
        lock (_sync)
        {
            maxEvents = Math.Clamp(maxEvents, 1, ServiceProtocol.MaxTelemetryEventsPerResponse);
            return _events
                .Where(item => item.Sequence > afterSequence)
                .Take(maxEvents)
                .ToList();
        }
    }

    private void OnNetEvent(IntPtr context, IntPtr eventPointer)
    {
        if (eventPointer == IntPtr.Zero)
            return;

        try
        {
            var netEvent = Marshal.PtrToStructure<FwpmNetEvent2>(eventPointer);
            if (netEvent.Type is not (EventTypeClassifyAllow or EventTypeClassifyDrop))
                return;

            var header = netEvent.Header;
            if ((header.Flags & FlagAppIdSet) == 0 || header.AppId.Data == IntPtr.Zero || header.AppId.Size < 2)
                return;

            var exePath = DecodeAppId(header.AppId);
            if (string.IsNullOrWhiteSpace(exePath) || !exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return;

            var protocol = (header.Flags & FlagIpProtocolSet) != 0
                ? header.IpProtocol switch
                {
                    6 => "TCP",
                    17 => "UDP",
                    _ => $"IP/{header.IpProtocol}"
                }
                : string.Empty;

            // GeniaFirewall 0.7.x enforcement and UI are scoped to TCP/UDP.
            if (protocol is not ("TCP" or "UDP"))
                return;

            var localAddress = string.Empty;
            var remoteAddress = string.Empty;
            if ((header.Flags & FlagIpVersionSet) != 0)
            {
                if ((header.Flags & FlagLocalAddrSet) != 0)
                    localAddress = FormatAddress(header.IpVersion, header.LocalAddress);
                if ((header.Flags & FlagRemoteAddrSet) != 0)
                    remoteAddress = FormatAddress(header.IpVersion, header.RemoteAddress);
            }

            var localPort = (header.Flags & FlagLocalPortSet) != 0 ? header.LocalPort : 0;
            var remotePort = (header.Flags & FlagRemotePortSet) != 0 ? header.RemotePort : 0;

            var action = netEvent.Type == EventTypeClassifyAllow
                ? WfpTelemetryAction.Allow
                : WfpTelemetryAction.Drop;

            var direction = WfpTelemetryDirection.Unknown;
            var isLoopback = IsLoopbackAddress(localAddress) || IsLoopbackAddress(remoteAddress);
            ulong filterId = 0;
            ushort layerId = 0;
            if (netEvent.EventData != IntPtr.Zero)
            {
                try
                {
                    var classify = Marshal.PtrToStructure<FwpmNetEventClassifyCommon>(netEvent.EventData);
                    filterId = classify.FilterId;
                    layerId = classify.LayerId;
                    direction = classify.Direction switch
                    {
                        DirectionInbound => WfpTelemetryDirection.Inbound,
                        DirectionOutbound => WfpTelemetryDirection.Outbound,
                        _ => WfpTelemetryDirection.Unknown
                    };
                    isLoopback |= classify.IsLoopback != 0;
                }
                catch
                {
                    // Header data remains useful even when the type-specific payload cannot be decoded.
                }
            }

            var descriptor = filterId == 0 ? null : _filterResolver(filterId);
            var layerName = GetLayerName(direction, header.IpVersion);
            var (interfaceIndex, interfaceName) = ResolveInterface(localAddress);
            var scope = ClassifyScope(isLoopback, localAddress, remoteAddress);
            var seenUtc = FileTimeToUtc(header.TimeStamp);
            if (seenUtc == DateTime.MinValue)
                seenUtc = DateTime.UtcNow;

            var dedupeKey = $"{exePath}|{protocol}|{direction}|{action}|{localAddress}|{localPort}|{remoteAddress}|{remotePort}|{filterId}";
            lock (_sync)
            {
                _received++;
                CleanupDedupeUnsafe();
                var now = DateTime.UtcNow;
                if (_dedupe.TryGetValue(dedupeKey, out var nextAllowed) && nextAllowed > now)
                    return;

                _dedupe[dedupeKey] = now.AddSeconds(2);
                var item = new WfpNetEventSnapshot
                {
                    Sequence = ++_sequence,
                    SeenUtc = seenUtc,
                    ExePath = exePath,
                    Protocol = protocol,
                    LocalAddress = localAddress,
                    LocalPort = localPort,
                    RemoteAddress = remoteAddress,
                    RemotePort = remotePort,
                    Direction = direction,
                    Action = action,
                    Scope = scope,
                    IsLoopback = isLoopback,
                    FilterId = filterId,
                    LayerId = layerId,
                    LayerName = layerName,
                    InterfaceIndex = interfaceIndex,
                    InterfaceName = interfaceName,
                    MatchedFilterName = descriptor?.Name ?? string.Empty,
                    Reason = descriptor?.Reason ?? (action == WfpTelemetryAction.Drop ? "OTHER_WFP_FILTER" : string.Empty)
                };

                if (action == WfpTelemetryAction.Drop)
                {
                    _blockedEventCount++;
                    var pid = TryFindProcessIdByPath(exePath);
                    var matchedRule = string.IsNullOrWhiteSpace(item.MatchedFilterName) ? "<none>" : item.MatchedFilterName;
                    var reason = string.IsNullOrWhiteSpace(item.Reason) ? "UNKNOWN" : item.Reason;
                    var remote = FormatEndpoint(remoteAddress, remotePort);
                    _lastBlockedEventSummary =
                        $"timeUtc={seenUtc.ToUniversalTime():yyyy-MM-ddTHH:mm:ss.fffZ}; layer={layerName}; filterId={filterId}; pid={(pid == 0 ? "?" : pid.ToString())}; app={exePath}; protocol={protocol}; remote={remote}; " +
                        $"ifIndex={interfaceIndex}; interface={(string.IsNullOrWhiteSpace(interfaceName) ? "?" : interfaceName)}; reason={reason}; matchedRule={matchedRule}";
                    ServiceLog.Write($"WFP BLOCK {_lastBlockedEventSummary}");
                }

                _events.AddLast(item);
                while (_events.Count > MaxBufferedEvents)
                {
                    _events.RemoveFirst();
                    _dropped++;
                }
            }
        }
        catch (Exception ex)
        {
            lock (_sync)
                _lastError = ex.Message;
        }
    }

    private static string GetLayerName(WfpTelemetryDirection direction, int ipVersion)
    {
        var suffix = ipVersion == IpVersionV6 ? "V6" : "V4";
        return direction switch
        {
            WfpTelemetryDirection.Outbound => $"ALE_AUTH_CONNECT_{suffix}",
            WfpTelemetryDirection.Inbound => $"ALE_AUTH_RECV_ACCEPT_{suffix}",
            _ => $"ALE_UNKNOWN_{suffix}"
        };
    }

    private static (uint Index, string Name) ResolveInterface(string localAddress)
    {
        if (!IPAddress.TryParse(localAddress, out var target))
            return (0, string.Empty);

        try
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                IPInterfaceProperties properties;
                try { properties = networkInterface.GetIPProperties(); }
                catch { continue; }

                if (!properties.UnicastAddresses.Any(item => item.Address.Equals(target)))
                    continue;

                uint index = 0;
                try
                {
                    if (target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        index = checked((uint)(properties.GetIPv4Properties()?.Index ?? 0));
                    else if (target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        index = checked((uint)(properties.GetIPv6Properties()?.Index ?? 0));
                }
                catch { }

                return (index, networkInterface.Name);
            }
        }
        catch
        {
        }

        return (0, string.Empty);
    }

    private static int TryFindProcessIdByPath(string exePath)
    {
        try
        {
            var baseName = Path.GetFileNameWithoutExtension(exePath);
            if (string.IsNullOrWhiteSpace(baseName))
                return 0;

            foreach (var process in Process.GetProcessesByName(baseName))
            {
                using (process)
                {
                    try
                    {
                        var candidate = process.MainModule?.FileName;
                        if (!string.IsNullOrWhiteSpace(candidate) &&
                            string.Equals(Path.GetFullPath(candidate), Path.GetFullPath(exePath), StringComparison.OrdinalIgnoreCase))
                            return process.Id;
                    }
                    catch
                    {
                    }
                }
            }
        }
        catch
        {
        }

        return 0;
    }

    private static string FormatEndpoint(string address, int port)
    {
        if (string.IsNullOrWhiteSpace(address))
            return port > 0 ? $"?:{port}" : "?";

        if (port <= 0)
            return address;

        return IPAddress.TryParse(address, out var ip) &&
               ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{address}]:{port}"
            : $"{address}:{port}";
    }

    private void CleanupDedupeUnsafe()
    {
        var now = DateTime.UtcNow;
        if (now - _lastDedupeCleanupUtc < TimeSpan.FromMinutes(1))
            return;

        var expired = _dedupe.Where(pair => pair.Value <= now).Select(pair => pair.Key).ToList();
        foreach (var key in expired)
            _dedupe.Remove(key);

        _lastDedupeCleanupUtc = now;
    }

    private string DecodeAppId(FwpByteBlob blob)
    {
        try
        {
            var size = checked((int)Math.Min(blob.Size, (uint)(MaxPathCharacters * 2)));
            if (size <= 1 || blob.Data == IntPtr.Zero)
                return string.Empty;

            var bytes = new byte[size];
            Marshal.Copy(blob.Data, bytes, 0, bytes.Length);
            var value = Encoding.Unicode.GetString(bytes).TrimEnd('\0').Trim();
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            value = value.Replace('/', '\\');
            if (value.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
                value = value[4..];
            else if (value.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
                value = value[4..];

            if (value.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var pair in _devicePrefixes.OrderByDescending(pair => pair.Key.Length))
                {
                    if (!value.StartsWith(pair.Key, StringComparison.OrdinalIgnoreCase))
                        continue;

                    value = pair.Value + value[pair.Key.Length..];
                    break;
                }
            }

            try
            {
                if (Path.IsPathFullyQualified(value))
                    value = Path.GetFullPath(value);
            }
            catch
            {
            }

            return value;
        }
        catch
        {
            return string.Empty;
        }
    }

    private void BuildDevicePrefixMap()
    {
        _devicePrefixes.Clear();
        for (var drive = 'A'; drive <= 'Z'; drive++)
        {
            var driveName = $"{drive}:";
            var buffer = new StringBuilder(4096);
            if (QueryDosDevice(driveName, buffer, buffer.Capacity) == 0)
                continue;

            var target = buffer.ToString().Split('\0', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(target))
                continue;

            _devicePrefixes[target] = driveName;
        }
    }

    private static string FormatAddress(int ipVersion, IpAddressUnion address)
    {
        try
        {
            if (ipVersion == IpVersionV4)
            {
                // FWPM_NET_EVENT_HEADER2 exposes IPv4 as a UINT32 in network byte
                // order. IPAddress(long) interprets the integer in host byte order on
                // Windows and would render 127.0.0.1 as 1.0.0.127.
                var value = address.Part0;
                return new IPAddress(new byte[]
                {
                    (byte)(value >> 24),
                    (byte)(value >> 16),
                    (byte)(value >> 8),
                    (byte)value
                }).ToString();
            }

            if (ipVersion == IpVersionV6)
            {
                var bytes = new byte[16];
                CopyUInt32Bytes(address.Part0, bytes, 0);
                CopyUInt32Bytes(address.Part1, bytes, 4);
                CopyUInt32Bytes(address.Part2, bytes, 8);
                CopyUInt32Bytes(address.Part3, bytes, 12);
                return new IPAddress(bytes).ToString();
            }
        }
        catch
        {
        }

        return string.Empty;
    }

    private static void CopyUInt32Bytes(uint value, byte[] destination, int offset)
    {
        var bytes = BitConverter.GetBytes(value);
        Buffer.BlockCopy(bytes, 0, destination, offset, 4);
    }

    private static bool IsLoopbackAddress(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
            return false;
        return IPAddress.IsLoopback(ip);
    }

    private static WfpTelemetryScope ClassifyScope(bool isLoopback, string localAddress, string remoteAddress)
    {
        if (isLoopback)
            return WfpTelemetryScope.Loopback;

        var candidate = remoteAddress;
        if (string.IsNullOrWhiteSpace(candidate))
            candidate = localAddress;

        if (!IPAddress.TryParse(candidate, out var address))
            return WfpTelemetryScope.Unknown;

        if (IPAddress.IsLoopback(address))
            return WfpTelemetryScope.Loopback;

        if (IsPrivateOrLinkLocal(address))
            return WfpTelemetryScope.Lan;

        return WfpTelemetryScope.Internet;
    }

    private static bool IsPrivateOrLinkLocal(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254);
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || (bytes[0] & 0xFE) == 0xFC;
        }

        return false;
    }

    private static DateTime FileTimeToUtc(FileTime value)
    {
        try
        {
            var combined = ((long)value.HighDateTime << 32) | value.LowDateTime;
            return combined <= 0 ? DateTime.MinValue : DateTime.FromFileTimeUtc(combined);
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
                return;
            _disposed = true;
            CloseUnsafe();
        }
    }

    private void CloseUnsafe()
    {
        if (_subscriptionHandle != IntPtr.Zero && _engineHandle != IntPtr.Zero)
        {
            try { _ = FwpmNetEventUnsubscribe0(_engineHandle, _subscriptionHandle); } catch { }
        }
        _subscriptionHandle = IntPtr.Zero;

        if (_engineHandle != IntPtr.Zero)
        {
            try { _ = FwpmEngineClose0(_engineHandle); } catch { }
        }
        _engineHandle = IntPtr.Zero;
        _callback = null;
        _available = false;
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void FwpmNetEventCallback1(IntPtr context, IntPtr netEvent);

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmNetEventSubscription0
    {
        public IntPtr EnumTemplate;
        public uint Flags;
        public Guid SessionKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct IpAddressUnion
    {
        [FieldOffset(0)] public uint Part0;
        [FieldOffset(4)] public uint Part1;
        [FieldOffset(8)] public uint Part2;
        [FieldOffset(12)] public uint Part3;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmNetEventHeader2
    {
        public FileTime TimeStamp;
        public uint Flags;
        public int IpVersion;
        public byte IpProtocol;
        public IpAddressUnion LocalAddress;
        public IpAddressUnion RemoteAddress;
        public ushort LocalPort;
        public ushort RemotePort;
        public uint ScopeId;
        public FwpByteBlob AppId;
        public IntPtr UserId;
        public int AddressFamily;
        public IntPtr PackageSid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmNetEvent2
    {
        public FwpmNetEventHeader2 Header;
        public uint Type;
        public IntPtr EventData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmNetEventClassifyCommon
    {
        public ulong FilterId;
        public ushort LayerId;
        public uint ReauthReason;
        public uint OriginalProfile;
        public uint CurrentProfile;
        public uint Direction;
        public int IsLoopback;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmNetEventSubscribe1(
        IntPtr engineHandle,
        ref FwpmNetEventSubscription0 subscription,
        FwpmNetEventCallback1 callback,
        IntPtr context,
        out IntPtr eventsHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmNetEventUnsubscribe0(IntPtr engineHandle, IntPtr eventsHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int maxLength);
}
