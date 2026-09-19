namespace GeniaFirewall.Models;

public sealed record NetworkConnectionInfo(
    int ProcessId,
    string ExePath,
    string Protocol,
    string RemoteAddress,
    int RemotePort,
    int LocalPort,
    DateTime SeenAt)
{
    public string RemoteHostName { get; init; } = string.Empty;
    public ProcessSnapshotInfo ProcessSnapshot { get; init; } = new();

    // 0.7.1 WFP telemetry context. Empty values are expected for legacy socket-table rows.
    public string LocalAddress { get; init; } = string.Empty;
    public string Direction { get; init; } = string.Empty;
    public string NetworkScope { get; init; } = string.Empty;
    public string TelemetryAction { get; init; } = string.Empty;
    public string TelemetrySource { get; init; } = string.Empty;
    public bool IsLoopback { get; init; }
    public bool IsListener { get; init; }

    public bool HasRemoteEndpoint => !string.IsNullOrWhiteSpace(RemoteAddress) && RemotePort > 0;

    public string RemoteDisplay
    {
        get
        {
            if (!HasRemoteEndpoint)
                return string.Empty;

            return string.IsNullOrWhiteSpace(RemoteHostName)
                ? $"{RemoteAddress}:{RemotePort}"
                : $"{RemoteHostName} ({RemoteAddress}):{RemotePort}";
        }
    }

    public string ActivityDisplay
    {
        get
        {
            if (IsListener)
            {
                var address = string.IsNullOrWhiteSpace(LocalAddress) || LocalAddress is "0.0.0.0" or "::"
                    ? "*"
                    : LocalAddress;
                return LocalPort > 0
                    ? $"TCP LISTEN · {address}:{LocalPort}"
                    : "TCP LISTEN";
            }

            var endpoint = HasRemoteEndpoint
                ? RemoteDisplay
                : LocalPort > 0
                    ? $"local port {LocalPort}"
                    : $"{Protocol} activity";

            var scope = NetworkScope switch
            {
                "Loopback" => "Loopback",
                "Lan" => "LAN",
                "Internet" => "Internet",
                _ => string.Empty
            };

            var direction = Direction switch
            {
                "Outbound" => "OUT",
                "Inbound" => "IN",
                _ => string.Empty
            };

            if (string.IsNullOrWhiteSpace(scope) && string.IsNullOrWhiteSpace(direction))
                return endpoint;
            if (string.IsNullOrWhiteSpace(scope))
                return $"{direction} · {endpoint}";
            if (string.IsNullOrWhiteSpace(direction))
                return $"{scope} · {endpoint}";
            return $"{scope} {direction} · {endpoint}";
        }
    }

    public string GroupKey => IsListener
        ? $"{Protocol}|LISTENER|{LocalAddress}|{LocalPort}"
        : HasRemoteEndpoint
            ? $"{Protocol}|{Direction}|{NetworkScope}|{RemoteAddress}|{RemotePort}"
            : $"{Protocol}|{Direction}|{NetworkScope}|LOCAL|{LocalPort}";
}
