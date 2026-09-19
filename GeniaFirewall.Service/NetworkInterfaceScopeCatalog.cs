using System.Net.NetworkInformation;

namespace GeniaFirewall.Service;

/// <summary>
/// Classifies local interfaces for WFP scoping. GeniaFirewall 0.7.3 treats
/// loopback and virtual/TUN adapters as internal plumbing so the normal-mode
/// unsolicited-inbound default block is applied to physical/external-facing
/// adapters instead of breaking local proxy/TUN data paths.
/// </summary>
internal static class NetworkInterfaceScopeCatalog
{
    internal sealed record Snapshot(
        IReadOnlyList<uint> PhysicalInterfaceIndexes,
        IReadOnlyList<uint> VirtualInterfaceIndexes,
        string PhysicalSummary,
        string VirtualSummary,
        bool UsedFallback);

    private static readonly string[] VirtualHints =
    [
        "wintun",
        "wireguard",
        "tap-windows",
        "tap adapter",
        "vpn",
        "virtual",
        "hyper-v",
        "vethernet",
        "vmware",
        "virtualbox",
        "tailscale",
        "zerotier",
        "openvpn",
        "xray",
        "sing-box",
        "singbox",
        "geniaproxy",
        "docker",
        "wsl"
    ];

    public static Snapshot Capture()
    {
        var physical = new SortedSet<uint>();
        var virtualIndexes = new SortedSet<uint>();
        var physicalNames = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var virtualNames = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var indexes = GetInterfaceIndexes(networkInterface);
                if (indexes.Count == 0)
                    continue;

                var isVirtual = IsVirtualOrTunnel(networkInterface);
                var target = isVirtual ? virtualIndexes : physical;
                foreach (var index in indexes)
                    target.Add(index);

                var label = BuildLabel(networkInterface, indexes);
                if (isVirtual)
                    virtualNames.Add(label);
                else
                    physicalNames.Add(label);
            }
        }
        catch (Exception ex)
        {
            ServiceLog.WriteException("Network-interface classification failed", ex);
        }

        // Fail-safe: if Windows did not expose any non-virtual interface, the WFP layer
        // falls back to the legacy external-inbound catch-all rather than silently
        // opening inbound traffic.
        var fallback = physical.Count == 0;

        return new Snapshot(
            physical.ToList(),
            virtualIndexes.ToList(),
            string.Join("; ", physicalNames),
            string.Join("; ", virtualNames),
            fallback);
    }

    private static List<uint> GetInterfaceIndexes(NetworkInterface networkInterface)
    {
        var indexes = new HashSet<uint>();
        try
        {
            var properties = networkInterface.GetIPProperties();

            try
            {
                var ipv4 = properties.GetIPv4Properties();
                if (ipv4 is not null && ipv4.Index > 0)
                    indexes.Add((uint)ipv4.Index);
            }
            catch
            {
            }

            try
            {
                var ipv6 = properties.GetIPv6Properties();
                if (ipv6 is not null && ipv6.Index > 0)
                    indexes.Add((uint)ipv6.Index);
            }
            catch
            {
            }
        }
        catch
        {
        }

        return indexes.OrderBy(value => value).ToList();
    }

    private static bool IsVirtualOrTunnel(NetworkInterface networkInterface)
    {
        var name = (networkInterface.Name ?? string.Empty).Trim().ToLowerInvariant();
        var description = (networkInterface.Description ?? string.Empty).Trim().ToLowerInvariant();
        var text = $"{name} {description}";

        if (VirtualHints.Any(hint => text.Contains(hint, StringComparison.Ordinal)))
            return true;

        // Common short names created by TUN stacks. Deliberately avoid treating every
        // NetworkInterfaceType.Tunnel as internal: Teredo/6to4-like Internet tunnels
        // must not bypass the physical/external inbound default deny accidentally.
        if (name is "tun" or "tap" ||
            name.StartsWith("tun-", StringComparison.Ordinal) ||
            name.StartsWith("tap-", StringComparison.Ordinal) ||
            (name.Length > 3 && name.StartsWith("tun", StringComparison.Ordinal) && char.IsDigit(name[3])) ||
            (name.Length > 3 && name.StartsWith("tap", StringComparison.Ordinal) && char.IsDigit(name[3])))
            return true;

        return false;
    }

    private static string BuildLabel(NetworkInterface networkInterface, IReadOnlyCollection<uint> indexes)
    {
        var name = string.IsNullOrWhiteSpace(networkInterface.Name)
            ? networkInterface.Description
            : networkInterface.Name;
        if (string.IsNullOrWhiteSpace(name))
            name = networkInterface.NetworkInterfaceType.ToString();

        var indexText = string.Join(",", indexes.OrderBy(value => value));
        return $"{name} [if={indexText}]";
    }
}
