using System.Collections.Concurrent;
using System.Net;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public sealed class HostnameResolverService
{
    private static readonly TimeSpan SuccessTtl = TimeSpan.FromHours(6);
    private static readonly TimeSpan FailureTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan LookupTimeout = TimeSpan.FromMilliseconds(700);

    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);

    public async Task<NetworkConnectionInfo> EnrichAsync(NetworkConnectionInfo connection)
    {
        if (!connection.HasRemoteEndpoint || string.IsNullOrWhiteSpace(connection.RemoteAddress))
            return connection;

        var hostName = await ResolveAsync(connection.RemoteAddress);
        return string.IsNullOrWhiteSpace(hostName)
            ? connection
            : connection with { RemoteHostName = hostName };
    }

    public async Task<IReadOnlyList<NetworkConnectionInfo>> EnrichAsync(IEnumerable<NetworkConnectionInfo> connections)
    {
        var items = connections.ToList();
        if (items.Count == 0)
            return items;

        var tasks = items.Select(EnrichAsync).ToArray();
        return await Task.WhenAll(tasks);
    }

    private async Task<string> ResolveAsync(string addressText)
    {
        if (!IPAddress.TryParse(addressText, out var address) || IPAddress.IsLoopback(address))
            return string.Empty;

        var now = DateTime.UtcNow;
        if (_cache.TryGetValue(addressText, out var cached) && cached.ExpiresAtUtc > now)
            return cached.HostName;

        try
        {
            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(LookupTimeout);
            var hostName = SanitizeHostName(entry.HostName, addressText);
            _cache[addressText] = new CacheEntry(hostName, now.Add(string.IsNullOrWhiteSpace(hostName) ? FailureTtl : SuccessTtl));
            return hostName;
        }
        catch
        {
            _cache[addressText] = new CacheEntry(string.Empty, now.Add(FailureTtl));
            return string.Empty;
        }
    }

    private static string SanitizeHostName(string? value, string addressText)
    {
        if (string.IsNullOrWhiteSpace(value) || string.Equals(value, addressText, StringComparison.OrdinalIgnoreCase))
            return string.Empty;

        var result = new string(value.Where(character => !char.IsControl(character)).ToArray()).Trim().TrimEnd('.');
        return result.Length <= 253 ? result : result[..253];
    }

    private sealed record CacheEntry(string HostName, DateTime ExpiresAtUtc);
}
