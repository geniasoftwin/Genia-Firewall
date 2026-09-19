using System.Text.Json;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

internal sealed class ServicePolicyStore
{
    private const long MaxPolicyBytes = 8L * 1024 * 1024;

    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public ServicePolicyStore()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        DirectoryPath = Path.Combine(programData, "GeniaFirewall", "Service");
        PolicyPath = Path.Combine(DirectoryPath, "wfp-policy.json");
    }

    public string DirectoryPath { get; }
    public string PolicyPath { get; }
    public bool Exists => File.Exists(PolicyPath);

    public WfpPolicySnapshot Load()
    {
        if (!File.Exists(PolicyPath))
            return DisabledPolicy();

        var length = new FileInfo(PolicyPath).Length;
        if (length > MaxPolicyBytes)
            throw new InvalidDataException($"Persisted WFP policy is too large ({length} bytes).");

        using var stream = new FileStream(
            PolicyPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.SequentialScan);
        var policy = JsonSerializer.Deserialize<WfpPolicySnapshot>(stream, _jsonOptions);
        return policy ?? DisabledPolicy();
    }

    public void Save(WfpPolicySnapshot policy)
    {
        Directory.CreateDirectory(DirectoryPath);
        var json = JsonSerializer.SerializeToUtf8Bytes(policy, _jsonOptions);
        if (json.LongLength > MaxPolicyBytes)
            throw new InvalidDataException($"WFP policy is too large ({json.LongLength} bytes).");

        var temporary = PolicyPath + ".tmp";
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       16 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(json);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, PolicyPath, overwrite: true);
        }
        finally
        {
            try
            {
                if (File.Exists(temporary))
                    File.Delete(temporary);
            }
            catch
            {
            }
        }
    }

    public static WfpPolicySnapshot DisabledPolicy() => new()
    {
        BackendActive = false,
        ProtectionEnabled = false,
        Mode = WfpPolicyMode.Normal,
        Applications = []
    };
}
