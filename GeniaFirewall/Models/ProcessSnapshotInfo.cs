namespace GeniaFirewall.Models;

/// <summary>
/// Best-effort snapshot captured while the process that generated network activity is still alive.
/// The values travel with the network event so short-lived host processes can still be explained
/// after they exit, before the user sees the prompt.
/// </summary>
public sealed record ProcessSnapshotInfo
{
    public int ProcessId { get; init; }
    public long StartTimeUtcTicks { get; init; }
    public int ParentProcessId { get; init; }
    public string ParentProcessName { get; init; } = string.Empty;
    public string ParentProcessPath { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;

    public bool HasData => ProcessId > 0 || ParentProcessId > 0 || !string.IsNullOrWhiteSpace(CommandLine);
}
