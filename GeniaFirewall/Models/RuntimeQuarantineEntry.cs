namespace GeniaFirewall.Models;

public sealed class RuntimeQuarantineEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ExePath { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
}
