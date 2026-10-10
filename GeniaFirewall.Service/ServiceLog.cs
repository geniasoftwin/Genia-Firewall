using System.Text;

namespace GeniaFirewall.Service;

internal static class ServiceLog
{
    private static readonly object Sync = new();

    private static string LogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "GeniaFirewall",
        "Logs");

    public static string CurrentLogPath => Path.Combine(LogDirectory, $"GeniaFirewall.Service-{DateTime.Now:yyyyMMdd}.log");

    public static void Write(string message)
    {
        try
        {
            lock (Sync)
            {
                ServiceStorageSecurity.EnsureProtectedDirectory(LogDirectory);
                ServiceStorageSecurity.ProtectFile(CurrentLogPath);
                File.AppendAllText(
                    CurrentLogPath,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}",
                    Encoding.UTF8);
                ServiceStorageSecurity.ProtectFile(CurrentLogPath);
            }
        }
        catch
        {
        }
    }

    public static void WriteException(string context, Exception exception) =>
        Write($"{context}{Environment.NewLine}{exception}");
}
