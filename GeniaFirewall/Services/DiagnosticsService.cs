using System.IO;
using System.Text;

namespace GeniaFirewall.Services;

public sealed class DiagnosticsService
{
    private readonly string _logDirectory;
    private readonly object _sync = new();

    public DiagnosticsService(string dataDirectory)
    {
        _logDirectory = Path.Combine(dataDirectory, "Logs");
    }

    public string LogDirectory => _logDirectory;

    public void Log(string message)
    {
        try
        {
            lock (_sync)
            {
                Directory.CreateDirectory(_logDirectory);
                var file = Path.Combine(_logDirectory, $"GeniaFirewall-{DateTime.Now:yyyyMMdd}.log");
                File.AppendAllText(
                    file,
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}{Environment.NewLine}",
                    Encoding.UTF8);
            }
        }
        catch
        {
        }
    }

    public void LogException(string context, Exception exception)
    {
        try
        {
            lock (_sync)
            {
                Directory.CreateDirectory(_logDirectory);
                var file = Path.Combine(_logDirectory, $"GeniaFirewall-{DateTime.Now:yyyyMMdd}.log");
                var text = new StringBuilder()
                    .AppendLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {context}")
                    .AppendLine(exception.ToString())
                    .AppendLine()
                    .ToString();

                File.AppendAllText(file, text, Encoding.UTF8);
            }
        }
        catch
        {
        }
    }
}
