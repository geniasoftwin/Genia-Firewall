using System.Diagnostics;
using System.Security.Cryptography;

namespace GeniaFirewall.Autostart;

internal static class Program
{
    // NativeAOT WinExe: no console subsystem. Exit codes:
    // 2 bad arguments, 20 missing target, 21 SHA-256 mismatch,
    // 22 launch failure, 23 reparse-point target.
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 4 ||
            !string.Equals(args[0], "--sha256", StringComparison.Ordinal) ||
            !string.Equals(args[2], "--target", StringComparison.Ordinal) ||
            args[1].Length != 64 ||
            !args[1].All(Uri.IsHexDigit) ||
            !Path.IsPathFullyQualified(args[3]))
            return 2;

        try
        {
            var path = Path.GetFullPath(args[3]);
            if (!string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
                return 2;
            if (!File.Exists(path))
                return 20;
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                return 23;

            // Keep a read-only handle open, denying writes and deletes, through CreateProcess.
            using var handle = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var actual = SHA256.HashData(handle);
            var expected = Convert.FromHexString(args[1]);
            if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                return 21;

            using var child = Process.Start(new ProcessStartInfo
            {
                FileName = path,
                WorkingDirectory = Path.GetDirectoryName(path)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                ArgumentList = { "--background" }
            });
            return child is null ? 22 : 0;
        }
        catch (FileNotFoundException)
        {
            return 20;
        }
        catch
        {
            return 22;
        }
    }
}
