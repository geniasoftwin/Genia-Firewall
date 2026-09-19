using System.IO;
using System.Runtime.InteropServices;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

/// <summary>
/// Conservative classifier for Windows components that may be auto-allowed without a prompt.
/// Trust is never granted by filename alone: the executable must live in System32, pass
/// WinVerifyTrust with a Microsoft publisher, and match a deliberately small allow-list.
/// svchost.exe is accepted only when every Win32 service hosted by the current PID is allow-listed.
/// </summary>
public sealed class TrustedSystemProcessService
{
    private const uint ScManagerEnumerateService = 0x0004;
    private const uint ServiceWin32 = 0x00000030;
    private const uint ServiceStateAll = 0x00000003;
    private const int ScEnumProcessInfo = 0;
    private const int ErrorMoreData = 234;

    private static readonly HashSet<string> TrustedSvchostServices = new(StringComparer.OrdinalIgnoreCase)
    {
        // Core address/name/connectivity services.
        "Dhcp",
        "Dnscache",
        "NlaSvc",
        "W32Time",

        // Windows servicing/update path. These remain constrained by Microsoft signature + System32.
        "BITS",
        "wuauserv",
        "UsoSvc",
        "DoSvc",
        "CryptSvc"
    };

    private static readonly HashSet<string> TrustedDirectExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows Update / servicing clients that can legitimately contact Microsoft directly.
        "MoUsoCoreWorker.exe",
        "UsoClient.exe",
        "wuauclt.exe",
        "SIHClient.exe"
    };

    private readonly string _system32Directory;

    public TrustedSystemProcessService()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _system32Directory = Path.GetFullPath(Path.Combine(windows, "System32"))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    public TrustedSystemDecision Evaluate(NetworkConnectionInfo connection)
    {
        if (connection.ProcessId <= 4 || string.IsNullOrWhiteSpace(connection.ExePath))
            return TrustedSystemDecision.NotTrusted;

        if (!TryGetSystem32Executable(connection.ExePath, out var fullPath, out var fileName))
            return TrustedSystemDecision.NotTrusted;

        var signature = ExecutableMetadataService.GetSignatureInfo(fullPath);
        if (!signature.IsTrusted || !IsMicrosoftPublisher(signature.Publisher))
            return TrustedSystemDecision.NotTrusted;

        if (fileName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
        {
            var services = GetServicesForProcess(connection.ProcessId);
            if (services.Count == 0 || services.Any(service => !TrustedSvchostServices.Contains(service)))
                return TrustedSystemDecision.NotTrusted;

            return new TrustedSystemDecision(
                true,
                $"Проверенный Microsoft Windows svchost.exe · службы: {string.Join(", ", services.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))}");
        }

        if (!TrustedDirectExecutables.Contains(fileName))
            return TrustedSystemDecision.NotTrusted;

        return new TrustedSystemDecision(
            true,
            $"Проверенный системный компонент Windows: {fileName} · Authenticode Microsoft подтверждена");
    }

    private bool TryGetSystem32Executable(string path, out string fullPath, out string fileName)
    {
        fullPath = string.Empty;
        fileName = string.Empty;

        try
        {
            if (!Path.IsPathFullyQualified(path) || !File.Exists(path))
                return false;

            fullPath = Path.GetFullPath(path);
            var directory = Path.GetDirectoryName(fullPath)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!string.Equals(directory, _system32Directory, StringComparison.OrdinalIgnoreCase))
                return false;

            fileName = Path.GetFileName(fullPath);
            return !string.IsNullOrWhiteSpace(fileName) && fullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            fullPath = string.Empty;
            fileName = string.Empty;
            return false;
        }
    }

    private static bool IsMicrosoftPublisher(string publisher) =>
        !string.IsNullOrWhiteSpace(publisher) &&
        (publisher.Equals("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
         publisher.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) ||
         publisher.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
         publisher.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase));

    private static IReadOnlyList<string> GetServicesForProcess(int processId)
    {
        if (processId <= 0)
            return [];

        var manager = OpenSCManager(null, null, ScManagerEnumerateService);
        if (manager == IntPtr.Zero)
            return [];

        IntPtr buffer = IntPtr.Zero;
        try
        {
            var bytesNeeded = 0;
            var servicesReturned = 0;
            var resumeHandle = 0;

            _ = EnumServicesStatusEx(
                manager,
                ScEnumProcessInfo,
                ServiceWin32,
                ServiceStateAll,
                IntPtr.Zero,
                0,
                out bytesNeeded,
                out servicesReturned,
                ref resumeHandle,
                null);

            if (bytesNeeded <= 0 && Marshal.GetLastWin32Error() != ErrorMoreData)
                return [];

            buffer = Marshal.AllocHGlobal(Math.Max(bytesNeeded, 64 * 1024));
            resumeHandle = 0;

            if (!EnumServicesStatusEx(
                    manager,
                    ScEnumProcessInfo,
                    ServiceWin32,
                    ServiceStateAll,
                    buffer,
                    Math.Max(bytesNeeded, 64 * 1024),
                    out bytesNeeded,
                    out servicesReturned,
                    ref resumeHandle,
                    null))
            {
                return [];
            }

            var result = new List<string>();
            var itemSize = Marshal.SizeOf<EnumServiceStatusProcess>();
            var current = buffer;

            for (var index = 0; index < servicesReturned; index++)
            {
                var item = Marshal.PtrToStructure<EnumServiceStatusProcess>(current);
                if (item.ServiceStatusProcess.ProcessId == (uint)processId && !string.IsNullOrWhiteSpace(item.ServiceName))
                    result.Add(item.ServiceName);

                current = IntPtr.Add(current, itemSize);
            }

            return result.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch
        {
            return [];
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
            CloseServiceHandle(manager);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EnumServiceStatusProcess
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string ServiceName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string DisplayName;

        public ServiceStatusProcess ServiceStatusProcess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusEx(
        IntPtr serviceManager,
        int infoLevel,
        uint serviceType,
        uint serviceState,
        IntPtr services,
        int bufferSize,
        out int bytesNeeded,
        out int servicesReturned,
        ref int resumeHandle,
        string? groupName);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);
}

public readonly record struct TrustedSystemDecision(bool IsTrusted, string Reason)
{
    public static TrustedSystemDecision NotTrusted => new(false, string.Empty);
}
