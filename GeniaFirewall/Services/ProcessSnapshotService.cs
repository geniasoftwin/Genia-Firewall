using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

/// <summary>
/// Captures process identity details immediately when a network row is observed. This is intentionally
/// best-effort: protected processes can deny access, and very short-lived processes may disappear while
/// being queried. Missing fields never weaken WFP enforcement; they only reduce UI context.
/// </summary>
public static class ProcessSnapshotService
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint Th32csSnapProcess = 0x00000002;
    private const int ProcessCommandLineInformationClass = 60;
    private const int MaxCommandLineCharacters = 4096;

    public static int TryFindProcessIdByPath(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return 0;

        string expectedPath;
        string processName;
        try
        {
            expectedPath = Path.GetFullPath(exePath);
            processName = Path.GetFileNameWithoutExtension(expectedPath);
        }
        catch
        {
            return 0;
        }

        if (string.IsNullOrWhiteSpace(processName))
            return 0;

        try
        {
            foreach (var process in Process.GetProcessesByName(processName))
            {
                using (process)
                {
                    var actualPath = TryGetProcessPath(process.Id);
                    if (string.Equals(actualPath, expectedPath, StringComparison.OrdinalIgnoreCase))
                        return process.Id;
                }
            }
        }
        catch
        {
        }

        return 0;
    }

    public static ProcessSnapshotInfo Capture(int processId)
    {
        if (processId <= 0)
            return new ProcessSnapshotInfo();

        long startTimeUtcTicks = 0;
        try
        {
            using var process = Process.GetProcessById(processId);
            startTimeUtcTicks = process.StartTime.ToUniversalTime().Ticks;
        }
        catch
        {
        }

        var parentProcessId = TryGetParentProcessId(processId);
        var commandLine = string.Empty;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle != IntPtr.Zero)
        {
            try
            {
                commandLine = TryGetCommandLine(handle);
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        var parentPath = parentProcessId > 0 ? TryGetProcessPath(parentProcessId) : string.Empty;
        var parentName = string.IsNullOrWhiteSpace(parentPath)
            ? TryGetProcessName(parentProcessId)
            : Path.GetFileName(parentPath);

        return new ProcessSnapshotInfo
        {
            ProcessId = processId,
            StartTimeUtcTicks = startTimeUtcTicks,
            ParentProcessId = parentProcessId,
            ParentProcessName = Sanitize(parentName, 260),
            ParentProcessPath = Sanitize(parentPath, 1024),
            CommandLine = Sanitize(commandLine, MaxCommandLineCharacters)
        };
    }

    private static int TryGetParentProcessId(int processId)
    {
        var snapshot = CreateToolhelp32Snapshot(Th32csSnapProcess, 0);
        if (snapshot == new IntPtr(-1))
            return 0;

        try
        {
            var entry = new ProcessEntry32
            {
                Size = (uint)Marshal.SizeOf<ProcessEntry32>(),
                ExeFile = string.Empty
            };

            if (!Process32First(snapshot, ref entry))
                return 0;

            do
            {
                if (entry.ProcessId == (uint)processId)
                    return entry.ParentProcessId <= int.MaxValue ? (int)entry.ParentProcessId : 0;
            }
            while (Process32Next(snapshot, ref entry));

            return 0;
        }
        catch
        {
            return 0;
        }
        finally
        {
            CloseHandle(snapshot);
        }
    }

    private static string TryGetCommandLine(IntPtr processHandle)
    {
        try
        {
            _ = NtQueryInformationProcess(
                processHandle,
                ProcessCommandLineInformationClass,
                IntPtr.Zero,
                0,
                out var requiredLength);

            if (requiredLength <= 0 || requiredLength > 256 * 1024)
                return string.Empty;

            var buffer = Marshal.AllocHGlobal(requiredLength);
            try
            {
                var status = NtQueryInformationProcess(
                    processHandle,
                    ProcessCommandLineInformationClass,
                    buffer,
                    requiredLength,
                    out _);
                if (status < 0)
                    return string.Empty;

                var value = Marshal.PtrToStructure<UnicodeString>(buffer);
                if (value.Buffer == IntPtr.Zero || value.Length == 0)
                    return string.Empty;

                var characterCount = Math.Min(value.Length / 2, MaxCommandLineCharacters);
                return Marshal.PtrToStringUni(value.Buffer, characterCount) ?? string.Empty;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string TryGetProcessPath(int processId)
    {
        if (processId <= 0)
            return string.Empty;

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
            return string.Empty;

        try
        {
            var capacity = 32768;
            var builder = new StringBuilder(capacity);
            return QueryFullProcessImageName(handle, 0, builder, ref capacity)
                ? builder.ToString()
                : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static string TryGetProcessName(int processId)
    {
        if (processId <= 0)
            return string.Empty;

        try
        {
            using var process = Process.GetProcessById(processId);
            return string.IsNullOrWhiteSpace(process.ProcessName)
                ? string.Empty
                : process.ProcessName + ".exe";
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string Sanitize(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var clean = new string(value.Where(character => !char.IsControl(character) || character == '\t').ToArray()).Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public UIntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr processHandle, uint flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
