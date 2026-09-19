using System.Runtime.InteropServices;
using System.Text;

namespace GeniaFirewall.Services;

public static class ProcessIdentityService
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public static bool IsSameProcessImageRunning(int processId, string exePath)
    {
        if (processId <= 0 || string.IsNullOrWhiteSpace(exePath))
            return false;

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
            return false;

        try
        {
            var capacity = 32768;
            var builder = new StringBuilder(capacity);
            if (!QueryFullProcessImageName(handle, 0, builder, ref capacity))
                return false;

            return string.Equals(builder.ToString(), exePath, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint processAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
