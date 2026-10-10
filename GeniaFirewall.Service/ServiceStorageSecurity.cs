using System.ComponentModel;
using System.Runtime.InteropServices;

namespace GeniaFirewall.Service;

/// <summary>
/// Protects LocalSystem-owned service state from modification by standard users.
/// </summary>
internal static class ServiceStorageSecurity
{
    private const string DirectorySddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    private const string FileSddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    private const uint SddlRevision1 = 1;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;

    public static void EnsureProtectedDirectory(string path)
    {
        var parent = Directory.GetParent(path)?.FullName;
        if (!string.IsNullOrWhiteSpace(parent) &&
            string.Equals(Path.GetFileName(parent), "GeniaFirewall", StringComparison.OrdinalIgnoreCase))
        {
            Directory.CreateDirectory(parent);
            RejectReparsePoint(parent);
            ApplyProtectedDacl(parent, DirectorySddl);
        }

        Directory.CreateDirectory(path);
        RejectReparsePoint(path);
        ApplyProtectedDacl(path, DirectorySddl);
    }

    public static void ProtectFile(string path)
    {
        if (!File.Exists(path))
            return;
        RejectReparsePoint(path);
        ApplyProtectedDacl(path, FileSddl);
    }

    public static void DeleteRegularFileIfExists(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
            return;
        RejectReparsePoint(path);
        if (Directory.Exists(path))
            throw new IOException($"Expected a service-state file but found a directory: {path}");
        File.Delete(path);
    }

    private static void RejectReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"Refusing reparse-point service storage: {path}");
    }

    private static void ApplyProtectedDacl(string path, string sddl)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl,
                SddlRevision1,
                out var securityDescriptor,
                out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not create a security descriptor for {path}.");
        }

        try
        {
            if (!SetFileSecurity(
                    path,
                    DaclSecurityInformation | ProtectedDaclSecurityInformation,
                    securityDescriptor))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not protect service storage ACL for {path}.");
            }
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", EntryPoint = "SetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileSecurity(string fileName, uint securityInformation, IntPtr securityDescriptor);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
