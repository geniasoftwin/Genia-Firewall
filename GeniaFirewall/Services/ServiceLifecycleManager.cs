using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Services;

public sealed record ServiceLifecycleStatus(
    bool Installed,
    bool Running,
    bool BinaryPresent,
    bool ConfigurationValid,
    bool StorageProtected,
    string BinaryPath,
    string Description);

/// <summary>
/// Installs the embedded privileged service into a machine-protected directory.
/// The portable UI remains a single file; the LocalSystem service never runs from
/// the user-writable portable directory.
/// </summary>
public sealed class ServiceLifecycleManager
{
    private const string EmbeddedServiceResourceName = "GeniaFirewall.Payload.GeniaFirewall.Service.exe";
    private const string ServiceFileName = "GeniaFirewall.Service.exe";
    private const string ServiceDescription = "GeniaFirewall privileged WFP policy service.";
    private const string DirectorySddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    private const string FileSddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
    private const string ServiceObjectSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint Delete = 0x00010000;
    private const uint WriteDac = 0x00040000;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceNoChange = 0xffffffff;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const int ScStatusProcessInfo = 0;
    private const int ServiceConfigDescription = 1;
    private const int ServiceConfigFailureActions = 2;
    private const uint ScActionRestart = 1;

    private const int ErrorAccessDenied = 5;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorServiceAlreadyRunning = 1056;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorServiceMarkedForDelete = 1072;

    private const uint SddlRevision1 = 1;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint ProtectedDaclSecurityInformation = 0x80000000;

    public ServiceLifecycleManager()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            programFiles = Environment.GetEnvironmentVariable("ProgramFiles") ?? string.Empty;

        ProductDirectory = Path.Combine(programFiles, "GeniaFirewall");
        ServiceDirectory = Path.Combine(ProductDirectory, "Service");
        ServiceBinaryPath = Path.Combine(ServiceDirectory, ServiceFileName);
        StagedServiceBinaryPath = ServiceBinaryPath + ".new";
    }

    public string ProductDirectory { get; }
    public string ServiceDirectory { get; }
    public string ServiceBinaryPath { get; }
    private string StagedServiceBinaryPath { get; }

    public ServiceLifecycleStatus EnsureInstalledAndRunning()
    {
        EnsureSupportedAndElevated();
        EnsureSafeInstallPaths();

        var payload = ReadEmbeddedServicePayload();
        var payloadHash = SHA256.HashData(payload);

        using var serviceManager = OpenServiceManager(ScManagerConnect | ScManagerCreateService);
        using var existingService = OpenServiceIfPresent(
            serviceManager,
            ServiceQueryConfig | ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop | Delete | WriteDac);

        var serviceExists = existingService is not null;
        var installedPayloadMatches = File.Exists(ServiceBinaryPath) &&
                                      HashesEqual(payloadHash, ComputeFileHash(ServiceBinaryPath));
        var configuredPathMatches = serviceExists && ServicePathMatches(existingService!, ServiceBinaryPath);

        if (serviceExists && (!installedPayloadMatches || !configuredPathMatches))
            StopServiceAndWait(existingService!, TimeSpan.FromSeconds(20));

        if (!installedPayloadMatches)
            WriteProtectedPayload(payload, payloadHash);
        else
            ProtectFile(ServiceBinaryPath);

        SafeServiceHandle? createdService = null;
        try
        {
            var service = existingService ?? (createdService = CreateConfiguredService(serviceManager));
            if (existingService is not null)
                ConfigureExistingService(existingService);

            ConfigureDescription(service);
            ConfigureFailureRecovery(service);
            ProtectServiceObject(service);
            StartServiceAndWait(service, TimeSpan.FromSeconds(20));
        }
        finally
        {
            createdService?.Dispose();
        }

        var status = GetStatus();
        if (!status.Installed || !status.Running || !status.BinaryPresent ||
            !status.ConfigurationValid || !status.StorageProtected)
        {
            throw new InvalidOperationException($"Service installation verification failed: {status.Description}");
        }

        return status;
    }

    public ServiceLifecycleStatus DeactivateAndRemove()
    {
        EnsureSupportedAndElevated();

        using (var serviceManager = OpenServiceManager(ScManagerConnect))
        {
            using var service = OpenServiceIfPresent(
                serviceManager,
                ServiceQueryStatus | ServiceStop | Delete);
            if (service is not null)
            {
                StopServiceAndWait(service, TimeSpan.FromSeconds(20));
                if (!DeleteService(service))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != ErrorServiceMarkedForDelete)
                        throw new Win32Exception(error, $"DeleteService({ServiceProtocol.ServiceName}) failed.");
                }
            }
        }

        WaitForServiceDeletion(TimeSpan.FromSeconds(10));
        RemoveInstalledPayload();

        var status = GetStatus();
        if (status.Installed || status.Running || status.BinaryPresent)
            throw new InvalidOperationException($"Service removal verification failed: {status.Description}");

        return status;
    }

    public ServiceLifecycleStatus GetStatus()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new ServiceLifecycleStatus(
                false,
                false,
                File.Exists(ServiceBinaryPath),
                false,
                false,
                ServiceBinaryPath,
                "Windows is required");
        }

        var binaryPresent = File.Exists(ServiceBinaryPath);
        var protectedStorage = binaryPresent &&
                               IsProtectedPath(ProductDirectory) &&
                               IsProtectedPath(ServiceDirectory) &&
                               IsProtectedPath(ServiceBinaryPath);

        try
        {
            using var serviceManager = OpenServiceManager(ScManagerConnect);
            using var service = OpenServiceIfPresent(serviceManager, ServiceQueryConfig | ServiceQueryStatus);
            if (service is null)
            {
                return new ServiceLifecycleStatus(
                    false,
                    false,
                    binaryPresent,
                    false,
                    protectedStorage,
                    ServiceBinaryPath,
                    binaryPresent ? "service is not registered; protected binary remains" : "service is not installed");
            }

            var state = QueryServiceState(service);
            var configurationValid = ServicePathMatches(service, ServiceBinaryPath) &&
                                     QueryServiceConfiguration(service).StartType == ServiceAutoStart;
            var running = state == ServiceRunning;
            return new ServiceLifecycleStatus(
                true,
                running,
                binaryPresent,
                configurationValid,
                protectedStorage,
                ServiceBinaryPath,
                $"installed; state={FormatServiceState(state)}; path={(configurationValid ? "verified" : "unexpected")}; ACL={(protectedStorage ? "protected" : "unverified")}");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorAccessDenied)
        {
            return new ServiceLifecycleStatus(
                false,
                false,
                binaryPresent,
                false,
                protectedStorage,
                ServiceBinaryPath,
                "service status access denied");
        }
    }

    private static void EnsureSupportedAndElevated()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("GeniaFirewall.Service lifecycle requires Windows.");

        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Administrator privileges are required to manage GeniaFirewall.Service.");
    }

    private void EnsureSafeInstallPaths()
    {
        if (string.IsNullOrWhiteSpace(ProductDirectory) || string.IsNullOrWhiteSpace(ServiceDirectory))
            throw new InvalidOperationException("The Program Files path could not be resolved.");

        Directory.CreateDirectory(ProductDirectory);
        RejectReparsePoint(ProductDirectory);
        ApplyProtectedDacl(ProductDirectory, DirectorySddl);

        Directory.CreateDirectory(ServiceDirectory);
        RejectReparsePoint(ServiceDirectory);
        ApplyProtectedDacl(ServiceDirectory, DirectorySddl);
    }

    private static byte[] ReadEmbeddedServicePayload()
    {
        using var payloadStream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream(EmbeddedServiceResourceName)
            ?? throw new InvalidOperationException(
                "The embedded GeniaFirewall.Service payload is missing. Use the official single-EXE portable build.");

        if (payloadStream.Length <= 0 || payloadStream.Length > 256L * 1024 * 1024)
            throw new InvalidDataException($"The embedded service payload has an invalid size ({payloadStream.Length} bytes).");

        using var memory = new MemoryStream((int)payloadStream.Length);
        payloadStream.CopyTo(memory);
        var payload = memory.ToArray();
        if (payload.Length < 2 || payload[0] != (byte)'M' || payload[1] != (byte)'Z')
            throw new InvalidDataException("The embedded GeniaFirewall.Service payload is not a Windows PE image.");
        return payload;
    }

    private void WriteProtectedPayload(byte[] payload, byte[] expectedHash)
    {
        TryDeleteFile(StagedServiceBinaryPath);
        try
        {
            using (var stream = new FileStream(
                       StagedServiceBinaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       128 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(payload);
                stream.Flush(flushToDisk: true);
            }

            ProtectFile(StagedServiceBinaryPath);
            var stagedHash = ComputeFileHash(StagedServiceBinaryPath);
            if (!HashesEqual(expectedHash, stagedHash))
                throw new InvalidDataException("The staged GeniaFirewall.Service payload failed SHA-256 verification.");

            File.Move(StagedServiceBinaryPath, ServiceBinaryPath, overwrite: true);
            ProtectFile(ServiceBinaryPath);

            var installedHash = ComputeFileHash(ServiceBinaryPath);
            if (!HashesEqual(expectedHash, installedHash))
                throw new InvalidDataException("The installed GeniaFirewall.Service payload failed SHA-256 verification.");
        }
        finally
        {
            TryDeleteFile(StagedServiceBinaryPath);
        }
    }

    private static byte[] ComputeFileHash(string path)
    {
        RejectReparsePoint(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return SHA256.HashData(stream);
    }

    private static bool HashesEqual(byte[] expected, byte[] actual) =>
        expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);

    private SafeServiceHandle CreateConfiguredService(SafeServiceHandle serviceManager)
    {
        var dependencies = Marshal.StringToHGlobalUni("BFE\0\0");
        try
        {
            var service = CreateService(
                serviceManager,
                ServiceProtocol.ServiceName,
                ServiceProtocol.DisplayName,
                ServiceQueryConfig | ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop | Delete | WriteDac,
                ServiceWin32OwnProcess,
                ServiceAutoStart,
                ServiceErrorNormal,
                QuoteServiceBinaryPath(ServiceBinaryPath),
                null,
                IntPtr.Zero,
                dependencies,
                null,
                null);

            if (service.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateService({ServiceProtocol.ServiceName}) failed.");

            return service;
        }
        finally
        {
            Marshal.FreeHGlobal(dependencies);
        }
    }

    private void ConfigureExistingService(SafeServiceHandle service)
    {
        var dependencies = Marshal.StringToHGlobalUni("BFE\0\0");
        try
        {
            if (!ChangeServiceConfig(
                    service,
                    ServiceNoChange,
                    ServiceAutoStart,
                    ServiceNoChange,
                    QuoteServiceBinaryPath(ServiceBinaryPath),
                    null,
                    IntPtr.Zero,
                    dependencies,
                    null,
                    null,
                    ServiceProtocol.DisplayName))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"ChangeServiceConfig({ServiceProtocol.ServiceName}) failed.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(dependencies);
        }
    }

    private static void ConfigureDescription(SafeServiceHandle service)
    {
        var description = new ServiceDescriptionInfo { Description = ServiceDescription };
        if (!ChangeServiceConfig2Description(service, ServiceConfigDescription, ref description))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not configure the GeniaFirewall service description.");
    }

    private static void ConfigureFailureRecovery(SafeServiceHandle service)
    {
        var actionSize = Marshal.SizeOf<ScAction>();
        var actionsPointer = Marshal.AllocHGlobal(actionSize * 3);
        try
        {
            for (var index = 0; index < 3; index++)
            {
                var action = new ScAction { Type = ScActionRestart, Delay = 5000 };
                Marshal.StructureToPtr(action, IntPtr.Add(actionsPointer, index * actionSize), fDeleteOld: false);
            }

            var failureActions = new ServiceFailureActionsInfo
            {
                ResetPeriod = 60,
                RebootMessage = IntPtr.Zero,
                Command = IntPtr.Zero,
                ActionCount = 3,
                Actions = actionsPointer
            };

            if (!ChangeServiceConfig2FailureActions(service, ServiceConfigFailureActions, ref failureActions))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not configure GeniaFirewall service recovery.");
        }
        finally
        {
            Marshal.FreeHGlobal(actionsPointer);
        }
    }

    private static void ProtectServiceObject(SafeServiceHandle service)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                ServiceObjectSddl,
                SddlRevision1,
                out var securityDescriptor,
                out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create the GeniaFirewall service-object security descriptor.");
        }

        try
        {
            if (!SetServiceObjectSecurity(service, DaclSecurityInformation, securityDescriptor))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not protect the GeniaFirewall SCM service object.");
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    private static void StartServiceAndWait(SafeServiceHandle service, TimeSpan timeout)
    {
        var state = QueryServiceState(service);
        if (state == ServiceRunning)
            return;

        if (!StartService(service, 0, null))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorServiceAlreadyRunning)
                throw new Win32Exception(error, $"StartService({ServiceProtocol.ServiceName}) failed.");
        }

        WaitForState(service, ServiceRunning, timeout);
    }

    private static void StopServiceAndWait(SafeServiceHandle service, TimeSpan timeout)
    {
        var state = QueryServiceState(service);
        if (state == ServiceStopped)
            return;

        if (state != ServiceStopPending)
        {
            if (!ControlService(service, ServiceControlStop, out _))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != ErrorServiceNotActive)
                    throw new Win32Exception(error, $"ControlService(STOP, {ServiceProtocol.ServiceName}) failed.");
            }
        }

        WaitForState(service, ServiceStopped, timeout);
    }

    private static void WaitForState(SafeServiceHandle service, uint expectedState, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var status = QueryServiceStatus(service);
            if (status.CurrentState == expectedState)
                return;

            if (expectedState == ServiceRunning && status.CurrentState == ServiceStopped)
            {
                throw new InvalidOperationException(
                    $"{ServiceProtocol.ServiceName} stopped during startup (Win32ExitCode={status.Win32ExitCode}, ServiceExitCode={status.ServiceSpecificExitCode}).");
            }

            Thread.Sleep(100);
        }

        throw new TimeoutException(
            $"Timed out waiting for {ServiceProtocol.ServiceName} to reach {FormatServiceState(expectedState)}.");
    }

    private void WaitForServiceDeletion(TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            using var serviceManager = OpenServiceManager(ScManagerConnect);
            using var service = OpenServiceIfPresent(serviceManager, ServiceQueryStatus);
            if (service is null)
                return;
            Thread.Sleep(100);
        }

        throw new TimeoutException($"Timed out waiting for {ServiceProtocol.ServiceName} registration to be removed.");
    }

    private void RemoveInstalledPayload()
    {
        if (Directory.Exists(ServiceDirectory))
            RejectReparsePoint(ServiceDirectory);

        DeleteFileWithRetry(StagedServiceBinaryPath, TimeSpan.FromSeconds(5));
        DeleteFileWithRetry(ServiceBinaryPath, TimeSpan.FromSeconds(5));

        if (Directory.Exists(ServiceDirectory))
        {
            if (Directory.EnumerateFileSystemEntries(ServiceDirectory).Any())
                throw new IOException($"The protected service directory contains unexpected files and was not removed: {ServiceDirectory}");
            Directory.Delete(ServiceDirectory, recursive: false);
        }

        if (Directory.Exists(ProductDirectory))
        {
            RejectReparsePoint(ProductDirectory);
            if (!Directory.EnumerateFileSystemEntries(ProductDirectory).Any())
                Directory.Delete(ProductDirectory, recursive: false);
        }
    }

    private static void DeleteFileWithRetry(string path, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        Exception? lastError = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                if (!File.Exists(path))
                    return;
                RejectReparsePoint(path);
                File.Delete(path);
                if (!File.Exists(path))
                    return;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }

            Thread.Sleep(100);
        }

        throw new IOException($"Could not remove protected service file: {path}", lastError);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
        }
    }

    private static void ProtectFile(string path)
    {
        RejectReparsePoint(path);
        ApplyProtectedDacl(path, FileSddl);
    }

    private static void RejectReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"Refusing to use a reparse point for privileged service storage: {path}");
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
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not protect ACL for {path}.");
            }
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }

        if (!IsProtectedPath(path))
            throw new UnauthorizedAccessException($"ACL verification failed for privileged service path: {path}");
    }

    private static bool IsProtectedPath(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
            return false;

        try
        {
            RejectReparsePoint(path);
            var sddl = ReadDaclSddl(path);
            return sddl.Contains("D:P", StringComparison.Ordinal) &&
                   sddl.Contains(";;;SY)", StringComparison.Ordinal) &&
                   sddl.Contains(";;;BA)", StringComparison.Ordinal) &&
                   !sddl.Contains(";;;WD)", StringComparison.Ordinal) &&
                   !sddl.Contains(";;;AU)", StringComparison.Ordinal) &&
                   !sddl.Contains(";;;BU)", StringComparison.Ordinal) &&
                   !sddl.Contains(";;;IU)", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private static string ReadDaclSddl(string path)
    {
        _ = GetFileSecurity(path, DaclSecurityInformation, IntPtr.Zero, 0, out var requiredLength);
        var error = Marshal.GetLastWin32Error();
        if (requiredLength == 0 || error != ErrorInsufficientBuffer)
            throw new Win32Exception(error, $"Could not query ACL size for {path}.");

        var buffer = Marshal.AllocHGlobal((int)requiredLength);
        try
        {
            if (!GetFileSecurity(path, DaclSecurityInformation, buffer, requiredLength, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not read ACL for {path}.");

            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    buffer,
                    SddlRevision1,
                    DaclSecurityInformation,
                    out var sddlPointer,
                    out _))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not format ACL for {path}.");
            }

            try
            {
                return Marshal.PtrToStringUni(sddlPointer) ?? string.Empty;
            }
            finally
            {
                _ = LocalFree(sddlPointer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static SafeServiceHandle OpenServiceManager(uint desiredAccess)
    {
        var handle = OpenSCManager(null, null, desiredAccess);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenSCManager failed.");
        return handle;
    }

    private static SafeServiceHandle? OpenServiceIfPresent(SafeServiceHandle serviceManager, uint desiredAccess)
    {
        var handle = OpenService(serviceManager, ServiceProtocol.ServiceName, desiredAccess);
        if (!handle.IsInvalid)
            return handle;

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (error is ErrorServiceDoesNotExist or ErrorServiceMarkedForDelete)
            return null;
        throw new Win32Exception(error, $"OpenService({ServiceProtocol.ServiceName}) failed.");
    }

    private static ServiceConfiguration QueryServiceConfiguration(SafeServiceHandle service)
    {
        _ = QueryServiceConfig(service, IntPtr.Zero, 0, out var requiredLength);
        var error = Marshal.GetLastWin32Error();
        if (requiredLength == 0 || error != ErrorInsufficientBuffer)
            throw new Win32Exception(error, $"QueryServiceConfig({ServiceProtocol.ServiceName}) size query failed.");

        var buffer = Marshal.AllocHGlobal((int)requiredLength);
        try
        {
            if (!QueryServiceConfig(service, buffer, requiredLength, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"QueryServiceConfig({ServiceProtocol.ServiceName}) failed.");

            var native = Marshal.PtrToStructure<QueryServiceConfigInfo>(buffer);
            return new ServiceConfiguration(
                Marshal.PtrToStringUni(native.BinaryPathName) ?? string.Empty,
                native.StartType);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ServicePathMatches(SafeServiceHandle service, string expectedPath)
    {
        var configured = QueryServiceConfiguration(service).BinaryPath.Trim();
        if (configured.Length >= 2 && configured[0] == '\"' && configured[^1] == '\"')
            configured = configured[1..^1];

        try
        {
            return string.Equals(
                Path.GetFullPath(configured),
                Path.GetFullPath(expectedPath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static ServiceStatusProcess QueryServiceStatus(SafeServiceHandle service)
    {
        var size = (uint)Marshal.SizeOf<ServiceStatusProcess>();
        if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out var status, size, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"QueryServiceStatusEx({ServiceProtocol.ServiceName}) failed.");
        return status;
    }

    private static uint QueryServiceState(SafeServiceHandle service) => QueryServiceStatus(service).CurrentState;

    private static string QuoteServiceBinaryPath(string path) => $"\"{path}\"";

    private static string FormatServiceState(uint state) => state switch
    {
        ServiceStopped => "stopped",
        ServiceStartPending => "start-pending",
        ServiceStopPending => "stop-pending",
        ServiceRunning => "running",
        _ => $"state-{state}"
    };

    private sealed record ServiceConfiguration(string BinaryPath, uint StartType);

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle() : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigInfo
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceDescriptionInfo
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction
    {
        public uint Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceFailureActionsInfo
    {
        public uint ResetPeriod;
        public IntPtr RebootMessage;
        public IntPtr Command;
        public uint ActionCount;
        public IntPtr Actions;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenService(SafeServiceHandle serviceManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "CreateServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle CreateService(
        SafeServiceHandle serviceManager,
        string serviceName,
        string displayName,
        uint desiredAccess,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPathName,
        string? loadOrderGroup,
        IntPtr tagId,
        IntPtr dependencies,
        string? serviceStartName,
        string? password);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig(
        SafeServiceHandle service,
        uint serviceType,
        uint startType,
        uint errorControl,
        string binaryPathName,
        string? loadOrderGroup,
        IntPtr tagId,
        IntPtr dependencies,
        string? serviceStartName,
        string? password,
        string displayName);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2Description(
        SafeServiceHandle service,
        int infoLevel,
        ref ServiceDescriptionInfo info);

    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfig2FailureActions(
        SafeServiceHandle service,
        int infoLevel,
        ref ServiceFailureActionsInfo info);

    [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfig(
        SafeServiceHandle service,
        IntPtr queryServiceConfig,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(
        SafeServiceHandle service,
        int infoLevel,
        out ServiceStatusProcess status,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", EntryPoint = "StartServiceW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartService(SafeServiceHandle service, uint argumentCount, string[]? arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(SafeServiceHandle service, uint control, out ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(SafeServiceHandle service);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceObjectSecurity(
        SafeServiceHandle service,
        uint securityInformation,
        IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr serviceHandle);

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

    [DllImport("advapi32.dll", EntryPoint = "GetFileSecurityW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileSecurity(
        string fileName,
        uint requestedInformation,
        IntPtr securityDescriptor,
        uint length,
        out uint lengthNeeded);

    [DllImport("advapi32.dll", EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
        IntPtr securityDescriptor,
        uint requestedStringSdRevision,
        uint securityInformation,
        out IntPtr stringSecurityDescriptor,
        out uint stringSecurityDescriptorLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
