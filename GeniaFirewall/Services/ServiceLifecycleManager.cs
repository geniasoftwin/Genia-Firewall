using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Services;

public sealed record ServiceLifecycleStatus(
    bool Installed,
    bool Running,
    bool BinaryPresent,
    bool PayloadVerified,
    bool ConfigurationValid,
    bool StorageProtected,
    bool ServiceObjectProtected,
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
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const int FileAllAccess = 0x001f01ff;
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const int ServiceAllAccess = 0x000f01ff;
    private const int GenericAll = 0x10000000;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceErrorNormal = 0x00000001;
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
    private static readonly Lazy<byte[]> EmbeddedServiceHash = new(
        ComputeEmbeddedServiceHash,
        LazyThreadSafetyMode.ExecutionAndPublication);

    public ServiceLifecycleManager()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles))
            programFiles = Environment.GetEnvironmentVariable("ProgramFiles") ?? string.Empty;

        ProductDirectory = Path.Combine(programFiles, "GeniaFirewall");
        ServiceDirectory = Path.Combine(ProductDirectory, "Service");
        ServiceBinaryPath = Path.Combine(ServiceDirectory, ServiceFileName);
        StagedServiceBinaryPath = ServiceBinaryPath + ".new";
        RollbackServiceBinaryPath = ServiceBinaryPath + ".previous";

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (string.IsNullOrWhiteSpace(programData))
        {
            ServiceStateProductDirectory = string.Empty;
            ServiceStateDirectory = string.Empty;
            ServicePolicyPath = string.Empty;
            StagedServicePolicyPath = string.Empty;
        }
        else
        {
            ServiceStateProductDirectory = Path.Combine(programData, "GeniaFirewall");
            ServiceStateDirectory = Path.Combine(ServiceStateProductDirectory, "Service");
            ServicePolicyPath = Path.Combine(ServiceStateDirectory, "wfp-policy.json");
            StagedServicePolicyPath = ServicePolicyPath + ".tmp";
        }
    }

    public string ProductDirectory { get; }
    public string ServiceDirectory { get; }
    public string ServiceBinaryPath { get; }
    private string StagedServiceBinaryPath { get; }
    private string RollbackServiceBinaryPath { get; }
    private string ServiceStateProductDirectory { get; }
    private string ServiceStateDirectory { get; }
    private string ServicePolicyPath { get; }
    private string StagedServicePolicyPath { get; }

    public ServiceLifecycleStatus EnsureInstalledAndRunning(bool startWithDisabledPolicy = false)
    {
        EnsureSupportedAndElevated();
        EnsureSafeInstallPaths();
        if (startWithDisabledPolicy)
            RemovePersistedServicePolicyBeforeStart();

        var payload = ReadEmbeddedServicePayload();
        var payloadHash = SHA256.HashData(payload);

        using var serviceManager = OpenServiceManager(ScManagerConnect | ScManagerCreateService);
        using var existingService = OpenServiceIfPresent(
            serviceManager,
            ServiceQueryConfig | ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop |
            Delete | ReadControl | WriteDac);

        var serviceExists = existingService is not null;
        var installedPayloadMatches = File.Exists(ServiceBinaryPath) &&
                                      HashesEqual(payloadHash, ComputeFileHash(ServiceBinaryPath));
        var configuredPathMatches = serviceExists && ServicePathMatches(existingService!, ServiceBinaryPath);

        if (serviceExists && (!installedPayloadMatches || !configuredPathMatches))
            StopServiceAndWait(existingService!, TimeSpan.FromSeconds(20));

        var payloadUpdate = PreparePayloadUpdate(payload, payloadHash, installedPayloadMatches);

        SafeServiceHandle? createdService = null;
        SafeServiceHandle? service = existingService;
        try
        {
            service ??= createdService = CreateConfiguredService(serviceManager);
            if (existingService is not null)
                ConfigureExistingService(existingService);

            ConfigureDescription(service);
            ConfigureFailureRecovery(service);
            ProtectServiceObject(service);
            StartServiceAndWait(service, TimeSpan.FromSeconds(20));
            WaitForCompatibleServiceIpc(TimeSpan.FromSeconds(8), requireCurrentProductVersion: true);
            if (startWithDisabledPolicy)
                ClearServicePolicyAndVerify();

            var status = GetStatus();
            if (!status.Installed || !status.Running || !status.BinaryPresent ||
                !status.PayloadVerified || !status.ConfigurationValid || !status.StorageProtected ||
                !status.ServiceObjectProtected)
            {
                throw new InvalidOperationException($"Service installation verification failed: {status.Description}");
            }

            CommitPayloadUpdate(payloadUpdate);
            return status;
        }
        catch (Exception updateError) when (payloadUpdate.PreviousHash is not null)
        {
            try
            {
                RollBackPayloadUpdate(service, payloadUpdate);
            }
            catch (Exception rollbackError)
            {
                throw new AggregateException(
                    "The service update failed and the previous protected payload could not be restored.",
                    updateError,
                    rollbackError);
            }

            throw new InvalidOperationException(
                "The service update failed; the previous protected service was restored and restarted.",
                updateError);
        }
        finally
        {
            createdService?.Dispose();
        }
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
                false,
                false,
                ServiceBinaryPath,
                "Windows is required");
        }

        var binaryPresent = File.Exists(ServiceBinaryPath);
        var payloadVerified = binaryPresent && IsEmbeddedPayload(ServiceBinaryPath);
        var protectedStorage = binaryPresent &&
                               IsProtectedPath(ProductDirectory) &&
                               IsProtectedPath(ServiceDirectory) &&
                               IsProtectedPath(ServiceBinaryPath);

        try
        {
            using var serviceManager = OpenServiceManager(ScManagerConnect);
            using var service = OpenServiceIfPresent(
                serviceManager,
                ServiceQueryConfig | ServiceQueryStatus | ReadControl);
            if (service is null)
            {
                return new ServiceLifecycleStatus(
                    false,
                    false,
                    binaryPresent,
                    payloadVerified,
                    false,
                    protectedStorage,
                    false,
                    ServiceBinaryPath,
                    binaryPresent ? "service is not registered; protected binary remains" : "service is not installed");
            }

            var state = QueryServiceState(service);
            var configurationValid = ServiceConfigurationMatches(
                QueryServiceConfiguration(service),
                ServiceBinaryPath);
            var serviceObjectProtected = IsProtectedServiceObject(service);
            var running = state == ServiceRunning;
            return new ServiceLifecycleStatus(
                true,
                running,
                binaryPresent,
                payloadVerified,
                configurationValid,
                protectedStorage,
                serviceObjectProtected,
                ServiceBinaryPath,
                $"installed; state={FormatServiceState(state)}; payload={(payloadVerified ? "verified" : "unexpected")}; " +
                $"SCM config={(configurationValid ? "verified" : "unexpected")}; " +
                $"file ACL={(protectedStorage ? "protected" : "unverified")}; " +
                $"service ACL={(serviceObjectProtected ? "protected" : "unverified")}");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorAccessDenied)
        {
            return new ServiceLifecycleStatus(
                false,
                false,
                binaryPresent,
                payloadVerified,
                false,
                protectedStorage,
                false,
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

    private void RemovePersistedServicePolicyBeforeStart()
    {
        if (string.IsNullOrWhiteSpace(ServiceStateProductDirectory) ||
            string.IsNullOrWhiteSpace(ServiceStateDirectory))
        {
            throw new InvalidOperationException("The ProgramData path could not be resolved.");
        }

        if (!Directory.Exists(ServiceStateProductDirectory))
            return;

        RejectReparsePoint(ServiceStateProductDirectory);
        ApplyProtectedDacl(ServiceStateProductDirectory, DirectorySddl);

        if (!Directory.Exists(ServiceStateDirectory))
            return;

        RejectReparsePoint(ServiceStateDirectory);
        ApplyProtectedDacl(ServiceStateDirectory, DirectorySddl);
        DeleteFileWithRetry(StagedServicePolicyPath, TimeSpan.FromSeconds(5));
        DeleteFileWithRetry(ServicePolicyPath, TimeSpan.FromSeconds(5));
    }

    private static void ClearServicePolicyAndVerify()
    {
        var clear = new GeniaFirewallServiceClient().ClearWfpPolicy();
        if (!clear.Success || clear.Status is null)
        {
            throw new InvalidOperationException(
                $"GeniaFirewall.Service did not confirm disabled startup policy: {clear.Description}");
        }

        var status = clear.Status;
        if (status.WfpBackendActive || status.WfpEngineOpen || status.ProviderRegistered ||
            status.SubLayerRegistered || status.ActiveFilterCount != 0 ||
            !status.RuntimeFilterCleanupVerified || status.ResidualRuntimeFilterCount != 0)
        {
            throw new InvalidOperationException(
                "GeniaFirewall.Service disabled-policy verification failed: " +
                $"backendActive={status.WfpBackendActive}; engineOpen={status.WfpEngineOpen}; " +
                $"provider={status.ProviderRegistered}; sublayer={status.SubLayerRegistered}; " +
                $"filters={status.ActiveFilterCount}; cleanupVerified={status.RuntimeFilterCleanupVerified}; " +
                $"residual={status.ResidualRuntimeFilterCount}.");
        }
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

    private PayloadUpdateTransaction PreparePayloadUpdate(
        byte[] payload,
        byte[] expectedHash,
        bool installedPayloadMatches)
    {
        TryDeleteFile(StagedServiceBinaryPath);

        if (installedPayloadMatches)
        {
            ProtectFile(ServiceBinaryPath);
            return new PayloadUpdateTransaction(ReadProtectedRollbackHashIfPresent());
        }

        byte[]? previousHash;
        if (File.Exists(ServiceBinaryPath))
        {
            ProtectFile(ServiceBinaryPath);
            previousHash = ComputeFileHash(ServiceBinaryPath);
            DeleteFileWithRetry(RollbackServiceBinaryPath, TimeSpan.FromSeconds(5));
        }
        else
        {
            previousHash = ReadProtectedRollbackHashIfPresent();
        }

        var targetReplaced = false;
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

            if (File.Exists(ServiceBinaryPath))
            {
                File.Replace(
                    StagedServiceBinaryPath,
                    ServiceBinaryPath,
                    RollbackServiceBinaryPath,
                    ignoreMetadataErrors: false);
            }
            else
            {
                File.Move(StagedServiceBinaryPath, ServiceBinaryPath);
            }

            targetReplaced = true;
            ProtectFile(ServiceBinaryPath);

            var installedHash = ComputeFileHash(ServiceBinaryPath);
            if (!HashesEqual(expectedHash, installedHash))
                throw new InvalidDataException("The installed GeniaFirewall.Service payload failed SHA-256 verification.");

            if (previousHash is not null)
            {
                if (!File.Exists(RollbackServiceBinaryPath))
                    throw new IOException("The previous protected service payload was not retained for rollback.");

                ProtectFile(RollbackServiceBinaryPath);
                var retainedHash = ComputeFileHash(RollbackServiceBinaryPath);
                if (!HashesEqual(previousHash, retainedHash))
                    throw new InvalidDataException("The retained rollback service payload failed SHA-256 verification.");
            }

            return new PayloadUpdateTransaction(previousHash);
        }
        catch
        {
            if (targetReplaced)
            {
                if (previousHash is not null)
                    RestorePreviousPayloadFile(previousHash);
                else
                    DeleteFileWithRetry(ServiceBinaryPath, TimeSpan.FromSeconds(5));
            }

            throw;
        }
        finally
        {
            TryDeleteFile(StagedServiceBinaryPath);
        }
    }

    private byte[]? ReadProtectedRollbackHashIfPresent()
    {
        if (!File.Exists(RollbackServiceBinaryPath))
            return null;

        ProtectFile(RollbackServiceBinaryPath);
        return ComputeFileHash(RollbackServiceBinaryPath);
    }

    private void CommitPayloadUpdate(PayloadUpdateTransaction transaction)
    {
        if (transaction.PreviousHash is not null || File.Exists(RollbackServiceBinaryPath))
            DeleteFileWithRetry(RollbackServiceBinaryPath, TimeSpan.FromSeconds(5));
    }

    private void RollBackPayloadUpdate(
        SafeServiceHandle? service,
        PayloadUpdateTransaction transaction)
    {
        var previousHash = transaction.PreviousHash
            ?? throw new InvalidOperationException("No protected rollback payload is available.");

        if (service is not null)
            StopServiceAndWait(service, TimeSpan.FromSeconds(20));

        RestorePreviousPayloadFile(previousHash);

        if (service is null)
            return;

        ConfigureExistingService(service);
        ConfigureDescription(service);
        ConfigureFailureRecovery(service);
        ProtectServiceObject(service);
        StartServiceAndWait(service, TimeSpan.FromSeconds(20));
        WaitForCompatibleServiceIpc(TimeSpan.FromSeconds(8), requireCurrentProductVersion: false);

        var status = GetStatus();
        if (!status.Installed || !status.Running || !status.BinaryPresent ||
            !status.ConfigurationValid || !status.StorageProtected || !status.ServiceObjectProtected)
        {
            throw new InvalidOperationException($"Restored service verification failed: {status.Description}");
        }
    }

    private void RestorePreviousPayloadFile(byte[] expectedHash)
    {
        if (!File.Exists(RollbackServiceBinaryPath))
            throw new FileNotFoundException(
                "The protected rollback service payload is missing.",
                RollbackServiceBinaryPath);

        ProtectFile(RollbackServiceBinaryPath);
        if (!HashesEqual(expectedHash, ComputeFileHash(RollbackServiceBinaryPath)))
            throw new InvalidDataException("The rollback service payload failed SHA-256 verification before restore.");

        if (File.Exists(ServiceBinaryPath))
        {
            File.Replace(
                RollbackServiceBinaryPath,
                ServiceBinaryPath,
                destinationBackupFileName: null,
                ignoreMetadataErrors: false);
        }
        else
        {
            File.Move(RollbackServiceBinaryPath, ServiceBinaryPath);
        }

        ProtectFile(ServiceBinaryPath);
        if (!HashesEqual(expectedHash, ComputeFileHash(ServiceBinaryPath)))
            throw new InvalidDataException("The restored service payload failed SHA-256 verification.");
    }

    private static byte[] ComputeEmbeddedServiceHash()
    {
        using var payloadStream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream(EmbeddedServiceResourceName)
            ?? throw new InvalidOperationException(
                "The embedded GeniaFirewall.Service payload is missing. Use the official single-EXE portable build.");
        return SHA256.HashData(payloadStream);
    }

    private static bool IsEmbeddedPayload(string path)
    {
        try
        {
            return HashesEqual(EmbeddedServiceHash.Value, ComputeFileHash(path));
        }
        catch
        {
            return false;
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
                ServiceQueryConfig | ServiceChangeConfig | ServiceQueryStatus | ServiceStart | ServiceStop |
                Delete | ReadControl | WriteDac,
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
                    ServiceWin32OwnProcess,
                    ServiceAutoStart,
                    ServiceErrorNormal,
                    QuoteServiceBinaryPath(ServiceBinaryPath),
                    null,
                    IntPtr.Zero,
                    dependencies,
                    "LocalSystem",
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

        if (!IsProtectedServiceObject(service))
            throw new UnauthorizedAccessException("SCM service-object ACL verification failed.");
    }

    private static bool IsProtectedServiceObject(SafeServiceHandle service)
    {
        try
        {
            return ServiceDaclMatchesExactly(ReadServiceDaclSddl(service));
        }
        catch
        {
            return false;
        }
    }

    private static bool ServiceDaclMatchesExactly(string actualSddl)
    {
        var descriptor = new RawSecurityDescriptor(actualSddl);
        var dacl = descriptor.DiscretionaryAcl;
        if (dacl is null || dacl.Count != 2)
            return false;

        var expectedSids = new HashSet<string>(StringComparer.Ordinal)
        {
            "S-1-5-18",
            "S-1-5-32-544"
        };

        foreach (GenericAce genericAce in dacl)
        {
            if (genericAce is not CommonAce ace ||
                ace.AceQualifier != AceQualifier.AccessAllowed ||
                ace.AceFlags != AceFlags.None ||
                (ace.AccessMask != GenericAll && ace.AccessMask != ServiceAllAccess) ||
                !expectedSids.Remove(ace.SecurityIdentifier.Value))
            {
                return false;
            }
        }

        return expectedSids.Count == 0;
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

    private static void WaitForCompatibleServiceIpc(
        TimeSpan timeout,
        bool requireCurrentProductVersion)
    {
        var deadline = DateTime.UtcNow + timeout;
        var client = new GeniaFirewallServiceClient();
        var lastDescription = "no IPC response";

        while (DateTime.UtcNow < deadline)
        {
            var probe = client.Probe(500);
            lastDescription = probe.Description;
            if (probe.Reachable && probe.Status is { } status)
            {
                var serviceNameMatches = string.Equals(
                    status.ServiceName,
                    ServiceProtocol.ServiceName,
                    StringComparison.Ordinal);
                var protocolMatches = string.Equals(
                    status.ProtocolVersion,
                    ServiceProtocol.ProtocolVersion,
                    StringComparison.Ordinal);
                var productMatches = string.Equals(
                    status.ProductVersion,
                    ServiceProtocol.ProductVersion,
                    StringComparison.Ordinal);

                if (status.Running && serviceNameMatches && protocolMatches &&
                    (!requireCurrentProductVersion || productMatches))
                {
                    return;
                }

                lastDescription =
                    $"identity mismatch: service={status.ServiceName}; protocol={status.ProtocolVersion}; " +
                    $"product={status.ProductVersion}; running={status.Running}";
            }

            Thread.Sleep(100);
        }

        throw new TimeoutException($"GeniaFirewall.Service IPC verification timed out: {lastDescription}");
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
        DeleteFileWithRetry(RollbackServiceBinaryPath, TimeSpan.FromSeconds(5));

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
            return FileDaclMatchesExactly(ReadDaclSddl(path), Directory.Exists(path));
        }
        catch
        {
            return false;
        }
    }

    private static bool FileDaclMatchesExactly(string actualSddl, bool directory)
    {
        var actual = new RawSecurityDescriptor(actualSddl);
        var dacl = actual.DiscretionaryAcl;
        if (dacl is null || dacl.Count != 2 ||
            (actual.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
        {
            return false;
        }

        var expectedFlags = directory
            ? AceFlags.ContainerInherit | AceFlags.ObjectInherit
            : AceFlags.None;
        var expectedSids = new HashSet<string>(StringComparer.Ordinal)
        {
            "S-1-5-18",
            "S-1-5-32-544"
        };

        foreach (GenericAce genericAce in dacl)
        {
            if (genericAce is not CommonAce ace ||
                ace.AceQualifier != AceQualifier.AccessAllowed ||
                ace.AceFlags != expectedFlags ||
                ace.AccessMask != FileAllAccess ||
                !expectedSids.Remove(ace.SecurityIdentifier.Value))
            {
                return false;
            }
        }

        return expectedSids.Count == 0;
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

    private static string ReadServiceDaclSddl(SafeServiceHandle service)
    {
        _ = QueryServiceObjectSecurity(
            service,
            DaclSecurityInformation,
            IntPtr.Zero,
            0,
            out var requiredLength);
        var error = Marshal.GetLastWin32Error();
        if (requiredLength == 0 || error != ErrorInsufficientBuffer)
            throw new Win32Exception(error, "Could not query the SCM service-object ACL size.");

        var buffer = Marshal.AllocHGlobal((int)requiredLength);
        try
        {
            if (!QueryServiceObjectSecurity(
                    service,
                    DaclSecurityInformation,
                    buffer,
                    requiredLength,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not read the SCM service-object ACL.");
            }

            if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    buffer,
                    SddlRevision1,
                    DaclSecurityInformation,
                    out var sddlPointer,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Could not format the SCM service-object ACL.");
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
                native.ServiceType,
                native.StartType,
                native.ErrorControl,
                Marshal.PtrToStringUni(native.BinaryPathName) ?? string.Empty,
                ReadMultiString(native.Dependencies),
                Marshal.PtrToStringUni(native.ServiceStartName) ?? string.Empty,
                Marshal.PtrToStringUni(native.DisplayName) ?? string.Empty);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool ServicePathMatches(SafeServiceHandle service, string expectedPath)
    {
        var configured = QueryServiceConfiguration(service).BinaryPath.Trim();
        return string.Equals(
            configured,
            QuoteServiceBinaryPath(Path.GetFullPath(expectedPath)),
            StringComparison.OrdinalIgnoreCase);
    }

    private static bool ServiceConfigurationMatches(
        ServiceConfiguration configuration,
        string expectedPath)
    {
        if (configuration.ServiceType != ServiceWin32OwnProcess ||
            configuration.StartType != ServiceAutoStart ||
            configuration.ErrorControl != ServiceErrorNormal ||
            !string.Equals(configuration.StartName, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(configuration.DisplayName, ServiceProtocol.DisplayName, StringComparison.Ordinal) ||
            configuration.Dependencies.Count != 1 ||
            !string.Equals(configuration.Dependencies[0], "BFE", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            return string.Equals(
                configuration.BinaryPath.Trim(),
                QuoteServiceBinaryPath(Path.GetFullPath(expectedPath)),
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static IReadOnlyList<string> ReadMultiString(IntPtr pointer)
    {
        if (pointer == IntPtr.Zero)
            return Array.Empty<string>();

        const int maxCharacters = 32 * 1024;
        var values = new List<string>();
        var offset = 0;
        while (offset < maxCharacters)
        {
            var length = 0;
            while (offset + length < maxCharacters &&
                   Marshal.ReadInt16(pointer, (offset + length) * sizeof(char)) != 0)
            {
                length++;
            }

            if (offset + length >= maxCharacters)
                throw new InvalidDataException("SCM dependency MULTI_SZ is not terminated.");
            if (length == 0)
                return values;

            values.Add(Marshal.PtrToStringUni(
                IntPtr.Add(pointer, offset * sizeof(char)),
                length) ?? string.Empty);
            offset += length + 1;
        }

        throw new InvalidDataException("SCM dependency MULTI_SZ exceeds the supported size.");
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

    private sealed record PayloadUpdateTransaction(byte[]? PreviousHash);

    private sealed record ServiceConfiguration(
        uint ServiceType,
        uint StartType,
        uint ErrorControl,
        string BinaryPath,
        IReadOnlyList<string> Dependencies,
        string StartName,
        string DisplayName);

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
    private static extern bool QueryServiceObjectSecurity(
        SafeServiceHandle service,
        uint securityInformation,
        IntPtr securityDescriptor,
        uint bufferSize,
        out uint bytesNeeded);

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
