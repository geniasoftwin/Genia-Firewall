using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

/// <summary>
/// Local IPC endpoint. Redacted status is readable without mutation privileges. Full diagnostics
/// and policy-changing commands require LocalSystem or local Administrators membership.
/// </summary>
internal sealed class NamedPipeControlServer
{
    private static readonly TimeSpan RequestReadTimeout = TimeSpan.FromSeconds(5);
    private readonly Func<ServiceStatusSnapshot> _snapshotProvider;
    private readonly Action<WfpPolicySnapshot> _applyPolicy;
    private readonly Action<Guid> _removeApplication;
    private readonly Action _clearPolicy;
    private readonly Func<long, int, IReadOnlyList<WfpNetEventSnapshot>> _readNetEvents;
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNameCaseInsensitive = true };

    public NamedPipeControlServer(
        Func<ServiceStatusSnapshot> snapshotProvider,
        Action<WfpPolicySnapshot> applyPolicy,
        Action<Guid> removeApplication,
        Action clearPolicy,
        Func<long, int, IReadOnlyList<WfpNetEventSnapshot>> readNetEvents)
    {
        _snapshotProvider = snapshotProvider;
        _applyPolicy = applyPolicy;
        _removeApplication = removeApplication;
        _clearPolicy = clearPolicy;
        _readNetEvents = readNetEvents;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await ServeOneClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                ServiceLog.WriteException("Named pipe server error", ex);
                try { await Task.Delay(250, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task ServeOneClientAsync(CancellationToken cancellationToken)
    {
        await using var pipe = new NamedPipeServerStream(
            ServiceProtocol.PipeName,
            PipeDirection.InOut,
            8,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough);

        await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

        using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };

        using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        requestTimeout.CancelAfter(RequestReadTimeout);

        string? requestLine;
        try
        {
            requestLine = await ReadLineLimitedAsync(
                    reader,
                    ServiceProtocol.MaxRequestCharacters,
                    requestTimeout.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            ServiceLog.Write("Named pipe client request timed out before a complete command was received.");
            return;
        }

        if (requestLine is null)
            return;

        var response = HandleRequest(pipe, requestLine);
        var json = JsonSerializer.Serialize(response, _jsonOptions);
        await writer.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
    }

    private ServiceCommandResponse HandleRequest(NamedPipeServerStream pipe, string requestLine)
    {
        var privilegedClient = IsMutationClientAuthorized(pipe);

        if (requestLine.Equals("ping", StringComparison.OrdinalIgnoreCase) ||
            requestLine.Equals("status", StringComparison.OrdinalIgnoreCase))
        {
            var status = _snapshotProvider();
            if (!privilegedClient)
                status = RedactUnprivilegedStatus(status);

            return new ServiceCommandResponse { Success = true, Message = "status", Status = status };
        }

        ServiceCommandRequest? request;
        try { request = JsonSerializer.Deserialize<ServiceCommandRequest>(requestLine, _jsonOptions); }
        catch (JsonException ex) { return FailureForClient($"invalid-json: {ex.Message}", privilegedClient); }

        if (request is null || string.IsNullOrWhiteSpace(request.Command))
            return FailureForClient("invalid-request", privilegedClient);

        var command = request.Command.Trim().ToLowerInvariant();

        // Telemetry includes executable paths and endpoints, so keep it behind the same
        // local Administrator/LocalSystem boundary as policy mutation for now.
        if (!privilegedClient)
        {
            ServiceLog.Write($"Rejected unauthorized IPC command: {request.Command}.");
            return FailureForClient("access-denied", privilegedClient: false);
        }

        try
        {
            switch (command)
            {
                case "get-net-events":
                {
                    var maxEvents = Math.Clamp(request.MaxEvents, 1, ServiceProtocol.MaxTelemetryEventsPerResponse);
                    return new ServiceCommandResponse
                    {
                        Success = true,
                        Message = "net-events",
                        Status = _snapshotProvider(),
                        NetEvents = _readNetEvents(request.AfterEventSequence, maxEvents).ToList()
                    };
                }

                case "apply-wfp-policy":
                    if (request.Policy is null)
                        return Failure("policy-required");
                    _applyPolicy(request.Policy);
                    return Success("WFP policy committed and persisted.");

                case "remove-wfp-application":
                    _removeApplication(request.ApplicationId);
                    return Success("WFP application rule removed.");

                case "clear-wfp-policy":
                    _clearPolicy();
                    return Success("WFP policy cleared and persisted as inactive.");

                default:
                    return Failure("unsupported-command");
            }
        }
        catch (Exception ex)
        {
            ServiceLog.WriteException($"IPC command '{request.Command}' failed", ex);
            return Failure(ex.Message);
        }
    }

    private ServiceCommandResponse Success(string message) => new() { Success = true, Message = message, Status = _snapshotProvider() };
    private ServiceCommandResponse Failure(string message) => new() { Success = false, Message = message, Status = _snapshotProvider() };

    private ServiceCommandResponse FailureForClient(string message, bool privilegedClient)
    {
        var status = _snapshotProvider();
        if (!privilegedClient)
            status = RedactUnprivilegedStatus(status);

        return new ServiceCommandResponse { Success = false, Message = message, Status = status };
    }

    private static ServiceStatusSnapshot RedactUnprivilegedStatus(ServiceStatusSnapshot status) => status with
    {
        PhysicalInterfaceSummary = string.Empty,
        VirtualTunInterfaceSummary = string.Empty,
        LastBlockedEventSummary = string.Empty,
        NetEventTelemetryLastError = string.Empty,
        LastError = string.Empty
    };

    private static bool IsMutationClientAuthorized(NamedPipeServerStream pipe)
    {
        try
        {
            var authorized = false;
            pipe.RunAsClient(() =>
            {
                using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                if (identity.IsSystem)
                {
                    authorized = true;
                    return;
                }

                var principal = new WindowsPrincipal(identity);
                authorized = principal.IsInRole(WindowsBuiltInRole.Administrator);
            });
            return authorized;
        }
        catch (Exception ex)
        {
            ServiceLog.WriteException("Could not verify IPC client token", ex);
            return false;
        }
    }

    private static async Task<string?> ReadLineLimitedAsync(StreamReader reader, int maxCharacters, CancellationToken cancellationToken)
    {
        var buffer = new char[4096];
        var builder = new StringBuilder();
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return builder.Length == 0 ? null : builder.ToString().TrimEnd('\r');

            for (var i = 0; i < read; i++)
            {
                var ch = buffer[i];
                if (ch == '\n')
                    return builder.ToString().TrimEnd('\r');
                builder.Append(ch);
                if (builder.Length > maxCharacters)
                    throw new InvalidDataException($"IPC request exceeds {maxCharacters} characters.");
            }
        }
    }
}
