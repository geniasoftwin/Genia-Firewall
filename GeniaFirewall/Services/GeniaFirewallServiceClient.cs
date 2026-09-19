using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using GeniaFirewall.Models;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Services;

public sealed class GeniaFirewallServiceClient
{
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public readonly record struct ServiceProbeResult(
        bool Reachable,
        ServiceStatusSnapshot? Status,
        string Description);

    public readonly record struct ServiceCommandResult(
        bool Success,
        ServiceStatusSnapshot? Status,
        string Description);

    public readonly record struct NetEventReadResult(
        bool Success,
        ServiceStatusSnapshot? Status,
        IReadOnlyList<WfpNetEventSnapshot> Events,
        string Description);

    public ServiceProbeResult Probe(int timeoutMilliseconds = 450)
    {
        var result = SendRaw("status", timeoutMilliseconds);
        if (!result.TransportSuccess)
            return new(false, null, result.Description);

        if (result.Response?.Status is not { } status)
            return new(false, null, "IPC response does not contain service status");

        if (!string.Equals(status.ProtocolVersion, ServiceProtocol.ProtocolVersion, StringComparison.Ordinal))
        {
            return new(
                true,
                status,
                $"IPC OK, protocol mismatch: UI={ServiceProtocol.ProtocolVersion}, Service={status.ProtocolVersion}");
        }

        return new(true, status, "IPC OK");
    }

    public ServiceCommandResult ApplyWfpPolicy(
        IEnumerable<ManagedApplication> applications,
        bool protectionEnabled,
        FirewallMode mode,
        int timeoutMilliseconds = 5000)
    {
        var rules = applications
            .Where(app => app.Access is FirewallAccess.Allow or FirewallAccess.Block or FirewallAccess.Ask)
            .Take(ServiceProtocol.MaxPolicyApplications + 1)
            .Select(app => new WfpApplicationRule
            {
                ApplicationId = app.Id,
                ExePath = app.ExePath,
                DisplayName = app.Name,
                Access = app.Access switch
                {
                    FirewallAccess.Allow => WfpRuleAccess.Allow,
                    FirewallAccess.Block => WfpRuleAccess.Block,
                    _ => WfpRuleAccess.Ask
                },
                Profile = app.RuleProfile switch
                {
                    ApplicationRuleProfile.EnableAll => WfpRuleProfile.EnableAll,
                    ApplicationRuleProfile.OutgoingOnly => WfpRuleProfile.OutgoingOnly,
                    ApplicationRuleProfile.IncomingOnly => WfpRuleProfile.IncomingOnly,
                    ApplicationRuleProfile.DisableAll => WfpRuleProfile.DisableAll,
                    ApplicationRuleProfile.Ask => WfpRuleProfile.Ask,
                    _ => WfpRuleProfile.Default
                }
            })
            .ToList();

        if (rules.Count > ServiceProtocol.MaxPolicyApplications)
        {
            return new(
                false,
                null,
                $"Too many applications for WFP backend (max {ServiceProtocol.MaxPolicyApplications}).");
        }

        var request = new ServiceCommandRequest
        {
            Command = "apply-wfp-policy",
            Policy = new WfpPolicySnapshot
            {
                BackendActive = true,
                ProtectionEnabled = protectionEnabled,
                Mode = mode switch
                {
                    FirewallMode.BlockAll => WfpPolicyMode.BlockAll,
                    FirewallMode.AllowAll => WfpPolicyMode.AllowAll,
                    FirewallMode.Monitor => WfpPolicyMode.Monitor,
                    _ => WfpPolicyMode.Normal
                },
                Applications = rules
            }
        };

        return SendCommand(request, timeoutMilliseconds);
    }

    public ServiceCommandResult RemoveWfpApplication(Guid applicationId, int timeoutMilliseconds = 5000)
    {
        var request = new ServiceCommandRequest
        {
            Command = "remove-wfp-application",
            ApplicationId = applicationId
        };
        return SendCommand(request, timeoutMilliseconds);
    }

    public ServiceCommandResult ClearWfpPolicy(int timeoutMilliseconds = 5000)
    {
        return SendCommand(new ServiceCommandRequest { Command = "clear-wfp-policy" }, timeoutMilliseconds);
    }

    public NetEventReadResult ReadNetEvents(long afterSequence, int maxEvents = 128, int timeoutMilliseconds = 1200)
    {
        var request = new ServiceCommandRequest
        {
            Command = "get-net-events",
            AfterEventSequence = Math.Max(0, afterSequence),
            MaxEvents = Math.Clamp(maxEvents, 1, ServiceProtocol.MaxTelemetryEventsPerResponse)
        };

        var requestJson = JsonSerializer.Serialize(request, _jsonOptions);
        var result = SendRaw(requestJson, timeoutMilliseconds);
        if (!result.TransportSuccess)
            return new(false, null, Array.Empty<WfpNetEventSnapshot>(), result.Description);

        if (result.Response is null)
            return new(false, null, Array.Empty<WfpNetEventSnapshot>(), "IPC response is invalid");

        return new(
            result.Response.Success,
            result.Response.Status,
            result.Response.NetEvents ?? [],
            string.IsNullOrWhiteSpace(result.Response.Message) ? result.Description : result.Response.Message);
    }

    private ServiceCommandResult SendCommand(ServiceCommandRequest request, int timeoutMilliseconds)
    {
        var requestJson = JsonSerializer.Serialize(request, _jsonOptions);
        var result = SendRaw(requestJson, timeoutMilliseconds);
        if (!result.TransportSuccess)
            return new(false, null, result.Description);

        if (result.Response is null)
            return new(false, null, "IPC response is invalid");

        return new(
            result.Response.Success,
            result.Response.Status,
            string.IsNullOrWhiteSpace(result.Response.Message) ? result.Description : result.Response.Message);
    }

    private TransportResult SendRaw(string requestLine, int timeoutMilliseconds)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".",
                ServiceProtocol.PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation);

            pipe.Connect(timeoutMilliseconds);

            using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true)
            {
                AutoFlush = true
            };

            writer.WriteLine(requestLine);
            var readTask = reader.ReadLineAsync();
            if (!readTask.Wait(timeoutMilliseconds))
                return new(false, null, "IPC timeout");

            var json = readTask.Result;
            if (string.IsNullOrWhiteSpace(json))
                return new(false, null, "IPC returned an empty response");

            var response = JsonSerializer.Deserialize<ServiceCommandResponse>(json, _jsonOptions);
            if (response is null)
                return new(false, null, "IPC response is invalid");

            return new(true, response, "IPC OK");
        }
        catch (TimeoutException)
        {
            return new(false, null, "service is not responding");
        }
        catch (IOException ex)
        {
            return new(false, null, $"IPC unavailable: {ex.Message}");
        }
        catch (UnauthorizedAccessException)
        {
            return new(false, null, "IPC access denied");
        }
        catch (Exception ex)
        {
            return new(false, null, $"IPC error: {ex.Message}");
        }
    }

    private readonly record struct TransportResult(
        bool TransportSuccess,
        ServiceCommandResponse? Response,
        string Description);
}
