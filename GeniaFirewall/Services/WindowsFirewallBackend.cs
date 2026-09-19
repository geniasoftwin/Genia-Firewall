using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using GeniaFirewall.Models;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Services;

public sealed class WindowsFirewallBackend : IFirewallBackend
{
    public FirewallBackendKind Kind => FirewallBackendKind.WindowsFirewallCompatibility;

    public string DisplayName => "Windows Firewall Compatibility";

    public FirewallBackendCapabilities Capabilities { get; } = new(
        OutboundRules: true,
        InboundRules: false,
        IPv4: true,
        IPv6: true,
        Tcp: true,
        Udp: true,
        PreConnectDecision: false,
        RequiresKernelCallout: false);
    private const string RuleGroup = "GeniaFirewall";
    private const string RulePrefix = "GeniaFirewall";
    private const string GlobalBlockRuleName = "GeniaFirewall — Global — BlockAll";

    private const int NetFwRuleDirectionOut = 2;
    private const int NetFwActionBlock = 0;
    private const int NetFwActionAllow = 1;
    private const int NetFwProfileAll = int.MaxValue;
    private const int NetFwIpProtocolAny = 256;

    public void ApplyState(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode)
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        try
        {
            TryRemove(policy, GlobalBlockRuleName);

            var applicationRulesEnabled = protectionEnabled && mode is FirewallMode.Normal or FirewallMode.Monitor;

            foreach (var application in applications)
            {
                RemoveRulesForApplication(policy, application.Id);

                if (application.Access == FirewallAccess.Ask)
                    continue;

                if (!TryGetValidExecutablePath(application.ExePath, out var executablePath))
                    continue;

                AddApplicationRule(policy, application, executablePath, applicationRulesEnabled);
            }

            if (protectionEnabled && mode == FirewallMode.BlockAll)
                AddGlobalBlockRule(policy);
        }
        finally
        {
            ReleaseComObject(policy);
        }
    }

    public void SynchronizeState(IEnumerable<ManagedApplication> applications, bool protectionEnabled, FirewallMode mode)
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        try
        {
            RemoveAllGeniaFirewallRules(policy);

            var applicationRulesEnabled = protectionEnabled && mode is FirewallMode.Normal or FirewallMode.Monitor;
            foreach (var application in applications)
            {
                if (application.Access == FirewallAccess.Ask)
                    continue;

                if (!TryGetValidExecutablePath(application.ExePath, out var executablePath))
                    continue;

                AddApplicationRule(policy, application, executablePath, applicationRulesEnabled);
            }

            if (protectionEnabled && mode == FirewallMode.BlockAll)
                AddGlobalBlockRule(policy);
        }
        finally
        {
            ReleaseComObject(policy);
        }
    }

    public FirewallBackendDiagnostics GetDiagnostics()
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        try
        {
            var profiles = new List<string>();
            profiles.Add($"Domain {FormatFirewallState(GetFirewallEnabled(policy, 1))}");
            profiles.Add($"Private {FormatFirewallState(GetFirewallEnabled(policy, 2))}");
            profiles.Add($"Public {FormatFirewallState(GetFirewallEnabled(policy, 4))}");

            var count = 0;
            foreach (dynamic rule in policy.Rules)
            {
                try
                {
                    string? grouping = rule.Grouping as string;
                    string? name = rule.Name as string;
                    if (string.Equals(grouping, RuleGroup, StringComparison.OrdinalIgnoreCase) ||
                        (!string.IsNullOrWhiteSpace(name) && name.StartsWith($"{RulePrefix} — ", StringComparison.OrdinalIgnoreCase)))
                    {
                        count++;
                    }
                }
                catch
                {
                }
                finally
                {
                    ReleaseComObject(rule);
                }
            }

            return new FirewallBackendDiagnostics(DisplayName, string.Join(" · ", profiles), count);
        }
        finally
        {
            ReleaseComObject(policy);
        }
    }

    private static bool? GetFirewallEnabled(dynamic policy, int profile)
    {
        try
        {
            return (bool)policy.FirewallEnabled[profile];
        }
        catch
        {
            return null;
        }
    }

    private static string FormatFirewallState(bool? enabled) => enabled switch
    {
        true => "ВКЛ",
        false => "ВЫКЛ",
        null => "?"
    };

    public void RemoveRules(Guid applicationId)
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        try
        {
            RemoveRulesForApplication(policy, applicationId);
        }
        finally
        {
            ReleaseComObject(policy);
        }
    }

    public void RemoveAllGeniaFirewallRules()
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        try
        {
            RemoveAllGeniaFirewallRules(policy);
        }
        finally
        {
            ReleaseComObject(policy);
        }
    }

    private static void RemoveAllGeniaFirewallRules(dynamic policy)
    {
        var names = new List<string>();

        foreach (dynamic rule in policy.Rules)
        {
            try
            {
                string? grouping = rule.Grouping as string;
                string? name = rule.Name as string;

                if (string.Equals(grouping, RuleGroup, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrWhiteSpace(name) && name.StartsWith($"{RulePrefix} — ", StringComparison.OrdinalIgnoreCase)))
                {
                    names.Add(name ?? string.Empty);
                }
            }
            catch
            {
            }
            finally
            {
                ReleaseComObject(rule);
            }
        }

        foreach (var name in names.Where(name => !string.IsNullOrWhiteSpace(name)))
            TryRemove(policy, name);
    }

    private static void AddApplicationRule(dynamic policy, ManagedApplication application, string executablePath, bool enabled)
    {
        dynamic rule = CreateComObject("HNetCfg.FWRule");
        try
        {
            rule.Name = GetRuleName(application.Id, application.Access);
            rule.Description = $"Managed by GeniaFirewall {ServiceProtocol.ProductVersion} — {application.Name}";
            rule.ApplicationName = executablePath;
            rule.Direction = NetFwRuleDirectionOut;
            rule.Action = application.Access == FirewallAccess.Allow ? NetFwActionAllow : NetFwActionBlock;
            rule.Enabled = enabled;
            rule.Grouping = RuleGroup;
            rule.Profiles = NetFwProfileAll;
            rule.Protocol = NetFwIpProtocolAny;
            rule.InterfaceTypes = "All";
            rule.EdgeTraversal = false;
            policy.Rules.Add(rule);
        }
        finally
        {
            ReleaseComObject(rule);
        }
    }

    private static void AddGlobalBlockRule(dynamic policy)
    {
        dynamic rule = CreateComObject("HNetCfg.FWRule");
        try
        {
            rule.Name = GlobalBlockRuleName;
            rule.Description = $"GeniaFirewall {ServiceProtocol.ProductVersion} global outbound block mode";
            rule.Direction = NetFwRuleDirectionOut;
            rule.Action = NetFwActionBlock;
            rule.Enabled = true;
            rule.Grouping = RuleGroup;
            rule.Profiles = NetFwProfileAll;
            rule.Protocol = NetFwIpProtocolAny;
            rule.InterfaceTypes = "All";
            rule.EdgeTraversal = false;
            policy.Rules.Add(rule);
        }
        finally
        {
            ReleaseComObject(rule);
        }
    }

    private static bool TryGetValidExecutablePath(string path, out string fullPath)
    {
        fullPath = string.Empty;

        try
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
                return false;

            fullPath = Path.GetFullPath(path);
            return fullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(fullPath);
        }
        catch
        {
            fullPath = string.Empty;
            return false;
        }
    }

    private static void RemoveRulesForApplication(dynamic policy, Guid applicationId)
    {
        TryRemove(policy, GetRuleName(applicationId, FirewallAccess.Allow));
        TryRemove(policy, GetRuleName(applicationId, FirewallAccess.Block));
    }

    private static void TryRemove(dynamic policy, string ruleName)
    {
        try
        {
            policy.Rules.Remove(ruleName);
        }
        catch
        {
            // Removing a missing rule can raise a COM exception on some Windows builds.
        }
    }

    private static string GetRuleName(Guid id, FirewallAccess access) =>
        $"{RulePrefix} — {id:N} — {access}";

    private static dynamic CreateComObject(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: true)
                   ?? throw new PlatformNotSupportedException($"Windows COM object {progId} is unavailable.");

        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException($"Could not create Windows COM object {progId}.");
    }

    private static void ReleaseComObject(object? value)
    {
        try
        {
            if (value is not null && Marshal.IsComObject(value))
                Marshal.ReleaseComObject(value);
        }
        catch
        {
        }
    }
}
