namespace GeniaFirewall.Models;

public enum ApplicationRuleProfile
{
    Default,
    EnableAll,
    OutgoingOnly,
    IncomingOnly,
    DisableAll,
    Ask
}
