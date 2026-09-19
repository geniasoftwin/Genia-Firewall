using System.IO;
using System.Windows;
using System.Windows.Controls;
using WpfBrush = System.Windows.Media.Brush;
using GeniaFirewall.Models;
using GeniaFirewall.Services;

namespace GeniaFirewall;

public partial class ConnectionPromptWindow : Window
{
    public PromptDecision Decision { get; private set; } = PromptDecision.Later;
    public PromptAllowScope AllowScope { get; private set; } = PromptAllowScope.Always;
    public bool SuppressFuturePrompts => DontRemindCheckBox.IsChecked == true;

    public ConnectionPromptWindow(IReadOnlyList<NetworkConnectionInfo> connections, bool executableChanged = false)
    {
        if (connections is null || connections.Count == 0)
            throw new ArgumentException("At least one network connection is required.", nameof(connections));

        InitializeComponent();

        var connection = connections[0];
        ApplicationNameText.Text = GetDisplayName(connection.ExePath);
        PathText.Text = connection.ExePath;
        ApplicationIcon.Source = ExecutableMetadataService.TryLoadIcon(connection.ExePath);

        var signature = ExecutableMetadataService.GetSignatureInfo(connection.ExePath);
        PublisherText.Text = string.IsNullOrWhiteSpace(signature.Publisher) ? "—" : signature.Publisher;
        SignatureText.Text = signature.StatusLabel;
        SignatureText.ToolTip = signature.Details;
        SignatureText.Foreground = signature.IsTrusted
            ? (WpfBrush)FindResource("AllowedBrush")
            : signature.IsSigned
                ? (WpfBrush)FindResource("AskBrush")
                : (WpfBrush)FindResource("BlockedBrush");

        ConnectionText.Text = BuildConnectionSummary(connections);
        ConnectionText.ToolTip = BuildConnectionDetails(connections);

        var snapshot = connection.ProcessSnapshot.HasData
            ? connection.ProcessSnapshot
            : ProcessSnapshotService.Capture(connection.ProcessId);
        PopulateProcessSnapshot(snapshot);

        if (executableChanged)
        {
            Title = LocalizationService.Get("Prompt.ChangedTitle");
            PromptSubtitleText.Text = LocalizationService.Get("Prompt.ChangedSubtitle");
            PromptSubtitleText.Foreground = (WpfBrush)FindResource("AskBrush");
        }
        else if (connections.Count > 1)
        {
            PromptSubtitleText.Text = LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? $"Новая сетевая активность · объединено событий: {connections.Count}"
                : $"New network activity · grouped events: {connections.Count}";
        }
    }


    private void PopulateProcessSnapshot(ProcessSnapshotInfo snapshot)
    {
        var russian = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
        var startText = snapshot.StartTimeUtcTicks > 0
            ? new DateTime(snapshot.StartTimeUtcTicks, DateTimeKind.Utc).ToLocalTime().ToString("HH:mm:ss")
            : string.Empty;

        ProcessText.Text = snapshot.ProcessId > 0
            ? string.IsNullOrWhiteSpace(startText)
                ? $"PID {snapshot.ProcessId}"
                : russian
                    ? $"PID {snapshot.ProcessId} · запуск {startText}"
                    : $"PID {snapshot.ProcessId} · started {startText}"
            : "—";

        if (snapshot.ParentProcessId > 0)
        {
            var parentName = string.IsNullOrWhiteSpace(snapshot.ParentProcessName)
                ? (russian ? "неизвестный процесс" : "unknown process")
                : snapshot.ParentProcessName;
            ParentText.Text = $"{parentName} · PID {snapshot.ParentProcessId}";
            ParentText.ToolTip = string.IsNullOrWhiteSpace(snapshot.ParentProcessPath)
                ? ParentText.Text
                : snapshot.ParentProcessPath;
        }
        else
        {
            ParentText.Text = "—";
        }

        CommandLineText.Text = string.IsNullOrWhiteSpace(snapshot.CommandLine) ? "—" : snapshot.CommandLine;
        CommandLineText.ToolTip = CommandLineText.Text;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        var workArea = SystemParameters.WorkArea;
        Left = Math.Max(workArea.Left, workArea.Right - ActualWidth - 18);
        Top = Math.Max(workArea.Top, workArea.Bottom - ActualHeight - 18);
        Activate();
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        AllowScope = GetSelectedAllowScope();
        Decision = PromptDecision.Allow;
        DialogResult = true;
    }

    private void Block_Click(object sender, RoutedEventArgs e)
    {
        Decision = PromptDecision.Block;
        DialogResult = true;
    }

    private void Later_Click(object sender, RoutedEventArgs e)
    {
        Decision = PromptDecision.Later;
        DialogResult = false;
    }

    private PromptAllowScope GetSelectedAllowScope()
    {
        var tag = (AllowScopeComboBox.SelectedItem as ComboBoxItem)?.Tag?.ToString();
        return tag switch
        {
            "TenMinutes" => PromptAllowScope.TenMinutes,
            "UntilProcessExit" => PromptAllowScope.UntilProcessExit,
            _ => PromptAllowScope.Always
        };
    }

    private static string BuildConnectionSummary(IReadOnlyList<NetworkConnectionInfo> connections)
    {
        if (connections.Count == 1)
            return FormatConnection(connections[0]);

        var tcpCount = connections.Count(connection => connection.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase));
        var udpCount = connections.Count - tcpCount;
        var protocolSummary = tcpCount > 0 && udpCount > 0
            ? $"TCP: {tcpCount} · UDP: {udpCount}"
            : tcpCount > 0
                ? $"TCP: {tcpCount}"
                : $"UDP: {udpCount}";

        var destinations = connections
            .Select(FormatConnection)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(4)
            .ToList();

        var suffix = connections.Count > destinations.Count
            ? LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? $" · ещё {connections.Count - destinations.Count}"
                : $" · {connections.Count - destinations.Count} more"
            : string.Empty;
        var eventWord = LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "событий" : "events";
        return $"{connections.Count} {eventWord} · {protocolSummary}\n{string.Join("; ", destinations)}{suffix}";
    }

    private static string BuildConnectionDetails(IReadOnlyList<NetworkConnectionInfo> connections) =>
        string.Join(Environment.NewLine, connections
            .Select(FormatConnection)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(20));

    private static string FormatConnection(NetworkConnectionInfo connection)
    {
        if (connection.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            return connection.HasRemoteEndpoint ? $"TCP · {connection.RemoteDisplay}" : LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "TCP активность" : "TCP activity";

        return connection.HasRemoteEndpoint
            ? $"UDP · {connection.RemoteDisplay}"
            : connection.LocalPort > 0
                ? LocalizationService.EffectiveLanguage == UiLanguage.Russian ? $"UDP · локальный порт {connection.LocalPort}" : $"UDP · local port {connection.LocalPort}"
                : LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "UDP активность" : "UDP activity";
    }

    private static string GetDisplayName(string path)
    {
        try
        {
            var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            if (!string.IsNullOrWhiteSpace(version.FileDescription))
            {
                var displayName = new string(version.FileDescription.Where(character => !char.IsControl(character)).ToArray()).Trim();
                if (displayName.Length > 200)
                    displayName = displayName[..200];
                if (!string.IsNullOrWhiteSpace(displayName))
                    return displayName;
            }
        }
        catch
        {
        }

        return Path.GetFileNameWithoutExtension(path);
    }
}

public enum PromptDecision
{
    Later,
    Allow,
    Block
}

public enum PromptAllowScope
{
    Always,
    TenMinutes,
    UntilProcessExit
}
