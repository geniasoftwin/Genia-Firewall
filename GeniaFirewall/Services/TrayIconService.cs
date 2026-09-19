using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public sealed class TrayIconService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _openItem;
    private readonly ToolStripMenuItem _modeMenu;
    private readonly ToolStripMenuItem _protectionItem;
    private readonly ToolStripMenuItem _trustedSystemItem;
    private readonly ToolStripMenuItem _settingsItem;
    private readonly ToolStripMenuItem _exitItem;
    private readonly Dictionary<FirewallMode, ToolStripMenuItem> _modeItems = new();
    private bool _disposed;

    public TrayIconService(
        Action openAction,
        Action settingsAction,
        Action toggleProtectionAction,
        Action toggleTrustedSystemAction,
        Action<FirewallMode> setModeAction,
        Action exitAction)
    {
        ArgumentNullException.ThrowIfNull(openAction);
        ArgumentNullException.ThrowIfNull(settingsAction);
        ArgumentNullException.ThrowIfNull(toggleProtectionAction);
        ArgumentNullException.ThrowIfNull(toggleTrustedSystemAction);
        ArgumentNullException.ThrowIfNull(setModeAction);
        ArgumentNullException.ThrowIfNull(exitAction);

        var menu = new ContextMenuStrip
        {
            ShowImageMargin = false
        };

        _openItem = new ToolStripMenuItem(LocalizationService.Get("Tray.Open"));
        _openItem.Click += (_, _) => openAction();

        _modeMenu = new ToolStripMenuItem(LocalizationService.Get("Tray.Mode"));
        AddModeItem(_modeMenu, LocalizationService.GetModeTitle(FirewallMode.Normal), FirewallMode.Normal, setModeAction);
        AddModeItem(_modeMenu, LocalizationService.GetModeTitle(FirewallMode.BlockAll), FirewallMode.BlockAll, setModeAction);
        AddModeItem(_modeMenu, LocalizationService.GetModeTitle(FirewallMode.AllowAll), FirewallMode.AllowAll, setModeAction);
        AddModeItem(_modeMenu, LocalizationService.GetModeTitle(FirewallMode.Monitor), FirewallMode.Monitor, setModeAction);

        _protectionItem = new ToolStripMenuItem(LocalizationService.Get("Tray.ProtectionOn"));
        _protectionItem.Click += (_, _) => toggleProtectionAction();

        _trustedSystemItem = new ToolStripMenuItem(LocalizationService.Get("Tray.TrustSystem"));
        _trustedSystemItem.Click += (_, _) => toggleTrustedSystemAction();

        _settingsItem = new ToolStripMenuItem(LocalizationService.Get("Tray.Settings"));
        _settingsItem.Click += (_, _) => settingsAction();

        _exitItem = new ToolStripMenuItem(LocalizationService.Get("Tray.Exit"));
        _exitItem.Click += (_, _) => exitAction();

        menu.Items.Add(_openItem);
        menu.Items.Add(_modeMenu);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_protectionItem);
        menu.Items.Add(_trustedSystemItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_settingsItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_exitItem);

        var icon = TryGetApplicationIcon();

        _notifyIcon = new NotifyIcon
        {
            Text = "GeniaFirewall",
            Icon = icon,
            ContextMenuStrip = menu,
            Visible = true
        };

        _notifyIcon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left)
                openAction();
        };
    }

    private void AddModeItem(
        ToolStripMenuItem parent,
        string title,
        FirewallMode mode,
        Action<FirewallMode> setModeAction)
    {
        var item = new ToolStripMenuItem(title);
        item.Click += (_, _) => setModeAction(mode);
        parent.DropDownItems.Add(item);
        _modeItems[mode] = item;
    }

    public void UpdateProtectionState(bool enabled)
    {
        _protectionItem.Text = enabled ? LocalizationService.Get("Tray.ProtectionOn") : LocalizationService.Get("Tray.ProtectionOff");
        _protectionItem.Checked = enabled;
    }

    public void UpdateTrustedSystemState(bool enabled)
    {
        _trustedSystemItem.Checked = enabled;
    }

    public void UpdateMode(FirewallMode mode)
    {
        foreach (var pair in _modeItems)
            pair.Value.Checked = pair.Key == mode;

        _notifyIcon.Text = $"GeniaFirewall — {LocalizationService.GetModeTitle(mode)}";
    }

    public void ShowRunningInTrayHint()
    {
        _notifyIcon.BalloonTipTitle = "GeniaFirewall";
        _notifyIcon.BalloonTipText = LocalizationService.Get("Tray.Running");
        _notifyIcon.BalloonTipIcon = ToolTipIcon.Info;
        _notifyIcon.ShowBalloonTip(1800);
    }

    public void ShowDetectedApplicationHint(string applicationName)
    {
        _notifyIcon.BalloonTipTitle = LocalizationService.Get("Tray.Detected");
        _notifyIcon.BalloonTipText = applicationName;
        _notifyIcon.BalloonTipIcon = ToolTipIcon.Info;
        _notifyIcon.ShowBalloonTip(1500);
    }

    public void ShowChangedApplicationsHint(int count)
    {
        var russian = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
        _notifyIcon.BalloonTipTitle = russian ? "GeniaFirewall — изменённые приложения" : "GeniaFirewall — changed applications";
        _notifyIcon.BalloonTipText = count == 1
            ? (russian ? "Обнаружен изменившийся EXE. Он временно заблокирован до нового решения." : "A changed EXE was detected. It is temporarily blocked until a new decision is made.")
            : (russian ? $"Изменившихся EXE: {count}. Они временно заблокированы до нового решения." : $"Changed EXEs: {count}. They are temporarily blocked until a new decision is made.");
        _notifyIcon.BalloonTipIcon = ToolTipIcon.Warning;
        _notifyIcon.ShowBalloonTip(3000);
    }

    public void RefreshLocalization()
    {
        _openItem.Text = LocalizationService.Get("Tray.Open");
        _modeMenu.Text = LocalizationService.Get("Tray.Mode");
        foreach (var pair in _modeItems)
            pair.Value.Text = LocalizationService.GetModeTitle(pair.Key);
        _trustedSystemItem.Text = LocalizationService.Get("Tray.TrustSystem");
        _settingsItem.Text = LocalizationService.Get("Tray.Settings");
        _exitItem.Text = LocalizationService.Get("Tray.Exit");
        _notifyIcon.Text = "GeniaFirewall";
    }

    private static Icon TryGetApplicationIcon()
    {
        try
        {
            var processPath = Environment.ProcessPath;
            return string.IsNullOrWhiteSpace(processPath)
                ? (Icon)SystemIcons.Shield.Clone()
                : Icon.ExtractAssociatedIcon(processPath) ?? (Icon)SystemIcons.Shield.Clone();
        }
        catch
        {
            return (Icon)SystemIcons.Shield.Clone();
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _notifyIcon.Visible = false;
        _notifyIcon.ContextMenuStrip?.Dispose();
        _notifyIcon.Icon?.Dispose();
        _notifyIcon.Dispose();
    }
}
