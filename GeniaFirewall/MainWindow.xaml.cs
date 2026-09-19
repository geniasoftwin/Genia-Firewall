using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Media;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using GeniaFirewall.Models;
using GeniaFirewall.Services;

namespace GeniaFirewall;

public partial class MainWindow : Window
{
    private readonly AppStore _store = new();
    private readonly WindowsFirewallBackend _windowsFirewall = new();
    private readonly WfpPlatformProbeService _wfpPlatform = new();
    private readonly GeniaFirewallServiceClient _serviceClient = new();
    private readonly WfpServiceBackend _wfpFirewall;
    private IFirewallBackend _firewall;
    private readonly AutostartService _autostart = new();
    private readonly TrustedSystemProcessService _trustedSystem = new();
    private readonly HostnameResolverService _hostnameResolver = new();
    private readonly DiagnosticsService _diagnostics;
    private readonly TrayIconService _trayIcon;
    private readonly ICollectionView _applicationsView;
    private readonly Queue<PromptRequest> _promptQueue = new();
    private readonly Dictionary<string, PromptRequest> _queuedPrompts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<PromptProcessInstance>> _promptSnoozedUntilExit = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _handledPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _fingerprintChecks = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trustEvaluationInProgress = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _handledPathsLock = new();
    private readonly DispatcherTimer _activityPersistTimer;
    private readonly DispatcherTimer _temporaryRuleTimer;
    private readonly string? _selfExePath = Environment.ProcessPath;
    private readonly bool _startedInBackground = Environment.GetCommandLineArgs()
        .Any(argument => string.Equals(argument, "--background", StringComparison.OrdinalIgnoreCase));

    private NetworkWatcherService? _watcher;
    private WfpTelemetryWatcherService? _wfpTelemetryWatcher;
    private AppSettings _settings = new();
    private bool _protectionEnabled = true;
    private FirewallMode _mode = FirewallMode.Normal;
    private bool _allowExit;
    private bool _trayHintShown;
    private bool _promptOpen;
    private bool _initializing = true;
    private bool _activityDirty;
    private bool _temporaryRuleSweepRunning;
    private string? _sortProperty;
    private ListSortDirection _sortDirection = ListSortDirection.Ascending;
    private GridViewColumnHeader? _sortHeader;

    public ObservableCollection<ManagedApplication> Applications { get; } = [];

    public MainWindow()
    {
        _wfpFirewall = new WfpServiceBackend(_serviceClient);
        _firewall = _windowsFirewall;
        InitializeComponent();
        LocalizationService.Configure(UiLanguage.Auto);
        DataContext = this;
        _diagnostics = new DiagnosticsService(_store.DataDirectory);

        _applicationsView = CollectionViewSource.GetDefaultView(Applications);
        _applicationsView.Filter = FilterApplication;

        _activityPersistTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(15)
        };
        _activityPersistTimer.Tick += ActivityPersistTimer_Tick;

        _temporaryRuleTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(2)
        };
        _temporaryRuleTimer.Tick += TemporaryRuleTimer_Tick;

        _trayIcon = new TrayIconService(
            openAction: () => Dispatcher.Invoke(RestoreFromTray),
            settingsAction: () => Dispatcher.Invoke(() =>
            {
                RestoreFromTray();
                OpenSettings();
            }),
            toggleProtectionAction: () => Dispatcher.Invoke(() => RunUiTask(ToggleProtectionAsync, L("Не удалось переключить защиту.", "Failed to toggle protection."))),
            toggleTrustedSystemAction: () => Dispatcher.Invoke(() => RunUiTask(ToggleTrustedSystemModeAsync, L("Не удалось переключить доверие системным процессам.", "Failed to toggle trusted system processes."))),
            setModeAction: mode => Dispatcher.Invoke(() => RunUiTask(() => SetModeAsync(mode), L("Не удалось изменить режим.", "Failed to change mode."))),
            exitAction: () => Dispatcher.Invoke(() => RunUiTask(ExitApplicationAsync, L("Не удалось завершить GeniaFirewall.", "Failed to exit GeniaFirewall."))));

        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        Closed += MainWindow_Closed;
        PreviewKeyDown += MainWindow_PreviewKeyDown;
        System.Windows.Application.Current.SessionEnding += Current_SessionEnding;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _store.ValidatePortableStorage();
            _settings = await _store.LoadSettingsAsync();
            _settings.RuntimeQuarantines ??= [];
            if (!Enum.IsDefined(_settings.UiLanguage))
                _settings.UiLanguage = UiLanguage.Auto;
            LocalizationService.Configure(_settings.UiLanguage);
            _settings.StartWithWindows = _autostart.IsEnabled();
            if (!Enum.IsDefined(_settings.BackendMode))
                _settings.BackendMode = FirewallBackendMode.WindowsFirewallCompatibility;
            _firewall = GetBackend(_settings.BackendMode);
            if (!Enum.IsDefined(_settings.Mode))
                _settings.Mode = FirewallMode.Normal;

            _protectionEnabled = _settings.ProtectionEnabled;
            _mode = _settings.Mode;
            RestoreWindowPlacement(_settings);

            if (_settings.StartWithWindows && !_autostart.IsConfiguredForCurrentExecutable())
            {
                try
                {
                    _autostart.SetEnabled(true);
                }
                catch (Exception ex)
                {
                    _diagnostics.LogException("Repair autostart path", ex);
                }
            }

            const int maxLoadedApplications = 5000;
            var removedMissing = 0;
            var sanitizedEntries = 0;
            var changedExecutables = 0;
            var resetTemporaryRules = 0;
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenIds = new HashSet<Guid>();
            var loadedApplications = await _store.LoadApplicationsAsync();
            var applicationsDatabaseUnavailable = _store.ApplicationsDatabaseUnavailable;
            if (loadedApplications.Count > maxLoadedApplications)
                sanitizedEntries += loadedApplications.Count - maxLoadedApplications;

            foreach (var application in loadedApplications.Take(maxLoadedApplications))
            {
                if (!TryNormalizeLoadedApplication(application, seenPaths, seenIds))
                {
                    sanitizedEntries++;
                    continue;
                }

                if (IsSelfPath(application.ExePath))
                {
                    try
                    {
                        _firewall.RemoveRules(application.Id);
                    }
                    catch (Exception ex)
                    {
                        _diagnostics.LogException("Remove stale self rule", ex);
                    }

                    continue;
                }

                if (_settings.RemoveMissingOnStartup && !File.Exists(application.ExePath))
                {
                    try
                    {
                        _firewall.RemoveRules(application.Id);
                    }
                    catch (Exception ex)
                    {
                        _diagnostics.LogException("Remove missing application rule", ex);
                    }

                    removedMissing++;
                    continue;
                }

                if (NormalizeTemporaryAllowOnStartup(application))
                    resetTemporaryRules++;

                application.IconSource = ExecutableMetadataService.TryLoadIcon(application.ExePath);
                if (string.IsNullOrWhiteSpace(application.SignatureStatus) && File.Exists(application.ExePath))
                    await RefreshTrustMetadataAsync(application);

                if (await VerifyFingerprintAsync(application, establishBaselineIfMissing: false))
                {
                    application.Access = FirewallAccess.Block;
                    application.RuleProfile = ApplicationRuleProfile.Default;
                    ClearTemporaryAllow(application);
                    application.FingerprintChanged = true;
                    changedExecutables++;
                }

                Applications.Add(application);
            }

            if (!applicationsDatabaseUnavailable && (removedMissing > 0 || sanitizedEntries > 0 || changedExecutables > 0 || resetTemporaryRules > 0))
                await PersistAsync();

            RefreshHandledPaths();
            SelectModeInComboBox(_mode);
            _initializing = false;

            if (!applicationsDatabaseUnavailable)
            {
                try
                {
                    // Full synchronization at startup removes orphaned rules left by crashes or old databases.
                    SynchronizeFirewallState(allowWfpAutoFallback: true);
                }
                catch (Exception ex)
                {
                    ShowError(L("Не удалось синхронизировать firewall backend.", "Failed to synchronize the firewall backend."), ex);
                }
            }
            else
            {
                // Fail closed with respect to our existing policy: when the application database cannot
                // be recovered, do not translate an empty fallback database into deletion of all rules.
                _diagnostics.Log("apps.json is unavailable; startup firewall synchronization was skipped to preserve existing GeniaFirewall rules.");
            }

            _watcher = new NetworkWatcherService(IsHandledPath);
            _watcher.NetworkActivityDetected += Watcher_NetworkActivityDetected;
            _watcher.UnknownApplicationDetected += Watcher_UnknownApplicationDetected;
            _watcher.Error += Watcher_Error;
            _watcher.Start();

            // 0.7.1: WFP net-event telemetry complements socket-table polling and is especially
            // important for localhost and very short-lived connections (proxy launchers, helpers).
            _wfpTelemetryWatcher = new WfpTelemetryWatcherService(_serviceClient, IsHandledPath);
            _wfpTelemetryWatcher.NetworkActivityDetected += Watcher_NetworkActivityDetected;
            _wfpTelemetryWatcher.UnknownApplicationDetected += Watcher_UnknownApplicationDetected;
            _wfpTelemetryWatcher.Error += WfpTelemetryWatcher_Error;
            _wfpTelemetryWatcher.Start();

            _activityPersistTimer.Start();
            _temporaryRuleTimer.Start();

            RefreshLocalization();
            UpdateProtectionUi();
            RefreshList();
            UpdateSearchWatermark();
            _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(UpdateColumnWidths));

            var recoveryNotice = _store.ConsumeRecoveryNotice();
            if (applicationsDatabaseUnavailable)
                SetStatus(L("База приложений повреждена и не восстановлена. Существующие firewall-правила сохранены; см. Data\\Logs и .corrupt.", "The application database is damaged and could not be recovered. Existing firewall rules were preserved; see Data\\Logs and .corrupt."));
            else if (!string.IsNullOrWhiteSpace(recoveryNotice))
                SetStatus(recoveryNotice);
            else if (removedMissing > 0 || sanitizedEntries > 0 || changedExecutables > 0 || resetTemporaryRules > 0)
                SetStatus(L($"База проверена: отсутствующих удалено {removedMissing}, некорректных {sanitizedEntries}, изменённых EXE {changedExecutables}, временных правил сброшено {resetTemporaryRules}.", $"Database checked: missing removed {removedMissing}, invalid {sanitizedEntries}, changed EXEs {changedExecutables}, temporary rules reset {resetTemporaryRules}."));
            else
                SetStatus(L("Автоопределение сетевых приложений запущено. Portable-режим активен.", "Network application auto-detection is running. Portable mode is active."));

            if (changedExecutables > 0 && _settings.ShowTrayNotifications)
                _trayIcon.ShowChangedApplicationsHint(changedExecutables);

            if (_startedInBackground)
            {
                _ = Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() => HideToTray(showHint: false)));
            }
        }
        catch (Exception ex)
        {
            ShowError(L("Ошибка запуска GeniaFirewall.", "GeniaFirewall startup error."), ex);
        }
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowExit)
            return;

        e.Cancel = true;
        HideToTray();
    }

    private void MainWindow_Closed(object? sender, EventArgs e)
    {
        System.Windows.Application.Current.SessionEnding -= Current_SessionEnding;

        _activityPersistTimer.Stop();
        _activityPersistTimer.Tick -= ActivityPersistTimer_Tick;
        _temporaryRuleTimer.Stop();
        _temporaryRuleTimer.Tick -= TemporaryRuleTimer_Tick;

        if (_watcher is not null)
        {
            _watcher.NetworkActivityDetected -= Watcher_NetworkActivityDetected;
            _watcher.UnknownApplicationDetected -= Watcher_UnknownApplicationDetected;
            _watcher.Error -= Watcher_Error;
            _watcher.Dispose();
        }

        if (_wfpTelemetryWatcher is not null)
        {
            _wfpTelemetryWatcher.NetworkActivityDetected -= Watcher_NetworkActivityDetected;
            _wfpTelemetryWatcher.UnknownApplicationDetected -= Watcher_UnknownApplicationDetected;
            _wfpTelemetryWatcher.Error -= WfpTelemetryWatcher_Error;
            _wfpTelemetryWatcher.Dispose();
        }

        _trayIcon.Dispose();
    }

    private void Current_SessionEnding(object sender, SessionEndingCancelEventArgs e)
    {
        _allowExit = true;
        CaptureWindowPlacement();

        try
        {
            var applicationsSnapshot = CreateApplicationsSnapshot();
            var settingsSnapshot = BuildSettingsSnapshot();
            Task.Run(async () =>
            {
                await _store.SaveApplicationsAsync(applicationsSnapshot);
                await _store.SaveSettingsAsync(settingsSnapshot);
            }).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _diagnostics.LogException("Save settings on session ending", ex);
        }
    }

    private void HideToTray(bool showHint = true)
    {
        CaptureWindowPlacement();
        _ = SaveSettingsSilentlyAsync();
        Hide();
        SetStatus(L("GeniaFirewall работает в системном трее.", "GeniaFirewall is running in the system tray."));

        if (!showHint || !_settings.ShowTrayNotifications || _trayHintShown)
            return;

        _trayHintShown = true;
        _trayIcon.ShowRunningInTrayHint();
    }

    private void RestoreFromTray()
    {
        if (!IsVisible)
            Show();

        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;

        ShowInTaskbar = true;
        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    private async Task ExitApplicationAsync()
    {
        CaptureWindowPlacement();
        try
        {
            await PersistAsync();
        }
        catch (Exception ex)
        {
            _diagnostics.LogException("Save applications on exit", ex);
        }
        await SaveSettingsSilentlyAsync();
        _allowExit = true;
        System.Windows.Application.Current.Shutdown();
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e) => OpenSettings();

    private async void OpenSettings()
    {
        var previousBackendMode = _settings.BackendMode;
        var previousSettings = BuildSettingsSnapshot();
        var trustedSystemModeWasEnabled = _settings.TrustVerifiedSystemProcesses;
        var trustedSnapshots = Applications
            .Where(app => app.IsTrustedSystem)
            .Select(app => new
            {
                App = app,
                app.Access,
                app.FingerprintChanged,
                app.IsTrustedSystem,
                app.TrustReason
            })
            .ToList();

        try
        {
            var window = new SettingsWindow(
                BuildSettingsSnapshot(),
                _store,
                _autostart,
                rebuildRulesAction: () => SynchronizeFirewallState(),
                removeRulesAction: DisableAndRemoveRulesAsync,
                exportConfigurationAction: ExportConfigurationAsync,
                importConfigurationAction: ImportConfigurationAsync,
                diagnosticsProvider: BuildDiagnosticsText);

            if (IsVisible)
                window.Owner = this;

            if (window.ShowDialog() != true)
                return;

            _settings = window.ResultSettings;
            _settings.RuntimeQuarantines ??= [];
            _settings.StartWithWindows = _autostart.IsEnabled();
            _settings.ProtectionEnabled = _protectionEnabled;
            _settings.Mode = _mode;
            LocalizationService.Configure(_settings.UiLanguage);
            RefreshLocalization();

            if (trustedSystemModeWasEnabled && !_settings.TrustVerifiedSystemProcesses)
            {
                foreach (var trusted in Applications.Where(app => app.IsTrustedSystem))
                {
                    trusted.IsTrustedSystem = false;
                    trusted.TrustReason = string.Empty;
                    trusted.Access = FirewallAccess.Ask;
                    trusted.RuleProfile = ApplicationRuleProfile.Default;
                    trusted.FingerprintChanged = false;
                }
            }

            if (previousBackendMode != _settings.BackendMode)
                SwitchBackendOrThrow(previousBackendMode, _settings.BackendMode);
            else
            {
                _firewall = GetBackend(_settings.BackendMode);
                SynchronizeFirewallState();
            }

            if (trustedSystemModeWasEnabled && !_settings.TrustVerifiedSystemProcesses)
                await PersistAsync();

            RefreshHandledPaths();
            await SaveSettingsAsync();
            UpdateProtectionUi();
            SelectModeInComboBox(_mode);
            SetStatus(L($"Настройки сохранены. Backend: {_firewall.DisplayName}.", $"Settings saved. Backend: {_firewall.DisplayName}."));
        }
        catch (Exception ex)
        {
            _settings = previousSettings;
            _settings.StartWithWindows = _autostart.IsEnabled();
            LocalizationService.Configure(_settings.UiLanguage);
            RefreshLocalization();
            _firewall = GetBackend(previousBackendMode);

            foreach (var snapshot in trustedSnapshots)
            {
                snapshot.App.Access = snapshot.Access;
                snapshot.App.FingerprintChanged = snapshot.FingerprintChanged;
                snapshot.App.IsTrustedSystem = snapshot.IsTrustedSystem;
                snapshot.App.TrustReason = snapshot.TrustReason;
            }

            TryRestoreFirewallState("Rollback after settings/backend change failure");
            ShowError(L("Не удалось открыть или сохранить настройки.", "Failed to open or save settings."), ex);
        }
    }

    private async Task ToggleTrustedSystemModeAsync()
    {
        var previousSetting = _settings.TrustVerifiedSystemProcesses;
        var nextSetting = !previousSetting;
        var trustedSnapshots = Applications
            .Where(app => app.IsTrustedSystem)
            .Select(app => new
            {
                App = app,
                app.Access,
                app.FingerprintChanged,
                app.IsTrustedSystem,
                app.TrustReason
            })
            .ToList();

        try
        {
            _settings.TrustVerifiedSystemProcesses = nextSetting;

            if (!nextSetting)
            {
                foreach (var snapshot in trustedSnapshots)
                {
                    snapshot.App.IsTrustedSystem = false;
                    snapshot.App.TrustReason = string.Empty;
                    snapshot.App.Access = FirewallAccess.Ask;
                    snapshot.App.RuleProfile = ApplicationRuleProfile.Default;
                    snapshot.App.FingerprintChanged = false;
                }

                SynchronizeFirewallState();
                await PersistAsync();
                RefreshHandledPaths();
                RefreshList();
            }

            await SaveSettingsAsync();
            UpdateProtectionUi();
            SetStatus(nextSetting
                ? "Автодоверие строго проверенным системным компонентам Windows включено."
                : "Автодоверие системным компонентам выключено; прежние авто-разрешения переведены в «Спрашивать»." );
        }
        catch
        {
            _settings.TrustVerifiedSystemProcesses = previousSetting;
            foreach (var snapshot in trustedSnapshots)
            {
                snapshot.App.Access = snapshot.Access;
                snapshot.App.FingerprintChanged = snapshot.FingerprintChanged;
                snapshot.App.IsTrustedSystem = snapshot.IsTrustedSystem;
                snapshot.App.TrustReason = snapshot.TrustReason;
            }

            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after trusted-system mode toggle failure");
            RefreshList();
            UpdateProtectionUi();
            throw;
        }
    }

    private async Task DisableAndRemoveRulesAsync()
    {
        if (_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp)
            _wfpFirewall.RemoveAllGeniaFirewallRules();
        else
            _windowsFirewall.RemoveAllGeniaFirewallRules();

        // Also clean stale rules from the inactive compatibility backend.
        try { _windowsFirewall.RemoveAllGeniaFirewallRules(); } catch { }
        if (_settings.BackendMode != FirewallBackendMode.GeniaFirewallWfp)
            ClearWfpRuntimeOrThrow("remove all rules");

        _protectionEnabled = false;
        _settings.ProtectionEnabled = false;
        _settings.RuntimeQuarantines.Clear();
        await SaveSettingsAsync();
        UpdateProtectionUi();
        SetStatus(L("Все правила GeniaFirewall удалены. Защита программы выключена.", "All GeniaFirewall rules were removed. Protection is off."));
    }

    private async void ClearList_Click(object sender, RoutedEventArgs e)
    {
        if (Applications.Count == 0 && _settings.RuntimeQuarantines.Count == 0)
            return;

        var result = System.Windows.MessageBox.Show(
            this,
            L("Удалить все приложения и правила GeniaFirewall?\n\nВ нормальном режиме активные сетевые программы начнут определяться заново.", "Remove all applications and GeniaFirewall rules?\n\nIn Normal mode active network applications will be detected again."),
            "GeniaFirewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes)
            return;

        var backup = Applications.ToList();
        var quarantineBackup = _settings.RuntimeQuarantines
            .Select(item => new RuntimeQuarantineEntry { Id = item.Id, ExePath = item.ExePath, DisplayName = item.DisplayName })
            .ToList();

        try
        {
            _firewall.RemoveAllGeniaFirewallRules();
            Applications.Clear();
            _settings.RuntimeQuarantines.Clear();
            RefreshHandledPaths();
            await PersistAsync();
            await SaveSettingsAsync();
            SynchronizeFirewallState();
            RefreshList();
            SetStatus(L("Список очищен. Ожидаем новые сетевые приложения...", "List cleared. Waiting for new network applications..."));
        }
        catch (Exception ex)
        {
            Applications.Clear();
            foreach (var application in backup)
                Applications.Add(application);
            _settings.RuntimeQuarantines = quarantineBackup;

            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after clear list failure");
            try
            {
                await PersistAsync();
            }
            catch (Exception persistError)
            {
                _diagnostics.LogException("Rollback database after clear list failure", persistError);
            }

            RefreshList();
            ShowError(L("Не удалось очистить список.", "Failed to clear the list."), ex);
        }
    }

    private async void AddApplication_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = L("Добавить приложение в GeniaFirewall", "Add application to GeniaFirewall"),
            Filter = L("Приложения (*.exe)|*.exe", "Applications (*.exe)|*.exe"),
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
            return;

        var selectedPath = Path.GetFullPath(dialog.FileName);

        if (IsSelfPath(selectedPath))
        {
            SetStatus(L("GeniaFirewall не добавляет собственный процесс в список правил.", "GeniaFirewall does not add its own process to the rule list."));
            return;
        }

        var existing = FindApplication(selectedPath);
        if (existing is not null)
        {
            SetStatus(L("Это приложение уже находится в списке.", "This application is already in the list."));
            ApplicationsList.SelectedItem = existing;
            ApplicationsList.ScrollIntoView(existing);
            return;
        }

        var application = CreateApplication(selectedPath, FirewallAccess.Allow);
        await CaptureFingerprintBaselineAsync(application);
        Applications.Add(application);
        var removedQuarantine = FindRuntimeQuarantine(selectedPath);
        if (removedQuarantine is not null)
            RemoveRuntimeQuarantine(selectedPath);

        try
        {
            ApplyFirewallState();
            await PersistAsync();
            await SaveSettingsAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(L($"{application.Name}: разрешено.", $"{application.Name}: allowed."));
        }
        catch (Exception ex)
        {
            Applications.Remove(application);
            if (removedQuarantine is not null && FindRuntimeQuarantine(removedQuarantine.ExePath) is null)
                _settings.RuntimeQuarantines.Add(removedQuarantine);
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after add application failure");
            ShowError(L("Не удалось добавить правило.", "Failed to add the rule."), ex);
        }
    }

    private async Task SetAccessAsync(ManagedApplication application, FirewallAccess access, ApplicationRuleProfile ruleProfile = ApplicationRuleProfile.Default)
    {
        var previousAccess = application.Access;
        var previousRuleProfile = application.RuleProfile;
        var previousChanged = application.FingerprintChanged;
        var previousSha = application.Sha256;
        var previousLength = application.FileLength;
        var previousWrite = application.FileLastWriteUtc;
        var previousTrustedSystem = application.IsTrustedSystem;
        var previousTrustReason = application.TrustReason;
        var previousUntil = application.TemporaryAllowUntilUtc;
        var previousProcessId = application.TemporaryAllowProcessId;
        var previousSuppressPrompts = application.SuppressPromptNotifications;

        if (access is FirewallAccess.Allow or FirewallAccess.Block)
            await CaptureFingerprintBaselineAsync(application);

        application.FingerprintChanged = false;
        application.Access = access;
        application.RuleProfile = ruleProfile;
        application.IsTrustedSystem = false;
        application.TrustReason = string.Empty;
        application.SuppressPromptNotifications = false;
        _promptSnoozedUntilExit.Remove(application.ExePath);
        ClearTemporaryAllow(application);

        try
        {
            ApplyFirewallState();
            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(ruleProfile == ApplicationRuleProfile.Default
                ? $"{application.Name}: {GetAccessActionResult(access)}."
                : $"{application.Name}: {application.RuleProfileLabel}.");
        }
        catch (Exception ex)
        {
            application.Access = previousAccess;
            application.RuleProfile = previousRuleProfile;
            application.FingerprintChanged = previousChanged;
            application.Sha256 = previousSha;
            application.FileLength = previousLength;
            application.FileLastWriteUtc = previousWrite;
            application.IsTrustedSystem = previousTrustedSystem;
            application.TrustReason = previousTrustReason;
            application.TemporaryAllowUntilUtc = previousUntil;
            application.TemporaryAllowProcessId = previousProcessId;
            application.SuppressPromptNotifications = previousSuppressPrompts;
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after access change failure");
            RefreshList();
            ShowError(L("Не удалось изменить правило.", "Failed to change the rule."), ex);
        }
    }

    private async Task RemoveApplicationAsync(ManagedApplication application)
    {
        var index = Applications.IndexOf(application);
        var removedFromCollection = false;
        var previousRuntimeQuarantines = _settings.RuntimeQuarantines
            .Select(item => new RuntimeQuarantineEntry
            {
                Id = item.Id,
                ExePath = item.ExePath,
                DisplayName = item.DisplayName
            })
            .ToList();

        try
        {
            // Del means forget the visible decision/reminder state. Security is preserved separately
            // by the hidden WFP quarantine below, so the next detected activity may prompt again.
            _promptSnoozedUntilExit.Remove(application.ExePath);

            if (ShouldKeepHiddenQuarantineAfterDelete(application))
            {
                // 0.6.3 True Del: the row disappears, but the standalone WFP backend keeps a
                // hidden ASK-BLOCK for the executable. This preserves fail-closed behavior while
                // letting the application return to the visible list only when network activity
                // is detected again.
                UpsertRuntimeQuarantine(application);
                removedFromCollection = Applications.Remove(application);
                ApplyFirewallState();
                await PersistAsync();
                await SaveSettingsAsync();
                RefreshHandledPaths();
                RefreshList();
                _watcher?.Snooze(application.ExePath, TimeSpan.FromSeconds(2));
                SetStatus(LocalizationService.EffectiveLanguage == UiLanguage.Russian
                    ? $"{application.Name} удалено из списка; скрытый WFP-карантин сохранён до следующего сетевого запроса."
                    : $"{application.Name} was removed from the list; hidden WFP quarantine remains until the next network request.");
                return;
            }

            _firewall.RemoveRules(application.Id);
            removedFromCollection = Applications.Remove(application);
            RemoveRuntimeQuarantine(application.ExePath);
            await PersistAsync();
            await SaveSettingsAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? $"{application.Name} удалено из списка. При следующей сетевой активности приложение снова будет обнаружено."
                : $"{application.Name} was removed from the list. It will be detected again on its next network activity.");
        }
        catch (Exception ex)
        {
            _settings.RuntimeQuarantines = previousRuntimeQuarantines;
            if (removedFromCollection && !Applications.Contains(application))
            {
                if (index >= 0 && index <= Applications.Count)
                    Applications.Insert(index, application);
                else
                    Applications.Add(application);
            }

            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after remove application failure");
            RefreshList();
            ShowError(LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? "Не удалось удалить правило."
                : "Failed to remove the rule.", ex);
        }
    }

    private bool ShouldKeepHiddenQuarantineAfterDelete(ManagedApplication application) =>
        _settings.ImmediateQuarantineOnForget &&
        _protectionEnabled &&
        _mode == FirewallMode.Normal &&
        _settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp &&
        !IsSelfPath(application.ExePath);

    private void UpsertRuntimeQuarantine(ManagedApplication application)
    {
        _settings.RuntimeQuarantines ??= [];
        var existing = _settings.RuntimeQuarantines.FirstOrDefault(item =>
            string.Equals(item.ExePath, application.ExePath, StringComparison.OrdinalIgnoreCase));

        if (existing is null)
        {
            _settings.RuntimeQuarantines.Add(new RuntimeQuarantineEntry
            {
                Id = application.Id,
                ExePath = application.ExePath,
                DisplayName = application.Name
            });
        }
        else
        {
            existing.Id = application.Id;
            existing.ExePath = application.ExePath;
            existing.DisplayName = application.Name;
        }
    }

    private RuntimeQuarantineEntry? FindRuntimeQuarantine(string exePath) =>
        _settings.RuntimeQuarantines?.FirstOrDefault(item =>
            string.Equals(item.ExePath, exePath, StringComparison.OrdinalIgnoreCase));

    private bool RemoveRuntimeQuarantine(string exePath)
    {
        var entry = FindRuntimeQuarantine(exePath);
        return entry is not null && _settings.RuntimeQuarantines.Remove(entry);
    }

    private static int TryFindRunningProcessId(string exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath))
            return 0;

        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch
        {
            return 0;
        }

        foreach (var process in processes)
        {
            using (process)
            {
                try
                {
                    if (ProcessIdentityService.IsSameProcessImageRunning(process.Id, exePath))
                        return process.Id;
                }
                catch
                {
                    // Processes may exit while enumerating. Continue with the remaining snapshot.
                }
            }
        }

        return 0;
    }

    private async void ProtectionButton_Click(object sender, RoutedEventArgs e) =>
        await ToggleProtectionAsync();

    private async Task ToggleProtectionAsync()
    {
        var nextState = !_protectionEnabled;

        if (nextState && _mode == FirewallMode.BlockAll && _settings.ConfirmBlockAll)
        {
            var result = System.Windows.MessageBox.Show(
                this,
                L("Защита будет включена в режиме «Блокировать всё». Исходящие подключения будут заблокированы.\n\nПродолжить?", "Protection will be enabled in Block all mode. Outbound connections will be blocked.\n\nContinue?"),
                "GeniaFirewall",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes)
                return;
        }

        try
        {
            _firewall.ApplyState(GetPolicyApplications(_settings.BackendMode), nextState, _mode);
            if (_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp)
                TryRemoveCompatibilityRulesAfterWfpCommit();
            _protectionEnabled = nextState;
            await SaveSettingsAsync();
            UpdateProtectionUi();
            SetStatus(_protectionEnabled ? L("Защита GeniaFirewall включена.", "GeniaFirewall protection is on.") : L("Правила GeniaFirewall приостановлены.", "GeniaFirewall rules are paused."));
        }
        catch (Exception ex)
        {
            TryRestoreFirewallState("Rollback after protection toggle failure");
            ShowError(L("Не удалось изменить состояние защиты.", "Failed to change protection state."), ex);
        }
    }

    private async void ModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializing || ModeComboBox.SelectedItem is not ComboBoxItem item)
            return;

        if (!Enum.TryParse<FirewallMode>(item.Tag?.ToString(), out var mode))
            return;

        await SetModeAsync(mode);
    }

    private async Task SetModeAsync(FirewallMode mode)
    {
        if (mode == _mode)
        {
            SelectModeInComboBox(_mode);
            return;
        }

        if (mode == FirewallMode.BlockAll && _settings.ConfirmBlockAll)
        {
            var result = System.Windows.MessageBox.Show(
                this,
                L("Режим «Блокировать всё» создаст глобальное правило, запрещающее исходящие подключения. Интернет у программ временно перестанет работать до смены режима.\n\nВключить?", "Block all mode creates a global rule that blocks outbound connections. Applications will temporarily lose network access until the mode is changed.\n\nEnable it?"),
                "GeniaFirewall",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (result != MessageBoxResult.Yes)
            {
                SelectModeInComboBox(_mode);
                return;
            }
        }

        var previousMode = _mode;
        _mode = mode;

        try
        {
            ApplyFirewallState();
            RefreshHandledPaths();
            await SaveSettingsAsync();
            SelectModeInComboBox(_mode);
            UpdateProtectionUi();
            SetStatus(L($"Режим: {GetModeTitle(_mode)}.", $"Mode: {GetModeTitle(_mode)}."));
        }
        catch (Exception ex)
        {
            _mode = previousMode;
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after mode change failure");
            SelectModeInComboBox(_mode);
            ShowError(L("Не удалось изменить режим.", "Failed to change mode."), ex);
        }
    }

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateSearchWatermark();
        _applicationsView.Refresh();
    }

    private void UpdateSearchWatermark()
    {
        if (SearchWatermark is null || SearchBox is null)
            return;

        SearchWatermark.Visibility = string.IsNullOrEmpty(SearchBox.Text)
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    private bool FilterApplication(object item)
    {
        if (item is not ManagedApplication application)
            return false;

        var query = SearchBox?.Text?.Trim();
        if (string.IsNullOrWhiteSpace(query))
            return true;

        return application.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.ExePath.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.TrustReason.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.TrustLabel.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.AccessLabel.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.RuleProfileLabel.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               application.TemporaryAllowLabel.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void Watcher_NetworkActivityDetected(object? sender, NetworkConnectionInfo connection)
    {
        _ = DispatchNetworkActivityAsync(connection);
    }

    private async Task DispatchNetworkActivityAsync(NetworkConnectionInfo connection)
    {
        try
        {
            var operation = Dispatcher.InvokeAsync(new Func<Task>(() => HandleNetworkActivityAsync(connection)));
            var handlerTask = await operation.Task;
            await handlerTask;
        }
        catch (Exception ex)
        {
            _diagnostics.LogException("Update network activity", ex);
        }
    }

    private async Task HandleNetworkActivityAsync(NetworkConnectionInfo connection)
    {
        if (IsSelfPath(connection.ExePath))
            return;

        var application = FindApplication(connection.ExePath);
        if (application is null)
            return;

        connection = await ResolveHostNameIfEnabledAsync(connection);
        UpdateActivity(application, connection);
        _activityDirty = true;

        if (application.FingerprintChanged)
        {
            if (await TryRevalidateTrustedSystemAsync(application, connection))
                return;

            application.IsTrustedSystem = false;
            application.TrustReason = string.Empty;
            QueuePrompt(connection, force: true);
            return;
        }

        var previousAccess = application.Access;
        var previousRuleProfile = application.RuleProfile;
        var previousChanged = application.FingerprintChanged;
        var previousSha = application.Sha256;
        var previousLength = application.FileLength;
        var previousWrite = application.FileLastWriteUtc;
        var previousUntil = application.TemporaryAllowUntilUtc;
        var previousProcessId = application.TemporaryAllowProcessId;
        if (!await VerifyFingerprintAsync(application, establishBaselineIfMissing: true))
            return;

        if (await TryRevalidateTrustedSystemAsync(application, connection))
            return;

        application.IsTrustedSystem = false;
        application.TrustReason = string.Empty;
        application.Access = FirewallAccess.Block;
        application.RuleProfile = ApplicationRuleProfile.Default;
        ClearTemporaryAllow(application);
        application.FingerprintChanged = true;

        try
        {
            ApplyFirewallState();
            RefreshHandledPaths();
            await PersistAsync();
            _activityDirty = false;
            UpdateSummary();
            SetStatus(L($"{application.Name}: исполняемый файл изменился и временно заблокирован до нового решения.", $"{application.Name}: executable changed and is temporarily blocked until a new decision."));
            QueuePrompt(connection, force: true);
        }
        catch (Exception ex)
        {
            application.Access = previousAccess;
            application.RuleProfile = previousRuleProfile;
            application.FingerprintChanged = previousChanged;
            application.Sha256 = previousSha;
            application.FileLength = previousLength;
            application.FileLastWriteUtc = previousWrite;
            application.TemporaryAllowUntilUtc = previousUntil;
            application.TemporaryAllowProcessId = previousProcessId;
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after executable fingerprint change");
            _diagnostics.LogException("Apply changed executable policy", ex);
        }
    }

    private void Watcher_Error(Exception exception)
    {
        _diagnostics.LogException("Network watcher", exception);
        _ = Dispatcher.BeginInvoke(new Action(() => SetStatus(L("Автоопределение столкнулось с ошибкой. См. Data\\Logs.", "Auto-detection encountered an error. See Data\\Logs."))));
    }

    private void WfpTelemetryWatcher_Error(Exception exception)
    {
        _diagnostics.LogException("WFP telemetry watcher", exception);
        // Legacy socket polling remains active as a fallback; do not interrupt the user with a dialog.
    }

    private void Watcher_UnknownApplicationDetected(object? sender, NetworkConnectionInfo connection)
    {
        _ = DispatchDetectedApplicationAsync(connection);
    }

    private async Task DispatchDetectedApplicationAsync(NetworkConnectionInfo connection)
    {
        try
        {
            var operation = Dispatcher.InvokeAsync(new Func<Task>(() => HandleDetectedApplicationAsync(connection)));
            var handlerTask = await operation.Task;
            await handlerTask;
        }
        catch (Exception ex)
        {
            if (!Dispatcher.HasShutdownStarted)
                Dispatcher.Invoke(() => ShowError(L("Ошибка автоопределения сетевого приложения.", "Network application auto-detection error."), ex));
            else
                _diagnostics.LogException("Ошибка автоопределения сетевого приложения", ex);
        }
    }

    private async Task HandleDetectedApplicationAsync(NetworkConnectionInfo connection)
    {
        if (!_protectionEnabled || IsSelfPath(connection.ExePath))
            return;

        if (_mode is FirewallMode.AllowAll or FirewallMode.BlockAll)
            return;

        if (IsHandledPath(connection.ExePath))
        {
            await HandleNetworkActivityAsync(connection);
            return;
        }

        // 0.6.3 Secure Prompt Quarantine. The user-mode watcher still discovers the first
        // network attempt after it happens, but once an unknown EXE is discovered we install
        // an ASK-BLOCK WFP rule before signature checks and before showing the prompt.
        // This closes the much larger window where an application could keep using the network
        // for the entire time the decision dialog remained open.
        if (_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp && _mode == FirewallMode.Normal)
            await EnsureWfpPromptQuarantineAsync(connection);

        if (_settings.TrustVerifiedSystemProcesses)
        {
            if (!_trustEvaluationInProgress.Add(connection.ExePath))
            {
                // Another event from the same burst is already performing the expensive signature/service
                // check. In Normal mode keep its endpoint in the grouped request; the request is cancelled
                // automatically if that first evaluation proves the executable is trusted. Monitor mode never
                // opens a prompt, so the first event is sufficient for its lightweight activity record.
                if (_mode != FirewallMode.Monitor)
                    QueuePrompt(connection);
                return;
            }

            try
            {
                var trustedDecision = await Task.Run(() => _trustedSystem.Evaluate(connection));
                if (trustedDecision.IsTrusted)
                {
                    _queuedPrompts.Remove(connection.ExePath);
                    await AutoAllowTrustedSystemAsync(connection, trustedDecision);
                    return;
                }
            }
            finally
            {
                _trustEvaluationInProgress.Remove(connection.ExePath);
            }
        }

        if (_mode == FirewallMode.Monitor)
        {
            var application = FindApplication(connection.ExePath);
            if (application is null)
            {
                application = CreateApplication(connection.ExePath, FirewallAccess.Ask);
                await CaptureFingerprintBaselineAsync(application);
                Applications.Add(application);
            }

            connection = await ResolveHostNameIfEnabledAsync(connection);
            UpdateActivity(application, connection);
            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            if (_settings.ShowTrayNotifications)
                _trayIcon.ShowDetectedApplicationHint(application.Name);
            SetStatus(L($"Обнаружено: {application.Name}", $"Detected: {application.Name}"));
            return;
        }

        QueuePrompt(connection);
    }

    private async Task EnsureWfpPromptQuarantineAsync(NetworkConnectionInfo connection)
    {
        if (!_protectionEnabled ||
            _mode != FirewallMode.Normal ||
            _settings.BackendMode != FirewallBackendMode.GeniaFirewallWfp ||
            IsSelfPath(connection.ExePath))
        {
            return;
        }

        var existing = FindApplication(connection.ExePath);
        if (existing is not null)
            return;

        var hiddenQuarantine = FindRuntimeQuarantine(connection.ExePath);
        var application = CreateApplication(connection.ExePath, FirewallAccess.Ask);
        if (hiddenQuarantine is not null)
        {
            application.Id = hiddenQuarantine.Id;
            if (!string.IsNullOrWhiteSpace(hiddenQuarantine.DisplayName))
                application.Name = hiddenQuarantine.DisplayName;
            RemoveRuntimeQuarantine(connection.ExePath);
        }

        UpdateActivity(application, connection);
        Applications.Add(application);

        try
        {
            // Apply first: hashing/signature checks may take noticeable time. ASK is mapped to
            // a WFP BLOCK by the 0.6.3 service while Normal mode is active.
            ApplyFirewallState();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(L($"{application.Name}: WFP-карантин до решения пользователя.", $"{application.Name}: WFP quarantine pending your decision."));

            try
            {
                await CaptureFingerprintBaselineAsync(application);
                await PersistAsync();
                await SaveSettingsAsync();
            }
            catch (Exception metadataError)
            {
                // Keep the quarantine rule fail-closed even if metadata persistence fails. The
                // final Allow/Block decision will retry normal persistence.
                _diagnostics.LogException("Persist WFP prompt quarantine metadata", metadataError);
            }
        }
        catch
        {
            Applications.Remove(application);
            if (hiddenQuarantine is not null && FindRuntimeQuarantine(hiddenQuarantine.ExePath) is null)
                _settings.RuntimeQuarantines.Add(hiddenQuarantine);
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after WFP prompt quarantine failure");
            RefreshList();
            throw;
        }
    }

    private async Task AutoAllowTrustedSystemAsync(NetworkConnectionInfo connection, TrustedSystemDecision decision)
    {
        var application = FindApplication(connection.ExePath);
        var created = application is null;

        var previousAccess = application?.Access ?? FirewallAccess.Ask;
        var previousRuleProfile = application?.RuleProfile ?? ApplicationRuleProfile.Default;
        var previousChanged = application?.FingerprintChanged ?? false;
        var previousTrusted = application?.IsTrustedSystem ?? false;
        var previousReason = application?.TrustReason ?? string.Empty;
        var previousSha = application?.Sha256 ?? string.Empty;
        var previousLength = application?.FileLength ?? 0;
        var previousWrite = application?.FileLastWriteUtc;
        var previousUntil = application?.TemporaryAllowUntilUtc;
        var previousProcessId = application?.TemporaryAllowProcessId ?? 0;

        if (application is null)
        {
            application = CreateApplication(connection.ExePath, FirewallAccess.Allow);
            Applications.Add(application);
        }

        await CaptureFingerprintBaselineAsync(application);
        if (string.IsNullOrWhiteSpace(application.Sha256) || application.Sha256.Length != 64)
        {
            if (created)
                Applications.Remove(application);
            else
            {
                application.Access = previousAccess;
                application.RuleProfile = previousRuleProfile;
                application.FingerprintChanged = previousChanged;
                application.IsTrustedSystem = previousTrusted;
                application.TrustReason = previousReason;
                application.Sha256 = previousSha;
                application.FileLength = previousLength;
                application.FileLastWriteUtc = previousWrite;
                application.TemporaryAllowUntilUtc = previousUntil;
                application.TemporaryAllowProcessId = previousProcessId;
            }

            RefreshHandledPaths();
            QueuePrompt(connection, force: true);
            return;
        }

        application.Access = FirewallAccess.Allow;
        application.RuleProfile = ApplicationRuleProfile.Default;
        application.FingerprintChanged = false;
        application.IsTrustedSystem = true;
        application.TrustReason = decision.Reason;
        ClearTemporaryAllow(application);
        connection = await ResolveHostNameIfEnabledAsync(connection);
        UpdateActivity(application, connection);

        try
        {
            ApplyFirewallState();
            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(L($"{application.Name}: доверенный системный компонент, разрешён автоматически без запроса.", $"{application.Name}: trusted system component, automatically allowed without a prompt."));
        }
        catch (Exception ex)
        {
            if (created)
            {
                Applications.Remove(application);
            }
            else
            {
                application.Access = previousAccess;
                application.RuleProfile = previousRuleProfile;
                application.FingerprintChanged = previousChanged;
                application.IsTrustedSystem = previousTrusted;
                application.TrustReason = previousReason;
                application.Sha256 = previousSha;
                application.FileLength = previousLength;
                application.FileLastWriteUtc = previousWrite;
                application.TemporaryAllowUntilUtc = previousUntil;
                application.TemporaryAllowProcessId = previousProcessId;
            }

            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after trusted-system auto allow failure");
            _diagnostics.LogException("Auto-allow trusted system process", ex);
            QueuePrompt(connection, force: true);
        }
    }

    private async Task<bool> TryRevalidateTrustedSystemAsync(ManagedApplication application, NetworkConnectionInfo connection)
    {
        if (!_settings.TrustVerifiedSystemProcesses || !application.IsTrustedSystem)
            return false;

        var previousAccess = application.Access;
        var previousRuleProfile = application.RuleProfile;
        var previousChanged = application.FingerprintChanged;
        var previousTrusted = application.IsTrustedSystem;
        var previousReason = application.TrustReason;
        var previousSha = application.Sha256;
        var previousLength = application.FileLength;
        var previousWrite = application.FileLastWriteUtc;
        var previousUntil = application.TemporaryAllowUntilUtc;
        var previousProcessId = application.TemporaryAllowProcessId;

        try
        {
            var decision = await Task.Run(() => _trustedSystem.Evaluate(connection));
            if (!decision.IsTrusted)
                return false;

            await CaptureFingerprintBaselineAsync(application);
            if (string.IsNullOrWhiteSpace(application.Sha256) || application.Sha256.Length != 64)
                throw new InvalidOperationException("Не удалось зафиксировать SHA-256 доверенного системного компонента.");

            application.Access = FirewallAccess.Allow;
            application.RuleProfile = ApplicationRuleProfile.Default;
            application.FingerprintChanged = false;
            application.IsTrustedSystem = true;
            application.TrustReason = decision.Reason;
            ClearTemporaryAllow(application);
            connection = await ResolveHostNameIfEnabledAsync(connection);
            UpdateActivity(application, connection);

            ApplyFirewallState();
            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(L($"{application.Name}: системный компонент обновился, подпись и служба перепроверены — автодоверие сохранено.", $"{application.Name}: system component updated; signature and service identity were rechecked and auto-trust was retained."));
            return true;
        }
        catch (Exception ex)
        {
            application.Access = previousAccess;
            application.RuleProfile = previousRuleProfile;
            application.FingerprintChanged = previousChanged;
            application.IsTrustedSystem = previousTrusted;
            application.TrustReason = previousReason;
            application.Sha256 = previousSha;
            application.FileLength = previousLength;
            application.FileLastWriteUtc = previousWrite;
            application.TemporaryAllowUntilUtc = previousUntil;
            application.TemporaryAllowProcessId = previousProcessId;
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after trusted-system revalidation failure");
            _diagnostics.LogException("Revalidate trusted system process", ex);
            return false;
        }
    }

    private bool IsPromptSuppressed(string exePath)
    {
        var application = FindApplication(exePath);
        if (application?.SuppressPromptNotifications == true)
            return true;

        if (!_promptSnoozedUntilExit.TryGetValue(exePath, out var instances))
            return false;

        if (instances.Any(IsSameProcessInstanceRunning))
            return true;

        _promptSnoozedUntilExit.Remove(exePath);
        return false;
    }

    private static List<PromptProcessInstance> CaptureRunningProcessInstances(string exePath, int preferredProcessId = 0)
    {
        var result = new List<PromptProcessInstance>();
        Process[] processes;
        try
        {
            processes = Process.GetProcesses();
        }
        catch
        {
            processes = [];
        }

        foreach (var process in processes)
        {
            using (process)
            {
                try
                {
                    if (!ProcessIdentityService.IsSameProcessImageRunning(process.Id, exePath))
                        continue;

                    result.Add(new PromptProcessInstance(process.Id, process.StartTime.ToUniversalTime().Ticks, exePath));
                }
                catch
                {
                }
            }
        }

        // The event PID is the strongest hint for the prompt that was just shown. If process
        // enumeration was restricted or raced with process startup, keep a fallback instance so
        // Later/X still suppresses repeat prompts instead of immediately prompting again.
        if (preferredProcessId > 0 && result.All(item => item.ProcessId != preferredProcessId))
        {
            try
            {
                using var process = Process.GetProcessById(preferredProcessId);
                if (ProcessIdentityService.IsSameProcessImageRunning(preferredProcessId, exePath))
                    result.Add(new PromptProcessInstance(preferredProcessId, process.StartTime.ToUniversalTime().Ticks, exePath));
            }
            catch
            {
                result.Add(new PromptProcessInstance(preferredProcessId, 0, exePath));
            }
        }

        return result;
    }

    private static bool IsSameProcessInstanceRunning(PromptProcessInstance instance)
    {
        try
        {
            using var process = Process.GetProcessById(instance.ProcessId);
            if (!ProcessIdentityService.IsSameProcessImageRunning(instance.ProcessId, instance.ExePath))
                return false;

            return instance.StartTimeUtcTicks == 0 || process.StartTime.ToUniversalTime().Ticks == instance.StartTimeUtcTicks;
        }
        catch
        {
            return false;
        }
    }

    private void QueuePrompt(NetworkConnectionInfo connection, bool force = false)
    {
        if (IsSelfPath(connection.ExePath))
            return;

        if (!force && IsPromptSuppressed(connection.ExePath))
            return;

        if (!force && IsHandledPath(connection.ExePath))
            return;

        if (_queuedPrompts.TryGetValue(connection.ExePath, out var existing))
        {
            existing.Add(connection);
            existing.Force |= force;
            return;
        }

        var request = new PromptRequest(connection, force);
        _queuedPrompts[connection.ExePath] = request;
        _ = SchedulePromptAsync(request);
    }

    private async Task SchedulePromptAsync(PromptRequest request)
    {
        // A short debounce window collects a burst of destinations from the same EXE into one prompt.
        await Task.Delay(TimeSpan.FromMilliseconds(250));

        if (!_queuedPrompts.TryGetValue(request.ExePath, out var current) || !ReferenceEquals(current, request))
            return;

        _promptQueue.Enqueue(request);
        await ProcessNextPromptAsync();
    }

    private async Task ProcessNextPromptAsync()
    {
        if (_promptOpen)
            return;

        _promptOpen = true;
        try
        {
            while (_promptQueue.Count > 0)
            {
                var request = _promptQueue.Dequeue();
                while (_trustEvaluationInProgress.Contains(request.ExePath))
                    await Task.Delay(100);

                if (!_queuedPrompts.TryGetValue(request.ExePath, out var currentRequest) || !ReferenceEquals(currentRequest, request))
                    continue;

                if (request.Connections.Count == 0)
                {
                    _queuedPrompts.Remove(request.ExePath);
                    continue;
                }

                var connection = request.Connections[0];
                var applicationBeforePrompt = FindApplication(connection.ExePath);
                var changedApplicationPrompt = applicationBeforePrompt?.FingerprintChanged == true;
                if (IsSelfPath(connection.ExePath) || (IsHandledPath(connection.ExePath) && !changedApplicationPrompt && !request.Force))
                {
                    _queuedPrompts.Remove(connection.ExePath);
                    continue;
                }

                IReadOnlyList<NetworkConnectionInfo> promptConnections = request.Connections.ToList();
                if (_settings.ResolveHostNames)
                    promptConnections = await _hostnameResolver.EnrichAsync(promptConnections);

                connection = promptConnections[0];

                if (_settings.PlayDetectionSound)
                    SystemSounds.Exclamation.Play();

                var prompt = new ConnectionPromptWindow(promptConnections, changedApplicationPrompt);
                if (IsVisible)
                    prompt.Owner = this;

                prompt.ShowDialog();

                if (prompt.Decision == PromptDecision.Later)
                {
                    var pendingApplication = FindApplication(connection.ExePath);
                    if (pendingApplication is not null)
                    {
                        if (prompt.SuppressFuturePrompts)
                            pendingApplication.SuppressPromptNotifications = true;

                        _promptSnoozedUntilExit[connection.ExePath] = CaptureRunningProcessInstances(connection.ExePath, connection.ProcessId);
                        try
                        {
                            await PersistAsync();
                        }
                        catch (Exception persistError)
                        {
                            _diagnostics.LogException("Persist pending prompt suppression", persistError);
                        }
                    }

                    _watcher?.Snooze(connection.ExePath, TimeSpan.FromSeconds(2));
                    _queuedPrompts.Remove(connection.ExePath);
                    RefreshList();
                    SetStatus(LocalizationService.EffectiveLanguage == UiLanguage.Russian
                        ? $"Решение для {Path.GetFileName(connection.ExePath)} отложено; сеть остаётся заблокированной, повторный запрос для текущего запуска не показывается."
                        : $"Decision for {Path.GetFileName(connection.ExePath)} postponed; network remains blocked and this run will not prompt again.");
                    continue;
                }

                var access = prompt.Decision == PromptDecision.Allow
                    ? FirewallAccess.Allow
                    : FirewallAccess.Block;

                var application = FindApplication(connection.ExePath);
                var createdApplication = application is null;
                var previousAccess = application?.Access ?? FirewallAccess.Ask;
                var previousChanged = application?.FingerprintChanged ?? false;
                var previousUntil = application?.TemporaryAllowUntilUtc;
                var previousProcessId = application?.TemporaryAllowProcessId ?? 0;
                var previousTrustedSystem = application?.IsTrustedSystem ?? false;
                var previousTrustReason = application?.TrustReason ?? string.Empty;
                var previousSuppressPrompts = application?.SuppressPromptNotifications ?? false;

                if (application is null)
                {
                    application = CreateApplication(connection.ExePath, access);
                    await CaptureFingerprintBaselineAsync(application);
                    Applications.Add(application);
                }
                else
                {
                    // The user's decision acknowledges the executable that exists right now.
                    await CaptureFingerprintBaselineAsync(application);
                    application.Access = access;
                    application.RuleProfile = ApplicationRuleProfile.Default;
                    application.FingerprintChanged = false;
                }

                application.IsTrustedSystem = false;
                application.TrustReason = string.Empty;
                application.SuppressPromptNotifications = false;
                _promptSnoozedUntilExit.Remove(application.ExePath);
                ClearTemporaryAllow(application);

                if (access == FirewallAccess.Allow)
                {
                    switch (prompt.AllowScope)
                    {
                        case PromptAllowScope.TenMinutes:
                            application.TemporaryAllowUntilUtc = DateTime.UtcNow.AddMinutes(10);
                            break;
                        case PromptAllowScope.UntilProcessExit:
                            application.TemporaryAllowProcessId = connection.ProcessId;
                            break;
                    }
                }

                UpdateActivity(application, connection);

                try
                {
                    ApplyFirewallState();
                    await PersistAsync();
                    RefreshHandledPaths();
                    RefreshList();
                    SetStatus($"{application.Name}: {GetPromptActionResult(application, access)}.");
                }
                catch (Exception ex)
                {
                    if (createdApplication)
                    {
                        Applications.Remove(application);
                    }
                    else
                    {
                        application.Access = previousAccess;
                        application.FingerprintChanged = previousChanged;
                        application.TemporaryAllowUntilUtc = previousUntil;
                        application.TemporaryAllowProcessId = previousProcessId;
                        application.IsTrustedSystem = previousTrustedSystem;
                        application.TrustReason = previousTrustReason;
                        application.SuppressPromptNotifications = previousSuppressPrompts;
                    }

                    RefreshHandledPaths();
                    TryRestoreFirewallState("Rollback after prompt rule failure");
                    RefreshList();
                    ShowError(L("Не удалось применить выбранное правило.", "Failed to apply the selected rule."), ex);
                }
                finally
                {
                    _queuedPrompts.Remove(connection.ExePath);
                }
            }
        }
        catch (Exception ex)
        {
            _promptQueue.Clear();
            _queuedPrompts.Clear();
            ShowError(L("Ошибка обработки запроса сетевого доступа.", "Error while processing the network access prompt."), ex);
        }
        finally
        {
            _promptOpen = false;
        }
    }

    private static bool TryNormalizeLoadedApplication(
        ManagedApplication application,
        HashSet<string> seenPaths,
        HashSet<Guid> seenIds)
    {
        try
        {
            if (application is null ||
                string.IsNullOrWhiteSpace(application.ExePath) ||
                !Path.IsPathFullyQualified(application.ExePath))
            {
                return false;
            }

            var fullPath = Path.GetFullPath(application.ExePath);
            if (!fullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !seenPaths.Add(fullPath))
                return false;

            application.ExePath = fullPath;

            if (application.Id == Guid.Empty || !seenIds.Add(application.Id))
            {
                application.Id = Guid.NewGuid();
                seenIds.Add(application.Id);
            }

            if (!Enum.IsDefined(application.Access))
                application.Access = FirewallAccess.Ask;

            if (!Enum.IsDefined(application.RuleProfile) ||
                ((application.RuleProfile is ApplicationRuleProfile.EnableAll or ApplicationRuleProfile.OutgoingOnly or ApplicationRuleProfile.IncomingOnly) && application.Access != FirewallAccess.Allow) ||
                (application.RuleProfile == ApplicationRuleProfile.DisableAll && application.Access != FirewallAccess.Block) ||
                (application.RuleProfile == ApplicationRuleProfile.Ask && application.Access != FirewallAccess.Ask))
            {
                application.RuleProfile = ApplicationRuleProfile.Default;
            }

            // 0.7.0 migration: old 0.6.x Default rules were outbound-only in practice.
            // Preserve that behavior explicitly now that inbound enforcement exists.
            if (application.RuleProfile == ApplicationRuleProfile.Default && !application.IsTemporaryAllow)
            {
                application.RuleProfile = application.Access switch
                {
                    FirewallAccess.Allow => ApplicationRuleProfile.OutgoingOnly,
                    FirewallAccess.Block => ApplicationRuleProfile.DisableAll,
                    _ => ApplicationRuleProfile.Ask
                };
            }

            if (string.IsNullOrWhiteSpace(application.Name))
                application.Name = Path.GetFileNameWithoutExtension(fullPath);

            application.Name = new string(application.Name.Where(character => !char.IsControl(character)).ToArray()).Trim();
            if (string.IsNullOrWhiteSpace(application.Name))
                application.Name = Path.GetFileNameWithoutExtension(fullPath);
            if (application.Name.Length > 200)
                application.Name = application.Name[..200];

            NormalizeLegacyConnection(application);

            if (application.LastConnection?.Length > 300)
                application.LastConnection = application.LastConnection[..300];

            if (application.LastProtocol?.Length > 16)
                application.LastProtocol = application.LastProtocol[..16];

            if (application.Sha256?.Length > 128)
                application.Sha256 = string.Empty;

            if (!string.IsNullOrWhiteSpace(application.Sha256) &&
                (application.Sha256.Length != 64 || application.Sha256.Any(character => !Uri.IsHexDigit(character))))
            {
                application.Sha256 = string.Empty;
                application.FileLength = 0;
                application.FileLastWriteUtc = null;
                application.FingerprintChanged = false;
            }

            application.Publisher = SanitizeMetadata(application.Publisher, 200);
            application.SignatureStatus = SanitizeMetadata(application.SignatureStatus, 120);
            application.TrustReason = SanitizeMetadata(application.TrustReason, 500);

            if (application.TemporaryAllowProcessId < 0)
                application.TemporaryAllowProcessId = 0;

            if (application.TemporaryAllowUntilUtc is DateTime temporaryUntil && temporaryUntil.Kind != DateTimeKind.Utc)
                application.TemporaryAllowUntilUtc = temporaryUntil.ToUniversalTime();

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void NormalizeLegacyConnection(ManagedApplication application)
    {
        if (string.IsNullOrWhiteSpace(application.LastConnection))
            return;

        var value = application.LastConnection.Trim();
        var protocol = string.Empty;

        if (value.StartsWith("TCP →", StringComparison.OrdinalIgnoreCase))
        {
            protocol = "TCP";
            value = value[5..].Trim();
        }
        else if (value.StartsWith("TCP ->", StringComparison.OrdinalIgnoreCase))
        {
            protocol = "TCP";
            value = value[6..].Trim();
        }
        else if (value.StartsWith("UDP →", StringComparison.OrdinalIgnoreCase))
        {
            protocol = "UDP";
            value = value[5..].Trim();
        }
        else if (value.StartsWith("UDP ->", StringComparison.OrdinalIgnoreCase))
        {
            protocol = "UDP";
            value = value[6..].Trim();
        }

        if (string.IsNullOrWhiteSpace(protocol))
            return;

        application.LastConnection = value;
        application.LastProtocol = protocol;
        if (protocol == "TCP")
            application.SeenTcp = true;
        else
            application.SeenUdp = true;
    }

    private static string SanitizeMetadata(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var result = new string(value.Where(character => !char.IsControl(character)).ToArray()).Trim();
        return result.Length <= maxLength ? result : result[..maxLength];
    }

    private ManagedApplication CreateApplication(string exePath, FirewallAccess access)
    {
        var name = Path.GetFileNameWithoutExtension(exePath);

        try
        {
            var version = FileVersionInfo.GetVersionInfo(exePath);
            if (!string.IsNullOrWhiteSpace(version.FileDescription))
                name = version.FileDescription;
        }
        catch
        {
        }

        name = new string(name.Where(character => !char.IsControl(character)).ToArray()).Trim();
        if (string.IsNullOrWhiteSpace(name))
            name = Path.GetFileNameWithoutExtension(exePath);
        if (name.Length > 200)
            name = name[..200];

        var application = new ManagedApplication
        {
            Name = name,
            ExePath = exePath,
            Access = access,
            IconSource = ExecutableMetadataService.TryLoadIcon(exePath)
        };

        if (ExecutableMetadataService.TryGetFileState(exePath, out var state))
        {
            application.FileLength = state.Length;
            application.FileLastWriteUtc = state.LastWriteUtc;
        }

        return application;
    }

    private static void UpdateActivity(ManagedApplication application, NetworkConnectionInfo connection)
    {
        application.LastSeenAt = connection.SeenAt;
        application.LastProtocol = connection.Protocol;
        if (connection.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            application.SeenTcp = true;
        else if (connection.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
            application.SeenUdp = true;

        application.LastConnection = connection.ActivityDisplay;

        if (connection.ProcessSnapshot.HasData)
        {
            application.ParentProcessId = connection.ProcessSnapshot.ParentProcessId;
            application.ParentProcessName = connection.ProcessSnapshot.ParentProcessName;
            application.ParentProcessPath = connection.ProcessSnapshot.ParentProcessPath;
        }
    }

    private ManagedApplication? FindApplication(string exePath) =>
        Applications.FirstOrDefault(app => string.Equals(app.ExePath, exePath, StringComparison.OrdinalIgnoreCase));

    private bool IsSelfPath(string exePath) =>
        !string.IsNullOrWhiteSpace(_selfExePath) &&
        string.Equals(_selfExePath, exePath, StringComparison.OrdinalIgnoreCase);

    private bool IsHandledPath(string exePath)
    {
        lock (_handledPathsLock)
            return _handledPaths.Contains(exePath);
    }

    private void RefreshHandledPaths()
    {
        lock (_handledPathsLock)
        {
            _handledPaths.Clear();

            if (!string.IsNullOrWhiteSpace(_selfExePath))
                _handledPaths.Add(_selfExePath);

            foreach (var app in Applications)
            {
                if (_mode == FirewallMode.Monitor || app.Access is FirewallAccess.Allow or FirewallAccess.Block)
                    _handledPaths.Add(app.ExePath);
            }
        }
    }

    private ManagedApplication? SelectedApplication => ApplicationsList.SelectedItem as ManagedApplication;

    private void ApplicationsList_PreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (FindVisualParent<System.Windows.Controls.ListViewItem>(e.OriginalSource as DependencyObject) is { } item)
        {
            item.IsSelected = true;
            item.Focus();
            return;
        }

        ApplicationsList.SelectedItem = null;
    }

    private void ApplicationsContextMenu_Opened(object sender, RoutedEventArgs e)
    {
        var application = SelectedApplication;
        var hasSelection = application is not null;

        ContextAllowItem.Visibility = hasSelection && (application!.Access != FirewallAccess.Allow || application.IsTemporaryAllow)
            ? Visibility.Visible
            : Visibility.Collapsed;

        ContextBlockItem.Visibility = hasSelection && (application!.Access != FirewallAccess.Block || application.FingerprintChanged)
            ? Visibility.Visible
            : Visibility.Collapsed;

        ContextAskItem.Visibility = hasSelection && application!.Access != FirewallAccess.Ask
            ? Visibility.Visible
            : Visibility.Collapsed;

        ContextQuickRulesItem.IsEnabled = hasSelection;
        ContextTemporaryAccessItem.IsEnabled = hasSelection;

        ContextQuickEnableAllItem.IsChecked = hasSelection &&
            application!.Access == FirewallAccess.Allow &&
            application.RuleProfile == ApplicationRuleProfile.EnableAll;
        ContextQuickOutgoingOnlyItem.IsChecked = hasSelection &&
            application!.Access == FirewallAccess.Allow &&
            application.RuleProfile == ApplicationRuleProfile.OutgoingOnly;
        ContextQuickIncomingOnlyItem.IsEnabled = hasSelection && _settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp;
        ContextQuickIncomingOnlyItem.IsChecked = hasSelection &&
            application!.Access == FirewallAccess.Allow &&
            application.RuleProfile == ApplicationRuleProfile.IncomingOnly;
        ContextQuickDisableAllItem.IsChecked = hasSelection &&
            application!.Access == FirewallAccess.Block &&
            (application.RuleProfile == ApplicationRuleProfile.DisableAll || application.RuleProfile == ApplicationRuleProfile.Default);
        ContextQuickAskItem.IsChecked = hasSelection && application!.Access == FirewallAccess.Ask;

        ContextShowPromptItem.Visibility = hasSelection && application!.Access == FirewallAccess.Ask
            ? Visibility.Visible
            : Visibility.Collapsed;
        ContextMutePromptItem.Visibility = hasSelection && application!.Access == FirewallAccess.Ask
            ? Visibility.Visible
            : Visibility.Collapsed;
        ContextMutePromptItem.IsChecked = hasSelection && application!.SuppressPromptNotifications;

        ContextPropertiesItem.IsEnabled = hasSelection;
        ContextOpenLocationItem.IsEnabled = hasSelection;
        ContextResetStatisticsItem.IsEnabled = hasSelection;
        ContextRemoveItem.IsEnabled = hasSelection;
    }

    private async void ContextAllow_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Allow);
    }

    private async void ContextBlock_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Block);
    }

    private async void ContextAsk_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Ask);
    }

    private async void ContextQuickEnableAll_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Allow, ApplicationRuleProfile.EnableAll);
    }

    private async void ContextQuickOutgoingOnly_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Allow, ApplicationRuleProfile.OutgoingOnly);
    }

    private async void ContextQuickIncomingOnly_Click(object sender, RoutedEventArgs e)
    {
        if (_settings.BackendMode != FirewallBackendMode.GeniaFirewallWfp)
            return;

        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Allow, ApplicationRuleProfile.IncomingOnly);
    }

    private async void ContextQuickDisableAll_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetAccessAsync(application, FirewallAccess.Block, ApplicationRuleProfile.DisableAll);
    }

    private async void ContextQuickAsk_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is not { } application)
            return;

        await SetAccessAsync(application, FirewallAccess.Ask, ApplicationRuleProfile.Ask);
        if (application.Access != FirewallAccess.Ask)
            return;

        var processId = TryFindRunningProcessId(application.ExePath);
        if (processId <= 0)
            return;

        var protocol = application.LastProtocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ? "UDP" : "TCP";
        QueuePrompt(new NetworkConnectionInfo(processId, application.ExePath, protocol, string.Empty, 0, 0, DateTime.Now), force: true);
    }

    private async void ContextTempTenMinutes_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetTemporaryAllowAsync(application, untilProcessExit: false);
    }

    private async void ContextTempUntilExit_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await SetTemporaryAllowAsync(application, untilProcessExit: true);
    }

    private async Task SetTemporaryAllowAsync(ManagedApplication application, bool untilProcessExit)
    {
        var processId = 0;
        if (untilProcessExit)
        {
            processId = TryFindRunningProcessId(application.ExePath);
            if (processId <= 0)
            {
                SetStatus(L(
                    $"{application.Name}: приложение не запущено — правило «до закрытия» не создано.",
                    $"{application.Name}: the application is not running — the until-exit rule was not created."));
                return;
            }
        }

        var previousAccess = application.Access;
        var previousRuleProfile = application.RuleProfile;
        var previousChanged = application.FingerprintChanged;
        var previousSha = application.Sha256;
        var previousLength = application.FileLength;
        var previousWrite = application.FileLastWriteUtc;
        var previousTrustedSystem = application.IsTrustedSystem;
        var previousTrustReason = application.TrustReason;
        var previousUntil = application.TemporaryAllowUntilUtc;
        var previousProcessId = application.TemporaryAllowProcessId;
        var previousSuppressPrompts = application.SuppressPromptNotifications;

        try
        {
            await CaptureFingerprintBaselineAsync(application);
            application.Access = FirewallAccess.Allow;
            application.RuleProfile = ApplicationRuleProfile.Default;
            application.FingerprintChanged = false;
            application.IsTrustedSystem = false;
            application.TrustReason = string.Empty;
            application.SuppressPromptNotifications = false;
            _promptSnoozedUntilExit.Remove(application.ExePath);
            ClearTemporaryAllow(application);

            if (untilProcessExit)
                application.TemporaryAllowProcessId = processId;
            else
                application.TemporaryAllowUntilUtc = DateTime.UtcNow.AddMinutes(10);

            ApplyFirewallState();
            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(untilProcessExit
                ? L($"{application.Name}: разрешено до закрытия приложения.", $"{application.Name}: allowed until the application exits.")
                : L($"{application.Name}: разрешено на 10 минут.", $"{application.Name}: allowed for 10 minutes."));
        }
        catch (Exception ex)
        {
            application.Access = previousAccess;
            application.RuleProfile = previousRuleProfile;
            application.FingerprintChanged = previousChanged;
            application.Sha256 = previousSha;
            application.FileLength = previousLength;
            application.FileLastWriteUtc = previousWrite;
            application.IsTrustedSystem = previousTrustedSystem;
            application.TrustReason = previousTrustReason;
            application.TemporaryAllowUntilUtc = previousUntil;
            application.TemporaryAllowProcessId = previousProcessId;
            application.SuppressPromptNotifications = previousSuppressPrompts;
            RefreshHandledPaths();
            TryRestoreFirewallState("Rollback after temporary quick rule failure");
            RefreshList();
            ShowError(L("Не удалось применить временное правило.", "Failed to apply the temporary rule."), ex);
        }
    }

    private async void ContextMutePrompt_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is not { } application || application.Access != FirewallAccess.Ask)
            return;

        application.SuppressPromptNotifications = ContextMutePromptItem.IsChecked;
        if (!application.SuppressPromptNotifications)
            _promptSnoozedUntilExit.Remove(application.ExePath);

        try
        {
            await PersistAsync();
            RefreshList();
            SetStatus(application.SuppressPromptNotifications
                ? (LocalizationService.EffectiveLanguage == UiLanguage.Russian
                    ? $"{application.Name}: автоматические напоминания отключены; сеть остаётся заблокированной до решения."
                    : $"{application.Name}: automatic reminders disabled; network remains blocked until a decision is made.")
                : (LocalizationService.EffectiveLanguage == UiLanguage.Russian
                    ? $"{application.Name}: автоматические напоминания включены."
                    : $"{application.Name}: automatic reminders enabled."));
        }
        catch (Exception ex)
        {
            ShowError(LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? "Не удалось изменить настройку напоминаний."
                : "Failed to change reminder settings.", ex);
        }
    }

    private void ContextShowPrompt_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is not { } application || application.Access != FirewallAccess.Ask)
            return;

        application.SuppressPromptNotifications = false;
        _promptSnoozedUntilExit.Remove(application.ExePath);

        var processId = TryFindRunningProcessId(application.ExePath);
        if (processId <= 0)
        {
            SetStatus(LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? $"{application.Name}: приложение сейчас не запущено; запрос появится при следующем запуске."
                : $"{application.Name}: the application is not running; the prompt will appear on its next launch.");
            _ = PersistAsync();
            return;
        }

        var protocol = application.LastProtocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ? "UDP" : "TCP";
        QueuePrompt(new NetworkConnectionInfo(processId, application.ExePath, protocol, string.Empty, 0, 0, DateTime.Now), force: true);
        _ = PersistAsync();
    }

    private void ContextProperties_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            ShowApplicationProperties(application);
    }

    private void ApplicationsList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FindVisualParent<System.Windows.Controls.ListViewItem>(e.OriginalSource as DependencyObject) is null)
            return;

        if (SelectedApplication is { } application)
            ShowApplicationProperties(application);
    }

    private void ShowApplicationProperties(ManagedApplication application)
    {
        var lastSeen = application.LastSeenAt is null
            ? "—"
            : application.LastSeenAt.Value.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss");

        var lastConnection = string.IsNullOrWhiteSpace(application.LastConnection)
            ? "—"
            : application.LastConnection;

        var russian = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
        var temporaryRule = application.TemporaryAllowProcessId > 0
            ? russian
                ? $"До закрытия процесса · PID {application.TemporaryAllowProcessId}"
                : $"Until process exit · PID {application.TemporaryAllowProcessId}"
            : application.TemporaryAllowUntilUtc is DateTime untilUtc
                ? russian
                    ? $"До {untilUtc.ToLocalTime():dd.MM.yyyy HH:mm:ss}"
                    : $"Until {untilUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
                : "—";

        var text = russian
            ? $"{application.Name}\n\n" +
              $"Статус: {application.AccessLabel}\n" +
              $"Быстрое правило: {(application.HasQuickRuleProfile ? application.RuleProfileLabel : "—")}\n" +
              $"Временное правило: {temporaryRule}\n" +
              $"Напоминания: {(application.SuppressPromptNotifications ? "отключены" : "включены")}\n" +
              $"Последняя активность: {lastSeen}\n" +
              $"Протоколы: {application.ProtocolLabel}\n" +
              $"Последнее соединение: {lastConnection}\n" +
              $"Издатель: {(string.IsNullOrWhiteSpace(application.Publisher) ? "—" : application.Publisher)}\n" +
              $"Подпись: {(string.IsNullOrWhiteSpace(application.SignatureStatus) ? "не проверена" : application.SignatureStatus)}\n" +
              $"Доверие системе: {(application.IsTrustedSystem ? "Да — авто-разрешение" : "Нет")}\n" +
              $"Причина доверия: {(string.IsNullOrWhiteSpace(application.TrustReason) ? "—" : application.TrustReason)}\n" +
              $"Файл изменён: {(application.FingerprintChanged ? "Да — требуется новое решение" : "Нет")}\n" +
              $"SHA-256: {(string.IsNullOrWhiteSpace(application.Sha256) ? "ещё не зафиксирован" : application.Sha256)}\n\n" +
              $"{application.ExePath}"
            : $"{application.Name}\n\n" +
              $"Status: {application.AccessLabel}\n" +
              $"Quick rule: {(application.HasQuickRuleProfile ? application.RuleProfileLabel : "—")}\n" +
              $"Temporary rule: {temporaryRule}\n" +
              $"Reminders: {(application.SuppressPromptNotifications ? "disabled" : "enabled")}\n" +
              $"Last activity: {lastSeen}\n" +
              $"Protocols: {application.ProtocolLabel}\n" +
              $"Last connection: {lastConnection}\n" +
              $"Publisher: {(string.IsNullOrWhiteSpace(application.Publisher) ? "—" : application.Publisher)}\n" +
              $"Signature: {(string.IsNullOrWhiteSpace(application.SignatureStatus) ? "not checked" : application.SignatureStatus)}\n" +
              $"System trust: {(application.IsTrustedSystem ? "Yes — auto-allow" : "No")}\n" +
              $"Trust reason: {(string.IsNullOrWhiteSpace(application.TrustReason) ? "—" : application.TrustReason)}\n" +
              $"Executable changed: {(application.FingerprintChanged ? "Yes — a new decision is required" : "No")}\n" +
              $"SHA-256: {(string.IsNullOrWhiteSpace(application.Sha256) ? "not captured yet" : application.Sha256)}\n\n" +
              $"{application.ExePath}";

        System.Windows.MessageBox.Show(
            this,
            text,
            russian ? "Свойства приложения — GeniaFirewall" : "Application properties — GeniaFirewall",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void ContextOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        var application = SelectedApplication;
        if (application is null)
            return;

        if (!File.Exists(application.ExePath))
        {
            SetStatus(L("Исполняемый файл больше не существует.", "The executable file no longer exists."));
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"/select,\"{application.ExePath}\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            ShowError(L("Не удалось открыть расположение файла.", "Failed to open the file location."), ex);
        }
    }

    private async void ContextResetStatistics_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is not { } application)
            return;

        application.LastSeenAt = null;
        application.LastConnection = string.Empty;
        application.LastProtocol = string.Empty;
        application.SeenTcp = false;
        application.SeenUdp = false;
        await PersistAsync();
        RefreshList();
        SetStatus(L($"Статистика {application.Name} сброшена.", $"Statistics for {application.Name} were reset."));
    }

    private async void ContextRemove_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedApplication is { } application)
            await RemoveApplicationAsync(application);
    }

    private async void ContextRemoveMissing_Click(object sender, RoutedEventArgs e)
    {
        var missing = Applications
            .Select((application, index) => (Application: application, Index: index))
            .Where(item => !File.Exists(item.Application.ExePath))
            .ToList();

        if (missing.Count == 0)
        {
            SetStatus(L("Отсутствующих приложений нет.", "There are no missing applications."));
            return;
        }

        try
        {
            // First remove the corresponding firewall rules while the in-memory database is still intact.
            // If any COM operation fails, the catch block can reconstruct all rules from the unchanged list.
            foreach (var item in missing)
                _firewall.RemoveRules(item.Application.Id);

            // Remove from the end so the original indices remain valid during the transaction.
            foreach (var item in missing.OrderByDescending(item => item.Index))
                Applications.RemoveAt(item.Index);

            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            SetStatus(L($"Удалено отсутствующих приложений: {missing.Count}.", $"Removed missing applications: {missing.Count}."));
        }
        catch (Exception ex)
        {
            // Restore the collection and rules so a failed maintenance operation does not leave
            // the portable database and Windows Firewall in different states.
            foreach (var item in missing.OrderBy(item => item.Index))
            {
                if (Applications.Contains(item.Application))
                    continue;

                Applications.Insert(Math.Min(item.Index, Applications.Count), item.Application);
            }

            TryRestoreFirewallState("Rollback after remove-missing failure");

            try
            {
                await PersistAsync();
            }
            catch (Exception persistError)
            {
                _diagnostics.LogException("Persist rollback after remove-missing failure", persistError);
            }

            RefreshHandledPaths();
            RefreshList();
            ShowError(L("Не удалось удалить отсутствующие приложения. Изменения отменены.", "Failed to remove missing applications. Changes were rolled back."), ex);
        }
    }

    private void ContextRefresh_Click(object sender, RoutedEventArgs e)
    {
        RefreshList();
        SetStatus(L("Список обновлён.", "List refreshed."));
    }

    private void MainWindow_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.F5)
        {
            RefreshList();
            SetStatus(L("Список обновлён.", "List refreshed."));
            e.Handled = true;
            return;
        }

        // Delete never terminates the Windows process itself. In WFP Normal mode 0.6.3 may
        // immediately forget the old decision into ASK-BLOCK quarantine when that EXE is still
        // running; otherwise the entry and its GeniaFirewall rule are removed as before.
        // Guard against accidental deletion
        // while the user is typing in Search or another text control.
        if (e.Key == Key.Delete && ApplicationsList.IsKeyboardFocusWithin && SelectedApplication is { } application)
        {
            e.Handled = true;
            RunUiTask(() => RemoveApplicationAsync(application), L("Не удалось удалить приложение из списка.", "Failed to remove the application from the list."));
        }
    }

    private void ColumnHeader_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not GridViewColumnHeader header || header.Tag is not string propertyName || string.IsNullOrWhiteSpace(propertyName))
            return;

        if (ReferenceEquals(_sortHeader, header) && string.Equals(_sortProperty, propertyName, StringComparison.Ordinal))
        {
            _sortDirection = _sortDirection == ListSortDirection.Ascending
                ? ListSortDirection.Descending
                : ListSortDirection.Ascending;
        }
        else
        {
            _sortHeader = header;
            _sortProperty = propertyName;
            _sortDirection = ListSortDirection.Ascending;
        }

        ApplyCurrentSort();
        UpdateSortHeaderLabels();
        SetStatus($"Сортировка: {GetSortDisplayName(propertyName)} {(_sortDirection == ListSortDirection.Ascending ? "▲" : "▼")}.");
    }

    private void ApplyCurrentSort()
    {
        using (_applicationsView.DeferRefresh())
        {
            _applicationsView.SortDescriptions.Clear();
            if (string.IsNullOrWhiteSpace(_sortProperty))
                return;

            _applicationsView.SortDescriptions.Add(new SortDescription(_sortProperty, _sortDirection));

            // A stable secondary key prevents rows with equal values from changing order
            // every time network activity refreshes the view.
            if (!string.Equals(_sortProperty, nameof(ManagedApplication.Name), StringComparison.Ordinal))
                _applicationsView.SortDescriptions.Add(new SortDescription(nameof(ManagedApplication.Name), ListSortDirection.Ascending));
        }
    }

    private void UpdateSortHeaderLabels()
    {
        ProgramHeader.Content = BuildSortHeaderLabel(LocalizationService.Get("Column.Program"), nameof(ManagedApplication.Name));
        StatusHeader.Content = BuildSortHeaderLabel(LocalizationService.Get("Column.Status"), nameof(ManagedApplication.AccessLabel));
        TrustHeader.Content = BuildSortHeaderLabel(LocalizationService.Get("Column.Trust"), nameof(ManagedApplication.TrustLabel));
        ProtocolHeader.Content = BuildSortHeaderLabel(LocalizationService.Get("Column.Protocol"), nameof(ManagedApplication.ProtocolLabel));
        ActivityHeader.Content = BuildSortHeaderLabel(LocalizationService.Get("Column.Activity"), nameof(ManagedApplication.LastSeenAt));
        ConnectionHeader.Content = BuildSortHeaderLabel(LocalizationService.Get("Column.Connection"), nameof(ManagedApplication.LastConnection));
    }

    private string BuildSortHeaderLabel(string title, string propertyName)
    {
        if (!string.Equals(_sortProperty, propertyName, StringComparison.Ordinal))
            return title;

        return $"{title} {(_sortDirection == ListSortDirection.Ascending ? "▲" : "▼")}";
    }

    private static string GetSortDisplayName(string propertyName) => propertyName switch
    {
        nameof(ManagedApplication.Name) => LocalizationService.Get("Column.Program"),
        nameof(ManagedApplication.AccessLabel) => LocalizationService.Get("Column.Status"),
        nameof(ManagedApplication.TrustLabel) => LocalizationService.Get("Column.Trust"),
        nameof(ManagedApplication.ProtocolLabel) => LocalizationService.Get("Column.Protocol"),
        nameof(ManagedApplication.LastSeenAt) => LocalizationService.Get("Column.Activity"),
        nameof(ManagedApplication.LastConnection) => LocalizationService.Get("Column.Connection"),
        _ => propertyName
    };

    private void ApplicationsList_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateColumnWidths();

    private void UpdateColumnWidths()
    {
        if (!IsLoaded || ApplicationsList.ActualWidth <= 0)
            return;

        // Keep room for the permanently reserved vertical scrollbar and ListView borders.
        var available = Math.Max(620, ApplicationsList.ActualWidth - 24);
        var statusWidth = 112d;
        var trustWidth = 96d;
        var protocolWidth = 72d;
        var activityWidth = 126d;
        var programWidth = Math.Clamp(available * 0.36, 225d, 340d);
        var connectionWidth = available - programWidth - statusWidth - trustWidth - protocolWidth - activityWidth;

        if (connectionWidth < 170)
        {
            var shortage = 170 - connectionWidth;
            programWidth = Math.Max(220, programWidth - shortage);
            connectionWidth = available - programWidth - statusWidth - trustWidth - protocolWidth - activityWidth;
        }

        ProgramColumn.Width = Math.Floor(programWidth);
        StatusColumn.Width = statusWidth;
        TrustColumn.Width = trustWidth;
        ProtocolColumn.Width = protocolWidth;
        ActivityColumn.Width = activityWidth;
        ConnectionColumn.Width = Math.Max(150, Math.Floor(connectionWidth));
    }

    private void RefreshList()
    {
        var selectedId = SelectedApplication?.Id;
        var scrollViewer = FindVisualChild<ScrollViewer>(ApplicationsList);
        var verticalOffset = scrollViewer?.VerticalOffset ?? 0;

        _applicationsView.Refresh();
        ApplicationsList.Items.Refresh();
        UpdateEmptyState();
        UpdateSummary();
        UpdateColumnWidths();

        if (selectedId is Guid id)
            ApplicationsList.SelectedItem = Applications.FirstOrDefault(app => app.Id == id);

        _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            var viewer = FindVisualChild<ScrollViewer>(ApplicationsList);
            if (viewer is not null)
                viewer.ScrollToVerticalOffset(Math.Min(verticalOffset, viewer.ScrollableHeight));

            UpdateColumnWidths();
        }));
    }

    private void UpdateEmptyState()
    {
        EmptyState.Visibility = Applications.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void UpdateSummary()
    {
        var blocked = Applications.Count(app => app.Access == FirewallAccess.Block);
        var unknown = Applications.Count(app => app.Access == FirewallAccess.Ask);
        var changed = Applications.Count(app => app.FingerprintChanged);
        var trusted = Applications.Count(app => app.IsTrustedSystem);
        var temporary = Applications.Count(app => app.IsTemporaryAllow);
        SummaryText.Text = LocalizationService.EffectiveLanguage == UiLanguage.Russian
            ? changed > 0
                ? $"{Applications.Count} приложений · системных: {trusted} · временных: {temporary} · блок: {blocked} · неизвестно: {unknown} · изменено: {changed}"
                : $"{Applications.Count} приложений · системных: {trusted} · временных: {temporary} · блок: {blocked} · неизвестно: {unknown}"
            : changed > 0
                ? $"{Applications.Count} apps · system: {trusted} · temporary: {temporary} · blocked: {blocked} · pending: {unknown} · changed: {changed}"
                : $"{Applications.Count} apps · system: {trusted} · temporary: {temporary} · blocked: {blocked} · pending: {unknown}";
    }

    private List<ManagedApplication> CreateApplicationsSnapshot() =>
        Applications.Select(application => new ManagedApplication
        {
            Id = application.Id,
            Name = application.Name,
            ExePath = application.ExePath,
            Access = application.Access,
            RuleProfile = application.RuleProfile,
            LastSeenAt = application.LastSeenAt,
            LastConnection = application.LastConnection,
            LastProtocol = application.LastProtocol,
            SeenTcp = application.SeenTcp,
            SeenUdp = application.SeenUdp,
            Sha256 = application.Sha256,
            FileLength = application.FileLength,
            FileLastWriteUtc = application.FileLastWriteUtc,
            FingerprintChanged = application.FingerprintChanged,
            Publisher = application.Publisher,
            SignatureStatus = application.SignatureStatus,
            SignatureTrusted = application.SignatureTrusted,
            IsTrustedSystem = application.IsTrustedSystem,
            TrustReason = application.TrustReason,
            TemporaryAllowUntilUtc = application.TemporaryAllowUntilUtc,
            TemporaryAllowProcessId = application.TemporaryAllowProcessId,
            SuppressPromptNotifications = application.SuppressPromptNotifications
        }).ToList();

    private async Task PersistAsync()
    {
        // Serialize a stable snapshot so UI changes cannot mutate the collection during async file I/O.
        await _store.SaveApplicationsAsync(CreateApplicationsSnapshot());
    }

    private async void ActivityPersistTimer_Tick(object? sender, EventArgs e)
    {
        if (!_activityDirty)
            return;

        try
        {
            await PersistAsync();
            _activityDirty = false;

            // Activity/protocol/endpoint values can change without a full list rebuild.
            // Refresh an active dynamic sort only on the batched timer, not on every
            // network event, so the UI remains stable under heavy traffic.
            if (_sortProperty is nameof(ManagedApplication.LastSeenAt)
                or nameof(ManagedApplication.ProtocolLabel)
                or nameof(ManagedApplication.LastConnection))
            {
                _applicationsView.Refresh();
            }
        }
        catch (Exception ex)
        {
            _diagnostics.LogException("Persist network activity", ex);
        }
    }

    private async Task CaptureFingerprintBaselineAsync(ManagedApplication application)
    {
        try
        {
            var fingerprint = await Task.Run(() => ExecutableMetadataService.ComputeFingerprint(application.ExePath));
            application.Sha256 = fingerprint.Sha256;
            application.FileLength = fingerprint.Length;
            application.FileLastWriteUtc = fingerprint.LastWriteUtc;
            await RefreshTrustMetadataAsync(application);
        }
        catch (Exception ex)
        {
            _diagnostics.LogException($"Capture executable fingerprint: {application.ExePath}", ex);
        }
    }

    private async Task<bool> VerifyFingerprintAsync(ManagedApplication application, bool establishBaselineIfMissing)
    {
        if (string.IsNullOrWhiteSpace(application.ExePath) || !File.Exists(application.ExePath))
            return false;

        if (!_fingerprintChecks.Add(application.ExePath))
            return false;

        try
        {
            if (!ExecutableMetadataService.TryGetFileState(application.ExePath, out var state))
                return false;

            if (string.IsNullOrWhiteSpace(application.Sha256))
            {
                // 0.3.1 databases have no hash. Do not treat the upgrade itself as a file change.
                application.FileLength = state.Length;
                application.FileLastWriteUtc = state.LastWriteUtc;
                if (establishBaselineIfMissing)
                    await CaptureFingerprintBaselineAsync(application);
                return false;
            }

            if (application.FileLength == state.Length &&
                application.FileLastWriteUtc is DateTime storedWrite &&
                storedWrite == state.LastWriteUtc)
            {
                return false;
            }

            var fingerprint = await Task.Run(() => ExecutableMetadataService.ComputeFingerprint(application.ExePath));
            var changed = !string.Equals(application.Sha256, fingerprint.Sha256, StringComparison.OrdinalIgnoreCase);

            application.Sha256 = fingerprint.Sha256;
            application.FileLength = fingerprint.Length;
            application.FileLastWriteUtc = fingerprint.LastWriteUtc;
            if (changed)
                await RefreshTrustMetadataAsync(application);

            return changed;
        }
        catch (Exception ex)
        {
            _diagnostics.LogException($"Verify executable fingerprint: {application.ExePath}", ex);
            return false;
        }
        finally
        {
            _fingerprintChecks.Remove(application.ExePath);
        }
    }

    private async Task RefreshTrustMetadataAsync(ManagedApplication application)
    {
        try
        {
            var signature = await Task.Run(() => ExecutableMetadataService.GetSignatureInfo(application.ExePath));
            application.Publisher = signature.Publisher;
            application.SignatureStatus = signature.StatusLabel;
            application.SignatureTrusted = signature.IsTrusted;
        }
        catch (Exception ex)
        {
            _diagnostics.LogException($"Verify Authenticode signature: {application.ExePath}", ex);
        }
    }

    private async void TemporaryRuleTimer_Tick(object? sender, EventArgs e)
    {
        if (_temporaryRuleSweepRunning)
            return;

        _temporaryRuleSweepRunning = true;
        try
        {
            var expired = Applications
                .Where(application => application.Access == FirewallAccess.Allow && application.IsTemporaryAllow)
                .Where(IsTemporaryAllowExpired)
                .ToList();

            if (expired.Count == 0)
                return;

            var snapshots = expired.Select(application => new
            {
                App = application,
                application.Access,
                application.RuleProfile,
                application.TemporaryAllowUntilUtc,
                application.TemporaryAllowProcessId
            }).ToList();

            foreach (var application in expired)
            {
                application.Access = FirewallAccess.Ask;
                application.RuleProfile = ApplicationRuleProfile.Default;
                ClearTemporaryAllow(application);
            }

            try
            {
                ApplyFirewallState();
                await PersistAsync();
                RefreshHandledPaths();
                RefreshList();
                SetStatus(expired.Count == 1
                    ? $"{expired[0].Name}: временное разрешение завершено — снова спрашивать."
                    : $"Завершено временных разрешений: {expired.Count}. Приложения снова в режиме «Спрашивать»." );
            }
            catch (Exception ex)
            {
                foreach (var snapshot in snapshots)
                {
                    snapshot.App.Access = snapshot.Access;
                    snapshot.App.RuleProfile = snapshot.RuleProfile;
                    snapshot.App.TemporaryAllowUntilUtc = snapshot.TemporaryAllowUntilUtc;
                    snapshot.App.TemporaryAllowProcessId = snapshot.TemporaryAllowProcessId;
                }

                RefreshHandledPaths();
                TryRestoreFirewallState("Rollback after temporary rule expiration failure");
                _diagnostics.LogException("Expire temporary firewall rule", ex);
            }
        }
        finally
        {
            _temporaryRuleSweepRunning = false;
        }
    }

    private static bool IsTemporaryAllowExpired(ManagedApplication application)
    {
        if (application.TemporaryAllowUntilUtc is DateTime untilUtc && untilUtc <= DateTime.UtcNow)
            return true;

        if (application.TemporaryAllowProcessId > 0 &&
            !ProcessIdentityService.IsSameProcessImageRunning(application.TemporaryAllowProcessId, application.ExePath))
        {
            return true;
        }

        return false;
    }

    private static bool NormalizeTemporaryAllowOnStartup(ManagedApplication application)
    {
        var changed = false;

        if (application.Access != FirewallAccess.Allow || application.IsTrustedSystem)
        {
            if (application.IsTemporaryAllow)
            {
                ClearTemporaryAllow(application);
                changed = true;
            }

            return changed;
        }

        // A process-instance decision cannot safely survive a GeniaFirewall restart because a PID
        // can be reused. Fail closed by returning the application to Ask.
        if (application.TemporaryAllowProcessId > 0)
        {
            ClearTemporaryAllow(application);
            application.Access = FirewallAccess.Ask;
            application.RuleProfile = ApplicationRuleProfile.Default;
            return true;
        }

        if (application.TemporaryAllowUntilUtc is DateTime untilUtc)
        {
            // 0.5.x only creates ten-minute rules. Reject implausibly long values from damaged or
            // manually edited portable data rather than silently allowing them.
            if (untilUtc <= DateTime.UtcNow || untilUtc > DateTime.UtcNow.AddHours(1))
            {
                ClearTemporaryAllow(application);
                application.Access = FirewallAccess.Ask;
                application.RuleProfile = ApplicationRuleProfile.Default;
                return true;
            }
        }

        return changed;
    }

    private static void ClearTemporaryAllow(ManagedApplication application)
    {
        application.TemporaryAllowUntilUtc = null;
        application.TemporaryAllowProcessId = 0;
    }

    private async Task<NetworkConnectionInfo> ResolveHostNameIfEnabledAsync(NetworkConnectionInfo connection)
    {
        if (!_settings.ResolveHostNames)
            return connection;

        return await _hostnameResolver.EnrichAsync(connection);
    }

    private async Task ExportConfigurationAsync(string filePath)
    {
        await PersistAsync();
        await _store.ExportConfigurationAsync(filePath, CreateApplicationsSnapshot(), BuildSettingsSnapshot());
        _diagnostics.Log($"Configuration exported: {filePath}");
    }

    private async Task<AppSettings> ImportConfigurationAsync(string filePath)
    {
        var configuration = await _store.ImportConfigurationAsync(filePath);
        var imported = new List<ManagedApplication>();
        var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenIds = new HashSet<Guid>();

        foreach (var application in configuration.Applications)
        {
            if (!TryNormalizeLoadedApplication(application, seenPaths, seenIds) || IsSelfPath(application.ExePath))
                continue;

            // "Trusted System" is machine/runtime evidence, not portable policy. Never import the
            // trust badge/reason from another JSON file without a live PID/service validation.
            application.IsTrustedSystem = false;
            application.TrustReason = string.Empty;

            // Temporary decisions are local runtime state. Importing them as permanent Allow would
            // silently broaden policy, so return them to Ask.
            if (application.IsTemporaryAllow)
            {
                if (application.Access == FirewallAccess.Allow)
                    application.Access = FirewallAccess.Ask;
                application.RuleProfile = ApplicationRuleProfile.Default;
                ClearTemporaryAllow(application);
            }

            application.IconSource = ExecutableMetadataService.TryLoadIcon(application.ExePath);
            if (File.Exists(application.ExePath))
            {
                // Imported rules are never trusted by path alone: bind them to the current executable.
                var hadFingerprint = !string.IsNullOrWhiteSpace(application.Sha256);
                var changed = await VerifyFingerprintAsync(application, establishBaselineIfMissing: true);
                if (hadFingerprint && changed)
                {
                    application.Access = FirewallAccess.Block;
                    application.RuleProfile = ApplicationRuleProfile.Default;
                    ClearTemporaryAllow(application);
                    application.FingerprintChanged = true;
                }
                await RefreshTrustMetadataAsync(application);
            }

            imported.Add(application);
        }

        var previousApps = Applications.ToList();
        var previousSettings = BuildSettingsSnapshot();
        try
        {
            Applications.Clear();
            foreach (var application in imported)
                Applications.Add(application);

            _protectionEnabled = configuration.Settings.ProtectionEnabled;
            _mode = Enum.IsDefined(configuration.Settings.Mode) ? configuration.Settings.Mode : FirewallMode.Normal;
            _settings.PlayDetectionSound = configuration.Settings.PlayDetectionSound;
            _settings.ShowTrayNotifications = configuration.Settings.ShowTrayNotifications;
            _settings.ResolveHostNames = configuration.Settings.ResolveHostNames;
            _settings.ImmediateQuarantineOnForget = configuration.Settings.ImmediateQuarantineOnForget;
            _settings.RuntimeQuarantines.Clear();
            _settings.UiLanguage = Enum.IsDefined(configuration.Settings.UiLanguage) ? configuration.Settings.UiLanguage : UiLanguage.Auto;
            _settings.ConfirmBlockAll = configuration.Settings.ConfirmBlockAll;
            _settings.RemoveMissingOnStartup = configuration.Settings.RemoveMissingOnStartup;
            _settings.TrustVerifiedSystemProcesses = configuration.Settings.TrustVerifiedSystemProcesses;
            // Backend, autostart and window placement are intentionally machine-local and are not imported.
            _settings.StartWithWindows = _autostart.IsEnabled();
            LocalizationService.Configure(_settings.UiLanguage);
            RefreshLocalization();

            SynchronizeFirewallState();
            await PersistAsync();
            RefreshHandledPaths();
            RefreshList();
            SelectModeInComboBox(_mode);
            UpdateProtectionUi();
            await SaveSettingsAsync();
            _diagnostics.Log($"Configuration imported: {filePath}; applications: {Applications.Count}");
            return BuildSettingsSnapshot();
        }
        catch
        {
            Applications.Clear();
            foreach (var application in previousApps)
                Applications.Add(application);

            _protectionEnabled = previousSettings.ProtectionEnabled;
            _mode = previousSettings.Mode;
            _settings = previousSettings;
            LocalizationService.Configure(_settings.UiLanguage);
            RefreshLocalization();
            TryRestoreFirewallState("Rollback after configuration import failure");
            try
            {
                await _store.SaveApplicationsAsync(CreateApplicationsSnapshot());
                await _store.SaveSettingsAsync(previousSettings);
            }
            catch (Exception persistError)
            {
                _diagnostics.LogException("Persist rollback after configuration import failure", persistError);
            }
            RefreshHandledPaths();
            RefreshList();
            SelectModeInComboBox(_mode);
            UpdateProtectionUi();
            throw;
        }
    }

    private string BuildDiagnosticsText()
    {
        var ru = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
        var yes = ru ? "да" : "yes";
        var no = ru ? "нет" : "no";
        var on = ru ? "ВКЛ" : "ON";
        var off = ru ? "ВЫКЛ" : "OFF";
        var lines = new List<string>();
        lines.Add(ru ? $"Активный backend: {_firewall.DisplayName}" : $"Active backend: {_firewall.DisplayName}");

        try
        {
            var defender = _windowsFirewall.GetDiagnostics();
            lines.Add($"Microsoft Defender Firewall: {defender.ProfileStatus}");
            lines.Add(ru
                ? $"Compatibility-правил GeniaFirewall: {defender.GeniaFirewallRuleCount}"
                : $"GeniaFirewall compatibility rules: {defender.GeniaFirewallRuleCount}");
        }
        catch (Exception ex)
        {
            lines.Add(ru
                ? $"Microsoft Defender Firewall: ошибка проверки — {ex.Message}"
                : $"Microsoft Defender Firewall: probe error — {ex.Message}");
        }

        var caps = _firewall.Capabilities;
        lines.Add($"Backend capabilities: outbound={(caps.OutboundRules ? yes : no)} · inbound={(caps.InboundRules ? yes : no)} · IPv4={(caps.IPv4 ? yes : no)} · IPv6={(caps.IPv6 ? yes : no)} · TCP={(caps.Tcp ? yes : no)} · UDP={(caps.Udp ? yes : no)} · pre-connect={(caps.PreConnectDecision ? yes : no)}");

        try
        {
            var wfp = _wfpPlatform.Probe();
            lines.Add($"WFP/BFE (UI probe): {wfp.Description}");
        }
        catch (Exception ex)
        {
            lines.Add(ru ? $"WFP/BFE: ошибка probe — {ex.Message}" : $"WFP/BFE: probe error — {ex.Message}");
        }

        try
        {
            var serviceProbe = _serviceClient.Probe();
            if (!serviceProbe.Reachable || serviceProbe.Status is null)
            {
                lines.Add(ru
                    ? $"GeniaFirewall.Service: не подключена · {serviceProbe.Description}"
                    : $"GeniaFirewall.Service: unavailable · {serviceProbe.Description}");
                if (_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp)
                {
                    lines.Add(ru
                        ? "ВНИМАНИЕ: выбран WFP backend, но Service недоступна. При следующей синхронизации UI выполнит fallback на Compatibility."
                        : "WARNING: the WFP backend is selected but the Service is unavailable. The next UI synchronization will fall back to Compatibility.");
                }
            }
            else
            {
                var status = serviceProbe.Status;
                lines.Add($"GeniaFirewall.Service: {status.ProductVersion} · {serviceProbe.Description}");
                lines.Add($"WFP session: engine={(status.WfpEngineOpen ? "open" : "closed")} · dynamic={(status.DynamicSession ? yes : no)} · provider={(status.ProviderRegistered ? "registered" : no)} · sublayer={(status.SubLayerRegistered ? "registered" : no)}");
                lines.Add($"WFP backend: active={(status.WfpBackendActive ? yes : no)} · protection={(status.ProtectionEnabled ? on : off)} · mode={status.PolicyMode} · restored={(status.PolicyRestoredOnStartup ? yes : no)} · revision={status.PolicyRevision}");
                lines.Add($"WFP apps: allow={status.AllowedApplicationCount} · block={status.BlockedApplicationCount} · ask/quarantine={status.PendingApplicationCount} · filters={status.ActiveFilterCount} · global-block={status.GlobalBlockFilterCount}");
                lines.Add($"WFP direction: outbound={status.OutboundFilterCount} · inbound={status.InboundFilterCount} · global-out={status.GlobalOutboundBlockFilterCount} · global-in={status.GlobalInboundBlockFilterCount}");
                lines.Add(ru
                    ? $"WFP loopback policy: {(status.LoopbackAwareDirectionalRules ? "aware" : "legacy")} · Normal global-in={(status.LoopbackAwareDirectionalRules ? "только внешний inbound" : "включая loopback")}"
                    : $"WFP loopback policy: {(status.LoopbackAwareDirectionalRules ? "aware" : "legacy")} · Normal global-in={(status.LoopbackAwareDirectionalRules ? "external inbound only" : "includes loopback")}");
                lines.Add(ru
                    ? $"WFP TUN policy: {(status.TunAwareDirectionalRules ? "aware" : "legacy")} · physical-in={status.PhysicalInboundInterfaceCount} · virtual/TUN={status.VirtualTunInterfaceCount} · fallback={(status.InterfaceScopeFallback ? "ДА" : "нет")}"
                    : $"WFP TUN policy: {(status.TunAwareDirectionalRules ? "aware" : "legacy")} · physical-in={status.PhysicalInboundInterfaceCount} · virtual/TUN={status.VirtualTunInterfaceCount} · fallback={(status.InterfaceScopeFallback ? "YES" : "no")}");
                if (!string.IsNullOrWhiteSpace(status.PhysicalInterfaceSummary))
                    lines.Add((ru ? "Physical interfaces: " : "Physical interfaces: ") + status.PhysicalInterfaceSummary);
                if (!string.IsNullOrWhiteSpace(status.VirtualTunInterfaceSummary))
                    lines.Add((ru ? "Virtual/TUN interfaces: " : "Virtual/TUN interfaces: ") + status.VirtualTunInterfaceSummary);
                lines.Add($"WFP filters: IPv4={status.IPv4FilterCount} · IPv6={status.IPv6FilterCount} · TCP={status.TcpFilterCount} · UDP={status.UdpFilterCount}");
                lines.Add($"WFP telemetry: {(status.NetEventTelemetryAvailable ? "active" : "unavailable")} · seq={status.NetEventTelemetryLastSequence} · received={status.NetEventTelemetryReceivedCount} · evicted={status.NetEventTelemetryDroppedCount} · BLOCK={status.BlockedEventCount}");
                lines.Add(ru
                    ? $"WFP lifecycle: cleanup-verified={(status.RuntimeFilterCleanupVerified ? yes : no)} · residual={status.ResidualRuntimeFilterCount} · weight-plan={(status.FilterWeightPlanValid ? "PROBE>APP>GLOBAL" : "ОШИБКА")}"
                    : $"WFP lifecycle: cleanup-verified={(status.RuntimeFilterCleanupVerified ? yes : no)} · residual={status.ResidualRuntimeFilterCount} · weight-plan={(status.FilterWeightPlanValid ? "PROBE>APP>GLOBAL" : "ERROR")}");
                if (status.StartupStaleCleanupAttempted)
                    lines.Add($"WFP startup stale cleanup: removed={status.StartupStaleFilterRemovedCount} · residual={status.StartupStaleFilterResidualCount} · {status.StartupStaleCleanupStatus}");
                if (!string.IsNullOrWhiteSpace(status.LastBlockedEventSummary))
                    lines.Add(ru
                        ? $"WFP последний наблюдавшийся BLOCK: {status.LastBlockedEventSummary}"
                        : $"WFP last observed BLOCK: {status.LastBlockedEventSummary}");
                if (!string.IsNullOrWhiteSpace(status.NetEventTelemetryLastError))
                    lines.Add($"WFP telemetry error: {status.NetEventTelemetryLastError}");
                if (!string.IsNullOrWhiteSpace(status.LastError))
                    lines.Add($"WFP service error: {status.LastError}");
            }
        }
        catch (Exception ex)
        {
            lines.Add(ru
                ? $"GeniaFirewall.Service: ошибка проверки — {ex.Message}"
                : $"GeniaFirewall.Service: probe error — {ex.Message}");
        }

        lines.Add(ru
            ? $"Автоопределение: socket watcher={(_watcher is null ? "не запущен" : "работает")} · WFP telemetry watcher={(_wfpTelemetryWatcher is null ? "не запущен" : "работает")}"
            : $"Auto detection: socket watcher={(_watcher is null ? "not running" : "running")} · WFP telemetry watcher={(_wfpTelemetryWatcher is null ? "not running" : "running")}");
        lines.Add(ru
            ? $"Защита: {(_protectionEnabled ? on : off)} · режим: {GetModeTitle(_mode)}"
            : $"Protection: {(_protectionEnabled ? on : off)} · mode: {GetModeTitle(_mode)}");
        lines.Add(ru ? $"Выбор backend: {_settings.BackendMode}" : $"Selected backend: {_settings.BackendMode}");
        lines.Add(ru
            ? $"Secure Prompt Quarantine: {(_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp && _protectionEnabled && _mode == FirewallMode.Normal ? on : "не активен")} · safe Del={(_settings.ImmediateQuarantineOnForget ? on : off)} · скрытых={_settings.RuntimeQuarantines.Count}"
            : $"Secure Prompt Quarantine: {(_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp && _protectionEnabled && _mode == FirewallMode.Normal ? on : "inactive")} · safe Del={(_settings.ImmediateQuarantineOnForget ? on : off)} · hidden={_settings.RuntimeQuarantines.Count}");
        lines.Add(ru
            ? $"Не напоминать: {Applications.Count(app => app.Access == FirewallAccess.Ask && app.SuppressPromptNotifications)} приложений"
            : $"Do not remind: {Applications.Count(app => app.Access == FirewallAccess.Ask && app.SuppressPromptNotifications)} applications");
        lines.Add(ru
            ? $"Quick Rules: EnableAll={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.EnableAll)} · OutgoingOnly={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.OutgoingOnly)} · IncomingOnly={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.IncomingOnly)} · DisableAll={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.DisableAll)} · Ask={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.Ask)}"
            : $"Quick Rules: EnableAll={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.EnableAll)} · OutgoingOnly={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.OutgoingOnly)} · IncomingOnly={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.IncomingOnly)} · DisableAll={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.DisableAll)} · Ask={Applications.Count(app => app.RuleProfile == ApplicationRuleProfile.Ask)}");
        lines.Add(ru
            ? $"Язык: {_settings.UiLanguage} → {LocalizationService.EffectiveLanguage}"
            : $"Language: {_settings.UiLanguage} → {LocalizationService.EffectiveLanguage}");
        lines.Add(ru
            ? $"Доверенные системные процессы: {(_settings.TrustVerifiedSystemProcesses ? on : off)} · помечено: {Applications.Count(app => app.IsTrustedSystem)}"
            : $"Trusted system processes: {(_settings.TrustVerifiedSystemProcesses ? on : off)} · marked: {Applications.Count(app => app.IsTrustedSystem)}");
        lines.Add(ru
            ? $"Reverse DNS: {(_settings.ResolveHostNames ? on : off)} · временных разрешений: {Applications.Count(app => app.IsTemporaryAllow)}"
            : $"Reverse DNS: {(_settings.ResolveHostNames ? on : off)} · temporary allows: {Applications.Count(app => app.IsTemporaryAllow)}");

        try
        {
            _store.ValidatePortableStorage();
            lines.Add(ru ? "Portable Data: запись доступна" : "Portable Data: writable");
        }
        catch (Exception ex)
        {
            lines.Add(ru ? $"Portable Data: ошибка записи — {ex.Message}" : $"Portable Data: write error — {ex.Message}");
        }

        lines.Add(_store.GetDatabaseHealthDescription());
        lines.Add(ru ? $"Автозагрузка: {_autostart.GetStatusDescription()}" : $"Autostart: {_autostart.GetStatusDescription()}");
        lines.Add(ru ? $"Логи: {_diagnostics.LogDirectory}" : $"Logs: {_diagnostics.LogDirectory}");
        lines.Add(ru ? $"Диагностика обновлена: {DateTime.Now:HH:mm:ss}" : $"Diagnostics refreshed: {DateTime.Now:HH:mm:ss}");
        return string.Join(Environment.NewLine, lines);
    }

    private async Task SaveSettingsAsync()
    {
        CaptureWindowPlacement();
        _settings = BuildSettingsSnapshot();
        await _store.SaveSettingsAsync(_settings);
    }

    private async Task SaveSettingsSilentlyAsync()
    {
        try
        {
            await SaveSettingsAsync();
        }
        catch (Exception ex)
        {
            _diagnostics.LogException("Save settings silently", ex);
        }
    }

    private AppSettings BuildSettingsSnapshot() => new()
    {
        ProtectionEnabled = _protectionEnabled,
        Mode = _mode,
        StartWithWindows = _settings.StartWithWindows,
        PlayDetectionSound = _settings.PlayDetectionSound,
        ShowTrayNotifications = _settings.ShowTrayNotifications,
        ResolveHostNames = _settings.ResolveHostNames,
        BackendMode = _settings.BackendMode,
        ImmediateQuarantineOnForget = _settings.ImmediateQuarantineOnForget,
        UiLanguage = _settings.UiLanguage,
        RuntimeQuarantines = _settings.RuntimeQuarantines.Select(item => new RuntimeQuarantineEntry
        {
            Id = item.Id,
            ExePath = item.ExePath,
            DisplayName = item.DisplayName
        }).ToList(),
        ConfirmBlockAll = _settings.ConfirmBlockAll,
        RemoveMissingOnStartup = _settings.RemoveMissingOnStartup,
        TrustVerifiedSystemProcesses = _settings.TrustVerifiedSystemProcesses,
        WindowLeft = _settings.WindowLeft,
        WindowTop = _settings.WindowTop,
        WindowWidth = _settings.WindowWidth,
        WindowHeight = _settings.WindowHeight,
        WindowMaximized = _settings.WindowMaximized
    };

    private void CaptureWindowPlacement()
    {
        var bounds = WindowState == WindowState.Normal
            ? new Rect(Left, Top, ActualWidth > 0 ? ActualWidth : Width, ActualHeight > 0 ? ActualHeight : Height)
            : RestoreBounds;

        if (!IsFinite(bounds.Left) || !IsFinite(bounds.Top) || !IsFinite(bounds.Width) || !IsFinite(bounds.Height))
            return;

        if (bounds.Width < MinWidth || bounds.Height < MinHeight)
            return;

        _settings.WindowLeft = bounds.Left;
        _settings.WindowTop = bounds.Top;
        _settings.WindowWidth = bounds.Width;
        _settings.WindowHeight = bounds.Height;
        _settings.WindowMaximized = WindowState == WindowState.Maximized;
    }

    private void RestoreWindowPlacement(AppSettings settings)
    {
        if (settings.WindowLeft is not double left ||
            settings.WindowTop is not double top ||
            settings.WindowWidth is not double width ||
            settings.WindowHeight is not double height)
        {
            return;
        }

        if (!IsFinite(left) || !IsFinite(top) || !IsFinite(width) || !IsFinite(height))
            return;

        width = Math.Max(MinWidth, width);
        height = Math.Max(MinHeight, height);

        var virtualLeft = SystemParameters.VirtualScreenLeft;
        var virtualTop = SystemParameters.VirtualScreenTop;
        var virtualRight = virtualLeft + SystemParameters.VirtualScreenWidth;
        var virtualBottom = virtualTop + SystemParameters.VirtualScreenHeight;

        // Require at least a small part of the title bar to remain reachable on the current desktop layout.
        if (left + 80 < virtualLeft || top + 40 < virtualTop || left > virtualRight - 80 || top > virtualBottom - 40)
            return;

        WindowStartupLocation = WindowStartupLocation.Manual;
        Left = left;
        Top = top;
        Width = Math.Min(width, Math.Max(MinWidth, SystemParameters.VirtualScreenWidth));
        Height = Math.Min(height, Math.Max(MinHeight, SystemParameters.VirtualScreenHeight));

        if (settings.WindowMaximized)
            WindowState = WindowState.Maximized;
    }

    private void SelectModeInComboBox(FirewallMode mode)
    {
        var oldInitializing = _initializing;
        _initializing = true;

        foreach (var item in ModeComboBox.Items.OfType<ComboBoxItem>())
        {
            if (string.Equals(item.Tag?.ToString(), mode.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                ModeComboBox.SelectedItem = item;
                break;
            }
        }

        _initializing = oldInitializing;
        _trayIcon.UpdateMode(mode);
    }

    private void UpdateProtectionUi()
    {
        ProtectionText.Text = _protectionEnabled
            ? LocalizationService.Get("Main.ProtectionOn")
            : LocalizationService.Get("Main.ProtectionOff");
        ProtectionDot.Opacity = _protectionEnabled ? 1.0 : 0.55;
        ProtectionButton.Opacity = 1.0;
        _trayIcon.UpdateProtectionState(_protectionEnabled);
        _trayIcon.UpdateTrustedSystemState(_settings.TrustVerifiedSystemProcesses);
        _trayIcon.UpdateMode(_mode);
    }

    private void RefreshLocalization()
    {
        foreach (var application in Applications)
            application.RefreshLocalizedProperties();

        _trayIcon.RefreshLocalization();
        UpdateSortHeaderLabels();
        UpdateProtectionUi();
        UpdateSummary();
        _applicationsView.Refresh();
    }

    private void SetStatus(string text) => StatusText.Text = text;

    private static string L(string russian, string english) =>
        LocalizationService.EffectiveLanguage == UiLanguage.Russian ? russian : english;

    private static string GetModeTitle(FirewallMode mode) => LocalizationService.GetModeTitle(mode);

    private static string GetPromptActionResult(ManagedApplication application, FirewallAccess access)
    {
        var russian = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
        if (access == FirewallAccess.Block)
            return russian ? "заблокировано" : "blocked";

        if (application.TemporaryAllowProcessId > 0)
            return russian ? "разрешено до закрытия процесса" : "allowed until process exit";

        if (application.TemporaryAllowUntilUtc is not null)
            return russian ? "разрешено на 10 минут" : "allowed for 10 minutes";

        return russian ? "разрешено всегда" : "allowed permanently";
    }

    private static string GetAccessActionResult(FirewallAccess access) => access switch
    {
        FirewallAccess.Allow => LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "разрешено" : "allowed",
        FirewallAccess.Block => LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "заблокировано" : "blocked",
        _ => LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "будет запрашиваться решение" : "will ask for a decision"
    };

    private IReadOnlyList<ManagedApplication> GetPolicyApplications(FirewallBackendMode backendMode)
    {
        if (backendMode == FirewallBackendMode.WindowsFirewallCompatibility)
        {
            // Compatibility backend is outbound-only. Never reinterpret IncomingOnly as outbound Allow.
            return Applications.Select(app => app.RuleProfile == ApplicationRuleProfile.IncomingOnly
                ? new ManagedApplication
                {
                    Id = app.Id,
                    Name = app.Name,
                    ExePath = app.ExePath,
                    Access = FirewallAccess.Block,
                    RuleProfile = ApplicationRuleProfile.IncomingOnly
                }
                : app).ToList();
        }

        if (_settings.RuntimeQuarantines.Count == 0)
            return Applications.ToList();

        var policyApplications = Applications.ToList();
        var visiblePaths = new HashSet<string>(policyApplications.Select(app => app.ExePath), StringComparer.OrdinalIgnoreCase);
        foreach (var quarantine in _settings.RuntimeQuarantines)
        {
            if (string.IsNullOrWhiteSpace(quarantine.ExePath) || visiblePaths.Contains(quarantine.ExePath))
                continue;

            policyApplications.Add(new ManagedApplication
            {
                Id = quarantine.Id == Guid.Empty ? Guid.NewGuid() : quarantine.Id,
                Name = string.IsNullOrWhiteSpace(quarantine.DisplayName) ? Path.GetFileNameWithoutExtension(quarantine.ExePath) : quarantine.DisplayName,
                ExePath = quarantine.ExePath,
                Access = FirewallAccess.Ask
            });
        }

        return policyApplications;
    }

    private void ApplyFirewallState()
    {
        _firewall.ApplyState(GetPolicyApplications(_settings.BackendMode), _protectionEnabled, _mode);
        if (_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp)
            TryRemoveCompatibilityRulesAfterWfpCommit();
    }

    private void SynchronizeFirewallState(bool allowWfpAutoFallback = false)
    {
        try
        {
            _firewall.SynchronizeState(GetPolicyApplications(_settings.BackendMode), _protectionEnabled, _mode);
            if (_settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp)
                TryRemoveCompatibilityRulesAfterWfpCommit();
        }
        catch (Exception ex) when (allowWfpAutoFallback && _settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp)
        {
            _diagnostics.LogException("WFP backend startup synchronization failed; attempting verified fallback to Windows Firewall Compatibility", ex);

            // HF2 fail-safe handoff: do not claim Compatibility is active until the
            // service has removed and verified zero GeniaFirewall WFP runtime filters.
            ClearWfpRuntimeOrThrow("startup fallback");
            _windowsFirewall.SynchronizeState(GetPolicyApplications(FirewallBackendMode.WindowsFirewallCompatibility), _protectionEnabled, _mode);
            _settings.BackendMode = FirewallBackendMode.WindowsFirewallCompatibility;
            _firewall = _windowsFirewall;
            _ = SaveSettingsSilentlyAsync();
        }
    }

    private IFirewallBackend GetBackend(FirewallBackendMode mode) => mode switch
    {
        FirewallBackendMode.GeniaFirewallWfp => _wfpFirewall,
        _ => _windowsFirewall
    };

    private void SwitchBackendOrThrow(FirewallBackendMode previous, FirewallBackendMode next)
    {
        if (previous == next)
        {
            _firewall = GetBackend(next);
            SynchronizeFirewallState();
            return;
        }

        if (next == FirewallBackendMode.GeniaFirewallWfp)
        {
            // Safe handoff: commit WFP first, then remove only GeniaFirewall's compatibility rules.
            _wfpFirewall.SynchronizeState(GetPolicyApplications(FirewallBackendMode.GeniaFirewallWfp), _protectionEnabled, _mode);
            try
            {
                _windowsFirewall.RemoveAllGeniaFirewallRules();
            }
            catch
            {
                // Do not leave a newly activated WFP policy behind when the handoff itself failed.
                try { ClearWfpRuntimeOrThrow("rollback after Compatibility cleanup failure"); } catch { }
                throw;
            }
            _firewall = _wfpFirewall;
            return;
        }

        // HF2 handoff back: first stop/clear the WFP policy and REQUIRE a verified
        // zero-filter state. Only then install Compatibility rules and report the backend
        // switch as successful. If Compatibility setup fails, restore the previous WFP policy.
        ClearWfpRuntimeOrThrow("backend switch to Windows Firewall Compatibility");
        try
        {
            _windowsFirewall.SynchronizeState(GetPolicyApplications(FirewallBackendMode.WindowsFirewallCompatibility), _protectionEnabled, _mode);
        }
        catch
        {
            try
            {
                _wfpFirewall.SynchronizeState(GetPolicyApplications(FirewallBackendMode.GeniaFirewallWfp), _protectionEnabled, _mode);
            }
            catch (Exception restoreError)
            {
                _diagnostics.LogException("Restore WFP after Compatibility handoff failure", restoreError);
            }
            throw;
        }
        _firewall = _windowsFirewall;
    }

    private void ClearWfpRuntimeOrThrow(string context)
    {
        var clear = _serviceClient.ClearWfpPolicy();
        if (!clear.Success || clear.Status is null)
            throw new InvalidOperationException($"GeniaFirewall.Service did not confirm WFP clear ({context}): {clear.Description}");

        var status = clear.Status;
        if (status.WfpBackendActive || status.WfpEngineOpen || status.ProviderRegistered || status.SubLayerRegistered ||
            status.ActiveFilterCount != 0 || !status.RuntimeFilterCleanupVerified || status.ResidualRuntimeFilterCount != 0)
        {
            throw new InvalidOperationException(
                $"GeniaFirewall.Service WFP clear verification failed ({context}): " +
                $"backendActive={status.WfpBackendActive}; engineOpen={status.WfpEngineOpen}; provider={status.ProviderRegistered}; sublayer={status.SubLayerRegistered}; " +
                $"filters={status.ActiveFilterCount}; cleanupVerified={status.RuntimeFilterCleanupVerified}; residual={status.ResidualRuntimeFilterCount}.");
        }

        _diagnostics.Log(
            $"Verified WFP runtime clear ({context}): filters=0; residual=0; " +
            $"verified={status.RuntimeFilterCleanupVerified}; revision={status.PolicyRevision}.");
    }

    private void TryRemoveCompatibilityRulesAfterWfpCommit()
    {
        try
        {
            _windowsFirewall.RemoveAllGeniaFirewallRules();
        }
        catch (Exception ex)
        {
            _diagnostics.LogException("Remove stale Windows Firewall Compatibility rules after WFP commit", ex);
        }
    }

    private void TryRestoreFirewallState(string context)
    {
        try
        {
            SynchronizeFirewallState();
        }
        catch (Exception rollbackError)
        {
            _diagnostics.LogException(context, rollbackError);
        }
    }

    private void RunUiTask(Func<Task> action, string errorTitle)
    {
        _ = RunUiTaskSafelyAsync(action, errorTitle);
    }

    private async Task RunUiTaskSafelyAsync(Func<Task> action, string errorTitle)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            ShowError(errorTitle, ex);
        }
    }

    private void ShowError(string title, Exception ex)
    {
        _diagnostics.LogException(title, ex);
        SetStatus(L("Ошибка. Подробности записаны в Data\\Logs.", "Error. Details were written to Data\\Logs."));
        System.Windows.MessageBox.Show(this, $"{title}\n\n{ex.Message}", "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static T? FindVisualChild<T>(DependencyObject? parent) where T : DependencyObject
    {
        if (parent is null)
            return null;

        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T typed)
                return typed;

            var descendant = FindVisualChild<T>(child);
            if (descendant is not null)
                return descendant;
        }

        return null;
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        while (child is not null)
        {
            if (child is T typed)
                return typed;

            child = VisualTreeHelper.GetParent(child);
        }

        return null;
    }

    private static bool IsFinite(double value) => !double.IsNaN(value) && !double.IsInfinity(value);
    private readonly record struct PromptProcessInstance(int ProcessId, long StartTimeUtcTicks, string ExePath);

    private sealed class PromptRequest
    {
        private const int MaxConnections = 20;

        public PromptRequest(NetworkConnectionInfo connection, bool force)
        {
            ExePath = connection.ExePath;
            Force = force;
            Add(connection);
        }

        public string ExePath { get; }
        public bool Force { get; set; }
        public List<NetworkConnectionInfo> Connections { get; } = [];

        public void Add(NetworkConnectionInfo connection)
        {
            if (Connections.Count >= MaxConnections)
                return;

            if (Connections.Any(existing => string.Equals(existing.GroupKey, connection.GroupKey, StringComparison.OrdinalIgnoreCase)))
                return;

            Connections.Add(connection);
        }
    }

}
