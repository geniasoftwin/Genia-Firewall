using System.Diagnostics;
using System.IO;
using System.Windows;
using GeniaFirewall.Models;
using GeniaFirewall.Services;

namespace GeniaFirewall;

public partial class SettingsWindow : Window
{
    private readonly AppStore _store;
    private readonly AutostartService _autostart;
    private readonly Action _rebuildRulesAction;
    private readonly Func<Task> _removeRulesAction;
    private readonly Func<string, Task> _exportConfigurationAction;
    private readonly Func<string, Task<AppSettings>> _importConfigurationAction;
    private readonly Func<string> _diagnosticsProvider;
    private readonly Func<ServiceLifecycleStatus> _serviceStatusProvider;
    private readonly Func<Task<ServiceLifecycleStatus>> _activateServiceAction;
    private readonly Func<Task<ServiceLifecycleStatus>> _deactivateServiceAction;
    private AppSettings _original;
    private bool _serviceEnabled;

    public AppSettings ResultSettings { get; private set; }
    private static bool IsRussian => LocalizationService.EffectiveLanguage == UiLanguage.Russian;

    public SettingsWindow(
        AppSettings settings,
        AppStore store,
        AutostartService autostart,
        Action rebuildRulesAction,
        Func<Task> removeRulesAction,
        Func<string, Task> exportConfigurationAction,
        Func<string, Task<AppSettings>> importConfigurationAction,
        Func<string> diagnosticsProvider,
        Func<ServiceLifecycleStatus> serviceStatusProvider,
        Func<Task<ServiceLifecycleStatus>> activateServiceAction,
        Func<Task<ServiceLifecycleStatus>> deactivateServiceAction)
    {
        InitializeComponent();

        _store = store;
        _autostart = autostart;
        _rebuildRulesAction = rebuildRulesAction;
        _removeRulesAction = removeRulesAction;
        _exportConfigurationAction = exportConfigurationAction;
        _importConfigurationAction = importConfigurationAction;
        _diagnosticsProvider = diagnosticsProvider;
        _serviceStatusProvider = serviceStatusProvider;
        _activateServiceAction = activateServiceAction;
        _deactivateServiceAction = deactivateServiceAction;
        _original = CloneSettings(settings);
        ResultSettings = CloneSettings(settings);

        ApplySettingsToControls(settings);
        DataPathText.Text = _store.DataDirectory;
        RefreshAutostartStatus();
        RefreshServiceStatus();
        RefreshDiagnostics();

        if (_autostart.IsEnabled() && !_autostart.IsConfiguredForCurrentExecutable())
            SettingsStatusText.Text = IsRussian ? "Путь или SHA-256 автозагрузки устарел. Нажмите «Сохранить», чтобы исправить." : "The autostart path or SHA-256 is outdated. Click Save to repair it.";
    }

    private void ApplySettingsToControls(AppSettings settings)
    {
        StartWithWindowsCheckBox.IsChecked = _autostart.IsEnabled();
        PlayDetectionSoundCheckBox.IsChecked = settings.PlayDetectionSound;
        ShowTrayNotificationsCheckBox.IsChecked = settings.ShowTrayNotifications;
        ResolveHostNamesCheckBox.IsChecked = settings.ResolveHostNames;
        CompatibilityBackendRadio.IsChecked = settings.BackendMode == FirewallBackendMode.WindowsFirewallCompatibility;
        WfpBackendRadio.IsChecked = settings.BackendMode == FirewallBackendMode.GeniaFirewallWfp;
        _serviceEnabled = settings.ServiceEnabled;
        ImmediateQuarantineOnForgetCheckBox.IsChecked = settings.ImmediateQuarantineOnForget;
        SelectLanguage(settings.UiLanguage);
        ConfirmBlockAllCheckBox.IsChecked = settings.ConfirmBlockAll;
        RemoveMissingOnStartupCheckBox.IsChecked = settings.RemoveMissingOnStartup;
        TrustVerifiedSystemProcessesCheckBox.IsChecked = settings.TrustVerifiedSystemProcesses;
    }

    private void SelectLanguage(UiLanguage language)
    {
        if (!Enum.IsDefined(language))
            language = UiLanguage.Auto;

        foreach (var item in LanguageComboBox.Items.OfType<System.Windows.Controls.ComboBoxItem>())
        {
            if (Enum.TryParse<UiLanguage>(item.Tag?.ToString(), out var candidate) && candidate == language)
            {
                LanguageComboBox.SelectedItem = item;
                return;
            }
        }

        LanguageComboBox.SelectedIndex = 0;
    }

    private UiLanguage GetSelectedLanguage()
    {
        var tag = (LanguageComboBox.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Tag?.ToString();
        return Enum.TryParse<UiLanguage>(tag, out var language) && Enum.IsDefined(language)
            ? language
            : UiLanguage.Auto;
    }

    private void CheckAutostart_Click(object sender, RoutedEventArgs e) => RefreshAutostartStatus();

    private void RefreshAutostartStatus()
    {
        try
        {
            AutostartStatusText.Text = _autostart.GetStatusDescription();
        }
        catch (Exception ex)
        {
            AutostartStatusText.Text = IsRussian ? $"Не удалось проверить автозагрузку: {ex.Message}" : $"Failed to check autostart: {ex.Message}";
        }
    }

    private void RefreshDiagnostics_Click(object sender, RoutedEventArgs e) => RefreshDiagnostics();

    private void RefreshDiagnostics()
    {
        try
        {
            DiagnosticsText.Text = _diagnosticsProvider();
        }
        catch (Exception ex)
        {
            DiagnosticsText.Text = IsRussian ? $"Не удалось собрать диагностику: {ex.Message}" : $"Failed to collect diagnostics: {ex.Message}";
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var startWithWindows = StartWithWindowsCheckBox.IsChecked == true;
            _autostart.SetEnabled(startWithWindows);

            ResultSettings = CloneSettings(_original);
            ResultSettings.StartWithWindows = startWithWindows;
            ResultSettings.PlayDetectionSound = PlayDetectionSoundCheckBox.IsChecked == true;
            ResultSettings.ShowTrayNotifications = ShowTrayNotificationsCheckBox.IsChecked == true;
            ResultSettings.ResolveHostNames = ResolveHostNamesCheckBox.IsChecked == true;
            ResultSettings.BackendMode = WfpBackendRadio.IsChecked == true
                ? FirewallBackendMode.GeniaFirewallWfp
                : FirewallBackendMode.WindowsFirewallCompatibility;
            if (ResultSettings.BackendMode == FirewallBackendMode.GeniaFirewallWfp && !_serviceEnabled)
                throw new InvalidOperationException(IsRussian
                    ? "Сначала активируйте системную службу GeniaFirewall."
                    : "Activate the GeniaFirewall system service first.");
            ResultSettings.ServiceEnabled = _serviceEnabled;
            ResultSettings.ImmediateQuarantineOnForget = ImmediateQuarantineOnForgetCheckBox.IsChecked == true;
            ResultSettings.UiLanguage = GetSelectedLanguage();
            ResultSettings.ConfirmBlockAll = ConfirmBlockAllCheckBox.IsChecked == true;
            ResultSettings.RemoveMissingOnStartup = RemoveMissingOnStartupCheckBox.IsChecked == true;
            ResultSettings.TrustVerifiedSystemProcesses = TrustVerifiedSystemProcessesCheckBox.IsChecked == true;

            DialogResult = true;
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                this,
                IsRussian ? $"Не удалось сохранить настройки.\n\n{ex.Message}" : $"Failed to save settings.\n\n{ex.Message}",
                "GeniaFirewall",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Directory.CreateDirectory(_store.DataDirectory);
            OpenFolder(_store.DataDirectory);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OpenLogs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var logDirectory = Path.Combine(_store.DataDirectory, "Logs");
            Directory.CreateDirectory(logDirectory);
            OpenFolder(logDirectory);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void ExportConfiguration_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = IsRussian ? "Экспорт конфигурации GeniaFirewall" : "Export GeniaFirewall configuration",
                Filter = IsRussian ? "GeniaFirewall JSON (*.json)|*.json|Все файлы (*.*)|*.*" : "GeniaFirewall JSON (*.json)|*.json|All files (*.*)|*.*",
                DefaultExt = ".json",
                AddExtension = true,
                FileName = $"GeniaFirewall-config-{DateTime.Now:yyyyMMdd-HHmm}.json"
            };

            if (dialog.ShowDialog(this) != true)
                return;

            await _exportConfigurationAction(dialog.FileName);
            SettingsStatusText.Text = IsRussian ? "Конфигурация экспортирована." : "Configuration exported.";
            RefreshDiagnostics();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, IsRussian ? $"Не удалось экспортировать конфигурацию.\n\n{ex.Message}" : $"Failed to export configuration.\n\n{ex.Message}", "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void ImportConfiguration_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = IsRussian ? "Импорт конфигурации GeniaFirewall" : "Import GeniaFirewall configuration",
            Filter = IsRussian ? "GeniaFirewall JSON (*.json)|*.json|Все файлы (*.*)|*.*" : "GeniaFirewall JSON (*.json)|*.json|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
            return;

        var confirm = System.Windows.MessageBox.Show(
            this,
            IsRussian
                ? "Импорт заменит текущий список приложений и правил GeniaFirewall.\n\nПеред заменой текущая база останется защищена ротационными резервными копиями. Автозагрузка и положение окна не импортируются. Продолжить?"
                : "Import will replace the current GeniaFirewall application list and rules.\n\nRotating backups protect the current database. Autostart and window placement are not imported. Continue?",
            IsRussian ? "Импорт конфигурации — GeniaFirewall" : "Import configuration — GeniaFirewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
            return;

        try
        {
            var importedSettings = await _importConfigurationAction(dialog.FileName);
            _original = CloneSettings(importedSettings);
            ResultSettings = CloneSettings(importedSettings);
            ApplySettingsToControls(importedSettings);
            SettingsStatusText.Text = IsRussian ? "Конфигурация импортирована и применена." : "Configuration imported and applied.";
            RefreshAutostartStatus();
            RefreshServiceStatus();
            RefreshDiagnostics();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, IsRussian ? $"Не удалось импортировать конфигурацию.\n\n{ex.Message}" : $"Failed to import configuration.\n\n{ex.Message}", "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RebuildRules_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _rebuildRulesAction();
            SettingsStatusText.Text = IsRussian ? "Правила GeniaFirewall пересобраны." : "GeniaFirewall rules rebuilt.";
            RefreshDiagnostics();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, IsRussian ? $"Не удалось пересобрать правила.\n\n{ex.Message}" : $"Failed to rebuild rules.\n\n{ex.Message}", "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void RemoveRules_Click(object sender, RoutedEventArgs e)
    {
        var result = System.Windows.MessageBox.Show(
            this,
            IsRussian
                ? "Удалить все правила GeniaFirewall и выключить защиту программы?\n\nСистемные правила Microsoft Defender Firewall не удаляются."
                : "Remove all GeniaFirewall rules and turn off application protection?\n\nMicrosoft Defender Firewall system rules are not removed.",
            "GeniaFirewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes)
            return;

        try
        {
            await _removeRulesAction();
            ResultSettings.ProtectionEnabled = false;
            _original.ProtectionEnabled = false;
            SettingsStatusText.Text = IsRussian ? "Правила GeniaFirewall удалены, защита выключена." : "GeniaFirewall rules removed; protection is off.";
            RefreshDiagnostics();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, IsRussian ? $"Не удалось удалить правила.\n\n{ex.Message}" : $"Failed to remove rules.\n\n{ex.Message}", "GeniaFirewall", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void ActivateService_Click(object sender, RoutedEventArgs e)
    {
        SetServiceButtonsEnabled(false);
        try
        {
            var status = await _activateServiceAction();
            _serviceEnabled = true;
            ApplyServiceStatus(status);
            SettingsStatusText.Text = IsRussian
                ? "Служба установлена, защищена и запущена."
                : "The service is installed, protected, and running.";
            RefreshDiagnostics();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                this,
                IsRussian ? $"Не удалось активировать службу.\n\n{ex.Message}" : $"Failed to activate the service.\n\n{ex.Message}",
                "GeniaFirewall",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            RefreshServiceStatus();
        }
        finally
        {
            SetServiceButtonsEnabled(true);
        }
    }

    private async void DeactivateService_Click(object sender, RoutedEventArgs e)
    {
        var confirmation = System.Windows.MessageBox.Show(
            this,
            IsRussian
                ? "Деактивировать и удалить системную службу GeniaFirewall?\n\nWFP-политика будет проверенно очищена, backend переключится на Windows Firewall Compatibility. Portable-данные и правила приложений сохранятся."
                : "Deactivate and remove the GeniaFirewall system service?\n\nThe WFP policy will be cleared and verified, and the backend will switch to Windows Firewall Compatibility. Portable data and application rules will be preserved.",
            "GeniaFirewall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirmation != MessageBoxResult.Yes)
            return;

        SetServiceButtonsEnabled(false);
        try
        {
            var status = await _deactivateServiceAction();
            _serviceEnabled = false;
            CompatibilityBackendRadio.IsChecked = true;
            WfpBackendRadio.IsChecked = false;
            ApplyServiceStatus(status);
            SettingsStatusText.Text = IsRussian
                ? "Служба деактивирована и удалена; активен Compatibility backend."
                : "The service was deactivated and removed; the Compatibility backend is active.";
            RefreshDiagnostics();
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(
                this,
                IsRussian ? $"Не удалось полностью деактивировать службу.\n\n{ex.Message}" : $"Failed to fully deactivate the service.\n\n{ex.Message}",
                "GeniaFirewall",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            RefreshServiceStatus();
        }
        finally
        {
            SetServiceButtonsEnabled(true);
        }
    }

    private void RefreshServiceStatus()
    {
        try
        {
            ApplyServiceStatus(_serviceStatusProvider());
        }
        catch (Exception ex)
        {
            ServiceStatusText.Text = IsRussian
                ? $"Не удалось проверить службу: {ex.Message}"
                : $"Failed to inspect the service: {ex.Message}";
            ActivateServiceButton.IsEnabled = true;
            DeactivateServiceButton.IsEnabled = _serviceEnabled;
            WfpBackendRadio.IsEnabled = false;
        }
    }

    private void ApplyServiceStatus(ServiceLifecycleStatus status)
    {
        var ready = status.Installed && status.Running && status.BinaryPresent &&
                    status.ConfigurationValid && status.StorageProtected;
        ServiceStatusText.Text = IsRussian
            ? ready
                ? $"Активна · путь и ACL проверены · {status.BinaryPath}"
                : status.Installed
                    ? $"Требует внимания · {status.Description}"
                    : "Деактивирована · служба и защищённый EXE отсутствуют"
            : ready
                ? $"Active · path and ACL verified · {status.BinaryPath}"
                : status.Installed
                    ? $"Needs attention · {status.Description}"
                    : "Deactivated · service and protected EXE are absent";

        ActivateServiceButton.IsEnabled = !ready;
        DeactivateServiceButton.IsEnabled = status.Installed || status.BinaryPresent || _serviceEnabled;
        WfpBackendRadio.IsEnabled = ready && _serviceEnabled;
        if (!WfpBackendRadio.IsEnabled && WfpBackendRadio.IsChecked == true)
        {
            WfpBackendRadio.IsChecked = false;
            CompatibilityBackendRadio.IsChecked = true;
        }
    }

    private void SetServiceButtonsEnabled(bool enabled)
    {
        if (!enabled)
        {
            ActivateServiceButton.IsEnabled = false;
            DeactivateServiceButton.IsEnabled = false;
            return;
        }

        RefreshServiceStatus();
    }

    private static void OpenFolder(string path)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{path}\"",
            UseShellExecute = true
        });
    }

    private static AppSettings CloneSettings(AppSettings source) => new()
    {
        ProtectionEnabled = source.ProtectionEnabled,
        Mode = source.Mode,
        StartWithWindows = source.StartWithWindows,
        PlayDetectionSound = source.PlayDetectionSound,
        ShowTrayNotifications = source.ShowTrayNotifications,
        ResolveHostNames = source.ResolveHostNames,
        BackendMode = source.BackendMode,
        ImmediateQuarantineOnForget = source.ImmediateQuarantineOnForget,
        UiLanguage = source.UiLanguage,
        RuntimeQuarantines = source.RuntimeQuarantines.Select(item => new RuntimeQuarantineEntry
        {
            Id = item.Id,
            ExePath = item.ExePath,
            DisplayName = item.DisplayName
        }).ToList(),
        ServiceEnabled = source.ServiceEnabled,
        ConfirmBlockAll = source.ConfirmBlockAll,
        RemoveMissingOnStartup = source.RemoveMissingOnStartup,
        TrustVerifiedSystemProcesses = source.TrustVerifiedSystemProcesses,
        WindowLeft = source.WindowLeft,
        WindowTop = source.WindowTop,
        WindowWidth = source.WindowWidth,
        WindowHeight = source.WindowHeight,
        WindowMaximized = source.WindowMaximized
    };
}
