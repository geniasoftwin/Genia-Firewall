using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public sealed class AppStore
{
    private const int BackupCount = 5;
    private const long MaxPortableJsonBytes = 16L * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly SemaphoreSlim _ioLock = new(1, 1);
    private readonly string _dataDirectory;
    private readonly string _appsFile;
    private readonly string _settingsFile;
    private string? _recoveryNotice;
    private bool _applicationsDatabaseUnavailable;

    public AppStore()
    {
        // Portable-first: all mutable data lives beside the executable.
        _dataDirectory = Path.Combine(AppContext.BaseDirectory, "Data");
        _appsFile = Path.Combine(_dataDirectory, "apps.json");
        _settingsFile = Path.Combine(_dataDirectory, "settings.json");

        TryMigrateLegacyData();
    }

    public string DataDirectory => _dataDirectory;
    public string ApplicationsFile => _appsFile;
    public string SettingsFile => _settingsFile;
    public bool IsPortable => true;
    public bool ApplicationsDatabaseUnavailable => _applicationsDatabaseUnavailable;

    public void ValidatePortableStorage()
    {
        Directory.CreateDirectory(_dataDirectory);

        var probePath = Path.Combine(_dataDirectory, $".write-test-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(probePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.WriteByte(0x47);
                stream.Flush(flushToDisk: true);
            }
        }
        finally
        {
            try
            {
                if (File.Exists(probePath))
                    File.Delete(probePath);
            }
            catch
            {
            }
        }
    }

    public string? ConsumeRecoveryNotice()
    {
        var notice = _recoveryNotice;
        _recoveryNotice = null;
        return notice;
    }

    public async Task<List<ManagedApplication>> LoadApplicationsAsync()
    {
        await _ioLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _applicationsDatabaseUnavailable = false;
            return await LoadWithBackupsAsync<List<ManagedApplication>>(
                    _appsFile,
                    [],
                    onUnrecoverable: () => _applicationsDatabaseUnavailable = true)
                .ConfigureAwait(false);
        }
        finally
        {
            _ioLock.Release();
        }
    }

    public async Task SaveApplicationsAsync(IEnumerable<ManagedApplication> applications)
    {
        await _ioLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await SaveAtomicAsync(_appsFile, applications).ConfigureAwait(false);
        }
        finally
        {
            _ioLock.Release();
        }
    }

    public async Task<AppSettings> LoadSettingsAsync()
    {
        await _ioLock.WaitAsync().ConfigureAwait(false);
        try
        {
            return await LoadWithBackupsAsync(_settingsFile, new AppSettings()).ConfigureAwait(false);
        }
        finally
        {
            _ioLock.Release();
        }
    }

    public async Task SaveSettingsAsync(AppSettings settings)
    {
        await _ioLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await SaveAtomicAsync(_settingsFile, settings).ConfigureAwait(false);
        }
        finally
        {
            _ioLock.Release();
        }
    }

    public async Task ExportConfigurationAsync(
        string filePath,
        IReadOnlyCollection<ManagedApplication> applications,
        AppSettings settings)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("Не указан файл экспорта.", nameof(filePath));

        var configuration = new PortableConfiguration
        {
            ExportedAtUtc = DateTime.UtcNow,
            Applications = applications.Select(CloneApplication).ToList(),
            Settings = new PortableConfigurationSettings
            {
                ProtectionEnabled = settings.ProtectionEnabled,
                Mode = settings.Mode,
                PlayDetectionSound = settings.PlayDetectionSound,
                ShowTrayNotifications = settings.ShowTrayNotifications,
                ResolveHostNames = settings.ResolveHostNames,
                ImmediateQuarantineOnForget = settings.ImmediateQuarantineOnForget,
                UiLanguage = settings.UiLanguage,
                ConfirmBlockAll = settings.ConfirmBlockAll,
                RemoveMissingOnStartup = settings.RemoveMissingOnStartup,
                TrustVerifiedSystemProcesses = settings.TrustVerifiedSystemProcesses
            }
        };

        var directory = Path.GetDirectoryName(Path.GetFullPath(filePath));
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        var tempPath = filePath + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                             tempPath,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             16 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, configuration, JsonOptions).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }

            File.Move(tempPath, filePath, overwrite: true);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    public async Task<PortableConfiguration> ImportConfigurationAsync(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            throw new FileNotFoundException("Файл конфигурации не найден.", filePath);

        var configuration = await DeserializeAsync<PortableConfiguration>(filePath).ConfigureAwait(false)
                            ?? throw new InvalidDataException("Файл конфигурации пуст.");

        if (!string.Equals(configuration.Format, "GeniaFirewallPortableConfig", StringComparison.Ordinal) ||
            configuration.SchemaVersion != 1)
        {
            throw new InvalidDataException("Неподдерживаемый формат конфигурации GeniaFirewall.");
        }

        configuration.Applications ??= [];
        configuration.Settings ??= new PortableConfigurationSettings();
        if (configuration.Applications.Count > 5000)
            throw new InvalidDataException("В импортируемой конфигурации слишком много приложений.");

        return configuration;
    }

    public string GetDatabaseHealthDescription()
    {
        try
        {
            var apps = File.Exists(_appsFile) ? new FileInfo(_appsFile).Length : 0;
            var settings = File.Exists(_settingsFile) ? new FileInfo(_settingsFile).Length : 0;
            var backups = EnumerateBackupPaths(_appsFile).Count(File.Exists);
            return LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? $"apps.json: {FormatBytes(apps)} · settings.json: {FormatBytes(settings)} · резервных копий apps: {backups}/{BackupCount}"
                : $"apps.json: {FormatBytes(apps)} · settings.json: {FormatBytes(settings)} · app backups: {backups}/{BackupCount}";
        }
        catch (Exception ex)
        {
            return LocalizationService.EffectiveLanguage == UiLanguage.Russian
                ? $"Не удалось проверить portable-базу: {ex.Message}"
                : $"Failed to check the portable database: {ex.Message}";
        }
    }

    private async Task<T> LoadWithBackupsAsync<T>(string filePath, T fallback, Action? onUnrecoverable = null)
    {
        if (!File.Exists(filePath))
            return fallback;

        Exception? primaryError = null;
        try
        {
            return await DeserializeAsync<T>(filePath).ConfigureAwait(false) ?? fallback;
        }
        catch (Exception ex)
        {
            primaryError = ex;
        }

        foreach (var backupPath in EnumerateBackupPaths(filePath))
        {
            if (!File.Exists(backupPath))
                continue;

            try
            {
                var restored = await DeserializeAsync<T>(backupPath).ConfigureAwait(false);
                if (restored is null)
                    continue;

                File.Copy(backupPath, filePath, overwrite: true);
                _recoveryNotice = $"Повреждён файл {Path.GetFileName(filePath)}. Данные восстановлены из {Path.GetFileName(backupPath)}.";
                return restored;
            }
            catch
            {
            }
        }

        TryQuarantineCorruptFile(filePath);
        onUnrecoverable?.Invoke();
        _recoveryNotice = $"Не удалось прочитать {Path.GetFileName(filePath)}: {primaryError?.Message ?? "неизвестная ошибка"}. Повреждённый файл сохранён как .corrupt, использованы безопасные значения по умолчанию.";
        return fallback;
    }

    private static async Task<T?> DeserializeAsync<T>(string filePath)
    {
        var length = new FileInfo(filePath).Length;
        if (length > MaxPortableJsonBytes)
            throw new InvalidDataException($"Portable data file is too large ({length} bytes).");

        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions).ConfigureAwait(false);
    }

    private async Task SaveAtomicAsync<T>(string filePath, T value)
    {
        Directory.CreateDirectory(_dataDirectory);

        var tempPath = filePath + ".tmp";
        try
        {
            await using (var stream = new FileStream(
                             tempPath,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.None,
                             16 * 1024,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, value, JsonOptions).ConfigureAwait(false);
                await stream.FlushAsync().ConfigureAwait(false);
            }

            if (File.Exists(filePath))
            {
                RotateBackups(filePath);
                File.Copy(filePath, filePath + ".bak", overwrite: true);
            }

            File.Move(tempPath, filePath, overwrite: true);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    private static void RotateBackups(string filePath)
    {
        // .bak is newest; .bak.1 ... .bak.4 are progressively older.
        for (var index = BackupCount - 1; index >= 1; index--)
        {
            var source = index == 1 ? filePath + ".bak" : filePath + $".bak.{index - 1}";
            var destination = filePath + $".bak.{index}";

            if (File.Exists(source))
                File.Copy(source, destination, overwrite: true);
        }
    }

    private static IEnumerable<string> EnumerateBackupPaths(string filePath)
    {
        yield return filePath + ".bak";
        for (var index = 1; index < BackupCount; index++)
            yield return filePath + $".bak.{index}";
    }

    private static void TryDeleteFile(string filePath)
    {
        try
        {
            if (File.Exists(filePath))
                File.Delete(filePath);
        }
        catch
        {
        }
    }

    private static void TryQuarantineCorruptFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
                return;

            var quarantinePath = $"{filePath}.{DateTime.Now:yyyyMMdd-HHmmss}.corrupt";
            File.Move(filePath, quarantinePath, overwrite: false);
        }
        catch
        {
        }
    }

    private void TryMigrateLegacyData()
    {
        try
        {
            Directory.CreateDirectory(_dataDirectory);

            var legacyDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "GeniaFirewall");

            if (string.Equals(
                    Path.GetFullPath(legacyDirectory).TrimEnd(Path.DirectorySeparatorChar),
                    Path.GetFullPath(_dataDirectory).TrimEnd(Path.DirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            CopyLegacyFileIfNeeded(Path.Combine(legacyDirectory, "apps.json"), _appsFile);
            CopyLegacyFileIfNeeded(Path.Combine(legacyDirectory, "settings.json"), _settingsFile);
        }
        catch
        {
            // Migration is best-effort only; portable storage must still be usable from a clean folder.
        }
    }

    private void CopyLegacyFileIfNeeded(string source, string destination)
    {
        if (File.Exists(destination) || !File.Exists(source))
            return;

        File.Copy(source, destination, overwrite: false);
        _recoveryNotice = "Данные предыдущей тестовой версии перенесены в portable-папку Data.";
    }

    private static ManagedApplication CloneApplication(ManagedApplication application) => new()
    {
        Id = application.Id,
        Name = application.Name,
        ExePath = application.ExePath,
        // Temporary Allow is runtime state, not portable policy. Export it as Ask so importing a
        // configuration can never turn a ten-minute/process-lifetime decision into permanent Allow.
        Access = application.IsTemporaryAllow ? FirewallAccess.Ask : application.Access,
        RuleProfile = application.IsTemporaryAllow ? ApplicationRuleProfile.Default : application.RuleProfile,
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
        SuppressPromptNotifications = application.SuppressPromptNotifications
    };

    private static string FormatBytes(long value)
    {
        if (value <= 0)
            return "0 Б";
        if (value < 1024)
            return $"{value} Б";
        if (value < 1024 * 1024)
            return $"{value / 1024d:0.0} КБ";
        return $"{value / 1024d / 1024d:0.0} МБ";
    }
}
