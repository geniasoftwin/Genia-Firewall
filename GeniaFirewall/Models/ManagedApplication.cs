using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using System.Windows.Media;
using GeniaFirewall.Services;

namespace GeniaFirewall.Models;

public sealed class ManagedApplication : INotifyPropertyChanged
{
    private Guid _id = Guid.NewGuid();
    private string _name = string.Empty;
    private string _exePath = string.Empty;
    private FirewallAccess _access = FirewallAccess.Ask;
    private ApplicationRuleProfile _ruleProfile = ApplicationRuleProfile.Default;
    private DateTime? _lastSeenAt;
    private string _lastConnection = string.Empty;
    private string _lastProtocol = string.Empty;
    private bool _seenTcp;
    private bool _seenUdp;
    private string _sha256 = string.Empty;
    private long _fileLength;
    private DateTime? _fileLastWriteUtc;
    private bool _fingerprintChanged;
    private string _publisher = string.Empty;
    private string _signatureStatus = string.Empty;
    private bool _signatureTrusted;
    private bool _isTrustedSystem;
    private string _trustReason = string.Empty;
    private DateTime? _temporaryAllowUntilUtc;
    private int _temporaryAllowProcessId;
    private ImageSource? _iconSource;
    private bool _suppressPromptNotifications;
    private int _parentProcessId;
    private string _parentProcessName = string.Empty;
    private string _parentProcessPath = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public Guid Id
    {
        get => _id;
        set => SetField(ref _id, value);
    }

    public string Name
    {
        get => _name;
        set
        {
            if (!SetField(ref _name, value))
                return;
            OnPropertyChanged(nameof(Initial));
        }
    }

    public string ExePath
    {
        get => _exePath;
        set
        {
            if (!SetField(ref _exePath, value))
                return;
            OnPropertyChanged(nameof(ShortPath));
        }
    }

    public FirewallAccess Access
    {
        get => _access;
        set
        {
            if (!SetField(ref _access, value))
                return;
            OnPropertyChanged(nameof(AccessLabel));
            OnPropertyChanged(nameof(RuleProfileLabel));
        }
    }

    public ApplicationRuleProfile RuleProfile
    {
        get => _ruleProfile;
        set
        {
            if (!SetField(ref _ruleProfile, value))
                return;
            OnPropertyChanged(nameof(AccessLabel));
            OnPropertyChanged(nameof(RuleProfileLabel));
        }
    }

    public DateTime? LastSeenAt
    {
        get => _lastSeenAt;
        set
        {
            if (!SetField(ref _lastSeenAt, value))
                return;
            OnPropertyChanged(nameof(LastSeenLabel));
        }
    }

    public string LastConnection
    {
        get => _lastConnection;
        set => SetField(ref _lastConnection, value);
    }

    public string LastProtocol
    {
        get => _lastProtocol;
        set
        {
            if (!SetField(ref _lastProtocol, value))
                return;
            OnPropertyChanged(nameof(ProtocolLabel));
        }
    }

    public bool SeenTcp
    {
        get => _seenTcp;
        set
        {
            if (!SetField(ref _seenTcp, value))
                return;
            OnPropertyChanged(nameof(ProtocolLabel));
        }
    }

    public bool SeenUdp
    {
        get => _seenUdp;
        set
        {
            if (!SetField(ref _seenUdp, value))
                return;
            OnPropertyChanged(nameof(ProtocolLabel));
        }
    }

    public string Sha256
    {
        get => _sha256;
        set => SetField(ref _sha256, value);
    }

    public long FileLength
    {
        get => _fileLength;
        set => SetField(ref _fileLength, value);
    }

    public DateTime? FileLastWriteUtc
    {
        get => _fileLastWriteUtc;
        set => SetField(ref _fileLastWriteUtc, value);
    }

    public bool FingerprintChanged
    {
        get => _fingerprintChanged;
        set
        {
            if (!SetField(ref _fingerprintChanged, value))
                return;
            OnPropertyChanged(nameof(AccessLabel));
        }
    }

    public string Publisher
    {
        get => _publisher;
        set => SetField(ref _publisher, value ?? string.Empty);
    }

    public string SignatureStatus
    {
        get => _signatureStatus;
        set => SetField(ref _signatureStatus, value ?? string.Empty);
    }

    public bool SignatureTrusted
    {
        get => _signatureTrusted;
        set => SetField(ref _signatureTrusted, value);
    }

    public bool IsTrustedSystem
    {
        get => _isTrustedSystem;
        set
        {
            if (!SetField(ref _isTrustedSystem, value))
                return;
            OnPropertyChanged(nameof(TrustLabel));
            OnPropertyChanged(nameof(AccessLabel));
        }
    }

    public string TrustReason
    {
        get => _trustReason;
        set
        {
            if (!SetField(ref _trustReason, value ?? string.Empty))
                return;
            OnPropertyChanged(nameof(TrustLabel));
        }
    }

    public DateTime? TemporaryAllowUntilUtc
    {
        get => _temporaryAllowUntilUtc;
        set
        {
            if (!SetField(ref _temporaryAllowUntilUtc, value))
                return;
            OnPropertyChanged(nameof(IsTemporaryAllow));
            OnPropertyChanged(nameof(AccessLabel));
            OnPropertyChanged(nameof(TemporaryAllowLabel));
        }
    }

    public int TemporaryAllowProcessId
    {
        get => _temporaryAllowProcessId;
        set
        {
            if (!SetField(ref _temporaryAllowProcessId, value))
                return;
            OnPropertyChanged(nameof(IsTemporaryAllow));
            OnPropertyChanged(nameof(AccessLabel));
            OnPropertyChanged(nameof(TemporaryAllowLabel));
        }
    }


    public bool SuppressPromptNotifications
    {
        get => _suppressPromptNotifications;
        set => SetField(ref _suppressPromptNotifications, value);
    }

    public int ParentProcessId
    {
        get => _parentProcessId;
        set
        {
            if (!SetField(ref _parentProcessId, value))
                return;
            OnPropertyChanged(nameof(ProgramSubtitle));
            OnPropertyChanged(nameof(ProgramToolTip));
        }
    }

    public string ParentProcessName
    {
        get => _parentProcessName;
        set
        {
            if (!SetField(ref _parentProcessName, value ?? string.Empty))
                return;
            OnPropertyChanged(nameof(ProgramSubtitle));
            OnPropertyChanged(nameof(ProgramToolTip));
        }
    }

    public string ParentProcessPath
    {
        get => _parentProcessPath;
        set
        {
            if (!SetField(ref _parentProcessPath, value ?? string.Empty))
                return;
            OnPropertyChanged(nameof(ProgramToolTip));
        }
    }

    [JsonIgnore]
    public ImageSource? IconSource
    {
        get => _iconSource;
        set => SetField(ref _iconSource, value);
    }

    [JsonIgnore]
    public string ProgramSubtitle => string.IsNullOrWhiteSpace(ParentProcessName)
        ? string.Empty
        : $"↳ {ParentProcessName}";

    [JsonIgnore]
    public string ProgramToolTip
    {
        get
        {
            if (string.IsNullOrWhiteSpace(ParentProcessName))
                return ExePath;

            var parent = string.IsNullOrWhiteSpace(ParentProcessPath)
                ? ParentProcessName
                : ParentProcessPath;
            return $"{ExePath}\nParent: {parent} · PID {ParentProcessId}";
        }
    }

    [JsonIgnore]
    public string Initial => string.IsNullOrWhiteSpace(Name)
        ? "?"
        : Name[..1].ToUpperInvariant();

    [JsonIgnore]
    public string AccessLabel => FingerprintChanged
        ? LocalizationService.Get("Access.Changed")
        : IsTrustedSystem && Access == FirewallAccess.Allow
            ? LocalizationService.Get("Access.AutoAllowed")
            : IsTemporaryAllow && Access == FirewallAccess.Allow
                ? TemporaryAllowLabel
                : RuleProfileLabel;

    [JsonIgnore]
    public string RuleProfileLabel => RuleProfile switch
    {
        ApplicationRuleProfile.EnableAll when Access == FirewallAccess.Allow => LocalizationService.Get("Access.EnableAll"),
        ApplicationRuleProfile.OutgoingOnly when Access == FirewallAccess.Allow => LocalizationService.Get("Access.OutgoingOnly"),
        ApplicationRuleProfile.IncomingOnly => LocalizationService.Get("Access.IncomingOnly"),
        ApplicationRuleProfile.DisableAll when Access == FirewallAccess.Block => LocalizationService.Get("Access.DisableAll"),
        ApplicationRuleProfile.Ask when Access == FirewallAccess.Ask => LocalizationService.Get("Access.Ask"),
        _ => Access switch
        {
            FirewallAccess.Allow => LocalizationService.Get("Access.Allow"),
            FirewallAccess.Block => LocalizationService.Get("Access.Block"),
            _ => LocalizationService.Get("Access.Ask")
        }
    };

    [JsonIgnore]
    public bool HasQuickRuleProfile => RuleProfile != ApplicationRuleProfile.Default;

    [JsonIgnore]
    public bool IsTemporaryAllow => TemporaryAllowUntilUtc is not null || TemporaryAllowProcessId > 0;

    [JsonIgnore]
    public string TemporaryAllowLabel
    {
        get
        {
            if (TemporaryAllowProcessId > 0)
                return LocalizationService.Get("Temp.UntilExit");

            if (TemporaryAllowUntilUtc is not null)
                return LocalizationService.Get("Temp.TenMinutes");

            return string.Empty;
        }
    }

    [JsonIgnore]
    public string TrustLabel => IsTrustedSystem ? LocalizationService.Get("Trust.System") : "—";

    [JsonIgnore]
    public string LastSeenLabel => LastSeenAt is null
        ? "—"
        : LastSeenAt.Value.ToLocalTime().ToString("dd.MM HH:mm:ss");

    [JsonIgnore]
    public string ProtocolLabel
    {
        get
        {
            if (SeenTcp && SeenUdp)
                return "TCP/UDP";
            if (SeenTcp)
                return "TCP";
            if (SeenUdp)
                return "UDP";
            return string.IsNullOrWhiteSpace(LastProtocol) ? "—" : LastProtocol;
        }
    }

    [JsonIgnore]
    public string ShortPath
    {
        get
        {
            if (string.IsNullOrWhiteSpace(ExePath))
                return string.Empty;

            var fileName = Path.GetFileName(ExePath);
            var directory = Path.GetDirectoryName(ExePath);
            if (string.IsNullOrWhiteSpace(directory))
                return fileName;

            return ExePath.Length <= 84 ? ExePath : $"…\\{new DirectoryInfo(directory).Name}\\{fileName}";
        }
    }

    public void RefreshLocalizedProperties()
    {
        OnPropertyChanged(nameof(AccessLabel));
        OnPropertyChanged(nameof(RuleProfileLabel));
        OnPropertyChanged(nameof(TemporaryAllowLabel));
        OnPropertyChanged(nameof(TrustLabel));
        OnPropertyChanged(nameof(LastSeenLabel));
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
