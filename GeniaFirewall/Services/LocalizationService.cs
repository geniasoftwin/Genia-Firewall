using System.Globalization;
using System.Windows;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public static class LocalizationService
{
    private static UiLanguage _requestedLanguage = UiLanguage.Auto;
    private static UiLanguage _effectiveLanguage = ResolveEffective(UiLanguage.Auto);

    public static UiLanguage RequestedLanguage => _requestedLanguage;
    public static UiLanguage EffectiveLanguage => _effectiveLanguage;
    public static CultureInfo Culture => _effectiveLanguage == UiLanguage.Russian
        ? CultureInfo.GetCultureInfo("ru-RU")
        : CultureInfo.GetCultureInfo("en-US");

    public static void Configure(UiLanguage language)
    {
        if (!Enum.IsDefined(language))
            language = UiLanguage.Auto;

        _requestedLanguage = language;
        _effectiveLanguage = ResolveEffective(language);

        var app = System.Windows.Application.Current;
        if (app is null)
            return;

        var dictionaries = app.Resources.MergedDictionaries;
        for (var i = dictionaries.Count - 1; i >= 0; i--)
        {
            var source = dictionaries[i].Source?.OriginalString ?? string.Empty;
            if (source.Contains("Strings.ru-RU.xaml", StringComparison.OrdinalIgnoreCase) ||
                source.Contains("Strings.en-US.xaml", StringComparison.OrdinalIgnoreCase))
            {
                dictionaries.RemoveAt(i);
            }
        }

        var fileName = _effectiveLanguage == UiLanguage.Russian
            ? "Resources/Strings.ru-RU.xaml"
            : "Resources/Strings.en-US.xaml";

        dictionaries.Insert(0, new ResourceDictionary
        {
            Source = new Uri(fileName, UriKind.Relative)
        });
    }

    public static string Get(string key)
    {
        try
        {
            if (System.Windows.Application.Current?.TryFindResource(key) is string value)
                return value;
        }
        catch
        {
        }

        return key;
    }

    public static string Format(string key, params object?[] args) =>
        string.Format(Culture, Get(key), args);

    public static string GetModeTitle(FirewallMode mode) => mode switch
    {
        FirewallMode.BlockAll => Get("Mode.BlockAll"),
        FirewallMode.AllowAll => Get("Mode.AllowAll"),
        FirewallMode.Monitor => Get("Mode.Monitor"),
        _ => Get("Mode.Normal")
    };

    private static UiLanguage ResolveEffective(UiLanguage language)
    {
        if (language == UiLanguage.Russian || language == UiLanguage.English)
            return language;

        return CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("ru", StringComparison.OrdinalIgnoreCase)
            ? UiLanguage.Russian
            : UiLanguage.English;
    }
}
