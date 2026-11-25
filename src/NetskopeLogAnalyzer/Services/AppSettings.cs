using System.IO;
using System.Text.Json;
using Microsoft.Win32;

namespace NetskopeLogAnalyzer.Services;

/// <summary>Configurações do usuário (%LOCALAPPDATA%\NetskopeLogAnalyzer\settings.json) e políticas do TI (HKLM).</summary>
public sealed class AppSettings
{
    public static string DataDir { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetskopeLogAnalyzer");
    private static string FilePath => Path.Combine(DataDir, "settings.json");

    /// <summary>Tema da interface: "Sistema", "Claro" ou "Escuro".</summary>
    public string Theme { get; set; } = "Sistema";
    public bool AutoCheckUpdates { get; set; } = true;
    public bool AutoInstallUpdates { get; set; }
    public DateTime? LastUpdateCheck { get; set; }
    public string? SkippedVersion { get; set; }

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch (Exception) { }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception) { }
    }

    // ---------------------------------------------------------------- políticas (HKLM\Software\Policies\NetskopeLogAnalyzer)

    private const string PolicyKey = @"Software\Policies\NetskopeLogAnalyzer";

    private static object? Policy(string name)
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(PolicyKey);
            return k?.GetValue(name);
        }
        catch (Exception) { return null; }
    }

    /// <summary>DisableUpdates (DWORD 1) desliga a verificação e a instalação de atualizações.</summary>
    public static bool UpdatesDisabledByPolicy => Policy("DisableUpdates") is int i && i != 0;

    /// <summary>UpdateFeedUrl (texto) aponta para um espelho interno com o mesmo formato da API de releases do GitHub.</summary>
    public static string UpdateFeedUrl => Policy("UpdateFeedUrl") as string is { Length: > 0 } u ? u : "https://api.github.com/repos/rcalcic/netskope-log-analyzer/releases/latest";
}
