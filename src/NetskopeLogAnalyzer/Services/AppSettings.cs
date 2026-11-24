using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace NetskopeLogAnalyzer.Services;

/// <summary>Configurações do usuário (%LOCALAPPDATA%\NetskopeLogAnalyzer\settings.json) e políticas do TI (HKLM).</summary>
public sealed class AppSettings
{
    public static string DataDir { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetskopeLogAnalyzer");
    public static string TelemetryDir => Path.Combine(DataDir, "telemetry");
    private static string FilePath => Path.Combine(DataDir, "settings.json");

    /// <summary>Tenant Netskope (ex.: "acme" ou "acme.eu"); usado nos testes até o POP.</summary>
    public string? Tenant { get; set; }
    public List<string> ProbeUrls { get; set; } = new() { "https://www.microsoft.com", "https://www.google.com", "https://outlook.office.com" };
    public int IntervalSeconds { get; set; } = 30;
    public int ProbeSeconds { get; set; } = 60;
    public int TraceMinutes { get; set; } = 15;
    public int RetentionDays { get; set; } = 14;
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
        var s = new AppSettings();
        s.Tenant = DetectTenant();
        return s;
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

    /// <summary>Tenta descobrir o tenant pelos arquivos do Netskope Client instalado nesta máquina.</summary>
    public static string? DetectTenant()
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "netskope", "stagent");
        foreach (var name in new[] { "nsconfig.json", "nssteering.json", "nsbranding.json", "nsuser.conf" })
        {
            try
            {
                var f = Path.Combine(dir, name);
                if (!File.Exists(f)) continue;
                var m = Regex.Match(File.ReadAllText(f), @"(?:addon|achecker|gateway|nsauth|aproxy)-([a-z0-9]+(?:\.(?:eu|de|au))?)\.goskope\.com", RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups[1].Value.ToLowerInvariant();
            }
            catch (Exception) { }
        }
        return null;
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

    /// <summary>DisableCollector (DWORD 1) impede o uso do coletor de telemetria.</summary>
    public static bool CollectorDisabledByPolicy => Policy("DisableCollector") is int i && i != 0;

    /// <summary>Tenant (texto) definido pelo TI para todos os usuários.</summary>
    public static string? PolicyTenant => Policy("Tenant") as string;
}
