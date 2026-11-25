using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace NetskopeLogAnalyzer.Services;

public sealed record UpdateInfo(Version Version, string Tag, string Notes, string PageUrl, string? SetupUrl, string? SetupName, string? SumsUrl);

/// <summary>
/// Atualização automática: consulta a última release (GitHub ou espelho interno definido por política),
/// baixa o instalador, confere o SHA-256 publicado em SHA256SUMS.txt e executa a instalação silenciosa.
/// </summary>
public static class UpdateService
{
    public static Version Current => Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);

    private const long MaxSetupBytes = 400L * 1024 * 1024;

    /// <summary>Só HTTPS e só os hosts do GitHub (ou o host do espelho definido pelo TI na política).</summary>
    internal static bool AllowedUrl(string? url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return false;
        var host = u.Host.ToLowerInvariant();
        if (host is "api.github.com" or "github.com" or "objects.githubusercontent.com" or "release-assets.githubusercontent.com") return true;
        return Uri.TryCreate(AppSettings.UpdateFeedUrl, UriKind.Absolute, out var feed) && feed.Scheme == Uri.UriSchemeHttps && host == feed.Host.ToLowerInvariant();
    }

    private static readonly System.Text.RegularExpressions.Regex SetupNameRe = new(@"^NetskopeLogAnalyzer-\d+\.\d+\.\d+-Setup\.exe$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static HttpClient NewClient()
    {
        var h = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 }) { Timeout = TimeSpan.FromSeconds(60), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
        h.DefaultRequestHeaders.UserAgent.ParseAdd($"NetskopeLogAnalyzer/{Current.ToString(3)}");
        h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return h;
    }

    public static async Task<UpdateInfo?> CheckAsync(CancellationToken ct)
    {
        if (AppSettings.UpdatesDisabledByPolicy) return null;
        if (!AllowedUrl(AppSettings.UpdateFeedUrl)) return null;
        using var http = NewClient();
        using var doc = JsonDocument.Parse(await http.GetStringAsync(AppSettings.UpdateFeedUrl, ct));
        var root = doc.RootElement;
        var tag = root.GetProperty("tag_name").GetString() ?? "";
        if (!Version.TryParse(tag.TrimStart('v', 'V'), out var v)) return null;
        v = new Version(v.Major, v.Minor, Math.Max(0, v.Build));
        var cur = new Version(Current.Major, Current.Minor, Math.Max(0, Current.Build));
        if (v <= cur) return null;
        string? setupUrl = null, setupName = null, sumsUrl = null;
        if (root.TryGetProperty("assets", out var assets))
            foreach (var a in assets.EnumerateArray())
            {
                var name = a.GetProperty("name").GetString() ?? "";
                var url = a.GetProperty("browser_download_url").GetString();
                if (!AllowedUrl(url)) continue;
                if (SetupNameRe.IsMatch(name)) { setupUrl = url; setupName = name; }
                else if (name.Equals("SHA256SUMS.txt", StringComparison.OrdinalIgnoreCase)) sumsUrl = url;
            }
        var page = root.TryGetProperty("html_url", out var h) ? h.GetString() ?? "" : "";
        if (!AllowedUrl(page)) page = "https://github.com/rcalcic/netskope-log-analyzer/releases";
        var notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        if (notes.Length > 20000) notes = notes[..20000];
        return new UpdateInfo(v, tag, notes, page, setupUrl, setupName, sumsUrl);
    }

    /// <summary>Baixa o instalador e confere o hash. Lança exceção se o hash não bater.</summary>
    public static async Task<string> DownloadAndVerifyAsync(UpdateInfo u, IProgress<string>? progress, CancellationToken ct)
    {
        if (u.SetupUrl is null || u.SetupName is null) throw new InvalidOperationException("A release não tem instalador (Setup.exe).");
        if (u.SumsUrl is null) throw new InvalidOperationException("A release não publica SHA256SUMS.txt; a atualização não pode ser verificada.");
        if (!SetupNameRe.IsMatch(u.SetupName) || !AllowedUrl(u.SetupUrl) || !AllowedUrl(u.SumsUrl)) throw new InvalidOperationException("Endereço ou nome do instalador inválido; a atualização foi cancelada.");
        using var http = NewClient();
        // pasta nova e aleatória a cada atualização: outro processo não consegue trocar o instalador antes da verificação
        var dir = Path.Combine(Path.GetTempPath(), "NetskopeLogAnalyzer-update-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, Path.GetFileName(u.SetupName));
        progress?.Report($"Baixando {u.SetupName}…");
        using (var resp = await http.GetAsync(u.SetupUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            resp.EnsureSuccessStatusCode();
            var total = resp.Content.Headers.ContentLength;
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(path);
            var buf = new byte[81920]; long done = 0; int n; var lastPct = -1;
            if (total is long declared && declared > MaxSetupBytes) throw new InvalidOperationException("Instalador maior que o esperado; a atualização foi cancelada.");
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
                done += n;
                if (done > MaxSetupBytes) throw new InvalidOperationException("Instalador maior que o esperado; a atualização foi cancelada.");
                if (total is long t && t > 0) { var pct = (int)(100 * done / t); if (pct != lastPct && pct % 5 == 0) { lastPct = pct; progress?.Report($"Baixando… {pct}%"); } }
            }
        }
        progress?.Report("Verificando a assinatura de integridade (SHA-256)…");
        var sums = await http.GetStringAsync(u.SumsUrl, ct);
        var expected = sums.Split('\n').Select(l => l.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(p => p.Length == 2 && p[1].TrimStart('*').Equals(u.SetupName, StringComparison.OrdinalIgnoreCase) && p[0].Length == 64)
            .Select(p => p[0]).FirstOrDefault();
        if (expected is null) throw new InvalidOperationException("O instalador não aparece em SHA256SUMS.txt.");
        string actual;
        await using (var fs = File.OpenRead(path)) actual = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct));
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            try { File.Delete(path); } catch (Exception) { }
            throw new InvalidOperationException($"O hash do instalador não confere (esperado {expected}, obtido {actual}). A atualização foi cancelada.");
        }
        return path;
    }

    /// <summary>Instalado por máquina (Program Files) → precisa de elevação (UAC).</summary>
    public static bool IsPerMachine
    {
        get
        {
            var exe = Environment.ProcessPath ?? "";
            return exe.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase)
                || exe.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>Instalado pelo Setup (por máquina ou por usuário); a versão portátil não se atualiza sozinha.</summary>
    public static bool IsInstalled
    {
        get
        {
            var dir = Path.GetDirectoryName(Environment.ProcessPath ?? "") ?? "";
            return File.Exists(Path.Combine(dir, "unins000.exe"));
        }
    }

    /// <summary>Executa a instalação silenciosa; o instalador fecha este app e o reabre ao final.</summary>
    public static void LaunchInstaller(string setupPath)
    {
        var args = "/SILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS " + (IsPerMachine ? "/ALLUSERS" : "/CURRENTUSER");
        var psi = new ProcessStartInfo(setupPath, args) { UseShellExecute = true };
        if (IsPerMachine) psi.Verb = "runas";
        // mantém o arquivo aberto só para leitura enquanto o instalador inicia: ninguém consegue trocá-lo depois da verificação do hash
        var guard = new FileStream(setupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try { Process.Start(psi); }
        finally { _ = Task.Delay(TimeSpan.FromSeconds(20)).ContinueWith(_ => guard.Dispose(), TaskScheduler.Default); }
    }
}
