using System.Diagnostics;
using System.IO;
using System.IO.Compression;

namespace NetskopeLogAnalyzer.Services;

/// <summary>Gera pacotes de diagnóstico desta máquina: logs do Netskope Client (nsdiag -o) + telemetria do coletor.</summary>
public static class DiagnosticsPackager
{
    public static string? NsdiagPath
    {
        get
        {
            foreach (var root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                var p = Path.Combine(Environment.GetFolderPath(root), "Netskope", "STAgent", "nsdiag.exe");
                if (File.Exists(p)) return p;
            }
            return null;
        }
    }

    /// <summary>Salva os logs do Netskope Client desta máquina (equivalente a “Save logs”). Retorna o .zip ou null.</summary>
    public static async Task<string?> SaveNetskopeLogsAsync(string folder, IProgress<string>? progress, CancellationToken ct)
    {
        var nsdiag = NsdiagPath;
        if (nsdiag is null) return null;
        Directory.CreateDirectory(folder);
        var zip = Path.Combine(folder, $"NetskopeLogs-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmmss}.zip");
        progress?.Report("Coletando os logs do Netskope Client (pode levar até 2 minutos)…");
        var psi = new ProcessStartInfo(nsdiag, $"-o \"{zip}\"") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = Process.Start(psi)!;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromMinutes(4));
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch (Exception) { } }
        // o nsdiag às vezes termina antes de fechar o arquivo
        for (var i = 0; i < 20 && !IsComplete(zip); i++) await Task.Delay(500, ct);
        return IsComplete(zip) ? zip : null;
    }

    private static bool IsComplete(string zip)
    {
        try
        {
            if (!File.Exists(zip) || new FileInfo(zip).Length < 100) return false;
            using var z = ZipFile.OpenRead(zip);
            return z.Entries.Count > 0;
        }
        catch (Exception) { return false; }
    }

    /// <summary>Exporta um pacote único (logs do Netskope + telemetria) para enviar ao suporte.</summary>
    public static async Task<string> ExportAsync(string destZip, int telemetryDays, IProgress<string>? progress, CancellationToken ct)
    {
        var tmp = Path.Combine(Path.GetTempPath(), "NetskopeLogAnalyzer-export-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tmp);
        try
        {
            var ns = await SaveNetskopeLogsAsync(tmp, progress, ct);
            var tel = Path.Combine(tmp, "telemetria");
            Directory.CreateDirectory(tel);
            foreach (var f in TelemetryCollector.LocalTelemetryFiles(telemetryDays))
            {
                progress?.Report("Copiando telemetria " + Path.GetFileName(f) + "…");
                using var src = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var dst = File.Create(Path.Combine(tel, Path.GetFileName(f)));
                await src.CopyToAsync(dst, ct);
            }
            File.WriteAllText(Path.Combine(tmp, "LEIA-ME.txt"),
                $"Pacote de diagnóstico gerado pelo Netskope Log Analyzer em {DateTime.Now:dd/MM/yyyy HH:mm} na máquina {Environment.MachineName}.\r\n" +
                (ns is null ? "Os logs do Netskope Client não puderam ser coletados (cliente não instalado ou sem permissão).\r\n" : "") +
                "Abra este arquivo no Netskope Log Analyzer para analisar.\r\n");
            if (File.Exists(destZip)) File.Delete(destZip);
            progress?.Report("Compactando…");
            ZipFile.CreateFromDirectory(tmp, destZip, CompressionLevel.Optimal, false);
            return destZip;
        }
        finally
        {
            try { Directory.Delete(tmp, true); } catch (Exception) { }
        }
    }
}
