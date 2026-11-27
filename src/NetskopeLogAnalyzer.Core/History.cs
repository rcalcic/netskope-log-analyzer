using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetskopeLogAnalyzer.Core;

/// <summary>Resumo de uma análise guardado no histórico local (só no computador do analista).</summary>
public sealed class HistoryEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime AnalyzedAt { get; set; }
    public string Packages { get; set; } = "";
    public string? Host { get; set; }
    public string? Email { get; set; }
    public string? Login { get; set; }
    public string? Version { get; set; }
    public string? Os { get; set; }
    public DateTime? Start { get; set; }
    public DateTime? End { get; set; }
    public string Verdict { get; set; } = "";
    public int Critical { get; set; }
    public int Warning { get; set; }
    public int? Score { get; set; }
    public int NpaDrops { get; set; }
    public int TunnelDrops { get; set; }
    public string? Symptoms { get; set; }
    public List<HistoryFinding> Findings { get; set; } = new();
}

public sealed record HistoryFinding(string Key, string Title, Severity Severity, int Count, DateTime? Last);

/// <summary>Comparação da análise atual com a anterior da mesma máquina.</summary>
public sealed class HistoryComparison
{
    public required HistoryEntry Previous { get; init; }
    public List<HistoryEntry> Machine { get; } = new();
    public List<string> New { get; } = new();
    public List<string> Resolved { get; } = new();
    public List<string> Persistent { get; } = new();
    public List<string> Changes { get; } = new();
}

/// <summary>
/// Histórico local das análises: permite comparar pacotes da mesma máquina ao longo do tempo
/// (o que apareceu, o que sumiu, troca de versão). Guarda só o resumo, nunca as linhas de log.
/// </summary>
public sealed class HistoryStore
{
    public const int MaxEntries = 500;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false, Converters = { new JsonStringEnumConverter() } };
    private readonly string _path;

    public HistoryStore(string path) => _path = path;

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetskopeLogAnalyzer", "historico.json");

    public List<HistoryEntry> Load()
    {
        try
        {
            if (!File.Exists(_path)) return new();
            var fi = new FileInfo(_path);
            if (fi.Length > 50_000_000) return new();
            return JsonSerializer.Deserialize<List<HistoryEntry>>(File.ReadAllText(_path), Json) ?? new();
        }
        catch (Exception) { return new(); }
    }

    public void Save(List<HistoryEntry> all)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(all.OrderByDescending(e => e.AnalyzedAt).Take(MaxEntries).ToList(), Json));
        File.Move(tmp, _path, overwrite: true);
    }

    public void Clear() { try { File.Delete(_path); } catch (IOException) { } }

    public static HistoryEntry From(AnalysisResult r, string packages)
    {
        string? Id(string label) => r.Identity.FirstOrDefault(i => i.Label == label)?.Value;
        var e = new HistoryEntry
        {
            AnalyzedAt = DateTime.Now,
            Packages = packages,
            Host = r.Facts.Host ?? Id("Hostname"),
            Email = Id("E-mail registrado no Netskope"),
            Login = Id("Login no sistema operacional"),
            Version = r.Facts.Version,
            Os = r.Facts.OsName ?? r.Facts.Os,
            Start = r.Start,
            End = r.End,
            Verdict = Report.Verdict(r),
            Critical = r.Count(Severity.Critical),
            Warning = r.Count(Severity.Warning),
            Score = r.Score is double sc ? (int)Math.Round(sc) : null,
            NpaDrops = r.NpaSessions.Count(s => s.End != null && !s.Expected),
            TunnelDrops = r.Findings.FirstOrDefault(f => f.Key == "tundown")?.Count ?? 0,
            Symptoms = r.Options.Symptoms.Count > 0 ? string.Join(",", r.Options.Symptoms) : null,
        };
        e.Findings.AddRange(r.Findings.Where(f => f.Severity <= Severity.Warning && !f.Historical)
            .Select(f => new HistoryFinding(f.Key, f.Title, f.Severity, f.Count, f.Last)));
        return e;
    }

    /// <summary>Mesma máquina: hostname igual (sem diferenciar maiúsculas) ou, sem hostname, o mesmo e-mail.</summary>
    public static bool SameMachine(HistoryEntry a, HistoryEntry b) =>
        a.Host is { Length: > 0 } && b.Host is { Length: > 0 }
            ? string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase)
            : a.Email is { Length: > 0 } && string.Equals(a.Email, b.Email, StringComparison.OrdinalIgnoreCase);

    /// <summary>Mesmo pacote analisado de novo: mesma máquina e mesmo fim de log.</summary>
    public static bool SamePackage(HistoryEntry a, HistoryEntry b) => SameMachine(a, b) && a.End == b.End;

    /// <summary>Grava a análise (substituindo o mesmo pacote se já existir) e devolve a comparação com o pacote anterior.</summary>
    public HistoryComparison? Record(HistoryEntry current, bool save = true)
    {
        var all = Load();
        all.RemoveAll(e => SamePackage(e, current));
        var machine = all.Where(e => SameMachine(e, current)).OrderByDescending(e => e.End ?? e.AnalyzedAt).ToList();
        if (save) { all.Add(current); Save(all); }
        var prev = machine.FirstOrDefault(e => (e.End ?? DateTime.MinValue) < (current.End ?? DateTime.MaxValue)) ?? machine.FirstOrDefault();
        if (prev is null) return null;
        var cmp = new HistoryComparison { Previous = prev };
        cmp.Machine.AddRange(machine);
        var now = current.Findings.ToDictionary(f => f.Key, f => f);
        var before = prev.Findings.ToDictionary(f => f.Key, f => f);
        foreach (var f in current.Findings)
            (before.ContainsKey(f.Key) ? cmp.Persistent : cmp.New).Add(f.Title);
        foreach (var f in prev.Findings.Where(f => !now.ContainsKey(f.Key))) cmp.Resolved.Add(f.Title);
        if (prev.Version != current.Version && prev.Version != null && current.Version != null)
            cmp.Changes.Add($"Versão do cliente: {prev.Version} → {current.Version}");
        if (prev.Os != current.Os && prev.Os != null && current.Os != null) cmp.Changes.Add($"Sistema: {prev.Os} → {current.Os}");
        if (prev.Score is int a && current.Score is int b && Math.Abs(a - b) >= 5) cmp.Changes.Add($"Experience Score: {a} → {b}");
        if (prev.Critical != current.Critical) cmp.Changes.Add($"Problemas críticos: {prev.Critical} → {current.Critical}");
        return cmp;
    }
}
