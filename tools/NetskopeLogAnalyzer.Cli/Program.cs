using System.Diagnostics;
using NetskopeLogAnalyzer.Core;

// Ferramenta de linha de comando (Linux/macOS/Windows) para análise em lote e validação:
//   nla-cli <pacote.zip|pasta|arquivos...> [--json-summary]
// Imprime o relatório em Markdown. Nada é enviado para fora da máquina.
if (args.Length == 0)
{
    Console.Error.WriteLine("uso: nla-cli <pacote.zip|pasta|arquivos...> [--sintomas " + string.Join(",", FocusAnalyzer.All.Select(x => x.Id)) + "] [--site dominio] [--horario \"dd/MM/aaaa HH:mm\"]");
    return 2;
}
// opções: --sintomas lentidao,dns  --site exemplo.com  --horario "23/11/2026 12:44"
var opts = new AnalysisOptions();
var files = new List<string>();
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--sintomas" when i + 1 < args.Length:
            foreach (var s in args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) opts.Symptoms.Add(s);
            break;
        case "--site" when i + 1 < args.Length: opts.Domain = args[++i]; break;
        case "--horario" when i + 1 < args.Length:
            if (DateTime.TryParse(args[++i], System.Globalization.CultureInfo.GetCultureInfo("pt-BR"), System.Globalization.DateTimeStyles.None, out var t)) opts.ProblemTime = t;
            break;
        default: if (!args[i].StartsWith("--", StringComparison.Ordinal)) files.Add(args[i]); break;
    }
}
var sw = Stopwatch.StartNew();
var r = new Analyzer { Options = opts }.AnalyzePaths(files);
Console.WriteLine(Report.ToMarkdown(r));
Console.WriteLine();
Console.WriteLine("## Diagnóstico da ferramenta");
Console.WriteLine($"- tempo de análise: {sw.Elapsed.TotalSeconds:0.0} s; linhas: {r.Entries.Count:N0}; arquivos: {r.Files.Count}; capturas: {r.Captures.Count}");
Console.WriteLine($"- incidentes: {r.Incidents.Count}; achados: {r.Findings.Count}; séries: {r.Series.Count}; sessões NPA: {r.NpaSessions.Count}; score: {r.Score}");
foreach (var s in r.Series.Values.OrderBy(s => s.Key)) Console.WriteLine($"  - série {s.Key}: {s.Points.Count} pontos");
foreach (var c in r.Captures) Console.WriteLine($"  - captura {c.File}: {c.LinkType} {c.Packets} pacotes, {c.TcpFlows} fluxos, retrans {c.RetransPct:0.##}%, RST {c.Resets}, SYN sem resposta {c.HandshakeFailures}, DNS {string.Join(",", c.DnsRcodes.Select(k => k.Key + "=" + k.Value))}, erro {c.Error}");
foreach (var d in r.DnsInterfaces) Console.WriteLine($"  - dns {d.Interface} [{d.State}] {string.Join(",", d.Servers)} search={string.Join(",", d.Search)} {d.Note}");
foreach (var f in r.Findings.Where(f => f.Severity == Severity.Noise)) Console.WriteLine($"  - ruído: {f.Title} ({f.Count})");
foreach (var g in r.DataGaps) Console.WriteLine($"  - lacuna: {g}");
foreach (var c in r.Config) Console.WriteLine($"  - cfg {c.Section} › {c.Item} = {c.Value}{(c.Attention ? " [!]" : "")}");
return 0;
