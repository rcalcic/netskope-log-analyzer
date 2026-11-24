using System.Diagnostics;
using NetskopeLogAnalyzer.Core;

// Ferramenta de linha de comando (Linux/macOS/Windows) para análise em lote e validação:
//   nla-cli <pacote.zip|pasta|arquivos...> [--json-summary]
// Imprime o relatório em Markdown. Nada é enviado para fora da máquina.
if (args.Length == 0)
{
    Console.Error.WriteLine("uso: nla-cli <pacote.zip|pasta|arquivos...>");
    return 2;
}
var sw = Stopwatch.StartNew();
var r = new Analyzer().AnalyzePaths(args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)));
Console.WriteLine(Report.ToMarkdown(r));
Console.WriteLine();
Console.WriteLine("## Diagnóstico da ferramenta");
Console.WriteLine($"- tempo de análise: {sw.Elapsed.TotalSeconds:0.0} s; linhas: {r.Entries.Count:N0}; arquivos: {r.Files.Count}; capturas: {r.Captures.Count}");
Console.WriteLine($"- incidentes: {r.Incidents.Count}; achados: {r.Findings.Count}; séries: {r.Series.Count}; sessões NPA: {r.NpaSessions.Count}; score: {r.Score}");
foreach (var s in r.Series.Values.OrderBy(s => s.Key)) Console.WriteLine($"  - série {s.Key}: {s.Points.Count} pontos");
foreach (var c in r.Captures) Console.WriteLine($"  - captura {c.File}: {c.LinkType} {c.Packets} pacotes, {c.TcpFlows} fluxos, retrans {c.RetransPct:0.##}%, RST {c.Resets}, SYN sem resposta {c.HandshakeFailures}, DNS {string.Join(",", c.DnsRcodes.Select(k => k.Key + "=" + k.Value))}, erro {c.Error}");
foreach (var d in r.DnsInterfaces) Console.WriteLine($"  - dns {d.Interface} [{d.State}] {string.Join(",", d.Servers)} search={string.Join(",", d.Search)} {d.Note}");
foreach (var f in r.Findings.Where(f => f.Severity == Severity.Noise)) Console.WriteLine($"  - ruído: {f.Title} ({f.Count})");
foreach (var c in r.Config) Console.WriteLine($"  - cfg {c.Section} › {c.Item} = {c.Value}{(c.Attention ? " [!]" : "")}");
return 0;
