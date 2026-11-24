using System.Globalization;
using System.Text;

namespace NetskopeLogAnalyzer.Core;

public static class Report
{
    public static string SeverityLabel(Severity s) => s switch
    {
        Severity.Critical => "Crítico",
        Severity.Warning => "Atenção",
        Severity.Info => "Informativo",
        _ => "Ruído conhecido",
    };

    public static string Time(DateTime? t) => t is DateTime d ? d.ToString("dd/MM HH:mm:ss", CultureInfo.InvariantCulture) : "—";

    public static string Verdict(AnalysisResult r)
    {
        int c = r.Count(Severity.Critical), w = r.Count(Severity.Warning);
        if (c > 0) return c == 1 ? "1 problema crítico encontrado" : $"{c} problemas críticos encontrados";
        if (w > 0) return w == 1 ? "Sem falhas críticas, 1 ponto de atenção" : $"Sem falhas críticas, {w} pontos de atenção";
        return "Nenhum problema relevante encontrado";
    }

    /// <summary>Relatório em Markdown, pronto para colar num chamado.</summary>
    public static string ToMarkdown(AnalysisResult r)
    {
        var F = r.Facts;
        var sb = new StringBuilder();
        sb.AppendLine("# Análise de logs Netskope" + (F.Host != null ? " — " + F.Host : ""));
        sb.AppendLine($"Período: {Time(r.Start)} → {Time(r.End)} | Versão: {F.Version ?? "—"} | SO: {F.OsName ?? F.Os ?? "—"} | Tenant: {F.TenantHost ?? F.TenantId ?? "—"}");
        sb.AppendLine($"Resultado: {Verdict(r)} ({r.Count(Severity.Critical)} crítico(s), {r.Count(Severity.Warning)} de atenção, {r.Count(Severity.Info)} informativo(s), {r.Count(Severity.Noise)} ruído(s) conhecido(s)).");
        sb.AppendLine();
        foreach (var f in r.Findings.Where(f => f.Severity != Severity.Noise))
        {
            sb.AppendLine($"## [{SeverityLabel(f.Severity)}] {f.Title} ({f.Count}x)");
            if (f.First != null) sb.AppendLine($"Período: {Time(f.First)} → {Time(f.Last)}");
            sb.AppendLine("O que significa: " + f.Meaning);
            sb.AppendLine("Como resolver:");
            var steps = f.Steps.Count > 0 ? f.Steps : new List<FixStep> { new(f.Action) };
            for (var i = 0; i < steps.Count; i++)
            {
                sb.AppendLine($"{i + 1}. {steps[i].Text}");
                if (steps[i].Command != null) { sb.AppendLine("```"); sb.AppendLine(steps[i].Command); sb.AppendLine("```"); }
            }
            if (f.References.Count > 0) sb.AppendLine("Referências: " + string.Join(" , ", f.References.Select(x => x.Url)));
            sb.AppendLine();
        }
        if (r.Events.Count > 0)
        {
            sb.AppendLine("## Linha do tempo");
            foreach (var e in r.Events) sb.AppendLine($"- {Time(e.Time)} {e.Label}{(e.Detail.Length > 0 ? " (" + e.Detail + ")" : "")}");
        }
        return sb.ToString();
    }
}
