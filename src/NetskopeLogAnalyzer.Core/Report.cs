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

    /// <summary>Relatório em Markdown para documentar o caso.</summary>
    public static string ToMarkdown(AnalysisResult r)
    {
        var F = r.Facts;
        var sb = new StringBuilder();
        sb.AppendLine("# Análise de logs Netskope" + (F.Host != null ? " — " + F.Host : ""));
        sb.AppendLine($"Período: {Time(r.Start)} → {Time(r.End)} | Versão: {F.Version ?? "—"} | SO: {F.OsName ?? F.Os ?? "—"} | Tenant: {F.TenantHost ?? F.TenantId ?? "—"}");
        sb.AppendLine($"Resultado: {Verdict(r)} ({r.Count(Severity.Critical)} crítico(s), {r.Count(Severity.Warning)} de atenção, {r.Count(Severity.Info)} informativo(s), {r.Count(Severity.Noise)} ruído(s) conhecido(s)).");
        if (r.Score is double sc) sb.AppendLine($"Experience Score: {sc:0}/100 ({ExperienceScore.Band(sc)}) em {r.Scores.Count} janelas de 5 min.");
        foreach (var (svc, av) in r.Availability) sb.AppendLine($"Disponibilidade {svc}: {av:0.#}% do tempo conectado.");
        if (!r.HasTelemetry) sb.AppendLine("Observação: o pacote de logs não traz séries contínuas de CPU, memória, disco e Wi-Fi (só a foto do momento da coleta).");
        if (r.ScoreMissing != null) sb.AppendLine($"Score parcial: sem dados de {r.ScoreMissing}.");
        if (r.LogUtcOffset is TimeSpan tzo) sb.AppendLine($"Horários no fuso da máquina do usuário (UTC{(tzo < TimeSpan.Zero ? "−" : "+")}{tzo.Duration():hh\\:mm}).");
        sb.AppendLine();

        if (r.CaseSummary.Count > 0)
        {
            sb.AppendLine("## Resumo do caso");
            foreach (var (q, a) in r.CaseSummary) sb.AppendLine($"- **{q}** {a}");
            sb.AppendLine();
        }
        if (r.Focus.Count > 0 || r.Domain != null || r.Options.ProblemTime != null)
        {
            sb.AppendLine("## Foco da análise (relato do usuário)");
            var rel = new List<string>();
            if (r.Focus.Count > 0) rel.Add("sintomas: " + string.Join(", ", r.Focus.Select(f => f.Symptom.Label)));
            if (r.Domain != null) rel.Add("site: " + r.Domain.Domain);
            if (r.Options.ProblemTime is DateTime pt) rel.Add($"horário: {pt:dd/MM HH:mm}");
            sb.AppendLine("Relato: " + string.Join(" · ", rel) + ".");
            sb.AppendLine();
            foreach (var f in r.Focus)
            {
                sb.AppendLine($"### {f.Symptom.Label} — {f.Verdict}");
                sb.AppendLine(f.Summary);
                foreach (var c in f.Checks) sb.AppendLine($"- [{c.Status}] **{c.Name}**: {c.Detail}");
                if (f.NextSteps.Count > 0) { sb.AppendLine("Próximos passos:"); foreach (var n in f.NextSteps) sb.AppendLine("  - " + n); }
                sb.AppendLine();
            }
            if (r.Domain is DomainReport d && r.Focus.Count == 0)
            {
                sb.AppendLine($"Site {d.Domain}: {d.Lines} linha(s), {d.Tunneled} tunelada(s), {d.Bypassed} em bypass, {d.Errors} erro(s)" + (d.Exceptions.Count > 0 ? "; em exceção: " + string.Join("; ", d.Exceptions) : "") + ".");
                sb.AppendLine();
            }
        }
        if (r.Performance.Count > 0)
        {
            sb.AppendLine("## Desempenho (derivado dos logs)");
            sb.AppendLine("| Grupo | Métrica | Valor | Referência | Situação |");
            sb.AppendLine("|---|---|---|---|---|");
            foreach (var m in r.Performance) sb.AppendLine($"| {m.Group} | {m.Name} | {m.Value} | {m.Reference} | {m.Status} |");
            sb.AppendLine();
        }
        var drops = r.NpaSessions.Where(x => x.End != null).ToList();
        if (drops.Count > 0)
        {
            sb.AppendLine("## Quedas do Private Access");
            sb.AppendLine("| Queda | Motivo | POP | Voltou em |");
            sb.AppendLine("|---|---|---|---|");
            foreach (var d in drops.TakeLast(60)) sb.AppendLine($"| {Time(d.End)} | {d.EndReason} | {d.Pop ?? d.GatewayIp ?? "—"} | {(d.Downtime is TimeSpan dt ? TelemetryParser.Fmt(dt) : "—")} |");
            sb.AppendLine();
        }
        var cfg = r.Config.Where(c => c.Attention || c.Section is "Detecção on-prem" or "Steering").ToList();
        if (cfg.Count > 0)
        {
            sb.AppendLine("## Configuração relevante");
            foreach (var c in cfg) sb.AppendLine($"- {c.Section} › {c.Item}: **{c.Value}** — {c.Meaning}");
            sb.AppendLine();
        }
        if (r.Coverage.Count > 0)
        {
            sb.AppendLine("## Cobertura dos logs");
            foreach (var c in r.Coverage) sb.AppendLine($"- {c.Source}: {Time(c.First)} → {Time(c.Last)} ({TelemetryParser.Fmt(c.Span)}, {c.Lines:N0} linhas)");
            foreach (var g in r.DataGaps) sb.AppendLine("- " + g);
            sb.AppendLine();
        }

        if (r.Incidents.Count > 0)
        {
            sb.AppendLine("## Incidentes e causa raiz");
            foreach (var inc in r.Incidents)
            {
                sb.AppendLine($"### [{SeverityLabel(inc.Severity)}] {Time(inc.Start)} → {inc.End:HH:mm:ss} ({TelemetryParser.Fmt(inc.Duration)}) — {inc.Title}");
                if (inc.Impact.Length > 0) sb.AppendLine("Impacto: " + inc.Impact);
                if (inc.Causes.FirstOrDefault() is Cause c)
                {
                    sb.AppendLine($"**Causa raiz provável ({c.Confidence:0}%): {c.Title}** — {c.Evidence}");
                    sb.AppendLine("O que fazer: " + c.Recommendation);
                    foreach (var o in inc.Causes.Skip(1)) sb.AppendLine($"- Outra hipótese ({o.Confidence:0}%): {o.Title} — {o.Evidence}");
                }
                if (inc.Evidence.Count > 0)
                {
                    sb.AppendLine("```");
                    foreach (var e in inc.Evidence) sb.AppendLine($"{Time(e.Time)}  [{e.Source}]  {e.Text}");
                    sb.AppendLine("```");
                }
                sb.AppendLine();
            }
        }

        var keyMetrics = r.Series.Values.Where(x => x.Stats != null && x.Warn != null).OrderBy(x => x.Group).ThenBy(x => x.Label).ToList();
        if (keyMetrics.Count > 0)
        {
            sb.AppendLine("## Baseline");
            sb.AppendLine("| Métrica | Fonte | Mediana | p95/p5 | Pior | % em atenção |");
            sb.AppendLine("|---|---|---|---|---|---|");
            foreach (var m in keyMetrics)
            {
                var st = m.Stats!;
                sb.AppendLine(string.Create(CultureInfo.InvariantCulture, $"| {m.Label} | {m.Source} | {st.P50:0.#} {m.Unit} | {st.P95:0.#} {m.Unit} | {st.PeakValue:0.#} {m.Unit} ({Time(st.PeakTime)}) | {st.PctWarn:0}% |"));
            }
            sb.AppendLine();
        }

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
            sb.AppendLine("## Linha do tempo (eventos)");
            foreach (var e in r.Events) sb.AppendLine($"- {Time(e.Time)} {e.Label}{(e.Detail.Length > 0 ? " (" + e.Detail + ")" : "")}");
        }
        return sb.ToString();
    }
}
