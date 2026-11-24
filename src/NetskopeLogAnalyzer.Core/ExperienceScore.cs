namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Experience Score de 0 a 100 por janela de 5 minutos, no estilo do DEM:
///   Dispositivo — folga de CPU, memória disponível, disco livre e sinal Wi-Fi (coletor);
///   Rede        — latência, perda e jitter (coletor) e latência até o POP (logs Netskope);
///   Netskope    — túnel conectado e ausência de falhas de comunicação/configuração (logs);
///   Aplicação   — testes HTTP do coletor (sucesso e tempo até o 1º byte).
/// Componentes sem dados não entram na média. O pior componente limita a nota (gargalo).
/// Faixas: 0–30 ruim, 31–70 regular, 71–100 bom.
/// </summary>
public static class ExperienceScore
{
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    private static readonly string[] NetskopeFailureKeys = { "timeout", "dns", "conn", "ssl", "http", "cfgdl", "gslb", "npagw", "p407" };

    public static string Band(double score) => score <= 30 ? "Ruim" : score <= 70 ? "Regular" : "Bom";

    public static void Compute(AnalysisResult r)
    {
        if (r.Start is null || r.End is null) return;
        var start = Floor(r.Start.Value);
        var end = r.End.Value;
        if ((end - start).TotalDays > 31) start = Floor(end.AddDays(-31)); // limita o volume

        MetricSeries? S(string key) => r.Series.TryGetValue(key, out var s) ? s : null;
        IEnumerable<MetricSeries> Prefix(string p) => r.Series.Values.Where(s => s.Key.StartsWith(p, StringComparison.OrdinalIgnoreCase));

        var failTimes = r.Findings.Where(f => NetskopeFailureKeys.Contains(f.Key) && f.Severity != Severity.Noise).SelectMany(f => f.Times).OrderBy(t => t).ToList();
        var states = r.States.Where(s => s.Service is "Internet" or "Private Access" && s.State is not ("Reautenticando" or "Parado pelo cliente") && !s.State.StartsWith("Sem atividade", StringComparison.Ordinal)).ToList();
        var inactive = r.States.Where(s => s.State.StartsWith("Sem atividade", StringComparison.Ordinal)).Select(s => (s.Start, s.End)).ToList();
        var httpFail = r.Events.Where(e => e.Label == "Falha no teste HTTP").Select(e => e.Time).ToList();
        var tcpFail = r.Events.Where(e => e.Label is "Falha de conexão TCP" or "Falha de DNS").Select(e => e.Time).ToList();

        for (var w = start; w < end; w += Window)
        {
            var we = w + Window;
            if (inactive.Any(g => w >= g.Start && we <= g.End)) continue; // máquina sem atividade
            var notes = new List<string>();

            // ---- dispositivo
            var dev = new List<double>();
            if (Baseline.Avg(S("cpu"), w, we) is double cpu) { dev.Add(MetricCatalog.Grade(cpu, 60, 100)); if (cpu >= 90) notes.Add($"CPU {cpu:0}%"); }
            if (Baseline.Avg(S("mem.used"), w, we) is double mem) { dev.Add(MetricCatalog.Grade(mem, 75, 98)); if (mem >= 92) notes.Add($"memória {mem:0}%"); }
            foreach (var d in Prefix("disk.used:")) if (Baseline.Avg(d, w, we) is double du) { dev.Add(MetricCatalog.Grade(du, 85, 99)); if (du >= 95) notes.Add($"disco {du:0}%"); }
            if (Baseline.Avg(S("wifi.signal"), w, we) is double sig) { dev.Add(MetricCatalog.Grade(sig, 75, 25)); if (sig <= 40) notes.Add($"Wi-Fi {sig:0}%"); }
            else if (Baseline.Avg(S("wifi.rssi"), w, we) is double rssi) { dev.Add(MetricCatalog.Grade(rssi, -60, -85)); if (rssi <= -78) notes.Add($"Wi-Fi {rssi:0} dBm"); }
            // sinais de desempenho derivados dos logs (sem coletor)
            if (Baseline.Worst(S("perf.sched"), w, we) is double sd) { dev.Add(MetricCatalog.Grade(sd, 10, 180)); if (sd >= 60) notes.Add($"tarefas atrasadas {sd:0} s"); }
            if (Baseline.Worst(S("perf.stall"), w, we) is double stl && stl > 0) { dev.Add(MetricCatalog.Grade(stl, 0, 10)); notes.Add($"{stl:0} travamento(s) interno(s)"); }
            double? device = dev.Count > 0 ? Blend(dev) : null;

            // ---- rede
            var net = new List<double>();
            foreach (var p in Prefix("ping.rtt:")) if (Baseline.Avg(p, w, we) is double rtt) net.Add(MetricCatalog.Grade(rtt, 40, 300));
            foreach (var p in Prefix("ping.loss:")) if (Baseline.Avg(p, w, we) is double loss) { net.Add(MetricCatalog.Grade(loss, 0, 10)); if (loss >= 5) notes.Add($"perda {loss:0}%"); }
            foreach (var p in Prefix("ping.jitter:")) if (Baseline.Avg(p, w, we) is double jit) net.Add(MetricCatalog.Grade(jit, 10, 100));
            foreach (var p in Prefix("pop.best:")) if (Baseline.Avg(p, w, we) is double pr) { net.Add(MetricCatalog.Grade(pr, 30, 250)); if (pr >= 150) notes.Add($"POP {pr:0} ms"); }
            if (Baseline.Avg(S("dns.ms"), w, we) is double dnsMs) net.Add(MetricCatalog.Grade(dnsMs, 50, 1000));
            if (Baseline.Worst(S("npa.gw.rtt"), w.AddMinutes(-5), we) is double grtt) { net.Add(MetricCatalog.Grade(grtt, 40, 400)); if (grtt >= 250) notes.Add($"RTT NPA {grtt:0} ms"); }
            if (Baseline.Worst(S("npa.gw.retrans"), w.AddMinutes(-5), we) is double gre) { net.Add(MetricCatalog.Grade(gre, 20, 300)); if (gre >= 200) notes.Add($"{gre:0} retransmissões"); }
            if (Baseline.Worst(S("net.changes"), w.AddMinutes(-5), we) is double nch && nch > 0) { net.Add(MetricCatalog.Grade(nch, 1, 12)); if (nch >= 6) notes.Add($"{nch:0} mudanças de rede"); }
            var netFails = tcpFail.Count(t => t >= w && t < we);
            if (netFails > 0) { net.Add(Math.Max(0, 100 - 30 * netFails)); notes.Add($"{netFails} falha(s) de DNS/TCP"); }
            double? network = net.Count > 0 ? Blend(net) : null;

            // ---- Netskope
            double? ns = null;
            var stateInWin = states.Where(s => s.Start < we && s.End > w).ToList();
            if (stateInWin.Count > 0 || failTimes.Any(t => t >= w && t < we))
            {
                var downSec = stateInWin.Where(s => s.State != "Conectado").Sum(s => Overlap(s, w, we));
                var tunnel = stateInWin.Count > 0 ? 100 * (1 - downSec / (stateInWin.Select(s => s.Service).Distinct().Count() * Window.TotalSeconds)) : 100;
                var fails = failTimes.Count(t => t >= w && t < we);
                ns = Math.Max(0, Math.Min(tunnel, 100 - Math.Min(100, fails * 8.0)));
                if (downSec > 0) notes.Add("túnel fora");
                if (fails > 0) notes.Add($"{fails} falha(s) com o tenant");
            }

            // ---- aplicação
            var app = new List<double>();
            foreach (var p in Prefix("http.ttfb:")) if (Baseline.Avg(p, w, we) is double tt) app.Add(MetricCatalog.Grade(tt, 300, 3000));
            var hf = httpFail.Count(t => t >= w && t < we);
            if (hf > 0) { app.Add(Math.Max(0, 100 - 40 * hf)); notes.Add($"{hf} teste(s) HTTP com falha"); }
            double? application = app.Count > 0 ? Blend(app) : null;

            var parts = new List<(double V, double W)>();
            if (device is double a) parts.Add((a, 0.25));
            if (network is double b) parts.Add((b, 0.30));
            if (ns is double c) parts.Add((c, 0.25));
            if (application is double d2) parts.Add((d2, 0.20));
            if (parts.Count == 0) continue;
            var score = parts.Sum(x => x.V * x.W) / parts.Sum(x => x.W);
            var worst = parts.Min(x => x.V);
            score = Math.Min(score, worst + 25); // gargalo puxa a nota para baixo
            r.Scores.Add(new ScoreWindow(w, we, Math.Round(score), R(device), R(network), R(ns), R(application), string.Join(", ", notes)));
        }
        if (r.Scores.Count > 0) r.Score = Math.Round(r.Scores.Average(s => s.Score));
        var missing = new List<string>();
        if (!r.Scores.Any(s => s.Device != null)) missing.Add("Dispositivo");
        if (!r.Scores.Any(s => s.Network != null)) missing.Add("Rede");
        if (!r.Scores.Any(s => s.Netskope != null)) missing.Add("Netskope");
        if (!r.Scores.Any(s => s.App != null)) missing.Add("Aplicação");
        r.ScoreMissing = missing.Count > 0 ? string.Join(", ", missing) : null;
    }

    private static double? R(double? v) => v is double d ? Math.Round(d) : null;

    /// <summary>Média que penaliza o pior item (metade média, metade mínimo).</summary>
    private static double Blend(List<double> v) => 0.5 * v.Average() + 0.5 * v.Min();

    private static double Overlap(StateInterval s, DateTime a, DateTime b)
    {
        var st = s.Start > a ? s.Start : a; var en = s.End < b ? s.End : b;
        return Math.Max(0, (en - st).TotalSeconds);
    }

    private static DateTime Floor(DateTime t) => new(t.Ticks - t.Ticks % Window.Ticks, t.Kind);
}
