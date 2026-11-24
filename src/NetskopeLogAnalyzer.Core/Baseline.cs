namespace NetskopeLogAnalyzer.Core;

/// <summary>Estatísticas de baseline por métrica e detecção de anomalias (picos e vales fora do normal).</summary>
public static class Baseline
{
    public static void Compute(AnalysisResult r)
    {
        foreach (var s in r.Series.Values)
        {
            s.Points.Sort((a, b) => a.Time.CompareTo(b.Time));
            if (s.Points.Count == 0) continue;
            s.Stats = Stats(s);
            r.Anomalies.AddRange(FindAnomalies(s));
        }
        r.Anomalies.Sort((a, b) => a.Start.CompareTo(b.Start));
    }

    public static double Percentile(double[] sorted, double p)
    {
        if (sorted.Length == 0) return double.NaN;
        var idx = p * (sorted.Length - 1);
        var lo = (int)Math.Floor(idx); var hi = (int)Math.Ceiling(idx);
        return lo == hi ? sorted[lo] : sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
    }

    public static BaselineStats Stats(MetricSeries s)
    {
        var v = s.Points.Select(p => p.Value).ToArray();
        var sorted = v.OrderBy(x => x).ToArray();
        var mean = v.Average();
        var sd = v.Length > 1 ? Math.Sqrt(v.Sum(x => (x - mean) * (x - mean)) / (v.Length - 1)) : 0;
        var peak = s.HigherIsWorse ? s.Points.MaxBy(p => p.Value)! : s.Points.MinBy(p => p.Value)!;
        double pw = s.Warn is null ? 0 : 100.0 * v.Count(x => s.IsBad(x, false)) / v.Length;
        double pc = s.Crit is null ? 0 : 100.0 * v.Count(x => s.IsBad(x, true)) / v.Length;
        return new BaselineStats(v.Length, sorted[0], sorted[^1], mean, Percentile(sorted, 0.5), Percentile(sorted, s.HigherIsWorse ? 0.95 : 0.05),
            sd, pw, pc, peak.Time, peak.Value, v[^1]);
    }

    /// <summary>
    /// Um ponto é anômalo se passa do limite crítico da métrica, ou (com amostras suficientes) se foge
    /// mais de 3 desvios-padrão da mediana na direção ruim. Pontos próximos (até 3 min) viram um só evento.
    /// </summary>
    public static IEnumerable<Anomaly> FindAnomalies(MetricSeries s)
    {
        var st = s.Stats;
        if (st is null || st.Count < 3) yield break;
        var useStat = st.Count >= 20 && st.StdDev > 0;
        bool Bad(double x, out bool crit)
        {
            crit = s.IsBad(x, true);
            if (crit) return true;
            if (!useStat) return false;
            var dev = s.HigherIsWorse ? x - st.P50 : st.P50 - x;
            // desvio estatístico só conta se também for relevante em termos absolutos (acima do limite de atenção, se houver)
            return dev > 3 * st.StdDev && (s.Warn is null || s.IsBad(x, false));
        }

        DateTime? start = null; DateTime last = default; double peak = 0; var anyCrit = false;
        foreach (var p in s.Points)
        {
            if (Bad(p.Value, out var c))
            {
                if (start is null || (p.Time - last).TotalMinutes > 3)
                {
                    if (start is DateTime st0) yield return new Anomaly(st0, last, s.Key, s.Label, peak, st.P50, s.Unit, s.Group, anyCrit);
                    start = p.Time; peak = p.Value; anyCrit = false;
                }
                last = p.Time;
                peak = s.HigherIsWorse ? Math.Max(peak, p.Value) : Math.Min(peak, p.Value);
                anyCrit |= c;
            }
        }
        if (start is DateTime st1) yield return new Anomaly(st1, last, s.Key, s.Label, peak, st.P50, s.Unit, s.Group, anyCrit);
    }

    /// <summary>Média dos pontos de uma série dentro de [from, to); null se não houver.</summary>
    public static double? Avg(MetricSeries? s, DateTime from, DateTime to)
    {
        if (s is null) return null;
        double sum = 0; var n = 0;
        foreach (var p in s.Points) if (p.Time >= from && p.Time < to) { sum += p.Value; n++; }
        return n > 0 ? sum / n : null;
    }

    /// <summary>Pior valor (na direção ruim da métrica) dentro de [from, to].</summary>
    public static double? Worst(MetricSeries? s, DateTime from, DateTime to)
    {
        if (s is null) return null;
        double? w = null;
        foreach (var p in s.Points)
            if (p.Time >= from && p.Time <= to)
                w = w is null ? p.Value : s.HigherIsWorse ? Math.Max(w.Value, p.Value) : Math.Min(w.Value, p.Value);
        return w;
    }
}
