namespace NetskopeLogAnalyzer.Core;

public sealed record MetricPoint(DateTime Time, double Value);

public sealed record BaselineStats(int Count, double Min, double Max, double Mean, double P50, double P95, double StdDev,
    double PctWarn, double PctCrit, DateTime PeakTime, double PeakValue, double Last);

/// <summary>Série temporal de uma métrica (do coletor, dos logs da Netskope ou de snapshots).</summary>
public sealed class MetricSeries
{
    public required string Key { get; init; }
    public required string Label { get; init; }
    public string Unit { get; init; } = "";
    public required string Group { get; init; }
    public string Source { get; init; } = "";
    public bool HigherIsWorse { get; init; } = true;
    public double? Warn { get; init; }
    public double? Crit { get; init; }
    public List<MetricPoint> Points { get; } = new();
    public BaselineStats? Stats { get; set; }

    public bool IsBad(double v, bool critical) =>
        (critical ? Crit : Warn) is double t && (HigherIsWorse ? v >= t : v <= t);
}

public sealed record Anomaly(DateTime Start, DateTime End, string SeriesKey, string Label, double Peak, double Reference, string Unit, string Group, bool Critical);

public sealed class ProcessSample
{
    public required string Name { get; init; }
    public double CpuPct { get; set; }
    public double MemMb { get; set; }
    public double MemPct { get; set; }
    public int Instances { get; set; } = 1;
}

public sealed record DiskInfo(string Mount, double? TotalGb, double UsedPct);

public sealed class WifiInfo
{
    public string? Interface { get; set; }
    public string? Ssid { get; set; }
    public string? Bssid { get; set; }
    public string? Band { get; set; }
    public string? Radio { get; set; }
    public string? Channel { get; set; }
    public double? SignalPct { get; set; }
    public double? RssiDbm { get; set; }
    public double? RxMbps { get; set; }
    public double? TxMbps { get; set; }
    public string? State { get; set; }
}

public sealed record InterfaceInfo(string Name, string State, string Detail);

/// <summary>Foto instantânea da máquina (arquivos do pacote: ps aux, tasklist, systeminfo, netsh, nmcli, df, free, netstat…).</summary>
public sealed class Snapshot
{
    public required string Source { get; init; }
    public DateTime? Time { get; set; }
    public List<ProcessSample> Processes { get; } = new();
    public double? MemTotalMb { get; set; }
    public double? MemAvailMb { get; set; }
    public List<DiskInfo> Disks { get; } = new();
    public WifiInfo? Wifi { get; set; }
    public Dictionary<string, int> ConnectionStates { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<InterfaceInfo> Interfaces { get; } = new();
    public string? DefaultGateway { get; set; }
    public Dictionary<string, string> System { get; } = new();
}

public sealed record Hop(int Ttl, string? Address, double? RttMs, string Segment);

public sealed record PathTrace(DateTime Time, string Target, List<Hop> Hops);

/// <summary>Uso de rede por processo/destino, a partir dos fluxos registrados pelo Netskope Client.</summary>
public sealed class AppUsage
{
    public required string Process { get; init; }
    public required string Host { get; init; }
    public int Tunneled { get; set; }
    public int Bypassed { get; set; }
    public int BlockedUdp { get; set; }
    public DateTime First { get; set; } = DateTime.MaxValue;
    public DateTime Last { get; set; } = DateTime.MinValue;
    public int Total => Tunneled + Bypassed + BlockedUdp;
}

public sealed record PopStat(string Service, string Pop, string? Ip, int Samples, double Min, double Avg, double Max, double Last, DateTime LastTime);

public sealed record StateInterval(string Service, string State, DateTime Start, DateTime End)
{
    public TimeSpan Duration => End - Start;
}

public sealed record ScoreWindow(DateTime Start, DateTime End, double Score, double? Device, double? Network, double? Netskope, double? App, string Notes);

public sealed record Cause(string Title, string Category, double Confidence, string Evidence, string Recommendation, string? FindingKey);

public sealed record EvidenceLine(DateTime Time, string Source, string Text, EventKind Kind);

public sealed class Incident
{
    public required string Title { get; init; }
    public required DateTime Start { get; init; }
    public DateTime End { get; set; }
    public Severity Severity { get; set; }
    public required string Kind { get; init; }
    public string Impact { get; set; } = "";
    public List<Cause> Causes { get; } = new();
    public List<EvidenceLine> Evidence { get; } = new();
    public string? FindingKey { get; init; }
    public TimeSpan Duration => End - Start;
}
