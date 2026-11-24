namespace NetskopeLogAnalyzer.Core;

/// <summary>Um item da configuração efetiva do cliente, já interpretado.</summary>
public sealed record ConfigItem(string Section, string Item, string Value, string Meaning, bool Attention = false);

/// <summary>DNS e domínio de pesquisa de uma interface (nmcli, resolvectl, ipconfig, scutil).</summary>
public sealed record InterfaceDns(string Interface, string State, IReadOnlyList<string> Servers, IReadOnlyList<string> Search, string Note);

/// <summary>Quanto tempo cada fonte de log cobre — evita conclusões fora do período coberto.</summary>
public sealed record SourceCoverage(string Source, string Files, DateTime First, DateTime Last, int Lines)
{
    public TimeSpan Span => Last - First;
}

/// <summary>Uma sessão do túnel Private Access reconstruída a partir do npadebuglog.</summary>
public sealed class NpaSession
{
    public DateTime Start { get; set; }
    public DateTime? End { get; set; }
    public string? Pop { get; set; }
    public string? GatewayIp { get; set; }
    public double? SelectRttMs { get; set; }
    public string? EndReason { get; set; }
    public bool Expected { get; set; }
    public DateTime? ReconnectedAt { get; set; }
    public TimeSpan? Downtime => End is DateTime e && ReconnectedAt is DateTime r && r > e ? r - e : null;
}

/// <summary>Métrica de desempenho no estilo do DEM, derivada só dos logs (sem coletor).</summary>
public sealed record PerfMetric(string Group, string Name, string Value, string Reference, string Status, string Meaning, string? SeriesKey = null);

/// <summary>Resumo de uma captura de pacotes (.pcap/.pcapng) incluída no pacote.</summary>
public sealed class CaptureSummary
{
    public required string File { get; init; }
    public string LinkType { get; set; } = "";
    public long Packets { get; set; }
    public long Bytes { get; set; }
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }
    public int TcpFlows { get; set; }
    public long TcpDataSegments { get; set; }
    public long Retransmissions { get; set; }
    public long Resets { get; set; }
    public long ZeroWindow { get; set; }
    public int Syn { get; set; }
    public int SynAck { get; set; }
    public int HandshakeFailures { get; set; }
    public long Udp { get; set; }
    public Dictionary<string, int> DnsRcodes { get; } = new();
    public int TlsAlerts { get; set; }
    public List<KeyValuePair<string, long>> TopDestinations { get; } = new();
    public List<KeyValuePair<string, long>> TopRetransDestinations { get; } = new();
    public string? Error { get; set; }
    public double RetransPct => TcpDataSegments > 0 ? 100.0 * Retransmissions / TcpDataSegments : 0;
}
