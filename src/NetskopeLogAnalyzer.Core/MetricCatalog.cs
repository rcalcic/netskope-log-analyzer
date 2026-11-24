namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Rótulos, unidades, grupos e limites de cada métrica. A chave tem o formato "base" ou "base:alvo"
/// (ex.: "cpu", "disk.used:C:", "http.ttfb:office", "pop.rtt:NPA BR-SAO1").
/// </summary>
public static class MetricCatalog
{
    public const string Device = "Dispositivo";
    public const string Wifi = "Wi-Fi";
    public const string Network = "Rede";
    public const string Apps = "Aplicações";
    public const string Netskope = "Netskope";

    private sealed record Def(string Label, string Unit, string Group, double? Warn, double? Crit, bool HigherIsWorse = true);

    private static readonly Dictionary<string, Def> Defs = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cpu"] = new("CPU em uso", "%", Device, 80, 95),
        ["mem.used"] = new("Memória em uso", "%", Device, 85, 95),
        ["mem.avail"] = new("Memória disponível", "MB", Device, 1024, 512, false),
        ["mem.commit"] = new("Memória comprometida", "%", Device, 90, 98),
        ["disk.used"] = new("Disco em uso", "%", Device, 85, 95),
        ["disk.free"] = new("Disco livre", "GB", Device, 10, 3, false),
        ["disk.busy"] = new("Disco ocupado (E/S)", "%", Device, 80, 95),
        ["battery"] = new("Bateria", "%", Device, 20, 10, false),
        ["procs.top_cpu"] = new("CPU do processo mais pesado", "%", Device, 60, 90),
        ["wifi.signal"] = new("Sinal Wi-Fi", "%", Wifi, 60, 40, false),
        ["wifi.rssi"] = new("RSSI Wi-Fi", "dBm", Wifi, -70, -80, false),
        ["wifi.rx"] = new("Taxa de recepção Wi-Fi", "Mbps", Wifi, 50, 20, false),
        ["wifi.tx"] = new("Taxa de transmissão Wi-Fi", "Mbps", Wifi, 50, 20, false),
        ["net.rx"] = new("Tráfego recebido", "kbit/s", Network, null, null),
        ["net.tx"] = new("Tráfego enviado", "kbit/s", Network, null, null),
        ["ping.rtt"] = new("Latência (ping)", "ms", Network, 100, 250),
        ["ping.loss"] = new("Perda de pacotes", "%", Network, 1, 5),
        ["ping.jitter"] = new("Jitter", "ms", Network, 30, 60),
        ["tcp.connect"] = new("Conexão TCP", "ms", Network, 150, 400),
        ["dns.ms"] = new("Resolução DNS", "ms", Network, 100, 500),
        ["pop.rtt"] = new("Latência até o POP", "ms", Netskope, 80, 150),
        ["pop.best"] = new("Latência até o melhor POP", "ms", Netskope, 80, 150),
        ["http.dns"] = new("HTTP: DNS", "ms", Apps, 100, 500),
        ["http.tcp"] = new("HTTP: conexão TCP", "ms", Apps, 150, 400),
        ["http.tls"] = new("HTTP: handshake TLS", "ms", Apps, 300, 800),
        ["http.ttfb"] = new("HTTP: tempo até o 1º byte", "ms", Apps, 800, 2000),
        ["http.total"] = new("HTTP: tempo total", "ms", Apps, 2000, 5000),
        ["flows.tunnel"] = new("Fluxos tunelados (por minuto)", "fluxos", Netskope, null, null),
        ["flows.bypass"] = new("Fluxos em bypass (por minuto)", "fluxos", Netskope, null, null),
        ["flows.udpblock"] = new("UDP/QUIC bloqueado (por minuto)", "conexões", Netskope, null, null),
        ["log.errors"] = new("Eventos relevantes no log (por minuto)", "eventos", Netskope, 5, 20),
        // v3.1 — métricas derivadas dos logs (sem coletor)
        ["npa.gw.rtt"] = new("Private Access: RTT até o gateway", "ms", Netskope, 80, 250),
        ["npa.gw.retrans"] = new("Private Access: retransmissões TCP (por 5 min)", "segmentos", Netskope, 50, 200),
        ["npa.dns.nxdomain"] = new("DNS via Private Access: respostas NXDOMAIN", "%", Network, 50, 80),
        ["net.changes"] = new("Mudanças de rede detectadas pelo cliente (por 10 min)", "eventos", Network, 3, 10),
        ["perf.sched"] = new("Atraso das tarefas periódicas do cliente", "s", Device, 20, 120),
        ["perf.stall"] = new("Operações internas do cliente que estouraram o tempo (por 10 min)", "ocorrências", Device, 2, 10),
        ["perf.lograte"] = new("Atividade de log do cliente (linhas por minuto)", "linhas", Device, null, null),
    };

    public static MetricSeries Create(string key, string source)
    {
        var (baseKey, target) = Split(key);
        var d = Defs.TryGetValue(baseKey, out var def) ? def : new Def(Humanize(baseKey), "", Device, null, null);
        var label = target is null ? d.Label : $"{d.Label} — {target}";
        return new MetricSeries
        {
            Key = key, Label = label, Unit = d.Unit, Group = d.Group, Source = source,
            Warn = d.Warn, Crit = d.Crit, HigherIsWorse = d.HigherIsWorse,
        };
    }

    public static (string Base, string? Target) Split(string key)
    {
        var i = key.IndexOf(':');
        return i < 0 ? (key, null) : (key[..i], key[(i + 1)..]);
    }

    public static string BaseOf(string key) => Split(key).Base;

    private static string Humanize(string k) => k.Replace('.', ' ').Replace('_', ' ');

    /// <summary>Converte um valor para uma nota 0–100 (100 = ótimo) entre o ponto "bom" e o ponto "ruim".</summary>
    public static double Grade(double value, double good, double bad)
    {
        if (good < bad) return value <= good ? 100 : value >= bad ? 0 : 100 * (bad - value) / (bad - good);
        return value >= good ? 100 : value <= bad ? 0 : 100 * (value - bad) / (good - bad);
    }
}
