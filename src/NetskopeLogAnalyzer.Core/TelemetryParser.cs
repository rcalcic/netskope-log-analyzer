using System.Globalization;
using System.Text.Json;

namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Lê o arquivo de telemetria do coletor (JSON Lines). Cada linha é um objeto com "t" (data/hora ISO 8601) e "k" (tipo):
///   meta    host, os, cpu, cores, ramMb, collector, interval, tenant
///   cpu     v (%)
///   mem     usedPct, availMb, totalMb, commitPct
///   disk    d (unidade/ponto de montagem), usedPct, freeGb, totalGb
///   diskio  busyPct
///   battery pct, ac (bool)
///   wifi    connected, ssid, bssid, signal (%), rssi (dBm), rx, tx (Mbps), ch, band, radio
///   net     rxKbps, txKbps
///   ping    target, label, rtt, loss, jitter (ms/%)
///   tcp     target, label, ms, ok
///   dns     name, ms, ok
///   http    url, label, dns, tcp, tls, ttfb, total (ms), code, ok
///   trace   target, hops: [{ttl, ip, rtt}]
///   procs   top: [{n, cpu, memMb}]
///   event   type, detail
/// Campos numéricos desconhecidos viram séries "k.campo".
/// </summary>
public static class TelemetryParser
{
    public static bool LooksLikeTelemetry(string name, string text)
    {
        if (name.Contains("nla-telemetry", StringComparison.OrdinalIgnoreCase)) return true;
        var first = text.AsSpan().TrimStart();
        return first.StartsWith("{\"t\"") && text.Contains("\"k\"");
    }

    public static void Parse(string text, string fileName, AnalysisResult r)
    {
        var source = "Coletor";
        var wifiLast = (Ssid: (string?)null, Bssid: (string?)null, Connected: (bool?)null);
        bool? acLast = null;
        string? gwLast = null;
        var cpuTimes = new List<DateTime>();
        var interval = 30.0;
        var procAgg = new Dictionary<string, (double CpuSum, double CpuMax, double MemMax, int N)>(StringComparer.OrdinalIgnoreCase);
        var procSamples = 0;

        using var reader = new StringReader(text);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            line = line.Trim();
            if (line.Length < 5 || line[0] != '{') continue;
            JsonElement o;
            try { using var doc = JsonDocument.Parse(line); o = doc.RootElement.Clone(); }
            catch (JsonException) { continue; }
            if (!TryTime(o, out var t)) continue;
            var k = S(o, "k") ?? "";
            if (r.Start is null || t < r.Start) r.Start = t;
            if (r.End is null || t > r.End) r.End = t;

            switch (k)
            {
                case "meta":
                    foreach (var (f, label) in new[] { ("host", "Hostname"), ("os", "Sistema"), ("cpu", "Processador"), ("cores", "Núcleos"), ("ramMb", "Memória instalada (MB)"), ("collector", "Coletor"), ("model", "Modelo"), ("tenant", "Tenant (coletor)") })
                        if (S(o, f) is string v && v.Length > 0) r.Device[label] = v;
                    if (D(o, "interval") is double iv && iv > 0) interval = iv;
                    r.Facts.Host ??= S(o, "host");
                    break;
                case "cpu":
                    Add(r, "cpu", t, D(o, "v"), source);
                    cpuTimes.Add(t);
                    break;
                case "mem":
                    Add(r, "mem.used", t, D(o, "usedPct"), source);
                    Add(r, "mem.avail", t, D(o, "availMb"), source);
                    Add(r, "mem.commit", t, D(o, "commitPct"), source);
                    if (D(o, "totalMb") is double tot) r.Device["Memória instalada (MB)"] = tot.ToString("0", CultureInfo.InvariantCulture);
                    break;
                case "disk":
                    var dname = S(o, "d") ?? "disco";
                    Add(r, "disk.used:" + dname, t, D(o, "usedPct"), source);
                    Add(r, "disk.free:" + dname, t, D(o, "freeGb"), source);
                    break;
                case "diskio":
                    Add(r, "disk.busy", t, D(o, "busyPct"), source);
                    break;
                case "battery":
                    Add(r, "battery", t, D(o, "pct"), source);
                    var ac = B(o, "ac");
                    if (ac != null && acLast != null && ac != acLast)
                        r.Events.Add(new(t, ac.Value ? "Ligado na tomada" : "Na bateria", EventKind.Info, "energia", fileName));
                    acLast = ac ?? acLast;
                    break;
                case "wifi":
                    var connected = B(o, "connected") ?? true;
                    var ssid = S(o, "ssid"); var bssid = S(o, "bssid");
                    if (wifiLast.Connected == true && !connected)
                        r.Events.Add(new(t, "Wi-Fi desconectado", EventKind.Bad, wifiLast.Ssid ?? "", fileName));
                    else if (wifiLast.Connected == false && connected)
                        r.Events.Add(new(t, "Wi-Fi conectado", EventKind.Good, ssid ?? "", fileName));
                    else if (connected && wifiLast.Ssid != null && ssid != null && ssid != wifiLast.Ssid)
                        r.Events.Add(new(t, "Troca de rede Wi-Fi", EventKind.Alert, $"{wifiLast.Ssid} → {ssid}", fileName));
                    else if (connected && wifiLast.Bssid != null && bssid != null && !bssid.Equals(wifiLast.Bssid, StringComparison.OrdinalIgnoreCase))
                        r.Events.Add(new(t, "Roaming Wi-Fi (troca de AP)", EventKind.Info, $"{ssid} {wifiLast.Bssid} → {bssid}", fileName));
                    wifiLast = (ssid ?? wifiLast.Ssid, bssid ?? wifiLast.Bssid, connected);
                    if (connected)
                    {
                        Add(r, "wifi.signal", t, D(o, "signal"), source);
                        Add(r, "wifi.rssi", t, D(o, "rssi"), source);
                        Add(r, "wifi.rx", t, D(o, "rx"), source);
                        Add(r, "wifi.tx", t, D(o, "tx"), source);
                        var snap = LastWifiSnapshot(r);
                        snap.Wifi = new WifiInfo
                        {
                            Ssid = ssid, Bssid = bssid, SignalPct = D(o, "signal"), RssiDbm = D(o, "rssi"), RxMbps = D(o, "rx"), TxMbps = D(o, "tx"),
                            Channel = S(o, "ch"), Band = S(o, "band"), Radio = S(o, "radio"), Interface = S(o, "iface"), State = "conectado",
                        };
                        snap.Time = t;
                    }
                    break;
                case "net":
                    Add(r, "net.rx", t, D(o, "rxKbps"), source);
                    Add(r, "net.tx", t, D(o, "txKbps"), source);
                    var gw = S(o, "gateway");
                    if (gw != null && gwLast != null && gw != gwLast)
                        r.Events.Add(new(t, "Gateway padrão mudou", EventKind.Alert, $"{gwLast} → {gw}", fileName));
                    gwLast = gw ?? gwLast;
                    break;
                case "ping":
                    var pl = S(o, "label") ?? S(o, "target") ?? "alvo";
                    Add(r, "ping.rtt:" + pl, t, D(o, "rtt"), source);
                    Add(r, "ping.loss:" + pl, t, D(o, "loss"), source);
                    Add(r, "ping.jitter:" + pl, t, D(o, "jitter"), source);
                    break;
                case "tcp":
                    var tl = S(o, "label") ?? S(o, "target") ?? "alvo";
                    if (B(o, "ok") == false) r.Events.Add(new(t, "Falha de conexão TCP", EventKind.Bad, tl, fileName));
                    else Add(r, "tcp.connect:" + tl, t, D(o, "ms"), source);
                    break;
                case "dns":
                    var dn = S(o, "name") ?? "";
                    if (B(o, "ok") == false) r.Events.Add(new(t, "Falha de DNS", EventKind.Bad, dn, fileName));
                    else Add(r, "dns.ms", t, D(o, "ms"), source);
                    break;
                case "http":
                    var hl = S(o, "label") ?? S(o, "url") ?? "app";
                    if (B(o, "ok") == false)
                        r.Events.Add(new(t, "Falha no teste HTTP", EventKind.Bad, $"{hl} (código {S(o, "code") ?? "—"})", fileName));
                    else
                        foreach (var ph in new[] { "dns", "tcp", "tls", "ttfb", "total" }) Add(r, $"http.{ph}:{hl}", t, D(o, ph), source);
                    break;
                case "trace":
                    var hops = new List<Hop>();
                    if (o.TryGetProperty("hops", out var ha) && ha.ValueKind == JsonValueKind.Array)
                        foreach (var h in ha.EnumerateArray())
                        {
                            var ip = S(h, "ip");
                            hops.Add(new Hop((int)(D(h, "ttl") ?? hops.Count + 1), ip, D(h, "rtt"), PathSegments.Classify(ip, hops.Count)));
                        }
                    r.Paths.Add(new PathTrace(t, S(o, "target") ?? "", hops));
                    break;
                case "procs":
                    if (o.TryGetProperty("top", out var ta) && ta.ValueKind == JsonValueKind.Array)
                    {
                        procSamples++;
                        double topCpu = 0;
                        foreach (var p in ta.EnumerateArray())
                        {
                            var n = S(p, "n") ?? "?";
                            var c = D(p, "cpu") ?? 0; var m = D(p, "memMb") ?? 0;
                            topCpu = Math.Max(topCpu, c);
                            procAgg.TryGetValue(n, out var a);
                            procAgg[n] = (a.CpuSum + c, Math.Max(a.CpuMax, c), Math.Max(a.MemMax, m), a.N + 1);
                        }
                        Add(r, "procs.top_cpu", t, topCpu, source);
                        ProcessTimeline.Add(r, t, ta);
                    }
                    break;
                case "event":
                    var type = S(o, "type") ?? "evento";
                    var (label2, kind) = EventLabel(type);
                    r.Events.Add(new(t, label2, kind, S(o, "detail") ?? "", fileName));
                    break;
                default:
                    foreach (var prop in o.EnumerateObject())
                        if (prop.Name is not ("t" or "k") && prop.Value.ValueKind == JsonValueKind.Number)
                            Add(r, $"{k}.{prop.Name}", t, prop.Value.GetDouble(), source);
                    break;
            }
        }

        // lacunas na coleta = máquina suspensa, desligada ou coletor parado
        cpuTimes.Sort();
        for (var i = 1; i < cpuTimes.Count; i++)
        {
            var gap = cpuTimes[i] - cpuTimes[i - 1];
            if (gap.TotalSeconds > Math.Max(180, interval * 4))
                r.Events.Add(new(cpuTimes[i - 1], "Lacuna na telemetria", EventKind.Alert,
                    $"sem amostras por {Fmt(gap)} (suspensão, desligamento ou coletor parado)", fileName));
        }

        if (procAgg.Count > 0)
        {
            var procSnap = new Snapshot { Source = fileName + " (média do coletor)", Time = r.End };
            foreach (var (pname, agg) in procAgg.OrderByDescending(kv => kv.Value.CpuSum).Take(25))
                procSnap.Processes.Add(new ProcessSample { Name = pname, CpuPct = Math.Round(agg.CpuSum / Math.Max(1, procSamples), 1), MemMb = Math.Round(agg.MemMax), Instances = agg.N });
            r.Snapshots.Add(procSnap);
        }

        r.HasTelemetry = true;
        r.TelemetrySources.Add(fileName);
    }

    public static string Fmt(TimeSpan t) => t.TotalDays >= 2 ? $"{(int)t.TotalDays}d{t.Hours:00}h" : t.TotalHours >= 1 ? $"{(int)t.TotalHours}h{t.Minutes:00}min" : t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes}min{t.Seconds:00}s" : $"{t.Seconds}s";

    private static (string, EventKind) EventLabel(string type) => type switch
    {
        "net-change" => ("Mudança de rede", EventKind.Alert),
        "sleep" or "suspend" => ("Suspensão", EventKind.Alert),
        "resume" => ("Retorno da suspensão", EventKind.Info),
        "wifi-disconnect" => ("Wi-Fi desconectado", EventKind.Bad),
        "wifi-connect" => ("Wi-Fi conectado", EventKind.Good),
        "gateway-change" => ("Gateway padrão mudou", EventKind.Alert),
        "dns-change" => ("Servidores DNS mudaram", EventKind.Alert),
        "nsclient" => ("Status do Netskope (coletor)", EventKind.Info),
        "collector-start" => ("Coletor iniciado", EventKind.Info),
        "collector-stop" => ("Coletor parado", EventKind.Info),
        _ => (type, EventKind.Info),
    };

    private static Snapshot LastWifiSnapshot(AnalysisResult r)
    {
        var s = r.Snapshots.LastOrDefault(x => x.Source == "Coletor (Wi-Fi)");
        if (s is null) { s = new Snapshot { Source = "Coletor (Wi-Fi)" }; r.Snapshots.Add(s); }
        return s;
    }

    internal static void Add(AnalysisResult r, string key, DateTime t, double? v, string source)
    {
        if (v is not double d || double.IsNaN(d) || double.IsInfinity(d)) return;
        r.GetOrAddSeries(key, () => MetricCatalog.Create(key, source)).Points.Add(new MetricPoint(t, d));
    }

    private static bool TryTime(JsonElement o, out DateTime t)
    {
        t = default;
        var s = S(o, "t");
        if (s is null) return false;
        // guarda o horário de parede registrado na máquina (os logs do Netskope também são horário local)
        if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dto)) { t = dto.DateTime; return true; }
        return DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out t);
    }

    internal static string? S(JsonElement o, string name)
    {
        if (o.ValueKind != JsonValueKind.Object || !o.TryGetProperty(name, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null,
        };
    }

    internal static double? D(JsonElement o, string name)
    {
        if (o.ValueKind != JsonValueKind.Object || !o.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d)) return d;
        if (v.ValueKind == JsonValueKind.String && double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return d;
        return null;
    }

    private static bool? B(JsonElement o, string name)
    {
        if (o.ValueKind != JsonValueKind.Object || !o.TryGetProperty(name, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => v.GetString() is "true" or "1" or "yes" ? true : v.GetString() is "false" or "0" or "no" ? false : null,
            JsonValueKind.Number => v.GetDouble() != 0,
            _ => null,
        };
    }
}

/// <summary>Guarda, por instante, quais processos mais consumiam (para apontar o culpado num incidente).</summary>
public static class ProcessTimeline
{
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<AnalysisResult, List<(DateTime Time, double TopCpu, string Top)>> Table = new();

    internal static void Add(AnalysisResult r, DateTime t, JsonElement top)
    {
        var list = Table.GetOrCreateValue(r);
        var parts = new List<string>();
        double topCpu = 0;
        foreach (var p in top.EnumerateArray()) topCpu = Math.Max(topCpu, TelemetryParser.D(p, "cpu") ?? 0);
        foreach (var p in top.EnumerateArray().Take(3))
        {
            var n = TelemetryParser.S(p, "n") ?? "?";
            var c = TelemetryParser.D(p, "cpu");
            var m = TelemetryParser.D(p, "memMb");
            parts.Add(c is double cc ? $"{n} {cc:0}% CPU{(m is double mm ? $", {mm:0} MB" : "")}" : n);
        }
        list.Add((t, topCpu, string.Join("; ", parts)));
    }

    public static string? TopAt(AnalysisResult r, DateTime from, DateTime to)
    {
        if (!Table.TryGetValue(r, out var list)) return null;
        // o instante de maior consumo de CPU dentro da janela
        return list.Where(x => x.Time >= from && x.Time <= to).OrderByDescending(x => x.TopCpu).Select(x => x.Top).FirstOrDefault();
    }
}

/// <summary>Classifica saltos do traceroute em rede local, provedor/Internet ou Netskope.</summary>
public static class PathSegments
{
    public static string Classify(string? ip, int index)
    {
        if (string.IsNullOrEmpty(ip) || ip == "*") return "sem resposta";
        if (IsNetskope(ip)) return "Netskope";
        if (IsPrivate(ip)) return index <= 2 ? "Rede local" : "Rede privada/CGNAT";
        return "Provedor / Internet";
    }

    public static bool IsNetskope(string ip) => ip.StartsWith("163.116.", StringComparison.Ordinal) || ip.StartsWith("162.10.", StringComparison.Ordinal) || ip.StartsWith("8.36.116.", StringComparison.Ordinal) || ip.StartsWith("8.39.144.", StringComparison.Ordinal) || ip.StartsWith("31.186.239.", StringComparison.Ordinal);

    public static bool IsPrivate(string ip)
    {
        var p = ip.Split('.');
        if (p.Length != 4 || !int.TryParse(p[0], out var a) || !int.TryParse(p[1], out var b)) return false;
        return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || a == 127 || (a == 169 && b == 254);
    }
}
