using System.Globalization;
using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Extrai fotos instantâneas da máquina de saídas de comandos incluídas no pacote de logs
/// (ou exportadas pelo usuário): ps aux, tasklist, systeminfo, netsh wlan, nmcli, iw/iwconfig,
/// airport, df, free, netstat e ip addr. Reconhece saídas em inglês e português.
/// </summary>
public static class SnapshotParsers
{
    private const RegexOptions M = RegexOptions.Multiline | RegexOptions.CultureInvariant;
    private const RegexOptions MI = M | RegexOptions.IgnoreCase;

    public static Snapshot? Parse(string fileName, string text, DateTime? when)
    {
        var s = new Snapshot { Source = fileName, Time = when };
        var any = false;
        any |= PsAux(text, s);
        any |= Tasklist(text, s);
        any |= SystemInfo(text, s);
        any |= NetshWlan(text, s);
        any |= Nmcli(text, s);
        any |= NmcliWifiList(text, s);
        any |= IwLink(text, s);
        any |= Iwconfig(text, s);
        any |= Airport(text, s);
        any |= Df(text, s);
        any |= Free(text, s);
        any |= Netstat(text, s);
        any |= IpAddr(text, s);
        return any ? s : null;
    }

    private static double? Num(string s)
    {
        s = s.Trim();
        return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
    }

    /// <summary>Número com separador de milhar em qualquer localidade ("16,236" / "16.236" / "1 234").</summary>
    private static double? Digits(string s)
    {
        var d = new string(s.Where(char.IsDigit).ToArray());
        return d.Length > 0 && double.TryParse(d, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    private static string ProcName(string command)
    {
        var first = command.Trim();
        if (first.StartsWith('[')) return first;
        var tok = first.Split(' ', 2)[0];
        var slash = tok.LastIndexOf('/');
        return slash >= 0 && slash < tok.Length - 1 ? tok[(slash + 1)..] : tok;
    }

    // USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
    private static bool PsAux(string text, Snapshot s)
    {
        var h = Regex.Match(text, @"^\s*USER\s+PID\s+%CPU\s+%MEM\s+VSZ\s+RSS\b.*$", M);
        if (!h.Success) return false;
        var agg = new Dictionary<string, ProcessSample>(StringComparer.Ordinal);
        double rssKb = 0, memPct = 0, bigRss = 0, bigPct = 0, cpuTime = 0;
        int count = 0, cores = 0;
        foreach (var raw in text[(h.Index + h.Length)..].Split('\n').Skip(1))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith('$')) break;
            var c = line.Split((char[]?)null, 11, StringSplitOptions.RemoveEmptyEntries);
            if (c.Length < 11 || Num(c[2]) is not double cpu || Num(c[3]) is not double mem || Num(c[5]) is not double rss) continue;
            var name = ProcName(c[10]);
            var t = CpuTime(c[9]);
            count++;
            if (c[1] == "1") s.BootClock = c[8];
            if (Regex.IsMatch(c[10], @"^\[migration/\d+\]")) { cores++; continue; }
            if (c[10].StartsWith('[')) { cpuTime += t; continue; } // threads de kernel: contam só no total
            if (!agg.TryGetValue(name, out var p)) { p = new ProcessSample { Name = name, Instances = 0 }; agg[name] = p; }
            p.CpuPct += cpu; p.MemPct += mem; p.MemMb += rss / 1024.0; p.Instances++; p.CpuTimeSec += t;
            rssKb += rss; memPct += mem; cpuTime += t;
            if (mem >= 0.5) { bigRss += rss; bigPct += mem; }
        }
        if (agg.Count == 0) return false;
        s.Processes.AddRange(agg.Values.OrderByDescending(p => p.CpuPct).ThenByDescending(p => p.MemMb));
        // total de RAM estimado pelos processos grandes (o %MEM arredondado dos pequenos distorce a conta)
        if (bigPct > 2) s.MemTotalMb ??= Math.Round(bigRss / bigPct * 100 / 1024.0);
        else if (memPct > 1) s.MemTotalMb ??= Math.Round(rssKb / memPct * 100 / 1024.0);
        s.ProcessCount = count;
        s.CpuTimeTotalSec = cpuTime;
        s.RssTotalMb = Math.Round(rssKb / 1024.0);
        if (cores > 0) s.Cores = cores;
        return true;
    }

    /// <summary>Coluna TIME do ps: "MMM:SS" (aux) ou "[DD-]HH:MM:SS".</summary>
    internal static double CpuTime(string v)
    {
        var days = 0;
        var dash = v.IndexOf('-');
        if (dash > 0 && int.TryParse(v[..dash], NumberStyles.Integer, CultureInfo.InvariantCulture, out var d)) { days = d; v = v[(dash + 1)..]; }
        var p = v.Split(':');
        double N(string x) => double.TryParse(x, NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? r : 0;
        return p.Length switch
        {
            2 => N(p[0]) * 60 + N(p[1]),
            3 => N(p[0]) * 3600 + N(p[1]) * 60 + N(p[2]),
            _ => 0,
        } + days * 86400;
    }

    // Nome da imagem  PID Nome da sessão  Sessão#  Uso de memória
    private static bool Tasklist(string text, Snapshot s)
    {
        if (!Regex.IsMatch(text, @"^(Image Name|Nome da imagem)\s+PID", MI)) return false;
        var agg = new Dictionary<string, ProcessSample>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in Regex.Matches(text, @"^(.+?)\s+(\d+)\s+(\S+)\s+(\d+)\s+([\d.,\s ]+)\s*K\s*$", M))
        {
            var name = m.Groups[1].Value.Trim();
            var kb = Digits(m.Groups[5].Value) ?? 0;
            if (!agg.TryGetValue(name, out var p)) { p = new ProcessSample { Name = name, Instances = 0 }; agg[name] = p; }
            p.MemMb += kb / 1024.0; p.Instances++;
        }
        if (agg.Count == 0) return false;
        s.Processes.AddRange(agg.Values.OrderByDescending(p => p.MemMb));
        return true;
    }

    private static bool SystemInfo(string text, Snapshot s)
    {
        var found = false;
        void Field(string pattern, string label)
        {
            var m = Regex.Match(text, @"^(?:" + pattern + @")\s*:\s*(.+)$", MI);
            if (m.Success) { s.System[label] = m.Groups[1].Value.Trim(); found = true; }
        }
        Field("OS Name|Nome do sistema operacional|Nome do SO", "Sistema");
        Field("OS Version|Versão do sistema operacional|Versão do SO", "Versão do SO");
        Field("System Manufacturer|Fabricante do sistema", "Fabricante");
        Field("System Model|Modelo do sistema", "Modelo");
        Field("System Boot Time|Tempo de Inicialização do Sistema|Hora de inicialização do sistema", "Último boot");
        var tot = Regex.Match(text, @"^(?:Total Physical Memory|Memória física total)\s*:\s*([\d.,\s ]+)\s*MB", MI);
        var av = Regex.Match(text, @"^(?:Available Physical Memory|Memória física disponível)\s*:\s*([\d.,\s ]+)\s*MB", MI);
        if (tot.Success) { s.MemTotalMb = Digits(tot.Groups[1].Value); found = true; }
        if (av.Success) { s.MemAvailMb = Digits(av.Groups[1].Value); found = true; }
        return found && Regex.IsMatch(text, @"^(Host Name|Nome do host)\s*:", MI);
    }

    private static Dictionary<string, string> KeyValues(string text)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in Regex.Matches(text, @"^\s*([^:\r\n]{2,40}?)\s*:\s*(.+?)\s*$", M))
            d.TryAdd(m.Groups[1].Value.Trim(), m.Groups[2].Value.Trim());
        return d;
    }

    // netsh wlan show interfaces (en/pt)
    private static bool NetshWlan(string text, Snapshot s)
    {
        if (!Regex.IsMatch(text, @"^\s*SSID\s*:", MI) || !Regex.IsMatch(text, @"^\s*(Signal|Sinal)\s*:\s*\d+\s*%", MI)) return false;
        var kv = KeyValues(text);
        string? Get(params string[] starts) => kv.FirstOrDefault(p => starts.Any(st => p.Key.StartsWith(st, StringComparison.OrdinalIgnoreCase))).Value;
        var w = new WifiInfo
        {
            Interface = Get("Name", "Nome"),
            State = Get("State", "Estado"),
            Ssid = kv.TryGetValue("SSID", out var ssid) ? ssid : null,
            Bssid = Get("AP BSSID", "BSSID"),
            Radio = Get("Radio type", "Tipo de r"),
            Band = Get("Band", "Banda"),
            Channel = Get("Channel", "Canal"),
            RxMbps = Num(Get("Receive rate", "Taxa de recep") ?? ""),
            TxMbps = Num(Get("Transmit rate", "Taxa de transm") ?? ""),
            SignalPct = Num((Get("Signal", "Sinal") ?? "").Replace("%", "")),
            RssiDbm = Num(Get("Rssi") ?? ""),
        };
        s.Wifi = w;
        return true;
    }

    // nmcli dev show
    private static bool Nmcli(string text, Snapshot s)
    {
        if (!text.Contains("GENERAL.DEVICE:", StringComparison.Ordinal)) return false;
        string? dev = null, type = null, state = null, conn = null;
        void Flush()
        {
            if (dev is null) return;
            s.Interfaces.Add(new InterfaceInfo(dev, state ?? "", $"{type} {conn}".Trim()));
            if (type == "wifi" && state != null && Regex.IsMatch(state, @"^100\b") && s.Wifi is null)
                s.Wifi = new WifiInfo { Interface = dev, Ssid = conn, State = state };
        }
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var m = Regex.Match(line, @"^(GENERAL\.\w+|IP4\.GATEWAY):\s+(.*)$");
            if (!m.Success) continue;
            var v = m.Groups[2].Value.Trim();
            switch (m.Groups[1].Value)
            {
                case "GENERAL.DEVICE": Flush(); dev = v; type = state = conn = null; break;
                case "GENERAL.TYPE": type = v; break;
                case "GENERAL.STATE": state = v; break;
                case "GENERAL.CONNECTION": conn = v == "--" ? null : v; break;
                case "IP4.GATEWAY": if (v != "--" && v.Length > 0) s.DefaultGateway ??= v; break;
            }
        }
        Flush();
        return s.Interfaces.Count > 0;
    }

    // nmcli dev wifi list → linha em uso começa com "*"
    private static bool NmcliWifiList(string text, Snapshot s)
    {
        var m = Regex.Match(text, @"^\*\s+([0-9A-Fa-f:]{17})\s+(.+?)\s+Infra\s+(\d+)\s+(\d+)\s+Mbit/s\s+(\d+)", M);
        if (!m.Success) return false;
        s.Wifi ??= new WifiInfo();
        s.Wifi.Bssid = m.Groups[1].Value; s.Wifi.Ssid = m.Groups[2].Value.Trim(); s.Wifi.Channel = m.Groups[3].Value;
        s.Wifi.RxMbps = Num(m.Groups[4].Value); s.Wifi.SignalPct = Num(m.Groups[5].Value);
        return true;
    }

    // iw dev <if> link
    private static bool IwLink(string text, Snapshot s)
    {
        var sig = Regex.Match(text, @"^\s*signal:\s*(-?\d+)\s*dBm", MI);
        if (!sig.Success || !text.Contains("Connected to", StringComparison.Ordinal)) return false;
        s.Wifi ??= new WifiInfo();
        s.Wifi.RssiDbm = Num(sig.Groups[1].Value);
        var ssid = Regex.Match(text, @"^\s*SSID:\s*(.+)$", M); if (ssid.Success) s.Wifi.Ssid = ssid.Groups[1].Value.Trim();
        var freq = Regex.Match(text, @"^\s*freq:\s*([\d.]+)", M); if (freq.Success) s.Wifi.Band = BandFromFreq(Num(freq.Groups[1].Value));
        var rx = Regex.Match(text, @"^\s*rx bitrate:\s*([\d.]+)", M); if (rx.Success) s.Wifi.RxMbps = Num(rx.Groups[1].Value);
        var tx = Regex.Match(text, @"^\s*tx bitrate:\s*([\d.]+)", M); if (tx.Success) s.Wifi.TxMbps = Num(tx.Groups[1].Value);
        var bssid = Regex.Match(text, @"Connected to ([0-9a-fA-F:]{17})"); if (bssid.Success) s.Wifi.Bssid = bssid.Groups[1].Value;
        return true;
    }

    private static bool Iwconfig(string text, Snapshot s)
    {
        var sig = Regex.Match(text, @"Signal level=(-?\d+)\s*dBm");
        if (!sig.Success) return false;
        s.Wifi ??= new WifiInfo();
        s.Wifi.RssiDbm ??= Num(sig.Groups[1].Value);
        var essid = Regex.Match(text, @"ESSID:""([^""]*)"""); if (essid.Success) s.Wifi.Ssid ??= essid.Groups[1].Value;
        var rate = Regex.Match(text, @"Bit Rate[=:]([\d.]+)\s*Mb/s"); if (rate.Success) s.Wifi.TxMbps ??= Num(rate.Groups[1].Value);
        return true;
    }

    // macOS: airport -I
    private static bool Airport(string text, Snapshot s)
    {
        var rssi = Regex.Match(text, @"^\s*agrCtlRSSI:\s*(-?\d+)", M);
        if (!rssi.Success) return false;
        s.Wifi ??= new WifiInfo();
        s.Wifi.RssiDbm = Num(rssi.Groups[1].Value);
        var ssid = Regex.Match(text, @"^\s*SSID:\s*(.+)$", M); if (ssid.Success) s.Wifi.Ssid = ssid.Groups[1].Value.Trim();
        var bssid = Regex.Match(text, @"^\s*BSSID:\s*(\S+)", M); if (bssid.Success) s.Wifi.Bssid = bssid.Groups[1].Value;
        var rate = Regex.Match(text, @"^\s*lastTxRate:\s*(\d+)", M); if (rate.Success) s.Wifi.TxMbps = Num(rate.Groups[1].Value);
        var ch = Regex.Match(text, @"^\s*channel:\s*(\S+)", M); if (ch.Success) s.Wifi.Channel = ch.Groups[1].Value;
        return true;
    }

    public static string? BandFromFreq(double? mhz) => mhz switch
    {
        null => null,
        < 3000 => "2,4 GHz",
        < 5925 => "5 GHz",
        _ => "6 GHz",
    };

    // df -h / df -k
    private static bool Df(string text, Snapshot s)
    {
        var h = Regex.Match(text, @"^(Filesystem|Sist\. Arq\.|Sistema de arquivos)\s+.*(Use%|Uso%|Capacity).*$", MI);
        if (!h.Success) return false;
        var kb = Regex.IsMatch(h.Value, @"1K-blocks|1K-blocos|1024-blocks", RegexOptions.IgnoreCase);
        foreach (var raw in text[(h.Index + h.Length)..].Split('\n').Skip(1))
        {
            var line = raw.TrimEnd('\r');
            if (line.Length == 0 || line.StartsWith('$')) break;
            var c = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (c.Length < 6) continue;
            var fs = c[0]; var mount = c[^1];
            if (Regex.IsMatch(fs, "^(tmpfs|devtmpfs|udev|overlay|efivarfs|none|map|devfs)$") || mount.StartsWith("/snap/") || mount.StartsWith("/run") || mount.StartsWith("/sys") || mount.StartsWith("/dev") || mount.StartsWith("/System/Volumes/") && mount != "/System/Volumes/Data") continue;
            var pctTok = c.FirstOrDefault(x => x.EndsWith('%'));
            if (pctTok is null || Num(pctTok.TrimEnd('%')) is not double pct) continue;
            double? totalGb = kb ? Num(c[1]) / 1048576.0 : HumanGb(c[1]);
            s.Disks.Add(new DiskInfo(mount, totalGb is double g ? Math.Round(g, 1) : null, pct));
        }
        return s.Disks.Count > 0;
    }

    private static double? HumanGb(string v)
    {
        var m = Regex.Match(v.Replace(',', '.'), @"^([\d.]+)([KMGTP])i?$", RegexOptions.IgnoreCase);
        if (!m.Success || Num(m.Groups[1].Value) is not double n) return null;
        return char.ToUpperInvariant(m.Groups[2].Value[0]) switch { 'K' => n / 1048576, 'M' => n / 1024, 'G' => n, 'T' => n * 1024, 'P' => n * 1048576, _ => null };
    }

    // free -m / free
    private static bool Free(string text, Snapshot s)
    {
        var m = Regex.Match(text, @"^Mem\.?:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", M);
        if (!m.Success) return false;
        double total = Num(m.Groups[1].Value) ?? 0, avail = Num(m.Groups[6].Value) ?? 0;
        var div = total > 4_000_000 ? 1024.0 : 1.0; // "free" sem -m vem em KiB
        s.MemTotalMb = Math.Round(total / div);
        s.MemAvailMb = Math.Round(avail / div);
        return true;
    }

    private static readonly Dictionary<string, string> PtStates = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ESTABELECIDA"] = "ESTABLISHED", ["ESTABELECIDO"] = "ESTABLISHED", ["OUÇA"] = "LISTEN", ["ESCUTANDO"] = "LISTEN",
        ["SYN_ENVIADO"] = "SYN_SENT", ["SYN_RECEBIDO"] = "SYN_RECV", ["AGUARDANDO_FECHAMENTO"] = "CLOSE_WAIT", ["FECHANDO"] = "CLOSING",
    };

    private static bool Netstat(string text, Snapshot s)
    {
        var any = false;
        foreach (Match m in Regex.Matches(text, @"^\s*(tcp6?|TCP)\s+\S+\s+\S+\s+(?:\S+\s+){0,3}([A-ZÇÃÕÉ_]{4,})\s*$", M))
        {
            var st = m.Groups[2].Value;
            if (PtStates.TryGetValue(st, out var en)) st = en;
            s.ConnectionStates[st] = s.ConnectionStates.GetValueOrDefault(st) + 1;
            any = true;
        }
        return any && s.ConnectionStates.Values.Sum() >= 3;
    }

    private static bool IpAddr(string text, Snapshot s)
    {
        if (s.Interfaces.Count > 0) return false; // nmcli já descreveu as interfaces
        var any = false;
        foreach (Match m in Regex.Matches(text, @"^\d+: ([^:@\s]+)(?:@\S+)?: <([^>]*)>.*?state (\w+)", M))
        {
            s.Interfaces.Add(new InterfaceInfo(m.Groups[1].Value, m.Groups[3].Value, m.Groups[2].Value));
            any = true;
        }
        return any;
    }
}
