using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

/// <summary>Lê pacotes de logs do Netskope Client e produz o diagnóstico. Tudo em memória, nada sai do computador.</summary>
public sealed class Analyzer
{
    private const RegexOptions Opt = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    // 2026/11/23 15:33:52.326333 stAgentSvc p144e0e t144e19 info arquivo.cpp:191 modulo mensagem
    private static readonly Regex LineA = new(@"^(\d{4})[/-](\d\d)[/-](\d\d)[ T](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s+(\S+)\s+p(\w+)\s+t(\w+)\s+(\w+)\s+(\S+)\s?(.*)$", Opt);
    // [HOST:2026-11-23 15:39:40.467 -03:00] t154582 [info] arquivo.cpp:1587:func():0x0 mensagem
    private static readonly Regex LineB = new(@"^\[(?:[^\]]*?:)?(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d+))?[^\]]*\]\s+t(\w+)\s+\[(\w+)\]\s+(\S+)\s?(.*)$", Opt);

    private static readonly Regex StartRe = new(@"=+ (\S+) ([\d.]+) starting", Opt);
    private static readonly Regex StatusEventRe = new(@"event: ([^,]+), actor: (\w+).*?service: (\d)", Opt);
    private static readonly Regex LocationRe = new(@"Client location is (\S+)", Opt);
    private static readonly Regex NpaStatusRe = new(@"NPA Tunnel Status: (\w+)[^\[]*\[(\w+)\]", Opt);
    private static readonly Regex EgressRe = new(@"egress_ip""?\s*[:=]\s*""?([\d.]+)", Opt);
    private static readonly Regex PopNameRe = new(@"""name"":""([^""]+)""", Opt);
    private static readonly Regex DestIpRe = new(@"dest IP: (\S+)", Opt);
    private static readonly Regex TenantRe = new(@"(?:addon|achecker|gateway|download|nsauth|aproxy)-([a-z0-9]+(?:\.(?:eu|de|au))?)\.goskope\.com", Opt | RegexOptions.IgnoreCase);

    // métricas extraídas dos logs do Netskope Client
    private static readonly Regex PostRttRe = new(@"gslb \[(NPA|NSClient)\]:? post client rtt pop:(\S+) ip:([\d.]+) rtt:(\d+)", Opt);
    private static readonly Regex CalcRttRe = new(@"gslb \[(NPA|NSClient)\]:? calculate\(\) rtt:([\d.]+) duration:(\d+)", Opt);
    private static readonly Regex PopDefRe = new(@"gslb \[(NPA|NSClient)\] Pop:([^;]+);[^;]*;[^;]*;([\d.]+);", Opt);
    private static readonly Regex FlowRe = new(@"TLS Tunneling flow from addr: [^,]+, process: ?([^,]*?) to host: ([^,]+), addr", Opt);
    private static readonly Regex BypassRe = new(@"bypassing flow to exception host: ([^,]+), process: ([^,]+)", Opt);
    private static readonly Regex UdpBlockRe = new(@"Blocking UDP connection from process: ([^,]+), dest IP:([\d.:a-fA-F]+?):(\d+),", Opt);

    private static readonly Regex NormHex = new(@"0x[0-9a-f]+", Opt | RegexOptions.IgnoreCase);
    private static readonly Regex NormIp = new(@"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", Opt);
    private static readonly Regex NormUuid = new(@"[0-9a-f]{8}-[0-9a-f-]{27,}", Opt | RegexOptions.IgnoreCase);
    private static readonly Regex NormNum = new(@"\d+", Opt);
    private static readonly Regex SrcLine = new(@":\d+.*$", Opt);

    private static readonly Regex SkipExt = new(@"\.(pcap|pcapng|etl|dmp|exe|dll|png|jpe?g|gz|7z|evtx|p12|enc|der|pem|key|cab|bin|msi)$", Opt | RegexOptions.IgnoreCase);

    private static readonly Dictionary<string, (string Label, EventKind Kind)> EventNames = new()
    {
        ["Tunnel Up"] = ("Túnel conectado", EventKind.Good),
        ["Tunnel Down"] = ("Túnel desconectado", EventKind.Bad),
        ["User Disabled"] = ("Desabilitado pelo usuário", EventKind.Alert),
        ["User Enabled"] = ("Habilitado pelo usuário", EventKind.Good),
        ["Enrolled"] = ("Registrado (enroll)", EventKind.Good),
        ["Admin Disabled"] = ("Desabilitado pelo admin", EventKind.Alert),
        ["Admin Enabled"] = ("Habilitado pelo admin", EventKind.Good),
        ["Uninstalled"] = ("Desinstalado", EventKind.Bad),
        ["Installed"] = ("Instalado", EventKind.Info),
        ["Upgraded"] = ("Atualizado", EventKind.Info),
    };

    public static string EventLabel(string ev) => EventNames.TryGetValue(ev, out var t) ? t.Label : ev;
    public static EventKind EventKindOf(string ev) => EventNames.TryGetValue(ev, out var t) ? t.Kind : EventKind.Info;
    public static string ServiceName(int s) => s switch { 1 => "Internet", 2 => "Private Access", _ => "Serviço " + s };

    private sealed class RuleHits
    {
        public required Rule Rule;
        public int Count;
        public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
        public readonly HashSet<string> Files = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> Samples = new();
        public readonly Dictionary<string, int> Details = new();
        public readonly List<DateTime> Times = new();
    }

    /// <summary>Sintomas, site e horário informados pelo analista (opcional).</summary>
    public AnalysisOptions Options { get; set; } = new();

    private AnalysisResult _r = new();
    private readonly Dictionary<string, RuleHits> _hits = new();
    private readonly Dictionary<string, UnclassifiedGroup> _unc = new();
    private readonly Dictionary<string, JsonElement> _json = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Finding> _extra = new();
    private string? _lastLocation;
    private readonly Dictionary<string, string> _popNames = new();
    private readonly List<(DateTime Time, string Svc, string Pop, string? Ip, double Rtt)> _rtt = new();
    private readonly List<DateTime> _flowTunnel = new(), _flowBypass = new(), _flowUdp = new(), _errTimes = new();
    private readonly Dictionary<string, AppUsage> _apps = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(DateTime Time, int Svc, string Ev)> _svcEvents = new();
    private DateTime? _collectedAt;
    private readonly Dictionary<string, string> _texts = new(StringComparer.OrdinalIgnoreCase);
    private TacInsights? _tac;
    private readonly IdentityCollector _id = new();

    // ------------------------------------------------------------------ entrada

    public AnalysisResult AnalyzePaths(IEnumerable<string> paths, IProgress<string>? progress = null)
    {
        var items = new List<SourceItem>();
        var skipped = new List<string>();
        foreach (var p in paths)
        {
            if (Directory.Exists(p))
            {
                var opts = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System, IgnoreInaccessible = true, MaxRecursionDepth = 8 };
                var count = 0;
                foreach (var f in Directory.EnumerateFiles(p, "*", opts))
                {
                    if (++count > InputLimits.MaxFolderFiles) { skipped.Add($"{p}: mais de {InputLimits.MaxFolderFiles} arquivos — o restante foi ignorado"); break; }
                    AddFile(f, Path.GetRelativePath(p, f), items, skipped, progress);
                }
            }
            else if (File.Exists(p))
            {
                AddFile(p, Path.GetFileName(p), items, skipped, progress);
            }
        }
        var r = AnalyzeItems(items, progress);
        r.Skipped.InsertRange(0, skipped);
        return r;
    }

    private static void AddFile(string path, string name, List<SourceItem> items, List<string> skipped, IProgress<string>? progress)
    {
        progress?.Report("Lendo " + Path.GetFileName(path) + "…");
        try
        {
            var len = new FileInfo(path).Length;
            if (len > InputLimits.MaxFileBytes) { skipped.Add($"{name} (maior que {InputLimits.MaxFileBytes / 1048576} MB — ignorado)"); return; }
            var data = File.ReadAllBytes(path);
            if (IsZip(data)) ExtractZip(data, "", items, skipped);
            else items.Add(new SourceItem(name, data));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            skipped.Add($"{name} (não foi possível ler: {ex.Message})");
        }
    }

    private static bool IsZip(byte[] d) => d.Length > 4 && d[0] == 0x50 && d[1] == 0x4B && (d[2] == 3 || d[2] == 5) && (d[3] == 4 || d[3] == 6);

    public static void ExtractZip(byte[] data, string prefix, List<SourceItem> items, List<string> skipped)
    {
        long total = items.Sum(i => (long)i.Data.Length);
        ExtractZip(data, prefix, items, skipped, 0, ref total);
    }

    /// <summary>
    /// Extrai em memória (nada é gravado em disco, então não há "zip slip"), com limites contra zip bomb,
    /// zips aninhados em profundidade e excesso de entradas.
    /// </summary>
    private static void ExtractZip(byte[] data, string prefix, List<SourceItem> items, List<string> skipped, int depth, ref long total)
    {
        ZipArchive zip;
        try { zip = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read); }
        catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentException or NotSupportedException)
        {
            skipped.Add((prefix.Length > 0 ? prefix : "pacote") + " (zip inválido ou corrompido)");
            return;
        }
        using (zip)
        {
            var n = 0;
            foreach (var e in zip.Entries)
            {
                if (string.IsNullOrEmpty(e.Name)) continue; // pasta
                var full = prefix + e.FullName.Replace('\\', '/');
                if (++n > InputLimits.MaxZipEntries) { skipped.Add($"{prefix}: mais de {InputLimits.MaxZipEntries} arquivos no zip — o restante foi ignorado"); break; }
                if (e.Length > InputLimits.MaxEntryBytes) { skipped.Add($"{full} (muito grande: {e.Length / 1048576} MB)"); continue; }
                if (e.CompressedLength > 0 && e.Length > 50L * 1024 * 1024 && (double)e.Length / e.CompressedLength > InputLimits.MaxCompressionRatio)
                { skipped.Add($"{full} (taxa de compressão suspeita — possível zip bomb)"); continue; }
                if (total + e.Length > InputLimits.MaxTotalUncompressed) { skipped.Add($"{full} (limite total de {InputLimits.MaxTotalUncompressed / 1073741824} GB descompactados atingido)"); break; }
                try
                {
                    byte[]? bytes;
                    using (var s = e.Open()) bytes = InputLimits.ReadBounded(s, Math.Min(InputLimits.MaxEntryBytes, InputLimits.MaxTotalUncompressed - total));
                    if (bytes is null) { skipped.Add($"{full} (conteúdo maior que o declarado — ignorado)"); continue; }
                    total += bytes.Length;
                    if (e.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && IsZip(bytes))
                    {
                        if (depth + 1 >= InputLimits.MaxZipDepth) { skipped.Add($"{full} (zip aninhado em profundidade demais)"); continue; }
                        ExtractZip(bytes, full + "/", items, skipped, depth + 1, ref total);
                    }
                    else items.Add(new SourceItem(full, bytes));
                }
                catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException or UnauthorizedAccessException)
                {
                    skipped.Add(full + " (não foi possível extrair)");
                }
            }
        }
    }

    // ------------------------------------------------------------------ análise

    public AnalysisResult AnalyzeItems(IEnumerable<SourceItem> source, IProgress<string>? progress = null)
    {
        _r = new AnalysisResult();
        var items = source.OrderByDescending(i => i.Data.Length).ToList();
        var n = 0;
        foreach (var it in items)
        {
            n++;
            var baseName = Path.GetFileName(it.Name.Replace('\\', '/'));
            if (Regex.IsMatch(baseName, @"\.(pcap|pcapng|cap)$", RegexOptions.IgnoreCase))
            {
                progress?.Report($"Lendo captura {baseName}…");
                _r.Files.Add(new LogFileInfo { Name = it.Name, Size = it.Data.Length });
                _r.Captures.Add(PcapReader.Read(baseName, it.Data));
                continue;
            }
            if (SkipExt.IsMatch(baseName)) { _r.Skipped.Add(baseName); continue; }
            progress?.Report($"Analisando {baseName} ({n}/{items.Count})…");
            var text = Decode(it.Data);
            if (text is null) { _r.Skipped.Add(baseName); continue; }

            var fi = _r.Files.Count;
            _r.Files.Add(new LogFileInfo { Name = it.Name, Size = it.Data.Length });
            try
            {

                _id.OnFile(baseName, text);
                if (TelemetryParser.LooksLikeTelemetry(baseName, text))
                {
                    TelemetryParser.Parse(text, baseName, _r);
                    continue;
                }

                if (Regex.IsMatch(baseName, @"\.(json|conf|bak)$", RegexOptions.IgnoreCase)) ParseJson(baseName, text);
                if (baseName.Equals("install.log", StringComparison.OrdinalIgnoreCase)) ParseInstall(text);
                if (Regex.IsMatch(baseName, "network-state|ipconfig|netstat", RegexOptions.IgnoreCase)) ParseNetworkState(text, baseName);
                if (Regex.IsMatch(baseName, @"network-state|ipconfig|netstat|nmcli|resolv|route|ifconfig|ip[-_]?addr|scutil|ps[-_]?aux|process|appinfo", RegexOptions.IgnoreCase) && text.Length < 20_000_000) _texts[baseName] = text;
                if (Regex.IsMatch(baseName, @"process|tasklist|ps[-_]?aux", RegexOptions.IgnoreCase)) ScanProcesses(text, baseName);
                if (baseName.StartsWith("appinfo", StringComparison.OrdinalIgnoreCase))
                {
                    var apps = KnowledgeBase.Conflicts.Where(c => c.Re.IsMatch(text)).Select(c => c.Name).ToList();
                    if (apps.Count > 0) _r.Facts.InstalledVpnApps = string.Join(", ", apps);
                }
                ParseLog(fi, text);
                try
                {
                    if (_r.Files[fi].Lines < 20 && SnapshotParsers.Parse(baseName, text, _collectedAt) is Snapshot snap) _r.Snapshots.Add(snap);
                }
                catch (RegexMatchTimeoutException) { _r.Skipped.Add(baseName + " (formato anômalo)"); }
            }
            catch (Exception ex) when (ex is RegexMatchTimeoutException or JsonException or FormatException or InvalidOperationException or ArgumentException or OverflowException or IndexOutOfRangeException or KeyNotFoundException)
            {
                _r.Skipped.Add($"{baseName} (análise interrompida: formato inesperado)");
            }
        }

        if (_skippedLines > 0) _r.DataGaps.Add($"{_skippedLines} linha(s) ignorada(s) por formato anômalo (proteção contra entrada maliciosa).");
        DeriveFacts();
        BuildFindings();
        _r.Events.Sort((a, b) => a.Time.CompareTo(b.Time));
        // ordenação estável: linhas com o mesmo horário mantêm a ordem do arquivo
        var ordered = _r.Entries.OrderBy(e => e.Time).ToList();
        _r.Entries.Clear();
        _r.Entries.AddRange(ordered);
        _r.Unclassified.AddRange(_unc.Values.OrderByDescending(u => u.Count));
        _r.DetectedOs = DetectOs();
        // capturas: UTC → horário da máquina do usuário (fuso dos logs), não o do analista
        foreach (var c in _r.Captures)
        {
            DateTime Conv(DateTime t) => _r.LogUtcOffset is TimeSpan off ? DateTime.SpecifyKind(t + off, DateTimeKind.Unspecified) : t.ToLocalTime();
            if (c.First is DateTime f) c.First = Conv(f);
            if (c.Last is DateTime l) c.Last = Conv(l);
        }
        _tac = new TacInsights(_r, _texts, _json);
        Guard("análises de suporte", _tac.Run);
        Guard("identificação do usuário e da máquina", () => _id.Finish(_r, _json));
        foreach (var f in _r.Findings)
        {
            f.Steps.AddRange(KnowledgeBase.BuildSteps(f, _r.DetectedOs, _r.Facts.TenantHost));
            f.References.AddRange(KnowledgeBase.ReferencesFor(f.Key));
            if (f.SearchQuery.Length == 0) f.SearchQuery = KnowledgeBase.QueryFor(f.Key, f.Title);
        }
        _r.Findings.Sort((a, b) => a.Severity != b.Severity ? a.Severity.CompareTo(b.Severity) : b.Count.CompareTo(a.Count));
        FinalizeMetrics();
        return _r;
    }

    public static string? Decode(byte[] d)
    {
        if (d.Length >= 2 && d[0] == 0xFF && d[1] == 0xFE) return Encoding.Unicode.GetString(d, 2, d.Length - 2);
        if (d.Length >= 2 && d[0] == 0xFE && d[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(d, 2, d.Length - 2);
        if (d.Length >= 3 && d[0] == 0xEF && d[1] == 0xBB && d[2] == 0xBF) return Encoding.UTF8.GetString(d, 3, d.Length - 3);
        var zeros = 0;
        for (var i = 0; i < Math.Min(d.Length, 4096); i++) if (d[i] == 0) zeros++;
        if (zeros > 40)
        {
            if (d.Length > 1 && d[1] == 0 && d[0] != 0) return Encoding.Unicode.GetString(d);
            return null; // binário
        }
        return Encoding.UTF8.GetString(d);
    }

    private static LogLevel? NormLevel(string l)
    {
        l = l.ToLowerInvariant();
        if (l.StartsWith("err")) return LogLevel.Error;
        if (l.StartsWith("warn")) return LogLevel.Warn;
        if (l is "critical" or "fatal" or "crit") return LogLevel.Critical;
        if (l is "debug" or "trace") return LogLevel.Debug;
        if (l == "info") return LogLevel.Info;
        return null;
    }

    private static DateTime MakeTime(Match m, int frac)
    {
        static int I(Group g) => int.Parse(g.Value, CultureInfo.InvariantCulture);
        try
        {
            var t = new DateTime(I(m.Groups[1]), I(m.Groups[2]), I(m.Groups[3]), I(m.Groups[4]), I(m.Groups[5]), I(m.Groups[6]));
            var f = m.Groups[frac].Value;
            if (f.Length > 0) t = t.AddTicks(long.Parse((f + "0000000")[..7], CultureInfo.InvariantCulture));
            return t;
        }
        catch (ArgumentOutOfRangeException) { return DateTime.MinValue; }
    }

    private void ParseLog(int fi, string text)
    {
        var file = _r.Files[fi];
        using var reader = new StringReader(text);
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.Length == 0) continue;
            if (line.Length > 16384) line = line[..16384]; // linhas gigantes (forjadas ou corrompidas) não travam os regex
            if (_r.Entries.Count >= InputLimits.MaxEntries)
            {
                if (!_r.DataGaps.Any(g => g.StartsWith("Limite de linhas", StringComparison.Ordinal)))
                    _r.DataGaps.Add($"Limite de linhas atingido ({InputLimits.MaxEntries:N0}): o restante dos logs não foi analisado.");
                break;
            }
            try { ParseLine(fi, file, line); }
            catch (RegexMatchTimeoutException) { _skippedLines++; }
        }
    }

    private int _skippedLines;

    /// <summary>Uma etapa que falhar com dados inesperados não derruba a análise inteira.</summary>
    private void Guard(string stage, Action a)
    {
        try { a(); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _r.DataGaps.Add($"A etapa “{stage}” não pôde ser concluída com estes dados ({ex.GetType().Name}). O restante da análise segue válido.");
        }
    }

    private void ParseLine(int fi, LogFileInfo file, string line)
    {
        {
            DateTime time; LogLevel level; string src, msg;
            var a = LineA.Match(line);
            if (a.Success)
            {
                var lv = NormLevel(a.Groups[11].Value); if (lv is null) return;
                time = MakeTime(a, 7); level = lv.Value; src = a.Groups[12].Value; msg = a.Groups[13].Value;
            }
            else if (line[0] == '[' && LineB.Match(line) is { Success: true } b)
            {
                var lv = NormLevel(b.Groups[9].Value); if (lv is null) return;
                time = MakeTime(b, 7); level = lv.Value; src = b.Groups[10].Value; msg = b.Groups[11].Value;
                if (_r.LogUtcOffset is null && Regex.Match(line, @"^\[[^\]]*? ([+-])(\d\d):(\d\d)\]") is { Success: true } tz)
                    _r.LogUtcOffset = (tz.Groups[1].Value == "-" ? -1 : 1) * new TimeSpan(int.Parse(tz.Groups[2].Value, CultureInfo.InvariantCulture), int.Parse(tz.Groups[3].Value, CultureInfo.InvariantCulture), 0);
            }
            else return;
            if (time == DateTime.MinValue) return;

            file.Lines++;
            if (file.First is null || time < file.First) file.First = time;
            if (file.Last is null || time > file.Last) file.Last = time;
            if (_r.Start is null || time < _r.Start) _r.Start = time;
            if (_r.End is null || time > _r.End) _r.End = time;
            if (level is LogLevel.Error or LogLevel.Critical) { file.Errors++; _errTimes.Add(time); }
            else if (level == LogLevel.Warn) file.Warnings++;

            var entry = new LogEntry(fi, time, level, line, msg, src);
            _r.Entries.Add(entry);
            CollectEvents(entry, file.BaseName);
            _id.OnLine(msg, file.BaseName);
            Classify(entry, file);
        }
    }

    private void CollectEvents(LogEntry e, string file)
    {
        var m = e.Message;
        var F = _r.Facts;
        if (m.Contains("starting ======"))
        {
            var x = StartRe.Match(m);
            if (x.Success && x.Groups[1].Value.Contains("stAgentSvc", StringComparison.OrdinalIgnoreCase))
            {
                _r.Events.Add(new(e.Time, "Serviço iniciado", EventKind.Info, "v" + x.Groups[2].Value, file));
                F.Version = x.Groups[2].Value;
            }
        }
        else if (m.Contains("Service is stopping")) _r.Events.Add(new(e.Time, "Serviço parado", EventKind.Bad, "", file));
        else if (m.Contains("Caching client status, event:"))
        {
            var x = StatusEventRe.Match(m);
            if (x.Success)
            {
                var ev = x.Groups[1].Value; var actor = x.Groups[2].Value; var svc = int.Parse(x.Groups[3].Value, CultureInfo.InvariantCulture);
                var who = actor == "User" ? "usuário" : actor == "System" ? "sistema" : actor;
                _r.Events.Add(new(e.Time, EventLabel(ev), EventKindOf(ev), ServiceName(svc) + " · por " + who, file));
                F.Services[svc] = new ServiceState(ev, e.Time);
                _svcEvents.Add((e.Time, svc, ev));
            }
        }
        else if (m.Contains("Client location is"))
        {
            var x = LocationRe.Match(m);
            if (x.Success && x.Groups[1].Value != "N/A" && x.Groups[1].Value != _lastLocation)
            {
                _lastLocation = x.Groups[1].Value;
                _r.Events.Add(new(e.Time, "Local: " + _lastLocation, EventKind.Info, "", file));
            }
        }
        else if (m.Contains("Log collection complete")) { _r.Events.Add(new(e.Time, "Coleta de logs", EventKind.Info, "", file)); _collectedAt = e.Time; }
        else if (m.Contains("NPA Tunnel Status:"))
        {
            var x = NpaStatusRe.Match(m); if (x.Success) F.NpaLast = x.Groups[2].Value;
        }

        if (m.Contains("egress_ip"))
        {
            var x = EgressRe.Match(m);
            if (x.Success)
            {
                var ip = x.Groups[1].Value;
                if (F.Egress != null && F.Egress != ip) _r.Events.Add(new(e.Time, "IP de saída mudou", EventKind.Alert, $"{F.Egress} → {ip}", file));
                if (F.Egress != ip) _r.EgressHistory.Add(new(e.Time, ip));
                F.Egress = ip;
            }
        }
        CollectMetrics(e, m);
        if (m.Contains("fetched ordered POPs"))
        {
            var x = PopNameRe.Match(m);
            if (x.Success) { if (m.Contains("[NPA]")) F.PopNpa = x.Groups[1].Value; else F.PopSwg = x.Groups[1].Value; }
        }
        if (m.Contains("Primary tunnel dest IP")) { var x = DestIpRe.Match(m); if (x.Success) F.GatewayIp = x.Groups[1].Value; }
        if (F.TenantHost is null && m.Contains("goskope.com")) { var x = TenantRe.Match(m); if (x.Success) F.TenantHost = x.Groups[1].Value.ToLowerInvariant(); }
    }

    private void Classify(LogEntry e, LogFileInfo file)
    {
        foreach (var r in KnowledgeBase.Rules)
        {
            if (!r.AnyLevel) continue;
            if (r.Re.IsMatch(e.Message)) { Hit(r, e, file); return; }
        }
        if (e.Level is not (LogLevel.Error or LogLevel.Critical or LogLevel.Warn)) return;
        foreach (var r in KnowledgeBase.Rules)
        {
            if (r.AnyLevel) continue;
            if (r.Re.IsMatch(e.Message)) { Hit(r, e, file); return; }
        }
        var key = Normalize(SrcLine.Replace(e.Source, "") + " " + e.Message);
        if (!_unc.TryGetValue(key, out var u))
        {
            u = new UnclassifiedGroup { Key = key, Level = e.Level, Sample = e.Line, Last = e.Time };
            _unc[key] = u;
        }
        u.Count++;
        u.Files.Add(file.BaseName);
        if (e.Time > u.Last) u.Last = e.Time;
        if (e.Level != LogLevel.Warn) u.Level = e.Level;
    }

    public static string Normalize(string m)
    {
        m = NormHex.Replace(m, "#");
        m = NormIp.Replace(m, "<ip>");
        m = NormUuid.Replace(m, "<id>");
        m = NormNum.Replace(m, "#");
        return m.Length > 220 ? m[..220] : m;
    }

    private void Hit(Rule r, LogEntry e, LogFileInfo file)
    {
        if (!_hits.TryGetValue(r.Id, out var h)) { h = new RuleHits { Rule = r }; _hits[r.Id] = h; }
        h.Count++;
        if (e.Time < h.First) h.First = e.Time;
        if (e.Time > h.Last) h.Last = e.Time;
        h.Files.Add(file.BaseName);
        if (h.Times.Count < 20000) h.Times.Add(e.Time);
        if (h.Samples.Count < 6) h.Samples.Add(file.BaseName + ": " + e.Line);
        if (r.Id == "restapi")
        {
            var m = r.Re.Match(e.Message);
            var c = m.Groups[1].Success && m.Groups[1].Value.Length > 0 ? m.Groups[1].Value : m.Groups[2].Value;
            c = c.Trim();
            if (c.Length > 0) h.Details[c] = h.Details.GetValueOrDefault(c) + 1;
        }
        else if (r.Id == "http")
        {
            var m = r.Re.Match(e.Message);
            if (m.Groups[1].Success) { var k = "HTTP " + m.Groups[1].Value; h.Details[k] = h.Details.GetValueOrDefault(k) + 1; }
        }
    }

    // ------------------------------------------------------------------ arquivos auxiliares

    private void ParseJson(string baseName, string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            _json[baseName] = doc.RootElement.Clone();
        }
        catch (JsonException) { }
    }

    private void ParseInstall(string t)
    {
        var v = Regex.Match(t, @"NSClient Version:\s*(\S+)"); if (v.Success) _r.Facts.InstallVersion = v.Groups[1].Value;
        var o = Regex.Match(t, @"PRETTY_NAME:\s*""?([^""\r\n]+)"); if (o.Success) _r.Facts.OsName = o.Groups[1].Value.Trim();
        var d = Regex.Match(t, @"^Time:\s*(.+)$", RegexOptions.Multiline); if (d.Success) _r.Facts.InstallTime = d.Groups[1].Value.Trim();
        var missing = Regex.Matches(t, @"^(\S+) -+ \[not installed\]", RegexOptions.Multiline)
            .Select(m => m.Groups[1].Value)
            .Where(p => !Regex.IsMatch(t, "can replace " + Regex.Escape(p)))
            .ToList();
        if (missing.Count > 0)
        {
            var f = new Finding
            {
                Key = "deps", Severity = Severity.Warning, Category = "Instalação", Title = "Dependências ausentes na instalação",
                Meaning = "O instalador listou pacotes não instalados sem substituto: " + string.Join(", ", missing) + ".", Count = missing.Count,
            };
            f.MissingPackages.AddRange(missing);
            _extra.Add(f);
        }
    }

    private void ParseNetworkState(string t, string baseName)
    {
        var ifs = Regex.Matches(t, @"^\d+: ([^:@\s]+)(?:@\S+)?: <([^>]*)>", RegexOptions.Multiline)
            .Select(m => (Name: m.Groups[1].Value, Flags: m.Groups[2].Value)).ToList();
        var dnsByDev = new Dictionary<string, List<string>>();
        string? cur = null;
        foreach (var raw in t.Split('\n'))
        {
            var ln = raw.TrimEnd('\r');
            var d = Regex.Match(ln, @"^GENERAL\.DEVICE:\s+(\S+)");
            if (d.Success) { cur = d.Groups[1].Value; dnsByDev[cur] = new(); continue; }
            var s = Regex.Match(ln, @"^IP4\.DNS\[\d+\]:\s+(\S+)");
            if (s.Success && cur != null) dnsByDev[cur].Add(s.Groups[1].Value);
        }
        var dead = ifs.Where(i => KnowledgeBase.VpnInterface.IsMatch(i.Name) && i.Flags.Contains("NO-CARRIER")).ToList();
        if (dead.Count > 0)
        {
            var dns = dead.SelectMany(i => dnsByDev.GetValueOrDefault(i.Name) ?? new List<string>()).Distinct().ToList();
            var names = string.Join(", ", dead.Select(i => i.Name).Take(8)) + (dead.Count > 8 ? "…" : "");
            var f = new Finding
            {
                Key = "orphan", Severity = dns.Count > 0 ? Severity.Critical : Severity.Warning, Category = "Rede",
                Title = $"{dead.Count} interface(s) de VPN de terceiros sem link (órfãs)",
                Meaning = $"Interfaces {names} estão sem portadora (NO-CARRIER) mas continuam configuradas" + (dns.Count > 0
                    ? $", com servidores DNS {string.Join(", ", dns)}. Esses DNS internos podem ser consultados primeiro e não responder fora da rede corporativa — causa comum dos timeouts e falhas de DNS do Netskope."
                    : ". Podem deixar rotas inconsistentes."),
                Count = dead.Count,
            };
            f.Interfaces.AddRange(dead.Select(i => i.Name));
            foreach (var i in dead.Take(6))
                f.Samples.Add($"{baseName}: {i.Name} <{i.Flags}> DNS: {(dnsByDev.TryGetValue(i.Name, out var l) && l.Count > 0 ? string.Join(", ", l) : "—")}");
            f.Files.Add(baseName);
            _extra.Add(f);
        }
        var ps = Regex.Match(t, @"\$ [^\n]*ps aux[^\n]*\n([\s\S]*?)(?=\n\$ |\z)");
        if (ps.Success) ScanProcesses(ps.Groups[1].Value, baseName);
        var sysDns = dnsByDev.Where(kv => !KnowledgeBase.VpnInterface.IsMatch(kv.Key) && kv.Value.Count > 0).Select(kv => kv.Key + ": " + string.Join(", ", kv.Value)).ToList();
        if (sysDns.Count > 0) _r.Facts.Dns = string.Join(" · ", sysDns);
    }

    private void ScanProcesses(string txt, string baseName)
    {
        var lines = txt.Split('\n').Where(l => !Regex.IsMatch(l, "nsdiag|grep")).ToList();
        foreach (var c in KnowledgeBase.Conflicts)
        {
            var hits = lines.Where(l => c.Re.IsMatch(l)).ToList();
            if (hits.Count == 0 || _extra.Any(x => x.Key == "conflict" && x.Title.StartsWith(c.Name))) continue;
            var f = new Finding
            {
                Key = "conflict", Severity = Severity.Warning, Category = "Conflito", Title = $"{c.Name} em execução junto com o Netskope",
                Meaning = $"Foram encontrados {hits.Count} processo(s) do {c.Name} rodando. Duas soluções de VPN/proxy ativas disputam rotas, DNS e regras de firewall e são causa frequente de quedas e timeouts.",
                Count = hits.Count,
            };
            foreach (var h in hits.Take(5))
            {
                var sample = baseName + ": " + Regex.Replace(h.Trim(), @"\s+", " ");
                f.Samples.Add(sample.Length > 200 ? sample[..200] : sample);
            }
            f.Files.Add(baseName);
            _extra.Add(f);
        }
    }

    private static string? Str(JsonElement e, params string[] path)
    {
        foreach (var p in path)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(p, out e)) return null;
        }
        return e.ValueKind switch
        {
            JsonValueKind.String => e.GetString(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => e.GetRawText(),
            _ => null,
        };
    }

    private void DeriveFacts()
    {
        var F = _r.Facts;
        if (_json.TryGetValue("nsconfig.json", out var c) || _json.TryGetValue("nsconfig.json.bak", out c))
        {
            F.Host ??= Str(c, "cache", "device", "hostname");
            var os = $"{Str(c, "cache", "device", "os")} {Str(c, "cache", "device", "os_version")}".Trim();
            if (os.Length > 0) F.Os ??= os;
            F.Version ??= Str(c, "cache", "device", "ns_version");
            var model = string.Join(" ", new[] { Str(c, "cache", "device", "make"), Str(c, "cache", "device", "model") }.Where(s => !string.IsNullOrEmpty(s)));
            if (model.Length > 0) F.Model = model;
            F.ClientConfig = Str(c, "clientConfig", "configurationName");
            F.AllowDisable = Str(c, "clientConfig", "allowClientDisabling");
        }
        if (_json.TryGetValue("eventcache.json", out var ev) && ev.ValueKind == JsonValueKind.Object)
        {
            JsonElement? last = null; long lastTs = long.MinValue;
            foreach (var p in ev.EnumerateObject())
            {
                if (!p.Value.TryGetProperty("client_status", out var cs)) continue;
                long.TryParse(Str(cs, "timestamp"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ts);
                if (ts >= lastTs) { lastTs = ts; last = cs; }
            }
            if (last is JsonElement l)
            {
                F.TenantId = Str(l, "tenant_id");
                F.ServiceStatus = Str(l, "status");
                F.NpaStatus = Str(l, "npa_status");
                var st = Str(l, "onprem_status", "status"); var me = Str(l, "onprem_status", "method");
                if (st != null) F.OnPrem = me != null ? $"{st} ({me})" : st;
                F.Steering = Str(l, "host_info", "steeringConfig");
                F.Host ??= Str(l, "host_info", "hostname");
            }
        }
        if (_json.TryGetValue("nsuser.conf", out var u)) F.FailClose = Str(u, "userConfig", "failCloseStatus");
        if (_json.TryGetValue("nssteering.json", out var s))
        {
            F.Steering ??= Str(s, "steering_config_name");
            if (F.TenantHost is null && s.TryGetProperty("domains", out var doms) && doms.ValueKind == JsonValueKind.Array)
            {
                foreach (var d in doms.EnumerateArray())
                {
                    var m = Regex.Match(d.GetString() ?? "", @"^(?:achecker|aproxy|addon|saml)-([a-z0-9]+(?:\.(?:eu|de|au))?)\.goskope\.com$");
                    if (m.Success) { F.TenantHost = m.Groups[1].Value; break; }
                }
            }
        }
        if (F.InstallVersion != null && F.Version != null && F.InstallVersion != F.Version)
        {
            _extra.Add(new Finding
            {
                Key = "version", Severity = Severity.Info, Category = "Instalação", Title = "Versão em execução difere da última instalação registrada",
                Meaning = $"install.log registra a versão {F.InstallVersion} ({F.InstallTime ?? "data desconhecida"}), mas o serviço está rodando {F.Version}. Indica reinstalação, downgrade ou atualização automática (golden release).",
                Count = 1,
            });
        }
        if (F.Services.TryGetValue(1, out var s1) && s1.Event == "User Disabled" && F.FailClose == "true")
        {
            _extra.Add(new Finding
            {
                Key = "failclose", Severity = Severity.Warning, Category = "Túnel", Title = "Cliente terminou desabilitado com fail-close ativo",
                Meaning = "O último evento do serviço Internet foi “desabilitado pelo usuário” e o fail-close está ligado — o usuário pode ficar sem navegação.", Count = 1,
            });
        }
    }

    private ClientOs? DetectOs()
    {
        var s = ((_r.Facts.OsName ?? "") + " " + (_r.Facts.Os ?? "")).ToLowerInvariant();
        if (s.Contains("windows")) return ClientOs.Windows;
        if (s.Contains("mac") || s.Contains("darwin")) return ClientOs.Mac;
        if (Regex.IsMatch(s, "linux|ubuntu|debian|red ?hat|mint|fedora|centos|rocky")) return ClientOs.Linux;
        if (_r.Entries.Take(2000).Any(e => e.Line.Contains("C:\\", StringComparison.OrdinalIgnoreCase) || e.Line.Contains("stAgentSvc.exe", StringComparison.OrdinalIgnoreCase))) return ClientOs.Windows;
        if (_r.Entries.Take(2000).Any(e => e.Line.Contains("/opt/netskope", StringComparison.Ordinal))) return ClientOs.Linux;
        if (_r.Entries.Take(2000).Any(e => e.Line.Contains("/Library/", StringComparison.Ordinal))) return ClientOs.Mac;
        return null;
    }

    private void BuildFindings()
    {
        var starts = _r.Events.Where(e => e.Label == "Serviço iniciado").Select(e => e.Time).ToList();
        var window = TimeSpan.FromMinutes(3);
        foreach (var h in _hits.Values)
        {
            var sev = h.Rule.SeverityFor(h.Count);
            var meaning = h.Rule.Meaning;
            if (h.Rule.Category != "Ruído" && !h.Rule.AnyLevel && h.Last - h.First <= window && starts.Any(t => h.First >= t && h.First - t <= window))
            {
                sev = sev switch { Severity.Critical => Severity.Warning, Severity.Warning => Severity.Info, _ => sev };
                meaning += " Observação: todas as ocorrências ficaram concentradas nos primeiros minutos após o (re)início do serviço, então provavelmente é transitório.";
            }
            var f = new Finding
            {
                Key = h.Rule.Id, Severity = sev, Category = h.Rule.Category, Title = h.Rule.Title, Meaning = meaning, Action = h.Rule.Action,
                Count = h.Count, First = h.First, Last = h.Last, ExplorerQuery = h.Rule.ExplorerQuery,
            };
            f.Files.AddRange(h.Files);
            f.Samples.AddRange(h.Samples);
            f.Details.AddRange(h.Details.OrderByDescending(kv => kv.Value));
            f.Times.AddRange(h.Times);
            _r.Findings.Add(f);
        }
        _r.Findings.AddRange(_extra);
        _r.Findings.Sort((a, b) => a.Severity != b.Severity ? a.Severity.CompareTo(b.Severity) : b.Count.CompareTo(a.Count));
    }

    // ------------------------------------------------------------------ métricas dos logs (v3)

    private static readonly CultureInfo CI = CultureInfo.InvariantCulture;

    private static string SvcName(string gslbSvc) => gslbSvc == "NPA" ? "Private Access" : "Internet";

    private void AddRtt(DateTime t, string svc, string pop, string? ip, double rtt)
    {
        var name = SvcName(svc);
        for (var i = _rtt.Count - 1; i >= 0 && (t - _rtt[i].Time).TotalSeconds <= 3; i--)
            if (_rtt[i].Svc == name && _rtt[i].Ip == ip) return; // mesma medição registrada duas vezes
        _rtt.Add((t, name, pop, ip, rtt));
    }

    private AppUsage App(string process, string host, DateTime t)
    {
        process = string.IsNullOrWhiteSpace(process) ? "(desconhecido)" : process.Trim();
        host = host.Trim();
        var key = process + "|" + host;
        if (!_apps.TryGetValue(key, out var a)) { a = new AppUsage { Process = process, Host = host }; _apps[key] = a; }
        if (t < a.First) a.First = t;
        if (t > a.Last) a.Last = t;
        return a;
    }

    private void CollectMetrics(LogEntry e, string m)
    {
        if (m.Contains("gslb [", StringComparison.Ordinal))
        {
            var pd = PopDefRe.Match(m);
            if (pd.Success) { _popNames[pd.Groups[3].Value] = pd.Groups[2].Value; return; }
            var pr = PostRttRe.Match(m);
            if (pr.Success)
            {
                _popNames[pr.Groups[3].Value] = pr.Groups[2].Value;
                AddRtt(e.Time, pr.Groups[1].Value, pr.Groups[2].Value, pr.Groups[3].Value, double.Parse(pr.Groups[4].Value, CI));
                return;
            }
            var cr = CalcRttRe.Match(m);
            if (cr.Success)
            {
                var ip = cr.Groups[2].Value;
                AddRtt(e.Time, cr.Groups[1].Value, _popNames.GetValueOrDefault(ip) ?? ip, ip, double.Parse(cr.Groups[3].Value, CI));
            }
            return;
        }
        if (m.Contains("TLS Tunneling flow", StringComparison.Ordinal))
        {
            var x = FlowRe.Match(m);
            if (x.Success) { _flowTunnel.Add(e.Time); App(x.Groups[1].Value, x.Groups[2].Value, e.Time).Tunneled++; }
            return;
        }
        if (m.Contains("bypassing flow", StringComparison.Ordinal))
        {
            var x = BypassRe.Match(m);
            if (x.Success) { _flowBypass.Add(e.Time); App(x.Groups[2].Value, x.Groups[1].Value, e.Time).Bypassed++; }
            return;
        }
        if (m.Contains("Blocking UDP", StringComparison.Ordinal))
        {
            var x = UdpBlockRe.Match(m);
            if (x.Success) { _flowUdp.Add(e.Time); App(x.Groups[1].Value, x.Groups[2].Value + ":" + x.Groups[3].Value + " (UDP/QUIC)", e.Time).BlockedUdp++; }
        }
    }

    private void FinalizeMetrics()
    {
        var r = _r;
        var collected = _collectedAt ?? r.End;
        foreach (var sn in r.Snapshots) sn.Time ??= collected;
        foreach (var sn in r.Snapshots)
        {
            foreach (var kv in sn.System) r.Device.TryAdd(kv.Key, kv.Value);
            if (sn.MemTotalMb is double mt) r.Device.TryAdd("Memória total (MB)", mt.ToString("0", CI));
        }

        // latência por POP (medida pelo próprio cliente na seleção de gateway)
        foreach (var g in _rtt.GroupBy(x => (x.Svc, x.Pop)))
        {
            var key = $"pop.rtt:{g.Key.Svc} {g.Key.Pop}";
            var list = g.OrderBy(x => x.Time).ToList();
            foreach (var x in list) TelemetryParser.Add(r, key, x.Time, x.Rtt, "Logs Netskope");
            r.Pops.Add(new PopStat(g.Key.Svc, g.Key.Pop, list[^1].Ip, list.Count, list.Min(x => x.Rtt), Math.Round(list.Average(x => x.Rtt), 1), list.Max(x => x.Rtt), list[^1].Rtt, list[^1].Time));
        }
        r.Pops.Sort((a, b) => a.Service != b.Service ? string.CompareOrdinal(a.Service, b.Service) : a.Avg.CompareTo(b.Avg));
        foreach (var g in _rtt.GroupBy(x => x.Svc))
        {
            var ordered = g.OrderBy(x => x.Time).ToList();
            var i = 0;
            while (i < ordered.Count)
            {
                var t0 = ordered[i].Time; var best = double.MaxValue; var j = i;
                while (j < ordered.Count && (ordered[j].Time - t0).TotalSeconds <= 10) { best = Math.Min(best, ordered[j].Rtt); j++; }
                TelemetryParser.Add(r, "pop.best:" + g.Key, t0, best, "Logs Netskope");
                i = j;
            }
        }

        // contagens por minuto (fluxos e erros) no período coberto pelos logs do Netskope
        if (r.Entries.Count > 0)
        {
            var logStart = r.Entries[0].Time; var logEnd = r.Entries[^1].Time;
            var bucket = (logEnd - logStart).TotalDays > 3 ? TimeSpan.FromMinutes(10) : TimeSpan.FromMinutes(1);
            void PerMinute(string key, List<DateTime> times)
            {
                if (times.Count == 0) return;
                var t0 = new DateTime(logStart.Ticks - logStart.Ticks % bucket.Ticks);
                var n = (int)((logEnd - t0).Ticks / bucket.Ticks) + 1;
                var counts = new int[n];
                foreach (var t in times) { var b = (int)((t - t0).Ticks / bucket.Ticks); if (b >= 0 && b < n) counts[b]++; }
                for (var k = 0; k < n; k++) TelemetryParser.Add(r, key, t0 + bucket * k, counts[k] / bucket.TotalMinutes, "Logs Netskope");
            }
            PerMinute("flows.tunnel", _flowTunnel);
            PerMinute("flows.bypass", _flowBypass);
            PerMinute("flows.udpblock", _flowUdp);
            // só eventos relevantes (crítico/atenção), sem o ruído conhecido
            PerMinute("log.errors", r.Findings.Where(f => f.Severity <= Severity.Warning).SelectMany(f => f.Times).ToList());

            // estados do túnel por serviço
            var stops = r.Events.Where(x => x.Label == "Serviço parado").Select(x => x.Time).ToList();
            foreach (var svc in new[] { 1, 2 })
            {
                var changes = new List<(DateTime T, string State)>();
                foreach (var x in _svcEvents.Where(x => x.Svc == svc))
                {
                    string? st = x.Ev switch
                    {
                        "Tunnel Up" => "Conectado",
                        "Tunnel Down" => "Desconectado",
                        "User Disabled" => "Desabilitado pelo usuário",
                        "Admin Disabled" => "Desabilitado pelo admin",
                        _ => null,
                    };
                    if (st != null) changes.Add((x.Time, st));
                }
                if (changes.Count == 0) continue;
                var first = changes.Min(c => c.T);
                changes.AddRange(stops.Where(t => t > first).Select(t => (t, "Serviço parado")));
                changes.Sort((a, b) => a.T.CompareTo(b.T));
                var name = ServiceName(svc);
                double total = 0, up = 0;
                for (var k = 0; k < changes.Count; k++)
                {
                    if (k > 0 && changes[k].State == changes[k - 1].State) continue;
                    var next = k + 1;
                    while (next < changes.Count && changes[next].State == changes[k].State) next++;
                    var endT = next < changes.Count ? changes[next].T : logEnd;
                    if (endT <= changes[k].T) continue;
                    r.States.Add(new StateInterval(name, changes[k].State, changes[k].T, endT));
                    total += (endT - changes[k].T).TotalSeconds;
                    if (changes[k].State == "Conectado") up += (endT - changes[k].T).TotalSeconds;
                }
                if (total > 0) r.Availability[name] = Math.Round(100 * up / total, 1);
            }
        }

        r.Apps.AddRange(_apps.Values.OrderByDescending(a => a.Total));
        if (_tac != null) Guard("sessões e capturas", _tac.AfterMetrics);
        foreach (var f in r.Findings.Where(f => f.SearchQuery.Length == 0)) f.SearchQuery = f.Title;
        r.Findings.Sort((a, b) => a.Severity != b.Severity ? a.Severity.CompareTo(b.Severity) : b.Count.CompareTo(a.Count));

        if (!r.HasTelemetry)
            r.DataGaps.Add("O pacote de logs da Netskope não traz séries contínuas de CPU, memória, disco, Wi-Fi e perda: os recursos da máquina aparecem só na foto do momento em que o usuário salvou os logs. Desempenho e causa raiz usam os sinais que o próprio cliente registra ao longo do tempo (aba Desempenho).");
        if (_rtt.Count == 0)
            r.DataGaps.Add("Os logs não trazem medições de latência até os POPs (seleção de gateway/GSLB) neste período.");
        if (!r.Snapshots.Any(sn => sn.Processes.Count > 0 || sn.Wifi != null))
            r.DataGaps.Add("O pacote não traz fotos instantâneas de processos ou Wi-Fi (ps aux, tasklist, netsh wlan, nmcli…).");

        Guard("baseline", () => Baseline.Compute(r));
        Guard("Experience Score", () => ExperienceScore.Compute(r));
        Guard("causa raiz", () => RootCause.Analyze(r));
        if (_tac != null) Guard("desempenho e resumo do caso", _tac.Finish);
        Guard("análise direcionada", () => FocusAnalyzer.Run(r, Options));
    }
}
