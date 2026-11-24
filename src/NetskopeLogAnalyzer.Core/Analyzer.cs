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
    }

    private AnalysisResult _r = new();
    private readonly Dictionary<string, RuleHits> _hits = new();
    private readonly Dictionary<string, UnclassifiedGroup> _unc = new();
    private readonly Dictionary<string, JsonElement> _json = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Finding> _extra = new();
    private string? _lastLocation;

    // ------------------------------------------------------------------ entrada

    public AnalysisResult AnalyzePaths(IEnumerable<string> paths, IProgress<string>? progress = null)
    {
        var items = new List<SourceItem>();
        var skipped = new List<string>();
        foreach (var p in paths)
        {
            if (Directory.Exists(p))
            {
                foreach (var f in Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories))
                    AddFile(f, Path.GetRelativePath(p, f), items, skipped, progress);
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
        var data = File.ReadAllBytes(path);
        if (IsZip(data)) ExtractZip(data, "", items, skipped);
        else items.Add(new SourceItem(name, data));
    }

    private static bool IsZip(byte[] d) => d.Length > 4 && d[0] == 0x50 && d[1] == 0x4B && (d[2] == 3 || d[2] == 5) && (d[3] == 4 || d[3] == 6);

    public static void ExtractZip(byte[] data, string prefix, List<SourceItem> items, List<string> skipped)
    {
        using var zip = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        foreach (var e in zip.Entries)
        {
            if (string.IsNullOrEmpty(e.Name)) continue; // pasta
            var full = prefix + e.FullName;
            try
            {
                using var s = e.Open();
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                var bytes = ms.ToArray();
                if (e.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && IsZip(bytes)) ExtractZip(bytes, full + "/", items, skipped);
                else items.Add(new SourceItem(full, bytes));
            }
            catch (Exception)
            {
                skipped.Add(full + " (não foi possível extrair)");
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
            if (SkipExt.IsMatch(baseName)) { _r.Skipped.Add(baseName); continue; }
            progress?.Report($"Analisando {baseName} ({n}/{items.Count})…");
            var text = Decode(it.Data);
            if (text is null) { _r.Skipped.Add(baseName); continue; }

            var fi = _r.Files.Count;
            _r.Files.Add(new LogFileInfo { Name = it.Name, Size = it.Data.Length });

            if (Regex.IsMatch(baseName, @"\.(json|conf|bak)$", RegexOptions.IgnoreCase)) ParseJson(baseName, text);
            if (baseName.Equals("install.log", StringComparison.OrdinalIgnoreCase)) ParseInstall(text);
            if (Regex.IsMatch(baseName, "network-state|ipconfig|netstat", RegexOptions.IgnoreCase)) ParseNetworkState(text, baseName);
            if (Regex.IsMatch(baseName, @"process|tasklist|ps[-_]?aux", RegexOptions.IgnoreCase)) ScanProcesses(text, baseName);
            if (baseName.StartsWith("appinfo", StringComparison.OrdinalIgnoreCase))
            {
                var apps = KnowledgeBase.Conflicts.Where(c => c.Re.IsMatch(text)).Select(c => c.Name).ToList();
                if (apps.Count > 0) _r.Facts.InstalledVpnApps = string.Join(", ", apps);
            }
            ParseLog(fi, text);
        }

        DeriveFacts();
        BuildFindings();
        _r.Events.Sort((a, b) => a.Time.CompareTo(b.Time));
        _r.Entries.Sort((a, b) => a.Time.CompareTo(b.Time));
        _r.Unclassified.AddRange(_unc.Values.OrderByDescending(u => u.Count));
        _r.DetectedOs = DetectOs();
        foreach (var f in _r.Findings)
        {
            f.Steps.AddRange(KnowledgeBase.BuildSteps(f, _r.DetectedOs, _r.Facts.TenantHost));
            f.References.AddRange(KnowledgeBase.ReferencesFor(f.Key));
            f.SearchQuery = KnowledgeBase.QueryFor(f.Key, f.Title);
        }
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
            DateTime time; LogLevel level; string src, msg;
            var a = LineA.Match(line);
            if (a.Success)
            {
                var lv = NormLevel(a.Groups[11].Value); if (lv is null) continue;
                time = MakeTime(a, 7); level = lv.Value; src = a.Groups[12].Value; msg = a.Groups[13].Value;
            }
            else if (line[0] == '[' && LineB.Match(line) is { Success: true } b)
            {
                var lv = NormLevel(b.Groups[9].Value); if (lv is null) continue;
                time = MakeTime(b, 7); level = lv.Value; src = b.Groups[10].Value; msg = b.Groups[11].Value;
            }
            else continue;
            if (time == DateTime.MinValue) continue;

            file.Lines++;
            if (file.First is null || time < file.First) file.First = time;
            if (file.Last is null || time > file.Last) file.Last = time;
            if (_r.Start is null || time < _r.Start) _r.Start = time;
            if (_r.End is null || time > _r.End) _r.End = time;
            if (level is LogLevel.Error or LogLevel.Critical) file.Errors++;
            else if (level == LogLevel.Warn) file.Warnings++;

            var entry = new LogEntry(fi, time, level, line, msg, src);
            _r.Entries.Add(entry);
            CollectEvents(entry, file.BaseName);
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
        else if (m.Contains("Log collection complete")) _r.Events.Add(new(e.Time, "Coleta de logs", EventKind.Info, "", file));
        else if (m.Contains("NPA Tunnel Status:"))
        {
            var x = NpaStatusRe.Match(m); if (x.Success) F.NpaLast = x.Groups[2].Value;
        }

        if (m.Contains("egress_ip")) { var x = EgressRe.Match(m); if (x.Success) F.Egress = x.Groups[1].Value; }
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
            _r.Findings.Add(f);
        }
        _r.Findings.AddRange(_extra);
        _r.Findings.Sort((a, b) => a.Severity != b.Severity ? a.Severity.CompareTo(b.Severity) : b.Count.CompareTo(a.Count));
    }
}
