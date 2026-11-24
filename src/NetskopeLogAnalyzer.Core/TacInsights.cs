using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Análises no estilo do suporte/TAC da Netskope, feitas só com o pacote de logs:
/// sessões do Private Access (motivo de cada queda, reautenticação, POP escolhido), saúde do túnel NPA
/// (RTT e retransmissões), mudanças de rede em excesso e sua origem (Docker/VMs/VPNs), DNS (sufixo de
/// pesquisa indevido, NXDOMAIN, DNS por interface), redes locais sobrepostas às rotas do NPA, agentes
/// que consomem CPU, configuração efetiva, cobertura de cada log, métricas de desempenho da máquina
/// derivadas dos logs e o roteiro de perguntas do TAC respondido automaticamente.
/// </summary>
public sealed class TacInsights
{
    private const RegexOptions Opt = RegexOptions.Compiled | RegexOptions.CultureInvariant;
    private static readonly CultureInfo CI = CultureInfo.InvariantCulture;

    private static readonly Regex NpaGwStatRe = new(@"NPAGW ([\d.]+): RETRANS:(\d+), RTT:(\d+)ms", Opt);
    private static readonly Regex NpaStartRe = new(@"Starting handler with GW \S+ \(([\d.]+):\d+, pop:([^,]+), type", Opt);
    private static readonly Regex NpaGwListRe = new(@"GW FQDN = \S+, IP = ([\d.]+), POP = ([^,]+), RTT = (\d+) ms", Opt);
    private static readonly Regex NpaTlsRe = new(@"TLS client established connection .*server:([\d.]+):\d+", Opt);
    private static readonly Regex NpaShutdownRe = new(@"Shutdown packet received from gateway\. Reason = \[([^\]]+)", Opt);
    private static readonly Regex NpaKeepAliveRe = new(@"keepAlive fails with (\d+) tries", Opt);
    private static readonly Regex NpaDnsStatRe = new(@"PubDns Req = (\d+), .*?PubDns Resp = (\d+) \[NOERROR:(\d+), FORMERR:(\d+), SERVFAIL:(\d+), NXDOMAIN:(\d+)", Opt);
    private static readonly Regex DnsNameRe = new(@"name = ([A-Za-z0-9._-]+)", Opt);
    private static readonly Regex NetChangeRe = new(@"network status changed|Network status changed|network change detected|Network change detected|NetworkChange event", Opt);
    private static readonly Regex StallRe = new(@"cannot be completed within \d+ ms", Opt);
    private static readonly Regex LeakRe = new(@"^(?<fq>(?:[a-z0-9-]+\.)+(?:com|net|org|io|gov|edu|internal|cloud|app|dev|ai|co|ms|us|eu|br))\.(?<suf>[a-z0-9-]+(?:\.[a-z0-9-]+)+)$", Opt | RegexOptions.IgnoreCase);
    private static readonly Regex SecurityAgentRe = new(@"falcon|CSFalcon|mdatp|wdavdaemon|MsMpEng|MpDefender|SentinelAgent|sentinel|cbagentd|cbdaemon|RepMgr|ds_agent|xagt|cylance|sophos|savd|SophosScan|elastic-endpoint|elastic-agent|esets|ekrn|bdsec|kesl|avp\b|clamd|tanium|qualys|osqueryd|wazuh|ossec|trend|ntrtscan|PccNT|mcafee|masvc|mfetp|cyserver|traps|cortex|harmony|checkpoint|forti(edr|esnac)", Opt | RegexOptions.IgnoreCase);
    private static readonly Regex NetskopeProcRe = new(@"^(stAgent|nsdiag|stAgentSvc|stAgentApp|stAgentUI|nsAuxSvc|npa|Netskope)", Opt | RegexOptions.IgnoreCase);

    private readonly AnalysisResult _r;
    private readonly IReadOnlyDictionary<string, string> _texts;
    private readonly IReadOnlyDictionary<string, JsonElement> _json;

    private readonly List<(DateTime T, string Ip, double Rtt, long Retrans)> _gw = new();
    private readonly Dictionary<string, string> _gwPop = new();
    private readonly List<DateTime> _netChanges = new(), _stalls = new();
    private readonly List<(DateTime Start, DateTime End)> _gaps = new();
    private readonly Dictionary<string, int> _dnsNames = new(StringComparer.OrdinalIgnoreCase);
    private DateTime? _npaFirst, _npaLast, _svcFirst, _svcLast;
    private readonly List<double> _schedDelays = new();

    public TacInsights(AnalysisResult r, IReadOnlyDictionary<string, string> texts, IReadOnlyDictionary<string, JsonElement> json)
    {
        _r = r; _texts = texts; _json = json;
    }

    private string FileOf(LogEntry e) => _r.Files[e.FileIndex].BaseName;
    private static bool IsNpaFile(string n) => n.StartsWith("npadebuglog", StringComparison.OrdinalIgnoreCase);
    private static bool IsSvcFile(string n) => n.StartsWith("nsdebuglog", StringComparison.OrdinalIgnoreCase);
    private ClientOs Os => _r.DetectedOs ?? ClientOs.Linux;

    // =====================================================================================================
    // Fase 1 — logo após a leitura (antes das métricas, estados e score)
    // =====================================================================================================

    public void Run()
    {
        Coverage();
        ScanEntries();
        ActivityGaps();
        NetworkChurn();
        DnsInterfaces();
        DnsSuffixLeak();
        Overlaps();
        Processes();
        Config();
        ComponentBreakdown();
        Noise();
        AddSeries();
    }

    private void Coverage()
    {
        static string Family(string n)
        {
            n = n.ToLowerInvariant();
            if (n.StartsWith("nsdebuglog")) return "Serviço (nsdebuglog — túnel Internet, GSLB, steering)";
            if (n.StartsWith("npadebuglog")) return "Private Access (npadebuglog)";
            if (n.StartsWith("nsappui")) return "Interface do usuário (nsAppUI)";
            if (n.StartsWith("nsapp")) return "Aplicativo do usuário (nsApp)";
            if (n.StartsWith("nsdiag")) return "Diagnóstico (nsDiag)";
            if (n.StartsWith("nsinstallation") || n == "install.log") return "Instalação";
            if (n.StartsWith("nla-telemetry")) return "Telemetria do coletor";
            return "Outros";
        }
        foreach (var g in _r.Files.Where(f => f.First != null && f.Last != null && f.Lines > 0).GroupBy(f => Family(f.BaseName)))
        {
            _r.Coverage.Add(new SourceCoverage(g.Key, string.Join(", ", g.Select(f => f.BaseName).OrderBy(x => x)), g.Min(f => f.First!.Value), g.Max(f => f.Last!.Value), g.Sum(f => f.Lines)));
        }
        _r.Coverage.Sort((a, b) => b.Span.CompareTo(a.Span));
        var svc = _r.Coverage.FirstOrDefault(c => c.Source.StartsWith("Serviço", StringComparison.Ordinal));
        var npa = _r.Coverage.FirstOrDefault(c => c.Source.StartsWith("Private Access", StringComparison.Ordinal));
        if (svc != null) { _svcFirst = svc.First; _svcLast = svc.Last; }
        if (npa != null) { _npaFirst = npa.First; _npaLast = npa.Last; }
        if (svc != null && npa != null)
        {
            var big = svc.Span > npa.Span ? svc : npa; var small = svc.Span > npa.Span ? npa : svc;
            if (big.Span.TotalHours >= 24 && small.Span.TotalHours * 4 < big.Span.TotalHours)
                _r.DataGaps.Add($"Cobertura desigual: {big.Source} cobre {TelemetryParser.Fmt(big.Span)} ({big.First:dd/MM HH:mm} a {big.Last:dd/MM HH:mm}), mas {small.Source} cobre só {TelemetryParser.Fmt(small.Span)} ({small.First:dd/MM HH:mm} a {small.Last:dd/MM HH:mm}). Conclusões sobre esse serviço valem apenas para esse período — os logs giram por tamanho, então colete o pacote logo depois do problema.");
        }
    }

    private void ScanEntries()
    {
        DateTime lastChange = DateTime.MinValue;
        foreach (var e in _r.Entries)
        {
            var m = e.Message;
            if (m.Contains("NPAGW ", StringComparison.Ordinal))
            {
                var x = NpaGwStatRe.Match(m);
                if (x.Success) _gw.Add((e.Time, x.Groups[1].Value, D(x.Groups[3].Value), long.Parse(x.Groups[2].Value, CI)));
                continue;
            }
            if (m.Contains("PubDns Req", StringComparison.Ordinal))
            {
                var x = NpaDnsStatRe.Match(m);
                if (x.Success)
                {
                    var resp = D(x.Groups[2].Value); var nx = D(x.Groups[6].Value);
                    var s = _r.GetOrAddSeries("npa.dns.nxdomain", () => MetricCatalog.Create("npa.dns.nxdomain", "Logs Netskope"));
                    if (resp > 0 && (s.Points.Count == 0 || (e.Time - s.Points[^1].Time).TotalSeconds > 5))
                        s.Points.Add(new MetricPoint(e.Time, Math.Round(100 * nx / resp, 1)));
                }
                continue;
            }
            if (m.Contains("name = ", StringComparison.Ordinal) && _dnsNames.Count < 200000)
            {
                var x = DnsNameRe.Match(m);
                if (x.Success) { var n = x.Groups[1].Value.TrimEnd('.'); _dnsNames[n] = _dnsNames.GetValueOrDefault(n) + 1; }
            }
            if (NetChangeRe.IsMatch(m))
            {
                if ((e.Time - lastChange).TotalSeconds > 2) _netChanges.Add(e.Time);
                lastChange = e.Time;
                continue;
            }
            if (StallRe.IsMatch(m)) _stalls.Add(e.Time);
            if (m.Contains("GW FQDN = ", StringComparison.Ordinal))
            {
                var x = NpaGwListRe.Match(m);
                if (x.Success) _gwPop[x.Groups[1].Value] = x.Groups[2].Value.Trim();
            }
        }
    }

    private static double D(string s) => double.Parse(s, NumberStyles.Float, CI);

    // ---------------------------------------------------------------- períodos sem atividade (suspensão)

    private void ActivityGaps()
    {
        var from = new[] { _svcFirst, _npaFirst }.Where(x => x != null).Select(x => x!.Value).DefaultIfEmpty(DateTime.MaxValue).Min();
        if (from == DateTime.MaxValue || _r.End is null) return;
        var threshold = TimeSpan.FromMinutes(15);
        DateTime? prev = null;
        foreach (var e in _r.Entries)
        {
            if (e.Time < from) continue;
            if (prev is DateTime p && e.Time - p >= threshold) _gaps.Add((p, e.Time));
            prev = e.Time;
        }
        foreach (var (a, b) in _gaps)
            _r.Events.Add(new TimelineEvent(a, "Suspensão", EventKind.Info, $"nenhum log de {a:dd/MM HH:mm} a {b:dd/MM HH:mm} ({TelemetryParser.Fmt(b - a)}) — máquina suspensa, desligada ou sem o serviço", "logs"));
    }

    // ---------------------------------------------------------------- mudanças de rede em excesso

    private sealed record IfAddr(int Index, string Name, string Flags, List<(IPAddress Ip, int Prefix)> V4);

    private List<IfAddr> Interfaces()
    {
        var list = new List<IfAddr>();
        foreach (var (name, text) in _texts)
        {
            IfAddr? cur = null;
            foreach (var raw in text.Split('\n'))
            {
                var ln = raw.TrimEnd('\r');
                var h = Regex.Match(ln, @"^(\d+): ([^:@\s]+)(?:@\S+)?: <([^>]*)>");
                if (h.Success)
                {
                    cur = new IfAddr(int.Parse(h.Groups[1].Value, CI), h.Groups[2].Value, h.Groups[3].Value, new());
                    if (!list.Any(i => i.Name == cur.Name)) list.Add(cur); else cur = null;
                    continue;
                }
                if (ln.StartsWith("$ ", StringComparison.Ordinal)) { cur = null; continue; }
                var a = Regex.Match(ln, @"^\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)");
                if (a.Success && cur != null && IPAddress.TryParse(a.Groups[1].Value, out var ip)) cur.V4.Add((ip, int.Parse(a.Groups[2].Value, CI)));
            }
            if (list.Count > 0) break;
        }
        return list;
    }

    private string? PsText() => _texts.Values.Select(t => Regex.Match(t, @"^\s*USER\s+PID\s+%CPU[^\n]*\n([\s\S]*?)(?=\n\$ |\z)", RegexOptions.Multiline)).FirstOrDefault(m => m.Success)?.Groups[1].Value;

    private void NetworkChurn()
    {
        if (_netChanges.Count < 20) return;
        var from = _netChanges[0]; var to = _netChanges[^1];
        var hours = Math.Max(1.0 / 6, ((_svcLast ?? to) - (_svcFirst ?? from)).TotalHours);
        var perHour = _netChanges.Count / hours;
        if (perHour < 6) return;

        var ifs = Interfaces();
        var causes = new List<string>();
        var steps = new List<FixStep>();
        var veth = ifs.Count(i => i.Name.StartsWith("veth", StringComparison.Ordinal));
        var maxIdx = ifs.Count > 0 ? ifs.Max(i => i.Index) : 0;
        var ps = PsText() ?? "";
        var docker = ifs.Any(i => i.Name == "docker0" || i.Name.StartsWith("br-", StringComparison.Ordinal)) || ps.Contains("dockerd", StringComparison.Ordinal);
        var podman = ps.Contains("podman", StringComparison.Ordinal);
        var vms = ifs.Where(i => Regex.IsMatch(i.Name, "^(virbr|vnet|vmnet|vboxnet|tap)")).Select(i => i.Name).ToList();
        var vpn = ifs.Where(i => KnowledgeBase.VpnInterface.IsMatch(i.Name)).Select(i => i.Name).ToList();
        if (maxIdx > 0 && maxIdx - ifs.Count > 30)
            causes.Add($"o número de índice das interfaces chegou a {maxIdx} com só {ifs.Count} interfaces existentes — cerca de {maxIdx - ifs.Count} interfaces foram criadas e removidas desde o boot");
        if (docker)
        {
            var shims = Regex.Matches(ps, @"^\S+\s+\d+\s+\S+\s+\S+\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S*containerd-shim", RegexOptions.Multiline).Select(m => m.Groups[1].Value).ToList();
            var distinct = shims.Distinct().ToList();
            var ports = Regex.Matches(ps, @"docker-proxy .*?-host-port (\d+)").Select(m => m.Groups[1].Value).Distinct().ToList();
            var txt = $"Docker em execução ({veth} interface(s) veth ativas" + (ports.Count > 0 ? $", portas publicadas {string.Join(", ", ports.Take(8))}" : "") + ")";
            if (distinct.Count > 1)
                txt += $"; containers iniciados em horários diferentes ({string.Join(", ", distinct)}) — o mais recente às {distinct.Max()} indica container recriado depois do boot";
            causes.Add(txt + ". Cada vez que um container sobe ou cai, o Docker cria/remove uma interface veth e o Netskope trata isso como mudança de rede");
            steps.Add(new("Veja se algum container está reiniciando em loop (Status “Restarting” ou “Up X segundos”):", "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.RunningFor}}'"));
            steps.Add(new("Conte os reinícios de cada container:", "docker inspect -f '{{.Name}} reinícios={{.RestartCount}}' $(docker ps -aq)"));
            steps.Add(new("Veja os eventos dos últimos 30 minutos:", "docker events --since 30m --until 0s --filter type=container"));
            steps.Add(new("Descubra por que o container cai e corrija; enquanto isso, desligue o reinício automático dele:", "docker logs --tail 50 <container>\ndocker update --restart=no <container>"));
        }
        if (podman) causes.Add("Podman em execução (containers também criam interfaces virtuais)");
        if (vms.Count > 0) causes.Add($"interfaces de máquinas virtuais: {string.Join(", ", vms.Take(6))}");
        if (vpn.Count > 0) causes.Add($"interfaces de VPN de terceiros: {string.Join(", ", vpn.Take(6))}");
        if (Os == ClientOs.Linux)
            steps.Add(new("Para ver ao vivo qual interface sobe/desce (deixe rodando alguns minutos):", "ip -o monitor link"));
        else if (Os == ClientOs.Windows)
            steps.Add(new("Liste adaptadores e veja quais aparecem/desaparecem (Hyper-V, WSL, Docker Desktop, VPNs):", "Get-NetAdapter -IncludeHidden | Sort-Object ifIndex | Format-Table ifIndex,Name,Status,InterfaceDescription"));
        else
            steps.Add(new("Liste as interfaces e veja quais aparecem/desaparecem:", "ifconfig -l; scutil --nwi"));
        steps.Add(new("Depois da correção, confirme no próximo pacote de logs que “network status changed” voltou a aparecer só quando você troca de rede de verdade."));

        var routeHits = _r.Findings.FirstOrDefault(f => f.Key == "route")?.Count ?? 0;
        var gslbFetch = _r.Entries.Count(e => e.Message.Contains("Pops fetched begin", StringComparison.Ordinal));
        var f = new Finding
        {
            Key = "netchurn", Severity = perHour >= 30 ? Severity.Critical : Severity.Warning, Category = "Rede",
            Title = $"Mudanças de rede em excesso: {_netChanges.Count} em {TelemetryParser.Fmt(TimeSpan.FromHours(hours))} (~{perHour:0} por hora)",
            Meaning = "O cliente detectou mudança de rede o tempo todo, sem troca real de rede. A cada mudança ele refaz a seleção de POP (GSLB), a detecção on-prem/off-prem e recalcula rotas" +
                      (gslbFetch > 0 ? $" — foram {gslbFetch} consultas ao GSLB" : "") + (routeHits > 0 ? $" e {routeHits} erros de consulta de rota (ipRouteGet)" : "") +
                      ". Isso aumenta a chance de timeouts, troca de POP e quedas curtas." + (causes.Count > 0 ? " Origem provável: " + string.Join("; ", causes) + "." : ""),
            Action = "Encontre e estabilize a interface virtual que fica subindo e descendo.",
            Count = _netChanges.Count, First = from, Last = to,
        };
        f.Times.AddRange(_netChanges.Take(20000));
        foreach (var g in _netChanges.GroupBy(t => new DateTime(t.Year, t.Month, t.Day, t.Hour, 0, 0)).OrderByDescending(g => g.Count()).Take(6))
            f.Details.Add(new($"{g.Key:dd/MM HH}h", g.Count()));
        f.Samples.AddRange(_r.Entries.Where(e => NetChangeRe.IsMatch(e.Message)).Take(3).Select(e => FileOf(e) + ": " + e.Line));
        f.Files.Add("nsdebuglog");
        f.Steps.AddRange(steps);
        f.SearchQuery = "network status changed GSLB egress IP refresh";
        _r.Findings.Add(f);
    }

    // ---------------------------------------------------------------- DNS por interface e sufixo indevido

    private void DnsInterfaces()
    {
        var ifs = Interfaces().ToDictionary(i => i.Name, i => i);
        foreach (var text in _texts.Values)
        {
            if (!text.Contains("GENERAL.DEVICE", StringComparison.Ordinal)) continue;
            string? dev = null, state = null; var servers = new List<string>(); var search = new List<string>();
            void Flush()
            {
                if (dev is null || (servers.Count == 0 && search.Count == 0)) return;
                var note = "";
                if (KnowledgeBase.VpnInterface.IsMatch(dev))
                    note = ifs.TryGetValue(dev, out var i) && i.Flags.Contains("NO-CARRIER") ? "VPN de terceiros sem link — DNS e domínio herdados continuam ativos" : "VPN de terceiros";
                _r.DnsInterfaces.Add(new InterfaceDns(dev, state ?? "", servers.ToList(), search.ToList(), note));
            }
            foreach (var raw in text.Split('\n'))
            {
                var ln = raw.TrimEnd('\r');
                var d = Regex.Match(ln, @"^GENERAL\.DEVICE:\s+(\S+)");
                if (d.Success) { Flush(); dev = d.Groups[1].Value; state = null; servers.Clear(); search.Clear(); continue; }
                var st = Regex.Match(ln, @"^GENERAL\.STATE:\s+(.+)$"); if (st.Success) state = st.Groups[1].Value.Trim();
                var s = Regex.Match(ln, @"^IP[46]\.DNS\[\d+\]:\s+(\S+)"); if (s.Success) servers.Add(s.Groups[1].Value);
                var q = Regex.Match(ln, @"^IP[46]\.(?:SEARCHES|DOMAIN)\[\d+\]:\s+(\S+)"); if (q.Success && !search.Contains(q.Groups[1].Value)) search.Add(q.Groups[1].Value);
            }
            Flush();
            break;
        }
        foreach (var text in _texts.Values)
        {
            var rc = Regex.Matches(text, @"^(?:search|domain)\s+(.+)$", RegexOptions.Multiline);
            var ns = Regex.Matches(text, @"^nameserver\s+(\S+)", RegexOptions.Multiline);
            if (ns.Count > 0 && !_r.DnsInterfaces.Any(x => x.Interface == "resolv.conf"))
                _r.DnsInterfaces.Add(new InterfaceDns("resolv.conf", "sistema", ns.Select(m => m.Groups[1].Value).ToList(), rc.SelectMany(m => m.Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToList(), ""));
        }
    }

    private void DnsSuffixLeak()
    {
        var bySuffix = new Dictionary<string, (int Count, HashSet<string> Names)>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, n) in _dnsNames)
        {
            var m = LeakRe.Match(name);
            if (!m.Success) continue;
            var fq = m.Groups["fq"].Value; var suf = m.Groups["suf"].Value;
            if (fq.Count(c => c == '.') < 1) continue;
            if (!bySuffix.TryGetValue(suf, out var v)) v = (0, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
            v.Count += n; v.Names.Add(fq);
            bySuffix[suf] = v;
        }
        var leaks = bySuffix.Where(kv => kv.Value.Count >= 20 && kv.Value.Names.Count >= 3).OrderByDescending(kv => kv.Value.Count).ToList();
        if (leaks.Count == 0) return;
        var total = leaks.Sum(kv => kv.Value.Count);
        var carriers = _r.DnsInterfaces.Where(i => i.Search.Count > 0).ToList();
        var vpnCarriers = carriers.Where(i => KnowledgeBase.VpnInterface.IsMatch(i.Interface)).ToList();
        var nx = _r.Series.TryGetValue("npa.dns.nxdomain", out var nxs) && nxs.Points.Count > 0 ? nxs.Points.Average(p => p.Value) : (double?)null;
        var examples = leaks.SelectMany(kv => kv.Value.Names.Take(3).Select(n => n + "." + kv.Key)).Take(5).ToList();
        var f = new Finding
        {
            Key = "dnssuffix", Severity = total >= 500 ? Severity.Warning : Severity.Info, Category = "DNS",
            Title = $"Domínio de pesquisa DNS sendo anexado a nomes públicos ({total:N0} consultas)",
            Meaning = $"Nomes que já são completos estão sendo consultados de novo com o sufixo {string.Join(", ", leaks.Select(kv => kv.Key).Take(4))} (ex.: {string.Join(", ", examples.Take(3))}). " +
                      "Essas consultas extras vão para o DNS interno (pelo Private Access, quando o DNS privado está ativo), quase sempre voltam NXDOMAIN e atrasam a resolução — inclusive dos próprios domínios da Netskope." +
                      (nx is double x ? $" Em média {x:0}% das respostas de DNS pelo túnel foram NXDOMAIN." : "") +
                      (carriers.Count > 0 ? $" Domínios de pesquisa configurados: {string.Join("; ", carriers.Select(c => $"{c.Interface} → {string.Join(", ", c.Search)}"))}." : "") +
                      (vpnCarriers.Count > 0 ? $" {vpnCarriers.Count} deles vêm de interfaces de VPN de terceiros." : ""),
            Action = "Remova domínios de pesquisa herdados de VPNs antigas e mantenha só os domínios internos realmente usados.",
            Count = total,
        };
        foreach (var kv in leaks.Take(6)) f.Details.Add(new($"sufixo {kv.Key}", kv.Value.Count));
        f.Samples.AddRange(examples.Select(e => "consulta: " + e));
        if (Os == ClientOs.Windows)
        {
            f.Steps.Add(new("Veja a lista de sufixos de pesquisa e de qual adaptador cada um vem:", "ipconfig /all | findstr /i \"Sufixo Suffix Adaptador adapter\""));
            f.Steps.Add(new("Remova sufixos globais que vieram de outra VPN (ajuste a lista para os domínios corretos):", "Get-DnsClientGlobalSetting\nSet-DnsClientGlobalSetting -SuffixSearchList @()"));
            f.Steps.Add(new("Limpe o cache:", "ipconfig /flushdns"));
        }
        else if (Os == ClientOs.Mac)
        {
            f.Steps.Add(new("Veja os domínios de pesquisa por resolvedor:", "scutil --dns | grep -E 'search domain|nameserver|if_index'"));
            f.Steps.Add(new("Remova os domínios herdados no serviço de rede (ou desinstale a VPN antiga):", "networksetup -setsearchdomains Wi-Fi Empty"));
        }
        else
        {
            f.Steps.Add(new("Veja DNS e domínio de pesquisa por interface:", "resolvectl status"));
            f.Steps.Add(new("Liste as conexões do NetworkManager (as de VPN antiga costumam ter o nome da interface):", "nmcli -f NAME,TYPE,DEVICE,STATE connection show"));
            if (vpnCarriers.Count > 0)
                f.Steps.Add(new("Remova as conexões das interfaces de VPN que ficaram para trás:", string.Join("\n", vpnCarriers.Select(c => $"sudo nmcli connection delete {c.Interface}"))));
            f.Steps.Add(new("Ou retire só o domínio de pesquisa de uma interface:", "sudo resolvectl domain <interface> \"\""));
            f.Steps.Add(new("Limpe o cache e teste um nome público (não deve aparecer consulta com o sufixo):", "sudo resolvectl flush-caches\nresolvectl query gateway.gslb.goskope.com"));
        }
        f.Steps.Add(new("Se o sufixo vier da configuração de DNS do Private Access no tenant, restrinja-o aos domínios internos realmente usados pelas aplicações privadas."));
        f.SearchQuery = "Netskope private access DNS search domain suffix NXDOMAIN";
        _r.Findings.Add(f);
    }

    // ---------------------------------------------------------------- sobreposição de redes locais com rotas do NPA

    private static (uint Net, uint Mask) Cidr(IPAddress ip, int prefix)
    {
        var b = ip.GetAddressBytes();
        var v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (v & mask, mask);
    }

    private static bool Overlap((uint Net, uint Mask) a, (uint Net, uint Mask) b)
    {
        var m = a.Mask & b.Mask; // a sobreposição usa o prefixo menor (mais abrangente)
        return (a.Net & m) == (b.Net & m);
    }

    private void Overlaps()
    {
        var routes = new List<(string Cidr, (uint, uint) Range, string Dev)>();
        foreach (var text in _texts.Values)
        {
            var sec = Regex.Match(text, @"\$ [^\n]*route show table \d+[^\n]*\n([\s\S]*?)(?=\n\$ |\z)");
            if (!sec.Success) continue;
            foreach (Match m in Regex.Matches(sec.Groups[1].Value, @"^(\d+\.\d+\.\d+\.\d+)(?:/(\d+))? dev (\S+)", RegexOptions.Multiline))
            {
                if (!IPAddress.TryParse(m.Groups[1].Value, out var ip)) continue;
                var pre = m.Groups[2].Success ? int.Parse(m.Groups[2].Value, CI) : 32;
                routes.Add((m.Groups[1].Value + "/" + pre, Cidr(ip, pre), m.Groups[3].Value));
            }
            break;
        }
        if (routes.Count == 0) return;
        var npaDev = routes.GroupBy(x => x.Dev).OrderByDescending(g => g.Count()).First().Key;
        var hits = new List<(string If, string Local, string Route, string Kind)>();
        foreach (var i in Interfaces())
        {
            if (i.Name == "lo" || i.Name == npaDev) continue;
            foreach (var (ip, pre) in i.V4)
            {
                if (ip.ToString().StartsWith("169.254.", StringComparison.Ordinal) || ip.ToString().StartsWith("127.", StringComparison.Ordinal)) continue;
                var local = Cidr(ip, pre);
                var r = routes.Where(x => x.Dev == npaDev && Overlap(local, x.Range)).OrderByDescending(x => x.Range.Item2).FirstOrDefault();
                if (r.Cidr is null) continue;
                var kind = Regex.IsMatch(i.Name, "^(docker|br-|veth|cni|podman|virbr|vmnet|vboxnet)") ? "containers/VMs"
                    : KnowledgeBase.VpnInterface.IsMatch(i.Name) ? "VPN de terceiros"
                    : "rede local (LAN/Wi-Fi)";
                hits.Add((i.Name, $"{ip}/{pre}", r.Cidr, kind));
            }
        }
        if (hits.Count == 0) return;
        var lan = hits.Any(h => h.Kind.StartsWith("rede local", StringComparison.Ordinal));
        var f = new Finding
        {
            Key = "overlap", Severity = lan ? Severity.Critical : Severity.Warning, Category = "Rede",
            Title = $"Redes locais sobrepostas às rotas do Private Access ({hits.Count})",
            Meaning = "Faixas usadas por interfaces desta máquina coincidem com rotas que o Private Access envia pelo túnel (" + npaDev + "). " +
                      "Aplicações privadas nessas faixas podem ficar inacessíveis (o tráfego sai pela interface local) ou o acesso à rede local pode quebrar. " +
                      string.Join(" ", hits.GroupBy(h => h.Kind).Select(g => $"{g.Key}: {string.Join(", ", g.Take(4).Select(h => $"{h.If} {h.Local} ⊂ {h.Route}"))}{(g.Count() > 4 ? "…" : "")}.")),
            Action = "Mude a faixa local que conflita ou remova a interface que sobrou.",
            Count = hits.Count,
        };
        foreach (var h in hits.Take(12)) f.Samples.Add($"{h.If} {h.Local} sobrepõe a rota NPA {h.Route} ({h.Kind})");
        if (hits.Any(h => h.Kind == "containers/VMs"))
        {
            f.Steps.Add(new("Docker: mova as redes padrão para uma faixa que não seja usada por aplicações privadas. Em /etc/docker/daemon.json (ajuste as faixas):",
                "{\n  \"bip\": \"192.168.200.1/24\",\n  \"default-address-pools\": [ { \"base\": \"192.168.208.0/20\", \"size\": 24 } ]\n}"));
            f.Steps.Add(new("Aplique e recrie as redes dos projetos (docker compose down/up):", "sudo systemctl restart docker\ndocker network ls\ndocker network prune"));
        }
        if (hits.Any(h => h.Kind == "VPN de terceiros"))
            f.Steps.Add(new("Remova as interfaces de VPN de terceiros que ficaram configuradas (ou desinstale a VPN antiga):", string.Join("\n", hits.Where(h => h.Kind == "VPN de terceiros").Select(h => h.If).Distinct().Select(n => "sudo ip link delete " + n))));
        if (lan)
            f.Steps.Add(new("A rede local (casa/hotel) usa a mesma faixa de uma aplicação privada: troque a faixa do DHCP do roteador local ou publique a aplicação por nome em vez de faixa de IP."));
        f.Steps.Add(new("Confira as rotas que o Private Access instala:", Os == ClientOs.Linux ? "ip route show table 9" : Os == ClientOs.Windows ? "route print" : "netstat -rn"));
        f.SearchQuery = "Netskope private access overlapping subnet docker";
        _r.Findings.Add(f);
    }

    // ---------------------------------------------------------------- processos pesados / agentes de segurança

    private void Processes()
    {
        var snap = _r.Snapshots.Where(s => !s.Source.Contains("coletor", StringComparison.OrdinalIgnoreCase) && s.Processes.Any(p => p.CpuPct > 0)).OrderByDescending(s => s.Processes.Count).FirstOrDefault();
        if (snap is null) return;
        var heavy = snap.Processes.Where(p => p.CpuPct >= 25 && !NetskopeProcRe.IsMatch(p.Name)).OrderByDescending(p => p.CpuPct).Take(6).ToList();
        if (heavy.Count == 0) return;
        var agents = heavy.Where(p => SecurityAgentRe.IsMatch(p.Name)).ToList();
        var worst = heavy[0].CpuPct;
        var f = new Finding
        {
            Key = "heavyproc", Severity = worst >= 80 ? Severity.Warning : Severity.Info, Category = "Dispositivo",
            Title = agents.Count > 0 ? $"Agente de segurança com uso contínuo de CPU: {agents[0].Name} ({agents[0].CpuPct:0.#}% de um núcleo)" : $"Processo com uso contínuo de CPU: {heavy[0].Name} ({worst:0.#}% de um núcleo)",
            Meaning = "Na foto de processos do pacote (" + snap.Source + "), estes processos têm alto uso médio de CPU desde que iniciaram: " +
                      string.Join(", ", heavy.Select(p => $"{p.Name} {p.CpuPct:0.#}%")) + ". O valor do ps é a média desde o início do processo, em % de UM núcleo (100% = um núcleo inteiro). " +
                      (agents.Count > 0 ? "Agentes de EDR/antivírus inspecionam a mesma conexão que o Netskope; sem exclusões mútuas eles disputam CPU e podem atrasar handshakes e o túnel." : "Isso reduz a folga de CPU para o túnel e para as aplicações."),
            Action = "Confirme o consumo ao vivo e configure exclusões mútuas entre o agente e o Netskope.",
            Count = heavy.Count,
        };
        foreach (var p in heavy) f.Details.Add(new(p.Name, (int)Math.Round(p.CpuPct)));
        if (Os == ClientOs.Windows)
            f.Steps.Add(new("Confirme o consumo ao vivo:", "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name,CPU,WorkingSet"));
        else
        {
            f.Steps.Add(new("Confirme o consumo ao vivo (amostras de 5 s):", "top -b -n 3 -d 5 -o %CPU | head -25"));
            f.Steps.Add(new("Se tiver o sysstat, veja por processo ao longo de 1 minuto:", "pidstat -u 5 12"));
        }
        if (agents.Any(a => a.Name.Contains("falcon", StringComparison.OrdinalIgnoreCase)))
            f.Steps.Add(new("CrowdStrike: confira se o sensor está em modo de funcionalidade reduzida (RFM costuma aumentar o consumo após atualização de kernel):", "sudo /opt/CrowdStrike/falconctl -g --rfm-state --version"));
        if (agents.Count > 0)
        {
            f.Steps.Add(new("No console do EDR/antivírus, exclua os processos e a pasta do Netskope Client da inspeção (Linux: /opt/netskope/stagent/; Windows: C:\\Program Files\\Netskope\\STAgent\\; macOS: /Library/Application Support/Netskope/STAgent/)."));
            f.Steps.Add(new("No Netskope, coloque os domínios de nuvem do agente de segurança em exceção (Steering > Exceptions) para o agente não ser inspecionado."));
        }
        f.SearchQuery = "Netskope client EDR exclusions high CPU";
        _r.Findings.Add(f);
    }

    // ---------------------------------------------------------------- configuração efetiva

    private static string? Get(JsonElement e, params string[] path)
    {
        foreach (var p in path)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(p, out e)) return null;
        }
        return e.ValueKind switch
        {
            JsonValueKind.String => e.GetString(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => e.GetRawText(),
            JsonValueKind.Array => string.Join(", ", e.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() : x.GetRawText())),
            _ => null,
        };
    }

    private static bool True(string? v) => v is "true" or "1" or "True";

    private void Cfg(string section, string item, string? value, string meaning, bool attention = false)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        _r.Config.Add(new ConfigItem(section, item, value, meaning, attention));
    }

    private void Config()
    {
        var F = _r.Facts;
        if (_json.TryGetValue("nsconfig.json", out var c) || _json.TryGetValue("nsconfig.json.bak", out c))
        {
            const string S = "Cliente";
            Cfg(S, "Configuração do cliente", Get(c, "clientConfig", "configurationName"), "Perfil de configuração aplicado a este usuário/dispositivo no tenant.");
            var ver = Get(c, "cache", "lastClientConfigVersion");
            Cfg(S, "Versão da configuração", ver, "Quando a configuração foi publicada no tenant. Se mudou perto do problema, compare o que foi alterado.");
            var upd = Get(c, "cache", "configUpdateTimestamp");
            if (long.TryParse(upd, out var ut) && ut > 1_000_000_000) Cfg(S, "Última atualização de configuração no dispositivo", DateTimeOffset.FromUnixTimeSeconds(ut).LocalDateTime.ToString("dd/MM/yyyy HH:mm", CI), "Momento em que o dispositivo baixou a configuração pela última vez.");
            Cfg(S, "Usuário da configuração", Get(c, "cache", "lastClientConfigUserEmail"), "Usuário com quem o cliente está registrado.");
            var dis = Get(c, "clientConfig", "allowClientDisabling");
            Cfg(S, "Usuário pode desabilitar o cliente", Bool(dis), True(dis) ? "O usuário pode desligar o Netskope pela bandeja — verifique eventos “desabilitado pelo usuário”." : "O usuário não consegue desligar o cliente.", True(dis));
            var npaDis = Get(c, "clientConfig", "npa_client_allow_disable");
            Cfg(S, "Usuário pode desabilitar o Private Access", Bool(npaDis), True(npaDis) ? "O usuário pode desligar só o NPA." : "O NPA não pode ser desligado pelo usuário.", True(npaDis));
            var prot = Get(c, "clientConfig", "enableClientSelfProtection");
            Cfg(S, "Proteção contra adulteração (self-protection)", Bool(prot), True(prot) ? "Impede parar/alterar o cliente." : "Desligada: processos com privilégio podem parar ou alterar o cliente.", !True(prot));
            Cfg(S, "Atualização automática", Bool(Get(c, "clientConfig", "clientUpdate", "allowAutoUpdate")), "Se o cliente se atualiza sozinho.");
            var golden = Get(c, "clientConfig", "clientUpdate", "goldenReleaseVersion");
            Cfg(S, "Golden release", string.IsNullOrEmpty(golden) ? "(última versão)" : golden, "Versão-alvo definida pelo admin para atualização.");
            Cfg(S, "Intervalo de atualização da configuração", Get(c, "clientConfig", "configUpdate", "updateIntervalInMin") is string ui ? ui + " min" : null, "De quanto em quanto tempo o cliente busca configuração nova.");
            Cfg(S, "Protocolo do túnel", Get(c, "clientConfig", "protocol"), "TLS (TCP 443) ou DTLS (UDP 443).");
            var pin = Get(c, "clientConfig", "allowPOPPinning"); var upin = Get(c, "clientConfig", "allowUserPOPPinning");
            Cfg(S, "Fixar POP (POP pinning)", $"admin: {Bool(pin)} · usuário: {Bool(upin)}", "Se é possível fixar manualmente o POP em vez de deixar o GSLB escolher.");
            Cfg(S, "Bloquear IPv6", Bool(Get(c, "clientConfig", "blockIPv6")), "Com IPv6 liberado, tráfego IPv6 pode não passar pelo túnel.");
            Cfg(S, "Bypass de tráfego local", Bool(Get(c, "clientConfig", "localTrafficBypass")), "Tráfego para a rede local não é tunelado.");
            Cfg(S, "Tratar domínios sobrepostos no cliente", Bool(Get(c, "clientConfig", "clientHandleOverlappingDomains")), "Decide no cliente quando um domínio está em mais de uma regra (exceção x steering).");
            Cfg(S, "Fail-close bloqueia tráfego privado", Bool(Get(c, "clientConfig", "failcloseBlockPrivateTraffic")), "Com fail-close ativo, se também bloqueia a rede local/privada.");
            var dem = Get(c, "clientConfig", "pdem_subscription_level");
            Cfg("Experiência (DEM)", "Licença DEM", dem, dem is null or "None" ? "Sem licença de DEM: o console não mostra experiência deste dispositivo. Use o coletor deste app para ter as métricas." : "DEM licenciado.", dem is null or "None");
            Cfg("Experiência (DEM)", "Métricas sintéticas do cliente", Bool(Get(c, "clientConfig", "metrics", "enable")), "Testes de ping/traceroute/DNS do próprio cliente (quando licenciados).");
            Cfg("Experiência (DEM)", "Wi-Fi avançado (DEM)", Bool(Get(c, "clientConfig", "enableAdvanceDEMWifiMetrics")), "Coleta de métricas de Wi-Fi pelo cliente.");
            var post = Get(c, "clientConfig", "postureValidation", "periodic_validation_enabled");
            Cfg("Postura", "Validação periódica de postura", Bool(post) + (Get(c, "clientConfig", "postureValidation", "validation", "interval") is string pi ? $" (a cada {pi} s)" : ""), "Reavaliação do dispositivo; uma falha pode bloquear o acesso a aplicações privadas.");
        }
        if (_json.TryGetValue("nsuser.conf", out var u))
        {
            var fc = Get(u, "userConfig", "failCloseStatus");
            Cfg("Cliente", "Fail-close", Bool(fc), True(fc) ? "Se o túnel cair, a navegação é bloqueada até reconectar." : "Se o túnel cair, a navegação segue direta (sem inspeção).", True(fc));
        }
        if (_json.TryGetValue("nssteering.json", out var s))
        {
            const string S = "Steering";
            Cfg(S, "Configuração de steering", Get(s, "steering_config_name"), "Regras que definem o que vai pelo túnel.");
            Cfg(S, "Modo de tráfego", Get(s, "traffic_mode"), "Qual tráfego é direcionado ao Netskope (web, cloud apps ou todo o tráfego).");
            Cfg(S, "Steering dinâmico (on/off-prem)", Bool(Get(s, "dynamic_steering")), "Regras diferentes dentro e fora da empresa.");
            var off = Get(s, "private_apps_off_prem"); var on = Get(s, "private_apps_on_prem");
            if (off != null || on != null)
                Cfg(S, "Private Access", $"fora da empresa: {(True(off) ? "ativo" : "inativo")} · na empresa: {(True(on) ? "ativo" : "inativo")}",
                    !True(on) && True(off) ? "Na rede da empresa o NPA é desligado de propósito; quedas do NPA “on-prem” são esperadas." : "Quando o Private Access fica ativo.");
            if (s.TryGetProperty("onprem_labels", out var labels) && labels.ValueKind == JsonValueKind.Array)
            {
                foreach (var l in labels.EnumerateArray())
                {
                    var name = Get(l, "name");
                    var cfg = l.TryGetProperty("config", out var cc) && cc.TryGetProperty("onpremcheck", out var oc) ? oc : default;
                    if (cfg.ValueKind != JsonValueKind.Object) continue;
                    var method = Get(cfg, "onprem_detection_method");
                    var ips = cfg.TryGetProperty("onprem_egress_ips", out var ia) && ia.ValueKind == JsonValueKind.Array ? ia.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList() : new List<string>();
                    var host = Get(cfg, "onprem_host"); var httpHost = Get(cfg, "onprem_http_host");
                    var how = ips.Count > 0 ? $"IP de saída em {string.Join(", ", ips)}" : !string.IsNullOrEmpty(httpHost) ? $"HTTP para {httpHost}" : !string.IsNullOrEmpty(host) ? $"DNS de {host}" : $"método {method}";
                    var egress = F.Egress ?? _r.EgressHistory.LastOrDefault().Value;
                    var verdict = ips.Count > 0 && egress != null
                        ? (ips.Contains(egress) ? $" O IP de saída observado ({egress}) está na lista → On Prem." : $" O IP de saída observado ({egress}) NÃO está na lista → Off Prem.")
                        : "";
                    Cfg("Detecção on-prem", name ?? "Regra on-prem", how, "Como o cliente decide se está na rede da empresa." + verdict, false);
                }
            }
        }
        foreach (var (file, label) in new[] { ("nsexception.json", "Exceções (bypass)") })
        {
            if (!_json.TryGetValue(file, out var ex)) continue;
            foreach (var p in ex.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object) continue;
                int Cnt(string k) => p.Value.TryGetProperty(k, out var a) && a.ValueKind == JsonValueKind.Array ? a.GetArrayLength() : 0;
                var names = Cnt("names"); var ips = Cnt("ips"); var doms = Cnt("domains");
                if (names + ips + doms == 0) continue;
                var priv = p.Value.TryGetProperty("ips", out var ia) && ia.ValueKind == JsonValueKind.Array && ia.EnumerateArray().Any(x => (Get(x, "value") ?? "").StartsWith("10.0.0.0", StringComparison.Ordinal));
                Cfg(label, p.Name, $"{names} domínio(s), {ips} IP/faixa(s)" + (doms > 0 ? $", {doms} domínio(s)" : ""),
                    "Destinos que nunca passam pelo túnel neste local." + (priv ? " Inclui as faixas privadas (10/8, 172.16/12, 192.168/16): a rede local vai direto." : ""));
            }
        }
        if (_json.TryGetValue("nsbypass.json", out var bp))
        {
            foreach (var p in bp.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object || !p.Value.TryGetProperty("certPinnedAppList", out var apps) || apps.ValueKind != JsonValueKind.Array || apps.GetArrayLength() == 0) continue;
                var names = apps.EnumerateArray().Select(a => $"{Get(a, "appName")} ({Get(a, "processName")}, {Get(a, "mode")})").Distinct().Take(8);
                Cfg("Apps com certificado fixo (cert pinning)", p.Name, string.Join("; ", names), "Processos que ficam fora da inspeção porque não aceitam o certificado do Netskope.");
            }
        }
        if (_json.TryGetValue("nsbypasscat.json", out var bc) && bc.TryGetProperty("webcat_ids", out var cats) && cats.ValueKind == JsonValueKind.Array)
            Cfg("Exceções (bypass)", "Categorias em bypass", cats.GetArrayLength() + " categoria(s)", "Categorias web que vão direto (sem inspeção).");
        if (_json.TryGetValue("nsoverlap.json", out var ov) && ov.TryGetProperty("overlappingDomainList", out var ol) && ol.ValueKind == JsonValueKind.Object)
            Cfg("Steering", "Grupos de domínios sobrepostos", ol.EnumerateObject().Count() + " grupo(s)", "Domínios que aparecem em mais de uma regra; o cliente resolve conforme a configuração de domínios sobrepostos.");
        if (_json.TryGetValue("nsdcconfig.json", out var dc)) Cfg("Postura", "Classificação do dispositivo", Get(dc, "nscdcstatus"), "Resultado da classificação (Managed/Unmanaged). “Unmanaged” pode restringir políticas.", Get(dc, "nscdcstatus") == "Unmanaged");
        if (_json.TryGetValue("devicesettings.json", out var ds))
            Cfg("SD-WAN", "Endpoint SD-WAN", True(Get(ds, "dynamic_steering", "bwan_apps_enabled")) ? "ativo" : "inativo", "Se o módulo de SD-WAN do cliente está em uso. Inativo = erros de “bwan” no log são ruído.");
    }

    private static string? Bool(string? v) => v is null ? null : True(v) ? "sim" : v is "false" or "0" or "False" ? "não" : v;

    // ---------------------------------------------------------------- componente das falhas genéricas

    private void ComponentBreakdown()
    {
        var keys = new[] { "timeout", "conn", "dns", "http" };
        var times = _r.Entries.Select(e => e.Time).ToList(); // já ordenado
        foreach (var f in _r.Findings.Where(x => keys.Contains(x.Key)))
        {
            var counts = new Dictionary<string, int>();
            foreach (var t in f.Times.Take(5000))
            {
                var lo = LowerBound(times, t.AddSeconds(-3));
                var comp = "Outros";
                for (var i = lo; i < _r.Entries.Count && _r.Entries[i].Time <= t.AddSeconds(2); i++)
                {
                    var m = _r.Entries[i].Message;
                    if (m.Contains("NPA-gslb", StringComparison.OrdinalIgnoreCase)) { comp = "GSLB do Private Access"; break; }
                    if (m.Contains("gslb", StringComparison.OrdinalIgnoreCase)) { comp = "Seleção de POP (GSLB)"; break; }
                    if (m.Contains("longpoll", StringComparison.OrdinalIgnoreCase)) { comp = "Canal de notificação da interface (longpoll)"; break; }
                    if (m.Contains("client status", StringComparison.OrdinalIgnoreCase)) { comp = "Envio de status do cliente"; break; }
                    if (m.Contains("DEM", StringComparison.Ordinal)) { comp = "DEM"; break; }
                    if (m.Contains("supportability", StringComparison.OrdinalIgnoreCase)) { comp = "Parâmetros de suporte"; break; }
                    if (m.Contains("config", StringComparison.OrdinalIgnoreCase) || m.Contains("steering", StringComparison.OrdinalIgnoreCase)) { comp = "Download de configuração"; break; }
                    if (m.Contains("cert", StringComparison.OrdinalIgnoreCase)) { comp = "Certificados"; break; }
                }
                counts[comp] = counts.GetValueOrDefault(comp) + 1;
            }
            if (counts.Count == 0) continue;
            var total = counts.Values.Sum();
            foreach (var kv in counts.OrderByDescending(kv => kv.Value)) f.Details.Insert(0, new("Componente: " + kv.Key, kv.Value));
            var top = counts.OrderByDescending(kv => kv.Value).First();
            if (top.Key != "Outros" && top.Value >= total * 0.7)
                f.Meaning = $"Concentrado em: {top.Key} ({top.Value} de {total}). " + f.Meaning;
        }
    }

    private static int LowerBound(List<DateTime> list, DateTime t)
    {
        int lo = 0, hi = list.Count;
        while (lo < hi) { var mid = (lo + hi) / 2; if (list[mid] < t) lo = mid + 1; else hi = mid; }
        return lo;
    }

    // ---------------------------------------------------------------- reclassificação de ruído

    private void Noise()
    {
        var procs = _r.Snapshots.SelectMany(s => s.Processes).Select(p => p.Name).ToList();
        foreach (var f in _r.Findings)
        {
            if (f.Key == "firefox" && !procs.Any(p => p.Contains("firefox", StringComparison.OrdinalIgnoreCase)) && f.Samples.All(s => Regex.IsMatch(s, "snap|sanp|FF Snap", RegexOptions.IgnoreCase)))
            {
                f.Severity = Severity.Noise; f.Category = "Ruído";
                f.Title = "CA do Netskope não copiada para o Firefox Snap (Firefox Snap não está em uso)";
                f.Meaning = "O cliente tenta copiar a CA para o Firefox instalado via Snap; a pasta não existe. Sem Firefox Snap em execução, não há impacto. " + f.Meaning;
            }
            if (f.Key == "http" && f.Files.Count > 0 && f.Files.All(n => n.StartsWith("nsAppUI", StringComparison.OrdinalIgnoreCase)) && f.Details.Any(d => d.Key.Contains("403") || d.Key.Contains("longpoll")))
            {
                f.Severity = Severity.Noise; f.Category = "Ruído";
                f.Title = $"Canal de notificação da interface recusado pelo tenant (HTTP 403) — {f.Count:N0} vezes";
                f.Meaning = "A interface do cliente (stAgentUI) consulta o tenant a cada poucos segundos para receber notificações e recebe 403. Não afeta túnel nem navegação, mas gera muitas linhas e faz o nsAppUI.log girar rápido, apagando histórico útil. " + f.Meaning;
            }
            if (f.Key == "broker") { f.Severity = Severity.Noise; f.Category = "Ruído"; }
        }
        var churn = _r.Findings.FirstOrDefault(f => f.Key == "netchurn");
        if (churn != null)
        {
            foreach (var f in _r.Findings.Where(x => x.Key is "route" or "gslb"))
            {
                if (f.Key == "route") f.Severity = Severity.Info;
                f.Meaning += " Neste pacote, estas falhas acompanham as mudanças de rede em excesso — resolva aquele item primeiro.";
            }
        }
        // falhas por keepalive do NPA são tratadas como quedas de sessão; a regra genérica vira detalhe
        foreach (var f in _r.Findings.Where(x => x.Key == "npagw")) f.Meaning += " Veja na aba Rede o motivo de cada queda e o tempo até reconectar.";
    }

    // ---------------------------------------------------------------- séries derivadas

    private void AddSeries()
    {
        // saúde do gateway NPA
        string? lastIp = null; DateTime lastT = default; long lastRe = 0;
        foreach (var (t, ip, rtt, re) in _gw)
        {
            TelemetryParser.Add(_r, "npa.gw.rtt", t, rtt, "Logs Netskope");
            if (lastIp == ip && re >= lastRe && (t - lastT).TotalMinutes <= 15 && (t - lastT).TotalSeconds > 30)
            {
                var dt = (t - lastT).TotalSeconds;
                TelemetryParser.Add(_r, "npa.gw.retrans", t, Math.Round((re - lastRe) * 300 / dt), "Logs Netskope");
                if (dt <= 900) { var delay = Math.Max(0, dt - 300); _schedDelays.Add(delay); TelemetryParser.Add(_r, "perf.sched", t, Math.Round(delay, 1), "Logs Netskope"); }
            }
            lastIp = ip; lastT = t; lastRe = re;
        }
        Buckets("net.changes", _netChanges, TimeSpan.FromMinutes(10), _svcFirst, _svcLast);
        if (_stalls.Count > 0) Buckets("perf.stall", _stalls, TimeSpan.FromMinutes(10), _npaFirst ?? _svcFirst, _npaLast ?? _svcLast);
    }

    private void Buckets(string key, List<DateTime> times, TimeSpan size, DateTime? from, DateTime? to)
    {
        if (times.Count == 0 || from is null || to is null) return;
        var t0 = new DateTime(from.Value.Ticks - from.Value.Ticks % size.Ticks);
        var n = (int)((to.Value - t0).Ticks / size.Ticks) + 1;
        if (n <= 0 || n > 20000) return;
        var counts = new int[n];
        foreach (var t in times) { var b = (int)((t - t0).Ticks / size.Ticks); if (b >= 0 && b < n) counts[b]++; }
        for (var i = 0; i < n; i++)
        {
            var bs = t0 + size * i;
            if (_gaps.Any(g => bs >= g.Start && bs + size <= g.End)) continue; // máquina sem atividade: não conta como zero
            TelemetryParser.Add(_r, key, bs, counts[i], "Logs Netskope");
        }
    }

    // =====================================================================================================
    // Fase 2 — depois dos estados dos túneis e POPs (antes do baseline, score e causa raiz)
    // =====================================================================================================

    public void AfterMetrics()
    {
        NpaSessions();
        PopQuality();
        Captures();
    }

    private void NpaSessions()
    {
        NpaSession? cur = null;
        string? reason = null; DateTime reasonAt = default; var expected = false;
        string? pendingPop = null, pendingIp = null; double? pendingRtt = null; DateTime pendingAt = default;
        var file = "npadebuglog";
        foreach (var e in _r.Entries)
        {
            if (!IsNpaFile(FileOf(e))) continue;
            var m = e.Message;
            if (m.Contains("Starting handler with GW", StringComparison.Ordinal))
            {
                var x = NpaStartRe.Match(m);
                if (x.Success) { pendingIp = x.Groups[1].Value; pendingPop = x.Groups[2].Value.Trim(); pendingAt = e.Time; pendingRtt = null; }
                continue;
            }
            if (m.Contains("GW FQDN = ", StringComparison.Ordinal))
            {
                var x = NpaGwListRe.Match(m);
                if (x.Success && x.Groups[1].Value == pendingIp) pendingRtt = D(x.Groups[3].Value);
                continue;
            }
            if (m.Contains("TLS client established connection", StringComparison.Ordinal))
            {
                var x = NpaTlsRe.Match(m);
                if (!x.Success || (pendingIp != null && x.Groups[1].Value != pendingIp)) continue;
                var ip = x.Groups[1].Value;
                if (cur != null && cur.End is null) continue; // conexão auxiliar dentro da mesma sessão
                var prev = _r.NpaSessions.LastOrDefault();
                if (prev != null && prev.End != null && prev.ReconnectedAt is null) prev.ReconnectedAt = e.Time;
                cur = new NpaSession { Start = e.Time, GatewayIp = ip, Pop = pendingPop ?? _gwPop.GetValueOrDefault(ip), SelectRttMs = pendingRtt };
                _r.NpaSessions.Add(cur);
                pendingIp = null;
                continue;
            }
            if (m.Contains("keepAlive fails", StringComparison.Ordinal))
            {
                var x = NpaKeepAliveRe.Match(m);
                reason = $"Gateway parou de responder (keepalive falhou {(x.Success ? x.Groups[1].Value + " vezes" : "")})".Replace(" )", ")"); reasonAt = e.Time; expected = false;
                continue;
            }
            if (m.Contains("Shutdown packet received from gateway", StringComparison.Ordinal))
            {
                var x = NpaShutdownRe.Match(m);
                var why = x.Success ? x.Groups[1].Value : "";
                expected = why.Contains("expired", StringComparison.OrdinalIgnoreCase) || why.Contains("Authenticate again", StringComparison.OrdinalIgnoreCase);
                reason = expected ? "Sessão expirada — reautenticação programada" : "Gateway encerrou a sessão" + (why.Length > 0 ? ": " + why : "");
                reasonAt = e.Time;
                continue;
            }
            if (m.Contains("Failed to resolve GW", StringComparison.Ordinal)) { reason = "Não conseguiu resolver gateway.npa.goskope.com (DNS)"; reasonAt = e.Time; expected = false; continue; }
            if (m.Contains("Broken pipe", StringComparison.Ordinal) && reason is null) { reason = "Conexão TCP com o gateway interrompida (broken pipe)"; reasonAt = e.Time; continue; }
            if (m.Contains("NPA Tunnel is disconnected", StringComparison.Ordinal))
            {
                if (cur is null || cur.End != null)
                {
                    // sessão começou antes do início do log
                    var start = _npaFirst ?? e.Time;
                    var ip = _gw.LastOrDefault(g => g.T <= e.Time).Ip;
                    cur = new NpaSession { Start = start, GatewayIp = ip, Pop = ip != null ? _gwPop.GetValueOrDefault(ip) : null };
                    _r.NpaSessions.Add(cur);
                }
                cur.End = e.Time;
                var recent = reason != null && (e.Time - reasonAt).TotalSeconds <= 5;
                cur.EndReason = recent ? reason : NearNetChange(e.Time) ? "Troca de rede / mudança de interface" : NearGap(e.Time) ? "Suspensão ou desligamento" : "Encerrada pelo cliente (motivo não registrado)";
                cur.Expected = recent && expected;
                reason = null; expected = false;
                var kind = cur.Expected ? EventKind.Info : EventKind.Bad;
                _r.Events.Add(new TimelineEvent(e.Time, cur.Expected ? "Private Access: reautenticação" : "Private Access desconectado", kind, cur.EndReason + (cur.Pop != null ? $" · POP {cur.Pop}" : ""), file));
            }
        }
        // POP para sessões sem nome
        foreach (var s in _r.NpaSessions.Where(s => s.Pop is null && s.GatewayIp != null)) s.Pop = PopName(s.GatewayIp!);
        foreach (var s in _r.NpaSessions.Where(s => s.ReconnectedAt is DateTime))
            _r.Events.Add(new TimelineEvent(s.ReconnectedAt!.Value, "Private Access reconectado", EventKind.Good, $"após {TelemetryParser.Fmt(s.Downtime ?? TimeSpan.Zero)}", file));

        if (_r.NpaSessions.Count == 0) return;
        BuildNpaStates();
        NpaFindings();
    }

    private bool NearNetChange(DateTime t) => _netChanges.Any(c => Math.Abs((c - t).TotalSeconds) <= 15);
    private bool NearGap(DateTime t) => _gaps.Any(g => Math.Abs((g.Start - t).TotalMinutes) <= 2);

    private string? PopName(string ip)
    {
        if (_gwPop.TryGetValue(ip, out var p)) return p;
        var pre = ip[..(ip.LastIndexOf('.') + 1)];
        var byPrefix = _r.Pops.FirstOrDefault(x => x.Ip != null && x.Ip.StartsWith(pre, StringComparison.Ordinal));
        return byPrefix?.Pop;
    }

    private void BuildNpaStates()
    {
        var end = _npaLast ?? _r.End ?? DateTime.Now;
        var states = new List<StateInterval>();
        var sessions = _r.NpaSessions.OrderBy(s => s.Start).ToList();
        for (var i = 0; i < sessions.Count; i++)
        {
            var s = sessions[i];
            var sEnd = s.End ?? (i + 1 < sessions.Count ? sessions[i + 1].Start : end);
            if (sEnd > s.Start) states.Add(new StateInterval("Private Access", "Conectado", s.Start, sEnd));
            if (s.End is DateTime de)
            {
                var back = s.ReconnectedAt ?? (i + 1 < sessions.Count ? sessions[i + 1].Start : end);
                if (back > de) states.Add(new StateInterval("Private Access", s.Expected ? "Reautenticando" : "Desconectado", de, back));
            }
        }
        // períodos sem nenhuma atividade (suspensão/desligada) não contam como queda nem como conectado
        var cut = new List<StateInterval>();
        foreach (var st in states)
        {
            var pieces = new List<(DateTime A, DateTime B)> { (st.Start, st.End) };
            foreach (var g in _gaps)
            {
                pieces = pieces.SelectMany(p =>
                {
                    if (g.End <= p.A || g.Start >= p.B) return new[] { p };
                    var res = new List<(DateTime A, DateTime B)>();
                    if (g.Start > p.A) res.Add((p.A, g.Start));
                    if (g.End < p.B) res.Add((g.End, p.B));
                    return res.ToArray();
                }).ToList();
            }
            cut.AddRange(pieces.Where(p => p.B > p.A).Select(p => st with { Start = p.A, End = p.B }));
        }
        foreach (var g in _gaps.Where(g => sessions.Count > 0 && g.Start >= sessions[0].Start && g.End <= end))
            cut.Add(new StateInterval("Private Access", "Sem atividade (suspensa/desligada)", g.Start, g.End));
        cut.Sort((a, b) => a.Start.CompareTo(b.Start));

        var existing = _r.States.Where(x => x.Service == "Private Access").ToList();
        var existingSpan = existing.Count > 0 ? existing.Max(x => x.End) - existing.Min(x => x.Start) : TimeSpan.Zero;
        var newSpan = cut.Count > 0 ? cut.Max(x => x.End) - cut.Min(x => x.Start) : TimeSpan.Zero;
        if (newSpan <= existingSpan) return;
        _r.States.RemoveAll(x => x.Service == "Private Access");
        _r.States.AddRange(cut);
        double up = 0, total = 0;
        foreach (var st in cut)
        {
            if (st.State.StartsWith("Sem atividade", StringComparison.Ordinal)) continue;
            total += st.Duration.TotalSeconds;
            if (st.State is "Conectado" or "Reautenticando") up += st.Duration.TotalSeconds;
        }
        if (total > 0) _r.Availability["Private Access"] = Math.Round(100 * up / total, 2);
    }

    private void NpaFindings()
    {
        var drops = _r.NpaSessions.Where(s => s.End != null && !s.Expected).ToList();
        var reauth = _r.NpaSessions.Where(s => s.End != null && s.Expected).ToList();
        var days = Math.Max(1, ((_npaLast ?? DateTime.Now) - (_npaFirst ?? DateTime.Now)).TotalDays);
        if (drops.Count > 0)
        {
            var keep = drops.Count(d => d.EndReason!.StartsWith("Gateway parou", StringComparison.Ordinal));
            var perDay = drops.GroupBy(d => d.End!.Value.Date).OrderByDescending(g => g.Count()).ToList();
            var clusters = RootCause.Clusters(drops.Select(d => d.End!.Value).ToList(), TimeSpan.FromHours(1)).Where(c => c.Count >= 3).ToList();
            var downs = drops.Where(d => d.Downtime != null).Select(d => d.Downtime!.Value.TotalSeconds).OrderBy(x => x).ToList();
            var withTenant = drops.Count(d => _r.Findings.Any(f => f.Key is "timeout" or "gslb" or "conn" && f.Times.Any(t => Math.Abs((t - d.End!.Value).TotalMinutes) <= 4)));
            var f = new Finding
            {
                Key = "npadrops", Severity = drops.Count >= 10 || clusters.Count > 0 ? Severity.Critical : drops.Count >= 3 ? Severity.Warning : Severity.Info, Category = "Túnel",
                Title = $"Private Access caiu {drops.Count} vez(es) em {TelemetryParser.Fmt(TimeSpan.FromDays(days))}" + (keep > 0 ? $" — {keep} por falta de resposta do gateway" : ""),
                Meaning = string.Join(" ", new[]
                {
                    $"Média de {drops.Count / days:0.#} queda(s) por dia; pior dia {perDay[0].Key:dd/MM} com {perDay[0].Count()}.",
                    clusters.Count > 0 ? "Quedas em sequência (3 ou mais na mesma hora): " + string.Join("; ", clusters.Take(5).Select(c => $"{c.Start:dd/MM HH:mm}–{c.End:HH:mm} ({c.Count})")) + "." : "",
                    downs.Count > 0 ? $"Tempo até reconectar: mediana {TelemetryParser.Fmt(TimeSpan.FromSeconds(downs[downs.Count / 2]))}, máximo {TelemetryParser.Fmt(TimeSpan.FromSeconds(downs[^1]))}." : "",
                    keep > 0 ? "“Keepalive falhou” significa que o gateway deixou de responder por ~15 s: a conexão TCP até o POP ficou sem tráfego de volta." : "",
                    withTenant > 0 ? $"Em {withTenant} das quedas o cliente também falhou ao falar com o tenant/GSLB no mesmo horário — sinal de que a Internet da máquina caiu ou ficou instável, não de problema no Netskope." : "",
                }.Where(x => x.Length > 0)),
                Action = "Correlacione cada queda com a rede da máquina no mesmo horário.",
                Count = drops.Count, First = drops.Min(d => d.End), Last = drops.Max(d => d.End),
            };
            f.Times.AddRange(drops.Select(d => d.End!.Value));
            foreach (var g in drops.GroupBy(d => d.EndReason!).OrderByDescending(g => g.Count())) f.Details.Add(new(g.Key, g.Count()));
            foreach (var g in perDay.Take(8)) f.Details.Add(new($"dia {g.Key:dd/MM}", g.Count()));
            f.Samples.AddRange(drops.TakeLast(6).Select(d => $"{d.End:dd/MM HH:mm:ss} {d.EndReason} · POP {d.Pop ?? d.GatewayIp ?? "?"}" + (d.Downtime is TimeSpan dt ? $" · voltou em {TelemetryParser.Fmt(dt)}" : "")));
            var gwIp = drops.Last().GatewayIp ?? "gateway.npa.goskope.com";
            f.Steps.Add(new("Abra a aba Rede: para cada queda há o motivo, o POP e o tempo até reconectar; e os gráficos de RTT e retransmissões do túnel mostram se o caminho até o POP degradou antes."));
            f.Steps.Add(new("Se as quedas coincidirem com falhas de GSLB/tenant (Incidentes), o problema é a Internet da máquina: verifique Wi-Fi e roteador no mesmo horário."));
            if (Os == ClientOs.Windows)
            {
                f.Steps.Add(new("Teste o caminho até o POP do Private Access (perda por salto):", $"pathping -q 50 {gwIp}"));
                f.Steps.Add(new("Veja sinal e reconexões do Wi-Fi:", "netsh wlan show interfaces\nnetsh wlan show wlanreport"));
            }
            else if (Os == ClientOs.Mac)
            {
                f.Steps.Add(new("Teste o caminho até o POP do Private Access:", $"mtr -rwzbc 200 -T -P 443 {gwIp}"));
                f.Steps.Add(new("Veja o sinal do Wi-Fi:", "sudo wdutil info | grep -E 'RSSI|Noise|Tx Rate|Channel'"));
            }
            else
            {
                f.Steps.Add(new("Teste o caminho até o POP do Private Access (TCP 443, 200 amostras):", $"sudo mtr -rwzbc 200 -T -P 443 {gwIp}"));
                f.Steps.Add(new("Veja sinal, taxa e canal do Wi-Fi e o histórico de reconexões:", "nmcli -f IN-USE,SSID,SIGNAL,RATE,CHAN dev wifi\njournalctl -u NetworkManager --since \"-24h\" | grep -Ei 'disconnect|deauth|beacon|state change' | tail -40"));
            }
            f.Steps.Add(new("Rode o coletor deste app na máquina por um dia: ele grava Wi-Fi, perda e latência a cada 30 s e a causa raiz de cada queda passa a apontar o trecho exato."));
            f.SearchQuery = "Netskope private access keepAlive fails tunnel disconnected";
            _r.Findings.Add(f);
        }
        if (reauth.Count > 0)
        {
            var hours = reauth.Select(s => s.End!.Value.Hour).GroupBy(h => h).OrderByDescending(g => g.Count()).First().Key;
            var f = new Finding
            {
                Key = "npareauth", Severity = Severity.Info, Category = "Túnel",
                Title = $"Reautenticação do Private Access ({reauth.Count} vez(es)) — esperado",
                Meaning = $"O gateway encerrou a sessão porque ela expirou e pediu nova autenticação. É a política de reautenticação do tenant, não uma falha. A maioria ocorreu por volta das {hours}h. Se incomodar o usuário, revise o tempo de reautenticação nas configurações do Private Access.",
                Action = "Nenhuma, salvo se a frequência estiver maior que a política.",
                Count = reauth.Count, First = reauth.Min(s => s.End), Last = reauth.Max(s => s.End),
            };
            f.Samples.AddRange(reauth.TakeLast(6).Select(s => $"{s.End:dd/MM HH:mm:ss} {s.EndReason}" + (s.Downtime is TimeSpan dt ? $" · voltou em {TelemetryParser.Fmt(dt)}" : "")));
            _r.Findings.Add(f);
        }
    }

    // ---------------------------------------------------------------- qualidade do POP escolhido

    private static double Median(IEnumerable<double> v)
    {
        var l = v.OrderBy(x => x).ToList();
        return l.Count == 0 ? double.NaN : l.Count % 2 == 1 ? l[l.Count / 2] : (l[l.Count / 2 - 1] + l[l.Count / 2]) / 2;
    }

    private void PopQuality()
    {
        // mediana de latência por POP (medida pelo cliente na seleção de gateway)
        var med = new Dictionary<string, (double Med, int N)>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in _r.Series.Values.Where(s => s.Key.StartsWith("pop.rtt:", StringComparison.OrdinalIgnoreCase)))
        {
            var target = MetricCatalog.Split(s.Key).Target ?? "";
            var pop = target.Contains(' ') ? target[(target.LastIndexOf(' ') + 1)..] : target;
            if (s.Points.Count < 5) continue;
            var m = Median(s.Points.Select(p => p.Value));
            if (!med.TryGetValue(pop, out var cur) || s.Points.Count > cur.N) med[pop] = (m, s.Points.Count);
        }
        if (med.Count < 2) return;
        var best = med.OrderBy(kv => kv.Value.Med).First();
        var bad = new List<(NpaSession S, double Med, TimeSpan Dur)>();
        foreach (var s in _r.NpaSessions.Where(s => s.Pop != null && med.ContainsKey(s.Pop)))
        {
            var dur = (s.End ?? _npaLast ?? s.Start) - s.Start;
            var m = med[s.Pop!].Med;
            if (dur.TotalMinutes >= 30 && s.Pop != best.Key && m - best.Value.Med >= 5 && m >= best.Value.Med * 1.3) bad.Add((s, m, dur));
        }
        if (bad.Count == 0) return;
        var last = bad[^1];
        var f = new Finding
        {
            Key = "popsub", Severity = Severity.Info, Category = "Túnel",
            Title = $"Private Access ficou em POP mais lento: {last.S.Pop} (mediana {last.Med:0} ms) em vez de {best.Key} ({best.Value.Med:0} ms)",
            Meaning = $"Em {bad.Count} sessão(ões) o túnel ficou conectado a um POP com latência típica bem maior que a do melhor POP medido pelo próprio cliente. " +
                      (last.S.SelectRttMs is double sr ? $"Na conexão de {last.S.Start:dd/MM HH:mm} a medição instantânea deu {sr:0} ms para {last.S.Pop}, e o túnel permaneceu nele por {TelemetryParser.Fmt(last.Dur)}. " : "") +
                      "A diferença só pesa para aplicações sensíveis a latência (RDP, VoIP, bancos de dados).",
            Action = "Se a diferença impactar, reconecte o Private Access para o cliente medir os POPs de novo.",
            Count = bad.Count, First = bad[0].S.Start, Last = last.S.Start,
        };
        foreach (var kv in med.OrderBy(kv => kv.Value.Med).Take(6)) f.Details.Add(new($"{kv.Key}: mediana {kv.Value.Med:0} ms", kv.Value.N));
        f.Steps.Add(new("Compare a latência por POP na aba Rede (tabela de POPs e gráfico “Latência por POP”)."));
        f.Steps.Add(new("Para forçar nova seleção, desabilite e habilite o Private Access na bandeja do cliente (ou reinicie o serviço fora do horário de uso)."));
        f.SearchQuery = "Netskope private access gateway selection GSLB POP latency";
        _r.Findings.Add(f);
    }

    // ---------------------------------------------------------------- capturas de pacotes

    private void Captures()
    {
        foreach (var c in _r.Captures.Where(c => c.Error is null || c.Packets > 0))
        {
            var issues = new List<string>();
            if (c.TcpDataSegments >= 200 && c.RetransPct >= 3) issues.Add($"{c.RetransPct:0.#}% de retransmissões TCP ({c.Retransmissions:N0} de {c.TcpDataSegments:N0} segmentos com dados)");
            if (c.HandshakeFailures >= 5) issues.Add($"{c.HandshakeFailures} conexões TCP sem resposta ao SYN");
            if (c.TlsAlerts >= 5) issues.Add($"{c.TlsAlerts} alertas TLS");
            var fail = c.DnsRcodes.Where(kv => kv.Key is "SERVFAIL" or "REFUSED").Sum(kv => kv.Value);
            if (fail >= 5) issues.Add($"{fail} respostas DNS com falha (SERVFAIL/REFUSED)");
            if (issues.Count == 0) continue;
            var f = new Finding
            {
                Key = "pcap", Severity = c.RetransPct >= 8 || c.HandshakeFailures >= 30 ? Severity.Warning : Severity.Info, Category = "Rede",
                Title = $"Captura {c.File}: " + issues[0],
                Meaning = $"Resumo da captura ({c.LinkType}, {c.Packets:N0} pacotes" + (c.First is DateTime a && c.Last is DateTime b ? $", {a:dd/MM HH:mm:ss} a {b:HH:mm:ss}" : "") + "): " + string.Join("; ", issues) + "." +
                          (c.TopRetransDestinations.Count > 0 ? " Destinos com mais retransmissões: " + string.Join(", ", c.TopRetransDestinations.Take(4).Select(kv => $"{kv.Key} ({kv.Value})")) + "." : ""),
                Action = "Abra a captura no Wireshark filtrando os destinos citados.",
                Count = issues.Count,
            };
            f.Steps.Add(new("Filtros úteis no Wireshark:", "tcp.analysis.retransmission || tcp.analysis.zero_window\ntcp.flags.syn==1 && tcp.flags.ack==0\ntls.alert_message\ndns.flags.rcode != 0"));
            f.Steps.Add(new("nsouterpktdump = pacotes da placa de rede (fora do túnel); nspktdump/npatunnel = pacotes dentro do túnel. Retransmissão só fora do túnel aponta para Wi-Fi/provedor."));
            f.SearchQuery = "Netskope packet capture nspktdump retransmission";
            _r.Findings.Add(f);
        }
    }

    // =====================================================================================================
    // Fase 3 — depois do baseline, score e causa raiz
    // =====================================================================================================

    public void Finish()
    {
        Performance();
        CaseSummary();
    }

    private static string St(double v, double warn, double crit, bool higherWorse = true) =>
        higherWorse ? (v >= crit ? "crítico" : v >= warn ? "atenção" : "bom") : (v <= crit ? "crítico" : v <= warn ? "atenção" : "bom");

    private void P(string group, string name, string value, string reference, string status, string meaning, string? key = null) =>
        _r.Performance.Add(new PerfMetric(group, name, value, reference, status, meaning, key));

    private void Performance()
    {
        var r = _r;
        MetricSeries? S(string k) => r.Series.TryGetValue(k, out var s) && s.Points.Count > 0 ? s : null;
        string N(double v, string f = "0.#") => v.ToString(f, CultureInfo.GetCultureInfo("pt-BR"));

        // ---- dispositivo
        var snap = r.Snapshots.Where(s => !s.Source.Contains("coletor", StringComparison.OrdinalIgnoreCase) && s.Processes.Any(p => p.CpuPct > 0)).OrderByDescending(s => s.Processes.Count).FirstOrDefault();
        if (snap != null)
        {
            var top = snap.Processes.Where(p => !NetskopeProcRe.IsMatch(p.Name)).OrderByDescending(p => p.CpuPct).Take(3).ToList();
            if (top.Count > 0)
                P(MetricCatalog.Device, "Processos que mais usam CPU (média desde o início)", string.Join(" · ", top.Select(p => $"{p.Name} {N(p.CpuPct)}%")),
                    "< 25% de um núcleo", St(top[0].CpuPct, 25, 80), "Valor do ps: % de UM núcleo, média desde que o processo iniciou. Mostra quem disputa CPU com o túnel e as aplicações.");
            var ns = snap.Processes.Where(p => NetskopeProcRe.IsMatch(p.Name)).ToList();
            if (ns.Count > 0)
                P("Netskope", "Consumo do próprio Netskope Client", $"CPU {N(ns.Sum(p => p.CpuPct))}% · memória {N(ns.Sum(p => p.MemMb), "0")} MB", "< 10% · < 500 MB",
                    St(ns.Sum(p => p.CpuPct), 10, 40), "Processos stAgent*/nsdiag/npa. Valores altos indicam laço de reconexão ou volume muito alto de tráfego inspecionado.");
            var memPct = snap.Processes.Sum(p => p.MemPct);
            if (memPct > 1 && snap.MemTotalMb is double mt)
                P(MetricCatalog.Device, "Memória usada pelos processos", $"{N(memPct, "0")}% de ~{N(mt / 1024, "0.#")} GB", "< 85%", St(memPct, 85, 95), "Soma da memória residente (RSS) da foto de processos.");
        }
        if (S("perf.sched") is MetricSeries sch)
        {
            var v = sch.Points.Select(p => p.Value).OrderBy(x => x).ToList();
            P(MetricCatalog.Device, "Atraso das tarefas periódicas do cliente", $"mediana {N(Median(v))} s · p95 {N(v[(int)(0.95 * (v.Count - 1))])} s · máx. {N(v[^1])} s", "≤ 20 s", St(v[(int)(0.95 * (v.Count - 1))], 20, 120),
                "O túnel NPA registra estatísticas a cada 5 min; quanto ele atrasa mostra se a máquina estava sobrecarregada (CPU/disco) ou entrou em suspensão rápida — o equivalente do DEM para “responsividade do dispositivo”.", "perf.sched");
        }
        if (_stalls.Count > 0)
        {
            var h = Math.Max(1, ((_npaLast ?? _svcLast ?? DateTime.Now) - (_npaFirst ?? _svcFirst ?? DateTime.Now)).TotalHours);
            P(MetricCatalog.Device, "Operações internas do cliente que estouraram o tempo", $"{_stalls.Count} ({N(_stalls.Count / h, "0.##")} por hora)", "0", St(_stalls.Count / h, 0.5, 3),
                "Esperas internas do cliente acima do limite. Em rajada indicam CPU saturada ou o processo travado.", "perf.stall");
        }
        if (_gaps.Count > 0)
        {
            var total = _gaps.Aggregate(TimeSpan.Zero, (a, g) => a + (g.End - g.Start));
            var from = new[] { _svcFirst, _npaFirst }.Where(x => x != null).Min()!.Value;
            var span = (r.End ?? from) - from;
            var active = span - total;
            var days = Math.Max(1, span.TotalDays);
            P(MetricCatalog.Device, "Períodos sem atividade (suspensa/desligada)", $"{_gaps.Count} · total {TelemetryParser.Fmt(total)}", "—", "—",
                $"Intervalos de 15 min ou mais sem nenhum log. Tempo ativo médio: {TelemetryParser.Fmt(TimeSpan.FromHours(active.TotalHours / days))} por dia.");
        }

        // ---- rede
        if (S("net.changes") is MetricSeries nc)
        {
            var perH = _netChanges.Count / Math.Max(1.0 / 6, ((_svcLast ?? DateTime.Now) - (_svcFirst ?? DateTime.Now)).TotalHours);
            P(MetricCatalog.Network, "Mudanças de rede detectadas", $"{_netChanges.Count} · ~{N(perH, "0")} por hora · pico {N(nc.Points.Max(p => p.Value), "0")} em 10 min", "só quando troca de rede",
                St(perH, 6, 30), "Cada mudança faz o cliente refazer GSLB, detecção on-prem e rotas.", "net.changes");
        }
        foreach (var s in r.Series.Values.Where(s => s.Key.StartsWith("pop.best:", StringComparison.OrdinalIgnoreCase) && s.Points.Count > 0))
        {
            var v = s.Points.Select(p => p.Value).OrderBy(x => x).ToList();
            var p95 = v[(int)(0.95 * (v.Count - 1))];
            P(MetricCatalog.Network, "Latência até o melhor POP — " + MetricCatalog.Split(s.Key).Target, $"mediana {N(Median(v), "0")} ms · p95 {N(p95, "0")} ms · máx. {N(v[^1], "0")} ms", "≤ 80 ms", St(p95, 80, 150),
                "Medida pelo próprio cliente (TCP) a cada seleção de gateway.", s.Key);
        }
        if (S("npa.dns.nxdomain") is MetricSeries nx)
            P(MetricCatalog.Network, "DNS pelo Private Access: respostas NXDOMAIN", $"média {N(nx.Points.Average(p => p.Value), "0")}%", "< 50%", St(nx.Points.Average(p => p.Value), 50, 80),
                "Proporção de nomes inexistentes nas consultas DNS que passam pelo túnel. Alta = sufixo de pesquisa indevido ou nomes errados.", "npa.dns.nxdomain");
        if (r.Findings.FirstOrDefault(f => f.Key == "dnssuffix") is Finding ds)
            P(MetricCatalog.Network, "Consultas DNS com sufixo indevido", ds.Count.ToString("N0", CultureInfo.GetCultureInfo("pt-BR")), "0", "atenção", "Nomes públicos consultados de novo com o domínio de pesquisa interno.");

        // ---- Netskope
        foreach (var (svc, av) in r.Availability)
            P("Netskope", $"Disponibilidade — {svc}", $"{N(av, "0.##")}%", "≥ 99,5%", St(av, 99.5, 97, false), "Tempo conectado sobre o tempo em que a máquina estava ativa no período do log.");
        var drops = r.NpaSessions.Where(s => s.End != null && !s.Expected).ToList();
        if (r.NpaSessions.Count > 0)
        {
            var days = Math.Max(1, ((_npaLast ?? DateTime.Now) - (_npaFirst ?? DateTime.Now)).TotalDays);
            P("Netskope", "Quedas do Private Access", $"{drops.Count} ({N(drops.Count / days, "0.#")} por dia)", "0", St(drops.Count / days, 0.5, 2), "Quedas não programadas (reautenticação fica de fora).");
            var dt = drops.Where(d => d.Downtime != null).Select(d => d.Downtime!.Value.TotalSeconds).ToList();
            if (dt.Count > 0) P("Netskope", "Tempo até reconectar o Private Access", $"mediana {TelemetryParser.Fmt(TimeSpan.FromSeconds(Median(dt)))} · máx. {TelemetryParser.Fmt(TimeSpan.FromSeconds(dt.Max()))}", "≤ 30 s", St(Median(dt), 30, 120), "Tempo sem acesso às aplicações privadas em cada queda.");
        }
        if (S("npa.gw.rtt") is MetricSeries gr)
        {
            var v = gr.Points.Select(p => p.Value).OrderBy(x => x).ToList();
            var p95 = v[(int)(0.95 * (v.Count - 1))];
            P("Netskope", "RTT até o gateway do Private Access", $"mediana {N(Median(v), "0")} ms · p95 {N(p95, "0")} ms · máx. {N(v[^1], "0")} ms", "≤ 80 ms", St(p95, 80, 250), "Medido pelo próprio túnel a cada 5 min (RTT do TCP).", "npa.gw.rtt");
        }
        if (S("npa.gw.retrans") is MetricSeries rt)
        {
            var v = rt.Points.Select(p => p.Value).OrderBy(x => x).ToList();
            P("Netskope", "Retransmissões TCP do túnel Private Access", $"mediana {N(Median(v), "0")} · máx. {N(v[^1], "0")} por 5 min", "< 50 por 5 min", St(v[(int)(0.95 * (v.Count - 1))], 50, 200),
                "Segmentos reenviados por perda no caminho até o POP. Picos antes de uma queda apontam Wi-Fi/provedor.", "npa.gw.retrans");
        }
        if (r.Findings.FirstOrDefault(f => f.Key == "gslb") is Finding g)
            P("Netskope", "Falhas na seleção de POP (GSLB)", g.Count.ToString("N0", CultureInfo.GetCultureInfo("pt-BR")), "0", St(g.Count, 1, 20), "Consultas ao GSLB que não responderam.");
        var udp = r.Apps.Sum(a => a.BlockedUdp);
        if (udp > 0) P("Netskope", "Conexões UDP/QUIC bloqueadas", udp.ToString("N0", CultureInfo.GetCultureInfo("pt-BR")), "—", "—", "Comportamento padrão: força o navegador a usar TCP/TLS (inspecionável).");
        foreach (var c in r.Captures.Where(c => c.Packets > 0))
            P(MetricCatalog.Network, $"Captura {c.File}", $"{c.Packets:N0} pacotes · retransmissões {N(c.RetransPct)}% · RST {c.Resets:N0} · SYN sem resposta {c.HandshakeFailures}", "< 3% retransmissões",
                c.TcpDataSegments < 200 ? "—" : St(c.RetransPct, 3, 8), "Resumo da captura de pacotes do pacote de logs.");
    }

    // ---------------------------------------------------------------- roteiro do TAC

    private void CaseSummary()
    {
        var r = _r; var F = r.Facts;
        void Q(string q, string? a) { if (!string.IsNullOrWhiteSpace(a)) r.CaseSummary.Add(new(q, a)); }

        var main = r.Incidents.Where(i => i.Severity <= Severity.Warning).OrderBy(i => i.Severity).ThenByDescending(i => i.Duration).FirstOrDefault();
        var topFinding = r.Findings.FirstOrDefault(f => f.Severity <= Severity.Warning);
        Q("Qual é o sintoma principal?", main != null ? $"{main.Title} ({main.Start:dd/MM HH:mm}, {TelemetryParser.Fmt(main.Duration)})" + (main.Causes.FirstOrDefault() is Cause c ? $" — causa provável: {c.Title.ToLowerInvariant()} ({c.Confidence:0}%)." : ".")
            : topFinding?.Title ?? "Nenhum problema relevante encontrado.");

        var drops = r.NpaSessions.Where(s => s.End != null && !s.Expected).Select(s => s.End!.Value).ToList();
        var incTimes = r.Incidents.Select(i => i.Start).Concat(drops).OrderBy(t => t).ToList();
        if (incTimes.Count > 0)
        {
            var perDay = incTimes.GroupBy(t => t.Date).OrderByDescending(g => g.Count()).Take(3).Select(g => $"{g.Key:dd/MM} ({g.Count()})");
            var spanDays = (incTimes[^1] - incTimes[0]).TotalDays;
            Q("Quando começou e com que frequência?", $"Primeiro registro em {incTimes[0]:dd/MM HH:mm}, último em {incTimes[^1]:dd/MM HH:mm}; {incTimes.Count} ocorrência(s). " +
                (spanDays >= 1 ? "Intermitente, com dias piores: " + string.Join(", ", perDay) + "." : "Concentrado em um único dia."));
        }

        var svcs = new List<string>();
        if (r.Incidents.Any(i => i.Title.StartsWith("Internet", StringComparison.Ordinal)) || r.States.Any(s => s.Service == "Internet" && s.State != "Conectado")) svcs.Add("Internet (SWG)");
        if (drops.Count > 0 || r.Incidents.Any(i => i.Kind == "npa" || i.Title.StartsWith("Private Access", StringComparison.Ordinal))) svcs.Add("Private Access (NPA)");
        if (r.Incidents.Any(i => i.Kind == "tenant")) svcs.Add("comunicação com o tenant (configuração/GSLB)");
        Q("Afeta Internet, Private Access ou ambos?", svcs.Count > 0 ? string.Join(", ", svcs) + "." : "Nenhum serviço com queda registrada no período.");

        var wifi = r.DnsInterfaces.FirstOrDefault(i => i.State.Contains("conect", StringComparison.OrdinalIgnoreCase) && !KnowledgeBase.VpnInterface.IsMatch(i.Interface) && i.Interface.StartsWith("wl", StringComparison.Ordinal));
        var ssid = r.Snapshots.Select(s => s.Wifi?.Ssid).FirstOrDefault(x => x != null);
        var onprem = r.Config.FirstOrDefault(c => c.Section == "Detecção on-prem");
        Q("Onde a máquina estava?", string.Join(" ", new[]
        {
            F.OnPrem != null ? $"Estado: {F.OnPrem}." : onprem != null ? (onprem.Meaning.Contains("Off Prem") ? "Fora da empresa (Off Prem)." : onprem.Meaning.Contains("On Prem") ? "Na empresa (On Prem)." : "") : "",
            F.Egress != null ? $"IP de saída {F.Egress}." : "",
            ssid != null ? $"Wi-Fi “{ssid}”." : wifi != null ? $"Wi-Fi em {wifi.Interface}." : "",
            onprem != null ? onprem.Meaning.Replace("Como o cliente decide se está na rede da empresa.", "").Trim() : "",
        }.Where(x => x.Length > 0)));

        var changes = new List<string>();
        if (r.Config.FirstOrDefault(c => c.Item == "Versão da configuração") is ConfigItem cv) changes.Add($"configuração publicada em {cv.Value}");
        if (r.Findings.FirstOrDefault(f => f.Key == "version") is Finding v) changes.Add(v.Meaning);
        if (r.EgressHistory.Count > 1) changes.Add($"{r.EgressHistory.Count - 1} troca(s) de IP de saída");
        if (r.Findings.FirstOrDefault(f => f.Key == "netchurn") is Finding nc) changes.Add(nc.Title.ToLowerInvariant());
        var pops = r.NpaSessions.Select(s => s.Pop).Where(p => p != null).Distinct().ToList();
        if (pops.Count > 1) changes.Add($"Private Access passou pelos POPs {string.Join(", ", pops)}");
        Q("O que mudou?", changes.Count > 0 ? string.Join("; ", changes) + "." : "Nada relevante registrado nos logs.");

        var others = r.Findings.Where(f => f.Key is "conflict" or "orphan" or "overlap" or "heavyproc" or "dnssuffix").Select(f => f.Title).ToList();
        Q("Há outros softwares ou configurações interferindo?", others.Count > 0 ? string.Join("; ", others) + "." : "Nada detectado.");

        var perf = r.Performance.Where(p => p.Status is "crítico" or "atenção").Select(p => $"{p.Name}: {p.Value}").Take(4).ToList();
        Q("Como está o desempenho da máquina?", perf.Count > 0 ? string.Join("; ", perf) + "." : "Sem sinais de sobrecarga nos logs" + (r.HasTelemetry ? "." : " (sem coletor, CPU/memória/Wi-Fi contínuos não foram medidos)."));

        Q("O que os logs cobrem?", string.Join("; ", r.Coverage.Where(c => !c.Source.StartsWith("Outros", StringComparison.Ordinal)).Take(5).Select(c => $"{c.Source.Split(' ')[0]} {c.First:dd/MM HH:mm}–{c.Last:dd/MM HH:mm}")) + ".");

        var next = main?.Causes.FirstOrDefault()?.Recommendation ?? topFinding?.Action;
        Q("Próximo passo recomendado", next);
    }
}
