using System.Text;
using NetskopeLogAnalyzer.Core;
using Xunit;

namespace NetskopeLogAnalyzer.Tests;

/// <summary>Telemetria, snapshots, métricas dos logs, baseline, score e causa raiz (dados sintéticos).</summary>
public class V3Tests
{
    private static string L(string time, string level, string src, string msg) => $"2026/11/23 {time}.100000 stAgentSvc p1 t1 {level} {src} {msg}";

    private static string NetskopeLog()
    {
        var sb = new StringBuilder();
        sb.AppendLine(L("10:00:00", "info", "main.cpp:145", "main ======= stAgentSvc 141.1.14.2843 starting ======"));
        sb.AppendLine(L("10:00:02", "info", "GatewaySelection.cpp:164", "gslb [NPA] Pop:BR-SAO1;198.1;gateway.npa.goskope.com;163.116.224.49;0;BR;inCountryFlag=true;proxy="));
        sb.AppendLine(L("10:00:03", "info", "GatewaySelection.cpp:455", "gslb [NPA]: calculate() rtt:163.116.224.49 duration:9"));
        sb.AppendLine(L("10:00:03", "info", "GatewaySelection.cpp:569", "gslb [NPA]: post client rtt pop:BR-SAO1 ip:163.116.224.49 rtt:9"));
        sb.AppendLine(L("10:00:03", "info", "GatewaySelection.cpp:569", "gslb [NPA]: post client rtt pop:BR-GIG1 ip:163.116.228.122 rtt:65"));
        sb.AppendLine(L("10:00:04", "info", "GatewaySelection.cpp:455", "gslb [NSClient]: calculate() rtt:163.116.233.72 duration:12"));
        sb.AppendLine(L("10:00:05", "info", "x.cpp:1", "egress_ip\":\"177.92.52.39\""));
        sb.AppendLine(L("10:00:06", "info", "c.cpp:825", "clientStatusHandler [sessId 1] Caching client status, event: Tunnel Up, actor: System, time: 1, service: 1"));
        for (var i = 0; i < 5; i++)
            sb.AppendLine(L($"10:0{1 + i}:00", "info", "tunnel.cpp:1296", "nsTunnel TLS Tunneling flow from addr: 100.65.0.2:5000, process: chrome to host: teams.microsoft.com, addr: 52.123.128.14:443 to nsProxy"));
        sb.AppendLine(L("10:02:30", "info", "bypassAppMgr.cpp:1720", "BypassAppMgr bypassing flow to exception host: www.youtube.com, process: chrome, Dest IP: 1.2.3.4, Dest Port: 443, Src IP: 10.0.0.2"));
        sb.AppendLine(L("10:02:31", "info", "bypassAppMgrUDP.cpp:250", "BypassAppMgr Blocking UDP connection from process: chrome, dest IP:142.251.154.119:443, src IP 192.168.18.13:38365"));
        for (var i = 0; i < 6; i++)
            sb.AppendLine(L($"10:10:{i * 5:00}", "warn", "nsHTTPClient.cpp:537", "downloader curl_easy_perform failed, code 28, error Timeout was reached"));
        sb.AppendLine(L("10:20:00", "info", "x.cpp:1", "egress_ip\":\"200.1.1.1\""));
        sb.AppendLine(L("10:30:00", "info", "c.cpp:825", "clientStatusHandler [sessId 1] Caching client status, event: User Disabled, actor: User, time: 2, service: 1"));
        sb.AppendLine(L("10:40:00", "info", "x.cpp:1", "nsAgentSvc ======= Log collection complete ======="));
        return sb.ToString();
    }

    private static string Telemetry()
    {
        var sb = new StringBuilder();
        sb.AppendLine("""{"t":"2026-11-23T10:00:00-03:00","k":"meta","host":"PC01","os":"Windows 11 23H2","cpu":"Intel i7","cores":8,"ramMb":16000,"collector":"3.0.0","interval":30}""");
        var t = new DateTime(2026, 11, 23, 10, 0, 0);
        for (var i = 0; i <= 80; i++)
        {
            var ts = t.AddSeconds(30 * i);
            var iso = ts.ToString("yyyy-MM-ddTHH:mm:ss") + "-03:00";
            var spike = ts >= new DateTime(2026, 11, 23, 10, 9, 0) && ts <= new DateTime(2026, 11, 23, 10, 11, 0);
            sb.AppendLine($$"""{"t":"{{iso}}","k":"cpu","v":{{(spike ? 98 : 20 + i % 5)}}}""");
            sb.AppendLine($$"""{"t":"{{iso}}","k":"mem","usedPct":{{55 + i % 3}},"availMb":7000,"totalMb":16000}""");
            var down = ts >= new DateTime(2026, 11, 23, 10, 9, 30) && ts < new DateTime(2026, 11, 23, 10, 10, 30);
            sb.AppendLine(down
                ? $$"""{"t":"{{iso}}","k":"wifi","connected":false}"""
                : $$"""{"t":"{{iso}}","k":"wifi","connected":true,"ssid":"Corp","bssid":"aa:bb:cc:dd:ee:01","signal":{{(ts.Minute == 9 ? 30 : 85)}},"rx":400,"tx":300,"band":"5 GHz"}""");
            sb.AppendLine($$"""{"t":"{{iso}}","k":"ping","label":"POP","rtt":{{(down ? 400 : 12)}},"loss":{{(down ? 50 : 0)}},"jitter":2}""");
            if (i % 2 == 0)
                sb.AppendLine($$"""{"t":"{{iso}}","k":"http","label":"office","dns":10,"tcp":15,"tls":40,"ttfb":180,"total":250,"code":200,"ok":true}""");
            if (i % 4 == 0)
                sb.AppendLine($$"""{"t":"{{iso}}","k":"procs","top":[{"n":"{{(spike ? "MsMpEng" : "chrome")}}","cpu":{{(spike ? 85 : 10)}},"memMb":900}]}""");
        }
        sb.AppendLine("""{"t":"2026-11-23T10:05:00-03:00","k":"trace","target":"gateway-acme.goskope.com","hops":[{"ttl":1,"ip":"192.168.0.1","rtt":2},{"ttl":2,"ip":"200.200.1.1","rtt":8},{"ttl":3,"ip":"163.116.224.49","rtt":12}]}""");
        return sb.ToString();
    }

    private static AnalysisResult Run(bool withTelemetry = true)
    {
        var items = new List<SourceItem> { new("nsdebuglog.log", Encoding.UTF8.GetBytes(NetskopeLog())) };
        if (withTelemetry) items.Add(new("nla-telemetry-20261123.jsonl", Encoding.UTF8.GetBytes(Telemetry())));
        return new Analyzer().AnalyzeItems(items);
    }

    [Fact]
    public void ExtractsPopLatencyFromGslb()
    {
        var r = Run(false);
        Assert.Contains(r.Pops, p => p.Service == "Private Access" && p.Pop == "BR-SAO1" && p.Samples == 1 && p.Min == 9);
        Assert.Contains(r.Pops, p => p.Service == "Private Access" && p.Pop == "BR-GIG1");
        Assert.Contains(r.Pops, p => p.Service == "Internet" && p.Ip == "163.116.233.72");
        Assert.True(r.Series.ContainsKey("pop.best:Private Access"));
    }

    [Fact]
    public void ExtractsFlowsBypassAndUdpBlocks()
    {
        var r = Run(false);
        var teams = Assert.Single(r.Apps, a => a.Host == "teams.microsoft.com");
        Assert.Equal(5, teams.Tunneled);
        Assert.Contains(r.Apps, a => a.Host == "www.youtube.com" && a.Bypassed == 1);
        Assert.Contains(r.Apps, a => a.BlockedUdp == 1 && a.Host.Contains("UDP"));
        Assert.True(r.Series["flows.tunnel"].Points.Sum(p => p.Value) >= 5);
    }

    [Fact]
    public void EgressChangeAndTunnelStates()
    {
        var r = Run(false);
        Assert.Contains(r.Events, e => e.Label == "IP de saída mudou");
        Assert.Contains(r.States, s => s.Service == "Internet" && s.State == "Conectado");
        Assert.Contains(r.States, s => s.Service == "Internet" && s.State == "Desabilitado pelo usuário");
        Assert.InRange(r.Availability["Internet"], 50, 99);
    }

    [Fact]
    public void WithoutTelemetryReportsDataGap()
    {
        var r = Run(false);
        Assert.False(r.HasTelemetry);
        Assert.Contains(r.DataGaps, g => g.Contains("não traz séries contínuas"));
        Assert.NotNull(r.Score); // ainda há score parcial (Netskope + latência até o POP)
    }

    [Fact]
    public void ParsesTelemetryAndBuildsBaseline()
    {
        var r = Run();
        Assert.True(r.HasTelemetry);
        Assert.Equal("PC01", r.Facts.Host);
        Assert.Equal("Intel i7", r.Device["Processador"]);
        var cpu = r.Series["cpu"];
        Assert.Equal(81, cpu.Stats!.Count);
        Assert.Equal(98, cpu.Stats.Max);
        Assert.Contains(r.Anomalies, a => a.SeriesKey == "cpu" && a.Critical);
        Assert.Contains(r.Events, e => e.Label == "Wi-Fi desconectado");
        Assert.Contains(r.Events, e => e.Label == "Wi-Fi conectado");
        Assert.Single(r.Paths);
        Assert.Equal("Netskope", r.Paths[0].Hops[^1].Segment);
        Assert.Equal("Rede local", r.Paths[0].Hops[0].Segment);
        Assert.True(r.Series.ContainsKey("http.ttfb:office"));
    }

    [Fact]
    public void ExperienceScoreDropsDuringTheProblem()
    {
        var r = Run();
        Assert.NotEmpty(r.Scores);
        var good = r.Scores.First(s => s.Start == new DateTime(2026, 11, 23, 10, 0, 0));
        var bad = r.Scores.First(s => s.Start == new DateTime(2026, 11, 23, 10, 5, 0)); // janela 10:05–10:10 pega o início da queda
        var worst = r.Scores.Where(s => s.Start >= new DateTime(2026, 11, 23, 10, 5, 0) && s.Start <= new DateTime(2026, 11, 23, 10, 10, 0)).Min(s => s.Score);
        Assert.True(good.Score >= 70, $"bom={good.Score}");
        Assert.True(worst <= good.Score - 15, $"pior={worst} bom={good.Score}");
        Assert.NotNull(bad.Device);
    }

    [Fact]
    public void RootCausePointsToWifiForTimeoutBurst()
    {
        var r = Run();
        var inc = r.Incidents.First(i => i.Start >= new DateTime(2026, 11, 23, 10, 8, 0) && i.Start <= new DateTime(2026, 11, 23, 10, 11, 0));
        Assert.Equal("Wi-Fi", inc.Causes[0].Category);
        Assert.Contains(inc.Causes, c => c.Category == "Dispositivo" && c.Evidence.Contains("MsMpEng"));
        Assert.Contains(inc.Evidence, e => e.Text.Contains("Wi-Fi desconectado"));
    }

    [Fact]
    public void RootCauseUserDisabled()
    {
        var r = Run();
        var inc = r.Incidents.First(i => i.Title.Contains("desabilitado pelo usuário"));
        Assert.Equal("Ação do usuário", inc.Causes[0].Category);
    }

    [Fact]
    public void SnapshotParsersUnderstandPortugueseWindowsAndLinux()
    {
        var netsh = """

            Há 1 interface no sistema:

                Nome                   : Wi-Fi
                Estado                 : conectado
                SSID                   : Corp
                AP BSSID               : aa:bb:cc:dd:ee:ff
                Tipo de rádio          : 802.11ax
                Banda                  : 5 GHz
                Canal                  : 36
                Taxa de recepção (Mbps)  : 1201
                Taxa de transmissão (Mbps) : 960
                Sinal                  : 92%
            """;
        var s1 = SnapshotParsers.Parse("netsh-wlan.txt", netsh, null)!;
        Assert.Equal("Corp", s1.Wifi!.Ssid);
        Assert.Equal(92, s1.Wifi.SignalPct);
        Assert.Equal(1201, s1.Wifi.RxMbps);
        Assert.Equal("5 GHz", s1.Wifi.Band);

        var sysinfo = "Nome do host:                              PC01\nNome do sistema operacional:               Microsoft Windows 11 Pro\nMemória física total:                      16.236 MB\nMemória física disponível:                 4.120 MB\n";
        var s2 = SnapshotParsers.Parse("systeminfo.txt", sysinfo, null)!;
        Assert.Equal(16236, s2.MemTotalMb);
        Assert.Equal(4120, s2.MemAvailMb);
        Assert.Equal("Microsoft Windows 11 Pro", s2.System["Sistema"]);

        var linux = "$ df -h\nSist. Arq.      Tam. Usado Disp. Uso% Montado em\n/dev/nvme0n1p2  468G  420G   24G  95% /\ntmpfs           3,1G  2,0M  3,1G   1% /run\n$ free -m\n               total        usada       livre    compart.  buff/cache  disponível\nMem.:          15707        9000        1000         500        5707        6200\n";
        var s3 = SnapshotParsers.Parse("network-state.log", linux, null)!;
        Assert.Single(s3.Disks);
        Assert.Equal(95, s3.Disks[0].UsedPct);
        Assert.Equal(468, s3.Disks[0].TotalGb);
        Assert.Equal(6200, s3.MemAvailMb);

        var tasklist = "Nome da imagem                 PID Nome da sessão  Sessão#  Uso de memória\n========================= ======== ================ =========== ============\nchrome.exe                    1234 Console                    1    350.120 K\nchrome.exe                    1235 Console                    1    100.000 K\n";
        var s4 = SnapshotParsers.Parse("tasklist.txt", tasklist, null)!;
        var chrome = Assert.Single(s4.Processes);
        Assert.Equal(2, chrome.Instances);
        Assert.InRange(chrome.MemMb, 439, 440);
    }
}
