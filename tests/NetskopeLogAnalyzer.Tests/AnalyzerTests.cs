using System.IO.Compression;
using System.Text;
using NetskopeLogAnalyzer.Core;
using Xunit;

namespace NetskopeLogAnalyzer.Tests;

/// <summary>Testes com um pacote de logs sintético (nenhum log real é versionado).</summary>
public class AnalyzerTests
{
    private static string L(string time, string level, string src, string msg) => $"2026/11/23 {time}.123456 stAgentSvc p1a2b t3c4d {level} {src} {msg}";

    private static byte[] SyntheticPackage()
    {
        var debug = new StringBuilder();
        debug.AppendLine(L("10:00:00", "info", "main.cpp:145", "main ======= stAgentSvc 141.1.14.2843 starting ======"));
        debug.AppendLine(L("10:00:01", "error", "nsOpenSSLProviderMgr.cpp:345", "nsOpenSSLProviderMgr getFipsConfigPath: unsupported platform"));
        debug.AppendLine(L("10:00:05", "info", "tunnel.cpp:1296", "nsTunnel TLS Tunneling flow to host: achecker-acme.goskope.com, addr: 163.116.151.182:443"));
        debug.AppendLine(L("10:00:06", "info", "clientStatusHandler.cpp:825", "clientStatusHandler [sessId 1] Caching client status, event: Tunnel Up, actor: System, time: 1, service: 1"));
        // timeouts espalhados por 20 minutos, longe do início do serviço
        for (var i = 0; i < 12; i++)
            debug.AppendLine(L($"10:{10 + i:00}:00", "warn", "nsHTTPClient.cpp:537", "downloader curl_easy_perform failed, code 28, error Timeout was reached"));
        debug.AppendLine(L("10:30:00", "info", "clientStatusHandler.cpp:825", "clientStatusHandler [sessId 1] Caching client status, event: User Disabled, actor: User, time: 2, service: 1"));
        debug.AppendLine(L("10:31:00", "error", "weird.cpp:10", "Something totally new happened 42 times at 10.0.0.1"));
        debug.AppendLine(L("10:31:01", "error", "weird.cpp:10", "Something totally new happened 43 times at 10.0.0.2"));

        var npa = "[HOST:2026-11-23 10:20:00.467 -03:00] t154582 [error] neClientTransportHandler.cpp:183:operator()():0x0 Connection to GW gateway.npa.goskope.com (1.2.3.4) is terminated or failed with len = 0 or isErr = 0.\n";

        var net = """

            $ /usr/sbin/ip -d address
            1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
            3: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
            4: fctvpnabc123: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500
            $ /usr/bin/nmcli dev show
            GENERAL.DEVICE:                         wlo1
            IP4.DNS[1]:                             192.168.0.1
            GENERAL.DEVICE:                         fctvpnabc123
            IP4.DNS[1]:                             10.1.1.140
            $ /usr/bin/ps aux
            root  1006  0.0  0.0 1414520 7084 ?  Ssl 15:46 0:00 /opt/forticlient/fctsched
            root   974  8.3  0.2 1975528 84100 ? Ssl 15:46 0:51 /opt/netskope/stagent/stAgentSvc
            """;

        var install = "NSClient Version: 141.1.14.2843\n  PRETTY_NAME: \"Ubuntu 24.04.4 LTS\"\nlibfoo ------- [not installed]\nlibbar ------- [not installed]\nlibbaz can replace libbar\n";

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, string content)
            {
                var e = zip.CreateEntry(name);
                using var w = new StreamWriter(e.Open(), new UTF8Encoding(false));
                w.Write(content);
            }
            Add("nsdebuglog.log", debug.ToString());
            Add("npadebuglog.log", npa);
            Add("network-state.log", net);
            Add("install.log", install);
            Add("nsuser.conf", """{ "userConfig": { "failCloseStatus": "true" } }""");
            Add("authtoken.pem", "-----BEGIN CERTIFICATE-----");
        }
        return ms.ToArray();
    }

    private static AnalysisResult Run()
    {
        var items = new List<SourceItem>();
        var skipped = new List<string>();
        Analyzer.ExtractZip(SyntheticPackage(), "", items, skipped);
        Assert.Empty(skipped);
        return new Analyzer().AnalyzeItems(items);
    }

    private static Finding Get(AnalysisResult r, string key) => Assert.Single(r.Findings, f => f.Key == key);

    [Fact]
    public void ParsesLinesAndTimeRange()
    {
        var r = Run();
        Assert.True(r.Entries.Count >= 18);
        Assert.Equal(new DateTime(2026, 11, 23, 10, 0, 0).AddTicks(1234560), r.Start);
        Assert.Contains(r.Files, f => f.BaseName == "npadebuglog.log" && f.Errors == 1);
        Assert.Contains("authtoken.pem", r.Skipped);
    }

    [Fact]
    public void SustainedTimeoutsAreCritical()
    {
        var f = Get(Run(), "timeout");
        Assert.Equal(12, f.Count);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains(f.Steps, s => s.Command != null && s.Command.Contains("addon-acme.goskope.com"));
    }

    [Fact]
    public void DetectsOrphanVpnInterfaceWithDns()
    {
        var f = Get(Run(), "orphan");
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains("10.1.1.140", f.Meaning);
        Assert.Contains(f.Steps, s => s.Command == "sudo ip link delete fctvpnabc123");
    }

    [Fact]
    public void DetectsFortiClientRunning()
    {
        var f = Get(Run(), "conflict");
        Assert.StartsWith("FortiClient", f.Title);
    }

    [Fact]
    public void BuildsFactsAndEvents()
    {
        var r = Run();
        Assert.Equal("acme", r.Facts.TenantHost);
        Assert.Equal("141.1.14.2843", r.Facts.Version);
        Assert.Equal("Ubuntu 24.04.4 LTS", r.Facts.OsName);
        Assert.Equal(ClientOs.Linux, r.DetectedOs);
        Assert.Equal("User Disabled", r.Facts.Services[1].Event);
        Assert.Contains(r.Events, e => e.Label == "Serviço iniciado");
        Assert.Contains(r.Events, e => e.Label == "Desabilitado pelo usuário");
        Get(r, "failclose");
        Get(r, "userdis");
        Get(r, "npagw");
    }

    [Fact]
    public void MissingDependenciesIgnoreReplacedPackages()
    {
        var f = Get(Run(), "deps");
        Assert.Equal(new[] { "libfoo" }, f.MissingPackages);
    }

    [Fact]
    public void NoiseAndUnclassifiedAreSeparated()
    {
        var r = Run();
        Assert.Equal(Severity.Noise, Get(r, "fips").Severity);
        var u = Assert.Single(r.Unclassified);
        Assert.Equal(2, u.Count);
        Assert.Contains("<ip>", u.Key);
    }

    [Fact]
    public void ReportContainsResolution()
    {
        var md = Report.ToMarkdown(Run());
        Assert.Contains("Como resolver", md);
        Assert.Contains("problemas críticos", md);
    }
}
