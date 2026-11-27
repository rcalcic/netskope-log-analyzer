using System.Text;
using NetskopeLogAnalyzer.Core;
using Xunit;

namespace NetskopeLogAnalyzer.Tests;

/// <summary>4.2: recência, duplicados entre pacotes, HTTP com contexto, histórico local, novas regras (dados sintéticos).</summary>
public class V42Tests
{
    private static SourceItem Item(string name, string text) => new(name, Encoding.UTF8.GetBytes(text));
    private static string L(string ts, string proc, string lvl, string src, string msg) => $"{ts} {proc} t1 {lvl} {src} {msg}\n";

    private static string Debug(params (string Ts, string Msg)[] lines)
        => string.Concat(lines.Select(l => L(l.Ts, "stAgentSvc p10", "error", "x.cpp:1", l.Msg)));

    [Fact]
    public void OldCriticalsBecomeHistorical()
    {
        var text = string.Concat(Enumerable.Range(0, 12).Select(i => L($"2026/11/01 10:{i:00}:00.000001", "stAgentSvc p10", "warn", "nsHTTPClient.cpp:1", "downloader curl_easy_perform failed, code 28, error Timeout was reached")))
                 + L("2026/11/05 10:00:00.000001", "stAgentSvc p10", "info", "main.cpp:1", "main ok");
        var r = new Analyzer().AnalyzeItems(new[] { Item("nsdebuglog.log", text) });
        var f = r.Findings.First(x => x.Key == "timeout");
        Assert.True(f.Historical);
        Assert.Equal(0, r.Count(Severity.Critical));
        Assert.Contains("histórico", Report.Verdict(r));
        Assert.Contains("· histórico]", Report.ToMarkdown(r));
    }

    [Fact]
    public void SameFileInTwoPackagesCountsOnce()
    {
        var text = Debug(("2026/11/05 10:00:00.000001", "downloader curl_easy_perform failed, code 28, error Timeout was reached"),
                         ("2026/11/05 10:01:00.000001", "downloader curl_easy_perform failed, code 28, error Timeout was reached"));
        var other = Debug(("2026/11/05 10:01:00.000001", "downloader curl_easy_perform failed, code 28, error Timeout was reached"),
                          ("2026/11/05 10:02:00.000001", "downloader curl_easy_perform failed, code 28, error Timeout was reached"));
        var r = new Analyzer().AnalyzeItems(new[] { Item("a/nsdebuglog.log", text), Item("b/nsdebuglog.log", text), Item("b/nsdebuglog.1.log", other) });
        Assert.Equal(3, r.Findings.First(x => x.Key == "timeout").Count);
        Assert.Contains(r.DataGaps, g => g.Contains("repetid"));
    }

    [Fact]
    public void LongPollForbiddenIsInfoAndOtherRequestsAreNamed()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < 30; i++)
        {
            sb.Append(L($"2026/11/05 10:{i:00}:00.000001", "stAgentUI p20", "info", "restapi.cpp:259", "restapi longpoll connection headers:"));
            sb.Append(L($"2026/11/05 10:{i:00}:01.000001", "stAgentUI p20", "warn", "nsHTTPClient.cpp:550", "downloader curl_easy_perform failed, code 22, error HTTP response code said error"));
            sb.Append(L($"2026/11/05 10:{i:00}:01.000002", "stAgentUI p20", "warn", "nsHTTPClient.cpp:561", "downloader Got HTTP response code: 403"));
        }
        var r = new Analyzer().AnalyzeItems(new[] { Item("nsAppUI.log", sb.ToString()) });
        var f = r.Findings.First(x => x.Key == "http");
        Assert.Equal(30, f.Count);                       // a linha "code 22" não conta em dobro
        Assert.Equal(Severity.Noise, f.Severity);
        Assert.Contains("notificações", f.Title);

        sb.Append(L("2026/11/05 11:00:00.000001", "stAgentSvc p10", "info", "restapi.cpp:115", "restapi Downloading NPA-gslb pop info"));
        sb.Append(L("2026/11/05 11:00:01.000001", "stAgentSvc p10", "warn", "nsHTTPClient.cpp:548", "downloader Got HTTP response code: 403"));
        r = new Analyzer().AnalyzeItems(new[] { Item("nsAppUI.log", sb.ToString()) });
        f = r.Findings.First(x => x.Key == "http");
        Assert.Contains(f.Details, d => d.Key == "NPA-gslb pop info: HTTP 403");
        Assert.StartsWith("Tenant recusou requisições do cliente (além de 30", f.Title);
        Assert.Equal(1, f.Count);
    }

    [Fact]
    public void NewLinuxRules()
    {
        var text = Debug(
            ("2026/11/05 10:00:00.000001", "nsUtils boost::filesystem::copy_file: No such file or directory: \"/usr/local/share/ca-certificates/nscacert.crt\", \"/etc/firefox/policies/nscacert.crt\""),
            ("2026/11/05 10:00:01.000001", "nsFltThread Failed to send data to thread, -1-16-11"),
            ("2026/11/05 10:00:02.000001", "nsDnsMgr failed to bypass DNS query to uplink server 10.70.97.109, err = 11"),
            ("2026/11/05 10:00:03.000001", "tunnelPolicyMgr invalid params"));
        var r = new Analyzer().AnalyzeItems(new[] { Item("nsdebuglog.log", text) });
        Assert.Contains(r.Findings, f => f.Key == "sysca" && f.Steps.Count > 0);
        Assert.DoesNotContain(r.Findings, f => f.Key == "firefox");
        Assert.Contains(r.Findings, f => f.Key == "fltqueue" && f.Details.Any(d => d.Key == "Rajada em 05/11 10:00"));
        Assert.Contains(r.Findings, f => f.Key == "dnsbypass" && f.Details.Any(d => d.Key == "Servidor DNS 10.70.97.109"));
        Assert.Contains(r.Findings, f => f.Key == "nopid" && f.Severity == Severity.Noise);
    }

    [Fact]
    public void TenantIsNotAPop()
    {
        var r = new Analyzer().AnalyzeItems(new[]
        {
            Item("nsdebuglog.log", L("2026/11/05 10:00:00.000001", "stAgentSvc p10", "info", "x.cpp:1", "gslb [NSClient] Pop:BR-SAO1;1.0;gateway-sao1.goskope.com;163.116.233.35;1;BR;inCountryFlag=true;proxy=")),
            Item("nsconfig.json", "{\"nsgw\":{\"host\":\"gateway-acme.goskope.com\"}}"),
        });
        Assert.Equal("acme", r.Facts.TenantHost);
    }

    [Fact]
    public void HistoryComparesWithPreviousPackage()
    {
        var path = Path.Combine(Path.GetTempPath(), "nla-hist-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var store = new HistoryStore(path);
            var a = new HistoryEntry { Host = "PC1", End = new DateTime(2026, 11, 1), Version = "141.0", Critical = 2 };
            a.Findings.Add(new HistoryFinding("timeout", "Timeouts", Severity.Critical, 5, null));
            a.Findings.Add(new HistoryFinding("dns", "DNS", Severity.Warning, 5, null));
            Assert.Null(store.Record(a));
            var b = new HistoryEntry { Host = "pc1", End = new DateTime(2026, 11, 5), Version = "142.0", Critical = 1 };
            b.Findings.Add(new HistoryFinding("timeout", "Timeouts", Severity.Critical, 1, null));
            b.Findings.Add(new HistoryFinding("sysca", "CA", Severity.Warning, 1, null));
            var c = store.Record(b)!;
            Assert.Equal(new[] { "CA" }, c.New);
            Assert.Equal(new[] { "DNS" }, c.Resolved);
            Assert.Equal(new[] { "Timeouts" }, c.Persistent);
            Assert.Contains("Versão do cliente: 141.0 → 142.0", c.Changes);
            store.Record(b);                       // mesmo pacote de novo não duplica
            Assert.Equal(2, store.Load().Count);
            var other = new HistoryEntry { Host = "PC2", End = new DateTime(2026, 11, 5) };
            Assert.Null(store.Record(other));
        }
        finally { File.Delete(path); }
    }
}
