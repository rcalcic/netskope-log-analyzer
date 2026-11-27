using System.Buffers.Binary;
using System.Text;
using NetskopeLogAnalyzer.Core;
using Xunit;

namespace NetskopeLogAnalyzer.Tests;

/// <summary>Visão de TAC: sessões NPA, mudanças de rede, DNS, sobreposição, configuração, capturas e desempenho (dados sintéticos).</summary>
public class V31Tests
{
    private static readonly DateTime T0 = new(2026, 11, 23, 8, 0, 0);

    private static string Npa(DateTime t, string level, string msg) => $"[PC01:{t:yyyy-MM-dd HH:mm:ss.fff} -03:00] t1 [{level}] file.cpp:1:f():0x0 {msg}";
    private static string Svc(DateTime t, string level, string msg) => $"{t:yyyy/MM/dd HH:mm:ss}.100000 stAgentSvc p1 t1 {level} file.cpp:1 {msg}";

    private static void Connect(StringBuilder sb, DateTime t, string ip, string pop, int rtt)
    {
        sb.AppendLine(Npa(t, "info", "NPA Client is connecting to Primary Tenant."));
        sb.AppendLine(Npa(t.AddSeconds(1), "info", $"GW FQDN = gateway.npa.goskope.com, IP = {ip}, POP = {pop}, RTT = {rtt} ms."));
        sb.AppendLine(Npa(t.AddSeconds(1), "info", $"Starting handler with GW gateway.npa.goskope.com ({ip}:443, pop:{pop}, type:GSLB, newIp:1)."));
        sb.AppendLine(Npa(t.AddSeconds(2), "info", $"TLS client established connection TLS version:TLSv1.2 server:{ip}:443 cipher:ECDHE-RSA-AES256-GCM-SHA384"));
    }

    private static string NpaLog()
    {
        var sb = new StringBuilder();
        // sessão 1: 08:00 → queda por keepalive às 08:40; nova tentativa só 4 min depois; reconecta às 08:44
        Connect(sb, T0, "163.116.224.49", "BR-SAO1", 9);
        long re = 10;
        for (var i = 1; i <= 7; i++)
        {
            re += i == 7 ? 300 : 5;
            sb.AppendLine(Npa(T0.AddMinutes(5 * i).AddMilliseconds(3), "info", $"NPAGW 163.116.224.49: RETRANS:{re}, RTT:{(i == 7 ? 900 : 12)}ms, HIST:(0,0,1,183,25,2,2,0,1,0,0,0,1,0,0,0)."));
            sb.AppendLine(Npa(T0.AddMinutes(5 * i).AddSeconds(1), "info", "PubDns Req = 100, WildDns Req = 0, PubDns Resp = 100 [NOERROR:10, FORMERR:0, SERVFAIL:0, NXDOMAIN:90, NOTIMP:0, REFUSED:0, OTHERS:0], WildDns Resp = 0"));
        }
        var drop = T0.AddMinutes(40);
        sb.AppendLine(Npa(drop, "error", "keepAlive fails with 15 tries."));
        sb.AppendLine(Npa(drop, "info", "NPA Tunnel is disconnected."));
        sb.AppendLine(Npa(drop, "error", "Connection to GW gateway.npa.goskope.com (163.116.224.49) is terminated or failed with len = 0 or isErr = 0."));
        Connect(sb, drop.AddMinutes(4), "163.116.228.122", "BR-GIG1", 6);
        // DNS com sufixo indevido
        foreach (var n in new[] { "gateway.gslb.goskope.com", "events.goskope.com", "teams.microsoft.com", "login.microsoftonline.com" })
            for (var k = 0; k < 10; k++)
                sb.AppendLine(Npa(drop.AddMinutes(5).AddSeconds(k), "info", $"DNS over UDP built a empty reply for DNS type AAAA, name = {n}.corp.example.com."));
        // reautenticação programada às 09:30
        var reauth = T0.AddMinutes(90);
        sb.AppendLine(Npa(reauth, "error", "Shutdown packet received from gateway. Reason = [Active session has expired. Please Authenticate again to continue]"));
        sb.AppendLine(Npa(reauth, "info", "NPA Tunnel is disconnected."));
        Connect(sb, reauth.AddMinutes(1), "163.116.224.49", "BR-SAO1", 8);
        // cliente para o NPA às 10:00
        sb.AppendLine(Npa(T0.AddMinutes(120), "info", "Will shutdown NPA handler and dispatch thread, tunnelId = 5545. npaClientHandlerStop"));
        sb.AppendLine(Npa(T0.AddMinutes(121), "info", "Set NPA log level to 2"));
        return sb.ToString();
    }

    private static string SvcLog()
    {
        var sb = new StringBuilder();
        sb.AppendLine(Svc(T0, "info", "main ======= stAgentSvc 142.0.0.2821 starting ======"));
        for (var i = 0; i < 60; i++)
            sb.AppendLine(Svc(T0.AddSeconds(30 * i), "info", "KernelUserShim network status changed, GSLB egress IP refresh requested"));
        for (var i = 0; i < 40; i++)
            sb.AppendLine(Svc(T0.AddMinutes(10).AddSeconds(15 * i), "info", $"gslb [NSClient]: post client rtt pop:BR-SAO1 ip:163.116.224.35 rtt:{12 + i % 3}"));
        for (var i = 0; i < 40; i++)
            sb.AppendLine(Svc(T0.AddMinutes(10).AddSeconds(15 * i + 1), "info", $"gslb [NSClient]: post client rtt pop:BR-GIG1 ip:163.116.228.35 rtt:{25 + i % 3}"));
        sb.AppendLine(Svc(T0.AddMinutes(39).AddSeconds(50), "warn", "downloader curl_easy_perform failed, code 28, error Timeout was reached"));
        sb.AppendLine(Svc(T0.AddMinutes(39).AddSeconds(50), "error", "restapi Failed to download NSClient-gslb pop info, Error: -2"));
        sb.AppendLine(Svc(T0.AddMinutes(39).AddSeconds(51), "error", "gslb GSLB fetch failed, resetting Egress IP"));
        sb.AppendLine(Svc(T0.AddMinutes(41), "info", "egress_ip\":\"177.92.52.39\""));
        for (var i = 0; i < 200; i++) sb.AppendLine(Svc(T0.AddMinutes(30).AddSeconds(i), "error", "nsRtNetlink ipRouteGet: failed to get response"));
        sb.AppendLine(Svc(T0.AddMinutes(122), "info", "nsAgentSvc ======= Log collection complete ======="));
        return sb.ToString();
    }

    private const string NetworkState = """
        $ /usr/sbin/ip -d address
        1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
            inet 127.0.0.1/8 scope host lo
        3: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
            inet 192.168.18.13/24 brd 192.168.18.255 scope global dynamic noprefixroute wlo1
        4: fctvpn1077f7c3: <NO-CARRIER,POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 500
            inet 10.1.224.43/32 scope global noprefixroute fctvpn1077f7c3
        13: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
            inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
        20: sta0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
            inet 100.65.0.2/16 scope global sta0
        410: vethbc499af@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-0a309680498d state UP group default
        $ /usr/sbin/ip route show table 9
        default dev sta0 scope link metric 100
        10.0.0.0/8 dev sta0 scope link metric 100
        172.16.0.0/12 dev sta0 scope link metric 100
        $ /usr/bin/nmcli dev show
        GENERAL.DEVICE:                         wlo1
        GENERAL.STATE:                          100 (conectado)
        IP4.DNS[1]:                             192.168.18.1
        GENERAL.DEVICE:                         fctvpn1077f7c3
        GENERAL.STATE:                          100 (conectado)
        IP4.DNS[1]:                             10.1.55.119
        IP4.SEARCHES[1]:                        corp.example.com
        $ /usr/bin/ps aux
        USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
        root         100 43.5  2.0 100000 700000 ?       Sl   08:51 165:06 falcon-sensor-bpf
        root         200  4.4  0.2 100000 80000 ?        Ssl  08:51  16:54 /opt/netskope/stagent/stAgentSvc
        root         300  0.1  0.3 100000 90000 ?        Ssl  08:51   0:32 /usr/bin/dockerd -H fd://
        root         301  0.0  0.0 100000 9000 ?         Sl   08:51   0:01 /usr/bin/containerd-shim-runc-v2 -namespace moby -id aaa
        root         302  0.0  0.0 100000 9000 ?         Sl   15:09   0:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id bbb
        root         303  0.0  0.0 100000 9000 ?         Sl   15:09   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 27017 -container-ip 172.18.0.2 -container-port 27017
        """;

    private const string NsConfig = """
        {"cache":{"device":{"hostname":"PC01","os":"Linux","os_version":"24.04","ns_version":"142.0.0.2821"},"lastClientConfigVersion":"2026-11-23 07:00:00"},
         "clientConfig":{"configurationName":"Default tenant config","allowClientDisabling":true,"enableClientSelfProtection":false,"pdem_subscription_level":"None",
                         "clientUpdate":{"allowAutoUpdate":true,"goldenReleaseVersion":""},"metrics":{"enable":false}}}
        """;

    private const string NsSteering = """
        {"steering_config_name":"Netskope Client Enabled","traffic_mode":"cloud","dynamic_steering":1,"private_apps_off_prem":1,"private_apps_on_prem":0,
         "domains":["achecker-acme.goskope.com"],
         "onprem_labels":[{"name":"IP_Matriz","config":{"onpremcheck":{"onprem_detection_method":"2","onprem_egress_ips":["187.32.242.100"]}}}]}
        """;

    private static AnalysisResult Run(params (string Name, string Text)[] files)
        => new Analyzer().AnalyzeItems(files.Select(f => new SourceItem(f.Name, Encoding.UTF8.GetBytes(f.Text))).ToList());

    private static AnalysisResult Full() => Run(("npadebuglog.log", NpaLog()), ("nsdebuglog.log", SvcLog()), ("network-state.log", NetworkState),
        ("nsconfig.json", NsConfig), ("nssteering.json", NsSteering));

    [Fact]
    public void NpaSessions_ReasonsDowntimeAndReauth()
    {
        var r = Full();
        Assert.True(r.NpaSessions.Count >= 3);
        var drop = r.NpaSessions.First(s => s.EndReason != null && s.EndReason.StartsWith("Gateway parou", StringComparison.Ordinal));
        Assert.False(drop.Expected);
        Assert.Equal("BR-SAO1", drop.Pop);
        Assert.NotNull(drop.Downtime);
        Assert.InRange(drop.Downtime!.Value.TotalMinutes, 3.5, 5);
        Assert.Equal(1, drop.Attempts);
        Assert.Contains(r.NpaSessions, s => s.Expected && !s.Stopped && s.EndReason!.Contains("reautenticação", StringComparison.Ordinal));
        Assert.Contains(r.NpaSessions, s => s.Stopped);
        var f = Assert.Single(r.Findings, x => x.Key == "npadrops");
        Assert.Contains("tenta reconectar", f.Meaning, StringComparison.Ordinal);
        Assert.Contains(r.Findings, x => x.Key == "npareauth" && x.Severity == Severity.Info);
        Assert.True(r.Availability.TryGetValue("Private Access", out var av) && av < 100 && av > 80);
        Assert.Contains(r.States, s => s.Service == "Private Access" && s.State == "Reautenticando");
        // a reautenticação não vira incidente
        Assert.DoesNotContain(r.Incidents, i => i.Title.Contains("reautentic", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NpaGatewayHealthSeries_AndRootCauseInternet()
    {
        var r = Full();
        Assert.True(r.Series["npa.gw.rtt"].Points.Count >= 7);
        Assert.Contains(r.Series["npa.gw.retrans"].Points, p => p.Value >= 250);
        var inc = r.Incidents.First(i => i.Title.StartsWith("Private Access", StringComparison.Ordinal) && i.Start <= T0.AddMinutes(41) && i.End >= T0.AddMinutes(40));
        Assert.Contains(inc.Causes, c => c.Title.StartsWith("A Internet da máquina caiu", StringComparison.Ordinal));
    }

    [Fact]
    public void NetworkChurn_PointsToDocker()
    {
        var r = Full();
        var f = Assert.Single(r.Findings, x => x.Key == "netchurn");
        Assert.Contains("Docker", f.Meaning, StringComparison.Ordinal);
        Assert.Contains("410", f.Meaning, StringComparison.Ordinal);
        Assert.Contains(f.Steps, s => s.Command != null && s.Command.Contains("docker ps", StringComparison.Ordinal));
        var route = r.Findings.First(x => x.Key == "route");
        Assert.Equal(Severity.Info, route.Severity);
        Assert.True(r.Series.ContainsKey("net.changes"));
    }

    [Fact]
    public void Dns_SuffixLeakAndInterfaces()
    {
        var r = Full();
        var f = Assert.Single(r.Findings, x => x.Key == "dnssuffix");
        Assert.Contains("corp.example.com", f.Meaning, StringComparison.Ordinal);
        Assert.Contains(r.DnsInterfaces, d => d.Interface == "fctvpn1077f7c3" && d.Search.Contains("corp.example.com") && d.Note.Contains("VPN", StringComparison.Ordinal));
        Assert.Equal(90, r.Series["npa.dns.nxdomain"].Points[0].Value);
    }

    [Fact]
    public void Overlap_DockerAndVpnInsideNpaRoutes()
    {
        var r = Full();
        var f = Assert.Single(r.Findings, x => x.Key == "overlap");
        Assert.Contains("docker0", f.Meaning, StringComparison.Ordinal);
        Assert.Contains("fctvpn1077f7c3", f.Meaning, StringComparison.Ordinal);
        Assert.DoesNotContain("wlo1", f.Meaning, StringComparison.Ordinal);
    }

    [Fact]
    public void Processes_SecurityAgentAndPerformance()
    {
        var r = Full();
        var f = Assert.Single(r.Findings, x => x.Key == "heavyproc");
        Assert.Contains("falcon-sensor-bpf", f.Title, StringComparison.Ordinal);
        Assert.Contains(r.Performance, p => p.Group == TacInsights.ResourceGroup && p.Name == "Maiores consumidores de memória");
        Assert.Contains(r.Performance, p => p.Name == "Quedas do Private Access");
        Assert.Contains(r.Performance, p => p.Name.StartsWith("RTT até o gateway", StringComparison.Ordinal));
    }

    [Fact]
    public void Config_ExplainsOffPremAndAttentionItems()
    {
        var r = Full();
        Assert.Contains(r.Config, c => c.Section == "Detecção on-prem" && c.Meaning.Contains("NÃO está na lista", StringComparison.Ordinal));
        Assert.Contains(r.Config, c => c.Item == "Usuário pode desabilitar o cliente" && c.Attention);
        Assert.Contains(r.Config, c => c.Item == "Licença DEM" && c.Attention);
        Assert.Contains(r.Config, c => c.Item == "Private Access" && c.Meaning.Contains("Na rede da empresa", StringComparison.Ordinal));
    }

    [Fact]
    public void CaseSummary_AndCoverage()
    {
        var r = Full();
        Assert.Contains(r.CaseSummary, kv => kv.Key == "Qual é o sintoma principal?");
        Assert.Contains(r.CaseSummary, kv => kv.Key == "Afeta Internet, Private Access ou ambos?" && kv.Value.Contains("Private Access", StringComparison.Ordinal));
        Assert.Contains(r.Coverage, c => c.Source.StartsWith("Private Access", StringComparison.Ordinal));
        var md = Report.ToMarkdown(r);
        Assert.Contains("## Resumo do caso", md, StringComparison.Ordinal);
        Assert.Contains("## Quedas do Private Access", md, StringComparison.Ordinal);
    }

    [Fact]
    public void Noise_UiLongpoll403IsNoise()
    {
        var sb = new StringBuilder();
        for (var i = 0; i < 50; i++)
        {
            var t = T0.AddSeconds(3 * i);
            sb.AppendLine($"{t:yyyy/MM/dd HH:mm:ss}.100000 stAgentUI p1 t1 info restapi.cpp:259 restapi longpoll connection headers:");
            sb.AppendLine($"{t:yyyy/MM/dd HH:mm:ss}.200000 stAgentUI p1 t1 warn nsHTTPClient.cpp:561 downloader Got HTTP response code: 403");
        }
        var r = Run(("nsAppUI.log", sb.ToString()));
        var f = r.Findings.First(x => x.Key == "http");
        Assert.Equal(Severity.Noise, f.Severity);
        Assert.Contains("notificações", f.Title, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- captura sintética

    private static byte[] Tcp(string src, string dst, ushort sp, ushort dp, uint seq, byte flags, int payload)
    {
        var p = new byte[20 + 20 + payload];
        p[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length); p[8] = 64; p[9] = 6;
        System.Net.IPAddress.Parse(src).GetAddressBytes().CopyTo(p, 12); System.Net.IPAddress.Parse(dst).GetAddressBytes().CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), sp); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), dp);
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(24), seq); p[32] = 0x50; p[33] = flags; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(34), 1000);
        return p;
    }

    private static byte[] DnsReply(int rcode)
    {
        var p = new byte[20 + 8 + 12];
        p[0] = 0x45; BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)p.Length); p[9] = 17;
        new byte[] { 8, 8, 8, 8 }.CopyTo(p, 12); new byte[] { 10, 0, 0, 2 }.CopyTo(p, 16);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(20), 53); BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(22), 40000);
        p[30] = 0x81; p[31] = (byte)(0x80 | rcode);
        return p;
    }

    private static byte[] Pcap(params (double T, byte[] Ip)[] pkts)
    {
        var ms = new MemoryStream();
        var h = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(h, 0xa1b2c3d4); BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(4), 2); BinaryPrimitives.WriteUInt16LittleEndian(h.AsSpan(6), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(16), 65535); BinaryPrimitives.WriteUInt32LittleEndian(h.AsSpan(20), 101);
        ms.Write(h);
        foreach (var (t, ip) in pkts)
        {
            var r = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(r, 1795400000 + (uint)t); BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(4), (uint)((t % 1) * 1e6));
            BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(8), (uint)ip.Length); BinaryPrimitives.WriteUInt32LittleEndian(r.AsSpan(12), (uint)ip.Length);
            ms.Write(r); ms.Write(ip);
        }
        return ms.ToArray();
    }

    [Fact]
    public void Pcap_CountsRetransmissionsResetsAndDns()
    {
        var data = Pcap(
            (0.0, Tcp("10.0.0.2", "1.1.1.1", 50000, 443, 1, 0x02, 0)),
            (0.01, Tcp("1.1.1.1", "10.0.0.2", 443, 50000, 9, 0x12, 0)),
            (0.02, Tcp("10.0.0.2", "1.1.1.1", 50000, 443, 2, 0x18, 100)),
            (1.02, Tcp("10.0.0.2", "1.1.1.1", 50000, 443, 2, 0x18, 100)), // retransmissão
            (1.50, Tcp("1.1.1.1", "10.0.0.2", 443, 50000, 10, 0x04, 0)),   // RST
            (2.0, Tcp("10.0.0.2", "2.2.2.2", 50001, 443, 1, 0x02, 0)),     // SYN sem resposta
            (2.1, DnsReply(3)));
        var c = PcapReader.Read("nspktdump.pcap", data);
        Assert.Null(c.Error);
        Assert.Equal(7, c.Packets);
        Assert.Equal(1, c.Retransmissions);
        Assert.Equal(2, c.TcpDataSegments);
        Assert.Equal(1, c.Resets);
        Assert.Equal(1, c.HandshakeFailures);
        Assert.Equal(1, c.DnsRcodes["NXDOMAIN"]);
        Assert.Contains(c.TopDestinations, kv => kv.Key == "1.1.1.1:443");

        var r = new Analyzer().AnalyzeItems(new[] { new SourceItem("nspktdump.pcap", data) });
        Assert.Single(r.Captures);
    }
}
