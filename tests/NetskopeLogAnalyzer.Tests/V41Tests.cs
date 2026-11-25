using System.Text;
using NetskopeLogAnalyzer.Core;
using Xunit;

namespace NetskopeLogAnalyzer.Tests;

/// <summary>4.1: identificação do usuário e da máquina (dados sintéticos).</summary>
public class V41Tests
{
    private static SourceItem Item(string name, string text) => new(name, Encoding.UTF8.GetBytes(text));

    private static AnalysisResult Run() => new Analyzer().AnalyzeItems(new[]
    {
        Item("nsdebuglog.log",
            "2026/11/23 10:00:00.100000 stAgentSvc p1 t1 info main.cpp:1 main ======= stAgentSvc 142.0.0.2821 starting ======\n" +
            "2026/11/23 10:00:01.100000 stAgentSvc p1 t1 info config.cpp:1 Config Read cached client config version: 2026-11-23 07:00:00.0, curr config version . useremail ma***ia@exemplo.com.br\n" +
            "2026/11/23 10:00:02.100000 stAgentSvc p1 t1 info config.cpp:1345 Config setting STA user agent: hostname: PC-TESTE01\n"),
        Item("nsDiag-maria.log",
            "2026/11/23 10:30:00.100000 nsdiag p1 t1 info main.cpp:553 CNSDiag Output zip file to /home/maria/Downloads/NetskopeLogs.zip, 0, 1, 0, 0\n"),
        Item("npadebuglog.log",
            "[PC-TESTE01:2026-11-23 10:00:03.000 -03:00] t1 [info] neClientTransportHandler.cpp:1:sendGwDeviceAssessment():0x1 Received device info request. Device Info: " +
            "{\"client\": {\"authentication\": {\"jwt\": \"********\"}}, \"device\": {\"assessment\": {\"user_email\": \"ma***ia@exemplo.com.br\", \"machine_name\": \"PC*TESTE01\", \"os_distro\": \"ubuntu\", " +
            "\"primary_storage_encrypted\": true, \"managed\": false, \"last_logon_time\": 1795950000}, \"netskope_device_id\": \"AAAA-BBBB\", \"hardware_identifier\": \"abc123\"}}\n"),
        Item("nsconfig.json",
            "{\"cache\":{\"lastClientConfigUserEmail\":\"maria.silva@exemplo.com.br\",\"appinstalltimestamp\":\"1791989082\",\"device\":{\"hostname\":\"PC-TESTE01\",\"serial_num\":\"SN12345\",\"os\":\"Linux\",\"os_version\":\"24.04\",\"model\":\"Latitude\",\"make\":\"Dell Inc.\",\"ns_version\":\"142.0.0.2821\"}}," +
            "\"clientConfig\":{\"configurationName\":\"Padrão\"},\"nsgw\":{\"host\":\"gateway-exemplo.goskope.com\"},\"npa\":{\"tenant\":\"ns-1.npa.goskope.com\"}}"),
        Item("nsuser.conf", "{\"cache\":{\"userStatus\":\"true\",\"npaUserStatus\":\"true\",\"DeviceClassificationStatus\":\"not configured\",\"device_tags\":\"[]\",\"tunnelId\":\"t-1\"}}"),
        Item("install.log", "NSClient Version: 142.0.0.2821\nTime: seg 23 nov 2026 09:00:00 -03\n  Kernel arch: x86_64\nUser Info\n  Login User:  ma***a\n  SUDO User:   ma***a\nCurrent login users:\nmaria    tty2     -   1:00m gnome\n-------------------------------\nInstall by email invitation mode.\n"),
        Item("network-state.log", "$ /usr/sbin/ip -d address\n1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    link/ether 5c:cd:5b:00:00:01 brd ff:ff:ff:ff:ff:ff\n    inet 192.168.0.10/24 brd 192.168.0.255 scope global wlo1\n3: eno2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500\n    link/ether b0:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff\n"),
    });

    private static string V(AnalysisResult r, string label) => r.Identity.First(i => i.Label == label).Value;

    [Fact]
    public void Identity_CollectsUserAndMachine()
    {
        var r = Run();
        Assert.Equal("maria.silva@exemplo.com.br", V(r, "E-mail registrado no Netskope"));
        Assert.Equal("maria", V(r, "Login no sistema operacional"));      // nome sem máscara vence o mascarado do install.log
        Assert.Equal("PC-TESTE01", V(r, "Hostname"));
        Assert.Equal("SN12345", V(r, "Número de série"));
        Assert.Equal("Dell Inc.", V(r, "Fabricante"));
        Assert.Equal("Convite por e-mail", V(r, "Forma de registro"));
        Assert.Equal("sim", V(r, "Disco principal criptografado"));
        Assert.Equal("exemplo", V(r, "Tenant"));
        Assert.Contains("wlo1: 192.168.0.10/24 · MAC 5c:cd:5b:00:00:01", V(r, "Interfaces ativas"));
        Assert.DoesNotContain("eno2", V(r, "Interfaces ativas"));
        Assert.Contains("maria (tty2)", V(r, "Sessões abertas na instalação"));
        Assert.Equal("14/10/2026 11:44", V(r, "Cliente instalado em"));   // fuso -03:00 dos logs
        Assert.Contains(r.Identity, i => i.Label == "Último logon na máquina");
        Assert.Equal(IdentityCollector.User, r.Identity[0].Group);
        var md = Report.ToMarkdown(r);
        Assert.Contains("## Usuário e máquina", md);
        Assert.Contains("Usuário: maria.silva@exemplo.com.br · maria", md);
    }

    [Fact]
    public void Identity_SanitizesAndToleratesBrokenDeviceInfo()
    {
        var r = new Analyzer().AnalyzeItems(new[]
        {
            Item("npadebuglog.log", "[PC:2026-11-23 10:00:03.000 -03:00] t1 [info] x.cpp:1:f():0x1 Received device info request. Device Info: {\"device\": {\"assessment\": {\"user_email\": \n"),
            Item("nsconfig.json", "{\"cache\":{\"device\":{\"hostname\":\"PC‮evil\u0007\"}}}"),
        });
        var host = r.Identity.First(i => i.Label == "Hostname").Value;
        Assert.DoesNotContain('‮', host);
        Assert.DoesNotContain('\u0007', host);
    }
}
