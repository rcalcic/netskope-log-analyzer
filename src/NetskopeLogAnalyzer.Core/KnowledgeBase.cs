using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

public sealed class Rule
{
    public required string Id { get; init; }
    public required Regex Re { get; init; }
    public bool AnyLevel { get; init; }
    public Severity Severity { get; init; }
    public Func<int, Severity>? SeverityByCount { get; init; }
    public required string Category { get; init; }
    public required string Title { get; init; }
    public required string Meaning { get; init; }
    public required string Action { get; init; }
    public string? ExplorerQuery { get; init; }

    public Severity SeverityFor(int count) => SeverityByCount?.Invoke(count) ?? Severity;
}

public sealed class FixDef
{
    public List<FixStep> All { get; init; } = new();
    public List<FixStep> Linux { get; init; } = new();
    public List<FixStep> Windows { get; init; } = new();
    public List<FixStep> Mac { get; init; } = new();
    public List<FixStep> End { get; init; } = new();
    public string[] Refs { get; init; } = Array.Empty<string>();
    public string Query { get; init; } = "";
}

public sealed record ConflictApp(string Name, Regex Re);

/// <summary>
/// Padrões conhecidos do Netskope Client e resoluções.
/// Resoluções baseadas em docs.netskope.com e community.netskope.com (consultados em nov/2026).
/// </summary>
public static class KnowledgeBase
{
    private const RegexOptions Opt = RegexOptions.Compiled | RegexOptions.CultureInvariant;
    private const RegexOptions OptI = Opt | RegexOptions.IgnoreCase;

    private static Func<int, Severity> ByCount(Severity low, Severity high, int limit) => c => c >= limit ? high : low;

    private static Rule R(string id, string pattern, Severity sev, string cat, string title, string meaning, string action,
        bool any = false, bool ci = false, Func<int, Severity>? byCount = null, string? q = null) => new()
    {
        Id = id, Re = new Regex(pattern, ci ? OptI : Opt), Severity = sev, SeverityByCount = byCount, AnyLevel = any,
        Category = cat, Title = title, Meaning = meaning, Action = action, ExplorerQuery = q
    };

    public static readonly IReadOnlyList<Rule> Rules = new List<Rule>
    {
        // ---- vistos nos pacotes reais de clientes Linux (precisam vir antes das regras genéricas)
        R("fltqueue", @"nsFltThread Failed to send data to thread", Severity.Warning, "Desempenho",
            "Fila do filtro de tráfego cheia — pacotes descartados",
            "A thread que repassa os pacotes capturados não deu conta (erro 11 = fila cheia). Nesses momentos o Netskope descarta pacotes: páginas ficam lentas, conexões dão timeout e chamadas de vídeo travam. Acontece em rajadas, com muito tráfego de uma vez (sincronização, Docker, chamadas) ou com a CPU ocupada.",
            "Veja os horários das rajadas, compare com o uso de CPU e com o tráfego da máquina no mesmo minuto, e atualize o cliente.", byCount: ByCount(Severity.Warning, Severity.Critical, 2000), q: "Failed to send data to thread"),
        R("dnsbypass", @"failed to bypass DNS query to uplink server", Severity.Warning, "DNS",
            "Consultas DNS não chegaram ao servidor DNS da rede",
            "O cliente tentou mandar consultas DNS direto ao servidor DNS configurado na máquina e o envio falhou (erro 11 = fila/socket ocupado). Nesses momentos a resolução de nomes falha ou demora.",
            "Confira o servidor DNS indicado nos detalhes (está acessível a partir da rede atual?) e se ele coincide com rajadas de fila cheia.", q: "failed to bypass DNS query"),
        R("dtls", @"DTLS SSL_connect failed|DTLS failed to setup SSL tunnel", Severity.Info, "Túnel",
            "Túnel DTLS (UDP) não foi estabelecido — o cliente usou TLS (TCP)",
            "O cliente tenta primeiro o túnel em DTLS (UDP 443), mais rápido para chamadas e vídeo. Quando a rede bloqueia ou perde UDP, ele volta para TLS (TCP 443): funciona, mas com mais latência em aplicativos de tempo real.",
            "Se o usuário reclama de chamadas ruins, confira se a rede (firewall, roteador, proxy) libera UDP 443 para os gateways do Netskope.", byCount: ByCount(Severity.Info, Severity.Warning, 20), q: "DTLS"),
        R("npaexpired", @"Active session has expired", Severity.Noise, "Ruído",
            "Aviso de sessão expirada do Private Access",
            "Linha do gateway ao encerrar a sessão por tempo. A contagem e os horários estão em “Reautenticação do Private Access”.", "Nenhuma."),
        R("recvfail", @"Failure when receiving data from the peer", Severity.Info, "Conectividade",
            "Conexão com o tenant interrompida no meio da resposta",
            "A resposta do tenant começou a chegar e a conexão caiu antes do fim — sinal de rede instável ou de inspeção no caminho cortando a sessão.", "Compare com quedas de Wi-Fi e mudanças de rede no mesmo horário.",
            byCount: ByCount(Severity.Info, Severity.Warning, 30), q: "Failure when receiving data"),
        R("clientnoise", @"thread interrupted\. Exiting thread|eventcache\.json is empty|User config not found for (the )?sessId|dem\.json for reading|Failed to load legacy provider|netstat command not found|Skipping updateClientStatus|request to stop nsssl::wait thread|bytes of data in a paused socket|nsGetHostName failed|Operation was aborted by an application callback|Failed to read nsConfig\.json|update user config failed for sessId",
            Severity.Noise, "Ruído", "Mensagens internas do cliente durante reinícios e trocas de sessão",
            "Avisos esperados quando o serviço reinicia, quando a sessão do usuário muda ou quando um componente opcional não existe nesta máquina.", "Nenhuma."),
        R("nopid", @"tunnelPolicyMgr invalid params", Severity.Noise, "Ruído", "Fluxo sem processo identificado",
            "O cliente recebeu uma conexão sem processo de origem (/proc/0) e não aplicou política por processo; o fluxo segue normalmente.", "Nenhuma."),
        R("npanotready", @"Dropping packet, not ready!", Severity.Info, "Private Access", "Pacotes do Private Access descartados com o túnel ainda subindo",
            "Durante a (re)conexão do túnel NPA os pacotes de aplicações privadas são descartados até o túnel ficar pronto.", "Sem ação se coincidir com reconexões do Private Access.", q: "Dropping packet"),
        R("npanoise", @"Cannot get reauth timing settings|Cannot get status for the tunnel id|The wait call cannot be completed within|RTT getsockopt\(\) received error|Schedule a async function call when dispatcher is stopped", Severity.Noise, "Ruído",
            "Mensagens internas do módulo NPA", "Avisos internos do Private Access sem efeito para o usuário.", "Nenhuma."),
        R("crash", @"segmentation fault|SIGSEGV|SIGABRT|core dumped|unhandled exception|terminate called|access violation", Severity.Critical, "Estabilidade",
            "Travamento (crash) de processo do Netskope", "Um processo do cliente encerrou de forma anormal.",
            "Veja qual processo travou e o horário; atualize o cliente para a versão mais recente (ou a golden release do tenant) e, se repetir, reinstale.", any: true, ci: true),
        R("disk", @"No space left on device", Severity.Critical, "Sistema", "Disco cheio",
            "O sistema não tem espaço para gravar arquivos; configuração e logs podem ficar corrompidos.", "Libere espaço em disco e reinicie o serviço do Netskope.", any: true, ci: true),
        R("ssl", @"code (35|51|58|60),|SSL certificate problem|certificate verify failed|unable to get local issuer|SSL_ERROR|handshake fail", Severity.Critical, "Certificados",
            "Falhas de TLS / certificado na comunicação com o tenant",
            "A conexão HTTPS com o Netskope foi recusada por problema de certificado. Causas típicas: outro proxy/firewall fazendo inspeção SSL, data/hora do computador errada ou CA ausente.",
            "Confira data/hora; libere *.goskope.com da inspeção SSL em proxies e firewalls.", ci: true, q: "SSL"),
        R("certexp", @"certificate (has )?expired|certificate is not yet valid", Severity.Critical, "Certificados", "Certificado expirado ou ainda não válido",
            "Algum certificado usado pelo cliente está fora da validade — muitas vezes é o relógio do sistema errado.", "Corrija data/hora (NTP); se persistir, refaça o registro.", any: true, ci: true),
        R("p407", @"\b407\b|Proxy Authentication Required", Severity.Critical, "Conectividade", "Proxy exigindo autenticação",
            "Há um proxy no caminho pedindo credenciais; o cliente não consegue chegar ao tenant.", "Isente *.goskope.com de autenticação no proxy.", ci: true),
        R("timeout", @"code 28,|Timeout was reached|Operation timed out", Severity.Warning, "Conectividade", "Timeouts ao falar com o tenant Netskope",
            "Requisições HTTPS do cliente (download de configuração, listas de exceção, GSLB, status) não responderam a tempo.",
            "Teste a saída 443 para o tenant e os domínios Netskope.", ci: true, byCount: ByCount(Severity.Warning, Severity.Critical, 10), q: "code 28"),
        R("dns", @"code 6,|Could not resolve host|getaddrinfo failed|DNS resolution failed", Severity.Warning, "Conectividade", "Falhas de resolução DNS",
            "O cliente não conseguiu resolver o nome do tenant/gateway. Geralmente o sistema está usando um DNS que não responde (ex.: DNS interno herdado de uma VPN desconectada).",
            "Verifique os DNS ativos e remova interfaces de VPN órfãs.", ci: true, byCount: ByCount(Severity.Warning, Severity.Critical, 5), q: "code 6,"),
        R("conn", @"code 7,|Couldn't connect to server|Connection refused|Network is unreachable|No route to host", Severity.Warning, "Conectividade", "Conexão recusada ou rede inalcançável",
            "Não foi possível abrir conexão TCP com o destino.", "Verifique rota padrão, firewall local e outras VPNs.", ci: true, byCount: ByCount(Severity.Warning, Severity.Critical, 10), q: "code 7,"),
        R("http", @"Got HTTP response code: (4\d\d|5\d\d)", Severity.Warning, "Conectividade", "Tenant respondeu com erro HTTP",
            "O tenant recusou a requisição (403 = usuário/dispositivo não autorizado ou token inválido; 401 = autenticação; 5xx = erro do lado Netskope).",
            "Confirme o provisionamento do usuário; em 403 recorrente, refaça o registro.", q: "HTTP response"),
        R("cfgdl", @"Failed to download (config|admin config|steering|ca cert|tenant cert|exception list|bypass list|user cert)|download exceptional list failed|Failed to synchronize configuration|failed to get ST Agent update version info|download (steering config|ca cert|tenant cert) failed|failed to download (admin )?config|mandatory config download failed", Severity.Warning, "Configuração",
            "Falha ao baixar configuração do tenant", "O cliente não conseguiu atualizar a configuração (steering, exceções, políticas). Ele continua com a última configuração conhecida.",
            "Resolva a conectividade e force a atualização da configuração.", ci: true, byCount: ByCount(Severity.Warning, Severity.Critical, 6), q: "download config"),
        R("restapi", @"restapi Failed to (?:download|post) ([^,]+?)\s*,? ?Error|addonmanapi Failed to download (.+)$", Severity.Warning, "Configuração", "Chamadas de API ao tenant falharam",
            "Downloads ou envios específicos ao tenant falharam (listas de bypass, exceções, domínios, status).", "Consequência de conectividade.", q: "restapi Failed"),
        R("bypasscat", @"Failed to download bypass category list|Failed to download Category Bypass", Severity.Warning, "Configuração", "Lista de bypass por categoria não foi baixada",
            "Sem essa lista, categorias que deveriam ir direto podem ser enviadas ao proxy.", "Corrija a conectividade e atualize a configuração.", ci: true, q: "bypass"),
        R("gslb", @"GSLB fetch failed|forced GSLB refresh failed|Failed to download NSClient-gslb|Failed to download NPA-gslb", Severity.Warning, "Conectividade", "Falha na seleção automática de gateway (GSLB)",
            "O cliente não conseguiu obter a lista de POPs mais próximos; pode conectar num POP mais distante (latência maior).", "Libere gateway.gslb.goskope.com e dns.google.", ci: true, q: "GSLB"),
        R("tundown", @"event: Tunnel Down|onTunnelDisconnected", Severity.Warning, "Túnel", "Quedas do túnel",
            "O túnel (Internet/SWG ou Private Access/NPA) foi desconectado. Pode ser troca de rede, suspensão, reinício do serviço ou falha de comunicação.",
            "Compare com a linha do tempo e investigue conflitos de rede.", any: true, byCount: ByCount(Severity.Warning, Severity.Critical, 4), q: "Tunnel Down"),
        R("userdis", @"event: User Disabled", Severity.Warning, "Túnel", "Cliente desabilitado manualmente pelo usuário",
            "O próprio usuário desligou o Netskope Client. Enquanto desabilitado o tráfego não passa pela inspeção (ou é bloqueado, se fail-close estiver ativo).",
            "Reabilite e considere impedir a desativação.", any: true, q: "User Disabled"),
        R("restart", @"Service is stopping", Severity.Info, "Estabilidade", "Serviço do Netskope parado/reiniciado",
            "O serviço stAgentSvc recebeu sinal de parada. Pode ser reinício manual, atualização, desligamento ou reinstalação.",
            "Verifique atualizações automáticas e scripts de gestão.", any: true, byCount: ByCount(Severity.Info, Severity.Warning, 2), q: "Service is stopping"),
        R("npagw", @"Connection to GW .*(terminated|failed)|keepAlive fails", Severity.Warning, "Túnel", "Conexão do Private Access (NPA) com o gateway caiu",
            "O túnel NPA perdeu a conexão com gateway.npa.goskope.com (keepalive sem resposta).", "Verifique a estabilidade da rede e conflitos de VPN.", ci: true, q: "Connection to GW"),
        R("route", @"ip(Route|Rule)(Get|Del|Add)\w*: failed", Severity.Info, "Rede", "Falhas em consultas à tabela de rotas (netlink)",
            "O cliente pediu ao kernel a rota para destinos e não recebeu resposta. Volume alto costuma indicar tabela de rotas alterada por outra VPN ou interfaces em estado inconsistente.",
            "Revise interfaces de VPN de terceiros e rotas.", byCount: ByCount(Severity.Info, Severity.Warning, 50), q: "ipRoute"),
        R("driver", @"Failed to (start|load|install|open) (the )?(driver|filter|stadrv|nsfilter)|WFP .*fail", Severity.Critical, "Sistema", "Falha no driver de captura de tráfego",
            "O componente que intercepta o tráfego não iniciou; o túnel não captura nada.", "Reinstale o cliente e verifique conflitos com antivírus/EDR.", ci: true),
        R("iptables", @"iptables.*(fail|error)|Failed to (add|set|apply) iptables", Severity.Warning, "Rede", "Falha ao aplicar regras iptables",
            "No Linux o cliente usa iptables para direcionar tráfego; regras não aplicadas impedem a captura.", "Verifique se outro software reescreve as regras.", ci: true),
        R("sysca", @"copy_file: No such file or directory: ""/usr/local/share/ca-certificates/ns(?:ca|tenant)cert\.crt""|failed to open file for reading: /usr/local/share/ca-certificates/nscacert\.crt", Severity.Warning, "Certificados",
            "CA do Netskope fora do repositório de certificados do Linux",
            "O cliente procurou a CA do Netskope em /usr/local/share/ca-certificates e não encontrou. Navegadores baseados em Chromium usam o próprio repositório e costumam funcionar, mas ferramentas que usam o repositório do sistema (curl, git, apt, npm, pip, Python, Docker, Java, aplicativos em Go) dão erro de certificado em sites inspecionados. Se a CA foi instalada por script com outro nome, confira se ela está no bundle do sistema.",
            "Instale as duas CAs do Netskope no repositório do sistema e aponte as ferramentas para o bundle.", ci: true, q: "nscacert.crt"),
        R("firefox", @"firefox|FF Snap", Severity.Warning, "Certificados", "CA do Netskope não instalada para o Firefox",
            "O cliente não conseguiu copiar a CA para o Firefox (versão snap). Sites inspecionados podem mostrar erro de certificado no Firefox.",
            "Importe a CA do Netskope no Firefox.", ci: true, q: "firefox"),
        R("ipc", @"NSCOM2 .*(not running|connect failed|Connection closed)|disconnected by service|startServerMessagePump", Severity.Info, "Estabilidade", "Interface perdeu comunicação com o serviço",
            "A interface gráfica (stAgentUI/stAgentApp) ficou sem falar com o serviço. É esperado durante reinícios do serviço.", "Reinicie o serviço se ocorrer sem reinício.", q: "NSCOM2"),
        R("upn", @"UPN enroll|branding file using UPN", Severity.Info, "Provisionamento", "Registro por UPN não concluído",
            "O cliente tentou se registrar usando o UPN do usuário e não tinha informações suficientes; outro método foi usado.", "Confira se houve o evento “Registrado (enroll)”.", q: "UPN"),
        R("clientstatus", @"Failed to post client status", Severity.Info, "Configuração", "Status do dispositivo não foi enviado ao console",
            "O console pode mostrar status desatualizado deste dispositivo.", "É reenviado automaticamente.", ci: true, q: "client status"),
        R("dem", @"DEM .*fail", Severity.Info, "Configuração", "Falha no envio de dados de DEM", "Monitoramento de experiência digital não enviou status.", "Sem impacto no tráfego.", ci: true, q: "DEM"),
        R("npawait", @"cannot be completed within \d+ ms", Severity.Info, "Túnel", "Lentidão interna do módulo NPA", "Uma operação interna do Private Access demorou além do esperado.", "Sem ação se isolado."),
        R("broker", @"No Primary broker configured", Severity.Noise, "Ruído", "Nenhum broker NPA primário configurado", "Mensagem de seleção de gateway do NPA; o cliente usa a lista do GSLB.", "Sem ação."),
        R("bwan", @"bwan|Bwan", Severity.Noise, "Ruído", "Módulo SD-WAN ausente", "Mensagens do Endpoint SD-WAN (bwanclient). Esperado quando o SD-WAN não está instalado/em uso.", "Nenhuma.", q: "bwan"),
        R("perm", @"err: 13|Permission denied", Severity.Info, "Sistema", "Permissão negada ao gravar arquivo", "Algum processo do usuário tentou gravar em pasta protegida.", "Veja o arquivo citado nos exemplos.", q: "err: 13"),
        R("decrypt", @"Invalid decryption of protected file|decrypt file failed|nsEncryption invalid parameters", Severity.Noise, "Ruído", "Arquivos protegidos ainda não criados",
            "Comum na inicialização e antes do registro: o arquivo criptografado ainda não existe.", "Nenhuma, se o registro foi concluído.", q: "decrypt"),
        R("prereg", @"branding file|Failed to read user certificate|failed to read (file|from backup file|steering config|exception list|category list|tenant cert|ca cert)|nsgw info not available|eventCache failed to read|cannot open file .*provisioning|failed to open file for reading|Failed to read [\w. ]+ file|failed to read bypass list", Severity.Noise, "Ruído",
            "Leituras de configuração antes do registro", "Na primeira execução (ou logo após reinstalar) os arquivos de configuração ainda não existem.", "Nenhuma, se o registro foi concluído depois.", ci: true),
        R("fips", @"getFipsConfigPath|FIPS", Severity.Noise, "Ruído", "FIPS não suportado na plataforma", "Mensagem padrão em Linux/macOS.", "Nenhuma."),
        R("ipv6", @"IPv6 next header is not", Severity.Noise, "Ruído", "Pacote IPv6 ignorado", "Pacotes ICMPv6/extensões não são tunelados.", "Nenhuma."),
        R("session", @"Can not find session|Can't find NPA tunnel|No tunnel found|Tunnel is deleted or marked|SessId \[\d+\] No found|Failed to get Active User Session ID|Failed to get session details|Cannot get (status|reauth)|dispatcher is stopped", Severity.Noise, "Ruído",
            "Sessão/túnel ainda não disponível", "Mensagens transitórias durante criação ou remoção de túnel.", "Nenhuma."),
        R("misc", @"unknown message ID|npaCertRefTime|npaDnsCache|Invalid tunnel status: \d+|Failed to read pid file|No FQDN for client On-prem|using preload user cert|RTT getsockopt|Token not found in the client name|IdPProvisioning|cannot get linux key|no cert check rule|SetDeviceOption .* ignored|packet filter is already enabled|read_json failed|query device tags API|supportability params|addon host is empty|Failed to download device id|Failed to download overlapping|Failed to download tunnel policy|proc is not running", Severity.Noise, "Ruído",
            "Mensagens internas conhecidas", "Mensagens de diagnóstico interno comuns em clientes saudáveis.", "Nenhuma."),
    };

    public static readonly IReadOnlyList<ConflictApp> Conflicts = new List<ConflictApp>
    {
        new("FortiClient", new Regex(@"forticlient|fctsched|fortitray|FortiSSLVPN|fctvpn", OptI)),
        new("Zscaler", new Regex(@"zscaler|ZSATunnel|ZSAService", OptI)),
        new("GlobalProtect", new Regex(@"PanGPS|PanGPA|globalprotect", OptI)),
        new("Cisco Secure Client/AnyConnect", new Regex(@"vpnagentd|anyconnect|csc_ui", OptI)),
        new("OpenVPN", new Regex(@"openvpn", OptI)),
        new("WireGuard", new Regex(@"wg-quick|wireguard", OptI)),
        new("Tailscale", new Regex(@"tailscaled", OptI)),
        new("Cloudflare WARP", new Regex(@"warp-svc", OptI)),
        new("Check Point VPN", new Regex(@"TracSrvWrapper|trac\.exe|cpda", OptI)),
        new("Pulse/Ivanti Secure", new Regex(@"pulsesecure|dsAccessService", OptI)),
    };

    public static readonly Regex VpnInterface = new(@"^(fctvpn|ppp\d|tun\d|wg\d|utun|tailscale|cscotun|gpd\d|zcctun|CloudflareWARP)", OptI);

    public static readonly IReadOnlyDictionary<string, Reference> Refs = new Dictionary<string, Reference>
    {
        ["trouble"] = new("Guia de troubleshooting do Netskope Client", "https://docs.netskope.com/en/netskope-client-troubleshooting-guide"),
        ["netcfg"] = new("Requisitos de rede do cliente (domínios e portas)", "https://docs.netskope.com/en/netskope-client-network-configuration"),
        ["fw"] = new("Verificar política de firewall", "https://docs.netskope.com/en/check-firewall-policy"),
        ["cmd"] = new("Referência de comandos nsdiag", "https://docs.netskope.com/pt/netskope-client-command-reference"),
        ["interop"] = new("Interoperabilidade com softwares de terceiros", "https://docs.netskope.com/en/netskope-client-interoperability/"),
        ["vpnexc"] = new("Exceções de steering para aplicações VPN", "https://docs.netskope.com/en/exception-configuration-for-vpn-applications"),
        ["forti"] = new("FortiGate VPN + Netskope (boas práticas)", "https://docs.netskope.com/en/fortigate-vpn"),
        ["linux"] = new("Netskope Client para Linux", "https://docs.netskope.com/en/netskope-client-for-linux"),
        ["ubuntu"] = new("Instalação no Ubuntu (Comunidade)", "https://community.netskope.com/netskope-client-87/netskope-client-installation-on-ubuntu-linux-7705"),
        ["certs"] = new("Certificados (download das CAs)", "https://docs.netskope.com/en/certificates"),
        ["certerr"] = new("Gerenciando erros de certificado (Comunidade)", "https://community.netskope.com/inside-netskope-22/managing-certificate-errors-with-netskope-client-7999"),
        ["devtools"] = new("Ferramentas CLI e inspeção SSL", "https://docs.netskope.com/en/netskope-help/data-security/netskope-secure-web-gateway/configuring-cli-based-tools-and-development-frameworks-to-work-with-netskope-ssl-interception/"),
        ["bypass"] = new("Adicionar bypasses no Netskope", "https://docs.netskope.com/en/add-bypasses-in-netskope"),
        ["exceptions"] = new("Adicionar exceções de steering", "https://docs.netskope.com/en/adding-exceptions"),
        ["npagen"] = new("Private Access: troubleshooting geral", "https://docs.netskope.com/en/general-troubleshooting-methods"),
        ["npatool"] = new("NPA Troubleshooter Tool", "https://docs.netskope.com/en/the-npa-troubleshooter-tool"),
        ["npastatus"] = new("Status de dispositivo do Private Access", "https://docs.netskope.com/en/what-do-the-private-access-device-status-types-mean"),
        ["clientcfg"] = new("Configuração do cliente (Client Configuration)", "https://docs.netskope.com/en/netskope-client-configuration/"),
        ["tamper"] = new("Configurar o cliente / Tamperproof", "https://docs.netskope.com/en/configure-netskope-client-settings"),
        ["disable"] = new("Formas de desabilitar o túnel (Comunidade)", "https://community.netskope.com/netskope-client-87/different-ways-to-disable-the-netskope-internet-access-tunnel-swg-8547"),
        ["debug"] = new("Modo de debug do cliente", "https://docs.netskope.com/en/netskope-client-debug-mode"),
        ["using"] = new("Usando o Netskope Client", "https://docs.netskope.com/en/using-netskope-client"),
    };

    private const string Doms = "addon-{T}.goskope.com, gateway-{T}.goskope.com, achecker-{T}.goskope.com, download-{T}.goskope.com, nsauth-{T}.goskope.com, gateway.gslb.goskope.com, gateway.npa.goskope.com, enrollment.goskope.com e dns.google";

    private static FixStep S(string text, string? cmd = null) => new(text, cmd);
    private static List<FixStep> L(params FixStep[] s) => s.ToList();

    private static readonly FixStep RestartLinux = S("Reinicie o serviço:", "sudo systemctl stop stagentd.service\nsudo systemctl start stagentd.service");
    private static readonly FixStep RestartWindows = S("Reinicie o serviço (com “Protect Client configuration and resources” desativado na Client Configuration), em prompt de administrador:", "stagentsvc -stop\nstagentsvc -start");
    private static readonly FixStep RestartMac = S("No macOS Big Sur ou mais novo não há comando: desabilite e reabilite o cliente pelo ícone.");

    public static readonly IReadOnlyDictionary<string, FixDef> Fixes = new Dictionary<string, FixDef>
    {
        ["timeout"] = new()
        {
            Query = "curl_easy_perform failed code 28 Timeout was reached", Refs = new[] { "netcfg", "fw", "cmd" },
            All = L(S("Libere no firewall/proxy, sem inspeção SSL, TCP 443 para: " + Doms + ".")),
            Linux = L(S("Teste se o tenant responde (deve voltar um código HTTP, não timeout):", "curl -sv -o /dev/null https://addon-{T}.goskope.com"), S("Meça os tempos com o próprio cliente:", "{NSD} -r https://addon-{T}.goskope.com")),
            Windows = L(S("Teste se o tenant responde (PowerShell ou cmd):", "curl.exe -sv -o NUL https://addon-{T}.goskope.com"), S("Meça os tempos com o próprio cliente:", "{NSD} -r https://addon-{T}.goskope.com")),
            Mac = L(S("Teste se o tenant responde:", "curl -sv -o /dev/null https://addon-{T}.goskope.com"), S("Meça os tempos com o próprio cliente:", "{NSD} -r https://addon-{T}.goskope.com")),
            End = L(S("Se houver outra VPN conectada ou interfaces de VPN órfãs (veja os itens de Rede/Conflito), resolva isso primeiro."), S("Depois, force a atualização da configuração e confira o status do túnel:", "{NSD} -u\n{NSD} -f")),
        },
        ["dns"] = new()
        {
            Query = "Could not resolve hostname DNS", Refs = new[] { "netcfg", "npagen" },
            Linux = L(S("Veja qual DNS cada interface está usando:", "resolvectl status"), S("Teste a resolução do tenant:", "resolvectl query addon-{T}.goskope.com"), S("Se aparecer DNS de uma VPN desconectada, remova a interface/perfil dessa VPN e limpe o cache:", "sudo resolvectl flush-caches")),
            Windows = L(S("Veja os DNS de cada adaptador:", "ipconfig /all"), S("Teste a resolução do tenant:", "nslookup addon-{T}.goskope.com"), S("Remova adaptadores de VPN que ficaram com DNS e limpe o cache:", "ipconfig /flushdns")),
            Mac = L(S("Veja a ordem de resolvedores:", "scutil --dns"), S("Teste a resolução do tenant:", "nslookup addon-{T}.goskope.com"), S("Limpe o cache:", "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder")),
            End = L(S("Garanta UDP/53 para o resolvedor e TCP 443 para dns.google — o cliente usa dns.google para escolher o POP e cai para o DNS local se estiver bloqueado."), S("Depois:", "{NSD} -u")),
        },
        ["conn"] = new()
        {
            Query = "Couldn't connect to server Connection refused", Refs = new[] { "netcfg", "fw" },
            Linux = L(S("Confira a rota padrão e se alguma VPN está capturando o tráfego:", "ip route\nip -br link")),
            Windows = L(S("Confira a rota padrão:", "route print")),
            Mac = L(S("Confira a rota padrão:", "netstat -rn")),
            End = L(S("Libere TCP 443 de saída para " + Doms + "."), S("Valide:", "{NSD} -f")),
        },
        ["ssl"] = new()
        {
            Query = "SSL certificate problem goskope", Refs = new[] { "netcfg", "certerr", "bypass" },
            Linux = L(S("Confira data, hora e NTP:", "timedatectl")),
            Windows = L(S("Confira data, hora e NTP:", "w32tm /query /status")),
            Mac = L(S("Confira data e hora em Ajustes > Geral > Data e Hora.")),
            End = L(S("Veja quem assina o certificado do tenant — deve ser uma CA pública, não o seu firewall/proxy:", "openssl s_client -connect addon-{T}.goskope.com:443 -servername addon-{T}.goskope.com </dev/null | openssl x509 -noout -issuer"),
                    S("Se o emissor for o firewall/proxy/antivírus da empresa, crie nele uma regra de “não descriptografar” para *.goskope.com (a documentação exige essas conexões sem decriptação).")),
        },
        ["certexp"] = new()
        {
            Query = "certificate expired Netskope client", Refs = new[] { "trouble", "certs" },
            Linux = L(S("Sincronize o relógio:", "timedatectl\nsudo timedatectl set-ntp true")),
            Windows = L(S("Sincronize o relógio (admin):", "w32tm /resync")),
            End = L(S("Se o relógio estiver certo, refaça o registro do cliente para baixar novos certificados.")),
        },
        ["p407"] = new()
        {
            Query = "proxy authentication 407 Netskope client", Refs = new[] { "netcfg", "bypass" },
            All = L(S("No proxy corporativo, isente de autenticação e de decriptação os domínios *.goskope.com (ou ao menos " + Doms + ")."), S("Depois atualize a configuração:", "{NSD} -u")),
        },
        ["http"] = new()
        {
            Query = "Netskope client HTTP 403 enrollment", Refs = new[] { "trouble", "using" },
            All = L(S("No console: Settings > Security Cloud Platform > Devices — procure o usuário e confira se o dispositivo aparece e está ativo."),
                    S("Confira se o usuário está provisionado (SCIM/AD) e no grupo/OU coberto pela Client Configuration e pela Steering Configuration."),
                    S("Se o 403 persistir, refaça o registro: desinstale e reinstale o cliente com um novo convite.")),
            Linux = L(S("Desinstalar no Linux:", "sudo /opt/netskope/stagent/uninstall.sh")),
        },
        ["cfgdl"] = new()
        {
            Query = "failed to download config Netskope client", Refs = new[] { "using", "cmd", "netcfg" },
            All = L(S("É quase sempre consequência dos timeouts/DNS: resolva esses itens primeiro."), S("Force a atualização e veja a data de “Config Updated” em ícone > Configuration:", "{NSD} -u\n{NSD} -f")),
        },
        ["restapi"] = new()
        {
            Query = "restapi Failed to download Error -2", Refs = new[] { "netcfg", "cmd" },
            All = L(S("Os itens listados em “Detalhe” são as listas que não foram baixadas. Resolva a conectividade (addon-{T}.goskope.com) e force a atualização:", "{NSD} -u")),
        },
        ["bypasscat"] = new()
        {
            Query = "Failed to download bypass category list", Refs = new[] { "bypass", "exceptions" },
            All = L(S("Corrija a conectividade e rode:", "{NSD} -u"), S("Confirme no console (Steering Configuration > Exceptions) que as categorias de bypass estão corretas.")),
        },
        ["gslb"] = new()
        {
            Query = "GSLB fetch failed Netskope", Refs = new[] { "netcfg", "cmd" },
            All = L(S("Libere TCP 443 para gateway.gslb.goskope.com e dns.google."), S("Veja o POP e o gateway em uso:", "{NSD} -f"), S("Se o POP estiver errado ou lento, fixe temporariamente e depois volte ao automático:", "{NSD} --pin pop=BR-SAO1\n{NSD} --unpin")),
        },
        ["tundown"] = new()
        {
            Query = "Netskope client tunnel down disconnect", Refs = new[] { "trouble", "debug", "interop" },
            All = L(S("Compare com a linha do tempo: queda logo após “Serviço parado”, troca de rede ou suspensão é esperada."),
                    S("Se as quedas forem aleatórias, ative o modo debug, reproduza e colete o pacote para o suporte:", "{NSD} -b start\n# reproduza o problema\n{NSD} -b stop\n{NSD} -o netskope-logs.zip"),
                    S("Elimine conflitos com outras VPNs (veja o item de Conflito, se houver).")),
        },
        ["userdis"] = new()
        {
            Query = "allow disabling of clients tamperproof", Refs = new[] { "tamper", "disable", "clientcfg" },
            All = L(S("Peça ao usuário para reabilitar pelo ícone (Enable Netskope Client) ou rode:", "{NSD} -t enable"),
                    S("Pergunte o que motivou a desativação — geralmente é um site/app que quebrou; trate com exceção ou bypass em vez de desligar o cliente."),
                    S("Para impedir: Settings > Security Cloud Platform > Netskope Client > Client Configuration > Tamperproof > desmarque “Allow disabling of Clients” (ou exija senha mestra / reabilitação automática).")),
        },
        ["restart"] = new()
        {
            Query = "stagentd service stopping restart", Refs = new[] { "trouble", "clientcfg" },
            Linux = L(S("Veja quem parou o serviço:", "systemctl status stagentd.service\njournalctl -u stagentd.service --since today")),
            Windows = L(S("Veja o estado do serviço:", "sc query stagentsvc")),
            End = L(S("Confira em Client Configuration se atualização automática (Software Update / golden release) está ativa — reinícios coincidem com atualizações.")),
        },
        ["npagw"] = new()
        {
            Query = "Connection to GW gateway.npa.goskope.com terminated", Refs = new[] { "npagen", "npatool", "npastatus" },
            All = L(S("Veja o status do Private Access:", "{NSD} -n"), S("Libere TCP 443 para gateway.npa.goskope.com, *.npa.goskope.com e nsauth-{T}.goskope.com."), S("No console, use o NPA Troubleshooter (Private Access > Troubleshooter) com usuário e app privado.")),
            Linux = L(S("Em VMs clonadas, o NPA cai porque o machine-id é duplicado. Regere (procedimento oficial):",
                "sudo systemctl stop stagentd.service\nsudo rm /opt/netskope/stagent/data/npaccesscert.pem /opt/netskope/stagent/data/npaccesskey.pem /opt/netskope/stagent/data/npatenantcert.pem\nsudo rm /etc/machine-id /var/lib/dbus/machine-id\nsudo dbus-uuidgen --ensure\nsudo systemd-machine-id-setup\nsudo reboot")),
        },
        ["route"] = new()
        {
            Query = "nsRtNetlink ipRouteGet failed", Refs = new[] { "interop", "vpnexc" },
            Linux = L(S("Veja rotas e interfaces de VPN:", "ip route\nip -br link")),
            Windows = L(S("Veja as rotas:", "route print")),
            All = L(S("Remova interfaces de VPN órfãs e evite duas VPNs em túnel completo ao mesmo tempo.")),
        },
        ["driver"] = new()
        {
            Query = "Netskope client driver failed to start", Refs = new[] { "trouble", "interop" },
            All = L(S("Reinstale o cliente como administrador."), S("Verifique se antivírus/EDR bloqueou o driver e crie exclusão para o Netskope."), S("Colete log do driver:", "{NSD} -d start\n# reproduza\n{NSD} -d stop")),
        },
        ["iptables"] = new()
        {
            Query = "Netskope Linux iptables", Refs = new[] { "linux" },
            Linux = L(S("O cliente Linux exige iptables. Confira se está instalado e se outro firewall não reescreve as regras:", "sudo iptables -S | head -40"), RestartLinux),
        },
        ["fltqueue"] = new()
        {
            Query = "Netskope client packet drop performance Linux", Refs = new[] { "trouble" },
            All = L(S("Compare os horários das rajadas (detalhes) com o relato de lentidão e com a aba Desempenho (CPU, processos pesados)."),
                    S("Se coincidir com tráfego de containers ou de sincronização, avalie exceção de steering para esses destinos/processos."),
                    S("Atualize o cliente para a versão mais recente liberada no tenant.")),
            Linux = L(S("Veja carga e consumidores de CPU no momento:", "uptime; top -b -n1 | head -20")),
        },
        ["dnsbypass"] = new()
        {
            Query = "Netskope DNS uplink server bypass failed", Refs = new[] { "npagen" },
            Linux = L(S("Veja os servidores DNS ativos e teste o servidor dos detalhes:", "resolvectl status | sed -n '1,40p'\ndig @SERVIDOR_DNS www.google.com +time=2 +tries=1")),
            Windows = L(S("Veja os servidores DNS ativos e teste o servidor dos detalhes:", "ipconfig /all\nnslookup www.google.com SERVIDOR_DNS")),
        },
        ["sysca"] = new()
        {
            Query = "Netskope Linux certificate store nscacert update-ca-certificates", Refs = new[] { "certs", "devtools", "ubuntu" },
            Linux = L(S("Confira se o bundle do sistema já tem a CA do Netskope (procure “Netskope” na saída):",
                        "awk -v cmd='openssl x509 -noout -subject' '/BEGIN/{close(cmd)};{print | cmd}' /etc/ssl/certs/ca-certificates.crt | grep -i netskope"),
                      S("Ubuntu/Debian — copie as CAs do cliente e atualize o bundle:",
                        "sudo cp /opt/netskope/stagent/data/nscacert.pem /usr/local/share/ca-certificates/nscacert.crt\nsudo cp /opt/netskope/stagent/data/nstenantcert.pem /usr/local/share/ca-certificates/nstenantcert.crt\nsudo update-ca-certificates"),
                      S("Fedora/RHEL/Rocky — mesmo procedimento em outra pasta:",
                        "sudo cp /opt/netskope/stagent/data/nscacert.pem /etc/pki/ca-trust/source/anchors/nscacert.crt\nsudo cp /opt/netskope/stagent/data/nstenantcert.pem /etc/pki/ca-trust/source/anchors/nstenantcert.crt\nsudo update-ca-trust"),
                      S("Ferramentas que não leem o bundle do sistema precisam das variáveis (no ~/.bashrc e ~/.zshrc):",
                        "export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt\nexport REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt\nexport SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"),
                      S("Containers Docker não herdam o repositório do host: copie a CA para dentro da imagem (ou monte /etc/ssl/certs) e rode update-ca-certificates no build.")),
            Windows = L(S("No Windows a CA fica no repositório do computador. Confira em certlm.msc > Autoridades de Certificação Raiz Confiáveis se “Netskope” está listada.")),
            Mac = L(S("No macOS a CA fica no Keychain do sistema. Confira em Acesso às Chaves > Sistema se “Netskope” está como confiável.")),
        },
        ["firefox"] = new()
        {
            Query = "Firefox certificate Netskope Linux snap", Refs = new[] { "certs", "devtools", "ubuntu" },
            Linux = L(S("Instale o certutil:", "sudo apt install libnss3-tools"),
                      S("Importe as CAs do Netskope em todos os perfis do Firefox snap:",
                        "for d in ~/snap/firefox/common/.mozilla/firefox/*.default*; do\n  certutil -A -n \"Netskope CA\" -t \"C,,\" -i /usr/local/share/ca-certificates/nscacert.crt -d sql:\"$d\"\n  certutil -A -n \"Netskope Tenant CA\" -t \"C,,\" -i /usr/local/share/ca-certificates/nstenantcert.crt -d sql:\"$d\"\ndone"),
                      S("Reinicie o Firefox. Alternativa manual: Configurações > Privacidade e Segurança > Certificados > Ver certificados > Autoridades > Importar, marcando “Confiar nesta CA para identificar sites”.")),
            Windows = L(S("No Firefox, abra about:config e defina security.enterprise_roots.enabled = true (usa as CAs do Windows, onde o Netskope já instalou a sua).")),
            Mac = L(S("No Firefox, abra about:config e defina security.enterprise_roots.enabled = true.")),
        },
        ["ipc"] = new() { Query = "NSCOM2 disconnected by service", Refs = new[] { "trouble" }, Linux = L(RestartLinux), Windows = L(RestartWindows), Mac = L(RestartMac) },
        ["upn"] = new() { Query = "UPN enrollment Netskope client", Refs = new[] { "using" }, All = L(S("Sem ação se houve o evento “Registrado (enroll)”. Caso contrário, confira o UPN do usuário no IdP/AD e o método de instalação.")) },
        ["clientstatus"] = new() { Query = "Failed to post client status", Refs = new[] { "netcfg" }, All = L(S("Sem ação: é reenviado sozinho quando a conectividade volta.")) },
        ["dem"] = new() { Query = "DEM client status failure", Refs = new[] { "trouble" }, All = L(S("Sem impacto no tráfego.")) },
        ["npawait"] = new() { Query = "NPA dispatcher timeout", Refs = new[] { "npagen" }, All = L(S("Sem ação se isolado. Se recorrente, verifique uso de CPU do stAgentSvc.")) },
        ["broker"] = new() { Query = "No Primary broker configured NPA", Refs = new[] { "npagen" }, All = L(S("Sem ação, a menos que o Private Access não conecte.")) },
        ["perm"] = new() { Query = "Netskope permission denied err 13", Refs = new[] { "trouble" }, All = L(S("Veja o arquivo citado nos exemplos; se for do módulo bwan (SD-WAN) é inofensivo.")) },
        ["decrypt"] = new() { Query = "Invalid decryption of protected file", Refs = new[] { "trouble" }, All = L(S("Nenhuma ação, se o registro foi concluído. Se o erro continuar após o registro e o túnel não subir, reinstale o cliente.")) },
        ["orphan"] = new()
        {
            Query = "Netskope FortiClient VPN DNS conflict", Refs = new[] { "interop", "vpnexc", "forti" },
            Linux = L(S("Confirme as interfaces e o DNS que elas injetam:", "ip -br link | grep -iE \"fctvpn|tun|ppp|wg\"\nresolvectl status"),
                      S("Remova as interfaces órfãs:", "{DELIF}"),
                      S("Limpe o cache de DNS e atualize o Netskope:", "sudo resolvectl flush-caches\n{NSD} -u")),
            Windows = L(S("Liste adaptadores e DNS:", "ipconfig /all"), S("Desconecte a VPN de terceiros e desabilite/remova adaptadores virtuais que ficaram ativos sem conexão; depois:", "ipconfig /flushdns\n{NSD} -u")),
            End = L(S("Se o usuário já migrou para o Netskope, desinstale a VPN antiga para que as interfaces não voltem no próximo boot.")),
        },
        ["conflict"] = new()
        {
            Query = "Netskope client coexist third party VPN", Refs = new[] { "vpnexc", "forti", "interop" },
            All = L(S("Se a VPN antiga ainda for necessária: no console, crie um Network Location com o IP/FQDN do gateway VPN (Policies > Profiles > Network Location) e adicione uma exceção “Destination Location” na Steering Configuration (aba Exceptions)."),
                    S("No FortiGate, prefira split tunnel e evite VPN em túnel completo junto com o Netskope."),
                    S("Se a migração deste usuário já terminou, desinstale a VPN antiga.")),
            Linux = L(S("Remover o FortiClient (Ubuntu/Debian):", "sudo apt remove forticlient")),
            Windows = L(S("Remova pelo Painel de Controle > Programas e Recursos e reinicie.")),
        },
        ["deps"] = new()
        {
            Query = "Netskope client Linux dependencies install", Refs = new[] { "linux", "ubuntu" },
            Linux = L(S("Instale as dependências ausentes e reinicie o cliente:", "sudo apt install {MISSING}"), RestartLinux),
        },
        ["version"] = new()
        {
            Query = "Netskope client golden release version", Refs = new[] { "clientcfg" },
            All = L(S("Confira em Client Configuration > Software Update qual versão (golden release) o tenant distribui e se a atual é a esperada."), S("Versão em execução:", "{NSD} -v")),
        },
        ["failclose"] = new() { Query = "Netskope fail close client disabled", Refs = new[] { "disable", "tamper" }, All = L(S("Reabilite o cliente:", "{NSD} -t enable")) },
    };

    public static string NsdiagPath(ClientOs os) => os switch
    {
        ClientOs.Windows => "\"C:\\Program Files\\Netskope\\STAgent\\nsdiag.exe\"",
        ClientOs.Mac => "sudo \"/Library/Application Support/Netskope/STAgent/nsdiag\"",
        _ => "sudo /opt/netskope/stagent/nsdiag",
    };

    public static string OsLabel(ClientOs os) => os switch { ClientOs.Windows => "Windows", ClientOs.Mac => "macOS", _ => "Linux" };

    /// <summary>Monta os passos de resolução para o sistema do log, já com tenant e interfaces.</summary>
    public static List<FixStep> BuildSteps(Finding f, ClientOs? os, string? tenantHost)
    {
        if (!Fixes.TryGetValue(f.Key, out var d)) return new();
        var steps = new List<FixStep>(d.All);
        if (os is ClientOs o)
        {
            steps.AddRange(o switch { ClientOs.Windows => d.Windows, ClientOs.Mac => d.Mac, _ => d.Linux });
        }
        else
        {
            foreach (var (label, list) in new[] { ("Linux", d.Linux), ("Windows", d.Windows), ("macOS", d.Mac) })
                steps.AddRange(list.Select(s => s with { Text = $"({label}) {s.Text}" }));
        }
        steps.AddRange(d.End);
        string Sub(string t, ClientOs? osForCmd)
        {
            var nsd = NsdiagPath(osForCmd ?? ClientOs.Linux);
            // valores vindos do log entram nos comandos só se forem identificadores simples (evita injeção de comando)
            var delif = f.Interfaces.Count > 0 ? string.Join("\n", f.Interfaces.Select(i => "sudo ip link delete " + SafeText.Token(i, "<interface>")).Distinct()) : "sudo ip link delete <interface>";
            var missing = f.MissingPackages.Count > 0 ? string.Join(" ", f.MissingPackages.Select(p => SafeText.Token(p, "<pacote>")).Distinct()) : "<pacotes>";
            var tenant = tenantHost is null ? "<tenant>" : SafeText.Host(tenantHost, "<tenant>");
            return t.Replace("{NSD}", nsd).Replace("{T}", tenant).Replace("{DELIF}", delif).Replace("{MISSING}", missing);
        }
        return steps.Select(s =>
        {
            var cmdOs = os ?? (s.Text.StartsWith("(Windows)") ? ClientOs.Windows : s.Text.StartsWith("(macOS)") ? ClientOs.Mac : ClientOs.Linux);
            return new FixStep(Sub(s.Text, cmdOs), s.Command is null ? null : Sub(s.Command, cmdOs));
        }).ToList();
    }

    public static IEnumerable<Reference> ReferencesFor(string key) =>
        Fixes.TryGetValue(key, out var d) ? d.Refs.Where(Refs.ContainsKey).Select(r => Refs[r]) : Enumerable.Empty<Reference>();

    public static string QueryFor(string key, string fallback) => Fixes.TryGetValue(key, out var d) && d.Query.Length > 0 ? d.Query : fallback;

    public static IReadOnlyList<Reference> SearchLinks(string query)
    {
        static string E(string s) => Uri.EscapeDataString(s);
        return new List<Reference>
        {
            new("Docs Netskope", "https://www.google.com/search?q=" + E("site:docs.netskope.com " + query)),
            new("Comunidade", "https://www.google.com/search?q=" + E("site:community.netskope.com " + query)),
            new("Base de conhecimento (login)", "https://support.netskope.com/hc/en-us/search?query=" + E(query)),
            new("Web", "https://www.google.com/search?q=" + E("Netskope client " + query)),
        };
    }
}
