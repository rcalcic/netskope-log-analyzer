using System.Globalization;
using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

/// <summary>O que o analista informou antes de abrir o pacote: sintomas relatados, site afetado e horário do problema.</summary>
public sealed class AnalysisOptions
{
    public HashSet<string> Symptoms { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Domínio ou URL que o usuário não consegue acessar (opcional).</summary>
    public string? Domain { get; set; }
    /// <summary>Horário aproximado do problema, no fuso da máquina do usuário (opcional).</summary>
    public DateTime? ProblemTime { get; set; }
    public bool IsEmpty => Symptoms.Count == 0 && string.IsNullOrWhiteSpace(Domain) && ProblemTime is null;
}

public sealed record Symptom(string Id, string Label, string Hint, string[] FindingKeys);

public sealed record FocusCheck(string Name, string Status, string Detail);

public sealed class FocusResult
{
    public required Symptom Symptom { get; init; }
    /// <summary>"Problema encontrado", "Possível causa" ou "Nada relevante nos logs".</summary>
    public string Verdict { get; set; } = "";
    public string Summary { get; set; } = "";
    public List<FocusCheck> Checks { get; } = new();
    public List<string> NextSteps { get; } = new();
    public List<string> FindingKeys { get; } = new();
}

/// <summary>O que os logs mostram sobre um domínio/URL específico.</summary>
public sealed class DomainReport
{
    public required string Domain { get; init; }
    public int Lines { get; set; }
    public int Tunneled { get; set; }
    public int Bypassed { get; set; }
    public int Errors { get; set; }
    public int DnsQueries { get; set; }
    public Dictionary<string, int> Processes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Exceptions { get; } = new();
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }
    public List<string> Samples { get; } = new();
}

/// <summary>
/// Direciona a análise para o que o usuário relatou: para cada sintoma selecionado roda as verificações
/// que um analista de suporte faria, aponta evidências (com horário) e marca os itens relacionados.
/// </summary>
public static class FocusAnalyzer
{
    public static readonly IReadOnlyList<Symptom> All = new[]
    {
        new Symptom("lentidao", "Lentidão", "Sites e aplicações lentos com o Netskope ligado",
            new[] { "popsub", "resources", "heavyproc", "perfsched", "netchurn", "dnssuffix", "timeout", "gslb", "npawait", "npadrops" }),
        new Symptom("url", "Site ou URL não abre", "Erro, tela em branco ou timeout em um site específico",
            new[] { "ssl", "certexp", "http", "p407", "dns", "conn", "timeout", "failclose", "tundown", "dnssuffix" }),
        new Symptom("npa", "Private Access", "Aplicação privada (intranet, RDP, SSH, sistemas internos) não abre ou cai",
            new[] { "npadrops", "npagw", "npareauth", "popsub", "overlap", "dnssuffix", "orphan", "conflict", "session", "npawait", "prereg", "upn" }),
        new Symptom("dns", "DNS", "Nomes não resolvem, resolvem errado ou demoram",
            new[] { "dns", "dnssuffix", "orphan", "conflict" }),
        new Symptom("semnav", "Sem navegação", "Nada abre na Internet com o Netskope ligado",
            new[] { "tundown", "userdis", "restart", "crash", "failclose", "timeout", "conn", "dns", "gslb", "cfgdl", "ssl", "driver", "iptables", "ipc", "p407" }),
        new Symptom("quedas", "Quedas e desconexões", "Conexão cai e volta, sessões interrompidas",
            new[] { "npadrops", "tundown", "netchurn", "npagw", "restart", "perfsched", "timeout" }),
        new Symptom("cert", "Erro de certificado", "Aviso de certificado inválido, “conexão não é privada”",
            new[] { "ssl", "certexp", "firefox", "decrypt" }),
        new Symptom("app", "Aplicativo específico", "Teams, Zoom, Outlook, VPN, cliente de e-mail ou outro programa não conecta",
            new[] { "conflict", "ssl", "http", "timeout" }),
        new Symptom("bloqueio", "Acesso bloqueado", "Página de bloqueio do Netskope ou acesso negado",
            new[] { "failclose", "http" }),
        new Symptom("login", "Login e registro", "Cliente pede login, não registra o usuário ou o IdP falha",
            new[] { "upn", "prereg", "npareauth", "decrypt", "perm", "clientstatus" }),
        new Symptom("cliente", "Cliente desligado ou travando", "Netskope desabilitado, parando, reiniciando ou não abre",
            new[] { "userdis", "restart", "crash", "driver", "deps", "version", "ipc", "perm", "disk" }),
        new Symptom("maquina", "Máquina lenta (CPU/memória)", "Computador lento, ventoinha alta, travamentos",
            new[] { "resources", "heavyproc", "perfsched", "disk" }),
        new Symptom("vpn", "Conflito com VPN ou agente", "Outra VPN, EDR ou antivírus instalado junto",
            new[] { "conflict", "orphan", "overlap", "heavyproc", "dnssuffix" }),
        new Symptom("onprem", "Diferente na empresa e fora", "Funciona em um lugar e não no outro (On/Off Prem)",
            Array.Empty<string>()),
        new Symptom("wifi", "Wi-Fi ou rede instável", "Rede doméstica/hotspot, troca de rede, sinal fraco",
            new[] { "netchurn", "npadrops", "perfsched", "conn" }),
    };

    private const string Prob = "problema", Warn = "atenção", Ok = "ok", NoData = "sem dados";

    public static void Run(AnalysisResult r, AnalysisOptions o)
    {
        r.Options = o;
        r.Focus.Clear();
        foreach (var f in r.Findings) f.FocusTags.Clear();
        r.Domain = string.IsNullOrWhiteSpace(o.Domain) ? null : DomainSearch(r, o.Domain!);
        foreach (var s in All.Where(s => o.Symptoms.Contains(s.Id)))
        {
            var res = new FocusResult { Symptom = s };
            Checks(r, o, s, res);
            if (o.ProblemTime is DateTime pt) res.Checks.Insert(0, TimeCheck(r, pt, s));
            var probs = res.Checks.Count(c => c.Status == Prob);
            var warns = res.Checks.Count(c => c.Status == Warn);
            res.Verdict = probs > 0 ? "Problema encontrado" : warns > 0 ? "Possível causa" : "Nada relevante nos logs";
            var top = res.Checks.Where(c => c.Status is Prob or Warn).OrderBy(c => c.Status == Prob ? 0 : 1).Take(3).Select(c => c.Name.ToLowerInvariant()).ToList();
            res.Summary = top.Count > 0 ? "Pontos a verificar: " + string.Join("; ", top) + "." : "Nenhuma verificação deste sintoma encontrou problema no período dos logs. " + NoEvidenceTip(s);
            foreach (var f in r.Findings.Where(f => s.FindingKeys.Contains(f.Key) && f.Severity != Severity.Noise))
            {
                f.FocusTags.Add(s.Label);
                if (!res.FindingKeys.Contains(f.Key)) res.FindingKeys.Add(f.Key);
            }
            foreach (var f in r.Findings.Where(f => res.FindingKeys.Contains(f.Key) && f.Severity <= Severity.Warning).Take(4))
                if (!string.IsNullOrWhiteSpace(f.Action) && !res.NextSteps.Contains(f.Action)) res.NextSteps.Add(f.Action);
            res.NextSteps.AddRange(Tips(s).Where(t => !res.NextSteps.Contains(t)));
            r.Focus.Add(res);
        }
    }

    private static string NoEvidenceTip(Symptom s) => s.Id switch
    {
        "url" or "bloqueio" or "app" => "Se o problema continua, a decisão pode estar na política do tenant: procure o domínio e o usuário nos eventos do console no horário.",
        _ => "Confirme o horário do problema com o usuário e peça um novo pacote salvo logo depois de reproduzir.",
    };

    private static IEnumerable<string> Tips(Symptom s) => s.Id switch
    {
        "lentidao" => new[] { "Compare com o Netskope desabilitado por alguns minutos (se a política permitir): se continuar lento, a causa não é o túnel." },
        "url" => new[] { "Informe o domínio no campo “Site afetado” para ver se ele passa pelo túnel, está em exceção ou deu erro.", "Procure o domínio nos eventos do console (Skope IT) no horário: lá aparece se houve bloqueio por política ou erro de inspeção." },
        "npa" => new[] { "No console, use o Troubleshooter do Private Access com o usuário e a aplicação para ver política, publisher e conectividade." },
        "dns" => new[] { "Teste a resolução na máquina do usuário com e sem o Netskope (nslookup/resolvectl) e compare o servidor que respondeu." },
        "semnav" => new[] { "Peça ao usuário para abrir https://www.netskope.com e um site interno; se nada abre, desabilite o cliente por 1 minuto para isolar." },
        "cert" => new[] { "Na máquina, confira se a CA do Netskope está instalada e confiável no repositório do sistema e do navegador usado." },
        "app" => new[] { "Informe o domínio do serviço no campo “Site afetado”; se o app usa certificado fixo, ele precisa estar na lista de cert pinning (bypass)." },
        "bloqueio" => new[] { "O bloqueio por política é decidido no tenant: procure o domínio e o usuário nos eventos do console (Skope IT) no horário." },
        "login" => new[] { "Confira no console se o usuário existe/está no grupo certo e se o IdP está acessível pela rede da máquina." },
        "cliente" => new[] { "Se o cliente foi desabilitado pelo usuário, pergunte o motivo — normalmente ele estava contornando outro problema." },
        "maquina" => new[] { "Peça ao usuário para reiniciar a máquina se ela está ligada há dias e repetir o teste." },
        "vpn" => new[] { "Desinstale VPNs que não são mais usadas e remova interfaces/perfis que ficaram para trás." },
        "onprem" => new[] { "Compare um pacote salvo na empresa e outro fora: estado On/Off Prem, IP de saída e se o Private Access fica ativo." },
        "wifi" => new[] { "Peça ao usuário para testar cabeado ou outra rede (roteador do celular) e comparar." },
        _ => Array.Empty<string>(),
    };

    // ------------------------------------------------------------------ verificações

    private static Finding? F(AnalysisResult r, params string[] keys) =>
        r.Findings.Where(f => keys.Contains(f.Key) && f.Severity != Severity.Noise).OrderBy(f => f.Severity).FirstOrDefault();

    private static FocusCheck FromFindings(AnalysisResult r, string name, string okText, params string[] keys)
    {
        var fs = r.Findings.Where(f => keys.Contains(f.Key) && f.Severity != Severity.Noise).OrderBy(f => f.Severity).ToList();
        if (fs.Count == 0) return new(name, Ok, okText);
        var worst = fs[0].Severity;
        var st = worst == Severity.Critical ? Prob : worst == Severity.Warning ? Warn : Ok;
        return new(name, st, string.Join(" · ", fs.Take(3).Select(f => f.Title + (f.First is DateTime a ? $" ({Report.Time(a)})" : ""))));
    }

    private static FocusCheck? FromPerf(AnalysisResult r, string name, Func<PerfMetric, bool> pred)
    {
        var ms = r.Performance.Where(pred).ToList();
        if (ms.Count == 0) return null;
        var st = ms.Any(m => m.Status == "crítico") ? Prob : ms.Any(m => m.Status == "atenção") ? Warn : Ok;
        return new(name, st, string.Join(" · ", ms.Take(3).Select(m => $"{m.Name}: {m.Value}")));
    }

    private static FocusCheck Availability(AnalysisResult r, string svc)
    {
        if (!r.Availability.TryGetValue(svc, out var av)) return new($"Disponibilidade — {svc}", NoData, "Os logs não registram o estado deste túnel no período.");
        return new($"Disponibilidade — {svc}", av >= 99.5 ? Ok : av >= 97 ? Warn : Prob, $"{av:0.##}% do tempo conectado no período dos logs.");
    }

    private static FocusCheck Config(AnalysisResult r, string name, Func<ConfigItem, bool> pred, Func<ConfigItem, string> status)
    {
        var c = r.Config.FirstOrDefault(pred);
        return c is null ? new(name, NoData, "O pacote não traz essa configuração.") : new(name, status(c), $"{c.Item}: {c.Value}. {c.Meaning}");
    }

    private static void Add(FocusResult res, FocusCheck? c) { if (c != null) res.Checks.Add(c); }

    private static void Checks(AnalysisResult r, AnalysisOptions o, Symptom s, FocusResult res)
    {
        switch (s.Id)
        {
            case "lentidao":
                Add(res, FromPerf(r, "Latência até o POP", m => m.Name.StartsWith("Latência até o melhor POP", StringComparison.Ordinal)));
                Add(res, FromFindings(r, "POP escolhido", "O túnel usou o POP mais rápido medido.", "popsub"));
                Add(res, FromPerf(r, "Túnel do Private Access (RTT e retransmissões)", m => m.Name.StartsWith("RTT até o gateway", StringComparison.Ordinal) || m.Name.StartsWith("Retransmissões TCP", StringComparison.Ordinal)));
                Add(res, FromPerf(r, "Recursos da máquina", m => m.Group == TacInsights.ResourceGroup && m.Status != "—") ?? new("Recursos da máquina", NoData, "O pacote não tem foto de processos/memória."));
                Add(res, FromFindings(r, "Responsividade da máquina", "As tarefas periódicas do cliente rodaram no horário.", "perfsched"));
                Add(res, FromFindings(r, "Estabilidade da rede local", "Sem mudanças de rede em excesso.", "netchurn"));
                Add(res, FromFindings(r, "DNS", "Sem falhas nem sufixo de pesquisa indevido.", "dns", "dnssuffix"));
                Add(res, FromFindings(r, "Comunicação com o tenant", "Sem timeouts com o tenant/GSLB.", "timeout", "gslb"));
                if (r.Score is double sc) res.Checks.Add(new("Experience Score", sc <= 30 ? Prob : sc <= 70 ? Warn : Ok, $"{sc:0}/100 ({ExperienceScore.Band(sc)})" + (r.ScoreMissing != null ? $", parcial (sem {r.ScoreMissing})" : "") + "."));
                break;
            case "url":
            case "app":
            case "bloqueio":
                if (r.Domain is DomainReport d) res.Checks.Add(DomainCheck(r, d, s.Id));
                else res.Checks.Add(new("Site/domínio afetado", NoData, "Informe o domínio no campo “Site afetado” para ver como ele passou pelo cliente."));
                if (s.Id != "bloqueio") Add(res, FromFindings(r, "Certificados / inspeção SSL", "Sem erros de certificado registrados pelo cliente.", "ssl", "certexp"));
                Add(res, Availability(r, "Internet"));
                Add(res, FromFindings(r, "Fail-close / bloqueio quando o túnel cai", "Sem bloqueio por fail-close registrado.", "failclose"));
                if (s.Id == "app")
                {
                    res.Checks.Add(r.CertPinnedApps.Count > 0
                        ? new("Apps com certificado fixo (cert pinning)", Ok, "Na lista de bypass: " + string.Join(", ", r.CertPinnedApps.Take(10)) + (r.CertPinnedApps.Count > 10 ? "…" : "") + ". Se o app afetado não está aqui e usa certificado fixo, ele falha ao ser inspecionado.")
                        : new("Apps com certificado fixo (cert pinning)", NoData, "O pacote não traz a lista de cert pinning (nsbypass.json)."));
                    var udp = r.Apps.Where(a => a.BlockedUdp > 0).GroupBy(a => a.Process).OrderByDescending(g => g.Sum(a => a.BlockedUdp)).Take(5).ToList();
                    res.Checks.Add(udp.Count > 0
                        ? new("UDP/QUIC bloqueado por processo", Warn, string.Join(", ", udp.Select(g => $"{g.Key} ({g.Sum(a => a.BlockedUdp)})")) + ". Apps de voz/vídeo que dependem de UDP podem degradar.")
                        : new("UDP/QUIC bloqueado por processo", Ok, "Nenhum processo teve UDP bloqueado."));
                    Add(res, FromFindings(r, "VPN/agente de terceiros", "Nenhuma VPN concorrente detectada.", "conflict"));
                }
                if (s.Id == "url") Add(res, FromFindings(r, "Resolução DNS", "Sem falhas de resolução.", "dns", "dnssuffix"));
                if (s.Id == "url") Add(res, FromFindings(r, "Proxy no caminho", "Sem exigência de autenticação de proxy.", "p407"));
                break;
            case "npa":
                Add(res, Availability(r, "Private Access"));
                Add(res, FromFindings(r, "Quedas do túnel e motivo", "Nenhuma queda não programada.", "npadrops", "npagw"));
                Add(res, FromPerf(r, "Tempo de reconexão", m => m.Name.StartsWith("Tempo até reconectar", StringComparison.Ordinal)));
                Add(res, FromFindings(r, "POP do Private Access", "O túnel usou o POP mais rápido medido.", "popsub"));
                Add(res, FromFindings(r, "Redes locais sobrepostas às rotas do NPA", "Nenhuma faixa local coincide com as rotas do Private Access.", "overlap"));
                Add(res, FromFindings(r, "DNS das aplicações privadas", "Sem sufixo de pesquisa indevido.", "dnssuffix"));
                Add(res, FromFindings(r, "VPN de terceiros", "Nenhuma VPN concorrente ou órfã.", "conflict", "orphan"));
                Add(res, Config(r, "Private Access habilitado dentro/fora da empresa", c => c.Item == "Private Access", c => c.Value.Contains("na empresa: inativo", StringComparison.Ordinal) ? Warn : Ok));
                Add(res, FromFindings(r, "Reautenticação", "Sem reautenticações no período.", "npareauth"));
                if (r.Domain is DomainReport dn) res.Checks.Add(DomainCheck(r, dn, s.Id));
                break;
            case "dns":
                Add(res, FromFindings(r, "Falhas de resolução", "Sem falhas de resolução registradas.", "dns"));
                Add(res, FromFindings(r, "Domínio de pesquisa anexado a nomes públicos", "Não detectado.", "dnssuffix"));
                Add(res, FromPerf(r, "NXDOMAIN pelo Private Access", m => m.Name.StartsWith("DNS pelo Private Access", StringComparison.Ordinal)));
                var vpnDns = r.DnsInterfaces.Where(i => i.Note.Contains("VPN", StringComparison.Ordinal)).ToList();
                res.Checks.Add(r.DnsInterfaces.Count == 0 ? new("DNS por interface", NoData, "O pacote não traz a configuração de DNS das interfaces.")
                    : vpnDns.Count > 0 ? new("DNS por interface", Warn, $"{vpnDns.Count} interface(s) de VPN com DNS próprio: " + string.Join(", ", vpnDns.Take(4).Select(i => $"{i.Interface} → {string.Join(", ", i.Servers)}")))
                    : new("DNS por interface", Ok, string.Join(" · ", r.DnsInterfaces.Take(3).Select(i => $"{i.Interface} → {string.Join(", ", i.Servers)}"))));
                var fails = r.Captures.Sum(c => c.DnsRcodes.Where(k => k.Key is "SERVFAIL" or "REFUSED").Sum(k => k.Value));
                if (r.Captures.Count > 0) res.Checks.Add(new("Respostas DNS nas capturas", fails >= 5 ? Warn : Ok, string.Join(" · ", r.Captures.Where(c => c.DnsRcodes.Count > 0).Select(c => c.File + ": " + string.Join(", ", c.DnsRcodes.Select(k => $"{k.Key} {k.Value}")))) is { Length: > 0 } t ? t : "Sem DNS nas capturas."));
                if (r.Domain is DomainReport dd) res.Checks.Add(DomainCheck(r, dd, s.Id));
                break;
            case "semnav":
                Add(res, Availability(r, "Internet"));
                Add(res, FromFindings(r, "Cliente desabilitado pelo usuário", "O usuário não desabilitou o cliente.", "userdis"));
                Add(res, FromFindings(r, "Serviço parado, reiniciado ou travado", "O serviço não parou nem travou.", "restart", "crash"));
                Add(res, FromFindings(r, "Fail-close", "Sem bloqueio por fail-close.", "failclose"));
                Add(res, Config(r, "Fail-close configurado", c => c.Item == "Fail-close", c => c.Value == "sim" ? Warn : Ok));
                Add(res, FromFindings(r, "Comunicação com o tenant e GSLB", "Tenant e GSLB responderam.", "timeout", "conn", "gslb", "cfgdl"));
                Add(res, FromFindings(r, "Resolução de nomes", "Sem falhas de DNS.", "dns"));
                Add(res, FromFindings(r, "Inspeção SSL no caminho (firewall/proxy)", "Sem erros de certificado com o tenant.", "ssl", "p407"));
                Add(res, FromFindings(r, "Driver/firewall do cliente", "Sem falhas de driver ou regras de firewall.", "driver", "iptables", "ipc"));
                break;
            case "quedas":
                Add(res, Availability(r, "Internet"));
                Add(res, Availability(r, "Private Access"));
                Add(res, FromFindings(r, "Quedas do Private Access", "Nenhuma queda não programada.", "npadrops", "npagw"));
                Add(res, FromFindings(r, "Quedas do túnel Internet", "Nenhuma queda do túnel Internet.", "tundown"));
                Add(res, FromFindings(r, "Mudanças de rede", "Sem mudanças de rede em excesso.", "netchurn"));
                Add(res, FromFindings(r, "Suspensão/lentidão da máquina", "Sem atrasos de execução.", "perfsched"));
                Add(res, FromFindings(r, "Serviço reiniciado", "O serviço não reiniciou.", "restart", "crash"));
                break;
            case "cert":
                Add(res, FromFindings(r, "Erros de certificado do cliente", "Sem erros de certificado.", "ssl", "certexp"));
                Add(res, FromFindings(r, "CA no Firefox", "Sem falhas ao instalar a CA no Firefox.", "firefox"));
                Add(res, FromFindings(r, "Arquivos de configuração protegidos", "Sem falhas de leitura de arquivos protegidos.", "decrypt"));
                res.Checks.Add(r.CertPinnedApps.Count > 0 ? new("Apps com certificado fixo", Ok, string.Join(", ", r.CertPinnedApps.Take(10))) : new("Apps com certificado fixo", NoData, "Lista de cert pinning não está no pacote."));
                if (r.Domain is DomainReport dc) res.Checks.Add(DomainCheck(r, dc, s.Id));
                break;
            case "login":
                Add(res, FromFindings(r, "Registro do usuário (UPN/IdP)", "Sem falhas de registro.", "upn", "prereg"));
                Add(res, FromFindings(r, "Reautenticação do Private Access", "Sem reautenticações.", "npareauth"));
                Add(res, FromFindings(r, "Status do dispositivo no console", "Status enviado normalmente.", "clientstatus"));
                Add(res, FromFindings(r, "Permissões e arquivos protegidos", "Sem erros de permissão.", "perm", "decrypt"));
                Add(res, FromFindings(r, "Comunicação com o tenant", "Tenant respondeu.", "timeout", "conn", "restapi"));
                break;
            case "cliente":
                Add(res, FromFindings(r, "Desativação pelo usuário", "O usuário não desabilitou o cliente.", "userdis"));
                Add(res, Config(r, "Usuário pode desabilitar o cliente", c => c.Item == "Usuário pode desabilitar o cliente", c => c.Value == "sim" ? Warn : Ok));
                Add(res, FromFindings(r, "Serviço parado ou travado", "O serviço não parou nem travou.", "restart", "crash"));
                Add(res, FromFindings(r, "Versão e instalação", "Sem divergência de versão.", "version", "deps"));
                Add(res, FromFindings(r, "Driver e comunicação interna", "Sem falhas de driver/IPC.", "driver", "ipc"));
                Add(res, FromFindings(r, "Disco e permissões", "Sem disco cheio ou permissão negada.", "disk", "perm"));
                break;
            case "maquina":
                foreach (var m in r.Performance.Where(m => m.Group == TacInsights.ResourceGroup && m.Status != "—"))
                    res.Checks.Add(new(m.Name, m.Status == "crítico" ? Prob : m.Status == "atenção" ? Warn : Ok, m.Value));
                if (!r.Performance.Any(m => m.Group == TacInsights.ResourceGroup)) res.Checks.Add(new("Recursos da máquina", NoData, "O pacote não tem foto de processos/memória."));
                Add(res, FromFindings(r, "Agentes que disputam CPU", "Nenhum processo com uso contínuo alto.", "heavyproc"));
                Add(res, FromFindings(r, "Responsividade", "Sem atrasos de execução.", "perfsched"));
                Add(res, FromPerf(r, "Consumo do Netskope Client", m => m.Name.StartsWith("Consumo do próprio Netskope", StringComparison.Ordinal)));
                break;
            case "vpn":
                Add(res, FromFindings(r, "VPN de terceiros em execução", "Nenhuma VPN concorrente em execução.", "conflict"));
                Add(res, FromFindings(r, "Interfaces de VPN órfãs", "Nenhuma interface órfã.", "orphan"));
                Add(res, FromFindings(r, "Rotas sobrepostas", "Sem sobreposição com o Private Access.", "overlap"));
                Add(res, FromFindings(r, "DNS herdado de VPN", "Sem domínio de pesquisa indevido.", "dnssuffix"));
                Add(res, FromFindings(r, "EDR/antivírus", "Nenhum agente com uso contínuo alto.", "heavyproc"));
                break;
            case "onprem":
                Add(res, Config(r, "Detecção on-prem", c => c.Section == "Detecção on-prem", c => Ok));
                res.Checks.Add(r.Facts.OnPrem != null ? new("Estado no período", Ok, r.Facts.OnPrem) : new("Estado no período", NoData, "Os logs não registram On/Off Prem."));
                Add(res, Config(r, "Private Access dentro/fora", c => c.Item == "Private Access", c => c.Value.Contains("na empresa: inativo", StringComparison.Ordinal) ? Warn : Ok));
                res.Checks.Add(r.EgressHistory.Count > 1 ? new("Troca de IP de saída", Warn, $"{r.EgressHistory.Count} IPs de saída no período: " + string.Join(", ", r.EgressHistory.Select(k => k.Value).Distinct().Take(5))) : new("Troca de IP de saída", Ok, "Um único IP de saída no período."));
                Add(res, FromFindings(r, "Exceções e steering", "Sem falhas de steering.", "cfgdl"));
                break;
            case "wifi":
                Add(res, FromFindings(r, "Mudanças de rede", "Sem mudanças de rede em excesso.", "netchurn"));
                Add(res, FromFindings(r, "Quedas junto com o tenant (Internet caiu)", "Sem quedas simultâneas.", "npadrops"));
                var wifi = r.Snapshots.Select(x => x.Wifi).FirstOrDefault(w => w != null);
                res.Checks.Add(wifi?.SignalPct is double sg ? new("Sinal Wi-Fi na coleta", sg < 40 ? Prob : sg < 60 ? Warn : Ok, $"{sg:0}% em “{wifi.Ssid}”" + (wifi.Band != null ? $" ({wifi.Band})" : "")) : new("Sinal Wi-Fi na coleta", NoData, "O pacote não traz o sinal do Wi-Fi."));
                Add(res, FromFindings(r, "Suspensão/atrasos", "Sem atrasos de execução.", "perfsched"));
                break;
        }
    }

    private static FocusCheck DomainCheck(AnalysisResult r, DomainReport d, string symptom)
    {
        if (d.Lines == 0 && d.Exceptions.Count == 0)
            return new($"Site {d.Domain}", Warn, "O domínio não aparece em nenhum log do cliente: o tráfego não passou pelo Netskope Client (steering não inclui esse tráfego, bypass por IP, outro navegador/rede) ou o acesso não aconteceu no período coberto.");
        var parts = new List<string>();
        if (d.Tunneled > 0) parts.Add($"{d.Tunneled} conexão(ões) tunelada(s) para inspeção");
        if (d.Bypassed > 0) parts.Add($"{d.Bypassed} em bypass (exceção)");
        if (d.DnsQueries > 0) parts.Add($"{d.DnsQueries} consulta(s) DNS");
        if (d.Errors > 0) parts.Add($"{d.Errors} linha(s) de erro/aviso");
        if (d.Processes.Count > 0) parts.Add("processos: " + string.Join(", ", d.Processes.OrderByDescending(k => k.Value).Take(4).Select(k => k.Key)));
        if (d.Exceptions.Count > 0) parts.Add("está nas exceções: " + string.Join("; ", d.Exceptions.Take(3)));
        var status = d.Errors > 0 ? Warn : Ok;
        var detail = string.Join(" · ", parts) + (d.First is DateTime a ? $" ({Report.Time(a)} → {Report.Time(d.Last)})" : "") + ".";
        if (d.Exceptions.Count > 0 && symptom is "url" or "bloqueio") detail += " Em exceção, o Netskope não inspeciona nem bloqueia este site — o problema está fora do Netskope.";
        else if (d.Tunneled > 0 && d.Errors == 0 && symptom is "url" or "bloqueio") detail += " O cliente encaminhou o tráfego normalmente; se houve bloqueio ou erro, a decisão foi na política do tenant.";
        return new($"Site {d.Domain}", status, detail);
    }

    private static FocusCheck TimeCheck(AnalysisResult r, DateTime t, Symptom s)
    {
        var from = t.AddMinutes(-30); var to = t.AddMinutes(30);
        if (r.Start is DateTime st && r.End is DateTime en && (t < st.AddMinutes(-30) || t > en.AddMinutes(30)))
            return new($"Horário informado ({t:dd/MM HH:mm})", NoData, $"Fora do período dos logs ({Report.Time(st)} → {Report.Time(en)}). Peça ao usuário um pacote salvo logo depois do problema.");
        var inc = r.Incidents.Where(i => i.Start <= to && i.End >= from).OrderBy(i => Math.Abs((i.Start - t).TotalMinutes)).ToList();
        var fnd = r.Findings.Where(f => f.Severity <= Severity.Warning && f.Times.Any(x => x >= from && x <= to)).ToList();
        if (inc.Count == 0 && fnd.Count == 0)
            return new($"Horário informado ({t:dd/MM HH:mm} ± 30 min)", Ok, "Nenhum incidente nem erro relevante nesse intervalo.");
        var parts = inc.Take(3).Select(i => $"{i.Start:HH:mm} {i.Title}" + (i.Causes.FirstOrDefault() is Cause c ? $" — {c.Title.ToLowerInvariant()} ({c.Confidence:0}%)" : "")).ToList();
        parts.AddRange(fnd.Where(f => !inc.Any(i => i.FindingKey == f.Key)).Take(3).Select(f => $"{f.Title} ({f.Times.Count(x => x >= from && x <= to)}x)"));
        foreach (var i in inc) i.InFocusWindow = true;
        return new($"Horário informado ({t:dd/MM HH:mm} ± 30 min)", inc.Any(i => i.Severity == Severity.Critical) ? Prob : Warn, string.Join(" · ", parts));
    }

    // ------------------------------------------------------------------ busca por domínio

    public static string NormalizeDomain(string input)
    {
        var s = input.Trim();
        if (Uri.TryCreate(s.Contains("://", StringComparison.Ordinal) ? s : "https://" + s, UriKind.Absolute, out var u) && !string.IsNullOrEmpty(u.Host)) s = u.Host;
        s = s.Trim().TrimEnd('.').ToLowerInvariant();
        if (s.StartsWith("*.", StringComparison.Ordinal)) s = s[2..];
        return s.Length > 253 ? s[..253] : s;
    }

    internal static bool PatternMatches(string pattern, string domain)
    {
        var p = pattern.Trim().ToLowerInvariant().TrimEnd('.');
        if (p.Length == 0) return false;
        if (p.StartsWith("*.", StringComparison.Ordinal)) { var b = p[2..]; return domain == b || domain.EndsWith("." + b, StringComparison.Ordinal); }
        if (p.Contains('*'))
        {
            try { return Regex.IsMatch(domain, "^" + Regex.Escape(p).Replace(@"\*", "[^.]*") + "$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200)); }
            catch (RegexMatchTimeoutException) { return false; }
        }
        return domain == p || domain.EndsWith("." + p, StringComparison.Ordinal);
    }

    private static readonly Regex TunnelHostRe = new(@"process: (\S+) to host: ([^,\s]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex BypassHostRe = new(@"exception host: ([^,\s]+), process: ([^,]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static DomainReport DomainSearch(AnalysisResult r, string input)
    {
        var dom = NormalizeDomain(input);
        var d = new DomainReport { Domain = dom };
        if (dom.Length < 3) return d;
        foreach (var e in r.Entries)
        {
            if (e.Line.IndexOf(dom, StringComparison.OrdinalIgnoreCase) < 0) continue;
            d.Lines++;
            d.First ??= e.Time; d.Last = e.Time;
            var m = e.Message;
            var t = TunnelHostRe.Match(m);
            if (m.Contains("Tunneling flow", StringComparison.Ordinal) && t.Success && t.Groups[2].Value.EndsWith(dom, StringComparison.OrdinalIgnoreCase))
            { d.Tunneled++; d.Processes[t.Groups[1].Value] = d.Processes.GetValueOrDefault(t.Groups[1].Value) + 1; }
            else if (BypassHostRe.Match(m) is { Success: true } b && b.Groups[1].Value.EndsWith(dom, StringComparison.OrdinalIgnoreCase))
            { d.Bypassed++; var p = b.Groups[2].Value.Trim(); d.Processes[p] = d.Processes.GetValueOrDefault(p) + 1; }
            else if (m.Contains("name = ", StringComparison.Ordinal)) d.DnsQueries++;
            if (e.Level is LogLevel.Error or LogLevel.Critical or LogLevel.Warn) d.Errors++;
            if (d.Samples.Count < 40 && (e.Level != LogLevel.Info || d.Samples.Count < 15)) d.Samples.Add(r.Files[e.FileIndex].BaseName + ": " + (e.Line.Length > 300 ? e.Line[..300] : e.Line));
        }
        foreach (var (section, pat) in r.ExceptionPatterns)
            if (PatternMatches(pat, dom)) d.Exceptions.Add($"{section}: {pat}");
        return d;
    }
}
