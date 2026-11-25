namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Detecta incidentes (quedas de túnel, rajadas de falhas com o tenant, quedas do NPA, desativação,
/// experiência ruim, falhas de teste HTTP) e correlaciona, para cada um, as causas candidatas
/// observadas na janela anterior (5 min antes até 1 min depois do início): Wi-Fi, troca de rede,
/// latência/perda, DNS, recursos do dispositivo, suspensão, reinício do serviço, ação do usuário,
/// tenant inacessível e conflitos de VPN. Cada causa recebe uma confiança de 0 a 100% e as evidências.
/// </summary>
public static class RootCause
{
    private static readonly TimeSpan Before = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan After = TimeSpan.FromMinutes(1);
    private static readonly string[] TenantFailKeys = { "timeout", "conn", "ssl", "http", "cfgdl", "gslb", "p407", "restapi" };

    public static void Analyze(AnalysisResult r)
    {
        var incidents = new List<Incident>();
        var ev = r.Events.OrderBy(e => e.Time).ToList();

        // 1) quedas de túnel (por serviço), até a próxima reconexão
        foreach (var s in r.States.Where(x => x.State != "Conectado" && x.State != "Habilitado" && x.Service is "Internet" or "Private Access"))
        {
            if (s.State is "Serviço parado" or "Reautenticando" or "Parado pelo cliente" || s.State.StartsWith("Sem atividade", StringComparison.Ordinal)) continue;
            var sev = s.Duration.TotalMinutes >= 5 ? Severity.Critical : Severity.Warning;
            incidents.Add(new Incident
            {
                Title = $"{s.Service}: {s.State.ToLowerInvariant()}", Start = s.Start, End = s.End, Severity = sev, Kind = "túnel",
                Impact = $"Serviço {s.Service} indisponível por {TelemetryParser.Fmt(s.Duration)}" + (s.Service == "Internet" ? " (sem inspeção ou sem navegação, conforme o fail-close)." : " (aplicações privadas inacessíveis)."),
                FindingKey = s.State.Contains("usuário") ? "userdis" : s.Service == "Private Access" && r.Findings.Any(f => f.Key == "npadrops") ? "npadrops" : "tundown",
            });
        }

        // 2) rajadas de falhas com o tenant / DNS / NPA
        void Bursts(string[] keys, string title, string kind, string? findingKey, int min)
        {
            var times = r.Findings.Where(f => keys.Contains(f.Key) && f.Severity <= Severity.Warning).SelectMany(f => f.Times).OrderBy(t => t).ToList();
            foreach (var (a, b, n) in Clusters(times, TimeSpan.FromMinutes(2)))
            {
                if (n < min) continue;
                incidents.Add(new Incident
                {
                    Title = title, Start = a, End = b == a ? a.AddSeconds(30) : b, Kind = kind, FindingKey = findingKey,
                    Severity = n >= 10 || (b - a).TotalMinutes >= 5 ? Severity.Critical : Severity.Warning,
                    Impact = $"{n} falha(s) em {TelemetryParser.Fmt(b - a)}.",
                });
            }
        }
        Bursts(TenantFailKeys, "Falhas de comunicação com o tenant Netskope", "tenant", "timeout", 3);
        Bursts(new[] { "dns" }, "Falhas de resolução DNS", "dns", "dns", 2);
        if (r.NpaSessions.Count == 0) Bursts(new[] { "npagw" }, "Private Access: conexão com o gateway caiu", "npa", "npagw", 1);

        // 3) experiência ruim (janelas consecutivas com score <= 30)
        foreach (var (a, b, n) in Clusters(r.Scores.Where(s => s.Score <= 30).Select(s => s.Start).ToList(), ExperienceScore.Window + TimeSpan.FromSeconds(1)))
            incidents.Add(new Incident
            {
                Title = "Experiência ruim (score ≤ 30)", Start = a, End = b + ExperienceScore.Window, Kind = "experiência", Severity = Severity.Warning,
                Impact = $"{n} janela(s) de 5 min com experiência ruim.",
            });

        // 4) testes HTTP/TCP do coletor falhando
        foreach (var (a, b, n) in Clusters(ev.Where(e => e.Label is "Falha no teste HTTP" or "Falha de conexão TCP").Select(e => e.Time).ToList(), TimeSpan.FromMinutes(3)))
            if (n >= 2)
                incidents.Add(new Incident { Title = "Aplicações/POP inacessíveis nos testes do coletor", Start = a, End = b, Kind = "aplicação", Severity = Severity.Warning, Impact = $"{n} teste(s) com falha." });

        // 5) anomalias críticas de dispositivo/rede sem outro incidente (ex.: CPU a 100%)
        foreach (var an in r.Anomalies.Where(x => x.Critical && x.Group is MetricCatalog.Device or MetricCatalog.Wifi or MetricCatalog.Network
                     && !x.SeriesKey.StartsWith("npa.dns", StringComparison.Ordinal) && !x.SeriesKey.StartsWith("net.changes", StringComparison.Ordinal) && !x.SeriesKey.StartsWith("perf.", StringComparison.Ordinal)))
            incidents.Add(new Incident
            {
                Title = $"{an.Label} em nível crítico", Start = an.Start, End = an.End > an.Start ? an.End : an.Start.AddSeconds(30), Kind = "métrica", Severity = Severity.Warning,
                Impact = $"Pico de {an.Peak:0.#} {an.Unit} (normal: {an.Reference:0.#} {an.Unit}).",
            });

        // mescla incidentes sobrepostos (o de maior prioridade fica com o título)
        incidents.Sort((x, y) => x.Start.CompareTo(y.Start));
        var merged = new List<Incident>();
        foreach (var inc in incidents.OrderBy(i => i.Start).ThenBy(i => Priority(i)))
        {
            var host = merged.LastOrDefault(m => inc.Start <= m.End + TimeSpan.FromMinutes(2) && inc.Start >= m.Start - TimeSpan.FromMinutes(2));
            if (host is null) { merged.Add(inc); continue; }
            if (Priority(inc) < Priority(host))
            {
                var promoted = new Incident { Title = inc.Title, Start = Priority(inc) <= 1 ? inc.Start : Min(inc.Start, host.Start), End = Max(inc.End, host.End), Kind = inc.Kind, Severity = (Severity)Math.Min((int)inc.Severity, (int)host.Severity), Impact = inc.Impact + " " + host.Impact, FindingKey = inc.FindingKey ?? host.FindingKey };
                merged[merged.IndexOf(host)] = promoted;
            }
            else
            {
                host.End = Max(host.End, inc.End);
                host.Severity = (Severity)Math.Min((int)inc.Severity, (int)host.Severity);
                if (!host.Impact.Contains(inc.Title, StringComparison.Ordinal)) host.Impact += $" Também: {inc.Title.ToLowerInvariant()} ({inc.Impact.TrimEnd('.')}).";
            }
        }

        foreach (var inc in merged)
        {
            Correlate(r, inc, ev);
            Evidence(r, inc, ev);
        }
        r.Incidents.AddRange(merged.OrderBy(i => i.Severity).ThenByDescending(i => i.Duration).ThenBy(i => i.Start).Take(60));
        r.Incidents.Sort((a, b) => a.Start.CompareTo(b.Start));
    }

    private static int Priority(Incident i) => i.Kind switch { "túnel" => 0, "npa" => 1, "tenant" => 2, "dns" => 3, "aplicação" => 4, "experiência" => 5, _ => 6 };
    private static DateTime Min(DateTime a, DateTime b) => a < b ? a : b;
    private static DateTime Max(DateTime a, DateTime b) => a > b ? a : b;

    public static IEnumerable<(DateTime Start, DateTime End, int Count)> Clusters(List<DateTime> times, TimeSpan gap)
    {
        if (times.Count == 0) yield break;
        times.Sort();
        DateTime a = times[0], b = times[0]; var n = 1;
        for (var i = 1; i < times.Count; i++)
        {
            if (times[i] - b <= gap) { b = times[i]; n++; continue; }
            yield return (a, b, n);
            a = b = times[i]; n = 1;
        }
        yield return (a, b, n);
    }

    private static void Correlate(AnalysisResult r, Incident inc, List<TimelineEvent> ev)
    {
        var from = inc.Start - Before; var to = inc.Start + After;
        var inWin = ev.Where(e => e.Time >= from && e.Time <= Max(to, inc.Start.AddMinutes(1))).ToList();
        double Prox(DateTime t) // 1.0 colado no início do incidente, caindo até 0.5 no limite da janela
            => t >= inc.Start ? 0.9 : 1.0 - 0.5 * Math.Min(1, (inc.Start - t).TotalSeconds / Before.TotalSeconds);
        MetricSeries? S(string k) => r.Series.TryGetValue(k, out var s) ? s : null;
        IEnumerable<MetricSeries> P(string p) => r.Series.Values.Where(s => s.Key.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        var causes = new List<Cause>();
        void C(string title, string cat, double conf, string evidence, string rec, string? fk = null) =>
            causes.Add(new Cause(title, cat, Math.Round(Math.Clamp(conf, 0.05, 0.98) * 100), evidence, rec, fk));

        // ação do usuário
        var userDis = inWin.LastOrDefault(e => e.Label == "Desabilitado pelo usuário");
        if (userDis != null || inc.FindingKey == "userdis")
            C("O usuário desabilitou o Netskope Client", "Ação do usuário", 0.95, userDis is null ? "Evento “User Disabled”." : $"{userDis.Time:HH:mm:ss} desabilitado pelo usuário ({userDis.Detail}).",
                "Confirme com o usuário o motivo; considere bloquear a desativação (Tamperproof).", "userdis");

        // reinício do serviço
        var stop = inWin.LastOrDefault(e => e.Label == "Serviço parado");
        if (stop != null)
            C("Reinício/parada do serviço Netskope", "Serviço", 0.9 * Prox(stop.Time), $"{stop.Time:HH:mm:ss} serviço stAgentSvc parado.",
                "Verifique atualizações automáticas, reinstalação ou scripts que reiniciam o serviço.", "restart");

        // suspensão / lacuna
        var gap = ev.LastOrDefault(e => (e.Label is "Lacuna na telemetria" or "Suspensão") && e.Time <= inc.Start && e.Time >= inc.Start.AddMinutes(-30));
        if (gap != null)
            C("Suspensão, hibernação ou desligamento da máquina", "Energia", 0.75, $"{gap.Time:HH:mm:ss} {gap.Label.ToLowerInvariant()}: {gap.Detail}.",
                "Quedas logo após voltar da suspensão são esperadas; se o túnel demora a voltar, verifique a política de energia do adaptador de rede.");

        // Wi-Fi
        var wifiEv = inWin.LastOrDefault(e => e.Label is "Wi-Fi desconectado" or "Troca de rede Wi-Fi" or "Roaming Wi-Fi (troca de AP)");
        var sigMin = Baseline.Worst(S("wifi.signal"), from, to);
        var rssiMin = Baseline.Worst(S("wifi.rssi"), from, to);
        if (wifiEv != null)
            C(wifiEv.Label == "Roaming Wi-Fi (troca de AP)" ? "Troca de ponto de acesso Wi-Fi (roaming)" : "Wi-Fi caiu ou trocou de rede", "Wi-Fi",
                (wifiEv.Label == "Wi-Fi desconectado" ? 0.92 : 0.7) * Prox(wifiEv.Time), $"{wifiEv.Time:HH:mm:ss} {wifiEv.Label.ToLowerInvariant()} {wifiEv.Detail}".Trim() + ".",
                "Verifique cobertura e estabilidade do Wi-Fi (canal, interferência, distância do AP); prefira 5 GHz/cabo.");
        if (sigMin is double sg && sg <= 40 || rssiMin is double rs && rs <= -78)
            C("Sinal Wi-Fi fraco", "Wi-Fi", sigMin is double s2 ? (s2 <= 25 ? 0.85 : 0.65) : 0.7,
                sigMin is double s3 ? $"Sinal mínimo de {s3:0}% na janela." : $"RSSI mínimo de {rssiMin:0} dBm na janela.",
                "Aproxime do AP, troque para 5 GHz ou cabo; avalie o posicionamento dos APs.");

        // troca de rede / IP de saída / gateway / localização
        var netEv = inWin.LastOrDefault(e => e.Label is "IP de saída mudou" or "Gateway padrão mudou" or "Mudança de rede" or "Servidores DNS mudaram" || e.Label.StartsWith("Local: ", StringComparison.Ordinal));
        if (netEv != null)
            C("Troca de rede (IP de saída, gateway ou localização mudou)", "Rede", 0.8 * Prox(netEv.Time), $"{netEv.Time:HH:mm:ss} {netEv.Label.ToLowerInvariant()} {netEv.Detail}".Trim() + ".",
                "Quedas breves durante troca de rede são normais; se forem frequentes, investigue Wi-Fi/roteador, VPN de terceiros ou on-prem/off-prem.");

        // latência / perda (provedor)
        var loss = P("ping.loss:").Select(s => Baseline.Worst(s, from, to)).Where(v => v != null).Select(v => v!.Value).DefaultIfEmpty(0).Max();
        var rttW = P("ping.rtt:").Concat(P("pop.best:")).Concat(P("pop.rtt:")).Select(s => Baseline.Worst(s, from, to)).Where(v => v != null).Select(v => v!.Value).DefaultIfEmpty(0).Max();
        if (loss >= 5 || rttW >= 250)
        {
            // se o Wi-Fi caiu/está fraco ou a máquina estava suspensa, a perda é sintoma e não causa
            var symptom = causes.Any(c => c.Category is "Wi-Fi" or "Energia" && c.Confidence >= 55);
            C("Latência alta ou perda de pacotes no caminho (provedor/rede local)", "Rede", (loss >= 20 ? 0.85 : loss >= 5 ? 0.7 : 0.6) * (symptom ? 0.6 : 1),
                $"{(loss > 0 ? $"perda máx. {loss:0}%" : "")}{(loss > 0 && rttW > 0 ? ", " : "")}{(rttW > 0 ? $"latência máx. {rttW:0} ms" : "")} na janela" + (symptom ? " (provável consequência do Wi-Fi/suspensão)." : "."),
                "Compare o traceroute (aba Rede) para ver em qual trecho a latência aparece: rede local, provedor ou Netskope.");
        }

        // Private Access: gateway sem resposta / encerrado
        var npaDrop = inWin.LastOrDefault(e => e.Label == "Private Access desconectado");
        if (npaDrop != null)
        {
            var tenantNear = r.Findings.Where(f => TenantFailKeys.Contains(f.Key) && f.Severity != Severity.Noise).SelectMany(f => f.Times).Count(t => t >= from && t <= inc.End.AddMinutes(2));
            var retrans = Baseline.Worst(S("npa.gw.retrans"), from.AddMinutes(-10), to);
            var keep = npaDrop.Detail.Contains("keepalive", StringComparison.OrdinalIgnoreCase);
            if (tenantNear > 0)
                C("A Internet da máquina caiu ou ficou instável (túnel NPA e tenant pararam de responder juntos)", "Rede", keep ? 0.82 : 0.7,
                    $"{npaDrop.Time:HH:mm:ss} {npaDrop.Detail}; {tenantNear} falha(s) de comunicação com o tenant/GSLB no mesmo intervalo" + (retrans is double rt && rt > 0 ? $"; {rt:0} retransmissões em 5 min antes da queda." : "."),
                    "Pergunte ao usuário se a Internet/Wi-Fi caiu nesse horário e verifique roteador e provedor; se for recorrente, compare com outra rede.", "npadrops");
            else if (keep)
                C("Caminho até o POP do Private Access instável (gateway deixou de responder)", "Rede", 0.65,
                    $"{npaDrop.Time:HH:mm:ss} {npaDrop.Detail}" + (retrans is double rt2 && rt2 > 0 ? $"; {rt2:0} retransmissões em 5 min." : "."),
                    "Teste o caminho até o POP (mtr/pathping na aba Diagnóstico) e compare com outro POP/rede.", "npadrops");
            else if (npaDrop.Detail.Contains("DNS", StringComparison.Ordinal))
                C("Falha de DNS ao localizar o gateway do Private Access", "DNS", 0.75, $"{npaDrop.Time:HH:mm:ss} {npaDrop.Detail}.", "Verifique os servidores DNS ativos e domínios de pesquisa (aba Rede).", "dnssuffix");
        }

        // mudanças de rede em excesso (interfaces virtuais)
        var churn = r.Findings.FirstOrDefault(f => f.Key == "netchurn");
        if (churn != null && Baseline.Worst(S("net.changes"), from.AddMinutes(-5), to) is double nch && nch >= 2)
            C("Mudanças de rede em excesso (interfaces virtuais subindo e descendo)", "Rede", causes.Count == 0 ? 0.55 : 0.35,
                $"{nch:0} mudança(s) de rede em 10 min perto do início. {churn.Title}.", churn.Action, "netchurn");

        // DNS
        var dnsHits = r.Findings.Where(f => f.Key == "dns").SelectMany(f => f.Times).Count(t => t >= from && t <= to)
                      + inWin.Count(e => e.Label == "Falha de DNS");
        if (dnsHits > 0)
        {
            var orphan = r.Findings.FirstOrDefault(f => f.Key == "orphan");
            C(orphan != null ? "DNS inacessível — provável DNS de VPN órfã" : "Falha de resolução DNS", "DNS",
                orphan != null ? 0.85 : 0.7, $"{dnsHits} falha(s) de DNS na janela." + (orphan != null ? $" {orphan.Title}." : ""),
                orphan != null ? "Remova as interfaces de VPN órfãs (veja o diagnóstico) e limpe o cache de DNS." : "Verifique os servidores DNS ativos e se respondem fora da rede corporativa.",
                orphan != null ? "orphan" : "dns");
        }

        // recursos do dispositivo
        var cpuMax = Baseline.Worst(S("cpu"), from, to);
        var memMax = Baseline.Worst(S("mem.used"), from, to);
        if (cpuMax is double cm && cm >= 90 || memMax is double mm && mm >= 95)
        {
            var top = ProcessTimeline.TopAt(r, from, to);
            C("Recursos do dispositivo esgotados (CPU/memória)", "Dispositivo", 0.7,
                $"{(cpuMax is double c1 ? $"CPU máx. {c1:0}%" : "")}{(memMax is double m1 ? $" memória máx. {m1:0}%" : "")}".Trim() + (top != null ? $". Maiores consumidores: {top}." : "."),
                "Identifique o processo consumidor (aba Dispositivo) e avalie atualização, limitação ou upgrade de hardware.");
        }
        var diskMin = P("disk.free:").Select(s => Baseline.Worst(s, from, to)).Where(v => v != null).Select(v => v!.Value).DefaultIfEmpty(double.MaxValue).Min();
        if (diskMin <= 2)
            C("Disco quase cheio", "Dispositivo", 0.6, $"Apenas {diskMin:0.#} GB livres.", "Libere espaço; o cliente precisa gravar configuração e logs.", "disk");

        // tenant/POP inacessível (falhas sem causa local aparente)
        var tenantHits = r.Findings.Where(f => TenantFailKeys.Contains(f.Key) && f.Severity != Severity.Noise).SelectMany(f => f.Times).Count(t => t >= from && t <= inc.End);
        if (tenantHits > 0 && !causes.Any(c => c.Category is "Wi-Fi" or "Rede" or "DNS" or "Energia" or "Serviço"))
        {
            var ssl = r.Findings.Any(f => f.Key == "ssl" && f.Times.Any(t => t >= from && t <= inc.End));
            var p407 = r.Findings.Any(f => f.Key == "p407" && f.Times.Any(t => t >= from && t <= inc.End));
            C(ssl ? "Inspeção SSL de terceiros bloqueando o tenant" : p407 ? "Proxy exigindo autenticação" : "Tenant/POP Netskope inacessível a partir desta rede (firewall/proxy)",
                "Netskope", r.HasTelemetry ? 0.75 : 0.6, $"{tenantHits} falha(s) de comunicação com o tenant sem problema local detectado.",
                "Libere TCP 443 para os domínios Netskope sem inspeção SSL (veja o diagnóstico).", ssl ? "ssl" : p407 ? "p407" : "timeout");
        }

        // fatores de fundo
        var conflict = r.Findings.FirstOrDefault(f => f.Key == "conflict");
        if (conflict != null)
            C($"Fator contribuinte: {conflict.Title.ToLowerInvariant()}", "Conflito", causes.Count == 0 ? 0.5 : 0.3, conflict.Meaning, "Desconecte/desinstale a VPN de terceiros ou configure exceções.", "conflict");
        var orphanBg = r.Findings.FirstOrDefault(f => f.Key == "orphan");
        if (orphanBg != null && !causes.Any(c => c.FindingKey == "orphan"))
            C("Fator contribuinte: interfaces de VPN órfãs com DNS interno", "Rede", causes.Count == 0 ? 0.45 : 0.25, orphanBg.Title + ".", "Remova as interfaces órfãs (veja o diagnóstico).", "orphan");

        if (causes.Count == 0)
            C("Causa não determinada com os dados disponíveis", "Indeterminado", 0.1,
                "Nenhum sinal de Wi-Fi, rede, DNS, dispositivo ou serviço registrado nos logs nesta janela.",
                "Peça ao usuário para reproduzir o problema, anotar o horário e salvar um novo pacote de logs logo em seguida.");

        inc.Causes.AddRange(causes.OrderByDescending(c => c.Confidence));
    }

    private static void Evidence(AnalysisResult r, Incident inc, List<TimelineEvent> ev)
    {
        var from = inc.Start - Before; var to = inc.End + After;
        var lines = new List<EvidenceLine>();
        foreach (var e in ev.Where(x => x.Time >= from && x.Time <= to))
            lines.Add(new EvidenceLine(e.Time, e.File, e.Label + (e.Detail.Length > 0 ? " — " + e.Detail : ""), e.Kind));
        foreach (var f in r.Findings.Where(x => x.Severity <= Severity.Info))
        {
            var hits = f.Times.Where(t => t >= from && t <= to).ToList();
            if (hits.Count == 0) continue;
            lines.Add(new EvidenceLine(hits[0], "logs", hits.Count == 1 ? f.Title : $"{f.Title} ({hits.Count}x até {hits[^1]:HH:mm:ss})", f.Severity == Severity.Critical ? EventKind.Bad : EventKind.Alert));
        }
        foreach (var a in r.Anomalies.Where(x => x.Start <= to && x.End >= from))
            lines.Add(new EvidenceLine(a.Start, "métricas", $"{a.Label}: pico de {a.Peak:0.#} {a.Unit} (normal {a.Reference:0.#} {a.Unit})", a.Critical ? EventKind.Bad : EventKind.Alert));
        inc.Evidence.AddRange(lines.OrderBy(l => l.Time).Take(40));
    }
}
