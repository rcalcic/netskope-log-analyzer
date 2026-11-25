using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using NetskopeLogAnalyzer.Core;

namespace NetskopeLogAnalyzer;

/// <summary>v3.1 — visão de TAC: resumo do caso, desempenho pelos logs, configuração efetiva, sessões NPA, DNS e capturas.</summary>
public partial class MainWindow
{
    private static (System.Windows.Media.Brush Fg, System.Windows.Media.Brush Bg) StatusColors(string s) => s switch
    {
        "crítico" => (Red, RedBg), "atenção" => (AmberText, AmberBg), "bom" => (Green, GreenBg), _ => (Mute, Soft),
    };

    // ================================================================= Resumo: roteiro do caso + cobertura

    private UIElement CaseSummaryBlock()
    {
        var r = _result!;
        var sp = new StackPanel { Margin = new Thickness(0, 8, 0, 0) };
        if (r.CaseSummary.Count > 0)
        {
            sp.Children.Add(H2("Resumo do caso", new Thickness(0, 18, 0, 4)));
            sp.Children.Add(Sub("As perguntas que o suporte faz primeiro, respondidas a partir dos logs."));
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(260) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var i = 0;
            foreach (var (q, a) in r.CaseSummary)
            {
                g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var tq = T(q, 14, FontWeights.SemiBold, margin: new Thickness(0, 6, 16, 6));
                var ta = T(a, 14, margin: new Thickness(0, 6, 0, 6));
                Grid.SetRow(tq, i); Grid.SetRow(ta, i); Grid.SetColumn(ta, 1);
                g.Children.Add(tq); g.Children.Add(ta);
                i++;
            }
            sp.Children.Add(Card(g));
        }
        if (r.Coverage.Count > 0)
        {
            sp.Children.Add(H4("Período coberto por cada log"));
            sp.Children.Add(Table(new[] { "Fonte", "De", "Até", "Duração", "Linhas" },
                r.Coverage.Select(c => new[] { c.Source, Tm(c.First), Tm(c.Last), TelemetryParser.Fmt(c.Span), c.Lines.ToString("N0", Br) }),
                new double[] { 0, 130, 130, 110, 100 }));
            foreach (var gap in r.DataGaps.Where(x => x.StartsWith("Cobertura", StringComparison.Ordinal))) sp.Children.Add(Notice(gap, AmberText, AmberBg));
        }
        return sp;
    }

    // ================================================================= Desempenho

    private void RenderPerformance()
    {
        var r = _result!;
        var p = PerformancePanel;
        p.Children.Clear();
        p.Children.Add(T("Desempenho da máquina e do túnel", 24, FontWeights.Bold));
        p.Children.Add(Sub("Métricas no estilo do DEM calculadas só a partir dos logs do Netskope Client: responsividade da máquina (atraso das tarefas periódicas, travamentos internos, suspensões), processos que disputam CPU, estabilidade da rede (mudanças de rede, DNS), latência e retransmissões até o POP, quedas e tempo de reconexão do Private Access."));
        if (!r.HasTelemetry)
            p.Children.Add(Notice("O pacote de logs não traz séries contínuas de CPU, memória, disco e Wi-Fi: os indicadores de dispositivo abaixo são inferidos da foto de processos e do comportamento do próprio cliente ao longo do tempo.", AmberText, AmberBg));
        if (r.Performance.Count == 0) { p.Children.Add(Notice("Os logs deste pacote não têm dados suficientes para métricas de desempenho.", AmberText, AmberBg)); return; }

        var wrap = new WrapPanel { Margin = new Thickness(0, 6, 0, 8) };
        foreach (var m in r.Performance.Where(m => m.Status is "crítico" or "atenção").Take(8))
        {
            var (fg, bg) = StatusColors(m.Status);
            var s = new StackPanel();
            s.Children.Add(Pill(m.Status, fg, bg));
            s.Children.Add(T(m.Name, 14, FontWeights.SemiBold, margin: new Thickness(0, 6, 0, 2)));
            s.Children.Add(T(m.Value, 13));
            wrap.Children.Add(new Border { Background = Soft, CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 10), Margin = new Thickness(0, 0, 10, 10), Width = 300, Child = s, ToolTip = m.Meaning });
        }
        if (wrap.Children.Count > 0) { p.Children.Add(H4("Pontos fora do esperado")); p.Children.Add(wrap); }

        foreach (var g in r.Performance.GroupBy(m => m.Group))
        {
            p.Children.Add(H2(g.Key, new Thickness(0, 14, 0, 6)));
            p.Children.Add(Table(new[] { "Métrica", "Valor", "Referência", "Situação", "O que indica" },
                g.Select(m => new[] { m.Name, m.Value, m.Reference, m.Status, m.Meaning }), new double[] { 230, 250, 120, 85, 0 }));
        }

        void Chart(string title, string? sub, params string[] keys) { var s = SeriesStarting(keys).ToList(); if (s.Count > 0) p.Children.Add(ChartBlock(title, s, sub)); }
        p.Children.Add(H2("Ao longo do tempo"));
        Chart("Atraso das tarefas periódicas do cliente", "Quanto as estatísticas de 5 em 5 min do túnel atrasaram. Picos = máquina sobrecarregada ou suspensão curta.", "perf.sched");
        Chart("Operações internas que estouraram o tempo", null, "perf.stall");
        Chart("Mudanças de rede detectadas pelo cliente", "Por janela de 10 min. Sem troca real de rede, o normal é zero.", "net.changes");
        Chart("Private Access: RTT até o gateway", null, "npa.gw.rtt");
        Chart("Private Access: retransmissões TCP", "Segmentos reenviados por 5 min. Picos antes de uma queda indicam perda no Wi-Fi/provedor.", "npa.gw.retrans");
        Chart("DNS pelo Private Access: NXDOMAIN", null, "npa.dns.nxdomain");
        Chart("Eventos relevantes no log", "Só ocorrências de itens críticos e de atenção — o ruído conhecido fica de fora.", "log.errors");

        var suspend = r.Events.Where(e => e.Label == "Suspensão").ToList();
        if (suspend.Count > 0)
        {
            p.Children.Add(H2("Períodos sem atividade"));
            p.Children.Add(Sub("Intervalos de 15 min ou mais sem nenhuma linha em nenhum log: máquina suspensa, desligada ou com o serviço parado. Não contam como queda."));
            p.Children.Add(Table(new[] { "Início", "Detalhe" }, suspend.Select(e => new[] { Tm(e.Time), e.Detail }), new double[] { 150, 0 }));
        }
    }

    // ================================================================= Configuração

    private void RenderConfig()
    {
        var r = _result!;
        var p = ConfigPanel;
        p.Children.Clear();
        p.Children.Add(T("Configuração efetiva do cliente", 24, FontWeights.Bold));
        p.Children.Add(Sub("O que o tenant entregou a este dispositivo (nsconfig, steering, exceções, detecção on-prem, apps com certificado fixo), traduzido. Itens marcados merecem atenção no troubleshooting."));
        if (r.Config.Count == 0) { p.Children.Add(Notice("O pacote não traz os arquivos de configuração (nsconfig.json, nssteering.json…).", AmberText, AmberBg)); return; }
        var attention = r.Config.Where(c => c.Attention).ToList();
        if (attention.Count > 0)
            p.Children.Add(Notice("Atenção: " + string.Join(" · ", attention.Select(c => $"{c.Item}: {c.Value}")), AmberText, AmberBg));
        foreach (var g in r.Config.GroupBy(c => c.Section))
        {
            p.Children.Add(H2(g.Key, new Thickness(0, 14, 0, 6)));
            p.Children.Add(Table(new[] { "Item", "Valor", "O que significa" }, g.Select(c => new[] { (c.Attention ? "⚠ " : "") + c.Item, c.Value, c.Meaning }), new double[] { 260, 280, 0 }));
        }
    }

    // ================================================================= Rede: seções de TAC

    private void NetworkTacSections(StackPanel p)
    {
        var r = _result!;
        var sessions = r.NpaSessions.OrderBy(s => s.Start).ToList();
        if (sessions.Count > 0)
        {
            var drops = sessions.Where(s => s.End != null && !s.Expected).ToList();
            p.Children.Add(H2("Sessões do Private Access"));
            p.Children.Add(Sub($"{sessions.Count} sessão(ões), {drops.Count} queda(s) não programada(s), {sessions.Count(s => s.Expected)} reautenticação(ões). O motivo vem do próprio npadebuglog; o tempo até reconectar é o intervalo sem túnel."));
            p.Children.Add(Table(new[] { "Conectou", "POP", "Gateway", "RTT na escolha", "Terminou", "Motivo", "Voltou em" },
                sessions.AsEnumerable().Reverse().Take(200).Select(s => new[]
                {
                    Tm(s.Start), s.Pop ?? "—", s.GatewayIp ?? "—", s.SelectRttMs is double rt ? $"{rt:0} ms" : "—",
                    s.End is DateTime e ? Tm(e) : "(ativa)", s.EndReason ?? "—", s.Downtime is TimeSpan d ? TelemetryParser.Fmt(d) : "—",
                }), new double[] { 140, 90, 120, 100, 140, 0, 90 }));
        }
        void Chart(string title, string? sub, params string[] keys) { var s = SeriesStarting(keys).ToList(); if (s.Count > 0) p.Children.Add(ChartBlock(title, s, sub)); }
        Chart("Private Access: RTT até o gateway", "Medido pelo túnel a cada 5 min.", "npa.gw.rtt");
        Chart("Private Access: retransmissões TCP", "Por 5 min. Picos antes de uma queda = perda no caminho (Wi-Fi/provedor).", "npa.gw.retrans");
        Chart("Mudanças de rede detectadas", "Por 10 min.", "net.changes");

        if (r.DnsInterfaces.Count > 0)
        {
            p.Children.Add(H2("DNS por interface"));
            p.Children.Add(Sub("Servidores e domínios de pesquisa de cada interface. Interfaces de VPN antigas que continuam com DNS e domínio de pesquisa fazem consultas irem para servidores errados."));
            p.Children.Add(Table(new[] { "Interface", "Estado", "Servidores DNS", "Domínio de pesquisa", "Observação" },
                r.DnsInterfaces.Select(d => new[] { d.Interface, d.State, string.Join(", ", d.Servers), string.Join(", ", d.Search), d.Note }), new double[] { 150, 120, 220, 180, 0 }));
        }
        Chart("DNS pelo Private Access: respostas NXDOMAIN", null, "npa.dns.nxdomain");

        if (r.Captures.Count > 0)
        {
            p.Children.Add(H2("Capturas de pacotes"));
            p.Children.Add(Sub("Resumo das capturas incluídas no pacote. nsouterpktdump = placa de rede (fora do túnel); nspktdump/npatunnel = dentro do túnel."));
            p.Children.Add(Table(new[] { "Arquivo", "Tipo", "Período", "Pacotes", "Fluxos TCP", "Retransmissões", "RST", "SYN sem resposta", "DNS", "Alertas TLS" },
                r.Captures.Select(c => new[]
                {
                    c.File + (c.Error != null ? $" ({c.Error})" : ""), c.LinkType,
                    c.First is DateTime a && c.Last is DateTime b ? $"{a:dd/MM HH:mm:ss}–{b:HH:mm:ss}" : "—",
                    c.Packets.ToString("N0", Br), c.TcpFlows.ToString("N0", Br), $"{c.Retransmissions:N0} ({c.RetransPct.ToString("0.#", Br)}%)",
                    c.Resets.ToString("N0", Br), c.HandshakeFailures.ToString(CultureInfo.InvariantCulture),
                    string.Join(" ", c.DnsRcodes.OrderByDescending(k => k.Value).Select(k => $"{k.Key} {k.Value}")), c.TlsAlerts.ToString(CultureInfo.InvariantCulture),
                }), new double[] { 0, 110, 150, 80, 80, 120, 60, 110, 150, 80 }));
            foreach (var c in r.Captures.Where(c => c.TopDestinations.Count > 0))
                p.Children.Add(Sub($"{c.File} — principais destinos: " + string.Join(", ", c.TopDestinations.Take(6).Select(kv => $"{kv.Key} ({kv.Value / 1024.0:N0} KB)"))));
        }
    }
}
