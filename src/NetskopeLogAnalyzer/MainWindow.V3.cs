using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using NetskopeLogAnalyzer.Core;
using NetskopeLogAnalyzer.Services;

namespace NetskopeLogAnalyzer;

public partial class MainWindow
{
    private static readonly Brush[] Palette =
    {
        B("#0A5CFF"), B("#E6261F"), B("#00A05A"), B("#FFB400"), B("#7A3EF0"), B("#00A3BF"), B("#D13FA0"), B("#5B6270"),
    };
    private static readonly Brush BandCrit = B("#30E6261F"), BandWarn = B("#30FFB400");
    private static readonly CultureInfo Br = CultureInfo.GetCultureInfo("pt-BR");

    private AppSettings _settings = AppSettings.Load();
    private UpdateInfo? _update;
    private readonly DispatcherTimer _collectorTimer = new() { Interval = TimeSpan.FromSeconds(5) };

    // ================================================================= inicialização v3

    private void InitV3()
    {
        _collectorTimer.Tick += (_, _) => RefreshCollectorStatus();
        _collectorTimer.Start();
        RefreshCollectorStatus();
        if (!AppSettings.CollectorDisabledByPolicy && TelemetryCollector.AutoStartEnabled && !TelemetryCollector.IsRunning())
            Try(TelemetryCollector.StartBackground);
        Loaded += async (_, _) =>
        {
            if (_settings.AutoCheckUpdates && !AppSettings.UpdatesDisabledByPolicy && (_settings.LastUpdateCheck is null || DateTime.Now - _settings.LastUpdateCheck > TimeSpan.FromHours(12)))
                await CheckUpdatesAsync(false);
        };
    }

    private static void Try(Action a) { try { a(); } catch (Exception) { } }

    private void RefreshCollectorStatus()
    {
        if (AppSettings.CollectorDisabledByPolicy) { TxtCollectorStatus.Text = "O coletor de telemetria foi desativado pela política do TI."; return; }
        var files = TelemetryCollector.LocalTelemetryFiles().ToList();
        var running = TelemetryCollector.IsRunning();
        var size = files.Sum(f => new FileInfo(f).Length);
        TxtCollectorStatus.Text = (running ? "Coletor em execução" : "Coletor parado") +
            (TelemetryCollector.AutoStartEnabled ? " · coleta contínua no logon ativada" : "") +
            (files.Count > 0 ? $" · {files.Count} dia(s) de telemetria ({size / 1048576.0:0.0} MB), última amostra {File.GetLastWriteTime(files[^1]):dd/MM HH:mm}" : " · nenhuma telemetria coletada ainda") +
            ". Com telemetria, o app mede CPU, memória, disco, Wi-Fi, latência, perda, DNS e aplicações continuamente — como o DEM.";
    }

    // ================================================================= helpers de layout

    private static TextBlock H2(string text, Thickness? m = null) => T(text, 22, FontWeights.Bold, margin: m ?? new Thickness(0, 26, 0, 6));
    private static TextBlock Sub(string text) => T(text, 13.5, fg: Mute, margin: new Thickness(0, 0, 0, 10));

    private static Border Card(UIElement child, Thickness? margin = null) => new()
    {
        Background = White, BorderBrush = LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12),
        Padding = new Thickness(14, 12, 14, 12), Margin = margin ?? new Thickness(0, 0, 0, 12), Child = child,
    };

    private static Border Notice(string text, Brush fg, Brush bg) => new()
    {
        Background = bg, CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 10), Margin = new Thickness(0, 4, 0, 10),
        Child = T(text, 14, FontWeights.SemiBold, fg),
    };

    private static string N(double v, string fmt = "0.#") => v.ToString(fmt, Br);
    private static string Tm(DateTime t) => t.ToString("dd/MM HH:mm:ss", CultureInfo.InvariantCulture);

    /// <summary>Tabela leve (Grid) — evita bindings e funciona bem até algumas centenas de linhas.</summary>
    private static Border Table(string[] headers, IEnumerable<string[]> rows, double[]? widths = null, int max = 400)
    {
        var g = new Grid();
        for (var c = 0; c < headers.Length; c++)
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = widths != null && c < widths.Length && widths[c] > 0 ? new GridLength(widths[c]) : new GridLength(1, GridUnitType.Star) });
        void Row(string[] cells, bool header, int r)
        {
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            for (var c = 0; c < headers.Length; c++)
            {
                var tb = new TextBlock
                {
                    Text = c < cells.Length ? cells[c] : "", FontSize = header ? 12 : 13, FontWeight = header ? FontWeights.SemiBold : FontWeights.Normal,
                    Foreground = header ? Mute : Ink, TextWrapping = TextWrapping.Wrap, Padding = new Thickness(6, 5, 6, 5),
                };
                var cell = new Border { BorderBrush = LineBrush, BorderThickness = new Thickness(0, 0, 0, 1), Child = tb, Background = header ? Soft : White };
                Grid.SetRow(cell, r); Grid.SetColumn(cell, c);
                g.Children.Add(cell);
            }
        }
        Row(headers, true, 0);
        var i = 1;
        foreach (var row in rows) { if (i > max) break; Row(row, false, i++); }
        if (i == 1) { Row(new[] { "— sem dados —" }, false, 1); }
        return new Border { BorderBrush = LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), ClipToBounds = true, Child = g, Margin = new Thickness(0, 0, 0, 12) };
    }

    private IEnumerable<MetricSeries> SeriesStarting(params string[] prefixes) =>
        _result!.Series.Values.Where(s => s.Points.Count > 0 && prefixes.Any(p => s.Key.Equals(p, StringComparison.OrdinalIgnoreCase) || s.Key.StartsWith(p + ":", StringComparison.OrdinalIgnoreCase)))
            .OrderBy(s => s.Key, StringComparer.OrdinalIgnoreCase);

    private static string StatsText(MetricSeries s)
    {
        if (s.Stats is not BaselineStats st) return "";
        var u = s.Unit.Length > 0 ? " " + s.Unit : "";
        var worstLabel = s.HigherIsWorse ? "máx." : "mín.";
        var p = s.HigherIsWorse ? "p95" : "p5";
        var txt = $"mediana {N(st.P50)}{u} · {p} {N(st.P95)}{u} · {worstLabel} {N(st.PeakValue)}{u} às {Tm(st.PeakTime)} · média {N(st.Mean)}{u} · {st.Count:N0} amostras";
        if (s.Warn != null) txt += $" · {N(st.PctWarn, "0")}% do tempo em atenção";
        if (s.Crit != null && st.PctCrit > 0) txt += $" · {N(st.PctCrit, "0")}% crítico";
        return txt;
    }

    private UIElement ChartBlock(string title, IEnumerable<MetricSeries> seriesEnum, string? subtitle = null, double height = 170, double? yMin = null, double? yMax = null)
    {
        var series = seriesEnum.Take(8).ToList();
        var sp = new StackPanel();
        sp.Children.Add(T(title, 15, FontWeights.Bold));
        if (subtitle != null) sp.Children.Add(T(subtitle, 12, fg: Mute));
        var chart = new TimeChart { Height = height, From = _result!.Start, To = _result.End, YMin = yMin, YMax = yMax, Margin = new Thickness(0, 6, 0, 4) };
        for (var i = 0; i < series.Count; i++) chart.Lines.Add(new TimeChart.Line(series[i], Palette[i % Palette.Length]));
        if (series.Count > 0) { chart.Unit = series[0].Unit; if (series.Select(s => s.Unit).Distinct().Count() == 1) { chart.Warn = series[0].Warn; chart.Crit = series[0].Crit; } }
        foreach (var inc in _result.Incidents) chart.Bands.Add((inc.Start, inc.End > inc.Start ? inc.End : inc.Start.AddMinutes(1), inc.Severity == Severity.Critical ? BandCrit : BandWarn));
        sp.Children.Add(chart);
        foreach (var (s, i) in series.Select((s, i) => (s, i)))
        {
            var row = new DockPanel { Margin = new Thickness(0, 2, 0, 0) };
            var dot = new System.Windows.Shapes.Rectangle { Width = 10, Height = 10, Fill = Palette[i % Palette.Length], Margin = new Thickness(0, 4, 6, 0), VerticalAlignment = VerticalAlignment.Top };
            DockPanel.SetDock(dot, Dock.Left);
            row.Children.Add(dot);
            row.Children.Add(T(s.Label + (StatsText(s) is { Length: > 0 } t ? " — " + t : ""), 12, fg: Ink));
            sp.Children.Add(row);
        }
        return Card(sp);
    }

    private UIElement BaselineTable(params string[] groups)
    {
        var rows = _result!.Series.Values.Where(s => s.Stats != null && groups.Contains(s.Group) && !s.Key.StartsWith("flows.", StringComparison.Ordinal))
            .OrderBy(s => s.Group).ThenBy(s => s.Label)
            .Select(s =>
            {
                var st = s.Stats!;
                var bad = s.Crit != null && st.PctCrit > 5 ? "crítico" : s.Warn != null && st.PctWarn > 10 ? "atenção" : s.Warn != null ? "normal" : "—";
                return new[] { s.Label, s.Source, st.Count.ToString("N0", Br), N(st.Min), N(st.P50), N(st.P95), N(st.Max), s.Unit, s.Warn != null ? N(st.PctWarn, "0") + "%" : "—", bad };
            });
        return Table(new[] { "Métrica", "Fonte", "Amostras", "Mín.", "Mediana", "p95/p5", "Máx.", "Unid.", "% em atenção", "Situação" }, rows,
            new double[] { 0, 110, 80, 70, 75, 75, 70, 60, 95, 85 });
    }

    private UIElement AnomalyList(params string[] groups)
    {
        var list = _result!.Anomalies.Where(a => groups.Contains(a.Group)).OrderByDescending(a => a.Critical).ThenBy(a => a.Start).Take(40)
            .Select(a => new[] { Tm(a.Start) + (a.End > a.Start ? " → " + a.End.ToString("HH:mm:ss", CultureInfo.InvariantCulture) : ""), a.Label, $"{N(a.Peak)} {a.Unit}", $"{N(a.Reference)} {a.Unit}", a.Critical ? "crítico" : "fora do padrão" });
        return Table(new[] { "Quando", "Métrica", "Pico", "Normal (mediana)", "Tipo" }, list, new double[] { 190, 0, 110, 130, 110 });
    }

    // ================================================================= Resumo: indicadores v3

    private UIElement SummaryKpis()
    {
        var r = _result!;
        var wrap = new WrapPanel { Margin = new Thickness(0, 18, 0, 0) };
        void Tile(string big, string label, Brush color, string tip, TabItem target)
        {
            var sp = new StackPanel();
            sp.Children.Add(T(big, 30, FontWeights.Bold, color, wrap: false));
            sp.Children.Add(T(label, 13, fg: Mute));
            var b = new Border { Background = Soft, CornerRadius = new CornerRadius(14), Padding = new Thickness(16, 12, 16, 12), Margin = new Thickness(0, 0, 10, 10), MinWidth = 170, MaxWidth = 380, Child = sp, Cursor = Cursors.Hand, ToolTip = tip };
            b.MouseLeftButtonUp += (_, _) => Tabs.SelectedItem = target;
            wrap.Children.Add(b);
        }
        if (r.Score is double sc)
            Tile($"{sc:0}", "Experience Score (" + ExperienceScore.Band(sc) + (r.ScoreMissing != null ? ", parcial" : "") + ")", sc <= 30 ? Red : sc <= 70 ? AmberText : Green, "0–100, como o DEM. Clique para ver os componentes.", TabExperience);
        var crit = r.Incidents.Count(i => i.Severity == Severity.Critical);
        Tile(r.Incidents.Count.ToString(CultureInfo.InvariantCulture), r.Incidents.Count == 1 ? "incidente" : $"incidentes ({crit} crítico(s))", r.Incidents.Count == 0 ? Green : crit > 0 ? Red : AmberText, "Clique para ver horário e causa raiz.", TabIncidents);
        foreach (var (svc, av) in r.Availability)
            Tile($"{av:0.#}%", $"{svc} conectado", av >= 99 ? Green : av >= 90 ? AmberText : Red, "Tempo com o túnel conectado no período dos logs.", TabNetwork);
        var main = r.Incidents.OrderBy(i => i.Severity).ThenByDescending(i => i.Duration).FirstOrDefault();
        if (main?.Causes.FirstOrDefault() is Cause c)
            Tile(c.Category, "Causa raiz principal: " + c.Title.ToLowerInvariant() + $" ({c.Confidence:0}%)", Ink, $"{main.Title} em {Tm(main.Start)}", TabIncidents);
        if (!r.HasTelemetry)
        {
            var note = Notice("Sem telemetria do coletor: CPU, memória, disco e Wi-Fi contínuos não estão no pacote da Netskope. Use “Telemetria” para coletar e obter baseline e causa raiz completos.", AmberText, AmberBg);
            var sp = new StackPanel(); sp.Children.Add(wrap); sp.Children.Add(note);
            return sp;
        }
        return wrap;
    }

    // ================================================================= Incidentes

    private void RenderIncidents()
    {
        var r = _result!;
        var p = IncidentsPanel;
        p.Children.Clear();
        p.Children.Add(T("Incidentes e causa raiz", 24, FontWeights.Bold));
        p.Children.Add(Sub("Cada incidente traz o horário, o impacto, a causa raiz mais provável (com grau de confiança) e as evidências que levaram a ela. As causas são avaliadas nos 5 minutos anteriores ao início: Wi-Fi, troca de rede, latência/perda, DNS, recursos do dispositivo, suspensão, reinício do serviço, ação do usuário e bloqueio do tenant."));
        if (!r.HasTelemetry) p.Children.Add(Notice("Sem telemetria do coletor, a causa raiz se baseia apenas nos logs da Netskope (confiança menor para Wi-Fi, dispositivo e rede local).", AmberText, AmberBg));
        if (r.Incidents.Count == 0) { p.Children.Add(Notice("Nenhum incidente detectado no período analisado.", Green, GreenBg)); TabIncidents.Header = "Incidentes (0)"; return; }
        TabIncidents.Header = $"Incidentes ({r.Incidents.Count})";
        foreach (var inc in r.Incidents.OrderBy(i => i.Start)) p.Children.Add(IncidentCard(inc));
    }

    private UIElement IncidentCard(Incident inc)
    {
        var (fg, bg) = SevColors(inc.Severity);
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.Children.Add(new Border { Background = SevBar(inc.Severity), CornerRadius = new CornerRadius(12, 0, 0, 12) });
        var sp = new StackPanel { Margin = new Thickness(16, 14, 16, 16) };
        Grid.SetColumn(sp, 1); grid.Children.Add(sp);

        var tags = new StackPanel { Orientation = Orientation.Horizontal };
        tags.Children.Add(Pill(Report.SeverityLabel(inc.Severity), fg, bg));
        tags.Children.Add(T($"{Tm(inc.Start)} → {inc.End:HH:mm:ss}  ·  duração {TelemetryParser.Fmt(inc.Duration)}  ·  {inc.Kind}", 12.5, fg: Mute, wrap: false));
        sp.Children.Add(tags);
        sp.Children.Add(T(inc.Title, 18, FontWeights.Bold, margin: new Thickness(0, 6, 0, 2)));
        if (inc.Impact.Length > 0) sp.Children.Add(T(inc.Impact, 14, fg: Ink));

        if (inc.Causes.FirstOrDefault() is Cause top)
        {
            var box = new StackPanel();
            var head = new DockPanel();
            var conf = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var barBg = new Border { Width = 140, Height = 10, Background = White, CornerRadius = new CornerRadius(5), BorderBrush = LineBrush, BorderThickness = new Thickness(1) };
            barBg.Child = new Border { Width = 1.38 * top.Confidence, HorizontalAlignment = HorizontalAlignment.Left, Background = top.Confidence >= 70 ? Green : top.Confidence >= 40 ? Amber : Gray, CornerRadius = new CornerRadius(5) };
            conf.Children.Add(barBg);
            conf.Children.Add(T($"  {top.Confidence:0}% de confiança", 12.5, FontWeights.SemiBold, wrap: false));
            DockPanel.SetDock(conf, Dock.Right);
            head.Children.Add(conf);
            head.Children.Add(T("Causa raiz provável", 13, FontWeights.SemiBold, Green));
            box.Children.Add(head);
            var title = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 2) };
            title.Children.Add(Pill(top.Category, Green, White));
            title.Children.Add(T(top.Title, 16, FontWeights.Bold, wrap: true));
            box.Children.Add(title);
            box.Children.Add(T("Evidência: " + top.Evidence, 13.5));
            box.Children.Add(T("O que fazer: " + top.Recommendation, 13.5, margin: new Thickness(0, 4, 0, 0)));
            var fk = top.FindingKey ?? inc.FindingKey;
            if (fk != null && _result!.Findings.FirstOrDefault(x => x.Key == fk) is Finding fnd)
            {
                var b = new Button { Content = "Ver resolução passo a passo", Style = (Style)FindResource("Small"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 8, 0, 0) };
                b.Click += (_, _) => ShowFinding(fnd);
                box.Children.Add(b);
            }
            sp.Children.Add(new Border { BorderBrush = Green, BorderThickness = new Thickness(2), Background = GreenBg, CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 12), Margin = new Thickness(0, 10, 0, 0), Child = box });
        }
        if (inc.Causes.Count > 1)
        {
            sp.Children.Add(H4("Outras hipóteses avaliadas"));
            foreach (var c in inc.Causes.Skip(1))
                sp.Children.Add(T($"•  {c.Title} — {c.Confidence:0}% ({c.Category}). {c.Evidence}", 13));
        }
        if (inc.Evidence.Count > 0)
        {
            sp.Children.Add(H4("Linha do tempo do incidente (5 min antes até o fim)"));
            sp.Children.Add(new TextBox
            {
                Text = string.Join(Environment.NewLine, inc.Evidence.Select(e => $"{Tm(e.Time)}  [{e.Source}]  {e.Text}")),
                IsReadOnly = true, FontFamily = Mono, FontSize = 12, Background = Soft, BorderBrush = LineBrush, Padding = new Thickness(8), MaxHeight = 220,
                TextWrapping = TextWrapping.NoWrap, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            });
        }
        return new Border { BorderBrush = LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Background = White, Margin = new Thickness(0, 0, 0, 14), ClipToBounds = true, Child = grid };
    }

    // ================================================================= Experiência

    private void RenderExperience()
    {
        var r = _result!;
        var p = ExperiencePanel;
        p.Children.Clear();
        p.Children.Add(T("Experience Score", 24, FontWeights.Bold));
        p.Children.Add(Sub("Nota de 0 a 100 a cada 5 minutos, no modelo do Netskope DEM: Dispositivo (CPU, memória, disco, Wi-Fi), Rede (latência, perda, jitter, DNS e latência até o POP), Netskope (túnel conectado e falhas com o tenant) e Aplicação (testes HTTP). Componentes sem dados ficam de fora; o pior componente limita a nota. Faixas: 0–30 ruim, 31–70 regular, 71–100 bom."));
        if (r.Scores.Count == 0) { p.Children.Add(Notice("Não há dados suficientes para calcular o score.", AmberText, AmberBg)); return; }
        if (r.ScoreMissing != null)
            p.Children.Add(Notice($"Score parcial: sem dados de {r.ScoreMissing}. A nota usa só os componentes medidos" + (r.HasTelemetry ? "." : " — rode o coletor na máquina para incluir CPU, memória, Wi-Fi e testes de aplicação."), AmberText, AmberBg));
        var sc = r.Score ?? 0;
        var color = sc <= 30 ? Red : sc <= 70 ? AmberText : Green;

        var top = new WrapPanel();
        var big = new StackPanel { Margin = new Thickness(0, 0, 30, 10) };
        big.Children.Add(T($"{sc:0}", 72, FontWeights.Bold, color, wrap: false));
        big.Children.Add(T(ExperienceScore.Band(sc) + $" · média de {r.Scores.Count} janelas de 5 min", 14, fg: Mute));
        top.Children.Add(big);
        int good = r.Scores.Count(s => s.Score > 70), fair = r.Scores.Count(s => s.Score > 30 && s.Score <= 70), poor = r.Scores.Count(s => s.Score <= 30);
        var dist = new StackPanel { Margin = new Thickness(0, 10, 30, 10), MinWidth = 260 };
        dist.Children.Add(T("Distribuição do tempo", 13, FontWeights.SemiBold, Mute));
        foreach (var (label, n, b) in new[] { ("Bom", good, Green), ("Regular", fair, Amber), ("Ruim", poor, Red) })
        {
            var row = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
            var pct = 100.0 * n / r.Scores.Count;
            var lab = T($"{label}  {pct:0}%", 13, wrap: false); lab.Width = 110; DockPanel.SetDock(lab, Dock.Left); row.Children.Add(lab);
            var bar = new Border { Background = Soft, Height = 12, CornerRadius = new CornerRadius(6), Width = 180 };
            bar.Child = new Border { Background = b, Width = 1.8 * pct, HorizontalAlignment = HorizontalAlignment.Left, CornerRadius = new CornerRadius(6) };
            row.Children.Add(bar);
            dist.Children.Add(row);
        }
        top.Children.Add(dist);
        var comps = new WrapPanel { Margin = new Thickness(0, 10, 0, 10) };
        void Comp(string name, Func<ScoreWindow, double?> sel, string hint)
        {
            var vals = r.Scores.Select(sel).Where(v => v != null).Select(v => v!.Value).ToList();
            var spc = new StackPanel();
            spc.Children.Add(T(vals.Count > 0 ? $"{vals.Average():0}" : "—", 28, FontWeights.Bold, vals.Count == 0 ? Gray : vals.Average() <= 30 ? Red : vals.Average() <= 70 ? AmberText : Green, wrap: false));
            spc.Children.Add(T(name, 13, FontWeights.SemiBold));
            spc.Children.Add(T(vals.Count > 0 ? $"pior: {vals.Min():0}" : hint, 11.5, fg: Mute));
            comps.Children.Add(new Border { Background = Soft, CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 10), Margin = new Thickness(0, 0, 10, 0), Width = 160, Child = spc });
        }
        Comp("Dispositivo", s => s.Device, "sem telemetria");
        Comp("Rede", s => s.Network, "sem medições");
        Comp("Netskope", s => s.Netskope, "sem eventos");
        Comp("Aplicação", s => s.App, "sem testes HTTP");
        top.Children.Add(comps);
        p.Children.Add(top);

        MetricSeries Mk(string key, string label, Func<ScoreWindow, double?> sel)
        {
            var s = new MetricSeries { Key = key, Label = label, Unit = "", Group = "Experiência", HigherIsWorse = false, Warn = 70, Crit = 30 };
            foreach (var w in r.Scores) if (sel(w) is double v) s.Points.Add(new MetricPoint(w.Start, v));
            return s;
        }
        var chart = new List<MetricSeries> { Mk("score", "Experience Score", w => w.Score), Mk("dev", "Dispositivo", w => w.Device), Mk("net", "Rede", w => w.Network), Mk("ns", "Netskope", w => w.Netskope), Mk("app", "Aplicação", w => w.App) }.Where(s => s.Points.Count > 0);
        p.Children.Add(ChartBlock("Score ao longo do tempo", chart, "Faixas coloridas = incidentes. Linhas tracejadas: 70 (bom) e 30 (ruim).", 220, 0, 100));

        p.Children.Add(H2("Piores momentos"));
        p.Children.Add(Table(new[] { "Janela", "Score", "Dispositivo", "Rede", "Netskope", "Aplicação", "O que pesou" },
            r.Scores.OrderBy(s => s.Score).Take(12).Select(s => new[] { $"{Tm(s.Start)} → {s.End:HH:mm}", $"{s.Score:0}", Fmt(s.Device), Fmt(s.Network), Fmt(s.Netskope), Fmt(s.App), s.Notes }),
            new double[] { 190, 60, 90, 70, 80, 85, 0 }));
        foreach (var g in r.DataGaps) p.Children.Add(Notice(g, AmberText, AmberBg));
        static string Fmt(double? v) => v is double d ? d.ToString("0", CultureInfo.InvariantCulture) : "—";
    }

    // ================================================================= Dispositivo

    private void RenderDevice()
    {
        var r = _result!;
        var p = DevicePanel;
        p.Children.Clear();
        p.Children.Add(T("Dispositivo e Wi-Fi", 24, FontWeights.Bold));
        p.Children.Add(Sub("Baseline de consumo da máquina (CPU, memória, disco, bateria e Wi-Fi) com picos, percentis e tempo acima dos limites. Faixas coloridas nos gráficos marcam os incidentes."));
        if (!r.HasTelemetry)
        {
            p.Children.Add(Notice("O pacote de logs da Netskope não traz séries contínuas de CPU, memória, disco e Wi-Fi. Os dados abaixo são fotos instantâneas do momento da coleta. Para um baseline completo, rode o coletor de telemetria nesta máquina (ou o script para Linux/macOS) e analise de novo junto com o pacote.", AmberText, AmberBg));
            var b = new Button { Content = "Abrir coletor de telemetria", Style = (Style)FindResource("Small"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
            b.Click += Telemetry_Click;
            p.Children.Add(b);
        }

        var info = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["Dispositivo"] = r.Facts.Host, ["Sistema"] = r.Facts.OsName ?? r.Facts.Os, ["Modelo"] = r.Facts.Model, ["Netskope Client"] = r.Facts.Version,
        };
        foreach (var kv in r.Device) info.TryAdd(kv.Key, kv.Value);
        p.Children.Add(Table(new[] { "Item", "Valor" }, info.Where(kv => !string.IsNullOrWhiteSpace(kv.Value)).Select(kv => new[] { kv.Key, kv.Value! }), new double[] { 220, 0 }));

        void Chart(string title, string? sub, params string[] keys) { var s = SeriesStarting(keys).ToList(); if (s.Count > 0) p.Children.Add(ChartBlock(title, s, sub)); }
        Chart("CPU", "CPU total e o processo mais pesado em cada amostra.", "cpu", "procs.top_cpu");
        Chart("Memória em uso", null, "mem.used", "mem.commit");
        Chart("Memória disponível", null, "mem.avail");
        Chart("Disco", null, "disk.used");
        Chart("Disco livre", null, "disk.free");
        Chart("Wi-Fi: sinal", "Qualidade do sinal (%). Abaixo de 60% começa a degradar; abaixo de 40% é crítico.", "wifi.signal");
        Chart("Wi-Fi: RSSI", "Potência recebida (dBm). Bom acima de −67 dBm; crítico abaixo de −80 dBm.", "wifi.rssi");
        Chart("Wi-Fi: taxa de conexão", null, "wifi.rx", "wifi.tx");
        Chart("Bateria", null, "battery");

        var wifiSnap = r.Snapshots.Where(s => s.Wifi != null).OrderByDescending(s => s.Time).FirstOrDefault();
        if (wifiSnap?.Wifi is WifiInfo w)
        {
            p.Children.Add(H2("Conexão Wi-Fi"));
            var roam = r.Events.Count(e => e.Label.StartsWith("Roaming", StringComparison.Ordinal));
            var drops = r.Events.Count(e => e.Label == "Wi-Fi desconectado");
            p.Children.Add(Table(new[] { "SSID", "BSSID (AP)", "Banda", "Canal", "Rádio", "Sinal", "RSSI", "Recepção", "Transmissão", "Quedas", "Trocas de AP" },
                new[] { new[] { w.Ssid ?? "—", w.Bssid ?? "—", w.Band ?? "—", w.Channel ?? "—", w.Radio ?? "—", w.SignalPct is double s ? $"{s:0}%" : "—", w.RssiDbm is double d ? $"{d:0} dBm" : "—", w.RxMbps is double rx ? $"{rx:0} Mbps" : "—", w.TxMbps is double tx ? $"{tx:0} Mbps" : "—", drops.ToString(CultureInfo.InvariantCulture), roam.ToString(CultureInfo.InvariantCulture) } }));
            p.Children.Add(Sub($"Fonte: {wifiSnap.Source}{(wifiSnap.Time is DateTime wt ? " em " + Tm(wt) : "")}."));
        }

        foreach (var snap in r.Snapshots.Where(s => s.Processes.Count > 0).Take(3))
        {
            p.Children.Add(H2("Processos — " + snap.Source));
            p.Children.Add(Sub(snap.Source.Contains("coletor", StringComparison.OrdinalIgnoreCase) ? "Média de CPU e pico de memória dos maiores consumidores durante a coleta." : $"Foto instantânea{(snap.Time is DateTime t ? " de " + Tm(t) : "")}. CPU do ps é a média desde o início de cada processo."));
            p.Children.Add(Table(new[] { "Processo", "CPU %", "Memória (MB)", "% memória", "Instâncias" },
                snap.Processes.OrderByDescending(x => x.CpuPct).ThenByDescending(x => x.MemMb).Take(15)
                    .Select(x => new[] { x.Name, N(x.CpuPct), N(x.MemMb, "0"), x.MemPct > 0 ? N(x.MemPct) : "—", x.Instances.ToString(CultureInfo.InvariantCulture) }),
                new double[] { 0, 90, 120, 100, 100 }));
            if (snap.MemTotalMb is double mt) p.Children.Add(Sub($"Memória total: {mt:N0} MB" + (snap.MemAvailMb is double ma ? $" · disponível: {ma:N0} MB ({100 * ma / mt:0}%)" : "")));
        }
        var disks = r.Snapshots.SelectMany(s => s.Disks).ToList();
        if (disks.Count > 0)
        {
            p.Children.Add(H2("Discos (foto instantânea)"));
            p.Children.Add(Table(new[] { "Ponto de montagem", "Tamanho", "Em uso" }, disks.Select(d => new[] { d.Mount, d.TotalGb is double g ? $"{g:0.#} GB" : "—", $"{d.UsedPct:0}%" }), new double[] { 0, 120, 100 }));
        }
        p.Children.Add(H2("Baseline"));
        p.Children.Add(BaselineTable(MetricCatalog.Device, MetricCatalog.Wifi));
        p.Children.Add(H2("Anomalias"));
        p.Children.Add(AnomalyList(MetricCatalog.Device, MetricCatalog.Wifi));
    }

    // ================================================================= Rede

    private void RenderNetwork()
    {
        var r = _result!;
        var p = NetworkPanel;
        p.Children.Clear();
        p.Children.Add(T("Rede e Netskope", 24, FontWeights.Bold));
        p.Children.Add(Sub("Disponibilidade do túnel, latência até os POPs (medida pelo próprio Netskope Client na seleção de gateway), caminho até o POP, IP de saída, DNS e testes de rede do coletor."));

        if (r.Availability.Count > 0 || r.States.Count > 0)
        {
            p.Children.Add(H2("Disponibilidade do túnel", new Thickness(0, 6, 0, 6)));
            p.Children.Add(Table(new[] { "Serviço", "Estado", "Início", "Fim", "Duração" },
                r.States.OrderBy(s => s.Start).Select(s => new[] { s.Service, s.State, Tm(s.Start), Tm(s.End), TelemetryParser.Fmt(s.Duration) }), new double[] { 140, 0, 150, 150, 110 }));
            foreach (var (svc, av) in r.Availability) p.Children.Add(Sub($"{svc}: conectado {av:0.#}% do tempo coberto pelos logs."));
        }

        if (r.Pops.Count > 0)
        {
            p.Children.Add(H2("POPs Netskope (latência medida pelo cliente)"));
            p.Children.Add(Table(new[] { "Serviço", "POP", "IP", "Medições", "Mín. (ms)", "Média (ms)", "Máx. (ms)", "Última", "Em" },
                r.Pops.Select(x => new[] { x.Service, x.Pop, x.Ip ?? "—", x.Samples.ToString(CultureInfo.InvariantCulture), N(x.Min, "0"), N(x.Avg, "0"), N(x.Max, "0"), N(x.Last, "0"), Tm(x.LastTime) }),
                new double[] { 110, 110, 130, 80, 80, 85, 80, 70, 150 }));
            var bestPop = r.Pops.GroupBy(x => x.Service).Select(g => $"{g.Key}: {g.OrderBy(x => x.Avg).First().Pop} ({g.OrderBy(x => x.Avg).First().Avg:0} ms)");
            p.Children.Add(Sub("POP mais rápido: " + string.Join(" · ", bestPop) + (r.Facts.PopNpa != null ? $" · POP NPA escolhido: {r.Facts.PopNpa}" : "")));
        }
        void Chart(string title, string? sub, params string[] keys) { var s = SeriesStarting(keys).ToList(); if (s.Count > 0) p.Children.Add(ChartBlock(title, s, sub)); }
        Chart("Latência até o melhor POP", "Menor latência em cada rodada de medição do GSLB.", "pop.best");
        Chart("Latência por POP", null, "pop.rtt");
        Chart("Latência (ping)", "Gateway local e Internet, medidos pelo coletor.", "ping.rtt");
        Chart("Perda de pacotes", null, "ping.loss");
        Chart("Jitter", null, "ping.jitter");
        Chart("Conexão TCP até os POPs", "Tempo para abrir conexão TCP 443 até os gateways Netskope.", "tcp.connect");
        Chart("Resolução DNS", null, "dns.ms");
        Chart("Tráfego de rede da máquina", null, "net.rx", "net.tx");

        foreach (var path in r.Paths.GroupBy(x => x.Target).Select(g => g.OrderByDescending(x => x.Time).First()))
        {
            p.Children.Add(H2($"Caminho até {path.Target}"));
            var segs = path.Hops.Where(h => h.RttMs != null).GroupBy(h => h.Segment).Select(g => $"{g.Key}: até {g.Max(h => h.RttMs):0} ms");
            p.Children.Add(Sub($"Traceroute de {Tm(path.Time)} ({r.Paths.Count(x => x.Target == path.Target)} medições no período). " + string.Join(" → ", segs)));
            p.Children.Add(Table(new[] { "Salto", "Endereço", "Latência", "Trecho" },
                path.Hops.Select(h => new[] { h.Ttl.ToString(CultureInfo.InvariantCulture), h.Address ?? "*", h.RttMs is double ms ? $"{ms:0} ms" : "—", h.Segment }), new double[] { 70, 200, 110, 0 }));
        }

        if (r.EgressHistory.Count > 0)
        {
            p.Children.Add(H2("IP de saída (egress)"));
            p.Children.Add(Table(new[] { "Desde", "IP de saída" }, r.EgressHistory.Select(e => new[] { Tm(e.Key), e.Value }), new double[] { 180, 0 }));
        }
        foreach (var snap in r.Snapshots.Where(s => s.Interfaces.Count > 0 || s.ConnectionStates.Count > 0).Take(2))
        {
            p.Children.Add(H2("Interfaces — " + snap.Source));
            if (snap.Interfaces.Count > 0)
                p.Children.Add(Table(new[] { "Interface", "Estado", "Detalhe" }, snap.Interfaces.Select(i => new[] { i.Name, i.State, i.Detail }), new double[] { 200, 220, 0 }));
            if (snap.DefaultGateway != null || r.Facts.Dns != null) p.Children.Add(Sub($"Gateway padrão: {snap.DefaultGateway ?? "—"} · DNS: {r.Facts.Dns ?? "—"}"));
            if (snap.ConnectionStates.Count > 0) p.Children.Add(Sub("Conexões TCP: " + string.Join(" · ", snap.ConnectionStates.OrderByDescending(kv => kv.Value).Select(kv => $"{kv.Key} {kv.Value}"))));
        }
        NetworkTacSections(p);
        p.Children.Add(H2("Baseline"));
        p.Children.Add(BaselineTable(MetricCatalog.Network, MetricCatalog.Netskope));
        p.Children.Add(H2("Anomalias"));
        p.Children.Add(AnomalyList(MetricCatalog.Network, MetricCatalog.Netskope));
    }

    // ================================================================= Aplicações

    private void RenderApps()
    {
        var r = _result!;
        var p = AppsPanel;
        p.Children.Clear();
        p.Children.Add(T("Aplicações e tráfego", 24, FontWeights.Bold));
        p.Children.Add(Sub("Testes sintéticos de aplicação do coletor (tempo por fase: DNS, TCP, TLS e 1º byte) e o tráfego que o Netskope Client registrou por processo e destino: tunelado para inspeção, em bypass (exceções) e UDP/QUIC bloqueado."));

        var probes = SeriesStarting("http.ttfb").ToList();
        if (probes.Count > 0)
        {
            p.Children.Add(ChartBlock("Tempo até o 1º byte (TTFB)", probes, "Inclui o tempo de inspeção do Netskope quando o tráfego é tunelado."));
            p.Children.Add(ChartBlock("Tempo total da requisição", SeriesStarting("http.total")));
            var labels = probes.Select(s => MetricCatalog.Split(s.Key).Target!).ToList();
            p.Children.Add(Table(new[] { "Aplicação", "DNS", "TCP", "TLS", "1º byte", "Total", "Total p95", "Falhas" },
                labels.Select(l =>
                {
                    string Med(string k) => _result.Series.TryGetValue($"http.{k}:{l}", out var s) && s.Stats is BaselineStats st ? $"{st.P50:0} ms" : "—";
                    var p95 = _result.Series.TryGetValue($"http.total:{l}", out var t) && t.Stats is BaselineStats ts ? $"{ts.P95:0} ms" : "—";
                    var fails = _result.Events.Count(e => e.Label == "Falha no teste HTTP" && e.Detail.StartsWith(l, StringComparison.OrdinalIgnoreCase));
                    return new[] { l, Med("dns"), Med("tcp"), Med("tls"), Med("ttfb"), Med("total"), p95, fails.ToString(CultureInfo.InvariantCulture) };
                }), new double[] { 0, 80, 80, 80, 90, 90, 90, 70 }));
            p.Children.Add(Sub("Valores = mediana por fase."));
        }
        else p.Children.Add(Notice("Sem testes de aplicação: o coletor de telemetria mede DNS, TCP, TLS e tempo até o 1º byte das URLs configuradas.", AmberText, AmberBg));

        var flows = SeriesStarting("flows.tunnel", "flows.bypass", "flows.udpblock").ToList();
        if (flows.Count > 0) p.Children.Add(ChartBlock("Tráfego registrado pelo Netskope Client", flows));
        if (r.Apps.Count > 0)
        {
            p.Children.Add(H2("Por processo"));
            p.Children.Add(Table(new[] { "Processo", "Destinos", "Tunelados", "Bypass", "UDP/QUIC bloqueado" },
                r.Apps.GroupBy(a => a.Process).Select(g => (g.Key, Hosts: g.Count(), Tun: g.Sum(a => a.Tunneled), Byp: g.Sum(a => a.Bypassed), Udp: g.Sum(a => a.BlockedUdp)))
                    .OrderByDescending(x => x.Tun + x.Byp + x.Udp).Take(20)
                    .Select(x => new[] { x.Key, x.Hosts.ToString(CultureInfo.InvariantCulture), x.Tun.ToString("N0", Br), x.Byp.ToString("N0", Br), x.Udp.ToString("N0", Br) }),
                new double[] { 0, 90, 110, 90, 150 }));
            if (r.Apps.Any(a => a.BlockedUdp > 0))
                p.Children.Add(Sub("UDP/QUIC bloqueado é o comportamento padrão do Netskope para forçar o tráfego por TCP/TLS (inspecionável). Só é problema se a aplicação depender de UDP — nesse caso crie uma exceção."));
            p.Children.Add(H2("Por destino"));
            p.Children.Add(Table(new[] { "Processo", "Destino", "Tunelados", "Bypass", "UDP bloq.", "Primeiro", "Último" },
                r.Apps.Take(300).Select(a => new[] { a.Process, a.Host, a.Tunneled.ToString("N0", Br), a.Bypassed.ToString("N0", Br), a.BlockedUdp.ToString("N0", Br), Tm(a.First), Tm(a.Last) }),
                new double[] { 130, 0, 85, 70, 80, 140, 140 }));
        }
        p.Children.Add(H2("Baseline"));
        p.Children.Add(BaselineTable(MetricCatalog.Apps));
    }

    // ================================================================= análise desta máquina

    private async void AnalyzeThisMachine_Click(object sender, RoutedEventArgs e)
    {
        DropView.Visibility = Visibility.Visible; Tabs.Visibility = Visibility.Collapsed;
        Busy.Visibility = Visibility.Visible;
        var progress = new Progress<string>(s => TxtProgress.Text = s);
        var paths = new List<string>();
        try
        {
            var zip = await DiagnosticsPackager.SaveNetskopeLogsAsync(Path.Combine(Path.GetTempPath(), "NetskopeLogAnalyzer"), progress, CancellationToken.None);
            if (zip != null) paths.Add(zip);
        }
        catch (Exception ex) { TxtProgress.Text = "Não foi possível coletar os logs do Netskope: " + ex.Message; }
        paths.AddRange(TelemetryCollector.LocalTelemetryFiles(7));
        Busy.Visibility = Visibility.Collapsed;
        if (paths.Count == 0)
        {
            TxtProgress.Text = "Netskope Client não encontrado nesta máquina e ainda não há telemetria. Inicie o coletor em “Telemetria”.";
            return;
        }
        LoadFiles(paths.ToArray());
    }

    // ================================================================= janela de Telemetria

    private void Telemetry_Click(object sender, RoutedEventArgs e)
    {
        var w = new Window { Title = "Telemetria desta máquina", Owner = this, Width = 640, SizeToContent = SizeToContent.Height, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, Background = White, FontFamily = FontFamily, FontSize = 14 };
        var sp = new StackPanel { Margin = new Thickness(22) };
        sp.Children.Add(T("Coletor de telemetria", 22, FontWeights.Bold));
        sp.Children.Add(T("Funciona como o agente do Netskope DEM, sem licença: grava a cada 30 s CPU, memória, disco, bateria, Wi-Fi (sinal, RSSI, taxa, troca de AP), tráfego e processos; a cada minuto ping/perda/jitter, conexão TCP até os POPs, DNS e testes HTTP por fase; e um traceroute até o POP a cada 15 min. Os dados ficam só nesta máquina (" + AppSettings.TelemetryDir + ").", 13.5, fg: Mute, margin: new Thickness(0, 6, 0, 12)));
        var status = T("", 14, FontWeights.SemiBold);
        sp.Children.Add(status);
        if (AppSettings.CollectorDisabledByPolicy) sp.Children.Add(Notice("O coletor foi desativado pela política do TI (DisableCollector).", AmberText, AmberBg));

        var btns = new WrapPanel { Margin = new Thickness(0, 12, 0, 0) };
        Button Btn(string text, string style, RoutedEventHandler h) { var b = new Button { Content = text, Style = (Style)FindResource(style), Margin = new Thickness(0, 0, 8, 8) }; b.Click += h; btns.Children.Add(b); return b; }
        var start = Btn("Iniciar coleta", "PillDark", (_, _) => { Try(TelemetryCollector.StartBackground); });
        var stop = Btn("Parar coleta", "Pill", (_, _) => { Try(TelemetryCollector.StopBackground); });
        Btn("Abrir pasta", "Pill", (_, _) => { Directory.CreateDirectory(AppSettings.TelemetryDir); Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppSettings.TelemetryDir}\"") { UseShellExecute = true }); });
        sp.Children.Add(btns);
        var auto = new CheckBox { Content = "Coleta contínua: iniciar o coletor automaticamente no logon", IsChecked = TelemetryCollector.AutoStartEnabled, Margin = new Thickness(0, 4, 0, 12), IsEnabled = !AppSettings.CollectorDisabledByPolicy };
        auto.Checked += (_, _) => { Try(() => TelemetryCollector.AutoStartEnabled = true); Try(TelemetryCollector.StartBackground); };
        auto.Unchecked += (_, _) => Try(() => TelemetryCollector.AutoStartEnabled = false);
        sp.Children.Add(auto);

        sp.Children.Add(T("Diagnóstico", 16, FontWeights.Bold, margin: new Thickness(0, 6, 0, 6)));
        var b2 = new WrapPanel();
        void Btn2(string text, string style, RoutedEventHandler h) { var b = new Button { Content = text, Style = (Style)FindResource(style), Margin = new Thickness(0, 0, 8, 8) }; b.Click += h; b2.Children.Add(b); }
        Btn2("Analisar esta máquina agora", "PillDark", (s, a) => { w.Close(); AnalyzeThisMachine_Click(s, a); });
        Btn2("Exportar pacote de diagnóstico…", "Pill", async (_, _) =>
        {
            var dlg = new SaveFileDialog { Title = "Salvar pacote de diagnóstico", FileName = $"NLA-diagnostico-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmm}.zip", Filter = "Zip (*.zip)|*.zip" };
            if (dlg.ShowDialog(w) != true) return;
            status.Text = "Gerando o pacote…";
            try
            {
                await DiagnosticsPackager.ExportAsync(dlg.FileName, 14, new Progress<string>(s => status.Text = s), CancellationToken.None);
                status.Text = "Pacote salvo em " + dlg.FileName;
            }
            catch (Exception ex) { status.Text = "Falha ao gerar o pacote: " + ex.Message; }
        });
        Btn2("Salvar coletor para Linux/macOS…", "Pill", (_, _) =>
        {
            var dlg = new SaveFileDialog { Title = "Salvar coletor para Linux/macOS", FileName = "nla-collect.sh", Filter = "Script (*.sh)|*.sh" };
            if (dlg.ShowDialog(w) != true) return;
            using var res = typeof(MainWindow).Assembly.GetManifestResourceStream("nla-collect.sh");
            if (res is null) { status.Text = "Script não encontrado no aplicativo."; return; }
            using (var f = File.Create(dlg.FileName)) res.CopyTo(f);
            status.Text = "Script salvo. No Linux/macOS: chmod +x nla-collect.sh && ./nla-collect.sh -t <tenant>  (ou --install para coleta contínua).";
        });
        sp.Children.Add(b2);
        sp.Children.Add(T("Para analisar outra máquina: rode o coletor nela (este app com “Coleta contínua”, ou o script no Linux/macOS), gere o pacote de logs do Netskope e abra os dois arquivos juntos aqui.", 12.5, fg: Mute, margin: new Thickness(0, 8, 0, 0)));

        void Refresh()
        {
            var running = TelemetryCollector.IsRunning();
            var files = TelemetryCollector.LocalTelemetryFiles().ToList();
            status.Text = (running ? "● Coletando agora" : "○ Coletor parado") + (files.Count > 0 ? $" · {files.Count} arquivo(s), último atualizado em {File.GetLastWriteTime(files[^1]):dd/MM HH:mm:ss}" : " · nenhum dado ainda");
            status.Foreground = running ? Green : Mute;
            start.IsEnabled = !running && !AppSettings.CollectorDisabledByPolicy;
            stop.IsEnabled = running;
        }
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        timer.Tick += (_, _) => Refresh();
        timer.Start();
        w.Closed += (_, _) => { timer.Stop(); RefreshCollectorStatus(); };
        Refresh();
        w.Content = sp;
        w.ShowDialog();
    }

    // ================================================================= Configurações

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var w = new Window { Title = "Configurações", Owner = this, Width = 600, SizeToContent = SizeToContent.Height, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, Background = White, FontFamily = FontFamily, FontSize = 14 };
        var sp = new StackPanel { Margin = new Thickness(22) };
        sp.Children.Add(T("Configurações", 22, FontWeights.Bold, margin: new Thickness(0, 0, 0, 12)));
        TextBox Field(string label, string value, bool multi = false, string? hint = null)
        {
            sp.Children.Add(T(label, 13, FontWeights.SemiBold, margin: new Thickness(0, 8, 0, 4)));
            var tb = new TextBox { Text = value, Padding = new Thickness(6, 4, 6, 4), AcceptsReturn = multi, Height = multi ? 80 : double.NaN, VerticalScrollBarVisibility = multi ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled };
            sp.Children.Add(tb);
            if (hint != null) sp.Children.Add(T(hint, 11.5, fg: Mute));
            return tb;
        }
        var policyTenant = AppSettings.PolicyTenant;
        var tenant = Field("Tenant Netskope", policyTenant ?? _settings.Tenant ?? "", hint: policyTenant != null ? "Definido pela política do TI." : "Ex.: acme (para acme.goskope.com) ou acme.eu. Usado nos testes até o POP. Detectado automaticamente quando o Netskope Client está instalado.");
        tenant.IsEnabled = policyTenant is null;
        var urls = Field("URLs para testes de aplicação (uma por linha)", string.Join(Environment.NewLine, _settings.ProbeUrls), true);
        var interval = Field("Intervalo de amostragem (segundos)", _settings.IntervalSeconds.ToString(CultureInfo.InvariantCulture));
        var probe = Field("Intervalo dos testes de rede e aplicação (segundos)", _settings.ProbeSeconds.ToString(CultureInfo.InvariantCulture));
        var trace = Field("Intervalo do traceroute (minutos)", _settings.TraceMinutes.ToString(CultureInfo.InvariantCulture));
        var ret = Field("Guardar telemetria por (dias)", _settings.RetentionDays.ToString(CultureInfo.InvariantCulture));

        sp.Children.Add(T("Atualizações", 16, FontWeights.Bold, margin: new Thickness(0, 16, 0, 4)));
        var autoCheck = new CheckBox { Content = "Verificar atualizações automaticamente", IsChecked = _settings.AutoCheckUpdates, Margin = new Thickness(0, 4, 0, 0) };
        var autoInstall = new CheckBox { Content = "Instalar atualizações automaticamente (pede confirmação do Windows)", IsChecked = _settings.AutoInstallUpdates, Margin = new Thickness(0, 4, 0, 0) };
        sp.Children.Add(autoCheck); sp.Children.Add(autoInstall);
        if (AppSettings.UpdatesDisabledByPolicy) { autoCheck.IsEnabled = autoInstall.IsEnabled = false; sp.Children.Add(T("Atualizações desativadas pela política do TI.", 12, fg: AmberText)); }
        var ver = T($"Versão instalada: {UpdateService.Current.ToString(3)}" + (_settings.LastUpdateCheck is DateTime lc ? $" · última verificação: {lc:dd/MM HH:mm}" : ""), 12.5, fg: Mute, margin: new Thickness(0, 6, 0, 0));
        sp.Children.Add(ver);

        var bar = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
        var check = new Button { Content = "Verificar agora", Style = (Style)FindResource("Pill"), Margin = new Thickness(0, 0, 8, 0), IsEnabled = !AppSettings.UpdatesDisabledByPolicy };
        check.Click += async (_, _) => { ver.Text = "Verificando…"; var found = await CheckUpdatesAsync(true); ver.Text = found ? $"Nova versão {_update!.Version.ToString(3)} disponível — veja a barra azul." : $"Você está na versão mais recente ({UpdateService.Current.ToString(3)})."; };
        var save = new Button { Content = "Salvar", Style = (Style)FindResource("PillDark") };
        save.Click += (_, _) =>
        {
            static int Int(TextBox tb, int def, int min, int max) => int.TryParse(tb.Text.Trim(), out var v) ? Math.Clamp(v, min, max) : def;
            if (policyTenant is null) _settings.Tenant = string.IsNullOrWhiteSpace(tenant.Text) ? null : tenant.Text.Trim().ToLowerInvariant().Replace(".goskope.com", "");
            _settings.ProbeUrls = urls.Text.Split('\n').Select(u => u.Trim()).Where(u => Uri.IsWellFormedUriString(u, UriKind.Absolute)).Distinct().ToList();
            _settings.IntervalSeconds = Int(interval, 30, 5, 3600);
            _settings.ProbeSeconds = Int(probe, 60, 15, 3600);
            _settings.TraceMinutes = Int(trace, 15, 1, 1440);
            _settings.RetentionDays = Int(ret, 14, 1, 365);
            _settings.AutoCheckUpdates = autoCheck.IsChecked == true;
            _settings.AutoInstallUpdates = autoInstall.IsChecked == true;
            _settings.Save();
            if (TelemetryCollector.IsRunning()) { Try(TelemetryCollector.StopBackground); _ = RestartCollectorSoon(); }
            w.Close();
            ShowToast("Configurações salvas.");
        };
        bar.Children.Add(check); bar.Children.Add(save);
        sp.Children.Add(bar);
        w.Content = new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = SystemParameters.WorkArea.Height * 0.9 };
        w.ShowDialog();
    }

    private static async Task RestartCollectorSoon()
    {
        for (var i = 0; i < 20 && TelemetryCollector.IsRunning(); i++) await Task.Delay(500);
        Try(TelemetryCollector.StartBackground);
    }

    // ================================================================= atualização automática

    private async Task<bool> CheckUpdatesAsync(bool manual)
    {
        try
        {
            var u = await UpdateService.CheckAsync(CancellationToken.None);
            _settings.LastUpdateCheck = DateTime.Now; _settings.Save();
            if (u is null) return false;
            _update = u;
            if (!manual && _settings.SkippedVersion == u.Version.ToString(3)) return true;
            UpdateText.Text = $"Nova versão {u.Version.ToString(3)} do Netskope Log Analyzer disponível (você está na {UpdateService.Current.ToString(3)}).";
            BtnUpdateNow.Content = UpdateService.IsInstalled ? "Atualizar agora" : "Baixar";
            UpdateBar.Visibility = Visibility.Visible;
            if (!manual && _settings.AutoInstallUpdates && UpdateService.IsInstalled) UpdateNow_Click(this, new RoutedEventArgs());
            return true;
        }
        catch (Exception ex)
        {
            if (manual) MessageBox.Show(this, "Não foi possível verificar atualizações:\n" + ex.Message, "Netskope Log Analyzer");
            return false;
        }
    }

    private async void UpdateNow_Click(object sender, RoutedEventArgs e)
    {
        if (_update is null) return;
        if (!UpdateService.IsInstalled) { OpenUrlSafe(_update.PageUrl); return; }
        BtnUpdateNow.IsEnabled = false;
        try
        {
            var path = await UpdateService.DownloadAndVerifyAsync(_update, new Progress<string>(s => UpdateText.Text = s), CancellationToken.None);
            UpdateText.Text = "Instalando… o aplicativo será reaberto ao final.";
            UpdateService.LaunchInstaller(path);
            Application.Current.Shutdown();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            UpdateText.Text = "A instalação foi cancelada (a confirmação do Windows não foi aceita).";
            BtnUpdateNow.IsEnabled = true;
        }
        catch (Exception ex)
        {
            UpdateText.Text = "Falha na atualização: " + ex.Message;
            BtnUpdateNow.IsEnabled = true;
        }
    }

    private void UpdateNotes_Click(object sender, RoutedEventArgs e) { if (_update != null) OpenUrlSafe(_update.PageUrl); }

    private void UpdateSkip_Click(object sender, RoutedEventArgs e)
    {
        if (_update != null) { _settings.SkippedVersion = _update.Version.ToString(3); _settings.Save(); }
        UpdateBar.Visibility = Visibility.Collapsed;
    }

    private static void OpenUrlSafe(string url)
    {
        if (string.IsNullOrEmpty(url)) return;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch (Exception) { }
    }
}
