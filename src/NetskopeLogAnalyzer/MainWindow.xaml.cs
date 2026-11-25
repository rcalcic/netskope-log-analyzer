using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using NetskopeLogAnalyzer.Core;
using IOPath = System.IO.Path;

namespace NetskopeLogAnalyzer;

public sealed class ExplorerRow
{
    public required string Text { get; init; }
    public required Brush Brush { get; init; }
}

public sealed class UnclassifiedRow
{
    public required string Message { get; init; }
    public required string LevelText { get; init; }
    public int Count { get; init; }
    public required string Files { get; init; }
    public required string Last { get; init; }
}

public sealed class FileRow
{
    public required string Name { get; init; }
    public required string Size { get; init; }
    public int Lines { get; init; }
    public int Errors { get; init; }
    public int Warnings { get; init; }
    public required string Period { get; init; }
}

public partial class MainWindow : Window
{
    private static Brush B(string hex) { var b = (SolidColorBrush)new BrushConverter().ConvertFromString(hex)!; b.Freeze(); return b; }

    private static readonly Brush Ink = B("#111418"), Mute = B("#5B6270"), LineBrush = B("#E3E6EA"), Soft = B("#F4F6F8"), White = Brushes.White,
        Red = B("#E6261F"), Blue = B("#0A5CFF"), Amber = B("#FFB400"), AmberText = B("#8A5D00"), Green = B("#00A05A"), Gray = B("#8A919C"),
        RedBg = B("#FDECEB"), AmberBg = B("#FFF6DC"), BlueBg = B("#E8F0FF"), GreenBg = B("#E4F6ED");
    private static readonly FontFamily Mono = new("Consolas");

    private AnalysisResult? _result;
    private string _filter = "problems";
    private readonly DispatcherTimer _searchTimer = new() { Interval = TimeSpan.FromMilliseconds(250) };
    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(2) };

    public MainWindow()
    {
        InitializeComponent();
        // ajusta a janela à área útil da tela (notebooks e telas pequenas)
        var wa = SystemParameters.WorkArea;
        Width = Math.Min(Width, wa.Width * 0.94);
        Height = Math.Min(Height, wa.Height * 0.94);
        MinWidth = Math.Min(MinWidth, Width);
        MinHeight = Math.Min(MinHeight, Height);
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        TxtVersion.Text = v is null ? "" : $"v{v.Major}.{v.Minor}.{v.Build}";
        _searchTimer.Tick += (_, _) => { _searchTimer.Stop(); RunExplorer(); };
        _toastTimer.Tick += (_, _) => { _toastTimer.Stop(); Toast.Visibility = Visibility.Collapsed; };
        BuildLegends();
        InitV3();
    }

    // ================================================================= entrada de arquivos

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Escolha o pacote de logs do Netskope",
            Filter = "Pacote de logs (*.zip;*.log;*.txt;*.json)|*.zip;*.log;*.txt;*.json;*.conf|Todos os arquivos (*.*)|*.*",
            Multiselect = true,
        };
        if (dlg.ShowDialog(this) == true) LoadFiles(dlg.FileNames);
    }

    private void Window_DragEnter(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        if (e.Effects == DragDropEffects.Copy) { DropRect.Stroke = Blue; DropRect.Fill = BlueBg; }
        e.Handled = true;
    }

    private void Window_DragLeave(object sender, DragEventArgs e) { DropRect.Stroke = Ink; DropRect.Fill = Soft; }

    private void Window_Drop(object sender, DragEventArgs e)
    {
        DropRect.Stroke = Ink; DropRect.Fill = Soft;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0) LoadFiles(files);
    }

    public async void LoadFiles(string[] paths)
    {
        Tabs.Visibility = Visibility.Collapsed;
        DropView.Visibility = Visibility.Visible;
        Busy.Visibility = Visibility.Visible;
        BtnOpen.IsEnabled = false;
        TxtProgress.Text = "Lendo…";
        var progress = new Progress<string>(s => TxtProgress.Text = s);
        try
        {
            var result = await Task.Run(() => new Analyzer().AnalyzePaths(paths, progress));
            if (result.Entries.Count == 0 && result.Findings.Count == 0 && !result.HasTelemetry && result.Snapshots.Count == 0)
            {
                TxtProgress.Text = "Nenhum log do Netskope reconhecido nesses arquivos.";
                return;
            }
            _result = result;
            TxtFileName.Text = paths.Length <= 2 ? string.Join(", ", paths.Select(p => IOPath.GetFileName(p.TrimEnd('\\', '/')))) : $"{paths.Length} arquivos" + (result.HasTelemetry ? " (com telemetria)" : "");
            TxtProgress.Text = "";
            RenderAll();
        }
        catch (Exception ex)
        {
            TxtProgress.Text = "Erro ao ler: " + ex.Message;
        }
        finally
        {
            Busy.Visibility = Visibility.Collapsed;
            BtnOpen.IsEnabled = true;
        }
    }

    // ================================================================= renderização

    private void RenderAll()
    {
        if (_result is null) return;
        DropView.Visibility = Visibility.Collapsed;
        Tabs.Visibility = Visibility.Visible;
        BtnCopyReport.Visibility = Visibility.Visible;
        BtnSaveReport.Visibility = Visibility.Visible;
        _filter = "problems";
        RenderSummary();
        RenderTimeline();
        RenderChart();
        RenderFilters();
        RenderFindings();
        RenderUnclassified();
        RenderFiles();
        InitExplorer();
        RenderIncidents();
        RenderExperience();
        RenderDevice();
        RenderNetwork();
        RenderApps();
        RenderPerformance();
        RenderConfig();
        int prob = _result.Count(Severity.Critical) + _result.Count(Severity.Warning);
        TabFindings.Header = $"Diagnóstico ({prob})";
        TabUnclassified.Header = $"Não classificados ({_result.Unclassified.Count})";
        TabFiles.Header = $"Arquivos ({_result.Files.Count})";
        Tabs.SelectedItem = TabSummary;
    }

    private static TextBlock T(string text, double size = 14, FontWeight? weight = null, Brush? fg = null, Thickness? margin = null, bool wrap = true) => new()
    {
        Text = text, FontSize = size, FontWeight = weight ?? FontWeights.Normal, Foreground = fg ?? Ink,
        Margin = margin ?? new Thickness(0), TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap,
    };

    private static (Brush Fg, Brush Bg) SevColors(Severity s) => s switch
    {
        Severity.Critical => (Red, RedBg),
        Severity.Warning => (AmberText, AmberBg),
        Severity.Info => (Blue, BlueBg),
        _ => (Mute, Soft),
    };

    private static Brush SevBar(Severity s) => s switch { Severity.Critical => Red, Severity.Warning => Amber, Severity.Info => Blue, _ => Gray };

    private static Border Pill(string text, Brush fg, Brush bg) => new()
    {
        Background = bg, CornerRadius = new CornerRadius(10), Padding = new Thickness(9, 1, 9, 2), Margin = new Thickness(0, 0, 8, 0),
        VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left,
        Child = new TextBlock { Text = text, FontSize = 12, FontWeight = FontWeights.Bold, Foreground = fg },
    };

    private void RenderSummary()
    {
        var r = _result!;
        var F = r.Facts;
        SummaryPanel.Children.Clear();
        int c = r.Count(Severity.Critical), w = r.Count(Severity.Warning);
        var accent = c > 0 ? Red : w > 0 ? Amber : Green;

        var head = new Border { BorderBrush = accent, BorderThickness = new Thickness(0, 8, 0, 0), Padding = new Thickness(0, 20, 0, 0) };
        var hs = new StackPanel();
        hs.Children.Add(T(Report.Verdict(r), 34, FontWeights.Bold));
        hs.Children.Add(T($"{r.Entries.Count:N0} linhas de log em {r.Files.Count(f => f.Lines > 0)} arquivos, de {Report.Time(r.Start)} a {Report.Time(r.End)}. " +
                          $"{r.RawErrors:N0} erros e {r.RawWarnings:N0} alertas brutos — a maior parte é ruído conhecido; abaixo estão os que importam.", 15, fg: Mute, margin: new Thickness(0, 8, 0, 0)));
        head.Child = hs;
        SummaryPanel.Children.Add(head);
        SummaryPanel.Children.Add(SummaryKpis());

        var grid = new Grid { Margin = new Thickness(0, 22, 0, 0) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(40) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var left = new StackPanel();
        var counts = new UniformGrid { Columns = 4 };
        foreach (var s in new[] { Severity.Critical, Severity.Warning, Severity.Info, Severity.Noise })
        {
            var tile = new Border { Background = Soft, CornerRadius = new CornerRadius(14), Padding = new Thickness(14), Margin = new Thickness(0, 0, 10, 0), Cursor = Cursors.Hand, ToolTip = "Ver no diagnóstico" };
            var sp = new StackPanel();
            sp.Children.Add(T(r.Count(s).ToString(CultureInfo.InvariantCulture), 36, FontWeights.Bold, s == Severity.Warning ? AmberText : SevBar(s)));
            sp.Children.Add(T(Report.SeverityLabel(s)));
            tile.Child = sp;
            var sev = s;
            tile.MouseLeftButtonUp += (_, _) => { _filter = sev switch { Severity.Critical => "crit", Severity.Warning => "warn", Severity.Info => "info", _ => "noise" }; RenderFilters(); RenderFindings(); Tabs.SelectedItem = TabFindings; };
            counts.Children.Add(tile);
        }
        left.Children.Add(counts);

        var top = r.Findings.Where(f => f.Severity <= Severity.Warning).Take(6).ToList();
        if (top.Count > 0)
        {
            left.Children.Add(T("Principais pontos", 18, FontWeights.Bold, margin: new Thickness(0, 22, 0, 6)));
            foreach (var f in top)
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 0), Cursor = Cursors.Hand };
                var (fg, bg) = SevColors(f.Severity);
                var pill = Pill(Report.SeverityLabel(f.Severity), fg, bg);
                DockPanel.SetDock(pill, Dock.Left);
                row.Children.Add(pill);
                row.Children.Add(T(f.Title, 15));
                var wrap = new Border { BorderBrush = LineBrush, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 8, 0, 8), Child = row };
                var target = f;
                wrap.MouseLeftButtonUp += (_, _) => ShowFinding(target);
                left.Children.Add(wrap);
            }
        }
        grid.Children.Add(left);

        var facts = new Grid();
        Grid.SetColumn(facts, 2);
        facts.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        facts.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var rows = new List<(string, UIElement)>
        {
            ("Internet (SWG)", ServiceElement(1, null)),
            ("Private Access", ServiceElement(2, F.NpaLast)),
        };
        void Add(string label, string? value) { if (!string.IsNullOrWhiteSpace(value)) rows.Add((label, T(value, 14, FontWeights.SemiBold))); }
        Add("Dispositivo", F.Host);
        Add("Sistema", F.OsName ?? F.Os);
        Add("Modelo", F.Model);
        Add("Versão do cliente", F.Version);
        Add("Tenant", F.TenantHost != null ? F.TenantHost + ".goskope.com" : null);
        Add("Tenant ID", F.TenantId);
        Add("Steering", F.Steering);
        Add("Perfil de configuração", F.ClientConfig);
        Add("Localização", F.OnPrem);
        Add("IP de saída", F.Egress);
        Add("POP NPA", F.PopNpa);
        Add("POP SWG", F.PopSwg);
        Add("Gateway SWG", F.GatewayIp);
        Add("DNS do sistema", F.Dns);
        Add("Fail-close", F.FailClose == "true" ? "Ativo" : F.FailClose == "false" ? "Inativo" : null);
        Add("Usuário pode desabilitar", F.AllowDisable == "true" ? "Sim" : F.AllowDisable == "false" ? "Não" : null);
        Add("Outras VPNs instaladas", F.InstalledVpnApps);
        for (var i = 0; i < rows.Count; i++)
        {
            facts.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var l = T(rows[i].Item1, 14, fg: Mute, margin: new Thickness(0, 4, 18, 4), wrap: false);
            Grid.SetRow(l, i);
            facts.Children.Add(l);
            var v = rows[i].Item2;
            if (v is FrameworkElement fe) fe.Margin = new Thickness(0, 4, 0, 4);
            Grid.SetRow(v, i); Grid.SetColumn(v, 1);
            facts.Children.Add(v);
        }
        grid.Children.Add(facts);
        SummaryPanel.Children.Add(grid);
        SummaryPanel.Children.Add(CaseSummaryBlock());
    }

    private UIElement ServiceElement(int svc, string? fallback)
    {
        if (_result!.Facts.Services.TryGetValue(svc, out var st))
        {
            var kind = Analyzer.EventKindOf(st.Event);
            var (fg, bg) = kind switch { EventKind.Good => (Green, GreenBg), EventKind.Bad => (Red, RedBg), EventKind.Alert => (AmberText, AmberBg), _ => (Blue, BlueBg) };
            var sp = new StackPanel { Orientation = Orientation.Horizontal };
            sp.Children.Add(Pill(Analyzer.EventLabel(st.Event), fg, bg));
            sp.Children.Add(T(Report.Time(st.Time), 12, fg: Mute, wrap: false));
            return sp;
        }
        return T(fallback ?? "—", 14, FontWeights.SemiBold);
    }

    private void ShowFinding(Finding f)
    {
        _filter = "all";
        RenderFilters();
        RenderFindings(f);
        Tabs.SelectedItem = TabFindings;
    }

    // ---------------------------------------------------------------- linha do tempo

    private static Brush KindBrush(EventKind k) => k switch { EventKind.Good => Green, EventKind.Bad => Red, EventKind.Alert => Amber, _ => Blue };

    private void BuildLegends()
    {
        void Dot(WrapPanel p, Brush b, string text, bool square = false)
        {
            var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 16, 0) };
            sp.Children.Add(square ? new Rectangle { Width = 12, Height = 12, Fill = b, Margin = new Thickness(0, 0, 6, 0) }
                                   : new Ellipse { Width = 12, Height = 12, Fill = b, Margin = new Thickness(0, 0, 6, 0) });
            sp.Children.Add(T(text, 12, fg: Mute, wrap: false));
            p.Children.Add(sp);
        }
        Dot(TimelineLegend, Green, "Conectado / registrado"); Dot(TimelineLegend, Red, "Queda / parada");
        Dot(TimelineLegend, Amber, "Desabilitado / alerta"); Dot(TimelineLegend, Blue, "Informativo");
        Dot(ChartLegend, Red, "Erros e críticos", true); Dot(ChartLegend, Amber, "Alertas (warn)", true);
    }

    private void RenderTimeline()
    {
        var ev = _result!.Events;
        var cv = TimelineCanvas;
        cv.Children.Clear();
        if (ev.Count == 0)
        {
            cv.Width = 600;
            var t = T("Nenhum evento de estado encontrado nos logs.", 14, fg: Mute);
            Canvas.SetLeft(t, 20); Canvas.SetTop(t, 20);
            cv.Children.Add(t);
            return;
        }
        const double gap = 150, y = 110, x0 = 100;
        cv.Width = x0 * 2 + (ev.Count - 1) * gap;
        cv.Children.Add(new Line { X1 = 24, X2 = x0 + (ev.Count - 1) * gap + 50, Y1 = y, Y2 = y, Stroke = Ink, StrokeThickness = 10, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round });
        for (var i = 0; i < ev.Count; i++)
        {
            var e = ev[i];
            var x = x0 + i * gap;
            if (i > 0 && e.Time.Date != ev[i - 1].Time.Date)
                cv.Children.Add(new Line { X1 = x - gap / 2, X2 = x - gap / 2, Y1 = y - 28, Y2 = y + 28, Stroke = Mute, StrokeDashArray = new DoubleCollection { 3, 3 } });
            var tip = $"{e.Label}{(e.Detail.Length > 0 ? " — " + e.Detail : "")}\n{e.Time:dd/MM/yyyy HH:mm:ss}\n{e.File}";
            var outer = new Ellipse { Width = 28, Height = 28, Fill = White, Stroke = Ink, StrokeThickness = 5, ToolTip = tip };
            Canvas.SetLeft(outer, x - 14); Canvas.SetTop(outer, y - 14);
            var inner = new Ellipse { Width = 12, Height = 12, Fill = KindBrush(e.Kind), IsHitTestVisible = false };
            Canvas.SetLeft(inner, x - 6); Canvas.SetTop(inner, y - 6);
            cv.Children.Add(outer); cv.Children.Add(inner);

            var up = i % 2 == 0;
            var det = e.Detail.Contains(" · por ") ? e.Detail[..e.Detail.IndexOf(" · por ", StringComparison.Ordinal)] : e.Detail;
            var label = new StackPanel { Width = 160, ToolTip = tip };
            label.Children.Add(new TextBlock { Text = e.Label, FontWeight = FontWeights.Bold, FontSize = 13, TextAlignment = TextAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, Foreground = Ink });
            label.Children.Add(new TextBlock { Text = e.Time.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + (det.Length > 0 ? " · " + det : ""), FontSize = 12, TextAlignment = TextAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, Foreground = Mute });
            Canvas.SetLeft(label, x - 80);
            Canvas.SetTop(label, up ? y - 70 : y + 26);
            cv.Children.Add(label);
        }
    }

    private void ChartHost_SizeChanged(object sender, SizeChangedEventArgs e) => RenderChart();

    private void RenderChart()
    {
        var cv = ChartCanvas;
        cv.Children.Clear();
        if (_result is null || _result.Start is null || _result.End is null) return;
        double W = ChartHost.ActualWidth, H = ChartHost.ActualHeight;
        if (W < 50 || H < 50) return;
        var start = _result.Start.Value; var end = _result.End.Value;
        var span = Math.Max((end - start).TotalSeconds, 60);
        var steps = new[] { 60, 300, 900, 3600, 21600, 86400 };
        var maxBars = Math.Max(20, W / 9);
        var step = steps.FirstOrDefault(s => span / s <= maxBars, 86400);
        var t0 = new DateTime(start.Ticks / TimeSpan.TicksPerSecond / step * step * TimeSpan.TicksPerSecond);
        var nb = (int)((end - t0).TotalSeconds / step) + 1;
        var err = new int[nb]; var wrn = new int[nb];
        foreach (var e in _result.Entries)
        {
            var b = (int)((e.Time - t0).TotalSeconds / step);
            if (b < 0 || b >= nb) continue;
            if (e.Level == LogLevel.Warn) wrn[b]++;
            else if (e.Level is LogLevel.Error or LogLevel.Critical) err[b]++;
        }
        var mx = Math.Max(1, Enumerable.Range(0, nb).Max(i => err[i] + wrn[i]));
        const double pl = 48, pb = 26, pt = 10;
        double cw = (W - pl - 8) / nb, ch = H - pb - pt;
        foreach (var f in new[] { 0.0, 0.5, 1.0 })
        {
            var yy = pt + ch * (1 - f);
            cv.Children.Add(new Line { X1 = pl, X2 = W - 8, Y1 = yy, Y2 = yy, Stroke = LineBrush });
            var lab = T(((int)Math.Round(mx * f)).ToString(CultureInfo.InvariantCulture), 11, fg: Mute, wrap: false);
            lab.Width = pl - 8; lab.TextAlignment = TextAlignment.Right;
            Canvas.SetLeft(lab, 0); Canvas.SetTop(lab, yy - 8);
            cv.Children.Add(lab);
        }
        for (var i = 0; i < nb; i++)
        {
            double he = err[i] / (double)mx * ch, hw = wrn[i] / (double)mx * ch, xx = pl + i * cw + cw * 0.12, bw = Math.Max(1, cw * 0.76);
            var when = t0.AddSeconds((double)i * step).ToString("dd/MM HH:mm", CultureInfo.InvariantCulture);
            if (hw > 0)
            {
                var r = new Rectangle { Width = bw, Height = hw, Fill = Amber, ToolTip = $"{when}: {wrn[i]} alertas" };
                Canvas.SetLeft(r, xx); Canvas.SetTop(r, pt + ch - he - hw); cv.Children.Add(r);
            }
            if (he > 0)
            {
                var r = new Rectangle { Width = bw, Height = he, Fill = Red, ToolTip = $"{when}: {err[i]} erros" };
                Canvas.SetLeft(r, xx); Canvas.SetTop(r, pt + ch - he); cv.Children.Add(r);
            }
        }
        var every = Math.Max(1, (int)Math.Ceiling(nb / (W / 90)));
        for (var i = 0; i < nb; i += every)
        {
            var t = t0.AddSeconds((double)i * step);
            var lab = T(step >= 86400 ? t.ToString("dd/MM", CultureInfo.InvariantCulture) : t.ToString("HH:mm", CultureInfo.InvariantCulture), 11, fg: Mute, wrap: false);
            lab.Width = 60; lab.TextAlignment = TextAlignment.Center;
            Canvas.SetLeft(lab, pl + i * cw + cw / 2 - 30); Canvas.SetTop(lab, H - pb + 6);
            cv.Children.Add(lab);
        }
    }

    // ---------------------------------------------------------------- diagnóstico

    private void RenderFilters()
    {
        var r = _result!;
        FilterPanel.Children.Clear();
        int c = r.Count(Severity.Critical), w = r.Count(Severity.Warning);
        var opts = new (string Key, string Label)[]
        {
            ("problems", $"Problemas ({c + w})"), ("crit", $"Crítico ({c})"), ("warn", $"Atenção ({w})"),
            ("info", $"Informativo ({r.Count(Severity.Info)})"), ("noise", $"Ruído conhecido ({r.Count(Severity.Noise)})"), ("all", $"Todos ({r.Findings.Count})"),
        };
        foreach (var (key, label) in opts)
        {
            var rb = new RadioButton { Content = label, GroupName = "filter", Style = (Style)FindResource("Filter"), IsChecked = key == _filter };
            var k = key;
            rb.Checked += (_, _) => { _filter = k; RenderFindings(); };
            FilterPanel.Children.Add(rb);
        }
    }

    private bool PassesFilter(Finding f) => _filter switch
    {
        "problems" => f.Severity <= Severity.Warning,
        "crit" => f.Severity == Severity.Critical,
        "warn" => f.Severity == Severity.Warning,
        "info" => f.Severity == Severity.Info,
        "noise" => f.Severity == Severity.Noise,
        _ => true,
    };

    private void RenderFindings(Finding? focus = null)
    {
        FindingsPanel.Children.Clear();
        var list = _result!.Findings.Where(PassesFilter).ToList();
        if (list.Count == 0)
        {
            FindingsPanel.Children.Add(new Border { Background = GreenBg, CornerRadius = new CornerRadius(14), Padding = new Thickness(20), Child = T("Nada nesta categoria.", 15, FontWeights.SemiBold, Green) });
            return;
        }
        FrameworkElement? focusCard = null;
        for (var i = 0; i < list.Count; i++)
        {
            var f = list[i];
            var open = focus != null ? ReferenceEquals(f, focus) : (i < 2 && f.Severity == Severity.Critical);
            var card = BuildCard(f, open);
            if (ReferenceEquals(f, focus)) focusCard = card;
            FindingsPanel.Children.Add(card);
        }
        if (focusCard != null) Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () => focusCard.BringIntoView());
        else FindingsScroll.ScrollToTop();
    }

    private FrameworkElement BuildCard(Finding f, bool open)
    {
        var (fg, bg) = SevColors(f.Severity);
        var outer = new Border { BorderBrush = LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Background = White, Margin = new Thickness(0, 0, 0, 12), ClipToBounds = true };
        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        var bar = new Border { Background = SevBar(f.Severity), CornerRadius = new CornerRadius(12, 0, 0, 12) };
        grid.Children.Add(bar);

        var stack = new StackPanel();
        Grid.SetColumn(stack, 1);
        grid.Children.Add(stack);
        outer.Child = grid;

        // cabeçalho clicável
        var header = new Grid { Background = Brushes.Transparent, Cursor = Cursors.Hand, Margin = new Thickness(16, 14, 16, 14) };
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var hl = new StackPanel();
        var tags = new StackPanel { Orientation = Orientation.Horizontal };
        tags.Children.Add(Pill(Report.SeverityLabel(f.Severity), fg, bg));
        tags.Children.Add(T(f.Category, 12, fg: Mute, wrap: false));
        hl.Children.Add(tags);
        var titleLine = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
        titleLine.Inlines.Add(new Run(open ? "▾ " : "▸ ") { Foreground = Mute, FontSize = 16 });
        titleLine.Inlines.Add(new Run(f.Title) { FontSize = 17, FontWeight = FontWeights.Bold });
        hl.Children.Add(titleLine);
        var meta = new List<string>();
        if (f.First != null) { meta.Add("Primeira: " + Report.Time(f.First)); meta.Add("Última: " + Report.Time(f.Last)); }
        if (f.Files.Count > 0) meta.Add(string.Join(", ", f.Files));
        if (meta.Count > 0) hl.Children.Add(T(string.Join("    ", meta), 12, fg: Mute, margin: new Thickness(0, 4, 0, 0)));
        header.Children.Add(hl);
        var num = new StackPanel { HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(16, 0, 0, 0) };
        num.Children.Add(new TextBlock { Text = f.Count.ToString("N0", CultureInfo.GetCultureInfo("pt-BR")), FontSize = 26, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Right });
        num.Children.Add(T(f.Count == 1 ? "ocorrência" : "ocorrências", 12, fg: Mute, wrap: false));
        Grid.SetColumn(num, 1);
        header.Children.Add(num);
        stack.Children.Add(header);

        var body = new StackPanel { Margin = new Thickness(16, 0, 16, 16), Visibility = open ? Visibility.Visible : Visibility.Collapsed };
        BuildBody(f, body);
        stack.Children.Add(body);

        header.MouseLeftButtonUp += (_, _) =>
        {
            var show = body.Visibility != Visibility.Visible;
            body.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            if (titleLine.Inlines.FirstInline is Run r) r.Text = show ? "▾ " : "▸ ";
        };
        return outer;
    }

    private static TextBlock H4(string text) => T(text, 13, FontWeights.SemiBold, Mute, new Thickness(0, 10, 0, 4));

    private void BuildBody(Finding f, StackPanel body)
    {
        body.Children.Add(H4("O que significa"));
        body.Children.Add(T(f.Meaning, 14.5));

        var os = _result!.DetectedOs;
        var fix = new Border { BorderBrush = Green, BorderThickness = new Thickness(2), CornerRadius = new CornerRadius(12), Background = GreenBg, Padding = new Thickness(16, 12, 16, 14), Margin = new Thickness(0, 14, 0, 0) };
        var fs = new StackPanel();
        var fh = new StackPanel { Orientation = Orientation.Horizontal };
        fh.Children.Add(T("Como resolver", 15, FontWeights.Bold, wrap: false, margin: new Thickness(0, 0, 10, 0)));
        if (os is ClientOs o) fh.Children.Add(Pill("Log de " + KnowledgeBase.OsLabel(o), Green, White));
        fs.Children.Add(fh);

        var steps = f.Steps.Count > 0 ? f.Steps : new List<FixStep> { new(f.Severity == Severity.Noise ? "Nenhuma ação necessária. " + f.Action : f.Action) };
        for (var i = 0; i < steps.Count; i++)
        {
            var s = steps[i];
            var sp = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
            sp.Children.Add(T($"{i + 1}. {s.Text}", 14.5));
            if (s.Command != null) sp.Children.Add(CommandBox(s.Command));
            fs.Children.Add(sp);
        }

        if (f.References.Count > 0)
        {
            fs.Children.Add(H4("Documentação oficial"));
            foreach (var rf in f.References) fs.Children.Add(LinkLine("•  ", rf));
        }
        fs.Children.Add(H4("Pesquisar mais"));
        var wp = new WrapPanel();
        foreach (var l in KnowledgeBase.SearchLinks(f.SearchQuery)) wp.Children.Add(LinkLine("", l with { Title = l.Title + " ↗" }, new Thickness(0, 0, 16, 0)));
        fs.Children.Add(wp);
        fix.Child = fs;
        body.Children.Add(fix);

        if (f.Details.Count > 0)
        {
            body.Children.Add(H4("Detalhe"));
            body.Children.Add(T(string.Join("  ·  ", f.Details.Take(8).Select(d => $"{d.Key} ×{d.Value}")), 14));
        }
        if (f.Samples.Count > 0)
        {
            body.Children.Add(H4("Exemplos do log"));
            body.Children.Add(new TextBox
            {
                Text = string.Join(Environment.NewLine, f.Samples), IsReadOnly = true, FontFamily = Mono, FontSize = 12, Background = Soft, BorderBrush = LineBrush,
                Padding = new Thickness(8), MaxHeight = 170, TextWrapping = TextWrapping.NoWrap,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            });
        }
        if (f.ExplorerQuery != null)
        {
            var b = new Button { Content = "Ver todas as linhas no explorador", Style = (Style)FindResource("Small"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 12, 0, 0) };
            b.Click += (_, _) =>
            {
                XLevel.SelectedIndex = 2; XFile.SelectedIndex = 0; XSearch.Text = f.ExplorerQuery;
                RunExplorer(); Tabs.SelectedItem = TabExplorer;
            };
            body.Children.Add(b);
        }
    }

    private UIElement CommandBox(string cmd)
    {
        var g = new Grid { Margin = new Thickness(0, 6, 0, 0) };
        var tb = new TextBox
        {
            Text = cmd.Replace("\n", Environment.NewLine), IsReadOnly = true, FontFamily = Mono, FontSize = 12.5, Background = White, BorderBrush = LineBrush,
            Padding = new Thickness(10, 8, 90, 8), TextWrapping = TextWrapping.NoWrap, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
        };
        g.Children.Add(tb);
        var btn = new Button { Content = "Copiar", Style = (Style)FindResource("Small"), HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 5, 6, 0) };
        btn.Click += (_, _) => { if (TryCopy(cmd.Replace("\n", Environment.NewLine))) { btn.Content = "Copiado"; var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) }; t.Tick += (_, _) => { t.Stop(); btn.Content = "Copiar"; }; t.Start(); } };
        g.Children.Add(btn);
        return g;
    }

    private static TextBlock LinkLine(string prefix, Reference r, Thickness? margin = null)
    {
        var tb = new TextBlock { Margin = margin ?? new Thickness(0, 2, 0, 2), TextWrapping = TextWrapping.Wrap };
        if (prefix.Length > 0) tb.Inlines.Add(new Run(prefix));
        var h = new Hyperlink(new Run(r.Title)) { Foreground = Blue, FontWeight = FontWeights.SemiBold, ToolTip = r.Url };
        h.Click += (_, _) => OpenUrl(r.Url);
        tb.Inlines.Add(h);
        return tb;
    }

    private static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show("Não foi possível abrir o link:\n" + url + "\n\n" + ex.Message, "Netskope Log Analyzer"); }
    }

    // ---------------------------------------------------------------- tabelas

    private void RenderUnclassified()
    {
        GridUnclassified.ItemsSource = _result!.Unclassified.Take(200).Select(u => new UnclassifiedRow
        {
            Message = u.Key, LevelText = u.Level == LogLevel.Warn ? "alerta" : "erro", Count = u.Count,
            Files = string.Join(", ", u.Files), Last = Report.Time(u.Last),
        }).ToList();
    }

    private void SearchUnclassified_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not UnclassifiedRow row) return;
        var q = System.Text.RegularExpressions.Regex.Replace(row.Message, @"^\S+\.(cpp|h)\s+", "");
        q = System.Text.RegularExpressions.Regex.Replace(q.Replace("<ip>", " ").Replace("<id>", " ").Replace("#", " "), @"\s+", " ").Trim();
        if (q.Length > 90) q = q[..90];
        var menu = new ContextMenu();
        foreach (var l in KnowledgeBase.SearchLinks(q))
        {
            var mi = new MenuItem { Header = l.Title };
            var url = l.Url;
            mi.Click += (_, _) => OpenUrl(url);
            menu.Items.Add(mi);
        }
        menu.PlacementTarget = (UIElement)sender;
        menu.IsOpen = true;
    }

    private void RenderFiles()
    {
        static string FmtSize(long b) => b > 1048576 ? (b / 1048576.0).ToString("0.0", CultureInfo.GetCultureInfo("pt-BR")) + " MB" : Math.Ceiling(b / 1024.0) + " KB";
        GridFiles.ItemsSource = _result!.Files.OrderByDescending(f => f.Lines).Select(f => new FileRow
        {
            Name = f.Name, Size = FmtSize(f.Size), Lines = f.Lines, Errors = f.Errors, Warnings = f.Warnings,
            Period = f.Lines > 0 ? Report.Time(f.First) + " → " + Report.Time(f.Last) : "configuração / texto",
        }).ToList();
        TxtSkipped.Text = _result.Skipped.Count > 0 ? "Não analisados (binários ou sensíveis): " + string.Join(", ", _result.Skipped) : "";
    }

    // ---------------------------------------------------------------- explorador

    private void InitExplorer()
    {
        XFile.Items.Clear();
        XFile.Items.Add(new ComboBoxItem { Content = "Todos os arquivos", Tag = -1 });
        for (var i = 0; i < _result!.Files.Count; i++)
            if (_result.Files[i].Lines > 0) XFile.Items.Add(new ComboBoxItem { Content = _result.Files[i].BaseName, Tag = i });
        XFile.SelectedIndex = 0;
        XLevel.SelectedIndex = 0;
        XSearch.Text = "";
        RunExplorer();
    }

    private void XSearch_TextChanged(object sender, TextChangedEventArgs e)
    {
        XSearchHint.Visibility = XSearch.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        _searchTimer.Stop(); _searchTimer.Start();
    }

    private void XFilter_Changed(object sender, SelectionChangedEventArgs e) { if (IsLoaded) RunExplorer(); }

    private void RunExplorer()
    {
        if (_result is null) return;
        var q = XSearch.Text.Trim();
        var lvl = XLevel.SelectedIndex;
        var file = (XFile.SelectedItem as ComboBoxItem)?.Tag is int t ? t : -1;
        var rows = new List<ExplorerRow>();
        var total = 0;
        foreach (var e in _result.Entries)
        {
            if (file >= 0 && e.FileIndex != file) continue;
            if (lvl == 0 && e.Level is LogLevel.Info or LogLevel.Debug) continue;
            if (lvl == 1 && e.Level is not (LogLevel.Error or LogLevel.Critical)) continue;
            if (q.Length > 0 && e.Line.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0) continue;
            total++;
            if (rows.Count < 5000)
            {
                var brush = e.Level switch { LogLevel.Error or LogLevel.Critical => Red, LogLevel.Warn => AmberText, LogLevel.Debug => Mute, _ => Ink };
                var line = e.Line.Length > 600 ? e.Line[..600] + "…" : e.Line;
                rows.Add(new ExplorerRow { Text = _result.Files[e.FileIndex].BaseName + " │ " + line, Brush = brush });
            }
        }
        XList.ItemsSource = rows;
        XInfo.Text = $"{total:N0} linha(s) encontrada(s)" + (total > 5000 ? " — mostrando as primeiras 5.000; refine a busca." : "");
    }

    // ---------------------------------------------------------------- relatório

    private bool TryCopy(string text)
    {
        for (var i = 0; i < 3; i++)
        {
            try { Clipboard.SetText(text); return true; }
            catch (System.Runtime.InteropServices.COMException) { Thread.Sleep(80); }
        }
        ShowToast("Não foi possível acessar a área de transferência.");
        return false;
    }

    private void CopyReport_Click(object sender, RoutedEventArgs e)
    {
        if (_result != null && TryCopy(Report.ToMarkdown(_result))) ShowToast("Relatório copiado — cole no chamado.");
    }

    private void SaveReport_Click(object sender, RoutedEventArgs e)
    {
        if (_result is null) return;
        var name = "netskope-analise" + (_result.Facts.Host != null ? "-" + _result.Facts.Host : "") + "-" + DateTime.Now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + ".md";
        var dlg = new SaveFileDialog { Title = "Salvar relatório", FileName = name, Filter = "Markdown (*.md)|*.md|Texto (*.txt)|*.txt" };
        if (dlg.ShowDialog(this) != true) return;
        System.IO.File.WriteAllText(dlg.FileName, Report.ToMarkdown(_result), new System.Text.UTF8Encoding(true));
        ShowToast("Relatório salvo.");
    }

    private void ShowToast(string text)
    {
        ToastText.Text = text;
        Toast.Visibility = Visibility.Visible;
        _toastTimer.Stop(); _toastTimer.Start();
    }
}
