using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using NetskopeLogAnalyzer.Core;
using NetskopeLogAnalyzer.Services;

namespace NetskopeLogAnalyzer;

/// <summary>v4 — análise direcionada pelo relato do usuário, tema escuro e baseline de recursos.</summary>
public partial class MainWindow
{
    private readonly List<ToggleButton> _startChips = new();

    private void InitV4()
    {
        foreach (var s in FocusAnalyzer.All)
        {
            var chip = new ToggleButton { Content = s.Label, Tag = s.Id, ToolTip = s.Hint, Style = (Style)FindResource("Chip") };
            System.Windows.Automation.AutomationProperties.SetName(chip, "Sintoma: " + s.Label);
            _startChips.Add(chip);
            SymptomChips.Children.Add(chip);
        }
        UpdateThemeButton();
        Theme.Changed += () =>
        {
            UpdateThemeButton();
            if (_result != null && Tabs.Visibility == Visibility.Visible)
            {
                var tab = Tabs.SelectedIndex;
                RenderAll();
                Tabs.SelectedIndex = tab;
            }
            BuildLegends();
        };
    }

    private void UpdateThemeButton()
    {
        BtnTheme.Content = Theme.IsDark ? "☀" : "☾";
        BtnTheme.ToolTip = Theme.IsDark ? "Usar tema claro" : "Usar tema escuro";
    }

    private void Theme_Click(object sender, RoutedEventArgs e)
    {
        _settings.Theme = Theme.IsDark ? Theme.Light : Theme.Dark;
        _settings.Save();
        Theme.Apply(_settings.Theme);
    }

    // ================================================================= opções informadas pelo analista

    private static readonly string[] TimeFormats =
    {
        "dd/MM/yyyy HH:mm", "dd/MM/yyyy HH:mm:ss", "dd/MM/yy HH:mm", "dd/MM HH:mm", "dd/MM HH:mm:ss", "d/M HH:mm", "d/M/yyyy HH:mm", "HH:mm", "H:mm",
    };

    /// <summary>Interpreta o horário digitado; sem data, usa o dia do fim do log (ou hoje).</summary>
    internal static DateTime? ParseProblemTime(string? text, DateTime? reference)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var t = text.Trim();
        if (!DateTime.TryParseExact(t, TimeFormats, CultureInfo.GetCultureInfo("pt-BR"), DateTimeStyles.AllowWhiteSpaces, out var d)) return null;
        var refDay = reference ?? DateTime.Now;
        if (!t.Contains('/')) d = refDay.Date + d.TimeOfDay;
        else if (!System.Text.RegularExpressions.Regex.IsMatch(t, @"\d{1,2}/\d{1,2}/\d{2,4}")) d = new DateTime(refDay.Year, d.Month, d.Day, d.Hour, d.Minute, d.Second);
        return d;
    }

    /// <summary>Pré-preenche o relato (argumentos --sintomas=, --site=, --horario=).</summary>
    public void PresetFocus(IEnumerable<string> symptoms, string? site, string? time)
    {
        var set = new HashSet<string>(symptoms.Select(x => x.Trim().ToLowerInvariant()));
        foreach (var c in _startChips) c.IsChecked = set.Contains((string)c.Tag);
        if (!string.IsNullOrWhiteSpace(site)) InDomain.Text = site.Trim();
        if (!string.IsNullOrWhiteSpace(time)) InTime.Text = time.Trim();
    }

    private AnalysisOptions BuildOptions()
    {
        var o = new AnalysisOptions();
        foreach (var c in _startChips.Where(c => c.IsChecked == true)) o.Symptoms.Add((string)c.Tag);
        var dom = InDomain.Text.Trim();
        if (dom.Length > 0) o.Domain = FocusAnalyzer.NormalizeDomain(dom);
        o.ProblemTime = ParseProblemTime(InTime.Text, null);
        return o;
    }

    // ================================================================= Resumo: foco da análise

    private UIElement FocusBlock()
    {
        var r = _result!;
        var box = new StackPanel { Margin = new Thickness(0, 6, 0, 10) };
        var card = new Border { Background = Theme.Soft, CornerRadius = new CornerRadius(14), Padding = new Thickness(18, 14, 18, 14), BorderBrush = Theme.Accent, BorderThickness = new Thickness(r.Focus.Count > 0 ? 2 : 0) };
        var sp = new StackPanel();
        card.Child = sp;
        box.Children.Add(card);
        sp.Children.Add(T("Foco da análise — o que o usuário relatou", 18, FontWeights.Bold));
        sp.Children.Add(T("Marque os sintomas, o site e o horário: o app roda as verificações de cada sintoma sobre este pacote e destaca os itens relacionados nas outras abas.", 13, fg: Mute, margin: new Thickness(0, 2, 0, 10)));

        var chips = new WrapPanel();
        var local = new List<ToggleButton>();
        foreach (var s in FocusAnalyzer.All)
        {
            var c = new ToggleButton { Content = s.Label, Tag = s.Id, ToolTip = s.Hint, Style = (Style)FindResource("Chip"), IsChecked = r.Options.Symptoms.Contains(s.Id) };
            System.Windows.Automation.AutomationProperties.SetName(c, "Sintoma: " + s.Label);
            local.Add(c); chips.Children.Add(c);
        }
        sp.Children.Add(chips);
        var row = new Grid { Margin = new Thickness(0, 4, 0, 0) };
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.4, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) });
        row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        var dom = new TextBox { Text = r.Options.Domain ?? "", Padding = new Thickness(8, 6, 8, 6), MaxLength = 300, ToolTip = "Site ou aplicação afetada (ex.: teams.microsoft.com)" };
        var tim = new TextBox { Text = r.Options.ProblemTime is DateTime pt ? pt.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture) : "", Padding = new Thickness(8, 6, 8, 6), MaxLength = 40, ToolTip = "Horário do problema na máquina do usuário (ex.: 23/11 12:44)" };
        var l1 = new StackPanel(); l1.Children.Add(T("Site ou aplicação afetada", 12.5, FontWeights.SemiBold, margin: new Thickness(0, 0, 0, 3))); l1.Children.Add(dom);
        var l2 = new StackPanel(); l2.Children.Add(T("Horário aproximado", 12.5, FontWeights.SemiBold, margin: new Thickness(0, 0, 0, 3))); l2.Children.Add(tim);
        Grid.SetColumn(l2, 2);
        var apply = new Button { Content = "Aplicar foco", Style = (Style)FindResource("PillDark"), VerticalAlignment = VerticalAlignment.Bottom };
        Grid.SetColumn(apply, 4);
        row.Children.Add(l1); row.Children.Add(l2); row.Children.Add(apply);
        sp.Children.Add(row);
        var err = T("", 12.5, fg: Red, margin: new Thickness(0, 4, 0, 0));
        sp.Children.Add(err);
        apply.Click += (_, _) =>
        {
            var o = new AnalysisOptions();
            foreach (var c in local.Where(c => c.IsChecked == true)) o.Symptoms.Add((string)c.Tag);
            if (dom.Text.Trim().Length > 0) o.Domain = FocusAnalyzer.NormalizeDomain(dom.Text);
            if (tim.Text.Trim().Length > 0)
            {
                o.ProblemTime = ParseProblemTime(tim.Text, r.End);
                if (o.ProblemTime is null) { err.Text = "Horário não reconhecido. Use, por exemplo, 23/11 12:44."; return; }
            }
            foreach (var i in r.Incidents) i.InFocusWindow = false;
            FocusAnalyzer.Run(r, o);
            foreach (var c in _startChips) c.IsChecked = o.Symptoms.Contains((string)c.Tag);
            InDomain.Text = o.Domain ?? ""; InTime.Text = tim.Text;
            RenderAll();
            ShowToast(r.Focus.Count > 0 ? "Foco aplicado." : "Foco removido.");
        };

        if (r.Domain is DomainReport d && r.Focus.Count == 0) box.Children.Add(DomainCard(d));
        foreach (var f in r.Focus) box.Children.Add(FocusCard(f));
        return box;
    }

    private static (Brush Fg, Brush Bg, string Icon) CheckLook(string status) => status switch
    {
        "problema" => (Theme.Red, Theme.RedBg, "✖"),
        "atenção" => (Theme.AmberText, Theme.AmberBg, "▲"),
        "ok" => (Theme.Green, Theme.GreenBg, "✔"),
        _ => (Theme.Mute, Theme.Soft, "–"),
    };

    private UIElement FocusCard(FocusResult f)
    {
        var verdictLook = f.Verdict.StartsWith("Problema", StringComparison.Ordinal) ? CheckLook("problema") : f.Verdict.StartsWith("Possível", StringComparison.Ordinal) ? CheckLook("atenção") : CheckLook("ok");
        var sp = new StackPanel();
        var head = new WrapPanel();
        head.Children.Add(T(f.Symptom.Label, 17, FontWeights.Bold, wrap: false, margin: new Thickness(0, 0, 10, 0)));
        head.Children.Add(Pill(f.Verdict, verdictLook.Fg, verdictLook.Bg));
        sp.Children.Add(head);
        sp.Children.Add(T(f.Summary, 13.5, fg: Mute, margin: new Thickness(0, 4, 0, 8)));
        foreach (var c in f.Checks)
        {
            var (fg, bg, icon) = CheckLook(c.Status);
            var g = new Grid { Margin = new Thickness(0, 3, 0, 3) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(28) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var ic = new Border { Background = bg, CornerRadius = new CornerRadius(10), Width = 20, Height = 20, VerticalAlignment = VerticalAlignment.Top, Child = new TextBlock { Text = icon, Foreground = fg, FontSize = 11, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }, ToolTip = c.Status };
            var tb = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Ink };
            tb.Inlines.Add(new System.Windows.Documents.Run(c.Name + ": ") { FontWeight = FontWeights.SemiBold });
            tb.Inlines.Add(new System.Windows.Documents.Run(SafeText.Printable(c.Detail)));
            Grid.SetColumn(tb, 1);
            g.Children.Add(ic); g.Children.Add(tb);
            sp.Children.Add(g);
        }
        if (f.NextSteps.Count > 0)
        {
            sp.Children.Add(H4("Próximos passos"));
            foreach (var n in f.NextSteps.Take(5)) sp.Children.Add(T("• " + n, 13.5, margin: new Thickness(0, 1, 0, 1)));
        }
        if (f.FindingKeys.Count > 0)
        {
            var b = new Button { Content = $"Ver os {f.FindingKeys.Count} item(ns) relacionados no Diagnóstico", Style = (Style)FindResource("Small"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 10, 0, 0) };
            b.Click += (_, _) => { _filter = "focus"; RenderFilters(); RenderFindings(); Tabs.SelectedItem = TabFindings; };
            sp.Children.Add(b);
        }
        return new Border { Background = Theme.Surface, BorderBrush = LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(16, 12, 16, 14), Margin = new Thickness(0, 10, 0, 0), Child = sp };
    }

    private UIElement DomainCard(DomainReport d)
    {
        var sp = new StackPanel();
        sp.Children.Add(T("Site " + d.Domain, 17, FontWeights.Bold));
        sp.Children.Add(T($"{d.Lines} linha(s) nos logs · {d.Tunneled} tunelada(s) · {d.Bypassed} em bypass · {d.DnsQueries} consulta(s) DNS · {d.Errors} erro(s)/aviso(s)" +
            (d.Exceptions.Count > 0 ? " · em exceção: " + string.Join("; ", d.Exceptions.Take(3)) : ""), 13.5, margin: new Thickness(0, 4, 0, 6)));
        foreach (var s in d.Samples.Take(8)) sp.Children.Add(T(SafeText.Printable(s), 12, fg: Mute, margin: new Thickness(0, 1, 0, 1)));
        return new Border { Background = Theme.Surface, BorderBrush = LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(16, 12, 16, 14), Margin = new Thickness(0, 10, 0, 0), Child = sp };
    }

    // ================================================================= Dispositivo: baseline de recursos

    private void DeviceResources()
    {
        var rows = _result!.Performance.Where(m => m.Group == TacInsights.ResourceGroup).ToList();
        if (rows.Count == 0) return;
        var idx = Math.Min(2, DevicePanel.Children.Count);
        var sp = new StackPanel();
        sp.Children.Add(H2("Baseline de recursos (foto do pacote)", new Thickness(0, 8, 0, 4)));
        sp.Children.Add(Sub("Calculado a partir da lista de processos e da memória registradas no pacote: CPU média desde o boot, quem consumiu mais CPU, memória em uso, discos, processos e navegadores. Compare com a referência ao lado."));
        sp.Children.Add(Table(new[] { "Recurso", "Valor", "Referência", "Situação", "O que indica" },
            rows.Select(m => new[] { m.Name, m.Value, m.Reference, m.Status, m.Meaning }), new double[] { 220, 300, 130, 85, 0 }));
        DevicePanel.Children.Insert(idx, sp);
    }
}
