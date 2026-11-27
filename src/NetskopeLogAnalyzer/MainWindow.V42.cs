using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using NetskopeLogAnalyzer.Core;
using NetskopeLogAnalyzer.Services;

namespace NetskopeLogAnalyzer;

/// <summary>4.2 — histórico da máquina, configurações reorganizadas, novidades da versão sem navegador.</summary>
public partial class MainWindow
{
    // ================================================================= Resumo: histórico desta máquina

    private UIElement? HistoryBlock()
    {
        var h = _result?.History;
        if (h is null) return null;
        var sp = new StackPanel();
        sp.Children.Add(T($"Comparado com o pacote anterior desta máquina", 17, FontWeights.Bold));
        sp.Children.Add(T($"Logs até {Report.Time(h.Previous.End)} · v{h.Previous.Version ?? "?"} · analisado em {h.Previous.AnalyzedAt:dd/MM/yyyy HH:mm} · {h.Previous.Verdict}", 12.5, fg: Mute, margin: new Thickness(0, 2, 0, 8)));
        foreach (var c in h.Changes) sp.Children.Add(T("• " + c, 13.5));
        void Group(string title, List<string> items, Brush fg)
        {
            if (items.Count == 0) return;
            sp.Children.Add(T($"{title} ({items.Count})", 14, FontWeights.SemiBold, fg, new Thickness(0, 8, 0, 2)));
            foreach (var i in items.Take(8)) sp.Children.Add(T("• " + i, 13.5));
            if (items.Count > 8) sp.Children.Add(T($"… e mais {items.Count - 8}", 12.5, fg: Mute));
        }
        Group("Novos neste pacote", h.New, Red);
        Group("Não aparecem mais", h.Resolved, Green);
        Group("Continuam", h.Persistent, AmberText);
        if (h.Machine.Count > 1)
        {
            sp.Children.Add(T($"Análises desta máquina ({h.Machine.Count})", 14, FontWeights.SemiBold, margin: new Thickness(0, 10, 0, 2)));
            foreach (var e in h.Machine.Take(6))
                sp.Children.Add(T($"• logs até {Report.Time(e.End)} · v{e.Version ?? "?"} · {e.Critical} crítico(s), {e.Warning} atenção · {e.Packages}", 12.5, fg: Mute));
        }
        return Card(sp, new Thickness(0, 14, 0, 4));
    }

    // ================================================================= novidades (embutidas no app, sem navegador)

    private static string EmbeddedNotes()
    {
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("RELEASE_NOTES.md");
            if (s is null) return "";
            using var r = new StreamReader(s);
            return r.ReadToEnd();
        }
        catch (Exception) { return ""; }
    }

    /// <summary>Mostra notas de versão (Markdown simples) numa janela do próprio app.</summary>
    private void ShowNotes(string title, string markdown)
    {
        var w = new Window { Title = title, Owner = this, Width = 720, Height = 620, WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Theme.Background, Foreground = Theme.Ink, FontFamily = FontFamily, FontSize = 14 };
        var sp = new StackPanel { Margin = new Thickness(22) };
        sp.Children.Add(T(title, 22, FontWeights.Bold, margin: new Thickness(0, 0, 0, 10)));
        foreach (var raw in markdown.Replace("\r", "").Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.Length == 0) { sp.Children.Add(new Border { Height = 6 }); continue; }
            var indent = line.Length - line.TrimStart().Length;
            var t = line.Trim();
            var bullet = t.StartsWith("- ", StringComparison.Ordinal) || t.StartsWith("* ", StringComparison.Ordinal);
            if (bullet) t = t[2..];
            var heading = t.StartsWith('#');
            t = t.TrimStart('#', ' ');
            var tb = new TextBlock { TextWrapping = TextWrapping.Wrap, Foreground = Theme.Ink, FontSize = heading ? 17 : 14, Margin = new Thickness(bullet ? 14 + indent * 6 : 0, heading ? 10 : 2, 0, 2) };
            if (bullet) tb.Inlines.Add(new Run("• ") { Foreground = Theme.Mute });
            // **negrito** e `código`
            var parts = System.Text.RegularExpressions.Regex.Split(t, @"(\*\*[^*]+\*\*|`[^`]+`)");
            foreach (var p in parts)
            {
                if (p.StartsWith("**", StringComparison.Ordinal) && p.EndsWith("**", StringComparison.Ordinal) && p.Length > 4) tb.Inlines.Add(new Run(p[2..^2]) { FontWeight = FontWeights.Bold });
                else if (p.StartsWith('`') && p.EndsWith('`') && p.Length > 2) tb.Inlines.Add(new Run(p[1..^1]) { FontFamily = new FontFamily("Consolas") });
                else tb.Inlines.Add(new Run(System.Text.RegularExpressions.Regex.Replace(p, @"\[([^\]]+)\]\([^)]+\)", "$1")));
            }
            if (heading) tb.FontWeight = FontWeights.Bold;
            sp.Children.Add(tb);
        }
        var close = new Button { Content = "Fechar", Style = (Style)FindResource("PillDark"), HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        close.Click += (_, _) => w.Close();
        sp.Children.Add(close);
        w.Content = new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        w.ShowDialog();
    }

    /// <summary>Depois de uma atualização, mostra uma vez o que mudou.</summary>
    private void InitV42()
    {
        Loaded += (_, _) =>
        {
            var cur = UpdateService.Current.ToString(3);
            if (_settings.LastSeenVersion == cur) return;
            var first = _settings.LastSeenVersion is null;
            _settings.LastSeenVersion = cur; _settings.Save();
            if (first) return; // primeira instalação: nada para comparar
            Dispatcher.BeginInvoke(() =>
            {
                ShowToast($"Atualizado para a versão {cur}.");
                var notes = EmbeddedNotes();
                if (notes.Length > 0) ShowNotes($"Novidades da versão {cur}", notes);
            });
        };
    }

    // ================================================================= Configurações

    private static TextBlock Section(string text) => T(text, 16, FontWeights.Bold, margin: new Thickness(0, 18, 0, 4));
    private static TextBlock Hint(string text) => T(text, 12.5, fg: Mute, margin: new Thickness(0, 3, 0, 0));

    private void OpenSettings()
    {
        var w = new Window { Title = "Configurações", Owner = this, Width = 640, SizeToContent = SizeToContent.Height, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, Background = Theme.Background, Foreground = Theme.Ink, FontFamily = FontFamily, FontSize = 14 };
        var sp = new StackPanel { Margin = new Thickness(24, 20, 24, 20) };
        sp.Children.Add(T("Configurações", 22, FontWeights.Bold));
        sp.Children.Add(Hint("Tudo fica neste computador. O app só lê os pacotes que você abrir; a única conexão externa é a verificação de atualização no GitHub."));

        // ---------- aparência
        sp.Children.Add(Section("Aparência"));
        var themeChoice = _settings.Theme;
        var themes = new WrapPanel();
        foreach (var opt in new[] { Theme.System, Theme.Light, Theme.Dark })
        {
            var rb = new RadioButton { Content = opt == Theme.System ? "Igual ao Windows" : opt, GroupName = "theme", IsChecked = _settings.Theme == opt, Margin = new Thickness(0, 4, 18, 0), Foreground = Theme.Ink };
            rb.Checked += (_, _) => themeChoice = opt;
            themes.Children.Add(rb);
        }
        sp.Children.Add(themes);

        // ---------- análise
        sp.Children.Add(Section("Análise"));
        sp.Children.Add(T("Considerar como histórico o que só aconteceu mais de", 14));
        var recency = new ComboBox { Width = 200, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 4, 0, 0) };
        var opts = new[] { (12, "12 horas"), (24, "24 horas (padrão)"), (72, "3 dias"), (168, "7 dias") };
        foreach (var (h, label) in opts) recency.Items.Add(new ComboBoxItem { Content = label, Tag = h, IsSelected = h == _settings.RecencyHours });
        if (recency.SelectedIndex < 0) recency.SelectedIndex = 1;
        sp.Children.Add(recency);
        sp.Children.Add(Hint("…antes da coleta (ou do horário informado no relato). O pacote traz semanas de log; o que é mais antigo aparece com a etiqueta “histórico” e não entra no resultado."));

        // ---------- histórico
        sp.Children.Add(Section("Histórico das análises"));
        var keep = new CheckBox { Content = "Guardar um resumo de cada análise para comparar pacotes da mesma máquina", IsChecked = _settings.KeepHistory, Margin = new Thickness(0, 4, 0, 0) };
        sp.Children.Add(keep);
        var store = new HistoryStore(HistoryStore.DefaultPath);
        var count = store.Load().Count;
        var histInfo = Hint($"{count} análise(s) guardada(s). Guarda só o resumo (máquina, usuário, versão, problemas), nunca as linhas de log.");
        sp.Children.Add(histInfo);
        var histBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
        var clear = new Button { Content = "Apagar histórico", Style = (Style)FindResource("Small"), IsEnabled = count > 0 };
        clear.Click += (_, _) =>
        {
            if (MessageBox.Show(w, "Apagar o resumo de todas as análises guardadas?", "Netskope Log Analyzer", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
            store.Clear(); histInfo.Text = "Histórico apagado."; clear.IsEnabled = false;
        };
        var folder = new Button { Content = "Abrir pasta de dados", Style = (Style)FindResource("Small"), Margin = new Thickness(8, 0, 0, 0) };
        folder.Click += (_, _) => Try(() => { Directory.CreateDirectory(AppSettings.DataDir); Process.Start(new ProcessStartInfo("explorer.exe", $"\"{AppSettings.DataDir}\"") { UseShellExecute = true }); });
        histBar.Children.Add(clear); histBar.Children.Add(folder);
        sp.Children.Add(histBar);

        // ---------- atualizações
        sp.Children.Add(Section("Atualizações"));
        var policy = AppSettings.UpdatesDisabledByPolicy;
        var autoCheck = new CheckBox { Content = "Verificar automaticamente ao abrir (no máximo a cada 12 horas)", IsChecked = _settings.AutoCheckUpdates, Margin = new Thickness(0, 4, 0, 0), IsEnabled = !policy };
        var autoInstall = new CheckBox { Content = "Instalar sozinho quando houver versão nova", IsChecked = _settings.AutoInstallUpdates, Margin = new Thickness(0, 4, 0, 0), IsEnabled = !policy && UpdateService.IsInstalled };
        sp.Children.Add(autoCheck); sp.Children.Add(autoInstall);
        if (policy) sp.Children.Add(T("Atualizações desativadas pela política do TI (DisableUpdates).", 12.5, fg: AmberText, margin: new Thickness(0, 4, 0, 0)));
        else if (!UpdateService.IsInstalled) sp.Children.Add(Hint("Versão portátil: a atualização abre a página da versão nova para baixar; a instalação automática só existe na versão instalada."));
        sp.Children.Add(Hint("Toda atualização confere o SHA-256 do instalador com o SHA256SUMS.txt da versão antes de executar; o Windows pede confirmação quando o app está instalado para todos os usuários."));

        var status = new Border { Background = Theme.Soft, CornerRadius = new CornerRadius(10), Padding = new Thickness(12, 10, 12, 10), Margin = new Thickness(0, 10, 0, 0) };
        var statusSp = new StackPanel();
        var statusText = T($"Versão instalada: {UpdateService.Current.ToString(3)}" + (_settings.LastUpdateCheck is DateTime lc ? $" · última verificação: {lc:dd/MM/yyyy HH:mm}" : " · ainda não verificada"), 13.5);
        statusSp.Children.Add(statusText);
        var statusBar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
        var check = new Button { Content = "Verificar agora", Style = (Style)FindResource("Small"), IsEnabled = !policy };
        var install = new Button { Content = "Atualizar agora", Style = (Style)FindResource("Small"), Margin = new Thickness(8, 0, 0, 0), Visibility = Visibility.Collapsed };
        var whatsNew = new Button { Content = "Novidades desta versão", Style = (Style)FindResource("Small"), Margin = new Thickness(8, 0, 0, 0) };
        check.Click += async (_, _) =>
        {
            check.IsEnabled = false; statusText.Text = "Verificando…";
            var found = await CheckUpdatesAsync(true);
            check.IsEnabled = true;
            if (found && _update != null)
            {
                statusText.Text = $"Versão {_update.Version.ToString(3)} disponível (você está na {UpdateService.Current.ToString(3)}).";
                install.Content = UpdateService.IsInstalled ? "Atualizar agora" : "Baixar";
                install.Visibility = Visibility.Visible;
                whatsNew.Content = $"Novidades da {_update.Version.ToString(3)}";
            }
            else statusText.Text = $"Você está na versão mais recente ({UpdateService.Current.ToString(3)}). Verificado agora.";
        };
        install.Click += (_, _) => { w.Close(); UpdateNow_Click(this, new RoutedEventArgs()); };
        whatsNew.Click += (_, _) =>
        {
            if (_update != null) ShowNotes($"Novidades da versão {_update.Version.ToString(3)}", _update.Notes);
            else ShowNotes($"Novidades da versão {UpdateService.Current.ToString(3)}", EmbeddedNotes());
        };
        statusBar.Children.Add(check); statusBar.Children.Add(install); statusBar.Children.Add(whatsNew);
        statusSp.Children.Add(statusBar);
        status.Child = statusSp;
        sp.Children.Add(status);

        // ---------- rodapé
        var bar = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 20, 0, 0) };
        var cancel = new Button { Content = "Cancelar", Style = (Style)FindResource("Pill"), Margin = new Thickness(0, 0, 8, 0) };
        cancel.Click += (_, _) => w.Close();
        var save = new Button { Content = "Salvar", Style = (Style)FindResource("PillDark") };
        save.Click += (_, _) =>
        {
            _settings.AutoCheckUpdates = autoCheck.IsChecked == true;
            _settings.AutoInstallUpdates = autoInstall.IsChecked == true;
            _settings.KeepHistory = keep.IsChecked == true;
            var newRecency = recency.SelectedItem is ComboBoxItem { Tag: int hh } ? hh : 24;
            var recencyChanged = newRecency != _settings.RecencyHours;
            _settings.RecencyHours = newRecency;
            var themeChanged = _settings.Theme != themeChoice;
            _settings.Theme = themeChoice;
            _settings.Save();
            w.Close();
            if (themeChanged) Theme.Apply(themeChoice);
            if (recencyChanged && _result != null)
            {
                var o = _result.Options;
                o.RecencyHours = newRecency;
                FocusAnalyzer.Run(_result, o);
                RenderAll();
            }
            ShowToast("Configurações salvas.");
        };
        bar.Children.Add(cancel); bar.Children.Add(save);
        sp.Children.Add(bar);
        w.Content = new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = SystemParameters.WorkArea.Height * 0.9 };
        w.ShowDialog();
    }
}
