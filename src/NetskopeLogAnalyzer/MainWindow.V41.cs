using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using NetskopeLogAnalyzer.Core;

namespace NetskopeLogAnalyzer;

/// <summary>4.1 — identificação do usuário e da máquina no Resumo.</summary>
public partial class MainWindow
{
    private UIElement IdentityBlock()
    {
        var r = _result!;
        var outer = new StackPanel { Margin = new Thickness(0, 4, 0, 8) };
        var head = new DockPanel { Margin = new Thickness(0, 14, 0, 4) };
        var copy = new Button { Content = "Copiar dados", Style = (Style)FindResource("Small"), VerticalAlignment = VerticalAlignment.Center };
        copy.Click += (_, _) =>
        {
            var text = string.Join(Environment.NewLine, r.Identity.Select(i => $"{i.Group} · {i.Label}: {i.Value.Replace("\n", "; ")}"));
            if (TryCopy(text)) ShowToast("Dados do usuário e da máquina copiados.");
        };
        DockPanel.SetDock(copy, Dock.Right);
        head.Children.Add(copy);
        head.Children.Add(T("Usuário e máquina", 20, FontWeights.Bold));
        outer.Children.Add(head);

        if (r.Identity.Count == 0)
        {
            outer.Children.Add(Sub("O pacote não traz dados de identificação do usuário nem da máquina."));
            return outer;
        }
        var email = r.Identity.FirstOrDefault(i => i.Label == "E-mail registrado no Netskope")?.Value;
        var login = r.Identity.FirstOrDefault(i => i.Label == "Login no sistema operacional")?.Value;
        var host = r.Identity.FirstOrDefault(i => i.Label == "Hostname")?.Value;
        var lead = string.Join("  ·  ", new[] { email, login is null ? null : "login " + login, host }.Where(s => !string.IsNullOrEmpty(s)));
        outer.Children.Add(T(lead.Length > 0 ? lead : "Usuário não identificado no pacote", 16, FontWeights.SemiBold, margin: new Thickness(0, 0, 0, 2)));
        outer.Children.Add(Sub("Tudo o que o pacote revela sobre quem é o usuário e qual é a máquina. Passe o mouse sobre um valor para ver de qual arquivo ele veio."));

        var grid = new UniformGrid { Columns = ActualWidth > 1100 ? 2 : 1 };
        foreach (var g in r.Identity.GroupBy(i => i.Group))
        {
            var table = new Grid();
            table.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(210) });
            table.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            var row = 0;
            foreach (var i in g)
            {
                table.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var l = T(i.Label, 13, fg: Mute, margin: new Thickness(0, 3, 12, 3));
                var v = T(i.Value, 13, FontWeights.SemiBold, margin: new Thickness(0, 3, 0, 3));
                v.ToolTip = "Fonte: " + i.Source;
                Grid.SetRow(l, row); Grid.SetRow(v, row); Grid.SetColumn(v, 1);
                table.Children.Add(l); table.Children.Add(v);
                row++;
            }
            var sp = new StackPanel();
            sp.Children.Add(T(g.Key, 15, FontWeights.Bold, margin: new Thickness(0, 0, 0, 6)));
            sp.Children.Add(table);
            grid.Children.Add(Card(sp, new Thickness(0, 0, 10, 10)));
        }
        outer.Children.Add(grid);
        return outer;
    }
}
