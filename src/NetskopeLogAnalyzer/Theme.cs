using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace NetskopeLogAnalyzer;

/// <summary>
/// Temas claro e escuro com a paleta oficial da Netskope (Brand Guidelines):
/// Netskope Blue #00A9CE, Light Blue #9ADBE8, Dark Blue #00587C, Orange #FF8200, Light Orange #FFA400,
/// Medium Orange #FF6720, Teal #64CCC9, Medium Teal #00BC95, Dark Teal #003B49, Gray #53565A,
/// Medium Gray #97999B, Light Gray #C8C9C7.
/// Os recursos do App (DynamicResource) e os pincéis usados no código vêm daqui.
/// </summary>
public static class Theme
{
    public const string System = "Sistema", Light = "Claro", Dark = "Escuro";

    public static bool IsDark { get; private set; }

    public static Brush Background { get; private set; } = Brushes.White;
    public static Brush Surface { get; private set; } = Brushes.White;
    public static Brush Soft { get; private set; } = Brushes.WhiteSmoke;
    public static Brush Line { get; private set; } = Brushes.LightGray;
    public static Brush Ink { get; private set; } = Brushes.Black;
    public static Brush Mute { get; private set; } = Brushes.Gray;
    public static Brush Night { get; private set; } = Brushes.Black;
    public static Brush NightMute { get; private set; } = Brushes.LightGray;
    public static Brush Accent { get; private set; } = Brushes.Teal;
    public static Brush OnAccent { get; private set; } = Brushes.White;
    public static Brush Red { get; private set; } = Brushes.Red;
    public static Brush Amber { get; private set; } = Brushes.Orange;
    public static Brush AmberText { get; private set; } = Brushes.DarkOrange;
    public static Brush Green { get; private set; } = Brushes.Green;
    public static Brush Blue { get; private set; } = Brushes.Blue;
    public static Brush Gray { get; private set; } = Brushes.Gray;
    public static Brush RedBg { get; private set; } = Brushes.MistyRose;
    public static Brush AmberBg { get; private set; } = Brushes.LightYellow;
    public static Brush BlueBg { get; private set; } = Brushes.AliceBlue;
    public static Brush GreenBg { get; private set; } = Brushes.Honeydew;
    public static Brush BandCrit { get; private set; } = Brushes.Transparent;
    public static Brush BandWarn { get; private set; } = Brushes.Transparent;
    public static Brush ChartGrid { get; private set; } = Brushes.LightGray;
    public static Brush ChartCursor { get; private set; } = Brushes.Gray;
    public static Brush[] Palette { get; private set; } = Array.Empty<Brush>();

    public static event Action? Changed;

    private static SolidColorBrush B(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    /// <summary>true quando o Windows está em modo escuro para aplicativos.</summary>
    public static bool SystemPrefersDark()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception) { return false; }
    }

    public static void Apply(string mode)
    {
        var dark = mode == Dark || (mode != Light && SystemPrefersDark());
        IsDark = dark;
        if (dark)
        {
            Background = B("#071B21"); Surface = B("#0C252D"); Soft = B("#12313B"); Line = B("#21495A");
            Ink = B("#E9F6F9"); Mute = B("#97A9AE"); Night = B("#00141A"); NightMute = B("#9ADBE8");
            Accent = B("#00A9CE"); OnAccent = B("#00222B");
            Red = B("#FF6B5E"); Amber = B("#FFA400"); AmberText = B("#FFC35C"); Green = B("#2CD3AE"); Blue = B("#38C6E6"); Gray = B("#97999B");
            RedBg = B("#3B1D1C"); AmberBg = B("#36290F"); BlueBg = B("#0B3644"); GreenBg = B("#0C3A31");
            BandCrit = B("#40FF6B5E"); BandWarn = B("#38FFA400"); ChartGrid = B("#21495A"); ChartCursor = B("#80E9F6F9");
            Palette = new Brush[] { B("#00A9CE"), B("#FF8200"), B("#00BC95"), B("#FFA400"), B("#9ADBE8"), B("#FF6720"), B("#64CCC9"), B("#C8C9C7") };
        }
        else
        {
            Background = B("#FFFFFF"); Surface = B("#FFFFFF"); Soft = B("#F1F6F7"); Line = B("#DCE5E8");
            Ink = B("#0F2329"); Mute = B("#53565A"); Night = B("#003B49"); NightMute = B("#9ADBE8");
            Accent = B("#00587C"); OnAccent = B("#FFFFFF");
            Red = B("#D92D20"); Amber = B("#FFA400"); AmberText = B("#8A4F00"); Green = B("#008F72"); Blue = B("#00799A"); Gray = B("#97999B");
            RedBg = B("#FDECEA"); AmberBg = B("#FFF4DE"); BlueBg = B("#E1F5F9"); GreenBg = B("#E0F5EF");
            BandCrit = B("#30D92D20"); BandWarn = B("#30FFA400"); ChartGrid = B("#DCE5E8"); ChartCursor = B("#800F2329");
            Palette = new Brush[] { B("#00A9CE"), B("#FF8200"), B("#00BC95"), B("#00587C"), B("#FF6720"), B("#64CCC9"), B("#53565A"), B("#FFA400") };
        }
        var res = Application.Current?.Resources;
        if (res != null)
        {
            res["Background"] = Background; res["Surface"] = Surface; res["Soft"] = Soft; res["Line"] = Line;
            res["Ink"] = Ink; res["Mute"] = Mute; res["Night"] = Night; res["NightMute"] = NightMute;
            res["Accent"] = Accent; res["OnAccent"] = OnAccent;
            res["Red"] = Red; res["Amber"] = Amber; res["AmberText"] = AmberText; res["Green"] = Green; res["Blue"] = Blue;
            res["BlueBg"] = BlueBg; res["AmberBg"] = AmberBg;
            // controles padrão do WPF (TextBox, ComboBox, ListBox, CheckBox) seguem o tema
            res[SystemColors.WindowBrushKey] = Surface; res[SystemColors.WindowTextBrushKey] = Ink;
            res[SystemColors.ControlBrushKey] = Soft; res[SystemColors.ControlTextBrushKey] = Ink;
            res[SystemColors.HighlightBrushKey] = Accent; res[SystemColors.HighlightTextBrushKey] = OnAccent;
            res[SystemColors.InactiveSelectionHighlightBrushKey] = Soft; res[SystemColors.InactiveSelectionHighlightTextBrushKey] = Ink;
            res[SystemColors.MenuBrushKey] = Surface; res[SystemColors.MenuTextBrushKey] = Ink;
            res[SystemColors.GrayTextBrushKey] = Mute;
        }
        Changed?.Invoke();
    }
}
