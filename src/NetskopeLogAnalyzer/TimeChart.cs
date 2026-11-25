using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using NetskopeLogAnalyzer.Core;

namespace NetskopeLogAnalyzer;

/// <summary>Gráfico temporal leve (desenhado direto no DrawingContext): linhas, limites, faixas de incidente e marcadores.</summary>
public sealed class TimeChart : FrameworkElement
{
    public sealed record Line(MetricSeries Series, Brush Brush, string? Label = null);

    public List<Line> Lines { get; } = new();
    public List<(DateTime Start, DateTime End, Brush Brush)> Bands { get; } = new();
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    public double? Warn { get; set; }
    public double? Crit { get; set; }
    public double? YMin { get; set; }
    public double? YMax { get; set; }
    public string Unit { get; set; } = "";

    // cores do tema atual (claro/escuro)
    private static Brush Axis => Theme.Mute;
    private static Pen GridPen => FreezePen(new Pen(Theme.ChartGrid, 1));
    private static Pen WarnPen => FreezePen(new Pen(Theme.Amber, 1) { DashStyle = DashStyles.Dash });
    private static Pen CritPen => FreezePen(new Pen(Theme.Red, 1) { DashStyle = DashStyles.Dash });
    private static Pen CursorPen => FreezePen(new Pen(Theme.ChartCursor, 1));
    private static readonly Typeface Face = new("Segoe UI");
    private double? _hoverX;
    private readonly ToolTip _tip = new() { Placement = System.Windows.Controls.Primitives.PlacementMode.Mouse };

    private static Brush Freeze(Brush b) { b.Freeze(); return b; }
    private static Pen FreezePen(Pen p) { p.Freeze(); return p; }

    public TimeChart()
    {
        Height = 180;
        ToolTip = _tip;
        ToolTipService.SetInitialShowDelay(this, 0);
        ToolTipService.SetShowDuration(this, 60000);
        MouseMove += OnMove;
        MouseLeave += (_, _) => { _hoverX = null; _tip.IsOpen = false; InvalidateVisual(); };
    }

    private const double L = 52, R = 10, T = 8, B = 22;

    private (DateTime From, DateTime To) Range()
    {
        var pts = Lines.SelectMany(l => l.Series.Points).ToList();
        var f = From ?? (pts.Count > 0 ? pts.Min(p => p.Time) : DateTime.Now.AddHours(-1));
        var t = To ?? (pts.Count > 0 ? pts.Max(p => p.Time) : DateTime.Now);
        if (t <= f) t = f.AddMinutes(1);
        return (f, t);
    }

    private (double Min, double Max) YRange()
    {
        var vals = Lines.SelectMany(l => l.Series.Points).Select(p => p.Value).ToList();
        double min = YMin ?? (vals.Count > 0 ? Math.Min(0, vals.Min()) : 0);
        double max = YMax ?? (vals.Count > 0 ? vals.Max() : 1);
        if (YMax is null)
        {
            if (Warn is double w && w > max && w < max * 3) max = w;
            max = max <= 0 ? 1 : max * 1.1;
            if (Unit == "%" && max > 90) max = 100;
        }
        if (max <= min) max = min + 1;
        return (min, max);
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        if (w < L + R + 20 || h < T + B + 20) return;
        var dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        var (from, to) = Range();
        var (ymin, ymax) = YRange();
        double pw = w - L - R, ph = h - T - B;
        double X(DateTime t) => L + pw * (t - from).TotalSeconds / (to - from).TotalSeconds;
        double Y(double v) => T + ph * (1 - (v - ymin) / (ymax - ymin));

        foreach (var (s, e, br) in Bands)
        {
            var x1 = Math.Max(L, X(s)); var x2 = Math.Min(L + pw, X(e));
            if (x2 > x1 - 2) dc.DrawRectangle(br, null, new Rect(x1, T, Math.Max(2, x2 - x1), ph));
        }
        for (var i = 0; i <= 3; i++)
        {
            var v = ymin + (ymax - ymin) * i / 3; var y = Y(v);
            dc.DrawLine(GridPen, new Point(L, y), new Point(L + pw, y));
            var ft = new FormattedText(Fmt(v) + (i == 3 ? " " + Unit : ""), CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Face, 10.5, Axis, dpi);
            dc.DrawText(ft, new Point(Math.Max(0, L - 6 - ft.Width), y - ft.Height / 2));
        }
        if (Warn is double wv && wv > ymin && wv < ymax) dc.DrawLine(WarnPen, new Point(L, Y(wv)), new Point(L + pw, Y(wv)));
        if (Crit is double cv && cv > ymin && cv < ymax) dc.DrawLine(CritPen, new Point(L, Y(cv)), new Point(L + pw, Y(cv)));

        var span = to - from;
        var ticks = Math.Max(2, Math.Min(7, (int)(pw / 110)));
        for (var i = 0; i <= ticks; i++)
        {
            var t = from + TimeSpan.FromTicks(span.Ticks * i / ticks);
            var label = span.TotalHours > 36 ? t.ToString("dd/MM HH'h'", CultureInfo.InvariantCulture) : t.ToString("HH:mm", CultureInfo.InvariantCulture);
            var ft = new FormattedText(label, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Face, 10.5, Axis, dpi);
            var x = X(t) - ft.Width / 2;
            dc.DrawText(ft, new Point(Math.Clamp(x, L - 4, w - ft.Width), T + ph + 5));
        }

        foreach (var line in Lines)
        {
            var pts = line.Series.Points;
            if (pts.Count == 0) continue;
            var pen = new Pen(line.Brush, 1.6) { LineJoin = PenLineJoin.Round };
            pen.Freeze();
            var gapLimit = TypicalGap(pts) * 4;
            var g = new StreamGeometry();
            using (var c = g.Open())
            {
                var open = false; DateTime prev = default;
                foreach (var p in pts)
                {
                    if (p.Time < from || p.Time > to) { open = false; continue; }
                    var pt = new Point(X(p.Time), Y(Math.Clamp(p.Value, ymin, ymax)));
                    if (!open || (p.Time - prev) > gapLimit) { c.BeginFigure(pt, false, false); open = true; }
                    else c.LineTo(pt, true, false);
                    prev = p.Time;
                }
            }
            g.Freeze();
            dc.DrawGeometry(null, pen, g);
            if (pts.Count <= 3)
                foreach (var p in pts) dc.DrawEllipse(line.Brush, null, new Point(X(p.Time), Y(Math.Clamp(p.Value, ymin, ymax))), 3, 3);
        }
        if (_hoverX is double hx && hx >= L && hx <= L + pw) dc.DrawLine(CursorPen, new Point(hx, T), new Point(hx, T + ph));
    }

    private static TimeSpan TypicalGap(List<MetricPoint> pts)
    {
        if (pts.Count < 3) return TimeSpan.FromHours(1);
        var gaps = new List<double>(Math.Min(pts.Count, 500));
        var step = Math.Max(1, pts.Count / 500);
        for (var i = step; i < pts.Count; i += step) gaps.Add((pts[i].Time - pts[i - step].Time).TotalSeconds / step);
        gaps.Sort();
        return TimeSpan.FromSeconds(Math.Max(30, gaps[gaps.Count / 2]));
    }

    private static string Fmt(double v) => Math.Abs(v) >= 100 ? v.ToString("0", CultureInfo.CurrentCulture) : v.ToString("0.#", CultureInfo.CurrentCulture);

    private void OnMove(object sender, MouseEventArgs e)
    {
        var x = e.GetPosition(this).X;
        _hoverX = x;
        InvalidateVisual();
        var (from, to) = Range();
        var pw = ActualWidth - L - R;
        if (pw <= 0 || x < L || x > L + pw) { _tip.IsOpen = false; return; }
        var t = from + TimeSpan.FromSeconds((to - from).TotalSeconds * (x - L) / pw);
        var lines = new List<string> { t.ToString("dd/MM HH:mm:ss", CultureInfo.InvariantCulture) };
        foreach (var l in Lines)
        {
            var pts = l.Series.Points;
            if (pts.Count == 0) continue;
            var idx = pts.BinarySearch(new MetricPoint(t, 0), Comparer<MetricPoint>.Create((a, b) => a.Time.CompareTo(b.Time)));
            if (idx < 0) idx = ~idx;
            MetricPoint? best = null;
            foreach (var j in new[] { idx - 1, idx })
                if (j >= 0 && j < pts.Count && (best is null || Math.Abs((pts[j].Time - t).TotalSeconds) < Math.Abs((best.Time - t).TotalSeconds))) best = pts[j];
            if (best != null && Math.Abs((best.Time - t).TotalSeconds) <= TypicalGap(pts).TotalSeconds * 2)
                lines.Add($"{l.Label ?? l.Series.Label}: {Fmt(best.Value)} {l.Series.Unit}");
        }
        _tip.Content = string.Join("\n", lines);
        _tip.IsOpen = true;
    }
}
