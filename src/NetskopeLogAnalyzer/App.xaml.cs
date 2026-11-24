using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using NetskopeLogAnalyzer.Services;

namespace NetskopeLogAnalyzer;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandled;

        // Modo coletor (sem janela): NetskopeLogAnalyzer.exe --collect [--minutes N] [--tenant x] [--interval s] [--url u]...
        if (e.Args.Any(a => a.Equals("--collect", StringComparison.OrdinalIgnoreCase)))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            _ = RunCollectorAsync(e.Args);
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
        // "Abrir com" no Explorador ou arquivo arrastado sobre o ícone
        var files = e.Args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToArray();
        if (files.Length > 0) window.LoadFiles(files);
    }

    private async Task RunCollectorAsync(string[] args)
    {
        if (AppSettings.CollectorDisabledByPolicy) { Shutdown(2); return; }
        using var single = new Mutex(true, TelemetryCollector.MutexName, out var first);
        if (!first) { Shutdown(0); return; } // já existe um coletor nesta sessão

        var settings = AppSettings.Load();
        int? minutes = null;
        for (var i = 0; i < args.Length; i++)
        {
            string? Next() => i + 1 < args.Length ? args[++i] : null;
            switch (args[i].ToLowerInvariant())
            {
                case "--minutes": if (int.TryParse(Next(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var m)) minutes = m; break;
                case "--tenant": settings.Tenant = Next(); break;
                case "--interval": if (int.TryParse(Next(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s) && s >= 5) settings.IntervalSeconds = s; break;
                case "--url": var u = Next(); if (u != null) { if (!settings.ProbeUrls.Contains(u)) settings.ProbeUrls.Insert(0, u); } break;
            }
        }

        using var stop = new EventWaitHandle(false, EventResetMode.ManualReset, TelemetryCollector.StopEventName);
        using var cts = new CancellationTokenSource();
        if (minutes is int mm && mm > 0) cts.CancelAfter(TimeSpan.FromMinutes(mm));
        var waiter = Task.Run(() => { WaitHandle.WaitAny(new WaitHandle[] { stop, cts.Token.WaitHandle }); cts.Cancel(); });
        SessionEnding += (_, _) => cts.Cancel();
        try
        {
            using var collector = new TelemetryCollector(settings);
            await Task.Run(() => collector.RunAsync(cts.Token));
        }
        catch (Exception) { }
        finally
        {
            cts.Cancel();
            await waiter;
            Shutdown(0);
        }
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        if (ShutdownMode == ShutdownMode.OnExplicitShutdown) { e.Handled = true; return; } // modo coletor: nunca mostrar janela
        MessageBox.Show("Ocorreu um erro inesperado:\n\n" + e.Exception.Message, "Netskope Log Analyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
