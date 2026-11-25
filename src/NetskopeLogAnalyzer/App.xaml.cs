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

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
        // "Abrir com" no Explorador ou arquivo arrastado sobre o ícone
        var files = e.Args.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToArray();
        if (files.Length > 0) window.LoadFiles(files);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show("Ocorreu um erro inesperado:\n\n" + e.Exception.Message, "Netskope Log Analyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
