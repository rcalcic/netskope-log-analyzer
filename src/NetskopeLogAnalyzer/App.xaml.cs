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

        // Versões 3.0/3.1 tinham um coletor iniciado no logon ("--collect"). Ele foi removido:
        // apaga a entrada de inicialização antiga; se foi ela que abriu o app, sai sem mostrar janela.
        try
        {
            using var run = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", writable: true);
            run?.DeleteValue("NetskopeLogAnalyzerCollector", throwOnMissingValue: false);
        }
        catch (Exception) { }
        if (e.Args.Any(a => a.Equals("--collect", StringComparison.OrdinalIgnoreCase))) { Shutdown(0); return; }

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
