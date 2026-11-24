using System.Windows;
using System.Windows.Threading;

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
        if (e.Args.Length > 0) window.LoadFiles(e.Args);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show("Ocorreu um erro inesperado:\n\n" + e.Exception.Message, "Netskope Log Analyzer", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
