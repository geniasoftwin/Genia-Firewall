using System.Threading;
using System.Windows;

namespace GeniaFirewall;

public partial class App : System.Windows.Application
{
    private Mutex? _singleInstanceMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        _singleInstanceMutex = new Mutex(
            initiallyOwned: true,
            name: @"Local\GeniaFirewall.SingleInstance",
            createdNew: out var createdNew);

        if (!createdNew)
        {
            System.Windows.MessageBox.Show(
                "GeniaFirewall уже запущен. Проверьте значок G в системном трее.",
                "GeniaFirewall",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            Shutdown();
            return;
        }

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            _singleInstanceMutex?.ReleaseMutex();
        }
        catch
        {
        }

        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}
