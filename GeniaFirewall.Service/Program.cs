using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("GeniaFirewall.Service requires Windows.");
            return 1;
        }

        if (args.Any(arg => arg.Equals("--console", StringComparison.OrdinalIgnoreCase)))
            return await RunConsoleAsync().ConfigureAwait(false);

        try
        {
            return NativeWindowsServiceHost.Run();
        }
        catch (Exception ex)
        {
            ServiceLog.WriteException("Fatal service host error", ex);
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static async Task<int> RunConsoleAsync()
    {
        Console.WriteLine($"{ServiceProtocol.DisplayName} {ServiceProtocol.ProductVersion} — console test mode");
        Console.WriteLine("This mode requires an elevated terminal. WFP policy can be applied by the elevated UI over local IPC.");
        Console.WriteLine("Press Ctrl+C to stop. Stopping the service releases all dynamic WFP filters; persisted policy is replayed on the next start.");

        await using var runtime = new ServiceRuntime();
        await runtime.StartAsync().ConfigureAwait(false);

        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        Console.CancelKeyPress += handler;

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            Console.CancelKeyPress -= handler;
        }

        return 0;
    }
}
