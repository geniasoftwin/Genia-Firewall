using System.ComponentModel;
using System.Runtime.InteropServices;
using GeniaFirewall.Protocol;

namespace GeniaFirewall.Service;

internal static class NativeWindowsServiceHost
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ServiceAcceptShutdown = 0x00000004;
    private const uint ServiceControlStop = 0x00000001;
    private const uint ServiceControlShutdown = 0x00000005;
    private const int ErrorFailedServiceControllerConnect = 1063;

    private static readonly ManualResetEventSlim StopEvent = new(false);
    private static ServiceMainDelegate? _serviceMainDelegate;
    private static HandlerExDelegate? _handlerDelegate;
    private static IntPtr _statusHandle;
    private static ServiceStatus _status;

    public static int Run()
    {
        _serviceMainDelegate = ServiceMain;
        var entries = new[]
        {
            new ServiceTableEntry
            {
                ServiceName = ServiceProtocol.ServiceName,
                ServiceMain = Marshal.GetFunctionPointerForDelegate(_serviceMainDelegate)
            },
            new ServiceTableEntry()
        };

        if (StartServiceCtrlDispatcher(entries))
            return 0;

        var error = Marshal.GetLastWin32Error();
        if (error == ErrorFailedServiceControllerConnect)
        {
            Console.Error.WriteLine("GeniaFirewall.Service is not running under the Windows Service Control Manager.");
            Console.Error.WriteLine("Use --console for a manual elevated test, or install-service.cmd to register the service.");
            return error;
        }

        throw new Win32Exception(error, "StartServiceCtrlDispatcher failed.");
    }

    private static void ServiceMain(uint argumentCount, IntPtr arguments)
    {
        _handlerDelegate = ServiceControlHandler;
        _statusHandle = RegisterServiceCtrlHandlerEx(ServiceProtocol.ServiceName, _handlerDelegate, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
        {
            ServiceLog.Write($"RegisterServiceCtrlHandlerEx failed: {Marshal.GetLastWin32Error()}.");
            return;
        }

        _status = new ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = ServiceStartPending,
            ControlsAccepted = 0,
            Win32ExitCode = 0,
            ServiceSpecificExitCode = 0,
            CheckPoint = 1,
            WaitHint = 15000
        };
        SetStatus();

        ServiceRuntime? runtime = null;
        try
        {
            runtime = new ServiceRuntime();
            runtime.StartAsync().GetAwaiter().GetResult();

            _status.CurrentState = ServiceRunning;
            _status.ControlsAccepted = ServiceAcceptStop | ServiceAcceptShutdown;
            _status.CheckPoint = 0;
            _status.WaitHint = 0;
            SetStatus();

            StopEvent.Wait();

            _status.CurrentState = ServiceStopPending;
            _status.ControlsAccepted = 0;
            _status.CheckPoint = 1;
            _status.WaitHint = 10000;
            SetStatus();

            runtime.StopAsync().GetAwaiter().GetResult();
            runtime = null;

            _status.CurrentState = ServiceStopped;
            _status.Win32ExitCode = 0;
            _status.CheckPoint = 0;
            _status.WaitHint = 0;
            SetStatus();
        }
        catch (Exception ex)
        {
            ServiceLog.WriteException("Unhandled service error", ex);
            _status.CurrentState = ServiceStopped;
            _status.ControlsAccepted = 0;
            _status.Win32ExitCode = 1;
            _status.CheckPoint = 0;
            _status.WaitHint = 0;
            SetStatus();
        }
        finally
        {
            if (runtime is not null)
            {
                try
                {
                    runtime.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
                catch
                {
                }
            }
        }
    }

    private static uint ServiceControlHandler(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control is ServiceControlStop or ServiceControlShutdown)
        {
            _status.CurrentState = ServiceStopPending;
            _status.ControlsAccepted = 0;
            _status.CheckPoint = 1;
            _status.WaitHint = 10000;
            SetStatus();
            StopEvent.Set();
        }

        return 0;
    }

    private static void SetStatus()
    {
        if (_statusHandle != IntPtr.Zero)
            _ = SetServiceStatus(_statusHandle, ref _status);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainDelegate(uint argumentCount, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerExDelegate(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? ServiceName;

        public IntPtr ServiceMain;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(
        string serviceName,
        HandlerExDelegate handlerProc,
        IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus serviceStatus);
}
