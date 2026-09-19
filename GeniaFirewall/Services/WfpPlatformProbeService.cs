using System.Runtime.InteropServices;

namespace GeniaFirewall.Services;

/// <summary>
/// Read-only WFP/BFE availability probe for the UI process. In 0.7.1 the
/// privileged GeniaFirewall.Service owns a separate dynamic WFP session; this
/// probe remains intentionally read-only and is used only for diagnostics.
/// </summary>
public sealed class WfpPlatformProbeService
{
    private const uint RpcCAuthnWinnt = 10;

    public readonly record struct WfpPlatformStatus(
        bool ApiAvailable,
        bool EngineAvailable,
        uint NativeError,
        string Description);

    public WfpPlatformStatus Probe()
    {
        if (!OperatingSystem.IsWindows())
            return new(false, false, 0, "недоступно: требуется Windows");

        IntPtr engineHandle = IntPtr.Zero;
        try
        {
            var result = FwpmEngineOpen0(
                serverName: null,
                authnService: RpcCAuthnWinnt,
                authIdentity: IntPtr.Zero,
                session: IntPtr.Zero,
                engineHandle: out engineHandle);

            if (result == 0 && engineHandle != IntPtr.Zero)
                return new(true, true, 0, "WFP/BFE доступен · policy engine открыт");

            return new(true, false, result, $"WFP API доступен, BFE не открыт · 0x{result:X8}");
        }
        catch (DllNotFoundException)
        {
            return new(false, false, 0, "fwpuclnt.dll не найден");
        }
        catch (EntryPointNotFoundException)
        {
            return new(false, false, 0, "FwpmEngineOpen0 недоступен");
        }
        catch (Exception ex)
        {
            return new(true, false, unchecked((uint)ex.HResult), $"ошибка WFP probe · {ex.Message}");
        }
        finally
        {
            if (engineHandle != IntPtr.Zero)
            {
                try
                {
                    _ = FwpmEngineClose0(engineHandle);
                }
                catch
                {
                }
            }
        }
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);
}
