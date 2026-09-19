using System.Runtime.InteropServices;

namespace GeniaFirewall.Service;

/// <summary>
/// Enumerates filters owned by the GeniaFirewall provider on the ALE layers used by the
/// product. HF2 uses this for two purposes: strict zero-filter verification when WFP is
/// disabled/switched away, and best-effort removal of persistent orphan objects left by
/// older builds. Current runtime objects are still created in a dynamic WFP session.
/// </summary>
internal static class WfpOwnedFilterInventory
{
    private const uint RpcCAuthnWinnt = 10;
    private const uint FwpFilterEnumFullyContained = 0;
    // FWPM_FILTER_ENUM_TEMPLATE0.actionMask is a bit mask, not an optional value.
    // Zero can never match a filter action and makes WFP reject the enumerator with
    // FWP_E_NEVER_MATCH (0x80320033). UINT32_MAX explicitly disables action filtering.
    private const uint FwpActionMaskAll = uint.MaxValue;
    private const uint FwpEProviderNotFound = 0x80320005;
    private const uint FwpESubLayerNotFound = 0x80320007;
    private const uint EnumBatchSize = 256;

    private static readonly Guid[] OwnedLayers =
    [
        new("C38D57D1-05A7-4C33-904F-7FBCEEE60E82"), // ALE_AUTH_CONNECT_V4
        new("4A72393B-319F-44BC-84C3-BA54DCB3B6B4"), // ALE_AUTH_CONNECT_V6
        new("E1CD9FE7-F4B5-4273-96C0-592E487B8650"), // ALE_AUTH_RECV_ACCEPT_V4
        new("A3B42C97-9F04-4672-B87E-CEE9C483257F")  // ALE_AUTH_RECV_ACCEPT_V6
    ];

    internal readonly record struct StartupCleanupResult(
        bool Attempted,
        int RemovedFilterCount,
        int ResidualFilterCount,
        string Status);

    public static IReadOnlyList<ulong> GetOwnedFilterIds(IntPtr engineHandle)
    {
        if (engineHandle == IntPtr.Zero)
            return Array.Empty<ulong>();

        var ids = new HashSet<ulong>();
        var providerKeyPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
        try
        {
            Marshal.StructureToPtr(WfpSessionManager.ProviderKey, providerKeyPtr, false);

            foreach (var layerKey in OwnedLayers)
            {
                var template = new FwpmFilterEnumTemplate0
                {
                    ProviderKey = providerKeyPtr,
                    LayerKey = layerKey,
                    EnumType = FwpFilterEnumFullyContained,
                    Flags = 0,
                    ProviderContextTemplate = IntPtr.Zero,
                    NumFilterConditions = 0,
                    FilterCondition = IntPtr.Zero,
                    ActionMask = FwpActionMaskAll,
                    CalloutKey = IntPtr.Zero
                };

                var createResult = FwpmFilterCreateEnumHandle0(engineHandle, ref template, out var enumHandle);
                if (createResult != 0 || enumHandle == IntPtr.Zero)
                    throw new InvalidOperationException($"FwpmFilterCreateEnumHandle0 failed on {layerKey}: 0x{createResult:X8}");

                try
                {
                    while (true)
                    {
                        var enumResult = FwpmFilterEnum0(engineHandle, enumHandle, EnumBatchSize, out var entries, out var returned);
                        if (enumResult != 0)
                            throw new InvalidOperationException($"FwpmFilterEnum0 failed on {layerKey}: 0x{enumResult:X8}");

                        try
                        {
                            if (returned == 0 || entries == IntPtr.Zero)
                                break;

                            for (var i = 0; i < returned; i++)
                            {
                                var filterPtr = Marshal.ReadIntPtr(entries, checked((int)i * IntPtr.Size));
                                if (filterPtr == IntPtr.Zero)
                                    continue;

                                var filter = Marshal.PtrToStructure<FwpmFilter0>(filterPtr);
                                if (filter.SubLayerKey == WfpSessionManager.SubLayerKey)
                                    ids.Add(filter.FilterId);
                            }
                        }
                        finally
                        {
                            if (entries != IntPtr.Zero)
                                FwpmFreeMemory0(ref entries);
                        }

                        if (returned < EnumBatchSize)
                            break;
                    }
                }
                finally
                {
                    _ = FwpmFilterDestroyEnumHandle0(engineHandle, enumHandle);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(providerKeyPtr);
        }

        return ids.OrderBy(id => id).ToList();
    }

    public static StartupCleanupResult CleanupStaleObjectsBestEffort()
    {
        IntPtr engineHandle = IntPtr.Zero;
        var removed = 0;
        try
        {
            var openResult = FwpmEngineOpen0(null, RpcCAuthnWinnt, IntPtr.Zero, IntPtr.Zero, out engineHandle);
            if (openResult != 0 || engineHandle == IntPtr.Zero)
                return new(true, 0, -1, $"stale-cleanup engine open failed: 0x{openResult:X8}");

            IReadOnlyList<ulong> existing;
            try
            {
                existing = GetOwnedFilterIds(engineHandle);
            }
            catch (Exception ex)
            {
                return new(true, 0, -1, $"stale-filter enumeration failed: {ex.Message}");
            }

            foreach (var filterId in existing)
            {
                var result = FwpmFilterDeleteById0(engineHandle, filterId);
                if (result == 0)
                    removed++;
                else
                    ServiceLog.Write($"Startup stale-filter delete failed: filterId={filterId}; error=0x{result:X8}");
            }

            IReadOnlyList<ulong> residual;
            try
            {
                residual = GetOwnedFilterIds(engineHandle);
            }
            catch (Exception ex)
            {
                return new(true, removed, -1, $"stale-filter verification failed: {ex.Message}");
            }

            // These calls are intentionally best effort. Not-found and wrong-session style
            // errors are harmless here; the subsequent dynamic registration is authoritative.
            var subLayerDelete = FwpmSubLayerDeleteByKey0(engineHandle, ref UnsafeSubLayerKey);
            var providerDelete = FwpmProviderDeleteByKey0(engineHandle, ref UnsafeProviderKey);

            var subLayerStatus = FormatBestEffortDeleteResult(subLayerDelete, FwpESubLayerNotFound);
            var providerStatus = FormatBestEffortDeleteResult(providerDelete, FwpEProviderNotFound);
            var status = residual.Count == 0
                ? $"clean; sublayer={subLayerStatus}; provider={providerStatus}"
                : $"residual objects remain; sublayer={subLayerStatus}; provider={providerStatus}";

            return new(true, removed, residual.Count, status);
        }
        catch (Exception ex)
        {
            return new(true, removed, -1, $"stale-cleanup exception: {ex.Message}");
        }
        finally
        {
            if (engineHandle != IntPtr.Zero)
            {
                try { _ = FwpmEngineClose0(engineHandle); } catch { }
            }
        }
    }

    private static string FormatBestEffortDeleteResult(uint result, uint notFoundResult) => result switch
    {
        0 => "deleted",
        _ when result == notFoundResult => "not-found (ok)",
        _ => $"error 0x{result:X8}"
    };

    // P/Invoke requires ref GUID variables rather than properties/readonly fields.
    private static Guid UnsafeProviderKey = WfpSessionManager.ProviderKey;
    private static Guid UnsafeSubLayerKey = WfpSessionManager.SubLayerKey;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmDisplayData0
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? Name;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpValue0
    {
        [FieldOffset(0)] public uint Type;
        [FieldOffset(8)] public IntPtr Pointer;
        [FieldOffset(8)] public byte UInt8;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmAction0
    {
        public uint Type;
        public Guid FilterType;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct FwpmFilterContextUnion
    {
        [FieldOffset(0)] public ulong RawContext;
        [FieldOffset(0)] public Guid ProviderContextKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FwpmFilter0
    {
        public Guid FilterKey;
        public FwpmDisplayData0 DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;
        public FwpByteBlob ProviderData;
        public Guid LayerKey;
        public Guid SubLayerKey;
        public FwpValue0 Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public FwpmAction0 Action;
        public FwpmFilterContextUnion Context;
        public IntPtr Reserved;
        public ulong FilterId;
        public FwpValue0 EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FwpmFilterEnumTemplate0
    {
        public IntPtr ProviderKey;
        public Guid LayerKey;
        public uint EnumType;
        public uint Flags;
        public IntPtr ProviderContextTemplate;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public uint ActionMask;
        public IntPtr CalloutKey;
    }

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
    private static extern uint FwpmEngineOpen0(string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engineHandle, ref FwpmFilterEnumTemplate0 enumTemplate, out IntPtr enumHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll")]
    private static extern void FwpmFreeMemory0(ref IntPtr pointer);
}
