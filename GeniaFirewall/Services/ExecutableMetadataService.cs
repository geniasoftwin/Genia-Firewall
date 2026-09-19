using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public static class ExecutableMetadataService
{
    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdUseDefaultOsverCheck = 0x00000400;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    public readonly record struct FileState(long Length, DateTime LastWriteUtc);
    public readonly record struct Fingerprint(string Sha256, long Length, DateTime LastWriteUtc);
    public readonly record struct SignatureInfo(bool IsSigned, bool IsTrusted, string Publisher, string StatusLabel, string Details);

    public static ImageSource? TryLoadIcon(string exePath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
                return null;

            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(exePath);
            if (icon is null)
                return null;

            var source = Imaging.CreateBitmapSourceFromHIcon(
                icon.Handle,
                Int32Rect.Empty,
                BitmapSizeOptions.FromWidthAndHeight(18, 18));
            source.Freeze();
            return source;
        }
        catch
        {
            return null;
        }
    }

    public static string TryGetCompanyName(string exePath)
    {
        try
        {
            var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(exePath);
            return SanitizeDisplayText(version.CompanyName, 200);
        }
        catch
        {
            return string.Empty;
        }
    }

    public static SignatureInfo GetSignatureInfo(string exePath)
    {
        var russian = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return new SignatureInfo(
                false,
                false,
                string.Empty,
                russian ? "Файл недоступен" : "File unavailable",
                russian ? "Исполняемый файл не найден." : "Executable file was not found.");

        // First check the PE's embedded Authenticode signature. If Windows reports no embedded signer,
        // fall back to the Windows catalog database. Many genuine Windows system binaries are catalog-
        // signed and must not be mislabeled as unsigned merely because the PE has no embedded signer.
        var verification = VerifyEmbeddedSignature(exePath);
        if (!verification.IsSigned)
        {
            var catalogVerification = VerifyCatalogSignature(exePath);
            if (catalogVerification.IsSigned)
                verification = catalogVerification;
        }

        if (!verification.IsSigned)
        {
            var company = TryGetCompanyName(exePath);
            return new SignatureInfo(
                false,
                false,
                company,
                russian ? "Не подписано" : "Unsigned",
                string.IsNullOrWhiteSpace(company)
                    ? (russian
                        ? "Windows не нашла ни встроенную Authenticode-подпись, ни подпись файла в системном каталоге."
                        : "Windows found neither an embedded Authenticode signature nor a system-catalog signature for this file.")
                    : (russian
                        ? $"Windows не нашла доверенную встроенную или каталоговую подпись. Поле издателя из метаданных файла: {company}."
                        : $"Windows found no trusted embedded or catalog signature. File-version publisher metadata: {company}."));
        }

        var signatureKind = verification.Kind == SignatureKind.Catalog
            ? (russian ? "каталог" : "catalog")
            : (russian ? "встроенная" : "embedded");

        if (verification.TrustResult == 0)
        {
            return new SignatureInfo(
                true,
                true,
                verification.Publisher,
                russian ? $"Подпись доверена · {signatureKind}" : $"Signature trusted · {signatureKind}",
                string.IsNullOrWhiteSpace(verification.Publisher)
                    ? (russian
                        ? $"Windows успешно проверила {signatureKind} цифровую подпись."
                        : $"Windows successfully verified the {signatureKind} digital signature.")
                    : (russian
                        ? $"Windows успешно проверила {signatureKind} цифровую подпись. Издатель: {verification.Publisher}."
                        : $"Windows successfully verified the {signatureKind} digital signature. Publisher: {verification.Publisher}."));
        }

        return new SignatureInfo(
            true,
            false,
            verification.Publisher,
            russian ? $"Подписано · {signatureKind} · доверие не подтверждено" : $"Signed · {signatureKind} · trust not confirmed",
            russian
                ? $"{(verification.Kind == SignatureKind.Catalog ? "Каталоговая" : "Встроенная")} подпись присутствует, но Windows не подтвердила доверие (WinVerifyTrust 0x{verification.TrustResult:X8})."
                : $"A {(verification.Kind == SignatureKind.Catalog ? "catalog" : "embedded")} signature is present, but Windows did not confirm trust (WinVerifyTrust 0x{verification.TrustResult:X8}).");
    }

    public static bool TryGetFileState(string exePath, out FileState state)
    {
        state = default;
        try
        {
            var info = new FileInfo(exePath);
            if (!info.Exists)
                return false;

            state = new FileState(info.Length, info.LastWriteTimeUtc);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static Fingerprint ComputeFingerprint(string exePath)
    {
        // Retry once if an updater replaces the executable while it is being hashed.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var before = new FileInfo(exePath);
            if (!before.Exists)
                throw new FileNotFoundException("Исполняемый файл не найден.", exePath);

            var beforeLength = before.Length;
            var beforeWrite = before.LastWriteTimeUtc;

            string hash;
            using (var stream = new FileStream(
                       exePath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete,
                       128 * 1024,
                       FileOptions.SequentialScan))
            {
                hash = Convert.ToHexString(SHA256.HashData(stream));
            }

            var after = new FileInfo(exePath);
            after.Refresh();
            if (!after.Exists)
                throw new IOException("Исполняемый файл был удалён во время проверки.");

            if (beforeLength == after.Length && beforeWrite == after.LastWriteTimeUtc)
                return new Fingerprint(hash, after.Length, after.LastWriteTimeUtc);
        }

        throw new IOException("Исполняемый файл изменяется во время вычисления SHA-256. Проверка отложена.");
    }

    private static SignatureVerification VerifyEmbeddedSignature(string filePath)
    {
        IntPtr fileInfoPtr = IntPtr.Zero;
        var data = default(WinTrustData);
        var action = WinTrustActionGenericVerifyV2;
        var verifyCalled = false;

        try
        {
            var fileInfo = new WinTrustFileInfo(filePath);
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            data = new WinTrustData(fileInfoPtr, WtdStateActionVerify, WtdChoiceFile);
            var trustResult = unchecked((uint)WinVerifyTrust(new IntPtr(-1), ref action, ref data));
            verifyCalled = true;

            var signer = ReadSigner(data.hWVTStateData);
            return new SignatureVerification(signer.IsSigned, trustResult, signer.Publisher, SignatureKind.Embedded);
        }
        catch
        {
            return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);
        }
        finally
        {
            CloseTrustState(ref action, ref data, verifyCalled);

            if (fileInfoPtr != IntPtr.Zero)
            {
                try
                {
                    Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPtr);
                }
                catch
                {
                }

                Marshal.FreeHGlobal(fileInfoPtr);
            }
        }
    }

    private static SignatureVerification VerifyCatalogSignature(string filePath)
    {
        var sha256 = VerifyCatalogSignatureCore(filePath, "SHA256");
        if (sha256.IsSigned)
            return sha256;

        // Legacy catalogs can use the system default hash algorithm. Keep this as a fallback so the
        // UI mirrors Windows trust behavior across older catalog entries as well.
        return VerifyCatalogSignatureCore(filePath, null);
    }

    private static SignatureVerification VerifyCatalogSignatureCore(string filePath, string? hashAlgorithm)
    {
        IntPtr catAdmin = IntPtr.Zero;
        IntPtr catInfo = IntPtr.Zero;
        IntPtr catalogInfoPtr = IntPtr.Zero;
        IntPtr hashPtr = IntPtr.Zero;
        var action = WinTrustActionGenericVerifyV2;
        var data = default(WinTrustData);
        var verifyCalled = false;

        try
        {
            if (!CryptCATAdminAcquireContext2(out catAdmin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0) || catAdmin == IntPtr.Zero)
                return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);

            using var fileHandle = File.OpenHandle(
                filePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var rawFileHandle = fileHandle.DangerousGetHandle();

            uint hashLength = 0;
            // The size-probe call may return FALSE with ERROR_INSUFFICIENT_BUFFER; the required size is
            // still returned in hashLength. Treat zero as failure and otherwise perform the real call.
            _ = CryptCATAdminCalcHashFromFileHandle2(catAdmin, rawFileHandle, ref hashLength, null, 0);
            if (hashLength == 0 || hashLength > 1024)
                return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);

            var hash = new byte[checked((int)hashLength)];
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, rawFileHandle, ref hashLength, hash, 0))
                return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);

            IntPtr previousCatalog = IntPtr.Zero;
            catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashLength, 0, ref previousCatalog);
            if (catInfo == IntPtr.Zero)
                return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);

            var catalog = new CatalogInfo { CbStruct = (uint)Marshal.SizeOf<CatalogInfo>(), CatalogFile = string.Empty };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref catalog, 0) || string.IsNullOrWhiteSpace(catalog.CatalogFile))
                return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);

            var memberTag = Convert.ToHexString(hash.AsSpan(0, checked((int)hashLength)));
            hashPtr = Marshal.AllocHGlobal(checked((int)hashLength));
            Marshal.Copy(hash, 0, hashPtr, checked((int)hashLength));

            var trustCatalogInfo = new WinTrustCatalogInfo
            {
                CbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                DwCatalogVersion = 0,
                CatalogFilePath = catalog.CatalogFile,
                MemberTag = memberTag,
                MemberFilePath = filePath,
                MemberFile = rawFileHandle,
                CalculatedFileHash = hashPtr,
                CalculatedFileHashSize = hashLength,
                CatalogContext = IntPtr.Zero,
                CatAdmin = catAdmin
            };

            catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(trustCatalogInfo, catalogInfoPtr, fDeleteOld: false);

            data = new WinTrustData(catalogInfoPtr, WtdStateActionVerify, WtdChoiceCatalog);
            var trustResult = unchecked((uint)WinVerifyTrust(new IntPtr(-1), ref action, ref data));
            verifyCalled = true;

            var signer = ReadSigner(data.hWVTStateData);
            // A catalog context + WinVerifyTrust result is sufficient to identify this as a catalog
            // signature even if friendly-name extraction is unavailable for a protected certificate.
            var isSigned = signer.IsSigned || trustResult == 0;
            return new SignatureVerification(isSigned, trustResult, signer.Publisher, SignatureKind.Catalog);
        }
        catch (EntryPointNotFoundException)
        {
            // Should not occur on supported Windows 10/11 builds, but fail closed to "unsigned" rather
            // than crashing the prompt if a catalog API is unavailable.
            return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);
        }
        catch
        {
            return new SignatureVerification(false, uint.MaxValue, string.Empty, SignatureKind.None);
        }
        finally
        {
            CloseTrustState(ref action, ref data, verifyCalled);

            if (catalogInfoPtr != IntPtr.Zero)
            {
                try
                {
                    Marshal.DestroyStructure<WinTrustCatalogInfo>(catalogInfoPtr);
                }
                catch
                {
                }
                Marshal.FreeHGlobal(catalogInfoPtr);
            }

            if (hashPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(hashPtr);

            if (catInfo != IntPtr.Zero && catAdmin != IntPtr.Zero)
            {
                try
                {
                    _ = CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
                }
                catch
                {
                }
            }

            if (catAdmin != IntPtr.Zero)
            {
                try
                {
                    _ = CryptCATAdminReleaseContext(catAdmin, 0);
                }
                catch
                {
                }
            }
        }
    }

    private static SignerInfo ReadSigner(IntPtr trustStateData)
    {
        if (trustStateData == IntPtr.Zero)
            return new SignerInfo(false, string.Empty);

        try
        {
            var providerData = WTHelperProvDataFromStateData(trustStateData);
            if (providerData == IntPtr.Zero)
                return new SignerInfo(false, string.Empty);

            var signerPointer = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
            if (signerPointer == IntPtr.Zero)
                return new SignerInfo(false, string.Empty);

            var signer = Marshal.PtrToStructure<CryptProviderSigner>(signerPointer);
            if (signer.csCertChain == 0 || signer.pasCertChain == IntPtr.Zero)
                return new SignerInfo(false, string.Empty);

            var providerCert = Marshal.PtrToStructure<CryptProviderCertHead>(signer.pasCertChain);
            if (providerCert.pCert == IntPtr.Zero)
                return new SignerInfo(false, string.Empty);

            var publisher = string.Empty;
            try
            {
                using var certificate = new X509Certificate2(providerCert.pCert);
                publisher = SanitizeDisplayText(certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false), 200);
                if (string.IsNullOrWhiteSpace(publisher))
                    publisher = SanitizeDisplayText(certificate.Subject, 200);
            }
            catch
            {
                // Trust status still remains useful if the certificate display name cannot be decoded.
            }

            return new SignerInfo(true, publisher);
        }
        catch
        {
            return new SignerInfo(false, string.Empty);
        }
    }

    private static void CloseTrustState(ref Guid action, ref WinTrustData data, bool verifyCalled)
    {
        if (!verifyCalled || data.hWVTStateData == IntPtr.Zero)
            return;

        try
        {
            data.dwStateAction = WtdStateActionClose;
            _ = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        catch
        {
        }
    }

    private static string SanitizeDisplayText(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var result = new string(value.Where(character => !char.IsControl(character)).ToArray()).Trim();
        return result.Length <= maxLength ? result : result[..maxLength];
    }

    private enum SignatureKind
    {
        None,
        Embedded,
        Catalog
    }

    private readonly record struct SignatureVerification(bool IsSigned, uint TrustResult, string Publisher, SignatureKind Kind);
    private readonly record struct SignerInfo(bool IsSigned, string Publisher);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionId, ref WinTrustData pWvtData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref uint pcbHash,
        [Out] byte[]? pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte[] pbHash,
        uint cbHash,
        uint dwFlags,
        ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CatalogInfo psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;

        public WinTrustFileInfo(string filePath)
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            pcwszFilePath = filePath;
            hFile = IntPtr.Zero;
            pgKnownSubject = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint CbStruct;
        public uint DwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string CatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string MemberFilePath;
        public IntPtr MemberFile;
        public IntPtr CalculatedFileHash;
        public uint CalculatedFileHashSize;
        public IntPtr CatalogContext;
        public IntPtr CatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint CbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string CatalogFile;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnionData;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;

        public WinTrustData(IntPtr unionInfoPtr, uint stateAction, uint unionChoice)
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustData>();
            pPolicyCallbackData = IntPtr.Zero;
            pSIPClientData = IntPtr.Zero;
            dwUIChoice = 2; // WTD_UI_NONE
            fdwRevocationChecks = 0; // WTD_REVOKE_NONE
            dwUnionChoice = unionChoice;
            pUnionData = unionInfoPtr;
            dwStateAction = stateAction;
            hWVTStateData = IntPtr.Zero;
            pwszURLReference = IntPtr.Zero;
            dwProvFlags = WtdCacheOnlyUrlRetrieval | (unionChoice == WtdChoiceCatalog ? WtdUseDefaultOsverCheck : 0); // No network retrieval; apply the default OS-version check for catalog signatures.
            dwUIContext = 0;
            pSignatureSettings = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderSigner
    {
        public uint cbStruct;
        public FILETIME sftVerifyAsOf;
        public uint csCertChain;
        public IntPtr pasCertChain;
        public uint dwSignerType;
        public IntPtr psSigner;
        public uint dwError;
        public uint csCounterSigners;
        public IntPtr pasCounterSigners;
        public IntPtr pChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCertHead
    {
        public uint cbStruct;
        public IntPtr pCert;
    }
}
