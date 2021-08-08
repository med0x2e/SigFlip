using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static SigFlip.WinTrustData;

namespace SigFlip
{

     public enum WinTrustDataUIChoice : uint
     {
         All = 1,
         None = 2,
         NoBad = 3,
         NoGood = 4
     }

     public enum WinTrustDataRevocationChecks : uint
     {
         None = 0x00000000,
         WholeChain = 0x00000001
     }

     public enum WinTrustDataChoice : uint
     {
         File = 1,
         Catalog = 2,
         Blob = 3,
         Signer = 4,
         Certificate = 5
     }

     public enum WinTrustDataStateAction : uint
     {
         Ignore = 0x00000000,
         Verify = 0x00000001,
         Close = 0x00000002,
         AutoCache = 0x00000003,
         AutoCacheFlush = 0x00000004
     }

     [FlagsAttribute]
     public enum WinTrustDataProvFlags : uint
     {
         UseIe4TrustFlag = 0x00000001,
         NoIe4ChainFlag = 0x00000002,
         NoPolicyUsageFlag = 0x00000004,
         RevocationCheckNone = 0x00000010,
         RevocationCheckEndCert = 0x00000020,
         RevocationCheckChain = 0x00000040,
         RevocationCheckChainExcludeRoot = 0x00000080,
         SaferFlag = 0x00000100,
         HashOnlyFlag = 0x00000200,
         UseDefaultOsverCheck = 0x00000400,
         LifetimeSigningFlag = 0x00000800,
         CacheOnlyUrlRetrieval = 0x00001000      
     }

     public enum WinTrustDataUIContext : uint
     {
         Execute = 0,
         Install = 1
     }

     [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
     public class WinTrustFileInfo : IDisposable
     {
         public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustFileInfo));
         public readonly IntPtr pszFilePath;            
         public IntPtr hFile = IntPtr.Zero;             
         public IntPtr pgKnownSubject = IntPtr.Zero;    

         public WinTrustFileInfo(String filePath)
         {
             pszFilePath = Marshal.StringToCoTaskMemAuto(filePath);
         }
         public void Dispose()
         {
             Marshal.FreeCoTaskMem(pszFilePath);
         }
     }

     [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
     public class WinTrustData : IDisposable
     {
         public UInt32 StructSize = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
         public IntPtr PolicyCallbackData = IntPtr.Zero;
         public IntPtr SIPClientData = IntPtr.Zero;
         
         public WinTrustDataUIChoice UIChoice = WinTrustDataUIChoice.None;
         
         public WinTrustDataRevocationChecks RevocationChecks = WinTrustDataRevocationChecks.None;
         
         public readonly WinTrustDataChoice UnionChoice;
         
         public readonly IntPtr FileInfoPtr;
         public WinTrustDataStateAction StateAction = WinTrustDataStateAction.Ignore;
         public IntPtr StateData = IntPtr.Zero;
         public String URLReference = null;
         public WinTrustDataProvFlags ProvFlags = WinTrustDataProvFlags.SaferFlag;
         public WinTrustDataUIContext UIContext = WinTrustDataUIContext.Execute;

         public WinTrustData(String fileName)
         {
             WinTrustFileInfo wtfiData = new WinTrustFileInfo(fileName);
             FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WinTrustFileInfo)));
             Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
             UnionChoice = WinTrustDataChoice.File;
         }

         public void Dispose()
         {
             Marshal.FreeCoTaskMem(FileInfoPtr);
         }

         public enum WinVerifyTrustResult : uint
         {
             Success = 0,
             
             TRUST_E_SYSTEM_ERROR = 0x80096001,
                 
             TRUST_E_NO_SIGNER_CERT = 0x80096002,
             
             TRUST_E_COUNTER_SIGNER = 0x80096003,
         
             TRUST_E_CERT_SIGNATURE = 0x80096004,
             
             TRUST_E_TIME_STAMP = 0x80096005,
             
             TRUST_E_BAD_DIGEST = 0x80096010,

             TRUST_E_BASIC_CONSTRAINTS = 0x80096019,

             TRUST_E_FINANCIAL_CRITERIA = 0x8009601E,

             TRUST_E_PROVIDER_UNKNOWN = 0x800B0001,

             TRUST_E_ACTION_UNKNOWN = 0x800B0002,

             TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003,

             TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004,

             TRUST_E_NOSIGNATURE = 0x800B0100,
             
             CERT_E_EXPIRED = 0x800B0101,
             
             CERT_E_VALIDITYPERIODNESTING = 0x800B0102,

             CERT_E_ROLE = 0x800B0103,
             
             CERT_E_PATHLENCONST = 0x800B0104,
             
             CERT_E_CRITICAL = 0x800B0105,
             
             CERT_E_PURPOSE = 0x800B0106,
             
             CERT_E_ISSUERCHAINING = 0x800B0107,
             
             CERT_E_MALFORMED = 0x800B0108,

             CERT_E_UNTRUSTEDROOT = 0x800B0109,
             
             CERT_E_CHAINING = 0x800B010A,
             
             TRUST_E_FAIL = 0x800B010B,
             
             CERT_E_REVOKED = 0x800B010C,
             
             CERT_E_UNTRUSTEDTESTROOT = 0x800B010D,
             
             CERT_E_REVOCATION_FAILURE = 0x800B010E,
             
             CERT_E_CN_NO_MATCH = 0x800B010F,
             
             CERT_E_WRONG_USAGE = 0x800B0110,
             
             TRUST_E_EXPLICIT_DISTRUST = 0x800B0111,
             
             CERT_E_UNTRUSTEDCA = 0x800B0112,
             
             CERT_E_INVALID_POLICY = 0x800B0113,
             
             CERT_E_INVALID_NAME = 0x800B0114
         }

         public static class WinTrust
         {
             public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
             
             public const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

             [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
             public static extern WinVerifyTrustResult WinVerifyTrust(
                 [In] IntPtr hwnd,
                 [In] [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
                 [In] WinTrustData pWVTData
             );

             public static bool VerifyEmbeddedSignature(string fileName)
             {
                 WinTrustData wtd = new WinTrustData(fileName);
                 Guid guidAction = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                 WinVerifyTrustResult result = WinVerifyTrust(INVALID_HANDLE_VALUE, guidAction, wtd);
                 bool ret = (result == WinVerifyTrustResult.Success);
                 return ret;
             }
         }
     }

    // http://www.pinvoke.net/default.aspx/wintrust.winverifytrust
     public static class _WinVerifyTrust
     {
         const uint FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
         const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
         const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
         static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

         [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
         static extern uint FormatMessage(
             uint dwFlags, IntPtr lpSource,
             uint dwMessageId, uint dwLanguageId,
             [Out] StringBuilder lpBuffer,
             uint nSize, IntPtr lpArguments
         );

         public static bool checkSig(string fileName, out string errorMessage)
         {
             using (var wtd = new WinTrustData(fileName)
             {
                 UIChoice = WinTrustDataUIChoice.None,
                 UIContext = WinTrustDataUIContext.Execute,
                 RevocationChecks = WinTrustDataRevocationChecks.None,
                 StateAction = WinTrustDataStateAction.Verify,
                 ProvFlags = WinTrustDataProvFlags.RevocationCheckNone
             })

             {
                 var trustResult = WinTrust.WinVerifyTrust(
                     INVALID_HANDLE_VALUE, new Guid(WinTrust.WINTRUST_ACTION_GENERIC_VERIFY_V2), wtd
                 );

                 if (trustResult == WinVerifyTrustResult.Success)
                 {
                     errorMessage = null;
                     return true;
                 }
                 else
                 {
                     var sb = new StringBuilder(1024);
                     var charCount = FormatMessage(
                         FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                         IntPtr.Zero, (uint)trustResult, 0,
                         sb, (uint)sb.Capacity, IntPtr.Zero
                     );

                     errorMessage = sb.ToString(0, (int)charCount);
                     return false;
                 }
             }
         }
     }


}
