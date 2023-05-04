using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace NetWinapiCms.NativeMethods;

[SupportedOSPlatform("WINDOWS")]
internal static class Advapi32
{
	public const string Advapi32Lib = "Advapi32.dll";




	public readonly static string OID_ALG_SIGN_GOST_2001 = "1.2.643.2.2.19";
	public readonly static string OID_ALG_SIGN_GOST_2012_256 = "1.2.643.7.1.1.1.1";
	public readonly static string OID_ALG_SIGN_GOST_2012_512 = "1.2.643.7.1.1.1.2";
	public readonly static string OID_ALG_DIGEST_GOST_94 = "1.2.643.2.2.9";
	public readonly static string OID_ALG_DIGEST_GOST_2012_256 = "1.2.643.7.1.1.2.2";
	public readonly static string OID_ALG_DIGEST_GOST_2012_512 = "1.2.643.7.1.1.2.3";
	public readonly static string OID_ALG_DIGEST_SHA_1 = "1.3.14.3.2.26";
	public readonly static string OID_ALG_DIGEST_SHA_256 = "2.16.840.1.101.3.4.2.1";

	public readonly static byte[] szOID_ALG_SIGN_GOST_2001 = Encoding.UTF8.GetBytes(OID_ALG_SIGN_GOST_2001);
	public readonly static byte[] szOID_ALG_SIGN_GOST_2012_256 = Encoding.UTF8.GetBytes(OID_ALG_SIGN_GOST_2012_256);
	public readonly static byte[] szOID_ALG_SIGN_GOST_2012_512 = Encoding.UTF8.GetBytes(OID_ALG_SIGN_GOST_2012_512);
	public readonly static byte[] szOID_ALG_DIGEST_GOST_94 = Encoding.UTF8.GetBytes(OID_ALG_DIGEST_GOST_94);
	public readonly static byte[] szOID_ALG_DIGEST_GOST_2012_256 = Encoding.UTF8.GetBytes(OID_ALG_DIGEST_GOST_2012_256);
	public readonly static byte[] szOID_ALG_DIGEST_GOST_2012_512 = Encoding.UTF8.GetBytes(OID_ALG_DIGEST_GOST_2012_512);
	public readonly static byte[] szOID_ALG_DIGEST_SHA_256 = Encoding.UTF8.GetBytes(OID_ALG_DIGEST_SHA_256);


	/// <summary>
	/// The CryptReleaseContext function releases the handle of a cryptographic service provider (CSP) and a key container.
	/// At each call to this function, the reference count on the CSP is reduced by one. When the reference count reaches zero,
	/// the context is fully released and it can no longer be used by any function in the application.
	/// </summary>
	/// <param name="hProv">Handle of a cryptographic service provider (CSP) created by a call to CryptAcquireContext</param>
	/// <param name="dwFlags">Reserved for future use and must be zero. If dwFlags is not set to zero, this function returns FALSE but the CSP is released.</param>
	/// <returns></returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext</remarks>
	[DllImport(Advapi32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptReleaseContext(
		[In] nint hProv,
		[In] uint dwFlags
	);


	[DllImport(Advapi32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptSetProvParam(
		[In] nint hProv,
		[In] SettableCryptProvParameter dwParam,
		[In] nint pvData,
		[In] uint dwFlags
	);

	/// <summary>
	/// Values for the CryptSetProvParam.dwParam parameter
	/// </summary>
	public enum SettableCryptProvParameter : uint
	{
		/// <summary>
		/// Set the window handle that the provider uses as the parent of any dialog boxes it creates. pbData contains a pointer to an HWND that contains the parent window handle.
		/// This parameter must be set before calling CryptAcquireContext because many CSPs will display a user interface when CryptAcquireContext is called. 
		/// You can pass NULL for the hProv parameter to set this window handle for all cryptographic contexts subsequently acquired within this process.
		/// </summary>
		PP_CLIENT_HWND = 1,

		/// <summary>
		/// Sets the security descriptor on the key storage container. The pbData parameter is the address of a SECURITY_DESCRIPTOR structure that contains the new security descriptor for the key storage container.
		/// </summary>
		PP_KEYSET_SEC_DESCR = 8,

		/// <summary>
		/// For a smart card provider, sets the search string that is displayed to the user as a prompt to insert the smart card. 
		/// This string is passed as the lpstrSearchDesc member of the OPENCARDNAME_EX structure that is passed to the SCardUIDlgSelectCard function. 
		/// This string is used for the lifetime of the calling process. The pbData parameter is a pointer to a null-terminated Unicode string.
		/// </summary>
		PP_UI_PROMPT = 21,

		/// <summary>
		/// Delete the ephemeral key associated with a hash, encryption, or verification context. This will free memory and clear registry settings associated with the key.
		/// </summary>
		PP_DELETEKEY = 24,

		/// <summary>
		/// Specifies that the key exchange PIN is contained in pbData. The PIN is represented as a null-terminated ASCII string.
		/// </summary>
		PP_KEYEXCHANGE_PIN = 32,

		/// <summary>
		/// Specifies the signature PIN. The pbData parameter is a null-terminated ASCII string that represents the PIN.
		/// </summary>
		PP_SIGNATURE_PIN = 33,

		/// <summary>
		/// Specifies that the CSP must exclusively use the hardware random number generator (RNG). When PP_USE_HARDWARE_RNG is set, random values are taken exclusively from the hardware RNG and no other sources are used. 
		/// If a hardware RNG is supported by the CSP and it can be exclusively used, the function succeeds and returns TRUE; otherwise, the function fails and returns FALSE. 
		/// The pbData parameter must be NULL and dwFlags must be zero when using this value.
		/// </summary>
		PP_USE_HARDWARE_RNG = 38,

		/// <summary>
		/// Specifies the user certificate store for the smart card. This certificate store contains all of the user certificates that are stored on the smart card. 
		/// The certificates in this store are encoded by using PKCS_7_ASN_ENCODING or X509_ASN_ENCODING encoding and should contain the CERT_KEY_PROV_INFO_PROP_ID property.		
		/// The pbData parameter is an HCERTSTORE variable that receives the handle of an in-memory certificate store. When this handle is no longer needed, the caller must close it by using the CertCloseStore function.
		/// </summary>
		PP_USER_CERTSTORE = 42,

		/// <summary>
		/// Specifies the name of the smart card reader. The pbData parameter is the address of an ANSI character array that contains a null-terminated ANSI string that contains the name of the smart card reader.
		/// </summary>
		PP_SMARTCARD_READER = 43,

		/// <summary>
		/// Sets an alternate prompt string to display to the user when the user's PIN is requested. The pbData parameter is a pointer to a null-terminated Unicode string.
		/// </summary>
		PP_PIN_PROMPT_STRING = 44,

		/// <summary>
		/// Specifies the identifier of the smart card. The pbData parameter is the address of a GUID structure that contains the identifier of the smart card.
		/// </summary>
		PP_SMARTCARD_GUID = 45,

		/// <summary>
		/// Sets the root certificate store for the smart card. The provider will copy the root certificates from this store onto the smart card.
		/// The pbData parameter is an HCERTSTORE variable that contains the handle of the new certificate store. 
		/// The provider will copy the certificates from the store during this call, so it is safe to close this store after this function is called.
		/// </summary>
		PP_ROOT_CERTSTORE = 46,

		/// <summary>
		/// Specifies that an encrypted key exchange PIN is contained in pbData. The pbData parameter contains a <see cref="CRYPT_INTEGER_BLOB"/>.
		/// </summary>
		PP_SECURE_KEYEXCHANGE_PIN = 47,

		/// <summary>
		/// pecifies that an encrypted signature PIN is contained in pbData. The pbData parameter contains a <see cref="CRYPT_INTEGER_BLOB"/>.
		/// </summary>
		PP_SECURE_SIGNATURE_PIN = 48
	}
}
