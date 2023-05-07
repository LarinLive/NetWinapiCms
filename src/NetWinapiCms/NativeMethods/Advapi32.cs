// Copyright © Antoine Larine. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetWinapiCms.NativeMethods;

[SupportedOSPlatform("WINDOWS")]
internal static class Advapi32
{
	public const string Advapi32Lib = "Advapi32.dll";

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


	/// <summary>
	/// Customizes the operations of a cryptographic service provider (CSP). This function is commonly used to set a security descriptor on the key container associated with a CSP to control access to the private keys in that key container.
	/// </summary>
	/// <param name="hProv">The handle of a CSP for which to set values. </param>
	/// <param name="dwParam">Specifies the parameter to set.</param>
	/// <param name="pvData">A pointer to a data buffer that contains the value to be set as a provider parameter. The form of this data varies depending on the dwParam value.</param>
	/// <param name="dwFlags">If dwParam contains PP_KEYSET_SEC_DESCR, dwFlags contains the SECURITY_INFORMATION applicable bit flags, as defined in the Platform SDK.</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE). If the function fails, the return value is zero (FALSE). For extended error information, call GetLastError.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptsetprovparam</remarks>
	[DllImport(Advapi32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptSetProvParam(
		[In] nint hProv,
		[In] uint dwParam,
		[In] nint pvData,
		[In] uint dwFlags
	);

	/// <summary>
	/// Set the window handle that the provider uses as the parent of any dialog boxes it creates. pbData contains a pointer to an HWND that contains the parent window handle.
	/// This parameter must be set before calling CryptAcquireContext because many CSPs will display a user interface when CryptAcquireContext is called. 
	/// You can pass NULL for the hProv parameter to set this window handle for all cryptographic contexts subsequently acquired within this process.
	/// </summary>
	public const uint PP_CLIENT_HWND = 1;

	/// <summary>
	/// Sets the security descriptor on the key storage container. The pbData parameter is the address of a SECURITY_DESCRIPTOR structure that contains the new security descriptor for the key storage container.
	/// </summary>
	public const uint PP_KEYSET_SEC_DESCR = 8;

	/// <summary>
	/// For a smart card provider, sets the search string that is displayed to the user as a prompt to insert the smart card. 
	/// This string is passed as the lpstrSearchDesc member of the OPENCARDNAME_EX structure that is passed to the SCardUIDlgSelectCard function. 
	/// This string is used for the lifetime of the calling process. The pbData parameter is a pointer to a null-terminated Unicode string.
	/// </summary>
	public const uint PP_UI_PROMPT = 21;

	/// <summary>
	/// Delete the ephemeral key associated with a hash, encryption, or verification context. This will free memory and clear registry settings associated with the key.
	/// </summary>
	public const uint PP_DELETEKEY = 24;

	/// <summary>
	/// Specifies that the key exchange PIN is contained in pbData. The PIN is represented as a null-terminated ASCII string.
	/// </summary>
	public const uint PP_KEYEXCHANGE_PIN = 32;

	/// <summary>
	/// Specifies the signature PIN. The pbData parameter is a null-terminated ASCII string that represents the PIN.
	/// </summary>
	public const uint PP_SIGNATURE_PIN = 33;

	/// <summary>
	/// Specifies that the CSP must exclusively use the hardware random number generator (RNG). When PP_USE_HARDWARE_RNG is set, random values are taken exclusively from the hardware RNG and no other sources are used. 
	/// If a hardware RNG is supported by the CSP and it can be exclusively used, the function succeeds and returns TRUE; otherwise, the function fails and returns FALSE. 
	/// The pbData parameter must be NULL and dwFlags must be zero when using this value.
	/// </summary>
	public const uint PP_USE_HARDWARE_RNG = 38;

	/// <summary>
	/// Specifies the user certificate store for the smart card. This certificate store contains all of the user certificates that are stored on the smart card. 
	/// The certificates in this store are encoded by using PKCS_7_ASN_ENCODING or X509_ASN_ENCODING encoding and should contain the CERT_KEY_PROV_INFO_PROP_ID property.		
	/// The pbData parameter is an HCERTSTORE variable that receives the handle of an in-memory certificate store. When this handle is no longer needed, the caller must close it by using the CertCloseStore function.
	/// </summary>
	public const uint PP_USER_CERTSTORE = 42;

	/// <summary>
	/// Specifies the name of the smart card reader. The pbData parameter is the address of an ANSI character array that contains a null-terminated ANSI string that contains the name of the smart card reader.
	/// </summary>
	public const uint PP_SMARTCARD_READER = 43;

	/// <summary>
	/// Sets an alternate prompt string to display to the user when the user's PIN is requested. The pbData parameter is a pointer to a null-terminated Unicode string.
	/// </summary>
	public const uint PP_PIN_PROMPT_STRING = 44;

	/// <summary>
	/// Specifies the identifier of the smart card. The pbData parameter is the address of a GUID structure that contains the identifier of the smart card.
	/// </summary>
	public const uint PP_SMARTCARD_GUID = 45;

	/// <summary>
	/// Sets the root certificate store for the smart card. The provider will copy the root certificates from this store onto the smart card.
	/// The pbData parameter is an HCERTSTORE variable that contains the handle of the new certificate store. 
	/// The provider will copy the certificates from the store during this call, so it is safe to close this store after this function is called.
	/// </summary>
	public const uint PP_ROOT_CERTSTORE = 46;

	/// <summary>
	/// Specifies that an encrypted key exchange PIN is contained in pbData. The pbData parameter contains a <see cref="CRYPT_INTEGER_BLOB"/>.
	/// </summary>
	public const uint PP_SECURE_KEYEXCHANGE_PIN = 47;

	/// <summary>
	/// pecifies that an encrypted signature PIN is contained in pbData. The pbData parameter contains a <see cref="CRYPT_INTEGER_BLOB"/>.
	/// </summary>
	public const uint PP_SECURE_SIGNATURE_PIN = 48;
}
