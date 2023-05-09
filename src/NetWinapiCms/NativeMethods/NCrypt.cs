// Copyright © Antoine Larine. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetWinapiCms.NativeMethods;

[SupportedOSPlatform("WINDOWS")]
internal static class NCrypt
{
	public const string NCryptLib = "NCrypt.dll";

	/// <summary>
	/// Frees a CNG key storage object
	/// </summary>
	/// <param name="hObject">The handle of the object to free. This can be either a provider handle (NCRYPT_PROV_HANDLE) or a key handle (NCRYPT_KEY_HANDLE)</param>
	/// <returns>Returns a status code that indicates the success or failure of the function./returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject</remarks>
	[DllImport(NCryptLib, CharSet = CharSet.Unicode)]
	public static extern int NCryptFreeObject(
		[In] nint hObject
	);

	/// <summary>
	/// Sets the value for a named property for a CNG key storage object.
	/// </summary>
	/// <param name="hObject">The handle of the key storage object to set the property for.</param>
	/// <param name="pszProperty">A pointer to a null-terminated Unicode string that contains the name of the property to set. 
	/// This can be one of the predefined Key Storage Property Identifiers or a custom property identifier.</param>
	/// <param name="pbInput">The address of a buffer that contains the new property value. The cbInput parameter contains the size of this buffer.</param>
	/// <param name="cbInput">The size, in bytes, of the pbInput buffer.</param>
	/// <param name="dwFlags">Flags that modify function behavior.</param>
	/// <returns>Returns a status code that indicates the success or failure of the function.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty</remarks>
	[DllImport(NCryptLib, CharSet = CharSet.Unicode)]
	public static extern int NCryptSetProperty(
		[In] nint hObject,
		[In] nint pszProperty,
		[In] nint pbInput,
		[In] uint cbInput,
		[In] uint dwFlags
	);

	/// <summary>
	/// Maximum length of property data (in bytes) 
	/// </summary>
	public const uint NCRYPT_MAX_PROPERTY_DATA = 0x100000;

	/// <summary>
	/// Do not overwrite any built-in values for this property and only set the user-persisted properties of the key. The maximum size of the data for any persisted property is NCRYPT_MAX_PROPERTY_DATA bytes. 
	/// This flag cannot be used with the NCRYPT_SECURITY_DESCR_PROPERTY property.
	/// </summary>
	public const uint NCRYPT_PERSIST_ONLY_FLAG = 0x40000000;

	/// <summary>
	/// The property should be stored in key storage along with the key material. This flag can only be used when the hObject parameter is the handle of a persisted key. 
	/// The maximum size of the data for any persisted property is NCRYPT_MAX_PROPERTY_DATA bytes.
	/// </summary>
	public const uint NCRYPT_PERSIST_FLAG = 0x80000000;

	/// <summary>
	/// Requests that the key service provider (KSP) not display any user interface. If the provider must display the UI to operate, the call fails and the KSP should set the NTE_SILENT_CONTEXT error code as the last error.
	/// </summary>
	public const uint NCRYPT_SILENT_FLAG = 0x00000040;

	/// <summary>
	/// A pointer to a null-terminated Unicode string that contains the PIN. The PIN is used for a smart card key or the password for a password-protected key stored in a software-based KSP. 
	/// This property can only be set. Microsoft KSPs will cache this value so that the user is only prompted once per process.
	/// </summary>
	public const string NCRYPT_PIN_PROPERTY = "SmartCardPin";
}
