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
}
