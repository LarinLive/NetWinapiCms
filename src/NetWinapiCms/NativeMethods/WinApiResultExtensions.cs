using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NetWinapiCms.NativeMethods;

/// <summary>
/// Extension methods for checking WinAPI result values
/// </summary>
internal static class WinApiResultExtensions
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool VerifyWinapiTrue(this bool input)
	{
		return input ? input : throw new Win32Exception(Marshal.GetLastPInvokeError());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static nint VerifyWinapiNonzero(this nint input)
	{
		return input != 0 ? input : throw new Win32Exception(Marshal.GetLastPInvokeError());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint VerifyWinapiNonzero(this uint input)
	{
		return input != 0 ? input : throw new Win32Exception(Marshal.GetLastPInvokeError());
	}


	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int VerifySelfWinapiZero(this int result)
	{
		return result == 0 ? result : throw new Win32Exception(result);
	}
}
