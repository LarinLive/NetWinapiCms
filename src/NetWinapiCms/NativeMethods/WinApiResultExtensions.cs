using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NetWinapiCms.NativeMethods;

/// <summary>
/// Extension methods for checking WinAPI result values
/// </summary>
internal static class WinApiResultExtensions
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool VerifyWinapiResult(this bool input)
	{
		return input ? input : throw new Win32Exception(Marshal.GetLastPInvokeError());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static nint VerifyWinapiResult(this nint input)
	{
		return input != 0 ? input : throw new Win32Exception(Marshal.GetLastPInvokeError());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static uint VerifyWinapiResult(this uint input)
	{
		return input != 0 ? input : throw new Win32Exception(Marshal.GetLastPInvokeError());
	}


	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int VerifySelfWinapiResult(this int result)
	{
		return result == 0 ? result : throw new Win32Exception(result);
	}
}
