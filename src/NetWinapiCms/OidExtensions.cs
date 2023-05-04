using System.Security.Cryptography;

namespace NetWinapiCms;
	
/// <summary>
/// Extension methods for the <see cref="Oid"/> class
/// </summary>
public static class OidExtensions
{
	public static Oid Branch(this Oid parent, string value, string? friendlyName)
	{
		var oid = new Oid((!string.IsNullOrEmpty(parent.Value) ? parent.Value + '.' : "") + value, friendlyName);
		return oid;
	}
}

