using System.Security.Cryptography;

namespace NetWinapiCms;

/// <summary>
/// OIDs for OIW Algorithms
/// </summary>
public static class OiwOids
{
	public static readonly Oid id_sha1 = new("1.3.14.3.2.26", "US Secure Hash Algorithm 1 (SHA1)");
}
