using System;
using System.Buffers;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetWinapiCms.NativeMethods;
using static NetWinapiCms.NativeMethods.Advapi32;
using static NetWinapiCms.NativeMethods.Crypt32;
using static NetWinapiCms.NativeMethods.NCrypt;

namespace NetWinapiCms;

/// <summary>
/// Helper methods for working with CMS
/// </summary>
[SupportedOSPlatform("WINDOWS")]
public static class CmsHelper
{
	public static unsafe byte[] Sign(ReadOnlySpan<byte> data, bool detachedSignature, X509Certificate2 certificate,
			Oid digestOid, bool silent, ReadOnlySpan<char> pin)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			throw new PlatformNotSupportedException();

		// prepare digest OID
		var digestOidLength = Encoding.ASCII.GetByteCount(digestOid.Value ?? throw new ArgumentException("Disget OID is undefined", nameof(digestOid)));
		var digestOidRaw = stackalloc byte[digestOidLength + 1];
		Encoding.ASCII.GetBytes(pin, new Span<byte>(digestOidRaw, digestOidLength));

		// acquire certificate private key
		var flags = (silent ? AcquiringFlags.CRYPT_ACQUIRE_SILENT_FLAG : 0) | AcquiringFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
		CryptAcquireCertificatePrivateKey(certificate.Handle, flags, 0,
			out var hProvider, out var dwKeySpec, out var pfCallerFreeProv).VerifyWinapiTrue();
		try
		{
			if (pin.Length > 0)
			{
				// set PIN-code for the private key
				var asciiPinLength = Encoding.ASCII.GetByteCount(pin);
				var asciiPin = stackalloc byte[asciiPinLength + 1];
				Encoding.ASCII.GetBytes(pin, new Span<byte>(asciiPin, asciiPinLength));
				if (dwKeySpec == AT_KEYEXCHANGE)
					CryptSetProvParam(hProvider, SettableCryptProvParameter.PP_KEYEXCHANGE_PIN, (nint)asciiPin, 0).VerifyWinapiTrue();
				else if (dwKeySpec == AT_SIGNATURE)
					CryptSetProvParam(hProvider, SettableCryptProvParameter.PP_SIGNATURE_PIN, (nint)asciiPin, 0).VerifyWinapiTrue();
			}

			// acquiring certificate context
			var certContext = new ReadOnlySpan<CERT_CONTEXT>(certificate.Handle.ToPointer(), 1);
			var signerCertBlob = new CRYPT_INTEGER_BLOB
			{
				cbData = certContext[0].cbCertEncoded,
				pbData = certContext[0].pbCertEncoded
			};

			// prepare CMSG_SIGNER_ENCODE_INFO structure
			var signerInfo = new CMSG_SIGNER_ENCODE_INFO();
			signerInfo.cbSize = (uint)Marshal.SizeOf(signerInfo);
			signerInfo.pCertInfo = certContext[0].pCertInfo;
			signerInfo.hKey = hProvider;
			signerInfo.dwKeySpec = dwKeySpec;
			signerInfo.HashAlgorithm.pszObjId = (nint)digestOidRaw;

			fixed (byte* pData = data)
			{
				// prepare CMSG_SIGNED_ENCODE_INFO structure
				var signedInfo = new CMSG_SIGNED_ENCODE_INFO();
				signedInfo.cbSize = (uint)Marshal.SizeOf(signedInfo);
				signedInfo.cSigners = 1;
				signedInfo.rgSigners = (nint)(&signerInfo);
				signedInfo.cCertEncoded = 1;
				signedInfo.rgCertEncoded = (nint)(&signerCertBlob);

				// create CMS
				var hMsg = CryptMsgOpenToEncode(MsgEncodingTypes.X509_ASN_ENCODING | MsgEncodingTypes.PKCS_7_ASN_ENCODING,
					detachedSignature ? MsgFlags.CMSG_DETACHED_FLAG : 0, MsgType.CMSG_SIGNED, (nint)(&signedInfo), null, 0).VerifyWinapiNonzero();
				try
				{
					// add, hash, and sign the data
					CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true).VerifyWinapiTrue();

					// extract signed CMS
					var cmsLength = 0;
					CryptMsgGetParam(hMsg, MsgParamType.CMSG_CONTENT_PARAM, 0, 0, ref cmsLength).VerifyWinapiTrue();
					var cms = new byte[cmsLength];
					fixed (byte* pSignature = cms)
						CryptMsgGetParam(hMsg, MsgParamType.CMSG_CONTENT_PARAM, 0, (nint)pSignature, ref cmsLength).VerifyWinapiTrue();
					return cms;
				}
				finally
				{
					CryptMsgClose(hMsg);
				}
			}
		}
		finally
		{
			if (pfCallerFreeProv)
				if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
					NCryptFreeObject(hProvider);
				else
					CryptReleaseContext(hProvider, 0);
		}
	}

	public static unsafe void VerifySignature(ReadOnlySpan<byte> cms, bool detachedSignature, ReadOnlySpan<byte> data,
		bool verifyCertificates = false, X509RevocationMode revocationMode = X509RevocationMode.Online,
		X509RevocationFlag revocationFlag = X509RevocationFlag.ExcludeRoot)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			throw new PlatformNotSupportedException();

		var hMsg = CryptMsgOpenToDecode(MsgEncodingTypes.X509_ASN_ENCODING | MsgEncodingTypes.PKCS_7_ASN_ENCODING,
			detachedSignature ? MsgFlags.CMSG_DETACHED_FLAG : 0, 0, 0, 0, 0).VerifyWinapiNonzero();
		try
		{
			// load signed CMS
			fixed (byte* pCms = cms)
				CryptMsgUpdate(hMsg, (nint)pCms, (uint)cms.Length, true).VerifyWinapiTrue();
			if (detachedSignature)
			{
				if (data.Length > 0)
					// load source data
					fixed (byte* pData = data)
						CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true).VerifyWinapiTrue();
				else
					throw new ArgumentException("The data must be specified for verifying a detached signature.", nameof(data));
			}
			// extract all included certificates from the CMS
			var hCertStore = CertOpenStore(1, 0, 0, 0, hMsg).VerifyWinapiNonzero();
			try
			{
				// determine signer count
				var signerCount = 0U;
				var signerCountSize = Marshal.SizeOf(signerCount);
				CryptMsgGetParam(hMsg, MsgParamType.CMSG_SIGNER_COUNT_PARAM, 0, (nint)(&signerCount), ref signerCountSize).VerifyWinapiTrue();
				if (signerCount == 0)
					throw new Win32Exception(CRYPT_E_NO_SIGNER);

				// verify signature for every signer
				for (var i = 0U; i < signerCount; i++)
				{
					// extract CERT_ID
					nint pCertContext = 0;
					var certIdLength = 0;
					CryptMsgGetParam(hMsg, MsgParamType.CMSG_SIGNER_CERT_ID_PARAM, i, 0, ref certIdLength).VerifyWinapiTrue();
					var certIdRaw = ArrayPool<byte>.Shared.Rent(certIdLength);
					try
					{
						fixed (byte* pCertId = certIdRaw)
						{
							CryptMsgGetParam(hMsg, MsgParamType.CMSG_SIGNER_CERT_ID_PARAM, 0, (nint)pCertId, ref certIdLength).VerifyWinapiTrue();
							pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
								0, CERT_FIND_CERT_ID, (nint)pCertId, 0);
							if (pCertContext == 0)
							{
								var error = Marshal.GetLastWin32Error();
								if (error == CRYPT_E_NOT_FOUND)
									throw new Win32Exception(CRYPT_E_SIGNER_NOT_FOUND);
								else
									throw new Win32Exception(error);
							}
						}
					}
					finally
					{
						ArrayPool<byte>.Shared.Return(certIdRaw, true);
					}

					// validate signature
					var vsp = new CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA();
					vsp.cbSize = (uint)Marshal.SizeOf(vsp);
					vsp.dwSignerIndex = i;
					vsp.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
					vsp.pvSigner = pCertContext;
					CryptMsgControl(hMsg, 0, MsgControlType.CMSG_CTRL_VERIFY_SIGNATURE_EX, (nint)(&vsp)).VerifyWinapiTrue();

					// verify certificates
					if (verifyCertificates)
					{
						nint pChainContext = 0;
						var chainParams = new CERT_CHAIN_PARA();
						chainParams.cbSize = (uint)Marshal.SizeOf(chainParams);
						try
						{
							var flags = 0U;
							if (revocationMode != X509RevocationMode.NoCheck)
							{
								flags = (revocationMode == X509RevocationMode.Offline ? CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY : 0U)
									| revocationFlag switch
									{
										X509RevocationFlag.EndCertificateOnly => CERT_CHAIN_REVOCATION_CHECK_END_CERT,
										X509RevocationFlag.ExcludeRoot => CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
										X509RevocationFlag.EntireChain => CERT_CHAIN_REVOCATION_CHECK_CHAIN,
										_ => 0U
									};
							};
							CertGetCertificateChain(HCCE_CURRENT_USER, pCertContext, 0, 0, (nint)(&chainParams), flags,
								0, (nint)(&pChainContext)).VerifyWinapiTrue();
						}
						finally
						{
							if (pChainContext != 0)
								CertFreeCertificateChain(pChainContext);
						}
					}
				}
			}
			finally
			{
				CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);
			}
		}
		finally
		{
			CryptMsgClose(hMsg);
		}
	}
}
