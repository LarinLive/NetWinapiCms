using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System;
using System.Runtime.Versioning;
using NetWinapiCms.NativeMethods;
using static NetWinapiCms.NativeMethods.Advapi32;
using static NetWinapiCms.NativeMethods.Crypt32;
using static NetWinapiCms.NativeMethods.NCrypt;

namespace NetWinapiCms;

[SupportedOSPlatform("WINDOWS")]
public static class CmsSigner
{
	public static unsafe byte[] SignCms(ReadOnlySpan<byte> data, bool detachedSignature, X509Certificate2 certificate, bool silent, ReadOnlySpan<char> pin)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			throw new PlatformNotSupportedException();

		var flags = (silent ? AcquiringFlags.CRYPT_ACQUIRE_SILENT_FLAG : 0) | AcquiringFlags.CRYPT_ACQUIRE_COMPARE_KEY_FLAG;
		CryptAcquireCertificatePrivateKey(certificate.Handle, flags, 0,
			out var hKey, out var dwKeySpec, out var pfCallerFreeProv).VerifyWinapiResult();
		try
		{
			if (pin.Length > 0)
			{
				Span<byte> asciiPin = stackalloc byte[Encoding.ASCII.GetByteCount(pin) + 1];
				Encoding.ASCII.GetBytes(pin, asciiPin);
				if (dwKeySpec == PrivateKeySpec.AT_KEYEXCHANGE)
					fixed (byte* pPin = asciiPin)
						CryptSetProvParam(hKey, SettableCryptProvParameter.PP_KEYEXCHANGE_PIN, (nint)pPin, 0).VerifyWinapiResult();
				else if (dwKeySpec == PrivateKeySpec.AT_SIGNATURE)
					fixed (byte* pPin = asciiPin)
						CryptSetProvParam(hKey, SettableCryptProvParameter.PP_SIGNATURE_PIN, (nint)pPin, 0).VerifyWinapiResult();
			}

			var certContext = new Span<CERT_CONTEXT>(certificate.Handle.ToPointer(), 1);

			var signerInfo = new CMSG_SIGNER_ENCODE_INFO();
			signerInfo.cbSize = (uint)Marshal.SizeOf(signerInfo);
			signerInfo.pCertInfo = certContext[0].pCertInfo;
			signerInfo.hKey = hKey;
			signerInfo.dwKeySpec = dwKeySpec;

			byte[] digestOid;
			if (certificate.PublicKey.Oid.Value == OID_ALG_SIGN_GOST_2012_256)
				digestOid = szOID_ALG_DIGEST_GOST_2012_256;
			else if (certificate.PublicKey.Oid.Value == OID_ALG_SIGN_GOST_2012_512)
				digestOid = szOID_ALG_DIGEST_GOST_2012_512;
			else if (certificate.PublicKey.Oid.Value == OID_ALG_SIGN_GOST_2001)
				digestOid = szOID_ALG_DIGEST_GOST_94;
			else
				digestOid = szOID_ALG_DIGEST_SHA_256;

			fixed (byte* pDigestOid = digestOid, pData = data)
			{
				signerInfo.HashAlgorithm.pszObjId = (nint)pDigestOid;

				var signerCertBlob = new CRYPT_INTEGER_BLOB
				{
					cbData = certContext[0].cbCertEncoded,
					pbData = certContext[0].pbCertEncoded
				};

				var signedInfo = new CMSG_SIGNED_ENCODE_INFO();

				signedInfo.cbSize = (uint)Marshal.SizeOf(signedInfo);
				signedInfo.cSigners = 1;
				signedInfo.rgSigners = (nint)(&signerInfo);
				signedInfo.cCertEncoded = 1;
				signedInfo.rgCertEncoded = (nint)(&signerCertBlob);

				var hMsg = CryptMsgOpenToEncode(MsgEncodingTypes.X509_ASN_ENCODING | MsgEncodingTypes.PKCS_7_ASN_ENCODING,
					detachedSignature ? MsgFlags.CMSG_DETACHED_FLAG : 0, MsgType.CMSG_SIGNED, (nint)(&signedInfo), null, 0).VerifyWinapiResult();
				try
				{
					CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true).VerifyWinapiResult();
					var cmsLength = 0U;
					CryptMsgGetParam(hMsg, MsgParamType.CMSG_CONTENT_PARAM, 0, 0, ref cmsLength).VerifyWinapiResult();
					var cms = new byte[cmsLength];
					fixed (byte* pSignature = cms)
						CryptMsgGetParam(hMsg, MsgParamType.CMSG_CONTENT_PARAM, 0, (nint)pSignature, ref cmsLength).VerifyWinapiResult();
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
				if (dwKeySpec == PrivateKeySpec.CERT_NCRYPT_KEY_SPEC)
					NCryptFreeObject(hKey);
				else
					CryptReleaseContext(hKey, 0);
		}
	}

	public static unsafe void VerifyCmsSignature(ReadOnlySpan<byte> cms, bool detachedSignature, ReadOnlySpan<byte> data)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			throw new PlatformNotSupportedException();

		var hMsg = CryptMsgOpenToDecode(MsgEncodingTypes.X509_ASN_ENCODING | MsgEncodingTypes.PKCS_7_ASN_ENCODING,
			detachedSignature ? MsgFlags.CMSG_DETACHED_FLAG : 0, 0, 0, 0, 0).VerifyWinapiResult();
		try
		{
			fixed (byte* pCms = cms)
				// load signed CMS
				CryptMsgUpdate(hMsg, (nint)pCms, (uint)cms.Length, true).VerifyWinapiResult();
			if (detachedSignature)
			{
				if (data.Length > 0)
					fixed (byte* pData = data)
						// load source data
						CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true).VerifyWinapiResult();
				else
					throw new ArgumentException("The data must be specified for verifying a detached signature.", nameof(data));
			}

			// check signature for the first signer
			var certBlobLength = 0U;
			CryptMsgGetParam(hMsg, MsgParamType.CMSG_CERT_PARAM, 0, 0, ref certBlobLength).VerifyWinapiResult();
			Span<byte> certBlob = stackalloc byte[(int)certBlobLength];
			nint pCertContext;
			fixed (byte* pCertBlob = certBlob)
			{
				CryptMsgGetParam(hMsg, MsgParamType.CMSG_CERT_PARAM, 0, (nint)pCertBlob, ref certBlobLength).VerifyWinapiResult();
				// create certificate context
				pCertContext = CertCreateCertificateContext(CertEncodingTypes.X509_ASN_ENCODING | CertEncodingTypes.PKCS_7_ASN_ENCODING,
					(nint)pCertBlob, (uint)certBlob.Length).VerifyWinapiResult();
			}
			try
			{
				// validate signature
				var vsp = new CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA();
				vsp.cbSize = (uint)Marshal.SizeOf(vsp);
				vsp.dwSignerIndex = 0;
				vsp.dwSignerType = CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA.SignerType.CMSG_VERIFY_SIGNER_CERT;
				vsp.pvSigner = pCertContext;
				CryptMsgControl(hMsg, 0, MsgControlType.CMSG_CTRL_VERIFY_SIGNATURE_EX, (nint)(&vsp)).VerifyWinapiResult();
			}
			finally
			{
				CertFreeCertificateContext(pCertContext);
			}
		}
		finally
		{
			CryptMsgClose(hMsg);
		}
	}
}
