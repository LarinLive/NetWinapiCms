// Copyright © Antoine Larine, 2023. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
using static NetWinapiCms.NativeMethods.Kernel32;
using static NetWinapiCms.NativeMethods.NCrypt;

namespace NetWinapiCms;

/// <summary>
/// Helper methods for working with CMS
/// </summary>
[SupportedOSPlatform("WINDOWS")]
public static class CmsHelper
{

	/// <summary>
	/// Signs a data with a provided certificate
	/// </summary>
	/// <param name="data">Data to be signed</param>
	/// <param name="detachedSignature">A flag of the detached signature</param>
	/// <param name="certificate">A signing certificate</param>
	/// <param name="digestOid">A data hash algorithm OID</param>
	/// <param name="silent">A flag of the silent cryptographic provider context</param>
	/// <param name="pin">A PIN-code for the private key</param>
	/// <returns>Signed CMS</returns>
	/// <exception cref="PlatformNotSupportedException"></exception>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="Win32Exception"></exception>
	public static unsafe byte[] Sign(ReadOnlySpan<byte> data, bool detachedSignature, X509Certificate2 certificate,
		Oid digestOid, bool silent, ReadOnlySpan<char> pin)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			throw new PlatformNotSupportedException();

		// prepare digest OID
		var digestOidLength = Encoding.ASCII.GetByteCount(digestOid.Value ?? throw new ArgumentException("Disget OID is undefined", nameof(digestOid)));
		var digestOidRaw = stackalloc byte[digestOidLength + 1];
		Encoding.ASCII.GetBytes(digestOid.Value, new Span<byte>(digestOidRaw, digestOidLength));

		// acquiring certificate context
		var certContext = new ReadOnlySpan<CERT_CONTEXT>(certificate.Handle.ToPointer(), 1);
		var signerCertBlob = new CRYPT_INTEGER_BLOB
		{
			cbData = certContext[0].cbCertEncoded,
			pbData = certContext[0].pbCertEncoded
		};

		// acquire certificate private key
		var flags = (silent ? CRYPT_ACQUIRE_SILENT_FLAG : 0U) | CRYPT_ACQUIRE_COMPARE_KEY_FLAG
		   | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG;
		CryptAcquireCertificatePrivateKey(certificate.Handle, flags, 0,
			out var hProvider, out var dwKeySpec, out var pfCallerFreeProv).VerifyWinapiTrue();
		try
		{
			if (pin.Length > 0)
			{
				// set PIN-code for the private key
				if (dwKeySpec == CERT_NCRYPT_KEY_SPEC)
					fixed (char* pPin = pin, pParam = NCRYPT_PIN_PROPERTY)
						NCryptSetProperty(hProvider, (nint)pParam, (nint)pPin, (uint)(pin.Length + 1) * 2, silent ? NCRYPT_SILENT_FLAG : 0U).VerifyWinapiZeroItself();
				else if (dwKeySpec == AT_KEYEXCHANGE || dwKeySpec == AT_SIGNATURE)
				{
					var asciiPinLength = Encoding.ASCII.GetByteCount(pin);
					var asciiPin = stackalloc byte[asciiPinLength + 1];
					var dwParam = dwKeySpec == AT_KEYEXCHANGE ? PP_KEYEXCHANGE_PIN : PP_SIGNATURE_PIN;
					Encoding.ASCII.GetBytes(pin, new Span<byte>(asciiPin, asciiPinLength));
					CryptSetProvParam(hProvider, dwParam, (nint)asciiPin, 0).VerifyWinapiTrue();
				}
			}

			// prepare CMSG_SIGNER_ENCODE_INFO structure
			var signerInfo = new CMSG_SIGNER_ENCODE_INFO();
			signerInfo.pCertInfo = certContext[0].pCertInfo;
			signerInfo.hKey = hProvider;
			signerInfo.dwKeySpec = dwKeySpec;
			signerInfo.HashAlgorithm.pszObjId = (nint)digestOidRaw;

			// prepare CMSG_SIGNED_ENCODE_INFO structure
			var signedInfo = new CMSG_SIGNED_ENCODE_INFO();
			signedInfo.cSigners = 1;
			signedInfo.rgSigners = (nint)(&signerInfo);
			signedInfo.cCertEncoded = 1;
			signedInfo.rgCertEncoded = (nint)(&signerCertBlob);

			// create CMS
			var hMsg = CryptMsgOpenToEncode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, detachedSignature ? CMSG_DETACHED_FLAG : 0U,
				CMSG_SIGNED, (nint)(&signedInfo), null, 0).VerifyWinapiNonzero();
			try
			{
				// add, hash, and sign the data
				fixed (byte* pData = data)
					CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true).VerifyWinapiTrue();

				// extract signed CMS
				var cmsLength = 0U;
				CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, 0, (nint)(&cmsLength)).VerifyWinapiTrue();
				var cms = new byte[cmsLength];
				fixed (byte* pSignature = cms)
					CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, (nint)pSignature, (nint)(&cmsLength)).VerifyWinapiTrue();
				return cms;
			}
			finally
			{
				CryptMsgClose(hMsg);
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

	private static unsafe void VerifyOneSigner(nint hMsg, nint hCertStore, uint signerIndex, bool verifyCertificates, uint chainFlags)
	{
		// extract CERT_ID
		nint pCertContext = 0;
		var certIdLength = 0;
		CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_ID_PARAM, signerIndex, 0, (nint)(&certIdLength)).VerifyWinapiTrue();
		var certIdRaw = ArrayPool<byte>.Shared.Rent(certIdLength);
		try
		{
			fixed (byte* pCertId = certIdRaw)
			{
				CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_ID_PARAM, signerIndex, (nint)pCertId, (nint)(&certIdLength)).VerifyWinapiTrue();
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

		// validate the digital signature itself
		var vsp = new CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA();
		vsp.dwSignerIndex = signerIndex;
		vsp.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
		vsp.pvSigner = pCertContext;
		CryptMsgControl(hMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, (nint)(&vsp)).VerifyWinapiTrue();

		if (verifyCertificates)
		{
			// validate certificates
			nint pChainContext = 0;
			var chainParams = new CERT_CHAIN_PARA();
			CertGetCertificateChain(HCCE_CURRENT_USER, pCertContext, 0, hCertStore, (nint)(&chainParams), chainFlags,
				0, (nint)(&pChainContext)).VerifyWinapiTrue();
			if (pChainContext != 0)
				try
				{
					var policyStatus = new CERT_CHAIN_POLICY_STATUS();
					CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext, 0, (nint)(&policyStatus)).VerifyWinapiTrue();
					policyStatus.dwError.VerifyWinapiZeroItself();
					CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASIC_CONSTRAINTS, pChainContext, 0, (nint)(&policyStatus)).VerifyWinapiTrue();
					policyStatus.dwError.VerifyWinapiZeroItself();
				}
				finally
				{
					CertFreeCertificateChain(pChainContext);
				}
		}
	}

	/// <summary>
	/// Verifies all signatures in a CMS
	/// </summary>
	/// <param name="cms">A CMS whose signatures should be verified</param>
	/// <param name="detachedSignature">A flag of the detached signature</param>
	/// <param name="data">Source data</param>
	/// <param name="verifyCertificates">If true also verifies certificates themselves</param>
	/// <param name="revocationMode">A X509 certificate revocation checking mode</param>
	/// <param name="revocationFlag">A X509 certificate revocation checking flag</param>
	/// <param name="revocationFlag">A X509 certificate revocation checking flag</param>
	/// <exception cref="PlatformNotSupportedException"></exception>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="Win32Exception"></exception>
	public static unsafe void Verify(ReadOnlySpan<byte> cms, bool detachedSignature, ReadOnlySpan<byte> data,
		bool verifyCertificates = true, X509RevocationMode revocationMode = X509RevocationMode.Online,
		X509RevocationFlag revocationFlag = X509RevocationFlag.ExcludeRoot)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			throw new PlatformNotSupportedException();

		var hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, detachedSignature ? CMSG_DETACHED_FLAG : 0U, 0, 0, 0, 0)
			.VerifyWinapiNonzero();
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
			// extract all included certificates from the CMS as cert store
			var hCertStore = CertOpenStore(CERT_STORE_PROV_MSG, 0, 0, 0, hMsg).VerifyWinapiNonzero();
			try
			{
				// determine signer count
				uint signerCount;
				var signerCountSize = Marshal.SizeOf<uint>();
				CryptMsgGetParam(hMsg, CMSG_SIGNER_COUNT_PARAM, 0, (nint)(&signerCount), (nint)(&signerCountSize)).VerifyWinapiTrue();
				if (signerCount == 0U)
					throw new Win32Exception(CRYPT_E_NO_SIGNER);

				var chainFlags = CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
				if (verifyCertificates && revocationMode != X509RevocationMode.NoCheck)
					chainFlags |= (revocationMode == X509RevocationMode.Offline ? CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY : 0U)
						| revocationFlag switch
						{
							X509RevocationFlag.EndCertificateOnly => CERT_CHAIN_REVOCATION_CHECK_END_CERT,
							X509RevocationFlag.ExcludeRoot => CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
							X509RevocationFlag.EntireChain => CERT_CHAIN_REVOCATION_CHECK_CHAIN,
							_ => 0U
						};

				// verify signature for every signer
				for (var i = 0U; i < signerCount; i++)
					VerifyOneSigner(hMsg, hCertStore, i, verifyCertificates, chainFlags);
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


	/// <summary>
	/// Calculates a timestamp token for a given data
	/// </summary>
	/// <param name="data">A source binary data for timestamping</param>
	/// <param name="tspDigestOid">An OID of a message digest algorithm</param>
	/// <param name="nonce">A nonce value, can be empty</param>
	/// <param name="tsaUri">An URI of a TSA</param>
	/// <param name="timeout">A TSA request timeout</param>
	/// <returns>A timestamp token in DER encoding</returns>
	public static unsafe byte[] RetriveTimestamp(ReadOnlySpan<byte> data, Oid tspDigestOid, ReadOnlySpan<byte> nonce, string tsaUri, TimeSpan timeout)
	{
		var tspReq = new CRYPT_TIMESTAMP_PARA();
		tspReq.fRequestCerts = true;
		fixed (byte* pData = data, pNonce = nonce)
		{
			if (nonce.Length > 0)
			{
				tspReq.Nonce.cbData = (uint)nonce.Length;
				tspReq.Nonce.pbData = (nint)pNonce;
			}

			nint pTsContext;
			CryptRetrieveTimeStamp(tsaUri, TIMESTAMP_NO_AUTH_RETRIEVAL | TIMESTAMP_VERIFY_CONTEXT_SIGNATURE,
				timeout.Milliseconds, tspDigestOid.Value, (nint)(&tspReq), (nint)pData, (uint)data.Length,
				(nint)(&pTsContext), 0, 0).VerifyWinapiTrue();
			try
			{
				var tsContext = new ReadOnlySpan<CRYPT_TIMESTAMP_CONTEXT>(pTsContext.ToPointer(), 1);
				var tst = new ReadOnlySpan<byte>(tsContext[0].pbEncoded.ToPointer(), (int)tsContext[0].cbEncoded);
				return tst.ToArray();
			}
			finally
			{
				if (pTsContext != 0)
					CryptMemFree(pTsContext);
			}
		}
	}

	/// <summary>
	/// Calculates and adds a timestamp token to a CMS message as an unsigned attribute
	/// </summary>
	/// <param name="cms">A target CMS message</param>
	/// <param name="detachedSignature">A flag of the detached signature in the CMS</param>
	/// <param name="signerIndex">An index of the CMS signer</param>
	/// <param name="tspDigestOid">An OID of a message digest algorithm</param>
	/// <param name="nonce">A nonce value, can be empty</param>
	/// <param name="tsaUri">An URI of a TSA</param>
	/// <param name="timeout">A TSA request timeout</param>
	/// <returns>A new CMS message with an injected timestamp token</returns>
	public static unsafe byte[] AddTimestampToCms(ReadOnlySpan<byte> cms, bool detachedSignature, uint signerIndex,
		Oid tspDigestOid, ReadOnlySpan<byte> nonce, string tsaUri, TimeSpan timeout)
	{
		var hMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, detachedSignature ? CMSG_DETACHED_FLAG : 0U, 0, 0, 0, 0)
			.VerifyWinapiNonzero();
		try
		{
			// load the CMS signed message
			fixed (byte* pCms = cms)
				CryptMsgUpdate(hMsg, (nint)pCms, (uint)cms.Length, true).VerifyWinapiTrue();

			// extract the signature from the CMS message for the specified signerIndex
			var signatureLength = 0;
			CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, signerIndex, 0, (nint)(&signatureLength)).VerifyWinapiTrue();
			var signature = stackalloc byte[signatureLength];
			CryptMsgGetParam(hMsg, CMSG_ENCRYPTED_DIGEST, signerIndex, (nint)signature, (nint)(&signatureLength)).VerifyWinapiTrue();

			// receive timestamp on the extracted signature
			var tst = RetriveTimestamp(new ReadOnlySpan<byte>(signature, signatureLength), tspDigestOid, nonce, tsaUri, timeout);

			// add a new unsigned attribute
			fixed (byte* pzdObjId = "1.2.840.113549.1.9.16.2.14"u8, pTst = tst)
			{
				var tstBlob = new CRYPT_INTEGER_BLOB();
				tstBlob.cbData = (uint)tst.Length;
				tstBlob.pbData = (nint)pTst;

				var tstAttr = new CRYPT_ATTRIBUTE();
				tstAttr.pszObjId = (nint)pzdObjId;
				tstAttr.cValue = 1;
				tstAttr.rgValue = (nint)(&tstBlob);

				// encode a timestamp attribute to DER
				var attr = (nint)0;
				var attrLen = 0U;
				CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_ATTRIBUTE, (nint)(&tstAttr), CRYPT_ENCODE_ALLOC_FLAG,
					0, (nint)(&attr), (nint)(&attrLen)).VerifyWinapiTrue();
				try
				{
					// inject the encoded unsigned attribute to the SignerInfo
					var cmsAttr = new CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA();
					cmsAttr.dwSignerIndex = signerIndex;
					cmsAttr.blob.cbData = attrLen;
					cmsAttr.blob.pbData = attr;
					CryptMsgControl(hMsg, 0, CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, (nint)(&cmsAttr)).VerifyWinapiTrue();
				}
				finally
				{
					LocalFree(attr).VerifyWinapiZero();
				}
			}

			// extract the updated CMS message
			uint updatedCmsLength = 0;
			CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, 0, (nint)(&updatedCmsLength)).VerifyWinapiTrue();
			var updatedCms = new byte[updatedCmsLength];
			fixed (byte* pUpdatedCms = updatedCms)
				CryptMsgGetParam(hMsg, CMSG_ENCODED_MESSAGE, 0, (nint)pUpdatedCms, (nint)(&updatedCmsLength)).VerifyWinapiTrue();
			return updatedCms;
		}
		finally
		{
			CryptMsgClose(hMsg);
		}
	}
}
