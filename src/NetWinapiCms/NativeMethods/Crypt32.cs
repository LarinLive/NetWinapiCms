using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace NetWinapiCms.NativeMethods;

[SupportedOSPlatform("WINDOWS")]
internal static class Crypt32
{
	public const string Crypt32Lib = "Crypt32.dll";

	/// <summary>
	/// Contains both the encoded and decoded representations of a certificate
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_CONTEXT
	{
		/// <summary>
		/// Type of encoding used
		/// </summary>
		public uint dwCertEncodingType;

		/// <summary>
		/// A pointer to a buffer that contains the encoded certificate
		/// </summary>
		public nint pbCertEncoded;

		/// <summary>
		/// The size, in bytes, of the encoded certificate
		/// </summary>
		public uint cbCertEncoded;

		/// <summary>
		/// The address of a <see cref="CERT_INFO"/> structure that contains the certificate information
		/// </summary>
		public nint pCertInfo;

		/// <summary>
		/// A handle to the certificate store that contains the certificate context
		/// </summary>
		public nint hCertStore;
	}

	/// <summary>
	/// Contains the extension information for a certificate, Certificate Revocation List (CRL) or Certificate Trust List (CTL).
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_extension</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_EXTENSION
	{
		/// <summary>
		/// Object identifier (OID) that specifies the structure of the extension data contained in the Value member.
		/// </summary>
		public nint pszObjId;

		/// <summary>
		/// If TRUE, any limitations specified by the extension in the Value member of this structure are imperative. If FALSE, limitations set by this extension can be ignored
		/// </summary>
		public bool fCritical;

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the encoded extension data. The cbData member of Value indicates the length in bytes of the pbData member. 
		/// The pbData member byte string is the encoded extension.
		/// </summary>
		public CRYPT_INTEGER_BLOB Value;
	}

	/// <summary>
	/// This structure is used as a flexible means of uniquely identifying a certificate
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_id</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_ID
	{
		/// <summary>
		/// Indicates which member of the union is being used
		/// </summary>
		public IdChoice dwIdChoice;

		/// <summary>
		/// If TRUE, any limitations specified by the extension in the Value member of this structure are imperative. If FALSE, limitations set by this extension can be ignored
		/// </summary>
		public CERT_ISSUER_SERIAL_NUMBER Value;

		public enum IdChoice : uint
		{
			/// <summary>
			/// IssuerSerialNumber
			/// </summary>
			CERT_ID_ISSUER_SERIAL_NUMBER = 1,

			/// <summary>
			/// KeyId
			/// </summary>
			CERT_ID_KEY_IDENTIFIER = 2,

			/// <summary>
			/// HashId
			/// </summary>
			CERT_ID_SHA1_HASH = 3
		}
	}


	/// <summary>
	/// This CryptoAPI structure is used for an arbitrary array of bytes. It is declared in Wincrypt.h and provides flexibility for objects that can contain various data types.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_INFO
	{
		/// <summary>
		/// The version number of a certificate
		/// </summary>
		public Version dwVersion;

		/// <summary>
		/// A BLOB that contains the serial number of a certificate. The least significant byte is the zero byte of the pbData member of SerialNumber. 
		/// The index for the last byte of pbData, is one less than the value of the cbData member of SerialNumber. The most significant byte is the last byte of pbData
		/// </summary>
		public CRYPT_INTEGER_BLOB SerialNumber;

		/// <summary>
		/// A <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure that contains the signature algorithm type and encoded additional encryption parameters
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;

		/// <summary>
		/// The name, in encoded form, of the issuer of the certificate
		/// </summary>
		public CRYPT_INTEGER_BLOB Issuer;

		/// <summary>
		/// Date and time before which the certificate is not valid
		/// </summary>
		public FILETIME NotBefore;

		/// <summary>
		/// Date and time after which the certificate is not valid
		/// </summary>
		public FILETIME NotAfter;

		/// <summary>
		/// The encoded name of the subject of the certificate
		/// </summary>
		public CRYPT_INTEGER_BLOB Subject;

		/// <summary>
		/// A <see cref="CERT_PUBLIC_KEY_INFO"/> structure that contains the encoded public key and its algorithm
		/// </summary>
		public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;

		/// <summary>
		/// A BLOB that contains a unique identifier of the issuer
		/// </summary>
		public CRYPT_BIT_BLOB IssuerUniqueId;

		/// <summary>
		/// A BLOB that contains a unique identifier of the subject
		/// </summary>
		public CRYPT_BIT_BLOB SubjectUniqueId;

		/// <summary>
		/// The number of elements in the rgExtension array
		/// </summary>
		public uint cExtension;

		/// <summary>
		/// An array of pointers to <see cref="CERT_EXTENSION"/> structures, each of which contains extension information about the certificate
		/// </summary>
		public nint rgExtension;

		/// <summary>
		/// The version number of a certificate
		/// </summary>
		public enum Version : uint
		{
			/// <summary>
			/// Version 1
			/// </summary>
			CERT_V1 = 0,

			/// <summary>
			/// Version 2
			/// </summary>
			CERT_V2 = 1,

			/// <summary>
			/// Version 3
			/// </summary>
			CERT_V3 = 2
		}
	}



	/// <summary>
	/// Acts as a unique identifier of a certificate containing the issuer and issuer's serial number for a certificate
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_issuer_serial_number</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_ISSUER_SERIAL_NUMBER
	{
		/// <summary>
		/// A BLOB structure that contains the name of the issuer
		/// </summaryCERT_NAME_BLOB     
		public CRYPT_ALGORITHM_IDENTIFIER Issuer;

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the serial number of the certificate. The combination of the issuer name and the serial number is a unique identifier of a certificate
		/// </summary>
		public CRYPT_INTEGER_BLOB SerialNumber;
	}

	/// <summary>
	/// Contains a public key and its algorithm
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_public_key_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_PUBLIC_KEY_INFO
	{
		/// <summary>
		/// Contains the public key algorithm type and associated additional parameters
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER Algorithm;

		/// <summary>
		/// BLOB containing an encoded public key
		/// </summary>
		public CRYPT_BIT_BLOB PublicKey;
	}


	/// <summary>
	/// Creates a certificate context from an encoded certificate. The created context is not persisted to a certificate store. The function makes a copy of the encoded certificate within the created context.
	/// </summary>
	/// <param name="dwCertEncodingType">Specifies the type of encoding used.</param>
	/// <param name="pbCertEncoded">A pointer to a buffer that contains the encoded certificate from which the context is to be created.</param>
	/// <param name="cbCertEncoded">The size, in bytes, of the pbCertEncoded buffer.</param>
	/// <returns>If the function succeeds, the function returns a pointer to a read-only <see cref="CERT_CONTEXT"/>. When you have finished using the certificate context, free it by calling the <see cref="CertFreeCertificateContext"/> function. 
	/// If the function is unable to decode and create the certificate context, it returns NULL.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certcreatecertificatecontext</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern nint CertCreateCertificateContext(
		[In] CertEncodingTypes dwCertEncodingType,
		[In] nint pbCertEncoded,
		[In] uint cbCertEncoded);


	/// <summary>
	/// Possible encoding types for the <see cref="CertCreateCertificateContext"/> function
	/// </summary>
	[Flags]
	public enum CertEncodingTypes : uint
	{
		X509_ASN_ENCODING = 0x00000001,
		PKCS_7_ASN_ENCODING = 0x00010000
	}


	/// <summary>
	/// Frees a certificate context by decrementing its reference count. When the reference count goes to zero, the function frees the memory used by a certificate contex
	/// </summary>
	/// <param name="pCertContext">A pointer to the <see cref="CERT_CONTEXT"/> to be freed.</param>
	/// <returns>The function always returns nonzero.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CertFreeCertificateContext([In] nint pCertContext);

	/// <summary>
	/// Contains information used to verify a message signature. It contains the signer index and signer public key. The signer public key can be the signer's <see cref="CERT_PUBLIC_KEY_INFO"/> structure, certificate context, or chain context.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_ctrl_verify_signature_ex_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA
	{
		/// <summary>
		/// The size, in bytes, of this structure. 
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// This member is not used and should be set to NULL.
		/// </summary>
		public nint hCryptProv;

		/// <summary>
		/// The index of the signer in the message.
		/// </summary>
		public uint dwSignerIndex;

		/// <summary>
		/// 
		/// </summary>
		public SignerType dwSignerType;

		/// <summary>
		/// A pointer to a <see cref="CERT_PUBLIC_KEY_INFO"/> structure, a certificate context, a chain context, or NULL depending on the value of dwSignerType.
		/// </summary>
		public nint pvSigner;

		/// <summary>
		/// Possible values for the dwSignerType field
		/// </summary>
		public enum SignerType : uint
		{
			/// <summary>
			/// pvSigner contains a pointer to a <see cref="CERT_PUBLIC_KEY_INFO"/> structure
			/// </summary>
			CMSG_VERIFY_SIGNER_PUBKEY = 1,

			/// <summary>
			/// pvSigner contains a pointer to a <see cref="CERT_CONTEXT"/> structure
			/// </summary>
			CMSG_VERIFY_SIGNER_CERT = 2,

			/// <summary>
			/// pvSigner contains a pointer to a <see cref="CERT_CHAIN_CONTEXT"/> structure
			/// </summary>
			CMSG_VERIFY_SIGNER_CHAIN = 3,

			/// <summary>
			///  pvSigner contains NULL
			/// </summary>
			CMSG_VERIFY_SIGNER_NULL = 4
		}
	}

	/// <summary>
	/// Contains information to be passed to <see cref="CryptMsgOpenToEncode"/> if dwMsgType is CMSG_SIGNED
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signed_encode_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CMSG_SIGNED_ENCODE_INFO
	{
		/// <summary>
		/// Size of this structure in bytes
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// Number of elements in the rgSigners array
		/// </summary>
		public uint cSigners;

		/// <summary>
		/// Array of pointers to <see cref="CMSG_SIGNER_ENCODE_INFO"/> structures each holding signer information
		/// </summary>
		public nint rgSigners;

		/// <summary>
		/// Number of elements in the rgCertEncoded array
		/// </summary>
		public uint cCertEncoded;

		/// <summary>
		/// Array of pointers to <see cref="CRYPT_INTEGER_BLOB"/> structures, each containing an encoded certificate
		/// </summary>
		public nint rgCertEncoded;

		/// <summary>
		/// Number of elements in the rgCrlEncoded array
		/// </summary>
		public uint cCrlEncoded;

		/// <summary>
		/// Array of pointers to <see cref="CRYPT_INTEGER_BLOB"/> structures, each containing an encoded CRL
		/// </summary>
		public nint rgCrlEncoded;

		/// <summary>
		/// Number of elements in the rgAttrCertEncoded array. Used only if CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS is defined
		/// </summary>
		public uint cAttrCertEncoded;

		/// <summary>
		/// Array of encoded attribute certificates. Used only if CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS is defined. This array of encoded attribute certificates can be used with CMS for PKCS #7 processing
		/// </summary>
		public nint rgAttrCertEncoded;
	}

	/// <summary>
	/// Contains signer information.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signer_encode_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CMSG_SIGNER_ENCODE_INFO
	{
		/// <summary>
		/// The size, in bytes, of this structure
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// A pointer to a <see cref="CERT_INFO"/> structure that contains the Issuer, SerialNumber, and SubjectPublicKeyInfo members
		/// </summary>
		public nint pCertInfo;

		/// <summary>
		/// A handle to the CSP Key or to the CNG NCryptKey or to the CNG BCryptKey
		/// </summary>
		public nint hKey;

		/// <summary>
		/// Specifies the private key to be used
		/// </summary>
		public PrivateKeySpec dwKeySpec;

		/// <summary>
		/// A <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure that specifies the hash algorithm
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

		/// <summary>
		/// Not used. This member must be set to NULL.
		/// </summary>
		public nint pvHashAuxInfo;

		/// <summary>
		/// The number of elements in the rgAuthAttr array. If no authenticated attributes are present in rgAuthAttr, then cAuthAttr is zero
		/// </summary>
		public uint cAuthAttr;

		/// <summary>
		/// An array of pointers to <see cref="CRYPT_ATTRIBUTE"/> structures, each of which contains authenticated attribute information
		/// </summary>
		public nint rgAuthAttr;

		/// <summary>
		/// The number of elements in the rgUnauthAttr array. If there are no unauthenticated attributes, cUnauthAttr is zero
		/// </summary>
		public uint cUnauthAttr;

		/// <summary>
		/// An array of pointers to <see cref="CRYPT_ATTRIBUTE"/> structures, each of which contains unauthenticated attribute information
		/// </summary>
		public nint rgUnauthAttr;

		/// <summary>
		/// A <see cref="CERT_ID"/> structure that contains a unique identifier of the signer's certificate
		/// </summary>
		public CERT_ID SignerId;

		/// <summary>
		/// A <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure optionally used with PKCS #7 with CMS. If this member is not NULL, the algorithm identified is used instead of the SubjectPublicKeyInfo.Algorithm algorithm. 
		/// If this member is set to szOID_PKIX_NO_SIGNATURE, the signature value contains only the hash octets
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;

		/// <summary>
		/// This member is not used. This member must be set to NULL if it is present in the data structure
		/// </summary>
		public nint pvHashEncryptionAuxInfo;
	}

	/// <summary>
	/// Contains the content of the PKCS #7 defined SignerInfo in signed messages. In decoding a received message, <see cref="CryptMsgGetParam"/> is called for each signer to get a <see cref="CMSG_SIGNER_INFO"/> structure.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signer_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CMSG_SIGNER_INFO
	{
		/// <summary>
		/// The version of this structure.
		/// </summary>
		public uint dwVersion;

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the issuer of a certificate with the public key needed to verify a signature.
		/// </summary>
		public CRYPT_INTEGER_BLOB Issuer;

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the serial number of the certificate that contains the public key needed to verify a signature.
		/// </summary>
		public CRYPT_INTEGER_BLOB SerialNumber;

		/// <summary>
		/// <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure specifying the algorithm used in generating the hash of a message.
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

		/// <summary>
		/// <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure specifying the algorithm used to encrypt the hash.
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;

		/// <summary>
		/// A <see cref="CRYPT_DATA_BLOB"/> that contains the encrypted hash of the message, the signature.
		/// </summary>
		public CRYPT_INTEGER_BLOB EncryptedHash;

		/// <summary>
		/// <see cref="CRYPT_ATTRIBUTES"/> structure containing authenticated attributes of the signer.
		/// </summary>
		public CRYPT_ATTRIBUTES AuthAttrs;

		/// <summary>
		/// <see cref="CRYPT_ATTRIBUTES"/> structure containing unauthenticated attributes of the signer.
		/// </summary>
		public CRYPT_ATTRIBUTES UnauthAttrs;
	}

	/// <summary>
	/// Specifies an attribute that has one or more values
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attribute</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_ATTRIBUTE
	{
		/// <summary>
		/// An object identifier (OID) that specifies the type of data contained in the rgValue array
		/// </summary>
		[MarshalAs(UnmanagedType.LPStr)]
		public nint pszObjId;

		/// <summary>
		/// A DWORD value that indicates the number of elements in the rgValue array
		/// </summary>
		public uint cValue;

		/// <summary>
		/// Pointer to an array of <see cref="CRYPT_INTEGER_BLOB"/> structures
		/// </summary>
		public nint rgValue;

	}

	/// <summary>
	/// Contains an array of attributes
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attributes</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_ATTRIBUTES
	{
		/// <summary>
		/// Number of elements in the rgAttr array
		/// </summary>
		public uint cAttr;

		/// <summary>
		/// Array of <see cref="CRYPT_ATTRIBUTE"/> structures
		/// </summary>
		public nint rgAttr;

	}

	/// <summary>
	/// Contains a set of bits represented by an array of bytes
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_bit_blob</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_BIT_BLOB
	{
		/// <summary>
		/// The number of bytes in the pbData array
		/// </summary>
		public uint cbData;

		/// <summary>
		/// A pointer to an array of bytes that represents the bits
		/// </summary>
		public nint pbData;

		/// <summary>
		/// The number of unused bits in the last byte of the array. The unused bits are always the least significant bits in the last byte of the array
		/// </summary>
		public uint cUnusedBits;

	}

	/// <summary>
	/// This CryptoAPI structure is used for an arbitrary array of bytes. It is declared in Wincrypt.h and provides flexibility for objects that can contain various data types.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_integer_blob</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_INTEGER_BLOB
	{
		/// <summary>
		/// The count of bytes in the buffer pointed to by pbData
		/// </summary>
		public uint cbData;

		/// <summary>
		/// A pointer to a block of data bytes
		/// </summary>
		public nint pbData;
	}

	/// <summary>
	/// Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct FILETIME
	{
		public uint dwLowDateTime;
		public uint dwHighDateTime;
	}


	/// <summary>
	/// Specifies an algorithm used to encrypt a private key. 
	/// The structure includes the object identifier (OID) of the algorithm and any needed parameters for that algorithm. 
	/// The parameters contained in its CRYPT_OBJID_BLOB are encoded.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_ALGORITHM_IDENTIFIER
	{
		/// <summary>
		/// An OID of an algorithm
		/// </summary>
		// [MarshalAs(UnmanagedType.LPStr)]
		public nint pszObjId;

		/// <summary>
		/// A BLOB that provides encoded algorithm-specific parameters. In many cases, there are no parameters. This is indicated by setting the cbData member of the Parameters BLOB to zero.
		/// </summary>
		public CRYPT_INTEGER_BLOB Parameters;
	}

	/// <summary>
	/// This structure is used by the <see cref="CRYPT_TIMESTAMP_INFO"/> structure to represent 
	/// the accuracy of the time deviation around the UTC time at which the time stamp token was created by the Time Stamp Authority (TSA).
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_timestamp_accuracy</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_TIMESTAMP_ACCURACY
	{
		/// <summary>
		/// Optional. Specifies, in seconds, the accuracy of the upper limit of the time at which the time stamp token was created by the TSA.
		/// </summary>
		public uint dwSeconds;

		/// <summary>
		/// Optional. Specifies, in milliseconds, the accuracy of the upper limit of the time at which the time stamp token was created by the TSA.
		/// </summary>
		public uint dwMillis;

		/// <summary>
		/// Optional. Specifies, in microseconds, the accuracy of the upper limit of the time at which the time-stamp token was created by the TSA.
		/// </summary>
		public uint dwMicros;
	}

	/// <summary>
	/// Contains both the encoded and decoded representations of a time stamp token.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_timestamp_context</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_TIMESTAMP_CONTEXT
	{
		/// <summary>
		/// The size, in bytes, of the buffer pointed to by the <see cref="pbEncoded"/> member.
		/// </summary>
		public int cbEncoded;

		/// <summary>
		/// A pointer to a buffer that contains an Abstract Syntax Notation One (ASN.1) encoded content information sequence. 
		/// This value should be stored for future time stamp validations on the signature. Applications can use the CertOpenStore function with the CERT_STORE_PROV_PKCS7 flag to find additional certificates or certificate revocation lists (CRLs) related to the TSA time stamp signature.
		/// </summary>
		public nint pbEncoded;

		/// <summary>
		/// A pointer to a <see cref="CRYPT_TIMESTAMP_INFO"/> structure that contains a signed data content type in Cryptographic Message Syntax (CMS) format.
		/// </summary>
		public nint pTimeStamp;
	}


	/// <summary>
	/// Contains a signed data content type in Cryptographic Message Syntax (CMS) format.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_timestamp_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_TIMESTAMP_INFO
	{
		/// <summary>
		/// A DWORD value that specifies the version of the time stamp request
		/// </summary>
		public uint dwVersion;

		/// <summary>
		/// Optional. A pointer to a null-terminated string that specifies the Time Stamping Authority (TSA) policy under which the time stamp token was provided
		/// </summary>
		[MarshalAs(UnmanagedType.LPStr)]
		public string? pszTSAPolicyId;

		/// <summary>
		/// A <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure that contains information about the algorithm used to calculate the hash. 
		/// This value must correspond with the value passed in the <see cref="CRYPT_TIMESTAMP_REQUEST"/> structure
		/// </summary>
		public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that specifies the hash values to be time stamped.
		/// </summary>
		public CRYPT_INTEGER_BLOB HashedMessage;

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the serial number assigned by the TSA to each time stamp token.
		/// </summary>
		public CRYPT_INTEGER_BLOB SerialNumber;

		/// <summary>
		/// A <see cref="FILETIME"/> value that specifies the time at which the time stamp token was produced by the TSA.
		/// </summary>
		public FILETIME ftTime;

		/// <summary>
		/// Optional. A pointer to a <see cref="CRYPT_TIMESTAMP_ACCURACY"/> structure that contains the time deviation around the UTC time at which the time stamp token was created by the TSA.
		/// </summary>
		public nint pvAccuracy;

		/// <summary>
		/// This member is reserved
		/// </summary>
		public uint fOrdering;

		/// <summary>
		/// Optional. A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the nonce value used by the client to verify the timeliness of the response when no local clock is available. 
		/// This value must correspond with the value passed in the <see cref="CRYPT_TIMESTAMP_REQUEST"/> structure.
		/// </summary>
		public CRYPT_INTEGER_BLOB Nonce;

		/// <summary>
		/// Optional. A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the subject name of the TSA certificate.
		/// </summary>
		public CRYPT_INTEGER_BLOB Tsa;

		/// <summary>
		/// The number of elements in the array pointed to by the <see cref="rgExtension"/> member.
		/// </summary>
		public uint cExtension;

		/// <summary>
		/// A pointer to an array of <see cref="CERT_EXTENSION"/> structures that contain extension information returned from the request.
		/// </summary>
		public nint rgExtension;
	}

	/// <summary>
	/// Defines additional parameters for the time stamp request.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_timestamp_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_TIMESTAMP_PARA
	{
		/// <summary>
		/// Optional. A pointer to a null-terminated character string that contains the Time Stamping Authority (TSA) policy under which the time stamp token should be provided.
		/// </summary>
		public nint pszTSAPolicyId;

		/// <summary>
		/// A Boolean value that specifies whether the TSA must include the certificates used to sign the time stamp token in the response .
		/// </summary>
		public bool fRequestCerts;

		/// <summary>
		/// Optional. A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the nonce value used by the client to verify the timeliness of the response when no local clock is available.
		/// </summary>
		public CRYPT_INTEGER_BLOB Nonce;

		/// <summary>
		/// The number of elements in the array pointed to by the <see cref="rgExtension"/> member.
		/// </summary>
		public uint cExtension;

		/// <summary>
		/// A pointer to an array of <see cref="CERT_EXTENSION"/> structures that contain extension information that is passed in the request.
		/// </summary>
		public nint rgExtension;
	}

	/// <summary>
	/// Handle of the certificate store to be closed
	/// </summary>
	/// <param name="hCertStore">Handle of the certificate store to be closed</param>
	/// <param name="dwFlags">Typically, this parameter uses the default value zero. The default is to close the store with memory remaining allocated for contexts that have not been freed. 
	/// In this case, no check is made to determine whether memory for contexts remains allocated.</param>
	/// <returns>If the function succeeds, the return value is TRUE</returns>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CertCloseStore(nint hCertStore, CertCloseStoreFlags dwFlags);

	[Flags]
	public enum CertCloseStoreFlags : uint
	{
		/// <summary>
		/// None of the flags specified
		/// </summary>
		None = 0,

		/// <summary>
		/// Forces the freeing of memory for all contexts associated with the store. This flag can be safely used only when the store is opened in a function and neither the store handle nor any of its contexts are passed to any called functions
		/// </summary>
		CERT_CLOSE_STORE_FORCE_FLAG = 1,

		/// <summary>
		/// Checks for nonfreed certificate, CRL, and CTL contexts. A returned error code indicates that one or more store elements is still in use. This flag should only be used as a diagnostic tool in the development of applications.
		/// </summary>
		CERT_CLOSE_STORE_CHECK_FLAG = 2
	}

	/// <summary>
	/// Obtains the private key for a certificate. This function is used to obtain access to a user's private key when the user's certificate is available, but the handle of the user's key container is not available. 
	/// This function can only be used by the owner of a private key and not by any other user.
	/// </summary>
	/// <param name="pCert">The address of a <see cref="CERT_CONTEXT"/> structure that contains the certificate context for which a private key will be obtained</param>
	/// <param name="dwFlags">A set of flags that modify the behavior of this function</param>
	/// <param name="pvParameters">If the CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG is set, then this is the address of an HWND. If the CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG is not set, then this parameter must be NULL.</param>
	/// <param name="phCryptProvOrNCryptKey">The address of an HCRYPTPROV_OR_NCRYPT_KEY_HANDLE variable that receives the handle of either the CryptoAPI provider or the CNG key. If the pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag, this is a CNG key handle of type NCRYPT_KEY_HANDLE; otherwise, this is a CryptoAPI provider handle of type HCRYPTPROV</param>
	/// <param name="pdwKeySpec">The address of a DWORD variable that receives additional information about the key</param>
	/// <param name="pfCallerFreeProv">The address of a BOOL variable that receives a value that indicates whether the caller must free the handle returned in the phCryptProvOrNCryptKey variable</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE).</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptAcquireCertificatePrivateKey(
		[In] nint pCert,
		[In] AcquiringFlags dwFlags,
		[In] nint pvParameters,
		out nint phCryptProvOrNCryptKey,
		out PrivateKeySpec pdwKeySpec,
		out bool pfCallerFreeProv
	);

	/// <summary>
	/// Values for the CryptAcquireCertificatePrivateKey.dwFlags parameter
	/// </summary>
	[Flags]
	public enum AcquiringFlags : uint
	{
		/// <summary>
		/// If a handle is already acquired and cached, that same handle is returned. Otherwise, a new handle is acquired and cached by using the certificate's CERT_KEY_CONTEXT_PROP_ID property. 
		/// When this flag is set, the pfCallerFreeProvOrNCryptKey parameter receives FALSE and the calling application must not release the handle. 
		/// The handle is freed when the certificate context is freed; however, you must retain the certificate context referenced by the pCert parameter as long as the key is in use, otherwise operations that rely on the key will fail.
		/// </summary>
		CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001,

		/// <summary>
		/// Uses the certificate's CERT_KEY_PROV_INFO_PROP_ID property to determine whether caching should be accomplished. For more information about the CERT_KEY_PROV_INFO_PROP_ID property, see CertSetCertificateContextProperty. 
		/// This function will only use caching if during a previous call, the dwFlags member of the CRYPT_KEY_PROV_INFO structure contained CERT_SET_KEY_CONTEXT_PROP.
		/// </summary>
		CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002,

		/// <summary>
		/// The public key in the certificate is compared with the public key returned by the cryptographic service provider (CSP). If the keys do not match, the acquisition operation fails and the last error code is set to NTE_BAD_PUBLIC_KEY. 
		/// If a cached handle is returned, no comparison is made.
		/// </summary>
		CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004,

		/// <summary>
		/// The CSP should not display any user interface (UI) for this context. If the CSP must display UI to operate, the call fails and the NTE_SILENT_CONTEXT error code is set as the last error.
		/// </summary>
		CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040,

		/// <summary>
		/// Any UI that is needed by the CSP or KSP will be a child of the HWND that is supplied in the pvParameters parameter. For a CSP key, using this flag will cause the CryptSetProvParam function with the flag PP_CLIENT_HWND using this HWND to be called with NULL for HCRYPTPROV. For a KSP key, using this flag will cause the NCryptSetProperty function with the NCRYPT_WINDOW_HANDLE_PROPERTY flag to be called using the HWND.
		/// Do not use this flag with CRYPT_ACQUIRE_SILENT_FLAG.
		/// </summary>
		CRYPT_ACQUIRE_WINDOWS_HANDLE_FLAG = 0x00000080,

		/// <summary>
		/// This function will attempt to obtain the key by using CryptoAPI. If that fails, this function will attempt to obtain the key by using the Cryptography API: Next Generation (CNG). 
		/// The pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag if CNG is used to obtain the key.
		/// </summary>
		CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000,

		/// <summary>
		/// This function will only attempt to obtain the key by using CNG and will not use CryptoAPI to obtain the key.
		/// The pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag if CNG is used to obtain the key.
		/// </summary>
		CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000,

		/// <summary>
		/// This function will attempt to obtain the key by using CNG. If that fails, this function will attempt to obtain the key by using CryptoAPI. 
		/// The pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag if CNG is used to obtain the key.
		/// </summary>
		CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000
	}

	/// <summary>
	/// Values for the CryptAcquireCertificatePrivateKey.pdwKeySpec parameter
	/// </summary>
	public enum PrivateKeySpec : uint
	{
		AT_KEYEXCHANGE = 1,
		AT_SIGNATURE = 2,
		CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
	}

	/// <summary>
	/// Frees memory allocated by <see cref="CryptMemAlloc"/> or <see cref="CryptMemRealloc"/>
	/// </summary>
	/// <param name="pv">A pointer to the buffer to be freed</param>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmemfree</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern void CryptMemFree(
		[In] nint pv
	);


	/// <summary>
	/// Closes a cryptographic message handle. At each call to this function, the reference count on the message is reduced by one. When the reference count reaches zero, the message is fully released
	/// </summary>
	/// <param name="hCryptMsg">Handle of the cryptographic message to be closed</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE). If the function fails, the return value is zero (FALSE)</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgclose</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptMsgClose(
		[In] nint hCryptMsg
	);

	/// <summary>
	/// Performs a control operation after a message has been decoded by a final call to the <see cref="CryptMsgUpdate"/> function.
	/// </summary>
	/// <param name="hCryptMsg">A handle of a cryptographic message for which a control is to be applied.</param>
	/// <param name="dwFlags">Operation flags</param>
	/// <param name="dwCtrlType">The type of operation to be performed.</param>
	/// <param name="pvCtrlPara">A pointer to a structure determined by the value of dwCtrlType.</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE). If the function fails, the return value is zero (FALSE)</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptMsgControl(
		[In] nint hCryptMsg,
		[In] MsgFlags dwFlags,
		[In] MsgControlType dwCtrlType,
		[In] nint pvCtrlPara
	);

	/// <summary>
	/// Message control types
	/// </summary>
	public enum MsgControlType : uint
	{
		/// <summary>
		/// A <see cref="CERT_INFO"/> structure that identifies the signer of the message whose signature is to be verified.
		/// </summary>
		CMSG_CTRL_VERIFY_SIGNATURE = 1,

		/// <summary>
		/// A <see cref="CMSG_CTRL_DECRYPT_PARA"/> structure used to decrypt the message for the specified key transport recipient. 
		/// This value is applicable to RSA recipients. This operation specifies that the CryptMsgControl function search the recipient index to obtain the key transport recipient information.
		/// </summary>
		CMSG_CTRL_DECRYPT = 2,

		/// <summary>
		/// This value is not used.
		/// </summary>
		CMSG_CTRL_VERIFY_HASH = 5,

		/// <summary>
		/// pvCtrlPara points to a <see cref="CMSG_SIGNER_ENCODE_INFO"/> structure that contains the signer information to be added to the message.
		/// </summary>
		CMSG_CTRL_ADD_SIGNER = 6,

		/// <summary>
		/// After a deletion is made, any other signer indices in use for this message are no longer valid and must be reacquired by calling the <see cref="CryptMsgGetParam"/> function.
		/// </summary>
		CMSG_CTRL_DEL_SIGNER = 7,

		/// <summary>
		/// A <see cref="CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA"/> structure that contains the index of the signer and a BLOB that contains the unauthenticated attribute information to be added to the message.
		/// </summary>
		CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR = 8,

		/// <summary>
		/// A <see cref="CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA"/> structure that contains an index that specifies the signer and the index that specifies the signer's unauthenticated attribute to be deleted.
		/// </summary>
		CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR = 9,

		/// <summary>
		/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the encoded bytes of the certificate to be added to the message.
		/// </summary>
		CMSG_CTRL_ADD_CERT = 10,

		/// <summary>
		/// The index of the certificate to be deleted from the message.
		/// </summary>
		CMSG_CTRL_DEL_CERT = 11,

		/// <summary>
		/// A BLOB that contains the encoded bytes of the CRL to be added to the message.
		/// </summary>
		CMSG_CTRL_ADD_CRL = 12,

		/// <summary>
		/// The index of the CRL to be deleted from the message.
		/// </summary>
		CMSG_CTRL_DEL_CRL = 13,

		/// <summary>
		/// A BLOB that contains the encoded bytes of attribute certificate.
		/// </summary>
		CMSG_CTRL_ADD_ATTR_CERT = 14,

		/// <summary>
		/// The index of the attribute certificate to be removed.
		/// </summary>
		CMSG_CTRL_DEL_ATTR_CERT = 15,

		/// <summary>
		/// A <see cref="CMSG_CTRL_KEY_TRANS_DECRYPT_PARA"/> structure used to decrypt the message for the specified key transport recipient. Key transport is used with RSA encryption/decryption.
		/// </summary>
		CMSG_CTRL_KEY_TRANS_DECRYPT = 16,

		/// <summary>
		/// A <see cref="CMSG_CTRL_KEY_AGREE_DECRYPT_PARA"/> structure used to decrypt the message for the specified key agreement session key. Key agreement is used with Diffie-Hellman encryption/decryption.
		/// </summary>
		CMSG_CTRL_KEY_AGREE_DECRYPT = 17,

		/// <summary>
		/// A <see cref="CMSG_CTRL_MAIL_LIST_DECRYPT_PARA"/> structure used to decrypt the message for the specified recipient using a previously distributed key-encryption key (KEK).
		/// </summary>
		CMSG_CTRL_MAIL_LIST_DECRYPT = 18,

		/// <summary>
		/// A <see cref="CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA"/> structure that specifies the signer index and public key to verify the message signature. 
		/// The signer public key can be a <see cref="CERT_PUBLIC_KEY_INFO"/> structure, a certificate context, or a certificate chain context.
		/// </summary>
		CMSG_CTRL_VERIFY_SIGNATURE_EX = 19,

		/// <summary>
		/// A <see cref="CMSG_CMS_SIGNER_INFO"/> structure that contains signer information. This operation differs from CMSG_CTRL_ADD_SIGNER because the signer information contains the signature.
		/// </summary>
		CMSG_CTRL_ADD_CMS_SIGNER_INFO = 20,

		/// <summary>
		/// A <see cref="CERT_STRONG_SIGN_PARA"/> structure used to perform strong signature checking.
		/// </summary>
		CMSG_CTRL_ENABLE_STRONG_SIGNATURE = 21
	}


	/// <summary>
	/// Acquires a message parameter after a cryptographic message has been encoded or decoded
	/// </summary>
	/// <param name="hCryptMsg">Handle of a cryptographic message</param>
	/// <param name="dwParamType">Indicates the parameter types of data to be retrieved. The type of data to be retrieved determines the type of structure to use for pvData</param>
	/// <param name="dwIndex">Index for the parameter being retrieved, where applicable. When a parameter is not being retrieved, this parameter is ignored and is set to zero</param>
	/// <param name="pvData">A pointer to a buffer that receives the data retrieved. The form of this data will vary depending on the value of the dwParamType parameter</param>
	/// <param name="pcbData">A pointer to a variable that specifies the size, in bytes, of the buffer pointed to by the pvData parameter. When the function returns, the variable pointed to by the pcbData parameter contains the number of bytes stored in the buffer</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE). If the function fails, the return value is zero (FALSE)</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsggetparam</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptMsgGetParam(
		[In] nint hCryptMsg,
		[In] MsgParamType dwParamType,
		[In] uint dwIndex,
		[In] nint pvData,
		ref uint pcbData
	);


	/// <summary>
	/// Possible dwParamType values for the <see cref="CryptMsgGetParam"/> function
	/// </summary>
	public enum MsgParamType : uint
	{
		/// <summary>
		/// pvData data type: pointer to a DWORD. 
		/// Returns the message type of a decoded message of unknown type. The retrieved message type can be compared to supported types to determine whether processing can continued
		/// </summary>
		CMSG_TYPE_PARAM = 1,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Returns the whole PKCS #7 message from a message opened to encode. Retrieves the inner content of a message opened to decode. 
		/// If the message is enveloped, the inner type is data, and <see cref="CryptMsgControl"/> has been called to decrypt the message, the decrypted content is returned. 
		/// If the inner type is not data, the encoded BLOB that requires further decoding is returned. 
		/// If the message is not enveloped and the inner content is DATA, the returned data is the octets of the inner content. 
		/// This type is applicable to both encode and decode. For decoding, if the type is CMSG_DATA, the content's octets are returned; else, the encoded inner content is returned.
		/// </summary>
		CMSG_CONTENT_PARAM = 2,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Retrieves the encoded content of an encoded cryptographic message, without the outer layer of the CONTENT_INFO structure. That is, only the encoding of the PKCS #7 defined ContentInfo.content field is returned
		/// </summary>
		CMSG_BARE_CONTENT_PARAM = 3,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a null-terminated object identifier (OID) string.
		/// Returns the inner content type of a received message. This type is not applicable to messages of type DATA
		/// </summary>
		CMSG_INNER_CONTENT_TYPE_PARAM = 4,

		/// <summary>
		/// pvData data type: pointer to a DWORD.
		/// Returns the number of signers of a received SIGNED message
		/// </summary>
		CMSG_SIGNER_COUNT_PARAM = 5,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_SIGNER_INFO"/> structure. 
		/// Returns information on a message signer. This includes the issuer and serial number of the signer's certificate and authenticated and unauthenticated attributes of the signer's certificate. 
		/// To retrieve signer information on all of the signers of a message, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one
		/// </summary>
		CMSG_SIGNER_INFO_PARAM = 6,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive the <see cref="CERT_INFO"/> structure. 
		/// Returns information on a message signer needed to identify the signer's certificate. A certificate's Issuer and SerialNumber can be used to uniquely identify a certificate for retrieval. 
		/// To retrieve information for all the signers, repetitively call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one. 
		/// Only the Issuer and SerialNumber fields in the <see cref="CERT_INFO"/> structure returned contain available, valid data
		/// </summary>
		CMSG_SIGNER_CERT_INFO_PARAM = 7,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive the <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure. 
		/// Returns the hash algorithm used by a signer of the message. To get the hash algorithm for a specified signer, call <see cref="CryptMsgGetParam"/> with dwIndex equal to that signer's index.
		/// </summary>
		CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a <see cref="CRYPT_ATTRIBUTES"/> structure.
		/// Returns the authenticated attributes of a message signer. To retrieve the authenticated attributes for a specified signer, call <see cref="CryptMsgGetParam"/> with dwIndex equal to that signer's index.
		/// </summary>
		CMSG_SIGNER_AUTH_ATTR_PARAM = 9,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a CRYPT_ATTRIBUTES structure. 
		/// Returns a message signer's unauthenticated attributes. To retrieve the unauthenticated attributes for a specified signer, call <see cref="CryptMsgGetParam"/> with dwIndex equal to that signer's index
		/// </summary>
		CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10,

		/// <summary>
		/// pvData data type: pointer to DWORD.
		/// Returns the number of certificates in a received SIGNED or ENVELOPED message.
		/// </summary>
		CMSG_CERT_COUNT_PARAM = 11,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Returns a signer's certificate. To get all of the signer's certificates, call <see cref="CryptMsgGetParam"/>, varying dwIndex from 0 to the number of available certificates minus one.
		/// </summary>
		CMSG_CERT_PARAM = 12,

		/// <summary>
		/// pvData data type: pointer to DWORD. 
		/// Returns the count of CRLs in a received, SIGNED or ENVELOPED message.
		/// </summary>
		CMSG_CRL_COUNT_PARAM = 13,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Returns a CRL. To get all the CRLs, call CryptMsgGetParam, varying dwIndex from 0 to the number of available CRLs minus one.
		/// </summary>
		CMSG_CRL_PARAM = 14,

		/// <summary>
		/// pvData data type: pointer to a BYTE array for a <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure.
		/// Returns the encryption algorithm used to encrypt an ENVELOPED message
		/// </summary>
		CMSG_ENVELOPE_ALGORITHM_PARAM = 15,

		/// <summary>
		/// pvData data type: pointer to a DWORD. 
		/// Returns the number of key transport recipients of an ENVELOPED received message.
		/// </summary>
		CMSG_RECIPIENT_COUNT_PARAM = 17,

		/// <summary>
		/// pvData data type: pointer to a DWORD.
		/// Returns the index of the key transport recipient used to decrypt an ENVELOPED message. This value is available only after a message has been decrypted.
		/// </summary>
		CMSG_RECIPIENT_INDEX_PARAM = 18,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a <see cref="CERT_INFO"/> structure.
		/// Returns certificate information about a key transport message's recipient. To get certificate information on all key transport message's recipients, repetitively call <see cref="CryptMsgGetParam"/>, varying dwIndex from 0 to the number of recipients minus one. 
		/// Only the Issuer, SerialNumber, and PublicKeyAlgorithm members of the CERT_INFO structure returned are available and valid
		/// </summary>
		CMSG_RECIPIENT_INFO_PARAM = 19,

		/// <summary>
		/// pvData data type: pointer to a BYTE array for a <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure.
		/// Returns the hash algorithm used to hash the message when it was created.
		/// </summary>
		CMSG_HASH_ALGORITHM_PARAM = 20,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Returns the hash value stored in the message when it was created.
		/// </summary>
		CMSG_HASH_DATA_PARAM = 21,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Returns the hash calculated of the data in the message. This type is applicable to both encode and decode.
		/// </summary>
		CMSG_COMPUTED_HASH_PARAM = 22,

		/// <summary>
		/// pvData data type: pointer to a BYTE array for a <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure.
		/// Returns the encryption algorithm used to encrypted the message.
		/// </summary>
		CMSG_ENCRYPT_PARAM = 26,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.
		/// Returns the encrypted hash of a signature. Typically used for performing time-stamping.
		/// </summary>
		CMSG_ENCRYPTED_DIGEST = 27,

		/// <summary>
		/// pvData data type: pointer to a BYTE array. 
		/// Returns the encoded <see cref="CMSG_SIGNER_INFO"/> signer information for a message signer.
		/// </summary>
		CMSG_ENCODED_SIGNER = 28,

		/// <summary>
		/// pvData data type: pointer to a BYTE array.	Changes the contents of an already encoded message. The message must first be decoded with a call to <see cref="CryptMsgOpenToDecode"/>. 
		/// Then the change to the message is made through a call to <see cref="CryptMsgControl"/>, <see cref="CryptMsgCountersign"/>, or <see cref="CryptMsgCountersignEncoded"/>. 
		/// The message is then encoded again with a call to <see cref="CryptMsgGetParam"/>, specifying CMSG_ENCODED_MESSAGE to get a new encoding that reflects the changes made. This can be used, for instance, to add a time-stamp attribute to a message.
		/// </summary>
		CMSG_ENCODED_MESSAGE = 29,

		/// <summary>
		/// pvData data type: pointer to a DWORD. 
		/// Returns the version of the decoded message.
		/// </summary>
		CMSG_VERSION_PARAM = 30,

		/// <summary>
		/// pvData data type: pointer to a DWORD. 
		/// Returns the count of the attribute certificates in a SIGNED or ENVELOPED message.
		/// </summary>
		CMSG_ATTR_CERT_COUNT_PARAM = 31,

		/// <summary>
		/// pvData data type: pointer to a BYTE array. 
		/// Retrieves an attribute certificate. To get all the attribute certificates, call <see cref="CryptMsgGetParam"/> varying dwIndex set to 0 the number of attributes minus one.
		/// </summary>
		CMSG_ATTR_CERT_PARAM = 32,

		/// <summary>
		/// pvData data type: pointer to DWORD. 
		/// Returns the total count of all message recipients including key agreement and mail list recipients.
		/// </summary>
		CMSG_CMS_RECIPIENT_COUNT_PARAM = 33,

		/// <summary>
		/// pvData data type: pointer to a DWORD. 
		/// Returns the index of the key transport, key agreement, or mail list recipient used to decrypt an ENVELOPED message.
		/// </summary>
		CMSG_CMS_RECIPIENT_INDEX_PARAM = 34,

		/// <summary>
		/// pvData data type: pointer to a DWORD. 
		/// Returns the index of the encrypted key of a key agreement recipient used to decrypt an ENVELOPED message.
		/// </summary>
		CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_CMS_RECIPIENT_INFO"/> structure.
		/// Returns information about a key transport, key agreement, or mail list recipient. It is not limited to key transport message recipients. 
		/// To get information on all of a message's recipients, repetitively call <see cref="CryptMsgGetParam"/>, varying dwIndex from 0 to the number of recipients minus one.
		/// </summary>
		CMSG_CMS_RECIPIENT_INFO_PARAM = 36,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_ATTR"/> structure. 
		/// Returns the unprotected attributes in an enveloped message.
		/// </summary>
		CMSG_UNPROTECTED_ATTR_PARAM = 37,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a CERT_ID structure.
		/// Returns information on a message signer needed to identify the signer's public key. This could be a certificate's Issuer and SerialNumber, a KeyID, or a HashId. 
		/// To retrieve information for all the signers, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one.
		/// </summary>
		CMSG_SIGNER_CERT_ID_PARAM = 38,

		/// <summary>
		/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_CMS_SIGNER_INFO"/> structure.
		/// Returns information on a message signer. This includes a signerId and authenticated and unauthenticated attributes. 
		/// To retrieve signer information on all of the signers of a message, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one.
		/// </summary>
		CMSG_CMS_SIGNER_INFO_PARAM = 39
	}

	/// <summary>
	/// Opens a cryptographic message for decoding and returns a handle of the opened message. The message remains open until the <see cref="CryptMsgClose"/> function is called.
	/// </summary>
	/// <param name="dwMsgEncodingType">Specifies the encoding type used.</param>
	/// <param name="dwFlags">Flags.</param>
	/// <param name="dwMsgType">Specifies the type of message to decode. In most cases, the message type is determined from the message header and zero is passed for this parameter.</param>
	/// <param name="hCryptProv">This parameter is not used and should be set to NULL.</param>
	/// <param name="pRecipientInfo">This parameter is reserved for future use and must be NULL.</param>
	/// <param name="pStreamInfo">When streaming is not being used, this parameter must be set to NULL.
	/// When streaming is being used, the pStreamInfo parameter is a pointer to a <see cref="CMSG_STREAM_INFO"/> structure that contains a pointer to a callback to be called when <see cref="CryptMsgUpdate"/> is executed or when <see cref="CryptMsgControl"/> is executed when decoding a streamed enveloped message.</param>
	/// <returns>If the function succeeds, the function returns the handle of the opened message. If the function fails, it returns NULL.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentodecode</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern nint CryptMsgOpenToDecode(
		[In] MsgEncodingTypes dwMsgEncodingType,
		[In] MsgFlags dwFlags,
		[In] MsgType dwMsgType,
		[In] nint hCryptProv,
		[In] nint pRecipientInfo,
		[In] nint pStreamInfo
	);

	/// <summary>
	/// Opens a cryptographic message for encoding and returns a handle of the opened message. The message remains open until <see cref="CryptMsgClose"/> is called
	/// </summary>
	/// <param name="dwMsgEncodingType">Specifies the encoding type used</param>
	/// <param name="dwFlags">Flags</param>
	/// <param name="dwMsgType">Indicates the message type</param>
	/// <param name="pvMsgEncodeInfo">The address of a structure that contains the encoding information. The type of data depends on the value of the dwMsgType parameter. For details, see dwMsgType</param>
	/// <param name="pszInnerContentObjID">If CryptMsgCalculateEncodedLength is called and the data for CryptMsgUpdate has already been message encoded, the appropriate object identifier (OID) is passed in pszInnerContentObjID. If pszInnerContentObjID is NULL, then the inner content type is assumed not to have been previously encoded and is therefore encoded as an octet string and given the type CMSG_DATA</param>
	/// <param name="pStreamInfo">When streaming is being used, this parameter is the address of a <see cref="CMSG_STREAM_INFO"/> structure</param>
	/// <returns>If the function succeeds, it returns a handle to the opened message. This handle must be closed when it is no longer needed by passing it to the <see cref="CryptMsgClose"/> function. If this function fails, NULL is returned</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgopentoencode</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern nint CryptMsgOpenToEncode(
		[In] MsgEncodingTypes dwMsgEncodingType,
		[In] MsgFlags dwFlags,
		[In] MsgType dwMsgType,
		[In] nint pvMsgEncodeInfo,
		[In] [MarshalAs(UnmanagedType.LPStr)] string? pszInnerContentObjID,
		[In] nint pStreamInfo);

	/// <summary>
	/// Possible encoding types for the <see cref="CryptMsgOpenToEncode"/> and the <see cref="CryptMsgOpenToDecode"/> functions
	/// </summary>
	[Flags]
	public enum MsgEncodingTypes : uint
	{
		X509_ASN_ENCODING = 0x00000001,
		PKCS_7_ASN_ENCODING = 0x00010000
	}

	/// <summary>
	/// Possible flags for the <see cref="CryptMsgOpenToEncode"/> function
	/// </summary>
	[Flags]
	public enum MsgFlags : uint
	{
		/// <summary>
		/// The streamed output will not have an outer ContentInfo wrapper (as defined by PKCS #7). This makes it suitable to be streamed into an enclosing message.
		/// </summary>
		CMSG_BARE_CONTENT_FLAG = 0x00000001,

		/// <summary>
		/// There is detached data being supplied for the subsequent calls to <see cref="CryptMsgUpdate"/>
		/// </summary>
		CMSG_DETACHED_FLAG = 0x00000004,

		/// <summary>
		/// Authenticated attributes are forced to be included in the SignerInfo (as defined by PKCS #7) in cases where they would not otherwise be required
		/// </summary>
		CMSG_AUTHENTICATED_ATTRIBUTES_FLAG = 0x00000008,

		/// <summary>
		/// Used when calculating the size of a message that has been encoded by using Distinguished Encoding Rules (DER) and that is nested inside an enveloped message. This is particularly useful when performing streaming
		/// </summary>
		CMSG_CONTENTS_OCTETS_FLAG = 0x00000010,

		/// <summary>
		/// When set, non-data type-inner content is encapsulated within an OCTET STRING. Applicable to both signed and enveloped messages
		/// </summary>
		CMSG_CMS_ENCAPSULATED_CONTENT_FLAG = 0x00000040,

		/// <summary>
		/// If set, the hCryptProv that is passed to this function is released on the final CryptMsgUpdate. The handle is not released if the function fails
		/// </summary>
		CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x00008000
	}

	/// <summary>
	/// Cryptographic message type
	/// </summary>
	public enum MsgType : uint
	{
		/// <summary>
		/// This value is not used
		/// </summary>
		CMSG_DATA = 1,

		/// <summary>
		/// The pvMsgEncodeInfo parameter is the address of a <see cref="CMSG_SIGNED_ENCODE_INFO"/> structure that contains the encoding information
		/// </summary>
		CMSG_SIGNED = 2,

		/// <summary>
		/// The pvMsgEncodeInfo parameter is the address of a <see cref="CMSG_ENVELOPED_ENCODE_INFO"/> structure that contains the encoding information
		/// </summary>
		CMSG_ENVELOPED = 3,

		/// <summary>
		/// This value is not currently implemented
		/// </summary>
		CMSG_SIGNED_AND_ENVELOPED = 4,

		/// <summary>
		/// The pvMsgEncodeInfo parameter is the address of a <see cref="CMSG_HASHED_ENCODE_INFO"/> structure that contains the encoding information
		/// </summary>
		CMSG_HASHED = 5
	}

	/// <summary>
	/// Adds contents to a cryptographic message
	/// </summary>
	/// <param name="hCryptMsg">Cryptographic message handle of the message to be updated</param>
	/// <param name="pbData">A pointer to the buffer holding the data to be encoded or decoded</param>
	/// <param name="cbData">Number of bytes of data in the pbData buffer</param>
	/// <param name="fFinal">Indicates that the last block of data for encoding or decoding is being processed</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE). If the function fails, the return value is zero (FALSE)</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgupdate</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptMsgUpdate(
		[In] nint hCryptMsg,
		[In] nint pbData,
		[In] uint cbData,
		[In] bool fFinal
	);

	/// <summary>
	///  Encodes a time stamp request and retrieves the time stamp token from a location specified by a URL to a Time Stamping Authority (TSA)
	/// </summary>
	/// <param name="wszUrl">A pointer to a null-terminated wide character string that contains the URL of the TSA to which to send the request</param>
	/// <param name="dwRetrievalFlags">A set of flags that specify how the time stamp is retrieved</param>
	/// <param name="dwTimeout">A DWORD value that specifies the maximum number of milliseconds to wait for retrieval. If this parameter is set to zero, this function does not time out</param>
	/// <param name="pszHashId">A pointer to a null-terminated character string that contains the hash algorithm object identifier (OID)</param>
	/// <param name="pPara">A pointer to a <see cref="CRYPT_TIMESTAMP_PARA"/> structure that contains additional parameters for the request</param>
	/// <param name="pbData">A pointer to an array of bytes to be time stamped</param>
	/// <param name="cbData">The size, in bytes, of the array pointed to by the pbData parameter</param>
	/// <param name="pTsContext">A pointer to a <see cref="CRYPT_TIMESTAMP_CONTEXT"/> structure. When you have finished using the context, you must free it by calling the <see cref="CryptMemFree"/> function</param>
	/// <param name="ppTsSigner">A pointer to a <see cref="CERT_CONTEXT"/> that receives the certificate of the signer. When you have finished using this structure, you must free it by passing this pointer to the <see cref="CertFreeCertificateContext"/> function.
	/// Set this parameter to NULL if the TSA signer's certificate is not needed.</param>
	/// <param name="phStore">The handle of a certificate store initialized with certificates from the time stamp response. This store can be used for validating the signer certificate of the time stamp response. 
	/// This parameter can be NULL if the TSA supporting certificates are not needed.When you have finished using this handle, release it by passing it to the <see cref="CertCloseStore"/> function</param>
	/// <returns>If the function is unable to retrieve, decode, and validate the time stamp context, it returns FALSE</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptretrievetimestamp</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptRetrieveTimeStamp
	(
		[In][MarshalAs(UnmanagedType.LPWStr)] string? wszUrl,
		[In] RetrievalFlags dwRetrievalFlags,
		[In] int dwTimeout,
		[In][MarshalAs(UnmanagedType.LPStr)] string? pszHashId,
		[In] nint pPara,
		[In] nint pbData,
		[In] uint cbData,
		[Out] nint pTsContext,
		[Out] nint ppTsSigner,
		[Out] nint phStore
	);


	/// <summary>
	/// Possible values for the CryptRetrieveTimeStamp.dwRetrievalFlags parameter 
	/// </summary>
	[Flags]
	public enum RetrievalFlags : uint
	{
		/// <summary>
		/// None of the flags specified
		/// </summary>
		None = 0,

		/// <summary>
		/// Inhibit hash calculation on the array of bytes pointed to by the pbData parameter.
		/// </summary>
		TIMESTAMP_DONT_HASH_DATA = 0x00000001,

		/// <summary>
		/// Enforce signature validation on the retrieved time stamp. This flag is valid only if the fRequestCerts member of the <see cref="CRYPT_TIMESTAMP_PARA"/> pointed to by the pPara parameter is set to TRUE.
		/// </summary>
		TIMESTAMP_VERIFY_CONTEXT_SIGNATURE = 0x00000020,

		/// <summary>
		/// Set this flag to inhibit automatic authentication handling
		/// </summary>
		TIMESTAMP_NO_AUTH_RETRIEVAL = 0x00020000
	}

	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptVerifyTimeStampSignature
	(
		[In] byte[] pbTSContentInfo,
		[In] int cbTSContentInfo,
		[In] byte[] pbData,
		[In] int cbData,
		[In] nint hAdditionalStore,
		[Out] nint pTsContext,
		[Out] nint pTsSigner,
		[Out] nint phStore
	);
}
