// Copyright © Antoine Larine, 2023. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
		public uint dwIdChoice;

		/// <summary>
		/// If TRUE, any limitations specified by the extension in the Value member of this structure are imperative. If FALSE, limitations set by this extension can be ignored
		/// </summary>
		public CERT_ISSUER_SERIAL_NUMBER Value;
	}

	/// <summary>
	/// IssuerSerialNumber
	/// </summary>
	public const uint CERT_ID_ISSUER_SERIAL_NUMBER = 1;

	/// <summary>
	/// KeyId
	/// </summary>
	public const uint CERT_ID_KEY_IDENTIFIER = 2;

	/// <summary>
	/// HashId
	/// </summary>
	public const uint CERT_ID_SHA1_HASH = 3;

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
		public uint dwVersion;

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
	}

	/// <summary>
	/// Version 1
	/// </summary>
	public const uint CERT_V1 = 0;

	/// <summary>
	/// Version 2
	/// </summary>
	public const uint CERT_V2 = 1;

	/// <summary>
	/// Version 3
	/// </summary>
	public const uint CERT_V3 = 2;



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
		[In] uint dwCertEncodingType,
		[In] nint pbCertEncoded,
		[In] uint cbCertEncoded);


	public const uint CERT_ENCODING_TYPE_MASK = 0x0000FFFF;
	public const uint CMSG_ENCODING_TYPE_MASK = 0xFFFF0000;
	public const uint CRYPT_ASN_ENCODING = 0x00000001;
	public const uint CRYPT_NDR_ENCODING = 0x00000002;
	public const uint X509_ASN_ENCODING = 0x00000001;
	public const uint X509_NDR_ENCODING = 0x00000002;
	public const uint PKCS_7_ASN_ENCODING = 0x00010000;
	public const uint PKCS_7_NDR_ENCODING = 0x00020000;



	/// <summary>
	/// Finds the first or next certificate context in a certificate store that matches a search criteria established by the dwFindType and its associated pvFindPara.
	/// This function can be used in a loop to find all of the certificates in a certificate store that match the specified find criteria.
	/// </summary>
	/// <param name="hCertStore">A handle of the certificate store to be searched.</param>
	/// <param name="dwCertEncodingType">Specifies the type of encoding used.</param>
	/// <param name="dwFindFlags">Used with some dwFindType values to modify the search criteria. For most dwFindType values, dwFindFlags is not used and should be set to zero.</param>
	/// <param name="dwFindType">Specifies the type of search being made. The search type determines the data type, contents, and the use of pvFindPara.</param>
	/// <param name="pvFindPara">Points to a data item or structure used with dwFindType.</param>
	/// <param name="pPrevCertContext">A pointer to the last <see cref="CERT_CONTEXT"/> structure returned by this function. This parameter must be NULL on the first call of the function. 
	/// To find successive certificates meeting the search criteria, set pPrevCertContext to the pointer returned by the previous call to the function. 
	/// This function frees the <see cref="CERT_CONTEXT"/> referenced by non-NULL values of this parameter.</param>
	/// <returns>If the function succeeds, the function returns a pointer to a read-only <see cref="CERT_CONTEXT"/> structure.
	/// If the function fails and a certificate that matches the search criteria is not found, the return value is NULL.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern nint CertFindCertificateInStore(
		[In] nint hCertStore,
		[In] uint dwCertEncodingType,
		[In] uint dwFindFlags,
		[In] uint dwFindType,
		[In] nint pvFindPara,
		[In] nint pPrevCertContext);

	// cert info flags.
	public const uint CERT_INFO_VERSION_FLAG = 1;
	public const uint CERT_INFO_SERIAL_NUMBER_FLAG = 2;
	public const uint CERT_INFO_SIGNATURE_ALGORITHM_FLAG = 3;
	public const uint CERT_INFO_ISSUER_FLAG = 4;
	public const uint CERT_INFO_NOT_BEFORE_FLAG = 5;
	public const uint CERT_INFO_NOT_AFTER_FLAG = 6;
	public const uint CERT_INFO_SUBJECT_FLAG = 7;
	public const uint CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG = 8;
	public const uint CERT_INFO_ISSUER_UNIQUE_ID_FLAG = 9;
	public const uint CERT_INFO_SUBJECT_UNIQUE_ID_FLAG = 10;
	public const uint CERT_INFO_EXTENSION_FLAG = 11;

	// cert compare flags.
	public const uint CERT_COMPARE_MASK = 0xFFFF;
	public const uint CERT_COMPARE_SHIFT = 16;
	public const uint CERT_COMPARE_ANY = 0;
	public const uint CERT_COMPARE_SHA1_HASH = 1;
	public const uint CERT_COMPARE_NAME = 2;
	public const uint CERT_COMPARE_ATTR = 3;
	public const uint CERT_COMPARE_MD5_HASH = 4;
	public const uint CERT_COMPARE_PROPERTY = 5;
	public const uint CERT_COMPARE_PUBLIC_KEY = 6;
	public const uint CERT_COMPARE_HASH = CERT_COMPARE_SHA1_HASH;
	public const uint CERT_COMPARE_NAME_STR_A = 7;
	public const uint CERT_COMPARE_NAME_STR_W = 8;
	public const uint CERT_COMPARE_KEY_SPEC = 9;
	public const uint CERT_COMPARE_ENHKEY_USAGE = 10;
	public const uint CERT_COMPARE_CTL_USAGE = CERT_COMPARE_ENHKEY_USAGE;
	public const uint CERT_COMPARE_SUBJECT_CERT = 11;
	public const uint CERT_COMPARE_ISSUER_OF = 12;
	public const uint CERT_COMPARE_EXISTING = 13;
	public const uint CERT_COMPARE_SIGNATURE_HASH = 14;
	public const uint CERT_COMPARE_KEY_IDENTIFIER = 15;
	public const uint CERT_COMPARE_CERT_ID = 16;
	public const uint CERT_COMPARE_CROSS_CERT_DIST_POINTS = 17;
	public const uint CERT_COMPARE_PUBKEY_MD5_HASH = 18;
	public const uint CERT_COMPARE_SUBJECT_INFO_ACCESS = 19;
	public const uint CERT_COMPARE_HASH_STR = 20;
	public const uint CERT_COMPARE_HAS_PRIVATE_KEY = 21;

	// cert find flags.
	/// <summary>
	/// No search criteria used. Returns the next certificate in the store.
	/// </summary>
	public const uint CERT_FIND_ANY = ((int)CERT_COMPARE_ANY << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// Searches for a certificate with a SHA1 hash that matches the hash in the <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// </summary>
	public const uint CERT_FIND_SHA1_HASH = ((int)CERT_COMPARE_SHA1_HASH << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// Searches for a certificate with an MD5 hash that matches the hash in <see cref="CRYPT_INTEGER_BLOB"/>.
	/// </summary>
	public const uint CERT_FIND_MD5_HASH = ((int)CERT_COMPARE_MD5_HASH << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// Searches for a certificate with a signature hash that matches the signature hash in the <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// </summary>
	public const uint CERT_FIND_SIGNATURE_HASH = ((int)CERT_COMPARE_SIGNATURE_HASH << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// Searches for a certificate with a <see cref="CERT_KEY_IDENTIFIER_PROP_ID"/> property that matches the key identifier in <see cref="CRYPT_INTEGER_BLOB"/>.
	/// </summary>
	public const uint CERT_FIND_KEY_IDENTIFIER = ((int)CERT_COMPARE_KEY_IDENTIFIER << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// Searches for a certificate with a SHA1 hash that matches the hash in the <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// </summary>
	public const uint CERT_FIND_HASH = CERT_FIND_SHA1_HASH;

	/// <summary>
	/// Data type of pvFindPara: DWORD variable that contains a property identifier.
	/// Searches for a certificate with a property that matches the property identifier specified by the DWORD value in pvFindPara.
	/// </summary>
	public const uint CERT_FIND_PROPERTY = ((int)CERT_COMPARE_PROPERTY << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_PUBLIC_KEY_INFO"/> structure.
	/// Searches for a certificate with a public key that matches the public key in the <see cref="CERT_PUBLIC_KEY_INFO"/> structure.
	/// </summary>
	public const uint CERT_FIND_PUBLIC_KEY = ((int)CERT_COMPARE_PUBLIC_KEY << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure.
	/// Searches for a certificate with an exact match of the entire subject name with the name in the <see cref="CRYPT_INTEGER_BLOB"/> structure.The search is restricted to certificates that match the value of dwCertEncodingType.
	/// </summary>
	public const uint CERT_FIND_SUBJECT_NAME = ((int)CERT_COMPARE_NAME << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_RDN"/> structure. Searches for a certificate with specified subject attributes that match attributes in the <see cref="CERT_RDN"/> structure.
	/// If RDN values are set, the function compares attributes of the subject in a certificate with elements of the <see cref="CERT_RDN_ATTR"/> array in this <see cref="CERT_RDN"/> structure.
	/// Comparisons iterate through the <see cref="CERT_RDN_ATTR"/> attributes looking for a match with the certificate's subject's attributes.
	/// </summary>
	public const uint CERT_FIND_SUBJECT_ATTR = ((int)CERT_COMPARE_ATTR << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CRYPT_INTEGER_BLOB"/> structure. 
	/// Search for a certificate with an exact match of the entire issuer name with the name in <see cref="CRYPT_INTEGER_BLOB"/>. 
	/// The search is restricted to certificates that match the dwCertEncodingType.
	/// </summary>
	public const uint CERT_FIND_ISSUER_NAME = ((int)CERT_COMPARE_NAME << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_RDN"/> structure. 
	/// Searches for a certificate with specified issuer attributes that match attributes in the <see cref="CERT_RDN"/> structure. 
	/// If these values are set, the function compares attributes of the issuer in a certificate with elements of the <see cref="CERT_RDN_ATTR"/> array in this <see cref="CERT_RDN"/> structure. 
	/// Comparisons iterate through the <see cref="CERT_RDN_ATTR"/> attributes looking for a match with the certificate's issuer attributes.
	/// </summary>
	public const uint CERT_FIND_ISSUER_ATTR = ((int)CERT_COMPARE_ATTR << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);

	/// <summary>
	/// Data type of pvFindPara: Null-terminated Unicode string.
	/// Searches for a certificate that contains the specified subject name string. The certificate's subject member is converted to a name string of the appropriate type using the appropriate form of CertNameToStr formatted as CERT_SIMPLE_NAME_STR. 
	/// Then a case-insensitive substring-within-a-string match is performed. When this value is set, the search is restricted to certificates whose encoding type matches dwCertEncodingType.
	/// </summary>
	public const uint CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W;
	public const uint CERT_FIND_SUBJECT_STR_A = ((int)CERT_COMPARE_NAME_STR_A << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);
	public const uint CERT_FIND_SUBJECT_STR_W = ((int)CERT_COMPARE_NAME_STR_W << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_SUBJECT_FLAG);

	/// <summary>
	/// Data type of pvFindPara: Null-terminated Unicode string. 
	/// Searches for a certificate that contains the specified issuer name string. The certificate's issuer member is converted to a name string of the appropriate type using the appropriate form of CertNameToStr formatted as CERT_SIMPLE_NAME_STR. 
	/// Then a case-insensitive substring-within-a-string match is performed. When this value is set, the search is restricted to certificates whose encoding type matches dwCertEncodingType.
	/// </summary>
	public const uint CERT_FIND_ISSUER_STR = CERT_FIND_ISSUER_STR_W;
	public const uint CERT_FIND_ISSUER_STR_A = ((int)CERT_COMPARE_NAME_STR_A << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);
	public const uint CERT_FIND_ISSUER_STR_W = ((int)CERT_COMPARE_NAME_STR_W << (int)CERT_COMPARE_SHIFT | (int)CERT_INFO_ISSUER_FLAG);

	/// <summary>
	/// Data type of pvFindPara: DWORD variable that contains a key specification.
	/// Searches for a certificate that has a <see cref="CERT_KEY_SPEC_PROP_ID"/> property that matches the key specification in pvFindPara.
	/// </summary>
	public const uint CERT_FIND_KEY_SPEC = ((int)CERT_COMPARE_KEY_SPEC << (int)CERT_COMPARE_SHIFT);
	public const uint CERT_FIND_ENHKEY_USAGE = ((int)CERT_COMPARE_ENHKEY_USAGE << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CTL_USAGE"/> structure.
	/// Searches for a certificate that has a szOID_ENHANCED_KEY_USAGE extension or a CERT_CTL_PROP_ID that matches the pszUsageIdentifier member of the <see cref="CTL_USAGE"/> structure.
	/// </summary>
	public const uint CERT_FIND_CTL_USAGE = CERT_FIND_ENHKEY_USAGE;

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_INFO"/> structure.
	/// Searches for a certificate with both an issuer and a serial number that match the issuer and serial number in the <see cref="CERT_INFO"/> structure.
	/// </summary>
	public const uint CERT_FIND_SUBJECT_CERT = ((int)CERT_COMPARE_SUBJECT_CERT << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_CONTEXT"/> structure.
	/// Searches for a certificate with a subject that matches the issuer in <see cref="CERT_CONTEXT"/>.
	/// </summary>
	public const uint CERT_FIND_ISSUER_OF = ((int)CERT_COMPARE_ISSUER_OF << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_CONTEXT"/> structure.
	/// Searches for a certificate that is an exact match of the specified certificate context.
	/// </summary>
	public const uint CERT_FIND_EXISTING = ((int)CERT_COMPARE_EXISTING << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: <see cref="CERT_ID"/> structure. 
	/// Find the certificate identified by the specified <see cref="CERT_ID"/>.
	/// </summary>
	public const uint CERT_FIND_CERT_ID = ((int)CERT_COMPARE_CERT_ID << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: Not used.
	/// Find a certificate that has either a cross certificate distribution point extension or property.
	/// </summary>
	public const uint CERT_FIND_CROSS_CERT_DIST_POINTS = ((int)CERT_COMPARE_CROSS_CERT_DIST_POINTS << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: CRYPT_HASH_BLOB structure.
	/// Find a certificate whose MD5-hashed public key matches the specified hash.
	/// </summary>
	public const uint CERT_FIND_PUBKEY_MD5_HASH = ((int)CERT_COMPARE_PUBKEY_MD5_HASH << (int)CERT_COMPARE_SHIFT);
	public const uint CERT_FIND_HASH_STR = ((int)CERT_COMPARE_HASH_STR << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Data type of pvFindPara: NULL, not used.
	/// Searches for a certificate that has a private key.The key can be ephemeral or saved on disk.The key can be a legacy Cryptography API(CAPI) key or a CNG key.
	/// </summary>
	public const uint CERT_FIND_HAS_PRIVATE_KEY = ((int)CERT_COMPARE_HAS_PRIVATE_KEY << (int)CERT_COMPARE_SHIFT);

	/// <summary>
	/// Value is used only with the CERT_FIND_SUBJECT_ATTR and CERT_FIND_ISSUER_ATTR values for dwFindType. 
	/// CERT_UNICODE_IS_RDN_ATTRS_FLAG must be set if the CERT_RDN_ATTR structure pointed to by pvFindPara was initialized with Unicode strings. 
	/// Before any comparison is made, the string to be matched is converted by using X509_UNICODE_NAME to provide for Unicode comparisons.
	/// </summary>
	public const uint CERT_UNICODE_IS_RDN_ATTRS_FLAG = 0x1;

	/// <summary>
	/// A pointer to a <see cref="CERT_CHAIN_CONTEXT"/> certificate chain context to be freed. If the reference count on the context reaches zero, the storage allocated for the context is freed.
	/// </summary>
	/// <param name="pChainContext"></param>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatechain</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern void CertFreeCertificateChain(
		[In] nint pChainContext
	);


	/// <summary>
	/// Frees a certificate context by decrementing its reference count. When the reference count goes to zero, the function frees the memory used by a certificate contex
	/// </summary>
	/// <param name="pCertContext">A pointer to the <see cref="CERT_CONTEXT"/> to be freed.</param>
	/// <returns>The function always returns nonzero.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfreecertificatecontext</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CertFreeCertificateContext(
		[In] nint pCertContext
	);

	/// <summary>
	/// Builds a certificate chain context starting from an end certificate and going back, if possible, to a trusted root certificate.
	/// </summary>
	/// <param name="hChainEngine">A handle of the chain engine (namespace and cache) to be used. If hChainEngine is NULL, the default chain engine, <see cref="HCCE_CURRENT_USER"/>, is used.</param>
	/// <param name="pCertContext">A pointer to the <see cref="CERT_CONTEXT"/> of the end certificate, the certificate for which a chain is being built. This certificate context will be the zero-index element in the first simple chain.</param>
	/// <param name="pTime">A pointer to a <see cref="FILETIME"/> variable that indicates the time for which the chain is to be validated. Note that the time does not affect trust list, revocation, or root store checking. The current system time is used if NULL is passed to this parameter.</param>
	/// <param name="hAdditionalStore">A handle to any additional store to search for supporting certificates and certificate trust lists (CTLs). This parameter can be NULL if no additional store is to be searched.</param>
	/// <param name="pChainPara">A pointer to a <see cref="CERT_CHAIN_PARA"/> structure that includes chain-building parameters.</param>
	/// <param name="dwFlags">Flag values that indicate special processing.</param>
	/// <param name="pvReserved">This parameter is reserved and must be NULL.</param>
	/// <param name="ppChainContext">The address of a pointer to the chain context created. When you have finished using the chain context, release the chain by calling the <see cref="CertFreeCertificateChain"/> function.</param>
	/// <returns>If the function succeeds, the function returns nonzero (TRUE). If the function fails, it returns zero (FALSE).</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CertGetCertificateChain(
	  [In, Optional] nint hChainEngine,
	  [In] nint pCertContext,
	  [In, Optional] nint pTime,
	  [In] nint hAdditionalStore,
	  [In] nint pChainPara,
	  [In] uint dwFlags,
	  [In] nint pvReserved,
	  [Out] nint ppChainContext
	);

	public const nint HCCE_CURRENT_USER = 0x0;
	public const nint HCCE_LOCAL_MACHINE = 0x1;
	public const nint HCCE_SERIAL_LOCAL_MACHINE = 0x2;

	/// <summary>
	/// When this flag is set, the end certificate is cached, which might speed up the chain-building process. 
	/// By default, the end certificate is not cached, and it would need to be verified each time a chain is built for it.
	/// </summary>
	public const uint CERT_CHAIN_CACHE_END_CERT = 0x00000001;

	/// <summary>
	/// Revocation checking only accesses cached URLs.
	/// </summary>
	public const uint CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY = 0x80000000;

	/// <summary>
	/// This flag is used internally during chain building for an online certificate status protocol (OCSP) signer certificate to prevent cyclic revocation checks. 
	/// During chain building, if the OCSP response is signed by an independent OCSP signer, then, in addition to the original chain build, there is a second chain built for the OCSP signer certificate itself. 
	/// This flag is used during this second chain build to inhibit a recursive independent OCSP signer certificate.
	/// </summary>
	public const uint CERT_CHAIN_REVOCATION_CHECK_OCSP_CERT = 0x04000000;

	/// <summary>
	/// Uses only cached URLs in building a certificate chain. The Internet and intranet are not searched for URL-based objects.
	/// This flag is not applicable to revocation checking. Set <see cref="CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY"/> to use only cached URLs for revocation checking.
	/// </summary>
	public const uint CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL = 0x00000004;

	/// <summary>
	/// For performance reasons, the second pass of chain building only considers potential chain paths that have quality greater than or equal to the highest quality determined during the first pass. 
	/// The first pass only considers valid signature, complete chain, and trusted roots to calculate chain quality. 
	/// This flag can be set to disable this optimization and consider all potential chain paths during the second pass.
	/// </summary>
	public const uint CERT_CHAIN_DISABLE_PASS1_QUALITY_FILTERING = 0x00000040;

	/// <summary>
	/// This flag is not supported. Certificates in the "My" store are never considered for peer trust.
	/// </summary>
	public const uint CERT_CHAIN_DISABLE_MY_PEER_TRUST = 0x00000800;

	/// <summary>
	/// End entity certificates in the "TrustedPeople" store are trusted without performing any chain building. 
	/// This function does not set the CERT_TRUST_IS_PARTIAL_CHAIN or CERT_TRUST_IS_UNTRUSTED_ROOT dwErrorStatus member bits of the ppChainContext parameter.
	/// </summary>
	public const uint CERT_CHAIN_ENABLE_PEER_TRUST = 0x00000400;

	/// <summary>
	/// Setting this flag indicates the caller wishes to opt into weak signature checks.
	/// </summary>
	public const uint CERT_CHAIN_OPT_IN_WEAK_SIGNATURE = 0x00010000;

	/// <summary>
	/// The default is to return only the highest quality chain path. Setting this flag will return the lower quality chains. 
	/// These are returned in the cLowerQualityChainContext and rgpLowerQualityChainContext fields of the chain context.
	/// </summary>
	public const uint CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS = 0x00000080;

	/// <summary>
	/// Setting this flag inhibits the auto update of third-party roots from the Windows Update Web Server.
	/// </summary>
	public const uint CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE = 0x00000100;

	/// <summary>
	/// When you set CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT and you also specify a value for the dwUrlRetrievalTimeout member of the CERT_CHAIN_PARA structure, the value you specify in dwUrlRetrievalTimeout represents the cumulative timeout across all revocation URL retrievals.
	/// If you set CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT but do not specify a dwUrlRetrievalTimeout value, the maximum cumulative timeout is set, by default, to 20 seconds. 
	/// Each URL tested will timeout after half of the remaining cumulative balance has passed. That is, the first URL times out after 10 seconds, the second after 5 seconds, the third after 2.5 seconds and so on until a URL succeeds, 20 seconds has passed, or there are no more URLs to test.
	/// If you do not set CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT, each revocation URL in the chain is assigned a maximum timeout equal to the value specified in dwUrlRetrievalTimeout. 
	/// If you do not specify a value for the dwUrlRetrievalTimeout member, each revocation URL is assigned a maximum default timeout of 15 seconds. 
	/// If no URL succeeds, the maximum cumulative timeout value is 15 seconds multiplied by the number of URLs in the chain.
	/// </summary>
	public const uint CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT = 0x08000000;

	/// <summary>
	/// When this flag is set, pTime is used as the time stamp time to determine whether the end certificate was time valid. Current time can also be used to determine whether the end certificate remains time valid. 
	/// All other certification authority (CA) and root certificates in the chain are checked by using current time and not pTime.
	/// </summary>
	public const uint CERT_CHAIN_TIMESTAMP_TIME = 0x00000200;

	/// <summary>
	/// Setting this flag explicitly turns off Authority Information Access (AIA) retrievals.
	/// </summary>
	public const uint CERT_CHAIN_DISABLE_AIA = 0x00002000;

	/// <summary>
	/// Revocation checking is done on the end certificate and only the end certificate.
	/// </summary>
	public const uint CERT_CHAIN_REVOCATION_CHECK_END_CERT = 0x10000000;

	/// <summary>
	/// Revocation checking is done on all of the certificates in every chain.
	/// </summary>
	public const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000;

	/// <summary>
	/// Revocation checking is done on all certificates in all of the chains except the root certificate.
	/// </summary>
	public const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x40000000;

	/// <summary>
	/// Establishes the searching and matching criteria to be used in building a certificate chain.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_CHAIN_PARA
	{
		/// <summary>
		/// The size, in bytes, of this structure.
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// Structure indicating the kind of matching necessary to find issuer certificates for building a certificate chain. 
		/// The structure pointed to indicates whether AND or OR logic is to be used in the matching process. The structure also includes an array of OIDs to be matched.
		/// </summary>
		public CERT_USAGE_MATCH RequestedUsage;

		/// <summary>
		/// Optional structure that indicates the kind of issuance policy constraint matching that applies when building a certificate chain. 
		/// The structure pointed to indicates whether AND or OR logic is to be used in the matching process. The structure also includes an array of OIDs to be matched.
		/// </summary>
		public CERT_USAGE_MATCH RequestedIssuancePolicy;

		/// <summary>
		/// Optional time, in milliseconds, before revocation checking times out. This member is optional.
		/// </summary>
		public uint dwUrlRetrievalTimeout;

		/// <summary>
		/// Optional member. When this flag is TRUE, an attempt is made to retrieve a new CRL if this update is greater than or equal to the current system time minus the dwRevocationFreshnessTime value. 
		/// If this flag is not set, the CRL's next update time is used.
		/// </summary>
		public bool fCheckRevocationFreshnessTime;

		/// <summary>
		/// The current time, in seconds, minus the CRL's update time of all elements checked.
		/// </summary>
		public uint dwRevocationFreshnessTime;

		/// <summary>
		/// Optional member. When set to a non-NULL value, information cached before the time specified is considered to be not valid and cache resynchronization is performed.
		/// </summary>
		public nint pftCacheResync;

		/// <summary>
		/// Optional. Specify a pointer to a <see cref="CERT_STRONG_SIGN_PARA"/> structure to enable strong signature checking.
		/// </summary>
		public nint pStrongSignPara;

		/// <summary>
		/// Optional flags that modify chain retrieval behavior.
		/// </summary>
		public uint dwStrongSignFlags;

		/// <summary>
		/// Initializes a new instance of the <see cref="CERT_CHAIN_PARA"/> structure
		/// </summary>
		public CERT_CHAIN_PARA()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
	}

	/// <summary>
	/// If the chain is strong signed, the public key in the end certificate will be checked to verify whether it satisfies the minimum public key length requirements for a strong signature. 
	/// You can specify this flag to disable default checking.
	/// </summary>
	public const uint CERT_CHAIN_STRONG_SIGN_DISABLE_END_CHECK_FLAG = 0x00000001;

	/// <summary>
	/// Provides criteria for identifying issuer certificates to be used to build a certificate chain.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_usage_match</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_USAGE_MATCH
	{
		/// <summary>
		/// Determines the kind of issuer matching to be done. In AND logic, the certificate must meet all criteria. In OR logic, the certificate must meet at least one of the criteria.
		/// </summary>
		public uint dwType;

		/// <summary>
		/// <see cref="CTL_USAGE"/> structure includes an array of certificate object identifiers (OIDs) that a certificate must match in order to be valid.
		/// </summary>
		public CTL_USAGE Usage;
	}

	public const uint USAGE_MATCH_TYPE_AND = 0x00000000;
	public const uint USAGE_MATCH_TYPE_OR = 0x00000001;

	/// <summary>
	/// Contains an array of object identifiers (OIDs) for Certificate Trust List (CTL) extensions. CTL_USAGE structures are used in functions that search for CTLs for specific uses.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-ctl_usage</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CTL_USAGE
	{
		/// <summary>
		/// Number of elements in the rgpszUsageIdentifier member array
		/// </summary>
		public uint cUsageIdentifier;

		/// <summary>
		/// Array of object identifiers (OIDs) of CTL extensions.
		/// </summary>
		public nint rgpszUsageIdentifier;
	}

	/// <summary>
	/// Checks a certificate chain to verify its validity, including its compliance with any specified validity policy criteria.
	/// </summary>
	/// <param name="pszPolicyOID">The policy</param>
	/// <param name="pChainContext">A pointer to a <see cref="CERT_CHAIN_CONTEXT"/> structure that contains a chain to be verified.</param>
	/// <param name="pPolicyPara">A pointer to a <see cref="CERT_CHAIN_POLICY_PARA"/> structure that provides the policy verification criteria for the chain. 
	/// The dwFlags member of that structure can be set to change the default policy checking behavior.
	///	In addition, policy-specific parameters can also be passed in the pvExtraPolicyPara member of the structure.</param>
	/// <param name="pPolicyStatus">A pointer to a <see cref="CERT_CHAIN_POLICY_STATUS"/> structure where status information on the chain is returned.
	/// OID-specific extra status can be returned in the pvExtraPolicyStatus member of this structure.</param>
	/// <returns>If the chain can be verified for the specified policy, TRUE is returned and the dwError member of the pPolicyStatus is updated.
	/// A dwError of 0 (ERROR_SUCCESS or S_OK) indicates the chain satisfies the specified policy.
	/// A value of FALSE indicates that the function wasn't able to check for the policy.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CertVerifyCertificateChainPolicy(
	  [In] nint pszPolicyOID,
	  [In] nint pChainContext,
	  [In] nint pPolicyPara,
	  [In, Out] nint pPolicyStatus
	);

	/// <summary>
	/// Implements the base chain policy verification checks. The dwFlags member of the structure pointed to by pPolicyPara can be set to alter the default policy checking behavior.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_BASE = 1;

	/// <summary>
	/// Implements the Authenticode chain policy verification checks. 
	/// The pvExtraPolicyPara member of the structure pointed to by pPolicyPara can be set to point to an <see cref="AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_PARA"/> structure. 
	/// The pvExtraPolicyStatus member of the structure pointed to by pPolicyStatus can be set to point to an <see cref="AUTHENTICODE_EXTRA_CERT_CHAIN_POLICY_STATUS"/> structure.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_AUTHENTICODE = 2;

	/// <summary>
	/// Implements Authenticode Time Stamp chain policy verification checks. 
	/// The pvExtraPolicyPara member of the data structure pointed to by pPolicyPara can be set to point to an <see cref="AUTHENTICODE_TS_EXTRA_CERT_CHAIN_POLICY_PARA"/> structure.
	/// The pvExtraPolicyStatus member of the data structure pointed to by pPolicyStatus is not used and must be set to NULL
	/// </summary>
	public const nint CERT_CHAIN_POLICY_AUTHENTICODE_TS = 3;

	/// <summary>
	///	Implements the SSL client/server chain policy verification checks. 
	///	The pvExtraPolicyPara member in the data structure pointed to by pPolicyPara can be set to point to an <see cref="SSL_EXTRA_CERT_CHAIN_POLICY_PARA"/> structure initialized with additional policy criteria.
	///	To differentiate between server and client authorization certificates, the call to the <see cref="CertGetCertificateChain"/> function to get the chain context should specify the certificate type by setting the expected usage. 
	///	Set the expected usage by setting the RequestedUsage member of the <see cref="CERT_CHAIN_PARA structure passed in the pChainPara input parameter of the CertGetCertificateChain function.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_SSL = 4;

	/// <summary>
	/// Implements the basic constraints chain policy. Iterates through all the certificates in the chain checking for either a szOID_BASIC_CONSTRAINTS or a szOID_BASIC_CONSTRAINTS2 extension. 
	/// If neither extension is present, the certificate is assumed to have valid policy. Otherwise, for the first certificate element,
	/// checks if it matches the expected CA_FLAG or END_ENTITY_FLAG specified in the dwFlags member of the <see cref="CERT_CHAIN_POLICY_PARA"/> structure pointed to by the pPolicyPara parameter. 
	/// If neither or both flags are set, then, the first element can be either a CA or END_ENTITY. All other elements must be a certification authority (CA). 
	/// If the PathLenConstraint is present in the extension, it is checked. The first elements in the remaining simple chains(that is, the certificates used to sign the CTL) are checked to be an END_ENTITY.
	/// If this verification fails, dwError will be set to TRUST_E_BASIC_CONSTRAINTS.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_BASIC_CONSTRAINTS = 5;

	/// <summary>
	/// Implements the Windows NT Authentication chain policy, which consists of three distinct chain verifications in the following order: 
	/// <see cref="CERT_CHAIN_POLICY_BASE"/> — Implements the base chain policy verification checks.The LOWORD of dwFlags can be set in pPolicyPara to alter the default policy checking behavior.For more information, see CERT_CHAIN_POLICY_BASE.
	/// <see cref="CERT_CHAIN_POLICY_BASIC_CONSTRAINTS"/> — Implements the basic constraints chain policy. The HIWORD of dwFlags can be set to specify if the first element must be either a CA or END_ENTITY. 
	/// For more information, see <see cref="CERT_CHAIN_POLICY_BASIC_CONSTRAINTS"/>. Checks if the second element in the chain, the CA that issued the end certificate, is a trusted CA for Windows NT Authentication.
	/// A CA is considered to be trusted if it exists in the "NTAuth" system registry store found in the CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE store location. 
	/// If this verification fails, the CA is untrusted, and dwError is set to CERT_E_UNTRUSTEDCA.
	/// If CERT_PROT_ROOT_DISABLE_NT_AUTH_REQUIRED_FLAG is set in the Flags value of the HKEY_LOCAL_MACHINE policy ProtectedRoots subkey, defined by CERT_PROT_ROOT_FLAGS_REGPATH and the above check fails, the chain is checked for CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS set in dwInfoStatus.
	/// This is set if there was a valid name constraint for all namespaces including UPN. If the chain does not have this info status set, dwError is set to CERT_E_UNTRUSTEDCA.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_NT_AUTH = 6;

	/// <summary>
	/// Checks the last element of the first simple chain for a Microsoft root public key. 
	/// If that element does not contain a Microsoft root public key, the dwError member of the CERT_CHAIN_POLICY_STATUS structure pointed to by the pPolicyStatus parameter is set to CERT_E_UNTRUSTEDROOT.
	/// The dwFlags member of the <see cref="CERT_CHAIN_POLICY_PARA"/> structure pointed to by the pPolicyStatus parameter can contain the MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG flag, 
	/// which causes this function to instead check for the Microsoft application root "Microsoft Root Certificate Authority 2011".
	/// The dwFlags member of the <see cref="CERT_CHAIN_POLICY_PARA"/> structure pointed to by the pPolicyPara parameter can contain the MICROSOFT_ROOT_CERT_CHAIN_POLICY_ENABLE_TEST_ROOT_FLAG flag, 
	/// which causes this function to also check for the Microsoft test roots.
	/// Note This policy object identifier (OID) does not perform any policy verification checks by itself, it is meant to be used in conjunction with other policies.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_MICROSOFT_ROOT = 7;

	/// <summary>
	/// Specifies that extended validation of certificates is performed.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_EV = 8;

	/// <summary>
	/// Checks if any certificates in the chain have weak crypto or if third party root certificate compliance and provide an error string. 
	/// The pvExtraPolicyStatus member of the <see cref="CERT_CHAIN_POLICY_STATUS"/> structure pointed to by the pPolicyStatus parameter must point to <see cref="SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS"/>, 
	/// which is updated with the results of the weak crypto and root program compliance checks. 
	/// Before calling, the cbSize member of the CERT_CHAIN_POLICY_STATUS structure pointed to by the pPolicyStatus parameter must be set to a value greater than or equal to sizeof(SSL_F12_EXTRA_CERT_CHAIN_POLICY_STATUS).
	/// The dwError member in <see cref="CERT_CHAIN_POLICY_STATUS"/> structure pointed to by the pPolicyStatus parameter will be set to TRUST_E_CERT_SIGNATURE for potential weak crypto and set to CERT_E_UNTRUSTEDROOT for Third Party Roots not in compliance with the Microsoft Root Program.
	/// </summary>
	public const nint CERT_CHAIN_POLICY_SSL_F12 = 9;


	/// <summary>
	/// Contains an array of simple certificate chains and a trust status structure that indicates summary validity data on all of the connected simple chains.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_context</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_CHAIN_CONTEXT
	{
		/// <summary>
		/// The size, in bytes, of this structure.
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// A structure that indicates the combined trust status of the simple chains array. The structure includes an error status code and an information status code.
		/// </summary>
		public CERT_TRUST_STATUS TrustStatus;

		/// <summary>
		/// The number of simple chains in the array.
		/// </summary>
		public uint cChain;

		/// <summary>
		/// An array of pointers to simple chain structures. rgpChain[0] is the end certificate simple chain, and rgpChain[cChain–1] is the final chain. 
		/// If the end certificate is to be considered valid, the final chain must begin with a certificate contained in the root store or an otherwise trusted, self-signed certificate. 
		/// If the original chain begins with a trusted certificate, there will be only a single simple chain in the array.
		/// </summary>
		public nint rgpChain;

		/// <summary>
		/// The number of chains in the rgpLowerQualityChainContext array.
		/// </summary>
		public uint cLowerQualityChainContext;

		/// <summary>
		/// An array of pointers to <see cref="CERT_CHAIN_CONTEXT"/> structures. Returned when <see cref="CERT_CHAIN_RETURN_LOWER_QUALITY_CONTEXTS"/> is set in dwFlags.
		/// </summary>
		public nint rgpLowerQualityChainContext;

		/// <summary>
		/// A Boolean value set to TRUE if dwRevocationFreshnessTime is available.
		/// </summary>
		public bool fHasRevocationFreshnessTime;

		/// <summary>
		/// The largest CurrentTime, in seconds, minus the certificate revocation list's (CRL's) ThisUpdate of all elements checked.
		/// </summary>
		public uint dwRevocationFreshnessTime;

		/// <summary>
		/// Not documented
		/// </summary>
		public uint dwCreateFlags;

		/// <summary>
		/// Not documented
		/// </summary>
		public Guid ChainId;
	}

	/// <summary>
	/// Contains trust information about a certificate in a certificate chain, summary trust information about a simple chain of certificates, or summary information about an array of simple chains.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_TRUST_STATUS
	{
		/// <summary>
		/// dwErrorStatus is a bitmask of the following error codes defined for certificates and chains.
		/// </summary>
		public uint dwErrorStatus;

		/// <summary>
		/// The following information status codes are defined.
		/// </summary>
		public uint dwInfoStatus;
	}

	/// <summary>
	/// No error found for this certificate or chain.
	/// </summary>
	public const uint CERT_TRUST_NO_ERROR = 0x00000000;

	/// <summary>
	/// This certificate or one of the certificates in the certificate chain is not time valid.
	/// </summary>
	public const uint CERT_TRUST_IS_NOT_TIME_VALID = 0x00000001;

	/// <summary>
	/// Trust for this certificate or one of the certificates in the certificate chain has been revoked.
	/// </summary>
	public const uint CERT_TRUST_IS_REVOKED = 0x00000004;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain does not have a valid signature.
	/// </summary>
	public const uint CERT_TRUST_IS_NOT_SIGNATURE_VALID = 0x00000008;

	/// <summary>
	/// The certificate or certificate chain is not valid for its proposed usage.
	/// </summary>
	public const uint CERT_TRUST_IS_NOT_VALID_FOR_USAGE = 0x00000010;

	/// <summary>
	/// The certificate or certificate chain is based on an untrusted root.
	/// </summary>
	public const uint CERT_TRUST_IS_UNTRUSTED_ROOT = 0x00000020;

	/// <summary>
	/// The revocation status of the certificate or one of the certificates in the certificate chain is unknown.
	/// </summary>
	public const uint CERT_TRUST_REVOCATION_STATUS_UNKNOWN = 0x00000040;

	/// <summary>
	/// One of the certificates in the chain was issued by a certification authority that the original certificate had certified.
	/// </summary>
	public const uint CERT_TRUST_IS_CYCLIC = 0x00000080;

	/// <summary>
	/// One of the certificates has an extension that is not valid.
	/// </summary>
	public const uint CERT_TRUST_INVALID_EXTENSION = 0x00000100;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a policy constraints extension, 
	/// and one of the issued certificates has a disallowed policy mapping extension or does not have a required issuance policies extension.
	/// </summary>
	public const uint CERT_TRUST_INVALID_POLICY_CONSTRAINTS = 0x00000200;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a basic constraints extension, and either the certificate cannot be used to issue other certificates, 
	/// or the chain path length has been exceeded.
	/// </summary>
	public const uint CERT_TRUST_INVALID_BASIC_CONSTRAINTS = 0x00000400;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a name constraints extension that is not valid.
	/// </summary>
	public const uint CERT_TRUST_INVALID_NAME_CONSTRAINTS = 0x00000800;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a name constraints extension that contains unsupported fields. 
	/// The minimum and maximum fields are not supported. Thus minimum must always be zero and maximum must always be absent. 
	/// Only UPN is supported for an Other Name.The following alternative name choices are not supported: X400 Address, EDI Party Name, Registered Id
	/// </summary>
	public const uint CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x00001000;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a name constraints extension and a name constraint is missing for one of the name choices in the end certificate.
	/// </summary>
	public const uint CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT = 0x00002000;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a name constraints extension, and there is not a permitted name constraint for one of the name choices in the end certificate.
	/// </summary>
	public const uint CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x00004000;

	/// <summary>
	/// The certificate or one of the certificates in the certificate chain has a name constraints extension, and one of the name choices in the end certificate is explicitly excluded.
	/// </summary>
	public const uint CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT = 0x00008000;

	/// <summary>
	/// The revocation status of the certificate or one of the certificates in the certificate chain is either offline or stale.
	/// </summary>
	public const uint CERT_TRUST_IS_OFFLINE_REVOCATION = 0x01000000;

	/// <summary>
	/// The end certificate does not have any resultant issuance policies, and one of the issuing certification authority certificates has a policy constraints extension requiring it.
	/// </summary>
	public const uint CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY = 0x02000000;

	/// <summary>
	/// The certificate is explicitly distrusted.
	/// </summary>
	public const uint CERT_TRUST_IS_EXPLICIT_DISTRUST = 0x04000000;

	/// <summary>
	/// The certificate does not support a critical extension.
	/// </summary>
	public const uint CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT = 0x08000000;

	/// <summary>
	/// The certificate has not been strong signed. Typically this indicates that the MD2 or MD5 hashing algorithms were used to create a hash of the certificate.
	/// </summary>
	public const uint CERT_TRUST_HAS_WEAK_SIGNATURE = 0x00100000;

	/// <summary>
	/// The certificate chain is not complete.
	/// </summary>
	public const uint CERT_TRUST_IS_PARTIAL_CHAIN = 0x00010000;

	/// <summary>
	/// A certificate trust list (CTL) used to create this chain was not time valid.
	/// </summary>
	public const uint CERT_TRUST_CTL_IS_NOT_TIME_VALID = 0x00020000;

	/// <summary>
	/// A CTL used to create this chain did not have a valid signature.
	/// </summary>
	public const uint CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID = 0x00040000;

	/// <summary>
	/// A CTL used to create this chain is not valid for this usage.
	/// </summary>
	public const uint CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE = 0x00080000;

	/// <summary>
	/// An exact match issuer certificate has been found for this certificate.This status code applies to certificates only.
	/// </summary>
	public const uint CERT_TRUST_HAS_EXACT_MATCH_ISSUER = 0x00000001;

	/// <summary>
	/// A key match issuer certificate has been found for this certificate.This status code applies to certificates only.
	/// </summary>
	public const uint CERT_TRUST_HAS_KEY_MATCH_ISSUER = 0x00000002;

	/// <summary>
	/// A name match issuer certificate has been found for this certificate.This status code applies to certificates only.
	/// </summary>
	public const uint CERT_TRUST_HAS_NAME_MATCH_ISSUER = 0x00000004;


	/// <summary>
	/// This certificate is self-signed.This status code applies to certificates only.
	/// </summary>
	public const uint CERT_TRUST_IS_SELF_SIGNED = 0x00000008;

	/// <summary>
	/// The certificate or chain has a preferred issuer.This status code applies to certificates and chains.
	/// </summary>
	public const uint CERT_TRUST_HAS_PREFERRED_ISSUER = 0x00000100;

	/// <summary>
	/// An issuance chain policy exists.This status code applies to certificates and chains.
	/// </summary>
	public const uint CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY = 0x00000400;


	/// <summary>
	/// A valid name constraints for all namespaces, including UPN. This status code applies to certificates and chains.
	/// </summary>
	public const uint CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS = 0x00000400;


	/// <summary>
	/// This certificate is peer trusted. This status code applies to certificates only.
	/// </summary>
	public const uint CERT_TRUST_IS_PEER_TRUSTED = 0x00000800;

	/// <summary>
	/// This certificate's certificate revocation list (CRL) validity has been extended. This status code applies to certificates only.
	/// </summary>
	public const uint CERT_TRUST_HAS_CRL_VALIDITY_EXTENDED = 0x00001000;

	/// <summary>
	/// The certificate was found in either a store pointed to by the hExclusiveRoot or hExclusiveTrustedPeople member of the CERT_CHAIN_ENGINE_CONFIG structure.
	/// </summary>
	public const uint CERT_TRUST_IS_FROM_EXCLUSIVE_TRUST_STORE = 0x00002000;

	/// <summary>
	/// The certificate chain created is a complex chain.This status code applies to chains only.
	/// </summary>
	public const uint CERT_TRUST_IS_COMPLEX_CHAIN = 0x00010000;


	/// <summary>
	/// A non-self-signed intermediate CA certificate was found in the store pointed to by the hExclusiveRoot member of the CERT_CHAIN_ENGINE_CONFIG structure. 
	/// The CA certificate is treated as a trust anchor for the certificate chain.
	/// This flag will only be set if the CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG value is set in the dwExclusiveFlags member of the <see cref="CERT_CHAIN_ENGINE_CONFIG"/> structure. 
	/// If this flag is set, the CERT_TRUST_IS_SELF_SIGNED and the CERT_TRUST_IS_PARTIAL_CHAIN dwErrorStatus flags will not be set.
	/// </summary>
	public const uint CERT_TRUST_IS_CA_TRUSTED = 0x00004000;

	/// <summary>
	/// Contains information used in <see cref="CertVerifyCertificateChainPolicy"/> to establish policy criteria for the verification of certificate chains.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_CHAIN_POLICY_PARA
	{
		/// <summary>
		/// The size, in bytes, of this structure.
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// A set of flags that indicate conditions that could potentially be not valid and that are to be ignored in building certificate chains.
		/// </summary>
		public uint dwFlags;

		/// <summary>
		/// The address of a pszPolicyOID-specific structure that provides additional validity policy conditions.
		/// </summary>
		public nint pvExtraPolicyPara;

		/// <summary>
		/// Initializes a new instance of the <see cref="CERT_CHAIN_POLICY_PARA"/> structure
		/// </summary>
		public CERT_CHAIN_POLICY_PARA()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
	}

	#region Possible values for the CERT_CHAIN_POLICY_PARA.dwFlags member

	/// <summary>
	/// Ignore not time valid errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG = 0x00000001;

	/// <summary>
	/// Ignore certificate trust list (CTL) not time valid errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG = 0x00000002;

	/// <summary>
	/// Ignore time nesting errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG = 0x00000004;

	/// <summary>
	/// Ignore all time validity errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS =
		CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG | CERT_CHAIN_POLICY_IGNORE_CTL_NOT_TIME_VALID_FLAG | CERT_CHAIN_POLICY_IGNORE_NOT_TIME_NESTED_FLAG;

	/// <summary>
	/// Ignore basic constraint errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG = 0x00000008;

	/// <summary>
	/// Allow untrusted roots.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG = 0x00000010;

	/// <summary>
	/// Ignore invalid usage errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG = 0x00000020;

	/// <summary>
	/// Ignore invalid name errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG = 0x00000040;

	/// <summary>
	/// Ignore invalid policy errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG = 0x00000080;

	/// <summary>
	/// Ignores errors in obtaining valid revocation information.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG = 0x00000100;

	/// <summary>
	/// Ignores errors in obtaining valid CTL revocation information.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG = 0x00000200;

	/// <summary>
	/// Ignores errors in obtaining valid certification authority (CA) revocation information.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG = 0x00000400;

	/// <summary>
	/// Ignores errors in obtaining valid root revocation information.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG = 0x00000800;

	/// <summary>
	/// Ignores errors in obtaining valid revocation information.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS =
		CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN_FLAG | CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN_FLAG
		| CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN_FLAG | CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN_FLAG;

	/// <summary>
	/// Allow untrusted test roots.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_ALLOW_TESTROOT_FLAG = 0x00008000;

	/// <summary>
	/// Always trust test roots.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_TRUST_TESTROOT_FLAG = 0x00004000;

	/// <summary>
	/// Ignore critical extension not supported errors.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_NOT_SUPPORTED_CRITICAL_EXT_FLAG = 0x00002000;

	/// <summary>
	/// Ignore peer trusts.
	/// </summary>
	public const uint CERT_CHAIN_POLICY_IGNORE_PEER_TRUST_FLAG = 0x00001000;

	/// <summary>
	/// Checks if the first certificate element is a CA.
	/// </summary>
	public const uint BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_CA_FLAG = 0x80000000;

	/// <summary>
	/// Checks if the first certificate element is an end entity.
	/// </summary>
	public const uint BASIC_CONSTRAINTS_CERT_CHAIN_POLICY_END_ENTITY_FLAG = 0x40000000;

	/// <summary>
	/// Also check for the Microsoft test roots in addition to the Microsoft public root.
	/// </summary>
	public const uint MICROSOFT_ROOT_CERT_CHAIN_POLICY_ENABLE_TEST_ROOT_FLAG = 0x00010000;

	#endregion

	/// <summary>
	/// Holds certificate chain status information returned by the CertVerifyCertificateChainPolicy function when the certificate chains are validated.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_status</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CERT_CHAIN_POLICY_STATUS
	{
		/// <summary>
		/// The size, in bytes, of this structure.
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// A value that indicates that an error or invalid condition was encountered during the validation process. 
		/// The values of this member are specific to the policy type as specified by the value of the pszPolicyOID parameter of the <see cref="CertVerifyCertificateChainPolicy"/> function.
		/// </summary>
		public uint dwError;

		/// <summary>
		/// Index that indicates the chain in which an error or condition that is not valid was found. 
		/// </summary>
		public int lChainIndex;

		/// <summary>
		/// Index that indicates the element in a chain where an error or condition that is not valid was found.
		/// </summary>
		public int lElementIndex;

		/// <summary>
		/// A pointer to a structure. The structure type is determined by the value of the pszPolicyOID parameter of the <see cref="CertVerifyCertificateChainPolicy"/> function.
		/// In addition to dwError errors, policy OID–specific extra status can also be returned here to provide additional chain status information.
		/// </summary>
		public nint pvExtraPolicyStatus;

		/// <summary>
		/// Initializes a new instance of the <see cref="CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA"/> structure
		/// </summary>
		public CERT_CHAIN_POLICY_STATUS()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
	}

	/// <summary>
	/// Opens a certificate store by using a specified store provider type. While this function can open a certificate store for most purposes, CertOpenSystemStore is recommended to open the most common certificate stores. 
	/// CertOpenStore is required for more complex options and special cases.
	/// </summary>
	/// <param name="lpszStoreProvider">A pointer to a null-terminated ANSI string that contains the store provider type.</param>
	/// <param name="dwEncodingType">Specifies the certificate encoding type and message encoding type.</param>
	/// <param name="hCryptProv">This parameter is not used and should be set to NULL.</param>
	/// <param name="dwFlags">These values consist of high-word and low-word values combined by using a bitwise-OR operation.</param>
	/// <param name="pvPara">A value that can contain additional information for this function. The contents of this parameter depends on the value of the lpszStoreProvider and other parameters.</param>
	/// <returns>If the function succeeds, the function returns a handle to the certificate store. When you have finished using the store, release the handle by calling the <see cref="CertCloseStore"/> function.
	/// If the function fails, it returns NULL.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern nint CertOpenStore(
		[In] nint lpszStoreProvider,
		[In] uint dwEncodingType,
		[In] nint hCryptProv,
		[In] uint dwFlags,
		[In] nint pvPara
	);

	public const nint CERT_STORE_PROV_MSG = 1;

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
		/// The structure that contains the signer information.
		/// </summary>
		public uint dwSignerType;

		/// <summary>
		/// A pointer to a <see cref="CERT_PUBLIC_KEY_INFO"/> structure, a certificate context, a chain context, or NULL depending on the value of dwSignerType.
		/// </summary>
		public nint pvSigner;

		/// <summary>
		/// Initializes a new instance of the <see cref="CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA"/> structure
		/// </summary>
		public CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
	}

	/// <summary>
	/// pvSigner contains a pointer to a <see cref="CERT_PUBLIC_KEY_INFO"/> structure
	/// </summary>
	public const uint CMSG_VERIFY_SIGNER_PUBKEY = 1;

	/// <summary>
	/// pvSigner contains a pointer to a <see cref="CERT_CONTEXT"/> structure
	/// </summary>
	public const uint CMSG_VERIFY_SIGNER_CERT = 2;

	/// <summary>
	/// pvSigner contains a pointer to a <see cref="CERT_CHAIN_CONTEXT"/> structure
	/// </summary>
	public const uint CMSG_VERIFY_SIGNER_CHAIN = 3;

	/// <summary>
	///  pvSigner contains NULL
	/// </summary>
	public const uint CMSG_VERIFY_SIGNER_NULL = 4;

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

		/// <summary>
		/// Initializes a new instance of the <see cref="CERT_CHAIN_PARA"/> structure
		/// </summary>
		public CMSG_SIGNED_ENCODE_INFO()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
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
		public uint dwKeySpec;

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

		/// <summary>
		/// Initializes a new instance of the <see cref="CMSG_SIGNER_ENCODE_INFO"/> structure
		/// </summary>
		public CMSG_SIGNER_ENCODE_INFO()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
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
		public uint cbEncoded;

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
		public nint pszTSAPolicyId;

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
	public static extern bool CertCloseStore(
		[In] nint hCertStore,
		[In] uint dwFlags);

	/// <summary>
	/// Forces the freeing of memory for all contexts associated with the store. This flag can be safely used only when the store is opened in a function and neither the store handle nor any of its contexts are passed to any called functions
	/// </summary>
	public const uint CERT_CLOSE_STORE_FORCE_FLAG = 1;

	/// <summary>
	/// Checks for nonfreed certificate, CRL, and CTL contexts. A returned error code indicates that one or more store elements is still in use. This flag should only be used as a diagnostic tool in the development of applications.
	/// </summary>
	public const uint CERT_CLOSE_STORE_CHECK_FLAG = 2;

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
		[In] uint dwFlags,
		[In] nint pvParameters,
		out nint phCryptProvOrNCryptKey,
		out uint pdwKeySpec,
		out bool pfCallerFreeProv
	);

	/// <summary>
	/// If a handle is already acquired and cached, that same handle is returned. Otherwise, a new handle is acquired and cached by using the certificate's CERT_KEY_CONTEXT_PROP_ID property. 
	/// When this flag is set, the pfCallerFreeProvOrNCryptKey parameter receives FALSE and the calling application must not release the handle. 
	/// The handle is freed when the certificate context is freed; however, you must retain the certificate context referenced by the pCert parameter as long as the key is in use, otherwise operations that rely on the key will fail.
	/// </summary>
	public const uint CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001;

	/// <summary>
	/// Uses the certificate's CERT_KEY_PROV_INFO_PROP_ID property to determine whether caching should be accomplished. For more information about the CERT_KEY_PROV_INFO_PROP_ID property, see CertSetCertificateContextProperty. 
	/// This function will only use caching if during a previous call, the dwFlags member of the CRYPT_KEY_PROV_INFO structure contained CERT_SET_KEY_CONTEXT_PROP.
	/// </summary>
	public const uint CRYPT_ACQUIRE_USE_PROV_INFO_FLAG = 0x00000002;

	/// <summary>
	/// The public key in the certificate is compared with the public key returned by the cryptographic service provider (CSP). If the keys do not match, the acquisition operation fails and the last error code is set to NTE_BAD_PUBLIC_KEY. 
	/// If a cached handle is returned, no comparison is made.
	/// </summary>
	public const uint CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004;

	/// <summary>
	/// The CSP should not display any user interface (UI) for this context. If the CSP must display UI to operate, the call fails and the NTE_SILENT_CONTEXT error code is set as the last error.
	/// </summary>
	public const uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;

	/// <summary>
	/// Any UI that is needed by the CSP or KSP will be a child of the HWND that is supplied in the pvParameters parameter. For a CSP key, using this flag will cause the CryptSetProvParam function with the flag PP_CLIENT_HWND using this HWND to be called with NULL for HCRYPTPROV. For a KSP key, using this flag will cause the NCryptSetProperty function with the NCRYPT_WINDOW_HANDLE_PROPERTY flag to be called using the HWND.
	/// Do not use this flag with CRYPT_ACQUIRE_SILENT_FLAG.
	/// </summary>
	public const uint CRYPT_ACQUIRE_WINDOWS_HANDLE_FLAG = 0x00000080;

	/// <summary>
	/// This function will attempt to obtain the key by using CryptoAPI. If that fails, this function will attempt to obtain the key by using the Cryptography API: Next Generation (CNG). 
	/// The pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag if CNG is used to obtain the key.
	/// </summary>
	public const uint CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000;

	/// <summary>
	/// This function will attempt to obtain the key by using CNG. If that fails, this function will attempt to obtain the key by using CryptoAPI. 
	/// The pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag if CNG is used to obtain the key.
	/// </summary>
	public const uint CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000;

	/// <summary>
	/// This function will only attempt to obtain the key by using CNG and will not use CryptoAPI to obtain the key. 
	/// The pdwKeySpec variable receives the CERT_NCRYPT_KEY_SPEC flag if CNG is used to obtain the key.
	/// </summary>
	public const uint CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000;


	public const uint AT_KEYEXCHANGE = 1;
	public const uint AT_SIGNATURE = 2;
	public const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;


	/// <summary>
	/// Encodes a structure of the type indicated by the value of the lpszStructType parameter. 
	/// The use of CryptEncodeObjectEx is recommended as an API that performs the same function with significant performance improvements.
	/// </summary>
	/// <param name="dwCertEncodingType">Type of encoding used. It is always acceptable to specify both the certificate and message encoding types by combining them with a bitwise-OR operation</param>
	/// <param name="lpszStructType">A pointer to an OID defining the structure type. If the high-order word of the lpszStructType parameter is zero, the low-order word specifies the integer identifier for the type of the specified structure.
	/// Otherwise, this parameter is a long pointer to a null-terminated string.</param>
	/// <param name="pvStructInfo">A pointer to the structure to be encoded. The structure must be of a type specified by lpszStructType.</param>
	/// <param name="pbEncoded">A pointer to a buffer to receive the encoded structure. When the buffer that is specified is not large enough to receive the decoded structure, 
	/// the function sets the ERROR_MORE_DATA code and stores the required buffer size, in bytes, in the variable pointed to by pcbEncoded.
	/// This parameter can be NULL to retrieve the size of this information for memory allocation purposes.</param>
	/// <param name="pcbEncoded">A pointer to a DWORD variable that contains the size, in bytes, of the buffer pointed to by the pbEncoded parameter.
	/// When the function returns, the DWORD value contains the number of allocated encoded bytes stored in the buffer.</param>
	/// <returns>If the function succeeds, the return value is nonzero (TRUE).
	/// If the function fails, the return value is zero(FALSE). For extended error information, call GetLastError</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencodeobject</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	[Obsolete("The use of CryptEncodeObjectEx is recommended as an API that performs the same function with significant performance improvements.")]
	public static extern bool CryptEncodeObject(
	  [In] uint dwCertEncodingType,
	  [In] nint lpszStructType,
	  [In] nint pvStructInfo,
	  [Out] nint pbEncoded,
	  [In, Out] nint pcbEncoded
	);

	/// <summary>
	/// Encodes a structure of the type indicated by the value of the lpszStructType parameter. This function offers a significant performance improvement over <see cref="CryptEncodeObject"/>
	/// by supporting memory allocation with the <see cref="CRYPT_ENCODE_ALLOC_FLAG"/> value
	/// </summary>
	/// <param name="dwCertEncodingType">Type of encoding used. It is always acceptable to specify both the certificate and message encoding types by combining them with a bitwise-OR operation</param>
	/// <param name="lpszStructType">A pointer to an object identifier (OID) that defines the structure type. If the high-order word of the lpszStructType parameter is zero, the low-order word specifies an integer identifier for the type of the specified structure. 
	/// Otherwise, this parameter is a pointer to a null-terminated string that contains the string representation of the OID.</param>
	/// <param name="pvStructInfo">A pointer to the structure to be encoded. The structure must be of the type specified by lpszStructType.</param>
	/// <param name="dwFlags">Specifies options for the encoding. This parameter can be zero or a combination of one or more of values.</param>
	/// <param name="pEncodePara">A pointer to a <see cref="CRYPT_ENCODE_PARA"/> structure that contains encoding information. This parameter can be NULL.	
	/// If either pEncodePara or the pfnAlloc member of pEncodePara is NULL, then LocalAlloc is used for the allocation and LocalFree must be called to free the memory.
	/// If both pEncodePara and the pfnAlloc member of pEncodePara are not NULL, then the function pointed to by the pfnAlloc member of the <see cref="CRYPT_ENCODE_PARA"/> structure pointed to by pEncodePara is called for the allocation.The function pointed to by the pfnFree member of pEncodePara must be called to free the memory.</param>
	/// <param name="pvEncoded">A pointer to a buffer to receive the encoded structure. The size of this buffer is specified in the pcbEncoded parameter. 
	/// When the buffer that is specified is not large enough to receive the decoded structure, the function sets the ERROR_MORE_DATA code and stores the required buffer size, in bytes, in the variable pointed to by pcbEncoded.
	/// This parameter can be NULL to retrieve the size of the buffer for memory allocation purposes.
	/// If dwFlags contains the <see cref="CRYPT_ENCODE_ALLOC_FLAG"/> flag, pvEncoded is not a pointer to a buffer but is the address of a pointer to the buffer. 
	/// Because memory is allocated inside the function and the pointer is stored in pvEncoded, pvEncoded cannot be NULL.</param>
	/// <param name="pcbEncoded">A pointer to a DWORD variable that contains the size, in bytes, of the buffer pointed to by the pvEncoded parameter. 
	/// When the function returns, the variable pointed to by the pcbEncoded parameter contains the number of allocated, encoded bytes stored in the buffer.
	/// When dwFlags contains the <see cref="CRYPT_ENCODE_ALLOC_FLAG"/> flag, pcbEncoded is the address of a pointer to the DWORD value that is updated.</param>
	/// <returns>Returns nonzero if successful or zero otherwise.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencodeobjectex</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptEncodeObjectEx(
		[In] uint dwCertEncodingType,
		[In] nint lpszStructType,
		[In] nint pvStructInfo,
		[In] uint dwFlags,
		[In] nint pEncodePara,
		[Out] nint pvEncoded,
		[In, Out] nint pcbEncoded
	);

	#region Possible values of the CryptEncodeObjectEx.lpszStructType parameter

	public const nint PKCS_ATTRIBUTE = 22;

	#endregion

	#region Possible values of the CryptEncodeObjectEx.dwFlags parameter

	/// <summary>
	/// The called encoding function allocates memory for the encoded bytes.A pointer to the allocated bytes is returned in pvEncoded.
	/// </summary>
	public const uint CRYPT_ENCODE_ALLOC_FLAG = 0x00008000;

	/// <summary>
	/// This flag is applicable for enabling Punycode encoding of Unicode string values.
	/// </summary>
	public const uint CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG = 0x00020000;

	/// <summary>
	/// This flag is applicable when encoding <see cref="X509_UNICODE_NAME"/>, <see cref="X509_UNICODE_NAME_VALUE"/>, or <see cref="X509_UNICODE_ANY_STRING"/>.
	/// If this flag is set, the characters are not checked to determine whether they are valid for the specified value type.
	/// </summary>
	public const uint CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG = 0x40000000;

	/// <summary>
	/// This flag is applicable when encoding X509_UNICODE_NAME. If this flag is set and all the Unicode characters are <= 0xFF, the CERT_RDN_T61_STRING is selected instead of the CERT_RDN_UNICODE_STRING.
	/// </summary>
	public const uint CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG = 0x80000000;

	/// <summary>
	/// This flag is applicable when encoding an X509_UNICODE_NAME.When set, <see cref="CERT_RDN_UTF8_STRING"/> is selected instead of <see cref="CERT_RDN_UNICODE_STRING"/>.
	/// </summary>
	public const uint CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG = 0x20000000;

	/// <summary>
	/// This flag is applicable when encoding an <see cref="X509_UNICODE_NAME"/>. When set, <see cref="CERT_RDN_UTF8_STRING"/> is selected instead of <see cref="CERT_RDN_PRINTABLE_STRING"/> for directory string types.
	/// Also, this flag enables <see cref="CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG"/>.
	/// </summary>
	public const uint CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG = 0x10000000;

	#endregion

	/// <summary>
	/// Is used by the <see cref="CryptEncodeObjectEx"/> function to provide access to memory allocation and memory freeing callback functions.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_encode_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CRYPT_ENCODE_PARA
	{
		/// <summary>
		/// Indicates the size, in bytes, of the structure.
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// This member is an optional pointer to a callback function used to allocate memory.
		/// </summary>
		public nint pfnAlloc;

		/// <summary>
		/// This member is an optional pointer to a callback function used to free memory allocated by the allocate callback function.
		/// </summary>
		public nint pfnFree;

		/// <summary>
		/// Initializes a new instance of the <see cref="CRYPT_ENCODE_PARA"/> structure
		/// </summary>
		public CRYPT_ENCODE_PARA()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
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
		[In] uint dwFlags,
		[In] uint dwCtrlType,
		[In] nint pvCtrlPara
	);

	/// <summary>
	/// A <see cref="CERT_INFO"/> structure that identifies the signer of the message whose signature is to be verified.
	/// </summary>
	public const uint CMSG_CTRL_VERIFY_SIGNATURE = 1;

	/// <summary>
	/// A <see cref="CMSG_CTRL_DECRYPT_PARA"/> structure used to decrypt the message for the specified key transport recipient. 
	/// This value is applicable to RSA recipients. This operation specifies that the CryptMsgControl function search the recipient index to obtain the key transport recipient information.
	/// </summary>
	public const uint CMSG_CTRL_DECRYPT = 2;

	/// <summary>
	/// This value is not used.
	/// </summary>
	public const uint CMSG_CTRL_VERIFY_HASH = 5;

	/// <summary>
	/// pvCtrlPara points to a <see cref="CMSG_SIGNER_ENCODE_INFO"/> structure that contains the signer information to be added to the message.
	/// </summary>
	public const uint CMSG_CTRL_ADD_SIGNER = 6;

	/// <summary>
	/// After a deletion is made, any other signer indices in use for this message are no longer valid and must be reacquired by calling the <see cref="CryptMsgGetParam"/> function.
	/// </summary>
	public const uint CMSG_CTRL_DEL_SIGNER = 7;

	/// <summary>
	/// A <see cref="CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA"/> structure that contains the index of the signer and a BLOB that contains the unauthenticated attribute information to be added to the message.
	/// </summary>
	public const uint CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR = 8;

	/// <summary>
	/// A <see cref="CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA"/> structure that contains an index that specifies the signer and the index that specifies the signer's unauthenticated attribute to be deleted.
	/// </summary>
	public const uint CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR = 9;

	/// <summary>
	/// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the encoded bytes of the certificate to be added to the message.
	/// </summary>
	public const uint CMSG_CTRL_ADD_CERT = 10;

	/// <summary>
	/// The index of the certificate to be deleted from the message.
	/// </summary>
	public const uint CMSG_CTRL_DEL_CERT = 11;

	/// <summary>
	/// A BLOB that contains the encoded bytes of the CRL to be added to the message.
	/// </summary>
	public const uint CMSG_CTRL_ADD_CRL = 12;

	/// <summary>
	/// The index of the CRL to be deleted from the message.
	/// </summary>
	public const uint CMSG_CTRL_DEL_CRL = 13;

	/// <summary>
	/// A BLOB that contains the encoded bytes of attribute certificate.
	/// </summary>
	public const uint CMSG_CTRL_ADD_ATTR_CERT = 14;

	/// <summary>
	/// The index of the attribute certificate to be removed.
	/// </summary>
	public const uint CMSG_CTRL_DEL_ATTR_CERT = 15;

	/// <summary>
	/// A <see cref="CMSG_CTRL_KEY_TRANS_DECRYPT_PARA"/> structure used to decrypt the message for the specified key transport recipient. Key transport is used with RSA encryption/decryption.
	/// </summary>
	public const uint CMSG_CTRL_KEY_TRANS_DECRYPT = 16;

	/// <summary>
	/// A <see cref="CMSG_CTRL_KEY_AGREE_DECRYPT_PARA"/> structure used to decrypt the message for the specified key agreement session key. Key agreement is used with Diffie-Hellman encryption/decryption.
	/// </summary>
	public const uint CMSG_CTRL_KEY_AGREE_DECRYPT = 17;

	/// <summary>
	/// A <see cref="CMSG_CTRL_MAIL_LIST_DECRYPT_PARA"/> structure used to decrypt the message for the specified recipient using a previously distributed key-encryption key (KEK).
	/// </summary>
	public const uint CMSG_CTRL_MAIL_LIST_DECRYPT = 18;

	/// <summary>
	/// A <see cref="CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA"/> structure that specifies the signer index and public key to verify the message signature. 
	/// The signer public key can be a <see cref="CERT_PUBLIC_KEY_INFO"/> structure, a certificate context, or a certificate chain context.
	/// </summary>
	public const uint CMSG_CTRL_VERIFY_SIGNATURE_EX = 19;

	/// <summary>
	/// A <see cref="CMSG_CMS_SIGNER_INFO"/> structure that contains signer information. This operation differs from CMSG_CTRL_ADD_SIGNER because the signer information contains the signature.
	/// </summary>
	public const uint CMSG_CTRL_ADD_CMS_SIGNER_INFO = 20;

	/// <summary>
	/// A <see cref="CERT_STRONG_SIGN_PARA"/> structure used to perform strong signature checking.
	/// </summary>
	public const uint CMSG_CTRL_ENABLE_STRONG_SIGNATURE = 21;

	/// <summary>
	/// The structure is used to add an unauthenticated attribute to a signer of a signed message. 
	/// This structure is passed to <see cref="CryptMsgControl"/> if the dwCtrlType parameter is set to <see cref="CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR"/>.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_ctrl_add_signer_unauth_attr_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
	public struct CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA
	{
		/// <summary>
		/// Size of this structure in bytes.
		/// </summary>
		public uint cbSize;

		/// <summary>
		/// Index of the signer in the rgSigners array of pointers of <see cref="CMSG_SIGNER_ENCODE_INFO"/> structures in a signed message's <see cref="CMSG_SIGNED_ENCODE_INFO"/> structure. 
		/// The unauthenticated attribute is to be added to this signer's information.
		/// </summary>
		public uint dwSignerIndex;

		/// <summary>
		/// The attribute encoded value
		/// </summary>
		public CRYPT_INTEGER_BLOB blob;

		/// <summary>
		/// Initializes a new instance of the <see cref="CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA"/> structure
		/// </summary>
		public CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA()
		{
			cbSize = (uint)Marshal.SizeOf(this);
		}
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
		[In] uint dwParamType,
		[In] uint dwIndex,
		[In] nint pvData,
		[In, Out] nint pcbData
	);


	/// <summary>
	/// pvData data type: pointer to a DWORD. 
	/// Returns the message type of a decoded message of unknown type. The retrieved message type can be compared to supported types to determine whether processing can continued
	/// </summary>
	public const uint CMSG_TYPE_PARAM = 1;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Returns the whole PKCS #7 message from a message opened to encode. Retrieves the inner content of a message opened to decode. 
	/// If the message is enveloped, the inner type is data, and <see cref="CryptMsgControl"/> has been called to decrypt the message, the decrypted content is returned. 
	/// If the inner type is not data, the encoded BLOB that requires further decoding is returned. 
	/// If the message is not enveloped and the inner content is DATA, the returned data is the octets of the inner content. 
	/// This type is applicable to both encode and decode. For decoding, if the type is CMSG_DATA, the content's octets are returned; else, the encoded inner content is returned.
	/// </summary>
	public const uint CMSG_CONTENT_PARAM = 2;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Retrieves the encoded content of an encoded cryptographic message, without the outer layer of the CONTENT_INFO structure. That is, only the encoding of the PKCS #7 defined ContentInfo.content field is returned
	/// </summary>
	public const uint CMSG_BARE_CONTENT_PARAM = 3;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a null-terminated object identifier (OID) string.
	/// Returns the inner content type of a received message. This type is not applicable to messages of type DATA
	/// </summary>
	public const uint CMSG_INNER_CONTENT_TYPE_PARAM = 4;

	/// <summary>
	/// pvData data type: pointer to a DWORD.
	/// Returns the number of signers of a received SIGNED message
	/// </summary>
	public const uint CMSG_SIGNER_COUNT_PARAM = 5;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_SIGNER_INFO"/> structure. 
	/// Returns information on a message signer. This includes the issuer and serial number of the signer's certificate and authenticated and unauthenticated attributes of the signer's certificate. 
	/// To retrieve signer information on all of the signers of a message, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one
	/// </summary>
	public const uint CMSG_SIGNER_INFO_PARAM = 6;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive the <see cref="CERT_INFO"/> structure. 
	/// Returns information on a message signer needed to identify the signer's certificate. A certificate's Issuer and SerialNumber can be used to uniquely identify a certificate for retrieval. 
	/// To retrieve information for all the signers, repetitively call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one. 
	/// Only the Issuer and SerialNumber fields in the <see cref="CERT_INFO"/> structure returned contain available, valid data
	/// </summary>
	public const uint CMSG_SIGNER_CERT_INFO_PARAM = 7;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive the <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure. 
	/// Returns the hash algorithm used by a signer of the message. To get the hash algorithm for a specified signer, call <see cref="CryptMsgGetParam"/> with dwIndex equal to that signer's index.
	/// </summary>
	public const uint CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a <see cref="CRYPT_ATTRIBUTES"/> structure.
	/// Returns the authenticated attributes of a message signer. To retrieve the authenticated attributes for a specified signer, call <see cref="CryptMsgGetParam"/> with dwIndex equal to that signer's index.
	/// </summary>
	public const uint CMSG_SIGNER_AUTH_ATTR_PARAM = 9;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a CRYPT_ATTRIBUTES structure. 
	/// Returns a message signer's unauthenticated attributes. To retrieve the unauthenticated attributes for a specified signer, call <see cref="CryptMsgGetParam"/> with dwIndex equal to that signer's index
	/// </summary>
	public const uint CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10;

	/// <summary>
	/// pvData data type: pointer to DWORD.
	/// Returns the number of certificates in a received SIGNED or ENVELOPED message.
	/// </summary>
	public const uint CMSG_CERT_COUNT_PARAM = 11;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Returns a signer's certificate. To get all of the signer's certificates, call <see cref="CryptMsgGetParam"/>, varying dwIndex from 0 to the number of available certificates minus one.
	/// </summary>
	public const uint CMSG_CERT_PARAM = 12;

	/// <summary>
	/// pvData data type: pointer to DWORD. 
	/// Returns the count of CRLs in a received, SIGNED or ENVELOPED message.
	/// </summary>
	public const uint CMSG_CRL_COUNT_PARAM = 13;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Returns a CRL. To get all the CRLs, call CryptMsgGetParam, varying dwIndex from 0 to the number of available CRLs minus one.
	/// </summary>
	public const uint CMSG_CRL_PARAM = 14;

	/// <summary>
	/// pvData data type: pointer to a BYTE array for a <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure.
	/// Returns the encryption algorithm used to encrypt an ENVELOPED message
	/// </summary>
	public const uint CMSG_ENVELOPE_ALGORITHM_PARAM = 15;

	/// <summary>
	/// pvData data type: pointer to a DWORD. 
	/// Returns the number of key transport recipients of an ENVELOPED received message.
	/// </summary>
	public const uint CMSG_RECIPIENT_COUNT_PARAM = 17;

	/// <summary>
	/// pvData data type: pointer to a DWORD.
	/// Returns the index of the key transport recipient used to decrypt an ENVELOPED message. This value is available only after a message has been decrypted.
	/// </summary>
	public const uint CMSG_RECIPIENT_INDEX_PARAM = 18;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a <see cref="CERT_INFO"/> structure.
	/// Returns certificate information about a key transport message's recipient. To get certificate information on all key transport message's recipients, repetitively call <see cref="CryptMsgGetParam"/>, varying dwIndex from 0 to the number of recipients minus one. 
	/// Only the Issuer, SerialNumber, and PublicKeyAlgorithm members of the CERT_INFO structure returned are available and valid
	/// </summary>
	public const uint CMSG_RECIPIENT_INFO_PARAM = 19;

	/// <summary>
	/// pvData data type: pointer to a BYTE array for a <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure.
	/// Returns the hash algorithm used to hash the message when it was created.
	/// </summary>
	public const uint CMSG_HASH_ALGORITHM_PARAM = 20;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Returns the hash value stored in the message when it was created.
	/// </summary>
	public const uint CMSG_HASH_DATA_PARAM = 21;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Returns the hash calculated of the data in the message. This type is applicable to both encode and decode.
	/// </summary>
	public const uint CMSG_COMPUTED_HASH_PARAM = 22;

	/// <summary>
	/// pvData data type: pointer to a BYTE array for a <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure.
	/// Returns the encryption algorithm used to encrypted the message.
	/// </summary>
	public const uint CMSG_ENCRYPT_PARAM = 26;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.
	/// Returns the encrypted hash of a signature. Typically used for performing time-stamping.
	/// </summary>
	public const uint CMSG_ENCRYPTED_DIGEST = 27;

	/// <summary>
	/// pvData data type: pointer to a BYTE array. 
	/// Returns the encoded <see cref="CMSG_SIGNER_INFO"/> signer information for a message signer.
	/// </summary>
	public const uint CMSG_ENCODED_SIGNER = 28;

	/// <summary>
	/// pvData data type: pointer to a BYTE array.	Changes the contents of an already encoded message. The message must first be decoded with a call to <see cref="CryptMsgOpenToDecode"/>. 
	/// Then the change to the message is made through a call to <see cref="CryptMsgControl"/>, <see cref="CryptMsgCountersign"/>, or <see cref="CryptMsgCountersignEncoded"/>. 
	/// The message is then encoded again with a call to <see cref="CryptMsgGetParam"/>, specifying CMSG_ENCODED_MESSAGE to get a new encoding that reflects the changes made. This can be used, for instance, to add a time-stamp attribute to a message.
	/// </summary>
	public const uint CMSG_ENCODED_MESSAGE = 29;

	/// <summary>
	/// pvData data type: pointer to a DWORD. 
	/// Returns the version of the decoded message.
	/// </summary>
	public const uint CMSG_VERSION_PARAM = 30;

	/// <summary>
	/// pvData data type: pointer to a DWORD. 
	/// Returns the count of the attribute certificates in a SIGNED or ENVELOPED message.
	/// </summary>
	public const uint CMSG_ATTR_CERT_COUNT_PARAM = 31;

	/// <summary>
	/// pvData data type: pointer to a BYTE array. 
	/// Retrieves an attribute certificate. To get all the attribute certificates, call <see cref="CryptMsgGetParam"/> varying dwIndex set to 0 the number of attributes minus one.
	/// </summary>
	public const uint CMSG_ATTR_CERT_PARAM = 32;

	/// <summary>
	/// pvData data type: pointer to DWORD. 
	/// Returns the total count of all message recipients including key agreement and mail list recipients.
	/// </summary>
	public const uint CMSG_CMS_RECIPIENT_COUNT_PARAM = 33;

	/// <summary>
	/// pvData data type: pointer to a DWORD. 
	/// Returns the index of the key transport, key agreement, or mail list recipient used to decrypt an ENVELOPED message.
	/// </summary>
	public const uint CMSG_CMS_RECIPIENT_INDEX_PARAM = 34;

	/// <summary>
	/// pvData data type: pointer to a DWORD. 
	/// Returns the index of the encrypted key of a key agreement recipient used to decrypt an ENVELOPED message.
	/// </summary>
	public const uint CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_CMS_RECIPIENT_INFO"/> structure.
	/// Returns information about a key transport, key agreement, or mail list recipient. It is not limited to key transport message recipients. 
	/// To get information on all of a message's recipients, repetitively call <see cref="CryptMsgGetParam"/>, varying dwIndex from 0 to the number of recipients minus one.
	/// </summary>
	public const uint CMSG_CMS_RECIPIENT_INFO_PARAM = 36;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_ATTR"/> structure. 
	/// Returns the unprotected attributes in an enveloped message.
	/// </summary>
	public const uint CMSG_UNPROTECTED_ATTR_PARAM = 37;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a CERT_ID structure.
	/// Returns information on a message signer needed to identify the signer's public key. This could be a certificate's Issuer and SerialNumber, a KeyID, or a HashId. 
	/// To retrieve information for all the signers, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one.
	/// </summary>
	public const uint CMSG_SIGNER_CERT_ID_PARAM = 38;

	/// <summary>
	/// pvData data type: pointer to a BYTE array to receive a <see cref="CMSG_CMS_SIGNER_INFO"/> structure.
	/// Returns information on a message signer. This includes a signerId and authenticated and unauthenticated attributes. 
	/// To retrieve signer information on all of the signers of a message, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one.
	/// </summary>
	public const uint CMSG_CMS_SIGNER_INFO_PARAM = 39;

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
		[In] uint dwMsgEncodingType,
		[In] uint dwFlags,
		[In] uint dwMsgType,
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
		[In] uint dwMsgEncodingType,
		[In] uint dwFlags,
		[In] uint dwMsgType,
		[In] nint pvMsgEncodeInfo,
		[In][MarshalAs(UnmanagedType.LPStr)] string? pszInnerContentObjID,
		[In] nint pStreamInfo);


	/// <summary>
	/// The streamed output will not have an outer ContentInfo wrapper (as defined by PKCS #7). This makes it suitable to be streamed into an enclosing message.
	/// </summary>
	public const uint CMSG_BARE_CONTENT_FLAG = 0x00000001;

	/// <summary>
	/// There is detached data being supplied for the subsequent calls to <see cref="CryptMsgUpdate"/>
	/// </summary>
	public const uint CMSG_DETACHED_FLAG = 0x00000004;

	/// <summary>
	/// Authenticated attributes are forced to be included in the SignerInfo (as defined by PKCS #7) in cases where they would not otherwise be required
	/// </summary>
	public const uint CMSG_AUTHENTICATED_ATTRIBUTES_FLAG = 0x00000008;

	/// <summary>
	/// Used when calculating the size of a message that has been encoded by using Distinguished Encoding Rules (DER) and that is nested inside an enveloped message. This is particularly useful when performing streaming
	/// </summary>
	public const uint CMSG_CONTENTS_OCTETS_FLAG = 0x00000010;

	/// <summary>
	/// When set, non-data type-inner content is encapsulated within an OCTET STRING. Applicable to both signed and enveloped messages
	/// </summary>
	public const uint CMSG_CMS_ENCAPSULATED_CONTENT_FLAG = 0x00000040;

	/// <summary>
	/// If set, the hCryptProv that is passed to this function is released on the final CryptMsgUpdate. The handle is not released if the function fails
	/// </summary>
	public const uint CMSG_CRYPT_RELEASE_CONTEXT_FLAG = 0x00008000;

	/// <summary>
	/// This value is not used
	/// </summary>
	public const uint CMSG_DATA = 1;

	/// <summary>
	/// The pvMsgEncodeInfo parameter is the address of a <see cref="CMSG_SIGNED_ENCODE_INFO"/> structure that contains the encoding information
	/// </summary>
	public const uint CMSG_SIGNED = 2;

	/// <summary>
	/// The pvMsgEncodeInfo parameter is the address of a <see cref="CMSG_ENVELOPED_ENCODE_INFO"/> structure that contains the encoding information
	/// </summary>
	public const uint CMSG_ENVELOPED = 3;

	/// <summary>
	/// This value is not currently implemented
	/// </summary>
	public const uint CMSG_SIGNED_AND_ENVELOPED = 4;

	/// <summary>
	/// The pvMsgEncodeInfo parameter is the address of a <see cref="CMSG_HASHED_ENCODE_INFO"/> structure that contains the encoding information
	/// </summary>
	public const uint CMSG_HASHED = 5;

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
	public static extern bool CryptRetrieveTimeStamp(
		[In][MarshalAs(UnmanagedType.LPWStr)] string? wszUrl,
		[In] uint dwRetrievalFlags,
		[In] int dwTimeout,
		[In][MarshalAs(UnmanagedType.LPStr)] string? pszHashId,
		[In] nint pPara,
		[In] nint pbData,
		[In] uint cbData,
		[Out] nint pTsContext,
		[Out] nint ppTsSigner,
		[Out] nint phStore
	);

	#region Possible values for the CryptRetrieveTimeStamp.dwRetrievalFlags parameter 

	/// <summary>
	/// Inhibit hash calculation on the array of bytes pointed to by the pbData parameter.
	/// </summary>
	public const uint TIMESTAMP_DONT_HASH_DATA = 0x00000001;

	/// <summary>
	/// Enforce signature validation on the retrieved time stamp. This flag is valid only if the fRequestCerts member of the <see cref="CRYPT_TIMESTAMP_PARA"/> pointed to by the pPara parameter is set to TRUE.
	/// </summary>
	public const uint TIMESTAMP_VERIFY_CONTEXT_SIGNATURE = 0x00000020;

	/// <summary>
	/// Set this flag to inhibit automatic authentication handling
	/// </summary>
	public const uint TIMESTAMP_NO_AUTH_RETRIEVAL = 0x00020000;

	#endregion

	/// <summary>
	/// Validates the time stamp signature on a specified array of bytes.
	/// </summary>
	/// <param name="pbTSContentInfo">A pointer to a buffer that contains time stamp content.</param>
	/// <param name="cbTSContentInfo">The size, in bytes, of the buffer pointed to by the pbTSContentInfo parameter.</param>
	/// <param name="pbData">A pointer to an array of bytes on which to validate the time stamp signature.</param>
	/// <param name="cbData">The size, in bytes, of the array pointed to by the pbData parameter.</param>
	/// <param name="hAdditionalStore">The handle of an additional store to search for supporting Time Stamping Authority (TSA) signing certificates and certificate trust lists (CTLs).
	/// This parameter can be NULL if no additional store is to be searched.</param>
	/// <param name="ppTsContext">A pointer to a PCRYPT_TIMESTAMP_CONTEXT structure. When you have finished using the context, you must free it by calling the <see cref="CryptMemFree"/> function.</param>
	/// <param name="ppTsSigner">A pointer to a PCERT_CONTEXT that receives the certificate of the signer. 
	/// When you have finished using this structure, you must free it by passing this pointer to the <see cref="CertFreeCertificateContext"/> function.
	/// Set this parameter to NULL if the TSA signer's certificate is not needed.</param>
	/// <param name="phStore">A pointer to a handle that receives the certificate store opened on CMS to search for supporting certificates. 
	/// This parameter can be NULL if the TSA supporting certificates are not needed.When you have finished using this handle, you must release it by passing it to the <see cref="CertCloseStore"/> function.</param>
	/// <returns>If the function succeeds, the function returns TRUE.</returns>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptverifytimestampsignature</remarks>
	[DllImport(Crypt32Lib, CharSet = CharSet.Unicode, SetLastError = true)]
	public static extern bool CryptVerifyTimeStampSignature(
		[In] nint pbTSContentInfo,
		[In] uint cbTSContentInfo,
		[In] nint pbData,
		[In] uint cbData,
		[In] nint hAdditionalStore,
		[Out] nint ppTsContext,
		[Out] nint ppTsSigner,
		[Out] nint phStore
	);

	/// <summary>
	/// Cannot find the original signer.
	/// </summary>
	public const int CRYPT_E_SIGNER_NOT_FOUND = unchecked((int)0x8009100E);

	/// <summary>
	/// Cannot find object or property.
	/// </summary>
	public const int CRYPT_E_NOT_FOUND = unchecked((int)0x80092004);

	/// <summary>
	/// The signed cryptographic message does not have a signer for the specified signer index.
	/// </summary>
	public const int CRYPT_E_NO_SIGNER = unchecked((int)0x8009200E);

	/// <summary>
	/// The certificate or signature has been revoked.
	/// </summary>
	public const int CRYPT_E_REVOKED = unchecked((int)0x80092010);

	/// <summary>
	/// The signature of the certificate cannot be verified.
	/// </summary>
	public const int TRUST_E_CERT_SIGNATURE = unchecked((int)0x80096004);

	/// <summary>
	/// A certification chain processed correctly but terminated in a root certificate that is not trusted by the trust provider.
	/// </summary>
	public const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);

	/// <summary>
	/// The root certificate is a testing certificate, and policy settings disallow test certificates.
	/// </summary>
	public const int CERT_E_UNTRUSTEDTESTROOT = unchecked((int)0x800B010D);

	/// <summary>
	/// A chain of certificates was not correctly created.
	/// </summary>
	public const int CERT_E_CHAINING = unchecked((int)0x800B010A);

	/// <summary>
	/// The certificate is not valid for the requested usage.
	/// </summary>
	public const int CERT_E_WRONG_USAGE = unchecked((int)0x800B0110);

	/// <summary>
	/// A required certificate is not within its validity period.
	/// </summary>
	public const int CERT_E_EXPIRED = unchecked((int)0x800B0101);

	/// <summary>
	/// The certificate has an invalid name. Either the name is not included in the permitted list, or it is explicitly excluded.
	/// </summary>
	public const int CERT_E_INVALID_NAME = unchecked((int)0x800B0114);

	/// <summary>
	/// The certificate has an invalid policy. 
	/// </summary>
	public const int CERT_E_INVALID_POLICY = unchecked((int)0x800B0113);

	/// <summary>
	/// The basic constraints of the certificate are not valid, or they are missing.
	/// </summary>
	public const int TRUST_E_BASIC_CONSTRAINTS = unchecked((int)0x80096019);

	/// <summary>
	/// The validity periods of the certification chain do not nest correctly.
	/// </summary>
	public const int CERT_E_CRITICAL = unchecked((int)0x800B0102);

	/// <summary>
	/// The validity periods of the certification chain do not nest correct
	/// </summary>
	public const int CERT_E_VALIDITYPERIODNESTING = unchecked((int)0x800B0102);

	/// <summary>
	/// The revocation function was unable to check revocation for the certificate.
	/// </summary>
	public const int CRYPT_E_NO_REVOCATION_CHECK = unchecked((int)0x80092012);

	/// <summary>
	/// The revocation function was unable to check revocation because the revocation server was offline.
	/// </summary>
	public const int CRYPT_E_REVOCATION_OFFLINE = unchecked((int)0x80092013);

	/// <summary>
	/// The certificate is being used for a purpose other than one specified by the issuing CA.
	/// </summary>
	public const int CERT_E_PURPOSE = unchecked((int)0x800B0106);

	/// <summary>
	/// The revocation process could not continue, and the certificate could not be checked.
	/// </summary>
	public const int CERT_E_REVOCATION_FAILURE = unchecked((int)0x800B010E);

	/// <summary>
	/// The certificate's CN name does not match the passed value.
	/// </summary>
	public const int CERT_E_CN_NO_MATCH = unchecked((int)0x800B010F);

	/// <summary>
	/// A certificate that can only be used as an end-entity is being used as a CA or vice versa.
	/// </summary>
	public const int CERT_E_ROLE = unchecked((int)0x800B0103);
}
