// Copyright © Antoine Larine. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;

namespace NetWinapiCms;

/// <summary>
/// OIDs for the Russian GOST Algorithms
/// </summary>
/// <remarks>https://tc26.ru/about/protsedury-i-reglamenty/identifikatory-obektov-oid-tekhnicheskogo-komiteta-po-standartizatsii-kriptograficheskaya-zashchita-1.html</remarks>
public static class GostOids
{
	public static readonly Oid id_tc26 = new("1.2.643.7.1", "Корень ТК 26 в российском сегменте мирового пространства идентификаторов объектов");
	public static readonly Oid modules = id_tc26.Branch("0", "Asn.1 модули ТК 26");
	public static readonly Oid gostR3410_2012_ParamSetSyntax = modules.Branch("1", "Asn.1 модуль синтаксиса параметров");
	public static readonly Oid gostR3410_2012_PKISyntax = modules.Branch("2", "Asn.1 модуль синтаксиса ключей");
	public static readonly Oid gostR3410_2012_SignatureSyntax = modules.Branch("3", "Asn.1 модуль синтаксиса подписи");
	public static readonly Oid gostR3410_2012_EncryptionSyntax = modules.Branch("4", "Asn.1 модуль синтаксиса зашифрованного сообщения");
	public static readonly Oid pkcs_12ruSyntax = modules.Branch("5", "Asn.1 модуль синтаксиса PKCS#12");
	public static readonly Oid id_tc26_algorithms = id_tc26.Branch("1", "алгоритмы");
	public static readonly Oid id_tc26_sign = id_tc26_algorithms.Branch("1", "алгоритмы подписи");
	public static readonly Oid id_tc26_gost3410_12_256 = id_tc26_sign.Branch("1", "алгоритм подписи ГОСТ Р 34.10-2012 с ключом 256");
	public static readonly Oid id_tc26_gost3410_12_512 = id_tc26_sign.Branch("2", "алгоритм подписи ГОСТ Р 34.10-2012 с ключом 512");
	public static readonly Oid id_tc26_digest = id_tc26_algorithms.Branch("2", "алгоритмы хэширования");
	public static readonly Oid id_tc26_gost3411_12_256 = id_tc26_digest.Branch("2", "алгоритм хэширования ГОСТ Р 34.11-12 с длиной 256");
	public static readonly Oid id_tc26_gost3411_12_512 = id_tc26_digest.Branch("3", "алгоритм хэширования ГОСТ Р 34.11-12 с длиной 512");
	public static readonly Oid id_tc26_signwithdigest = id_tc26_algorithms.Branch("3", "алгоритмы подписи вместе хэшированием");
	public static readonly Oid id_tc26_signwithdigest_gost3410_12_256 = id_tc26_signwithdigest.Branch("2", "алгоритм подписи ГОСТ Р 34.10-2012 с ключом 256 с хэшированием ГОСТ Р 34.11-2012");
	public static readonly Oid id_tc26_signwithdigest_gost3410_12_512 = id_tc26_signwithdigest.Branch("3", "алгоритм подписи ГОСТ Р 34.10-2012 с ключом 512 с хэшированием ГОСТ Р 34.11-2012");
	public static readonly Oid id_tc26_mac = id_tc26_algorithms.Branch("4", "алгоритмы выработки кодов аутентификации сообщений");
	public static readonly Oid id_tc26_hmac_gost_3411_12_256 = id_tc26_mac.Branch("1", "алгоритм HMAC на основе ГОСТ Р 34.11-2012 с ключом 256 со значениями B = 64, L = 32");
	public static readonly Oid id_tc26_hmac_gost_3411_12_512 = id_tc26_mac.Branch("2", "алгоритм HMAC на основе ГОСТ Р 34.11-2012 с ключом 512 со значениями B = 64, L = 64");
	public static readonly Oid id_tc26_cipher = id_tc26_algorithms.Branch("5", "алгоритмы шифрования");
	public static readonly Oid id_tc26_cipher_gostr3412_2015_magma = id_tc26_cipher.Branch("1", "алгоритм шифрования «Магма»");
	public static readonly Oid id_tc26_cipher_gostr3412_2015_magma_ctracpkm = id_tc26_cipher_gostr3412_2015_magma.Branch("1", "алгоритм шифрования «Магма» в режиме гаммирования CTR с механизмом преобразования ключа ACPKM");
	public static readonly Oid id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac = id_tc26_cipher_gostr3412_2015_magma.Branch("2", "алгоритм шифрования «Магма» в режиме гаммирования CTR с механизмом преобразования ключа ACPKM с вычислением имитовставки");
	public static readonly Oid id_tc26_cipher_gostr3412_2015_kuznyechik = id_tc26_cipher.Branch("2", "алгоритм шифрования «Кузнечик»");
	public static readonly Oid id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm = id_tc26_cipher_gostr3412_2015_kuznyechik.Branch("1", "алгоритм шифрования «Кузнечик» в режиме гаммирования CTR с механизмом преобразования ключа ACPKM");
	public static readonly Oid id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac = id_tc26_cipher_gostr3412_2015_kuznyechik.Branch("2", "алгоритм шифрования «Кузнечик» в режиме гаммирования CTR с механизмом преобразования ключа ACPKM c вычислением имитовставки");
	public static readonly Oid id_tc26_agreement = id_tc26_algorithms.Branch("6", "алгоритмы согласования ключа");
	public static readonly Oid id_tc26_agreement_gost_3410_12_256 = id_tc26_agreement.Branch("1", "алгоритмы согласования ключа на основе ГОСТ Р 34.10- 2012 для ключа 256");
	public static readonly Oid id_tc26_agreement_gost_3410_12_512 = id_tc26_agreement.Branch("2", "алгоритмы согласования ключа на основе ГОСТ Р 34.10-2012 для ключа 512");
	public static readonly Oid id_tc26_wrap = id_tc26_algorithms.Branch("7", "алгоритмы экспорта ключей");
	public static readonly Oid id_tc26_wrap_gostr3412_2015_magma = id_tc26_wrap.Branch("1", "алгоритмы экспорта ключей на основе симметричного блочного шифра «Магма»");
	public static readonly Oid id_tc26_wrap_gostr3412_2015_magma_kexp15 = id_tc26_wrap_gostr3412_2015_magma.Branch("1", "алгоритм экспорта ключей KExp15 на основе симметричного блочного шифра «Магма»");
	public static readonly Oid id_tc26_wrap_gostr3412_2015_kuznyechik = id_tc26_wrap.Branch("2", "алгоритмы экспорта ключей на основе симметричного блочного шифра «Кузнечик»");
	public static readonly Oid id_tc26_wrap_gostr3412_2015_kuznyechik_kexp15 = id_tc26_wrap_gostr3412_2015_kuznyechik.Branch("1", "алгоритм экспорта ключей KExp15 на основе симметричного блочного шифра «Кузнечик»");
	public static readonly Oid id_tc26_constants = id_tc26.Branch("2", "константы (параметры)");
	public static readonly Oid id_tc26_sign_constants = id_tc26_constants.Branch("1", "параметры алгоритмов подписи");
	public static readonly Oid id_tc26_gost_3410_12_256_constants = id_tc26_sign_constants.Branch("1", "параметры алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256");
	public static readonly Oid id_tc26_gost_3410_12_256_paramSetA = id_tc26_gost_3410_12_256_constants.Branch("1", "рабочие параметры А алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256");
	public static readonly Oid id_tc26_gost_3410_12_256_paramSetB = id_tc26_gost_3410_12_256_constants.Branch("2", "рабочие параметры B алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256");
	public static readonly Oid id_tc26_gost_3410_12_256_paramSetC = id_tc26_gost_3410_12_256_constants.Branch("3", "рабочие параметры C алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256");
	public static readonly Oid id_tc26_gost_3410_12_256_paramSetD = id_tc26_gost_3410_12_256_constants.Branch("4", "рабочие параметры D алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256");
	public static readonly Oid id_tc26_gost_3410_12_512_constants = id_tc26_sign_constants.Branch("2", "параметры алгоритма подписи ГОСТ Р 34.10-2012 с ключом 512");
	public static readonly Oid id_tc26_gost_3410_12_512_paramSetTest = id_tc26_gost_3410_12_512_constants.Branch("0", "тестовые параметры алгоритма подписи ГОСТ Р 34.10- 2012 с ключом 512");
	public static readonly Oid id_tc26_gost_3410_12_512_paramSetA = id_tc26_gost_3410_12_512_constants.Branch("1", "рабочие параметры A алгоритма подписи ГОСТ Р 34.10-2012 с ключом 512");
	public static readonly Oid id_tc26_gost_3410_12_512_paramSetB = id_tc26_gost_3410_12_512_constants.Branch("2", "рабочие параметры B алгоритма подписи ГОСТ Р 34.10-2012 с ключом 512");
	public static readonly Oid id_tc26_gost_3410_12_512_paramSetС = id_tc26_gost_3410_12_512_constants.Branch("3", "рабочие параметры С алгоритма подписи ГОСТ Р 34.10-2012 с ключом 512");
	public static readonly Oid id_tc26_digset_constants = id_tc26_constants.Branch("2", "параметры алгоритмов хэширования");
	public static readonly Oid id_tc26_cipher_constants = id_tc26_constants.Branch("5", "параметры алгоритмов шифрования");
	public static readonly Oid id_tc26_gost_28147_constants = id_tc26_cipher_constants.Branch("1", "параметры алгоритма шифрования ГОСТ 28147-89");
	public static readonly Oid id_tc26_gost_28147_param_Z = id_tc26_gost_28147_constants.Branch("1", "набор Z параметры алгоритма шифрования ГОСТ  28147-89");
}
