# NetWinapiCms
.NET 7 doesn't support non-Microsoft hash algorithms, and, may be, assymetric algorithms too. This can be a problem for Russia, Kazakhstan and other countries, where national cryptographic algorithms are obligatory.

In the older .NET Framework that stuff works fine, but the .NET Team, I guess, hasn't had enough motivation to fix it in new version of the framework. See https://github.com/dotnet/runtime/issues/26053 for details.

So, there are examples of using WinAPI functions as a workaround +for CMS signing and verifying. 

## Usage
For signing data use the following code snippet:
```c#
var certificate = new X509Certificate(...);
var data = Encoding.UTF8.GetBytes("Test");
var digestOid = GostOids.id_tc26_gost3410_12_256;
var signedCms = CmsHelper.Sign(data, true, certificate, digestOid, true, "12345678");
```

For verifiying the previously signed data use the following code:
```c#
CmsHelper.Verify(signedCms, true, data, true, X509RevocationMode.Online, X509RevocationFlag.ExcludeRoot);
```

## License
This repo is licensed under the [MIT](https://github.com/AntoineLarine/NetWinapiCms/blob/main/LICENSE) license.
