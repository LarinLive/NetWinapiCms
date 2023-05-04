# NetWinapiCms
.NET 7 doesn't support non-Microsoft hash algorithms, and, may be, assymetric algorithms too. This can be a problem for Russia, Kazakhstan and other countries, where national cryptographic algorithms are obligatory.

In the older .NET Framework that stuff works fine, but the .NET Team, I guess, hasn't had enough motivation to fix it in new version of the framework. See https://github.com/dotnet/runtime/issues/26053 for details.

So, there are examples of using WinAPI functions as a workaround +for CMS signing and verifying.

## License
This repo is licensed under the [MIT](https://github.com/AntoineLarine/NetWinapiCms/blob/main/LICENSE) license.