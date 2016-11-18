mkdir package\lib\net45
copy ..\src\bin\Release\LogicSoftware.WebPushEncryption.dll package\lib\net45
NuGet.EXE pack package\WebPushEncryption.nuspec