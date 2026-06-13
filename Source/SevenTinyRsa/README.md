# SevenTinyRsa

Precompiled `[SevenTiny.Bantina.Security.RSACommon]` — the RSA public-key
parser that `Private/Get-RsaPublicKeyInfo.ps1` uses to decode DKIM keys.

## Why this exists

Upstream `Get-RsaPublicKeyInfo.ps1` ships the C# source inline and compiles
it at runtime via `Add-Type -TypeDefinition $source -Language CSharp`. That
works fine when DNSHealth is loaded by a normal `pwsh` process (which has
the .NET reference assemblies bundled at `$PSHOME/ref/`), but fails in any
host that embeds PowerShell as a library — `$PSHOME` resolves to the host's
own directory and Roslyn can't find the ref assemblies, so `Add-Type`
throws `DirectoryNotFoundException`.

Bundling a precompiled DLL and listing it in `DNSHealth.psd1`'s
`RequiredAssemblies` registers the type before the module's runtime code
runs. `Get-RsaPublicKeyInfo`'s existing
`if (!('SevenTiny.Bantina.Security.RSACommon' -as [type]))` guard then
short-circuits and `Add-Type` is never reached. The inline source path
stays in place as a fallback for any future host that doesn't ship the
DLL.

Behaviour on standard `pwsh` is unchanged — the type lookup just hits the
preloaded assembly instead of going through the runtime compile.

## Rebuild

```pwsh
cd Source/SevenTinyRsa
dotnet build SevenTinyRsa.csproj -c Release -o ../../DNSHealth/
```

The output `SevenTinyRsa.dll` lands next to `DNSHealth.psd1`.
`build.psd1`'s `CopyDirectories` includes `SevenTinyRsa.dll`, so
`Build-Module` carries it into the built `Output/DNSHealth/` directory
beside the generated `.psm1`.

## Provenance

The C# source is verbatim from
[sevenTiny/Bamboo](https://github.com/sevenTiny/Bamboo) at
`10-Code/SevenTiny.Bantina/Security/RSACommon.cs`. The original
`Get-RsaPublicKeyInfo.ps1` cites the same source in its `.NOTES` block.
