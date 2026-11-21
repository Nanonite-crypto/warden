<#
.SYNOPSIS
    Makes the signed files that the signature tests need on Windows.

.DESCRIPTION
    FOR A THROWAWAY CI MACHINE ONLY. This script creates certificates and
    adds two of them to the machine's list of trusted root certificates,
    which is a change to the security settings of the machine it runs on.
    On a hosted runner that machine is deleted when the job ends. The script
    refuses to run anywhere else.

    A signature check has to be tested against signatures, and the ones
    that matter most are the ones it has to turn down. Nobody hands those
    out, so they are made here:

    - plain.exe       a small program built from one line of Rust, not signed
    - signed.exe      the same, validly signed by a publisher that is on no
                      trust list ("Warden Test Publisher")
    - tampered.exe    signed.exe with one byte changed after signing
    - padded.exe      signed.exe with bytes added inside the area that holds
                      the signature, which no signature covers
    - lookalike.exe   the same program, validly signed with a certificate
                      that carries the names Microsoft signs its applications
                      with, issued by a root made here. The machine trusts
                      that root, so Windows calls the signature valid.
    - package\        an app package signed by the test publisher, unpacked
                      into a folder the way Windows keeps installed apps
    - package-changed\  the same with one file changed afterwards
    - package-added\    the same with one file added afterwards

    fixtures.json says where everything is and what Windows itself says
    about each file. The private keys stay in the certificate store of the
    runner's user and are gone with the machine. Nothing made here is
    uploaded anywhere.

.PARAMETER Out
    Folder to write to. It is created if it does not exist.

.PARAMETER Remove
    Take the two root certificates out of the machine's list again. The
    thumbprints are read from fixtures.json in the folder.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'This script changes which root certificates a machine trusts. It only runs on a GitHub-hosted runner, which is deleted after the job.'
}

$manifestPath = Join-Path $Out 'fixtures.json'

if ($Remove) {
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        Write-Host 'No fixtures.json, so there is nothing to remove.'
        return
    }
    $made = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    foreach ($thumbprint in $made.trusted_roots) {
        $path = "Cert:\LocalMachine\Root\$thumbprint"
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path
            Write-Host "Removed the test root $thumbprint."
        }
    }
    return
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path -LiteralPath $Out).Path

# --- A small program to sign -------------------------------------------------

$source = Join-Path $Out 'tiny.rs'
Set-Content -LiteralPath $source -Encoding ASCII -Value 'fn main() { println!("a test program of Warden''s"); }'
$plain = Join-Path $Out 'plain.exe'
& rustc --edition 2024 -C opt-level=1 -C debuginfo=0 -o $plain $source
if ($LASTEXITCODE -ne 0) { throw 'rustc could not build the test program' }

# --- Certificates --------------------------------------------------------------

$store = 'Cert:\CurrentUser\My'
$until = (Get-Date).AddDays(30)
$key = @{ KeyAlgorithm = 'RSA'; KeyLength = 2048; HashAlgorithm = 'SHA256'; CertStoreLocation = $store; NotAfter = $until }

# A publisher whose certificate is its own root.
$publisher = New-SelfSignedCertificate @key -Type CodeSigningCert `
    -Subject 'CN=Warden Test Publisher, O=Warden Test'

# A root made here, and under it a certificate with the two names that
# Microsoft's own application certificates carry. Only the names are
# Microsoft's. The key is this script's, and so is the root.
$root = New-SelfSignedCertificate @key -Type Custom `
    -Subject 'CN=Warden Test Root, O=Warden Test' `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -TextExtension @('2.5.29.19={critical}{text}CA=true&pathlength=0')
$lookalike = New-SelfSignedCertificate @key -Type CodeSigningCert `
    -Subject 'CN=Microsoft Corporation, O=Microsoft Corporation' `
    -Signer $root

# This machine is told to trust both roots. That is what makes Windows call
# the signatures below valid, and it is the reason this script runs nowhere
# but on a machine that is thrown away.
$trusted = @()
foreach ($certificate in @($publisher, $root)) {
    $file = Join-Path $Out "$($certificate.Thumbprint).cer"
    Export-Certificate -Cert $certificate -FilePath $file | Out-Null
    Import-Certificate -FilePath $file -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    $trusted += $certificate.Thumbprint
}

# --- Signed files ----------------------------------------------------------------

function New-SignedCopy([string]$Name, $Certificate) {
    $path = Join-Path $Out $Name
    Copy-Item -LiteralPath $plain -Destination $path
    $result = Set-AuthenticodeSignature -LiteralPath $path -Certificate $Certificate -HashAlgorithm SHA256
    if ($result.Status -ne 'Valid') {
        throw "Signing $Name gave $($result.Status): $($result.StatusMessage)"
    }
    $path
}

$signed = New-SignedCopy 'signed.exe' $publisher
New-SignedCopy 'lookalike.exe' $lookalike | Out-Null

# One byte changed in the middle of the program, far from the signature.
$bytes = [IO.File]::ReadAllBytes($signed)
$middle = [int][Math]::Floor($bytes.Length / 2)
$bytes[$middle] = $bytes[$middle] -bxor 0xFF
[IO.File]::WriteAllBytes((Join-Path $Out 'tampered.exe'), $bytes)

# Bytes added at the end of the table that holds the signature. Two length
# fields say how long that table is, one in the program's header and one at
# the start of the table, and both are raised to take the new bytes in.
# The hash a signature is made over leaves the whole table out.
$bytes = [IO.File]::ReadAllBytes($signed)
$header = [BitConverter]::ToInt32($bytes, 0x3C)
$optional = $header + 24
$directories = if ([BitConverter]::ToUInt16($bytes, $optional) -eq 0x20B) { $optional + 112 } else { $optional + 96 }
$entry = $directories + 4 * 8
$tableAt = [BitConverter]::ToInt32($bytes, $entry)
$tableSize = [BitConverter]::ToInt32($bytes, $entry + 4)
if ($tableAt -le 0 -or $tableAt + $tableSize -ne $bytes.Length) {
    throw 'The signature table of signed.exe is not where it was expected, at the end of the file.'
}
$extra = [Text.Encoding]::ASCII.GetBytes('WARDEN-TEST-BYTES-ADDED-TO-THE-SIGNATURE')
if ($extra.Length % 8 -ne 0) { throw 'The added bytes have to keep the table a multiple of eight long.' }
$padded = New-Object byte[] ($bytes.Length + $extra.Length)
[Array]::Copy($bytes, $padded, $bytes.Length)
[Array]::Copy($extra, 0, $padded, $bytes.Length, $extra.Length)
[BitConverter]::GetBytes([int]($tableSize + $extra.Length)).CopyTo($padded, $entry + 4)
[BitConverter]::GetBytes([int]($tableSize + $extra.Length)).CopyTo($padded, $tableAt)
[IO.File]::WriteAllBytes((Join-Path $Out 'padded.exe'), $padded)

# --- An app package ----------------------------------------------------------------

$package = $null
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
function Find-KitTool([string]$Name) {
    Get-ChildItem -LiteralPath $kits -Recurse -Filter $Name -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
$makeappx = Find-KitTool 'makeappx.exe'
$signtool = Find-KitTool 'signtool.exe'
if (-not $makeappx -or -not $signtool) {
    Write-Warning "makeappx.exe or signtool.exe was not found under $kits, so no test package is made."
} else {
    $packageSource = Join-Path $Out 'package-source'
    New-Item -ItemType Directory -Force -Path (Join-Path $packageSource 'tools') | Out-Null
    Copy-Item -LiteralPath $plain -Destination (Join-Path $packageSource 'tools\tool.exe')
    Set-Content -LiteralPath (Join-Path $packageSource 'notes.txt') -Encoding ASCII `
        -Value 'A text file in a test package of Warden''s.'
    # A picture of one pixel, because a package has to name a logo.
    [IO.File]::WriteAllBytes((Join-Path $packageSource 'logo.png'), [Convert]::FromBase64String(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=='))
    # The package names its publisher, and that has to be the name in the
    # certificate it is signed with, letter for letter.
    $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="WardenTest.Package" Publisher="$($publisher.Subject)" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Warden test package</DisplayName>
    <PublisherDisplayName>Warden Test</PublisherDisplayName>
    <Logo>logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
  <Applications>
    <Application Id="Tool" Executable="tools\tool.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Warden test" Description="A test package of Warden's" BackgroundColor="transparent" Square150x150Logo="logo.png" Square44x44Logo="logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
"@
    [IO.File]::WriteAllText((Join-Path $packageSource 'AppxManifest.xml'), $manifest, (New-Object Text.UTF8Encoding($false)))

    $msix = Join-Path $Out 'test.msix'
    & $makeappx pack /d $packageSource /p $msix /nv /o
    if ($LASTEXITCODE -ne 0) { throw 'makeappx could not pack the test package' }
    & $signtool sign /fd SHA256 /sha1 $publisher.Thumbprint /s My $msix
    if ($LASTEXITCODE -ne 0) { throw 'signtool could not sign the test package' }

    # Unpacked into a folder, the way Windows keeps an installed app. A
    # package is a zip archive, so it is unpacked as one: that leaves every
    # file as it is in the package, the signature included.
    $package = Join-Path $Out 'package'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($msix, $package)
    foreach ($needed in 'AppxSignature.p7x', 'AppxBlockMap.xml', 'notes.txt', 'tools\tool.exe') {
        if (-not (Test-Path -LiteralPath (Join-Path $package $needed))) {
            throw "The unpacked test package has no $needed."
        }
    }

    # The same folder with a file changed after signing, same length.
    $changed = Join-Path $Out 'package-changed'
    Copy-Item -LiteralPath $package -Destination $changed -Recurse
    Set-Content -LiteralPath (Join-Path $changed 'notes.txt') -Encoding ASCII `
        -Value 'A text file in a test package of Warden''S.'
    # And with a file that the package never had.
    $added = Join-Path $Out 'package-added'
    Copy-Item -LiteralPath $package -Destination $added -Recurse
    Set-Content -LiteralPath (Join-Path $added 'added.txt') -Encoding ASCII -Value 'Not part of the package.'
}

# --- What Windows says ---------------------------------------------------------------

$said = foreach ($name in 'plain.exe', 'signed.exe', 'tampered.exe', 'padded.exe', 'lookalike.exe') {
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $Out $name)
    [pscustomobject]@{
        file         = $name
        windows_says = "$($signature.Status)"
        signer       = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    }
}
$packageSaid = $null
if ($package) {
    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $Out 'test.msix')
    $packageSaid = [pscustomobject]@{
        file         = 'test.msix'
        windows_says = "$($signature.Status)"
        signer       = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    }
}

$made = [pscustomobject]@{
    folder          = $Out
    publisher       = $publisher.Subject
    lookalike       = $lookalike.Subject
    lookalike_root  = $root.Subject
    trusted_roots   = $trusted
    has_package     = [bool]$package
    windows_says    = @($said)
    package_says    = $packageSaid
}
[IO.File]::WriteAllText($manifestPath, ($made | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding($false)))
Get-Content -LiteralPath $manifestPath
