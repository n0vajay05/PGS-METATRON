param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [string]$CertificateThumbprint = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$SignToolPath = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $FilePath)) {
    throw "File to sign was not found: $FilePath"
}

if (-not $SignToolPath) {
    $candidates = @(
        (Get-Command "signtool.exe" -ErrorAction SilentlyContinue).Source,
        "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $SignToolPath = $candidates | Select-Object -First 1
}

if (-not $SignToolPath) {
    throw "signtool.exe was not found. Install the Windows SDK or pass -SignToolPath."
}

$args = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
if ($PfxPath) {
    if (-not (Test-Path -LiteralPath $PfxPath)) {
        throw "PFX certificate file was not found: $PfxPath"
    }
    $args += @("/f", $PfxPath)
    if ($PfxPassword) {
        $args += @("/p", $PfxPassword)
    }
} elseif ($CertificateThumbprint) {
    $args += @("/sha1", $CertificateThumbprint)
} else {
    throw "Provide either -CertificateThumbprint or -PfxPath."
}

$args += $FilePath
& $SignToolPath @args
if ($LASTEXITCODE -ne 0) {
    throw "Signing failed for $FilePath."
}

Write-Host "[+] Signed $FilePath"
