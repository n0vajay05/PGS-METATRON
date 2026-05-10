param(
    [string]$SourcePath = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

$ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ToolRoot)

if ([string]::IsNullOrWhiteSpace($SourcePath)) {
    $SourcePath = Join-Path $RepoRoot ".tools\pingcastle-source"
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ToolRoot "bin"
}

$SourcePath = [System.IO.Path]::GetFullPath($SourcePath)
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$ProjectPath = Join-Path $SourcePath "PingCastle\PingCastle.csproj"
$CacheRoot = Join-Path $RepoRoot ".cache"
$DotnetHome = Join-Path $CacheRoot "dotnet"
$NugetPackages = Join-Path $CacheRoot "nuget\packages"
$LocalNugetSource = Join-Path $CacheRoot "nuget-local"
$AppData = Join-Path $CacheRoot "appdata"
$LocalAppData = Join-Path $CacheRoot "localappdata"
$UserProfile = Join-Path $CacheRoot "userprofile"
$NugetConfig = Join-Path $CacheRoot "NuGet.Config"

New-Item -ItemType Directory -Force -Path $CacheRoot, $DotnetHome, $NugetPackages, $LocalNugetSource, $AppData, $LocalAppData, $UserProfile, $OutputPath | Out-Null

@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="PGS-Metatron local NuGet cache" value="$LocalNugetSource" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"@ | Set-Content -Path $NugetConfig -Encoding UTF8

if (-not (Test-Path $ProjectPath)) {
    $Git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $Git) {
        throw "PingCastle source was not found and git is not available."
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $SourcePath) | Out-Null
    & git -c http.sslBackend=openssl clone --depth 1 https://github.com/netwrix/pingcastle.git $SourcePath
    if ($LASTEXITCODE -ne 0) {
        throw "Could not clone PingCastle source."
    }
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET SDK 8.0 or newer is required to build PingCastle."
}

$env:DOTNET_CLI_HOME = $DotnetHome
$env:NUGET_PACKAGES = $NugetPackages
$env:APPDATA = $AppData
$env:LOCALAPPDATA = $LocalAppData
$env:USERPROFILE = $UserProfile
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = "1"
$env:DOTNET_CLI_TELEMETRY_OPTOUT = "1"

Write-Host "[*] Building PingCastle from $ProjectPath"
Write-Host "[*] Output folder: $OutputPath"

dotnet publish $ProjectPath `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -o $OutputPath `
    /p:PublishSingleFile=true `
    --configfile $NugetConfig

if ($LASTEXITCODE -ne 0) {
    throw "PingCastle build failed."
}

$ExePath = Join-Path $OutputPath "PingCastle.exe"
if (-not (Test-Path $ExePath)) {
    throw "PingCastle.exe was not produced at $ExePath."
}

Write-Host "[+] PingCastle prepared: $ExePath"
