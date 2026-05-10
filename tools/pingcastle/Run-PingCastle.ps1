param(
    [string]$Target = "",
    [string]$Arguments = "",
    [string]$OutputPath = "",
    [string]$User = "",
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"

$ToolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExePath = Join-Path $ToolRoot "bin\PingCastle.exe"

function Split-CommandLineArguments {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return @()
    }

    Add-Type -ErrorAction SilentlyContinue -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class MetatronCommandLine {
    [DllImport("shell32.dll", SetLastError = true)]
    public static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
        out int pNumArgs);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);
}
"@

    $argc = 0
    $argv = [MetatronCommandLine]::CommandLineToArgvW($CommandLine, [ref]$argc)
    if ($argv -eq [IntPtr]::Zero) {
        return $CommandLine -split "\s+"
    }

    try {
        $items = New-Object string[] $argc
        for ($i = 0; $i -lt $argc; $i++) {
            $ptr = [Runtime.InteropServices.Marshal]::ReadIntPtr($argv, $i * [IntPtr]::Size)
            $items[$i] = [Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
        }
        return $items
    } finally {
        [void][MetatronCommandLine]::LocalFree($argv)
    }
}

if (-not (Test-Path $ExePath)) {
    throw "PingCastle executable was not found. Run tools\pingcastle\Build-PingCastle.ps1 first."
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $Documents = [Environment]::GetFolderPath("MyDocuments")
    if ([string]::IsNullOrWhiteSpace($Documents)) {
        $Documents = $ToolRoot
    }
    $OutputPath = Join-Path $Documents ("PGS-Metatron\reports\pingcastle\" + (Get-Date -Format "yyyyMMdd_HHmmss"))
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$RunArgs = @()
if (-not [string]::IsNullOrWhiteSpace($Arguments)) {
    $RunArgs += Split-CommandLineArguments $Arguments
} else {
    $RunArgs += "--healthcheck"
    if (-not [string]::IsNullOrWhiteSpace($Target)) {
        $RunArgs += "--server"
        $RunArgs += $Target
    }
}

if (-not [string]::IsNullOrWhiteSpace($User)) {
    $RunArgs += "--user"
    $RunArgs += $User
}
if (-not [string]::IsNullOrWhiteSpace($Password)) {
    $RunArgs += "--password"
    $RunArgs += $Password
}

Push-Location $OutputPath
try {
    & $ExePath @RunArgs
    $ExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($ExitCode -ne 0) {
    throw "PingCastle exited with code $ExitCode."
}

Write-Host "[PINGCASTLE ARTIFACTS]"
Write-Host $OutputPath
