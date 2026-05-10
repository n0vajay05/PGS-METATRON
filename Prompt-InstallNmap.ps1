param(
    [switch]$AssumeYes
)

$ErrorActionPreference = "Stop"

function Test-NmapInstalled {
    $command = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $true
    }

    $knownPaths = @(
        "$env:ProgramFiles\Nmap\nmap.exe",
        "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
    )
    foreach ($path in $knownPaths) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $true
        }
    }
    return $false
}

function Find-Winget {
    $command = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe",
        "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe"
    )
    foreach ($candidate in $candidates) {
        $match = Get-ChildItem -Path $candidate -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($match) {
            return $match.FullName
        }
    }
    return ""
}

function Show-Message {
    param(
        [string]$Text,
        [string]$Title = "PGS Metatron",
        [string]$Buttons = "OK",
        [string]$Icon = "Information"
    )

    Add-Type -AssemblyName System.Windows.Forms
    return [System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

if (Test-NmapInstalled) {
    Write-Host "[+] Nmap is already installed."
    exit 0
}

$install = $AssumeYes
if (-not $install) {
    $answer = Show-Message `
        -Text "Nmap is required for PGS Metatron's Nmap tool, but it was not found on this computer.`n`nInstall Nmap now using Windows Package Manager?" `
        -Buttons "YesNo" `
        -Icon "Question"
    $install = ($answer -eq [System.Windows.Forms.DialogResult]::Yes)
}

if (-not $install) {
    Write-Host "[*] Nmap installation skipped by user."
    exit 0
}

$winget = Find-Winget
if (-not $winget) {
    Show-Message `
        -Text "Windows Package Manager (winget) was not found, so Nmap could not be installed automatically.`n`nInstall Nmap manually with:`nwinget install Insecure.Nmap" `
        -Icon "Warning" | Out-Null
    exit 0
}

$arguments = @(
    "install",
    "--id", "Insecure.Nmap",
    "-e",
    "--source", "winget",
    "--accept-package-agreements",
    "--accept-source-agreements"
)

Write-Host "[*] Installing Nmap with winget..."
$process = Start-Process -FilePath $winget -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Show-Message `
        -Text "The Nmap installer returned exit code $($process.ExitCode).`n`nYou can install it manually later with:`nwinget install Insecure.Nmap" `
        -Icon "Warning" | Out-Null
    exit 0
}

Show-Message -Text "Nmap was installed successfully." | Out-Null
