param(
    [string]$Python = "python",
    [switch]$Cli
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Requirements = Join-Path $ProjectRoot "requirements.txt"
$DatabaseInstaller = Join-Path $ProjectRoot "Install-MetatronDatabase.ps1"
$LocalAppData = [Environment]::GetFolderPath("LocalApplicationData")
if (-not $LocalAppData) {
    $LocalAppData = $ProjectRoot
}

function Resolve-Python {
    if (Test-Path $VenvPython) {
        return $VenvPython
    }

    $pyLauncher = Get-Command "py" -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        return "py -3"
    }

    $pythonCommand = Get-Command $Python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        return $Python
    }

    throw "Python was not found. Install Python 3 from https://www.python.org/downloads/windows/ or Visual Studio's Python workload."
}

function Invoke-Python {
    param(
        [string]$PythonCommand,
        [string[]]$Arguments
    )

    if ($PythonCommand -eq "py -3") {
        & py -3 @Arguments
    } else {
        & $PythonCommand @Arguments
    }
}

$BasePython = Resolve-Python

if (-not (Test-Path $VenvPython)) {
    Write-Host "[*] Creating local Python environment: .venv"
    Invoke-Python -PythonCommand $BasePython -Arguments @("-m", "venv", ".venv")
}

$CacheDir = Join-Path $LocalAppData "PGS-Metatron\cache"
$RequirementsStamp = Join-Path $CacheDir "requirements.sha256"
$RequirementsHash = (Get-FileHash -LiteralPath $Requirements -Algorithm SHA256).Hash
$InstalledRequirementsHash = ""
if (Test-Path $RequirementsStamp) {
    $InstalledRequirementsHash = (Get-Content -LiteralPath $RequirementsStamp -Raw).Trim()
}

if ($InstalledRequirementsHash -ne $RequirementsHash) {
    & $VenvPython -c "import mysql.connector, requests, sslyze, playwright, bs4, PIL, tkinterweb" *> $null
    $DependenciesReady = $LASTEXITCODE -eq 0
    if (-not $DependenciesReady) {
        Write-Host "[*] Installing Python dependencies from requirements.txt"
        & $VenvPython -m pip install -r $Requirements
        if ($LASTEXITCODE -ne 0) {
            throw "Dependency installation failed. Re-run the PGS Metatron installer from an elevated PowerShell window."
        }
    }
    New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null
    Set-Content -LiteralPath $RequirementsStamp -Value $RequirementsHash -Encoding ASCII
}

if (-not (Test-NetConnection -ComputerName 127.0.0.1 -Port 3306 -InformationLevel Quiet)) {
    if (-not (Test-Path $DatabaseInstaller)) {
        throw "MariaDB is not listening on port 3306 and the integrated installer is missing: $DatabaseInstaller"
    }

    Write-Host "[*] MariaDB is not ready. Starting the integrated MariaDB installer..."
    & $DatabaseInstaller -AssumeYes

    if (-not (Test-NetConnection -ComputerName 127.0.0.1 -Port 3306 -InformationLevel Quiet)) {
        throw "MariaDB setup finished, but port 3306 is still not reachable."
    }
}

if ($Cli) {
    & $VenvPython metatron.py
    exit $LASTEXITCODE
}

$GuiScript = Join-Path $ProjectRoot "metatron_gui.py"
if (-not (Test-Path $GuiScript)) {
    & $VenvPython metatron.py
    exit $LASTEXITCODE
}

$Pythonw = Join-Path $ProjectRoot ".venv\Scripts\pythonw.exe"
if (Test-Path $Pythonw) {
    & $Pythonw $GuiScript
} else {
    & $VenvPython $GuiScript
}
