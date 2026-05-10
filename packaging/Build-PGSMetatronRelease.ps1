param(
    [switch]$SkipInstaller,
    [switch]$InstallerOnly,
    [switch]$NoDependencyInstall
)

$ErrorActionPreference = "Stop"
$PackagingRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $PackagingRoot
$BuildRoot = Join-Path $ProjectRoot ".build"
$BuildVenv = Join-Path $BuildRoot "pyinstaller-venv"
$BuildPython = Join-Path $BuildVenv "Scripts\python.exe"
$SpecPath = Join-Path $PackagingRoot "PGS-Metatron.spec"
$InnoScript = Join-Path $PackagingRoot "PGS-Metatron.iss"

function Resolve-BasePython {
    $py = Get-Command "py" -ErrorAction SilentlyContinue
    if ($py) {
        return @{ File = "py"; Args = @("-3") }
    }

    $python = Get-Command "python" -ErrorAction SilentlyContinue
    if ($python) {
        return @{ File = "python"; Args = @() }
    }

    throw "Python was not found. Install Python 3.11+ and run this build again."
}

function Invoke-BasePython {
    param(
        [hashtable]$PythonCommand,
        [string[]]$Arguments
    )
    & $PythonCommand.File @($PythonCommand.Args + $Arguments)
}

function Resolve-InnoCompiler {
    $iscc = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if ($iscc) {
        return $iscc.Source
    }

    foreach ($candidate in @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    return ""
}

Push-Location $PackagingRoot
try {
    if (-not $InstallerOnly) {
        New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null

        if (-not (Test-Path -LiteralPath $BuildPython)) {
            $basePython = Resolve-BasePython
            Write-Host "[*] Creating build Python environment..."
            Invoke-BasePython -PythonCommand $basePython -Arguments @("-m", "venv", $BuildVenv)
        }

        if (-not $NoDependencyInstall) {
            Write-Host "[*] Installing application and build dependencies..."
            $requirementsPath = Join-Path $ProjectRoot "requirements.txt"
            $buildRequirementsPath = Join-Path $PackagingRoot "requirements-build.txt"
            & $BuildPython -m pip install --upgrade pip setuptools wheel
            & $BuildPython -m pip install -r $requirementsPath -r $buildRequirementsPath
        }

        if (Test-Path -LiteralPath (Join-Path $PackagingRoot "dist")) {
            Remove-Item -LiteralPath (Join-Path $PackagingRoot "dist") -Recurse -Force
        }
        if (Test-Path -LiteralPath (Join-Path $PackagingRoot "build")) {
            Remove-Item -LiteralPath (Join-Path $PackagingRoot "build") -Recurse -Force
        }

        Write-Host "[*] Building PGS-Metatron.exe..."
        & $BuildPython -m PyInstaller --noconfirm --clean $SpecPath --distpath (Join-Path $PackagingRoot "dist") --workpath (Join-Path $PackagingRoot "build")
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller build failed."
        }
    }

    $exePath = Join-Path $PackagingRoot "dist\PGS-Metatron.exe"
    if (-not (Test-Path -LiteralPath $exePath)) {
        throw "Expected EXE was not created: $exePath"
    }
    Write-Host "[+] EXE created: $exePath"

    if (-not $SkipInstaller) {
        $iscc = Resolve-InnoCompiler
        if (-not $iscc) {
            throw "Inno Setup 6 was not found. Install Inno Setup 6 or rerun with -SkipInstaller."
        }

        Write-Host "[*] Building single-file Windows installer..."
        & $iscc $InnoScript
        if ($LASTEXITCODE -ne 0) {
            throw "Inno Setup build failed."
        }
        Write-Host "[+] Installer created: $(Join-Path $PackagingRoot 'output\PGS-Metatron-Setup.exe')"
    }
} finally {
    Pop-Location
}
