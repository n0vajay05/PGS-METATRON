param(
    [string]$MariaDbVersion = "11.4.3",
    [string]$RootPassword = "",
    [string]$ServiceName = "MariaDB",
    [string]$Database = "metatron",
    [string]$AppUser = "metatron",
    [string]$AppPassword = "",
    [switch]$AssumeYes,
    [switch]$NoElevate
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallerCache = Join-Path $ProjectRoot ".cache"
$MsiPath = Join-Path $InstallerCache "mariadb-$MariaDbVersion-winx64.msi"
$LogPath = Join-Path $InstallerCache "mariadb-install.log"
$MsiUrl = "https://downloads.mariadb.org/rest-api/mariadb/$MariaDbVersion/mariadb-$MariaDbVersion-winx64.msi"

function New-StrongPassword([int]$Length = 28) {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%+-=?@_"
    $bytes = [byte[]]::new($Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    if ($password -notmatch "[A-Z]" -or $password -notmatch "[a-z]" -or $password -notmatch "\d" -or $password -notmatch "[!#\$%\+\-=\?@_]") {
        return New-StrongPassword -Length $Length
    }
    return $password
}

function Write-Utf8NoBom([string]$Path, [string]$Content) {
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Save-CredentialManagerSecret {
    param(
        [string]$Target,
        [string]$UserName,
        [string]$Secret
    )
    & cmdkey.exe "/generic:$Target" "/user:$UserName" "/pass:$Secret" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not save $Target in Windows Credential Manager."
    }
}

function Save-MetatronDatabaseSettings {
    param(
        [string]$HostName,
        [int]$Port,
        [string]$DbName,
        [string]$UserName,
        [string]$Password
    )

    $configDir = Join-Path $env:LOCALAPPDATA "PGS-Metatron"
    $configPath = Join-Path $configDir "metatron_config.json"
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath -Raw | ConvertFrom-Json
        } catch {
            $config = [pscustomobject]@{}
        }
    } else {
        $config = [pscustomobject]@{}
    }
    $config | Add-Member -NotePropertyName "database_settings" -NotePropertyValue ([pscustomobject]@{
        host = $HostName
        port = $Port
        user = $UserName
        database = $DbName
    }) -Force
    Save-CredentialManagerSecret -Target "PGS-Metatron:DatabasePassword" -UserName $UserName -Secret $Password
    Write-Utf8NoBom -Path $configPath -Content ($config | ConvertTo-Json -Depth 8)
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ElevatedSelf {
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-MariaDbVersion", "`"$MariaDbVersion`"",
        "-RootPassword", "`"$RootPassword`"",
        "-ServiceName", "`"$ServiceName`"",
        "-Database", "`"$Database`"",
        "-AppUser", "`"$AppUser`"",
        "-AppPassword", "`"$AppPassword`"",
        "-NoElevate"
    )

    if ($AssumeYes) {
        $args += "-AssumeYes"
    }

    Write-Host "[*] Administrator approval is required to install/start MariaDB."
    $process = Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -Wait -PassThru
    return $process.ExitCode
}

if (-not $RootPassword) {
    $RootPassword = New-StrongPassword
}
if (-not $AppPassword) {
    $AppPassword = New-StrongPassword
}

function Find-DatabaseService {
    Get-Service | Where-Object {
        $_.Name -match "maria|mysql" -or $_.DisplayName -match "maria|mysql"
    } | Select-Object -First 1
}

function Test-DatabasePort {
    Test-NetConnection -ComputerName 127.0.0.1 -Port 3306 -InformationLevel Quiet
}

if (-not (Test-Administrator) -and -not $NoElevate) {
    $elevatedExitCode = Invoke-ElevatedSelf
    if ($elevatedExitCode -ne 0) {
        throw "Elevated MariaDB installer failed with exit code $elevatedExitCode."
    }
    return
}

if (-not (Test-Administrator)) {
    throw "MariaDB installation requires an elevated PowerShell session."
}

$existingService = Find-DatabaseService
if ($existingService) {
    Write-Host "[*] Found database service: $($existingService.Name)"
    if ($existingService.Status -ne "Running") {
        Write-Host "[*] Starting $($existingService.Name)"
        Start-Service -Name $existingService.Name
        Start-Sleep -Seconds 3
    }
} else {
    if (-not $AssumeYes) {
        Write-Host "Metatron can install MariaDB Server $MariaDbVersion as a local Windows service."
        $answer = Read-Host "Install MariaDB now? [y/N]"
        if ($answer.ToLowerInvariant() -ne "y") {
            throw "MariaDB installation was cancelled."
        }
    }

    New-Item -ItemType Directory -Force -Path $InstallerCache | Out-Null

    if (-not (Test-Path $MsiPath)) {
        Write-Host "[*] Downloading MariaDB Server $MariaDbVersion..."
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath
    }

    Write-Host "[*] Installing MariaDB Server as service '$ServiceName' on port 3306..."
    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "/qn",
        "/norestart",
        "/l*v", "`"$LogPath`"",
        "PASSWORD=$RootPassword",
        "SERVICENAME=$ServiceName",
        "PORT=3306",
        "UTF8=1"
    )

    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "MariaDB MSI install failed with exit code $($process.ExitCode). See $LogPath"
    }

    Start-Sleep -Seconds 5
    $existingService = Find-DatabaseService
    if (-not $existingService) {
        throw "MariaDB installed, but no Windows service was found. See $LogPath"
    }

    if ($existingService.Status -ne "Running") {
        Start-Service -Name $existingService.Name
        Start-Sleep -Seconds 3
    }
}

if (-not (Test-DatabasePort)) {
    throw "MariaDB is installed, but nothing is listening on 127.0.0.1:3306. Check $LogPath or the MariaDB my.ini networking settings."
}

Write-Host "[*] Creating Metatron database/user/schema..."
& (Join-Path $ProjectRoot "Setup-MetatronDatabase.ps1") `
    -RootUser "root" `
    -RootPassword $RootPassword `
    -Database $Database `
    -AppUser $AppUser `
    -AppPassword $AppPassword

if ($LASTEXITCODE -ne 0) {
    throw "Metatron database setup failed."
}

Write-Host "[+] MariaDB is ready for Metatron."
Save-CredentialManagerSecret -Target "PGS-Metatron:DatabaseRootPassword" -UserName "root" -Secret $RootPassword
Save-MetatronDatabaseSettings -HostName "localhost" -Port 3306 -DbName $Database -UserName $AppUser -Password $AppPassword
Write-Host "[+] PGS Metatron database settings saved for the current Windows user."
