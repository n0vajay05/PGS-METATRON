param(
    [string]$ServiceName = "MariaDB",
    [string]$Database = "metatron",
    [string]$AppUser = "metatron",
    [string]$ResultPath = "",
    [switch]$Apply
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ResultPath) {
    $ResultPath = Join-Path $ProjectRoot ".cache\database-rotation-result.json"
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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

function ConvertTo-SqlLiteral([string]$Value) {
    return $Value.Replace("\", "\\").Replace("'", "''")
}

function Resolve-MySqlTool([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }
    $matches = Get-ChildItem "C:\Program Files\MariaDB*\bin\$Name.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($matches) {
        return $matches.FullName
    }
    throw "Could not find $Name.exe."
}

function Resolve-ServiceDefaultsFile {
    $config = (& sc.exe qc $ServiceName) -join "`n"
    if ($config -match '--defaults-file=([^"]+?\.ini)') {
        return $matches[1]
    }
    if ($config -match '--defaults-file="([^"]+?\.ini)"') {
        return $matches[1]
    }
    $candidate = Get-ChildItem "C:\Program Files\MariaDB*\data\my.ini" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) {
        return $candidate.FullName
    }
    throw "Could not find MariaDB my.ini defaults file."
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

function Wait-DatabasePort([int]$TimeoutSeconds = 60) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $connected = Test-NetConnection -ComputerName 127.0.0.1 -Port 3306 -InformationLevel Quiet -WarningAction SilentlyContinue
            if ($connected) {
                return $true
            }
        } catch {}
        Start-Sleep -Seconds 1
    }
    return $false
}

if (-not $Apply) {
    if (-not (Test-Administrator)) {
        $args = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-ServiceName", "`"$ServiceName`"",
            "-Database", "`"$Database`"",
            "-AppUser", "`"$AppUser`"",
            "-ResultPath", "`"$ResultPath`"",
            "-Apply"
        )
        $process = Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Elevated password rotation failed with exit code $($process.ExitCode)."
        }
    } else {
        & $PSCommandPath -ServiceName $ServiceName -Database $Database -AppUser $AppUser -ResultPath $ResultPath -Apply
    }
    if (-not (Test-Path $ResultPath)) {
        throw "Password rotation did not produce a result file."
    }
    Write-Output "ROTATION_RESULT=$ResultPath"
    return
}

if (-not (Test-Administrator)) {
    throw "Administrator rights are required to rotate MariaDB root credentials."
}

$rootPassword = New-StrongPassword
$appPassword = New-StrongPassword
$mysqld = Resolve-MySqlTool "mysqld"
$mysql = Resolve-MySqlTool "mariadb"
$admin = Resolve-MySqlTool "mariadb-admin"
$defaultsFile = Resolve-ServiceDefaultsFile

$cacheDir = Split-Path -Parent $ResultPath
New-Item -ItemType Directory -Force -Path $cacheDir | Out-Null

$initPath = Join-Path $env:TEMP ("metatron-db-rotate-" + [guid]::NewGuid().ToString("N") + ".sql")
$serverOutPath = Join-Path $cacheDir "database-rotation-mysqld.out.log"
$serverErrPath = Join-Path $cacheDir "database-rotation-mysqld.err.log"
$databaseSql = $Database.Replace('`', '``')
$appUserSql = ConvertTo-SqlLiteral $AppUser
$rootPasswordSql = ConvertTo-SqlLiteral $rootPassword
$appPasswordSql = ConvertTo-SqlLiteral $appPassword
$backtick = [char]96

$initSql = @"
CREATE DATABASE IF NOT EXISTS $backtick$databaseSql$backtick;
CREATE USER IF NOT EXISTS '$appUserSql'@'localhost' IDENTIFIED BY '$appPasswordSql';
ALTER USER 'root'@'localhost' IDENTIFIED BY '$rootPasswordSql';
ALTER USER '$appUserSql'@'localhost' IDENTIFIED BY '$appPasswordSql';
GRANT ALL PRIVILEGES ON $backtick$databaseSql$backtick.* TO '$appUserSql'@'localhost';
FLUSH PRIVILEGES;
"@
Write-Utf8NoBom -Path $initPath -Content $initSql

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    $quotedDefaults = '--defaults-file="' + $defaultsFile + '"'
    $quotedInitFile = '--init-file="' + $initPath + '"'
    $serverArgs = @($quotedDefaults, $quotedInitFile, "--console") -join " "
    Remove-Item $serverOutPath, $serverErrPath -Force -ErrorAction SilentlyContinue
    $server = Start-Process `
        -FilePath $mysqld `
        -ArgumentList $serverArgs `
        -WindowStyle Hidden `
        -PassThru `
        -RedirectStandardOutput $serverOutPath `
        -RedirectStandardError $serverErrPath

    if (-not (Wait-DatabasePort -TimeoutSeconds 60)) {
        if (-not $server.HasExited) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        }
        throw "Temporary MariaDB server did not start within 60 seconds. Check $serverErrPath"
    }

    & $admin "-uroot" "-p$rootPassword" "-h" "127.0.0.1" "-P" "3306" "shutdown" *> $null
    if ($LASTEXITCODE -ne 0 -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
    try {
        $server.WaitForExit(15000) | Out-Null
    } catch {}

    Start-Service -Name $ServiceName
    if (-not (Wait-DatabasePort -TimeoutSeconds 60)) {
        throw "MariaDB service did not come back online within 60 seconds."
    }

    & $mysql "-uroot" "-p$rootPassword" "-h" "127.0.0.1" "-P" "3306" "-e" "SELECT 1" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Root password verification failed after rotation."
    }

    & $mysql "-u$AppUser" "-p$appPassword" "-h" "127.0.0.1" "-P" "3306" $Database "-e" "SELECT 1" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Metatron user password verification failed after rotation."
    }
    Save-CredentialManagerSecret -Target "PGS-Metatron:DatabaseRootPassword" -UserName "root" -Secret $rootPassword

    $appConfigDir = Join-Path $env:LOCALAPPDATA "PGS-Metatron"
    $appConfigPath = Join-Path $appConfigDir "metatron_config.json"
    New-Item -ItemType Directory -Force -Path $appConfigDir | Out-Null
    if (Test-Path $appConfigPath) {
        $config = Get-Content $appConfigPath -Raw | ConvertFrom-Json
    } else {
        $config = [pscustomobject]@{}
    }
    $config | Add-Member -NotePropertyName "database_settings" -NotePropertyValue ([pscustomobject]@{
        host = "localhost"
        port = 3306
        user = $AppUser
        database = $Database
    }) -Force
    Save-CredentialManagerSecret -Target "PGS-Metatron:DatabasePassword" -UserName $AppUser -Secret $appPassword
    Write-Utf8NoBom -Path $appConfigPath -Content ($config | ConvertTo-Json -Depth 8)

    $result = [pscustomobject]@{
        rotated_at = (Get-Date).ToString("s")
        service = $ServiceName
        database = $Database
        root_user = "root"
        root_password = "stored in Windows Credential Manager: PGS-Metatron:DatabaseRootPassword"
        app_user = $AppUser
        app_password = "stored in Windows Credential Manager: PGS-Metatron:DatabasePassword"
        app_config = $appConfigPath
    }
    Write-Utf8NoBom -Path $ResultPath -Content ($result | ConvertTo-Json -Depth 4)
    try {
        icacls $ResultPath /inheritance:r /grant:r "${env:USERNAME}:(R,W)" "Administrators:(F)" "SYSTEM:(F)" *> $null
    } catch {}
} finally {
    Remove-Item $initPath -Force -ErrorAction SilentlyContinue
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Running") {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
    } catch {}
}
