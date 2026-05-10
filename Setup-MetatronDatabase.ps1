param(
    [string]$RootUser = "root",
    [string]$RootPassword = "",
    [string]$Database = "metatron",
    [string]$AppUser = "metatron",
    [string]$AppPassword = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$SchemaPath = Join-Path $ProjectRoot "schema.sql"

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

if (-not $AppPassword) {
    $AppPassword = New-StrongPassword
}

function Resolve-MySqlClient {
    foreach ($name in @("mariadb", "mysql")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    }

    $candidates = @(
        "C:\Program Files\MariaDB*\bin\mariadb.exe",
        "C:\Program Files\MariaDB*\bin\mysql.exe",
        "C:\Program Files\MySQL\MySQL Server *\bin\mysql.exe"
    )

    foreach ($pattern in $candidates) {
        $match = Get-ChildItem $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($match) {
            return $match.FullName
        }
    }

    throw "Could not find mariadb.exe or mysql.exe. Install MariaDB Server, then rerun this script."
}

if (-not (Test-Path $SchemaPath)) {
    throw "Missing schema file: $SchemaPath"
}

$Client = Resolve-MySqlClient
$schema = Get-Content $SchemaPath -Raw
$backtick = [char]96
$DatabaseSql = $Database.Replace('`', '``')
$AppUserSql = $AppUser.Replace("'", "''")
$AppPasswordSql = $AppPassword.Replace("'", "''")
$sql = @"
CREATE DATABASE IF NOT EXISTS $backtick$DatabaseSql$backtick;
CREATE USER IF NOT EXISTS '$AppUserSql'@'localhost' IDENTIFIED BY '$AppPasswordSql';
ALTER USER '$AppUserSql'@'localhost' IDENTIFIED BY '$AppPasswordSql';
GRANT ALL PRIVILEGES ON $backtick$DatabaseSql$backtick.* TO '$AppUserSql'@'localhost';
FLUSH PRIVILEGES;
USE $backtick$DatabaseSql$backtick;
$schema
"@

$clientArgs = @("-u", $RootUser, "-h", "localhost", "-P", "3306")
if ($RootPassword) {
    $clientArgs += "-p$RootPassword"
}

Write-Host "[*] Creating/updating database '$Database' and user '$AppUser'..."
$sql | & $Client @clientArgs

if ($LASTEXITCODE -ne 0) {
    throw "Database setup failed. Confirm the MariaDB service is running and the root credentials are correct."
}

Write-Host "[+] Database setup complete."
Save-MetatronDatabaseSettings -HostName "localhost" -Port 3306 -DbName $Database -UserName $AppUser -Password $AppPassword
Write-Host "[+] PGS Metatron database settings saved for the current Windows user."
