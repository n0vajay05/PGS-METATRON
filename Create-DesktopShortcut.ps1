$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Launcher = Join-Path $ProjectRoot "Run-PGS-Metatron.vbs"
$WScript = Join-Path $env:SystemRoot "System32\wscript.exe"
$Icon = Join-Path $ProjectRoot "assets\pgs_metatron_icon.ico"

if (-not (Test-Path $Launcher)) {
    throw "PGS Metatron launcher was not found: $Launcher"
}
if (-not (Test-Path $WScript)) {
    throw "Windows Script Host was not found: $WScript"
}

$Desktop = [Environment]::GetFolderPath("Desktop")
$ShortcutPath = Join-Path $Desktop "PGS-Metatron.lnk"

$Shell = New-Object -ComObject WScript.Shell
$Shortcut = $Shell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $WScript
$Shortcut.Arguments = "`"$Launcher`""
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.WindowStyle = 7
$Shortcut.Description = "Start PGS Metatron"
if (Test-Path $Icon) {
    $Shortcut.IconLocation = "$Icon,0"
}
$Shortcut.Save()

Write-Host "[+] Created desktop shortcut: $ShortcutPath"
