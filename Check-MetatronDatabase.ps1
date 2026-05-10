$ErrorActionPreference = "Continue"

Write-Host "[*] Checking MariaDB/MySQL service..."
$services = Get-Service | Where-Object {
    $_.Name -match "maria|mysql" -or $_.DisplayName -match "maria|mysql"
}

if (-not $services) {
    Write-Warning "No MariaDB/MySQL Windows service was found."
    Write-Host "Run .\Install-MetatronDatabase.ps1 to install and configure MariaDB automatically."
    Write-Host "Official Windows MSI guide: https://mariadb.com/kb/en/installing-mariadb-msi-packages-on-windows/"
    exit 1
}

$services | Format-Table Name, DisplayName, Status, StartType -AutoSize

$running = $services | Where-Object { $_.Status -eq "Running" } | Select-Object -First 1
if (-not $running) {
    $service = $services | Select-Object -First 1
    Write-Host "[*] Attempting to start service: $($service.Name)"
    try {
        Start-Service -Name $service.Name -ErrorAction Stop
        Start-Sleep -Seconds 2
    } catch {
        Write-Warning "Could not start $($service.Name). Open PowerShell as Administrator and run: Start-Service $($service.Name)"
    }
}

Write-Host "[*] Checking TCP port 3306..."
$listening = Test-NetConnection -ComputerName 127.0.0.1 -Port 3306 -InformationLevel Quiet
if (-not $listening) {
    Write-Warning "Nothing is listening on 127.0.0.1:3306."
    Write-Host "In the MariaDB installer/configuration, make sure networking is enabled and the port is 3306."
    exit 1
}

Write-Host "[+] MariaDB/MySQL is listening on 127.0.0.1:3306."
Write-Host "If Metatron still cannot connect, run .\Setup-MetatronDatabase.ps1 to create the metatron database and user."
