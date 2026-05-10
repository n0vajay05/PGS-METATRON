param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [string]$OutputPath = ".",

    [int]$TimeoutMs = 750,

    [int]$MaxHosts = 4096
)

$ErrorActionPreference = "Continue"

function ConvertTo-IPv4UInt {
    param([string]$IpAddress)
    $bytes = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    return [uint32](
        ([uint64]$bytes[0] -shl 24) -bor
        ([uint64]$bytes[1] -shl 16) -bor
        ([uint64]$bytes[2] -shl 8) -bor
        [uint64]$bytes[3]
    )
}

function ConvertFrom-IPv4UInt {
    param([uint32]$Value)
    $bytes = [byte[]]@(
        [byte](($Value -shr 24) -band 0xff),
        [byte](($Value -shr 16) -band 0xff),
        [byte](($Value -shr 8) -band 0xff),
        [byte]($Value -band 0xff)
    )
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-TargetIPs {
    param([string]$InputTarget)

    $targetText = $InputTarget.Trim()
    if (-not $targetText) {
        return @()
    }

    if ($targetText -match "/") {
        $parts = $targetText.Split("/", 2)
        $baseIp = $parts[0].Trim()
        $prefix = [int]$parts[1].Trim()
        if ($prefix -lt 0 -or $prefix -gt 32) {
            throw "Invalid CIDR prefix: $prefix"
        }

        $base = ConvertTo-IPv4UInt $baseIp
        $hostCount = [uint64][Math]::Pow(2, 32 - $prefix)
        if ($hostCount -gt $MaxHosts) {
            throw "CIDR range contains $hostCount hosts. Refusing to scan more than $MaxHosts hosts."
        }

        if ($prefix -eq 0) {
            $mask = [uint32]0
        } elseif ($prefix -eq 32) {
            $mask = [uint32]4294967295
        } else {
            $hostMask = ([uint64]1 -shl (32 - $prefix)) - 1
            $mask = [uint32]([uint64]4294967295 - $hostMask)
        }
        $network = [uint32]($base -band $mask)
        $start = [uint64]$network
        $end = $start + $hostCount - 1

        if ($hostCount -gt 2) {
            $start += 1
            $end -= 1
        }

        $items = New-Object System.Collections.Generic.List[string]
        for ($value = $start; $value -le $end; $value++) {
            $items.Add((ConvertFrom-IPv4UInt ([uint32]$value)))
        }
        return $items.ToArray()
    }

    return @($targetText)
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$Timeout
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Parse-NetViewShares {
    param([string[]]$Lines)

    $shares = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        if ($trimmed -match "^(Share name|---|The command completed|System error|There are no entries)") { continue }
        if ($trimmed -match "^(.+?)\s{2,}") {
            $name = $matches[1].Trim()
        } else {
            $name = ($trimmed -split "\s+")[0]
        }
        if ($name -and $name -notmatch "^(\\\\|Remote|Comment)$") {
            $shares.Add($name)
        }
    }
    return $shares.ToArray()
}

function Enumerate-SmbGuest {
    param([string]$HostName)

    $result = [ordered]@{
        Host = $HostName
        Port445 = "Open"
        GuestSession = "Not established"
        Shares = @()
        ShareListings = @()
        Errors = @()
    }

    $null = cmd.exe /c "net use \\$HostName\IPC$ /delete /y" 2>$null
    $netUseOutput = cmd.exe /c "net use \\$HostName\IPC$ `"`" /user:Guest /persistent:no" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $result.GuestSession = "Established as Guest"
    } else {
        $result.Errors += "Guest session failed: $($netUseOutput -join ' ')"
    }

    $netViewOutput = cmd.exe /c "net view \\$HostName" 2>&1
    if ($LASTEXITCODE -ne 0) {
        $result.Errors += "Share enumeration failed: $($netViewOutput -join ' ')"
    } else {
        $shares = Parse-NetViewShares $netViewOutput
        $result.Shares = @($shares)
        foreach ($share in $shares) {
            $unc = "\\$HostName\$share"
            try {
                $items = Get-ChildItem -LiteralPath $unc -Force -ErrorAction Stop |
                    Select-Object -First 50 -ExpandProperty Name
                $result.ShareListings += [pscustomobject]@{
                    Share = $share
                    Path = $unc
                    Items = @($items)
                }
            } catch {
                $result.ShareListings += [pscustomobject]@{
                    Share = $share
                    Path = $unc
                    Items = @()
                    Error = $_.Exception.Message
                }
            }
        }
    }

    $null = cmd.exe /c "net use \\$HostName\IPC$ /delete /y" 2>$null
    return [pscustomobject]$result
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
$targets = Get-TargetIPs $Target
$summaryPath = Join-Path $OutputPath "smb-scanner-results.json"
$textPath = Join-Path $OutputPath "smb-scanner-results.txt"

$results = New-Object System.Collections.Generic.List[object]

"SMB Scanner" | Tee-Object -FilePath $textPath
"Target: $Target" | Tee-Object -FilePath $textPath -Append
"Expanded hosts: $($targets.Count)" | Tee-Object -FilePath $textPath -Append
"Output: $OutputPath" | Tee-Object -FilePath $textPath -Append
"" | Tee-Object -FilePath $textPath -Append

foreach ($hostName in $targets) {
    Write-Output "[*] Testing $hostName TCP/445"
    if (-not (Test-TcpPort -HostName $hostName -Port 445 -Timeout $TimeoutMs)) {
        $line = "$hostName`t445 closed or filtered"
        $line | Tee-Object -FilePath $textPath -Append
        $results.Add([pscustomobject]@{ Host = $hostName; Port445 = "ClosedOrFiltered" })
        continue
    }

    $line = "$hostName`t445 open"
    $line | Tee-Object -FilePath $textPath -Append
    $guestResult = Enumerate-SmbGuest -HostName $hostName
    $results.Add($guestResult)

    "  Guest: $($guestResult.GuestSession)" | Tee-Object -FilePath $textPath -Append
    if ($guestResult.Shares.Count -gt 0) {
        "  Shares: $($guestResult.Shares -join ', ')" | Tee-Object -FilePath $textPath -Append
    } else {
        "  Shares: none enumerated" | Tee-Object -FilePath $textPath -Append
    }
    foreach ($listing in $guestResult.ShareListings) {
        "  [$($listing.Share)] $($listing.Path)" | Tee-Object -FilePath $textPath -Append
        if ($listing.Error) {
            "    Error: $($listing.Error)" | Tee-Object -FilePath $textPath -Append
        } elseif ($listing.Items.Count -gt 0) {
            foreach ($item in $listing.Items) {
                "    $item" | Tee-Object -FilePath $textPath -Append
            }
        } else {
            "    No items listed" | Tee-Object -FilePath $textPath -Append
        }
    }
    foreach ($errorText in $guestResult.Errors) {
        "  Error: $errorText" | Tee-Object -FilePath $textPath -Append
    }
    "" | Tee-Object -FilePath $textPath -Append
}

$results | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding UTF8

Write-Output ""
Write-Output "[SMB SCANNER SUMMARY]"
Get-Content -Path $textPath
Write-Output ""
Write-Output "[SMB SCANNER JSON]"
Write-Output $summaryPath
