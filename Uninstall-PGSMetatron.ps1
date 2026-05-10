$ErrorActionPreference = "SilentlyContinue"

foreach ($target in @(
    "PGS-Metatron:DatabasePassword",
    "PGS-Metatron:DatabaseRootPassword",
    "PGS-Metatron:OpenAIApiKey",
    "PGS-Metatron:ClaudeApiKey"
)) {
    & cmdkey.exe "/delete:$target" *> $null
}

$usersRoot = Join-Path $env:SystemDrive "Users"
if (Test-Path -LiteralPath $usersRoot) {
    Get-ChildItem -LiteralPath $usersRoot -Directory -Force | ForEach-Object {
        $configPath = Join-Path $_.FullName "AppData\Local\PGS-Metatron"
        if (Test-Path -LiteralPath $configPath) {
            Remove-Item -LiteralPath $configPath -Recurse -Force
        }
    }
}
