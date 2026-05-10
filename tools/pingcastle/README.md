# PingCastle Prepared Internal Tool

This folder stages PingCastle for the GUI `Tools (Internal)` list.

Source repository:

```text
https://github.com/netwrix/pingcastle
```

Prepared source checkout used during staging:

```text
.tools\pingcastle-source
```

Build the standalone Windows executable:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\pingcastle\Build-PingCastle.ps1
```

The expected compiled output is:

```text
tools\pingcastle\bin\PingCastle.exe
```

This staged source currently pins updated package versions for the local PGS Metatron build:

```text
Microsoft.Kiota.* 1.22.2
Azure.Core 1.50.0
Std.UriTemplate 2.0.8
System.ClientModel 1.8.0
System.Memory.Data 8.0.1
Microsoft.Extensions.Logging.Abstractions 8.0.3
System.Security.Cryptography.Xml 8.0.3
```

Run the staged tool manually after build:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\pingcastle\Run-PingCastle.ps1 -Target "domain.local"
```

Run with explicit PingCastle command-line arguments:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\pingcastle\Run-PingCastle.ps1 -Arguments "--healthcheck --server domain.local"
```

The runner writes reports to:

```text
Documents\PGS-Metatron\reports\pingcastle\<timestamp>
```

Build note: PingCastle depends on NuGet packages from `https://api.nuget.org/v3/index.json`. If the build environment cannot reach NuGet, restore will fail before `PingCastle.exe` is produced.
