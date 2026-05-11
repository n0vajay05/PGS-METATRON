<img width="1536" height="279" alt="pgs-metatron" src="https://github.com/user-attachments/assets/45763e0d-2204-4e6c-844f-407bc3d8cc47" />

# PGS Metatron

PGS Metatron is a Windows GUI security assessment assistant for authorized testing. It runs external and internal reconnaissance tools, stores scan history in MariaDB, and can use a selected AI model provider for full-scan analysis.

The repository is prepared so another Windows user can inspect the source and build the same style of EXE/installer from the `packaging` folder.

## Important Use Notice

Use this software should be used **ONLY** on systems you own or have explicit permission to test.

## What Is Included

- Python GUI source and support modules.
- Database setup and password rotation scripts.
- Windows packaging files for PyInstaller and Inno Setup.
- Assets used by the GUI and reports.
- SMB Scanner PowerShell tool.
- PingCastle wrapper and build script.
- Bundled `subfinder.exe` used by the Subfinder tool.

## What Is Not Included

Generated or local-only files are intentionally left out:

- Local config such as `metatron_config.json`.
- Saved GUI layout state.
- Virtual environments and dependency caches.
- PyInstaller `build`, `dist`, and installer output folders.
- Code signing certificates or passwords.
- Compiled PingCastle binary and debug symbols.

PingCastle is large enough that its compiled EXE should be built locally instead of committed to GitHub.

## Windows Build Prerequisites

Install these on the build machine:

- Windows 10/11 x64.
- Python 3.11 or newer.
- Inno Setup 6, for the single-file installer.
- Git, if you want the PingCastle build script to clone PingCastle source automatically.
- .NET SDK 8.0 or newer, if you want to build/include PingCastle.

The installer can configure MariaDB during install. Nmap is checked during install and the user can be prompted to install it through Windows Package Manager.

## Build PingCastle Optional Tool

Run this before the release build if you want PingCastle included in the packaged EXE:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\pingcastle\Build-PingCastle.ps1
```

Expected generated file:

```text
tools\pingcastle\bin\PingCastle.exe
```

That generated `bin` folder is ignored by Git.

## Build The EXE And Installer

From the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\packaging\Build-PGSMetatronRelease.ps1
```

Outputs:

```text
packaging\dist\PGS-Metatron.exe
packaging\output\PGS-Metatron-Setup.exe
```

The installer installs to:

```text
C:\Program Files\PGS-Metatron
```

## Signing Flow

Build and sign the EXE first, then build and sign the installer:

```powershell
.\packaging\Build-PGSMetatronRelease.ps1 -SkipInstaller
.\packaging\Sign-PGSMetatronFile.ps1 -FilePath .\packaging\dist\PGS-Metatron.exe -CertificateThumbprint "<thumbprint>"
.\packaging\Build-PGSMetatronRelease.ps1 -InstallerOnly -NoDependencyInstall
.\packaging\Sign-PGSMetatronFile.ps1 -FilePath .\packaging\output\PGS-Metatron-Setup.exe -CertificateThumbprint "<thumbprint>"
```

Do not commit signing certificates, PFX files, or signing passwords.

## Running From Source

For development, create a virtual environment and install dependencies:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Then launch:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Metatron.ps1
```

Local database and AI provider settings are stored outside the repo in the user profile and Windows Credential Manager.

## Secrets And Local Settings

The project is set up so generated secrets do not need to live in source control:

- Database passwords are generated at install/setup time.
- Database passwords and cloud model API keys are stored in Windows Credential Manager.
- Non-secret connection settings are stored under `%LOCALAPPDATA%\PGS-Metatron`.
- Local config files are ignored by Git.
