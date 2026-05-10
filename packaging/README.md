# PGS Metatron Release Packaging

Run this from PowerShell on the build machine:

```powershell
.\packaging\Build-PGSMetatronRelease.ps1
```

Outputs:

- `packaging\dist\PGS-Metatron.exe`
- `packaging\output\PGS-Metatron-Setup.exe`

The installer installs to:

```text
C:\Program Files\PGS-Metatron
```

Recommended signing order:

```powershell
.\packaging\Build-PGSMetatronRelease.ps1 -SkipInstaller
.\packaging\Sign-PGSMetatronFile.ps1 -FilePath .\packaging\dist\PGS-Metatron.exe -CertificateThumbprint "<thumbprint>"
.\packaging\Build-PGSMetatronRelease.ps1 -InstallerOnly -NoDependencyInstall
.\packaging\Sign-PGSMetatronFile.ps1 -FilePath .\packaging\output\PGS-Metatron-Setup.exe -CertificateThumbprint "<thumbprint>"
```

Final signed artifacts:

- `packaging\dist\PGS-Metatron.exe`
- `packaging\output\PGS-Metatron-Setup.exe`

The EXE bundles the Python app, app images, SMB Scanner script, and Subfinder. The installer keeps only database setup support files external because they must remain callable by Windows PowerShell during installation.
