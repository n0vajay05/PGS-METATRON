#define AppName "PGS Metatron"
#define AppVersion "1.0.0"
#define AppPublisher "ProGuide Systems"
#define AppExeName "PGS-Metatron.exe"

[Setup]
AppId={{A08D7F0A-FE32-4CC5-B90D-928C821F8E61}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\PGS-Metatron
DefaultGroupName=PGS Metatron
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=PGS-Metatron-Setup
SetupIconFile=..\assets\pgs_metatron_icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce

[Files]
Source: "dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\schema.sql"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Install-MetatronDatabase.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Setup-MetatronDatabase.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Check-MetatronDatabase.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Prompt-InstallNmap.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Uninstall-PGSMetatron.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\PGS Metatron"; Filename: "{app}\{#AppExeName}"
Name: "{commondesktop}\PGS-Metatron"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Install-MetatronDatabase.ps1"" -AssumeYes"; StatusMsg: "Configuring the local PGS Metatron database..."; Flags: runhidden waituntilterminated
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Prompt-InstallNmap.ps1"""; StatusMsg: "Checking for Nmap..."; Flags: waituntilterminated skipifsilent
Filename: "{app}\{#AppExeName}"; Description: "Launch PGS Metatron"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Uninstall-PGSMetatron.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "PGSMetatronUserCleanup"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
