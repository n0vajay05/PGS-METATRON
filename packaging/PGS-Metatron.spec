# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata


project_root = Path(SPECPATH).parent

DPI_AWARE_MANIFEST = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="PGS-Metatron" type="win32"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
"""

datas = [
    (str(project_root / "assets"), "assets"),
    (str(project_root / "tools"), "tools"),
    (str(project_root / "subfinder.exe"), "."),
]

for package_name in ("tkinterweb", "tkinterweb_tkhtml", "playwright", "sslyze"):
    datas += collect_data_files(package_name)
	
datas += collect_data_files("mysql.connector.plugins")
datas += collect_data_files("mysql.connector.aio.plugins")

metadata = []
for package_name in ("tkinterweb", "tkinterweb_tkhtml", "playwright", "sslyze", "mysql-connector-python"):
    try:
        metadata += copy_metadata(package_name)
    except Exception:
        pass

hiddenimports = []
for package_name in (
    "bs4",
    "mysql",
    "mysql.connector",
    "PIL",
    "playwright",
    "sslyze",
    "tkinterweb",
    "tkinterweb_tkhtml",
):
    hiddenimports += collect_submodules(package_name)
	
hiddenimports += collect_submodules("mysql.connector.plugins")
hiddenimports += collect_submodules("mysql.connector.aio.plugins")

a = Analysis(
    [str(project_root / "metatron_gui.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas + metadata,
    hiddenimports=hiddenimports,
    hookspath=[str(project_root / "packaging" / "hooks")],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="PGS-Metatron",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(project_root / "assets" / "pgs_metatron_icon.ico"),
    manifest=DPI_AWARE_MANIFEST,
)
