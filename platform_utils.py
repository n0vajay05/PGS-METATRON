import os
import shlex
import shutil
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath


IS_WINDOWS = os.name == "nt"


def app_root_path() -> Path:
    """Return the app resource root in source runs and PyInstaller builds."""
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root)
    return Path(__file__).resolve().parent


def resource_path(*parts: str) -> Path:
    return app_root_path().joinpath(*parts)


def local_app_data_dir() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "PGS-Metatron"
    return Path.home() / ".pgs-metatron"


def clear_screen() -> None:
    os.system("cls" if IS_WINDOWS else "clear")


def default_reports_dir() -> str:
    if IS_WINDOWS:
        return str(Path.home() / "Documents" / "PGS-Metatron" / "reports")
    return str(Path.home() / "PGS-Metatron" / "reports")


def executable_name(command: str) -> str:
    token = command.strip().strip('"').strip("'")
    path_parser = PureWindowsPath if ("\\" in token or ":" in token) else PurePosixPath
    name = path_parser(token).name.lower()
    return name[:-4] if name.endswith(".exe") else name


def split_command(command: str) -> list[str]:
    if IS_WINDOWS:
        try:
            import ctypes

            argc = ctypes.c_int()
            argv = ctypes.windll.shell32.CommandLineToArgvW(command, ctypes.byref(argc))
            if argv:
                args = [argv[i] for i in range(argc.value)]
                ctypes.windll.kernel32.LocalFree(argv)
                return args
        except Exception:
            pass

    return [part.strip('"').strip("'") for part in shlex.split(command, posix=not IS_WINDOWS)]


def powershell_command(script: str, *args: str) -> list[str]:
    executable = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
    return [
        executable,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"& {{ {script} }}",
        *args,
    ]


def install_hint(tool: str) -> str:
    tool = executable_name(tool)
    if not IS_WINDOWS:
        return f"sudo apt install {tool}"

    hints = {
        "nmap": "winget install Insecure.Nmap",
        "whois": "winget install Microsoft.Sysinternals",
        "whatweb": "gem install whatweb",
        "curl": "curl.exe is included with modern Windows; otherwise install it with winget install cURL.cURL",
        "dig": "PowerShell Resolve-DnsName is used automatically on Windows",
        "subfinder": "PGS Metatron will try to install Subfinder with Go into .tools\\subfinder\\bin on first use",
    }
    return hints.get(tool, f"install {tool} and add it to PATH")


def database_service_hint() -> str:
    if IS_WINDOWS:
        return "Use Tools > Database Settings to verify the address and credentials. For a local database, start MariaDB from Services or run in PowerShell: Start-Service MariaDB"
    return "Make sure MariaDB is running: sudo systemctl start mariadb"
