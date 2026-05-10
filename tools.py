#!/usr/bin/env python3
"""
METATRON - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Tools used: nmap, whois, whatweb, curl, DNS lookup, SSLyze, HAR cookie consent, Subfinder, built-in web checks
Windows support: uses native PowerShell Resolve-DnsName when dig is unavailable.
"""

import ipaddress
import contextlib
import io
import json
import os
import re
import runpy
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning
from console_input import MenuBack, prompt

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
from platform_utils import (
    IS_WINDOWS,
    executable_name,
    default_reports_dir,
    install_hint,
    local_app_data_dir,
    powershell_command,
    resource_path,
    split_command,
)


WHOIS_IANA_SERVER = "whois.iana.org"
WHOIS_DEFAULT_SERVER = "whois.verisign-grs.com"
ABORT_SCAN = "__METATRON_ABORT_SCAN__"
SUBFINDER_INSTALL_DIR = local_app_data_dir() / "tools" / "subfinder" / "bin"
SMB_SCANNER_SCRIPT = resource_path("tools", "smb_scanner.ps1")
PINGCASTLE_RUNNER_SCRIPT = resource_path("tools", "pingcastle", "Run-PingCastle.ps1")


def find_nmap_executable() -> str:
    found = shutil.which("nmap")
    if found:
        return found
    if IS_WINDOWS:
        candidates = [
            Path(os.environ.get("ProgramFiles", "")) / "Nmap" / "nmap.exe",
            Path(os.environ.get("ProgramFiles(x86)", "")) / "Nmap" / "nmap.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
    return "nmap"


def query_whois_server(server: str, query: str, timeout: int = 15) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def extract_refer_whois(response: str) -> str:
    for pattern in (r"(?im)^refer:\s*(\S+)", r"(?im)^whois:\s*(\S+)", r"(?im)^Registrar WHOIS Server:\s*(\S+)"):
        match = re.search(pattern, response)
        if match:
            return match.group(1).strip()
    return ""


def run_python_whois(target: str) -> str:
    clean_target = target.strip().lower()
    clean_target = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0].strip()
    if not clean_target:
        return "[!] WHOIS lookup failed: empty target."

    try:
        ipaddress.ip_address(clean_target)
        iana_query = clean_target
    except ValueError:
        parts = clean_target.rstrip(".").split(".")
        iana_query = parts[-1] if len(parts) > 1 else clean_target

    try:
        iana_data = query_whois_server(WHOIS_IANA_SERVER, iana_query)
        referral = extract_refer_whois(iana_data)
        if not referral and "." in clean_target:
            referral = WHOIS_DEFAULT_SERVER

        if referral:
            referred_data = query_whois_server(referral, clean_target)
            return (
                f"[IANA WHOIS]\n{iana_data}\n\n"
                f"[REFERRED WHOIS: {referral}]\n{referred_data}"
            )

        return f"[IANA WHOIS]\n{iana_data}"
    except Exception as e:
        return f"[!] Built-in WHOIS lookup failed: {e}"


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120, cwd: str | None = None, env: dict | None = None) -> str:
    """
    Execute a shell command, return combined stdout + stderr as string.
    Never crashes the program — always returns something.
    """
    startupinfo = None
    creationflags = 0
    if IS_WINDOWS:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        output = result.stdout.strip()
        errors = result.stderr.strip()

        if output and errors:
            return output + "\n[STDERR]\n" + errors
        elif output:
            return output
        elif errors:
            return errors
        else:
            return "[!] Tool returned no output."

    except subprocess.TimeoutExpired as e:
        output = e.stdout or ""
        errors = e.stderr or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        if isinstance(errors, bytes):
            errors = errors.decode("utf-8", errors="replace")

        partial = "\n".join(part.strip() for part in (output, errors) if part and part.strip())
        message = f"[!] Timed out after {timeout}s: {' '.join(command)}"
        if partial:
            return f"{message}\n\n[PARTIAL OUTPUT BEFORE TIMEOUT]\n{partial}"
        return message
    except KeyboardInterrupt:
        print("\n[!] Scan aborted. Returning to tool selection.")
        return ABORT_SCAN
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]} - install it with: {install_hint(command[0])}"
    except Exception as e:
        return f"[!] Unexpected error running {command[0]}: {e}"


def is_scan_abort(output: object) -> bool:
    return str(output or "").strip() == ABORT_SCAN


def run_scan_step(func, target: str) -> str:
    try:
        return func(target)
    except KeyboardInterrupt:
        print("\n[!] Scan aborted. Returning to tool selection.")
        return ABORT_SCAN


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    """
    nmap -sV -sC -T4 --open
    -sV  : detect service versions
    -sC  : run default scripts (basic vuln checks)
    -T4  : aggressive timing (faster)
    --open : only show open ports
    """
    nmap = find_nmap_executable()
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool([nmap, "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_nmap_custom(target: str) -> str:
    """
    Nmap custom scan - passes the user's target text directly to Nmap with no preset flags.
    """
    target_text = str(target or "").strip()
    if not target_text:
        return "[!] Nmap custom scan failed: enter the Nmap target and any flags to run."

    nmap = find_nmap_executable()
    try:
        args = split_command(target_text)
    except Exception:
        args = target_text.split()

    if args and executable_name(args[0]) == "nmap":
        args = args[1:]
    if not args:
        return "[!] Nmap custom scan failed: enter the Nmap target and any flags to run."

    display = " ".join(args)
    print(f"  [*] nmap {display}")
    return run_tool([nmap, *args], timeout=1800)


def run_whois(target: str) -> str:
    """
    whois — domain registration, registrar, IP ownership info
    """
    if IS_WINDOWS:
        print(f"  [*] built-in whois {target}")
        return run_python_whois(target)

    print(f"  [*] whois {target}")
    output = run_tool(["whois", target], timeout=30)
    if output.startswith("[!] Tool not found"):
        return run_python_whois(target)
    return output


def run_whatweb(target: str) -> str:
    """
    whatweb -a 3 — fingerprint web technologies, CMS, frameworks, headers
    -a 3 : aggression level 3 (active but not destructive)
    """
    if IS_WINDOWS:
        print(f"  [*] built-in web fingerprint {target}")
        return run_web_fingerprint(target)

    print(f"  [*] whatweb -a 3 {target}")
    output = run_tool(["whatweb", "-a", "3", target], timeout=60)
    if output.startswith("[!] Tool not found"):
        return run_web_fingerprint(target)
    return output


def target_urls(target: str) -> list[str]:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return [target]
    clean = target.strip().strip("/")
    return [f"http://{clean}", f"https://{clean}"]


def detect_web_technologies(headers: dict, html: str) -> list[str]:
    technologies = []
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    combined = f"{header_text}\n{html[:20000]}".lower()

    checks = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Drupal": ["drupal-settings-json", "x-generator: drupal", "content=\"drupal"],
        "Joomla": ["content=\"joomla", "/media/system/js/", "joomla!"],
        "React": ["reactroot", "__react", "react-dom"],
        "Next.js": ["__next_data__", "/_next/static/"],
        "Vue.js": ["__vue__", "vue.js", "vue.min.js"],
        "Angular": ["ng-version", "angular.js", "angular.min.js"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.css", "bootstrap.min.js"],
        "PHP": ["x-powered-by: php", "phpsessid"],
        "ASP.NET": ["x-aspnet-version", "asp.net", "aspnet_sessionid"],
        "Cloudflare": ["server: cloudflare", "cf-ray"],
        "nginx": ["server: nginx"],
        "Apache": ["server: apache"],
        "IIS": ["server: microsoft-iis"],
    }

    for name, needles in checks.items():
        if any(needle in combined for needle in needles):
            technologies.append(name)
    return sorted(set(technologies))


def run_web_fingerprint(target: str) -> str:
    outputs = []
    for url in target_urls(target):
        try:
            resp = requests.get(
                url,
                timeout=15,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Metatron/1.0"},
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else ""
            generator = ""
            gen_tag = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
            if gen_tag:
                generator = gen_tag.get("content", "").strip()

            tech = detect_web_technologies(dict(resp.headers), resp.text)
            security_headers = {
                name: resp.headers.get(name, "MISSING")
                for name in (
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                    "Permissions-Policy",
                )
            }

            header_lines = "\n".join(f"  {k}: {v}" for k, v in resp.headers.items())
            security_lines = "\n".join(f"  {k}: {v}" for k, v in security_headers.items())
            outputs.append(
                f"[WEB FINGERPRINT: {url}]\n"
                f"Final URL: {resp.url}\n"
                f"Status: {resp.status_code}\n"
                f"Title: {title or '-'}\n"
                f"Generator: {generator or '-'}\n"
                f"Detected Technologies: {', '.join(tech) if tech else 'None detected'}\n\n"
                f"[Response Headers]\n{header_lines}\n\n"
                f"[Security Headers]\n{security_lines}"
            )
        except requests.exceptions.SSLError as e:
            outputs.append(f"[WEB FINGERPRINT: {url}]\n[!] TLS error: {e}")
        except requests.exceptions.ConnectionError as e:
            outputs.append(f"[WEB FINGERPRINT: {url}]\n[!] Connection failed: {e}")
        except requests.exceptions.Timeout:
            outputs.append(f"[WEB FINGERPRINT: {url}]\n[!] Timed out.")
        except Exception as e:
            outputs.append(f"[WEB FINGERPRINT: {url}]\n[!] Fingerprint failed: {e}")

    return "\n\n".join(outputs)


def run_curl_headers(target: str) -> str:
    """
    curl -sI — fetch HTTP headers only
    Reveals: server software, X-Powered-By, cookies, security headers (or lack of them)
    """
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",          # follow redirects
        f"http://{target}"
    ], timeout=20)

    # also try https
    https_output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",
        "-k",                  # ignore cert errors
        f"https://{target}"
    ], timeout=20)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """
    dig — DNS records: A, MX, NS, TXT
    Useful for subdomains, mail servers, SPF/DKIM info
    """
    if IS_WINDOWS:
        print(f"  [*] Resolve-DnsName {target}")
        return run_windows_dns_lookup(target)
    else:
        print(f"  [*] dig {target} ANY")
        a_record  = run_tool(["dig", "+short", "A",   target], timeout=15)
        mx_record = run_tool(["dig", "+short", "MX",  target], timeout=15)
        ns_record = run_tool(["dig", "+short", "NS",  target], timeout=15)
        txt_record= run_tool(["dig", "+short", "TXT", target], timeout=15)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_windows_dns_lookup(target: str, record_types: list[str] | None = None) -> str:
    record_types = record_types or ["A", "MX", "NS", "TXT"]
    records = {record_type: run_powershell_dns(target, record_type) for record_type in record_types}
    return "\n\n".join(f"[{record_type} Records]\n{output}" for record_type, output in records.items())


def run_powershell_dns(target: str, record_type: str) -> str:
    script = r"""
param($Name, $RecordType)
try {
    Resolve-DnsName -Name $Name -Type $RecordType -ErrorAction Stop |
        Select-Object Name, Type, IPAddress, NameHost, NameExchange, Preference, Strings |
        Format-Table -AutoSize |
        Out-String -Width 4096
} catch {
    "[!] DNS lookup failed: $($_.Exception.Message)"
}
"""
    return run_tool(powershell_command(script, target, record_type), timeout=20)


def normalize_tls_target(target: str) -> str:
    parsed = urlparse(target.strip())
    if parsed.scheme in {"http", "https"}:
        host = parsed.hostname or target
        port = parsed.port or 443
        return f"{host}:{port}"

    clean = target.strip().strip("/")
    if re.match(r"^\[[0-9a-fA-F:]+\](?::\d+)?$", clean):
        return clean if ":" in clean.rsplit("]", 1)[-1] else f"{clean}:443"
    if ":" in clean and clean.rsplit(":", 1)[-1].isdigit():
        return clean
    return f"{clean}:443"


def run_sslyze(target: str) -> str:
    """
    SSLyze — analyze SSL/TLS status, certificate, protocols, ciphers, and known TLS issues.
    """
    tls_target = normalize_tls_target(target)
    scan_args = [
        "--certinfo",
        "--sslv2",
        "--sslv3",
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--heartbleed",
        "--robot",
        "--compression",
        "--openssl_ccs",
        "--reneg",
        "--fallback",
        "--http_headers",
        "--elliptic_curves",
        "--ems",
        "--mozilla_config=intermediate",
    ]
    print(f"  [*] sslyze {' '.join(scan_args)} {tls_target}")
    if getattr(sys, "frozen", False):
        return run_python_module_in_process("sslyze", [*scan_args, tls_target])
    return run_tool([sys.executable, "-m", "sslyze", *scan_args, tls_target], timeout=600)


def run_python_module_in_process(module_name: str, args: list[str]) -> str:
    old_argv = sys.argv[:]
    stdout = io.StringIO()
    stderr = io.StringIO()
    exit_code = 0
    try:
        sys.argv = [module_name, *args]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                runpy.run_module(module_name, run_name="__main__", alter_sys=True)
            except SystemExit as e:
                exit_code = int(e.code or 0) if isinstance(e.code, int) else 1
    except Exception as e:
        stderr.write(f"{type(e).__name__}: {e}")
        exit_code = 1
    finally:
        sys.argv = old_argv

    output = stdout.getvalue().strip()
    errors = stderr.getvalue().strip()
    if output and errors:
        return output + "\n[STDERR]\n" + errors
    if output:
        return output
    if errors:
        return errors
    if exit_code:
        return f"[!] {module_name} exited with code {exit_code}."
    return "[!] Tool returned no output."


TRACKER_HOST_KEYWORDS = (
    "doubleclick",
    "googletagmanager",
    "google-analytics",
    "analytics.google",
    "facebook",
    "connect.facebook",
    "hotjar",
    "segment",
    "mixpanel",
    "amplitude",
    "adservice",
    "adsystem",
    "adnxs",
    "taboola",
    "outbrain",
    "quantserve",
    "scorecardresearch",
    "newrelic",
    "fullstory",
    "clarity.ms",
)


CONSENT_KEYWORDS = (
    "cookie",
    "cookies",
    "consent",
    "privacy preferences",
    "accept all",
    "reject all",
    "decline",
    "manage preferences",
    "do not sell",
    "gdpr",
    "ccpa",
)


def safe_artifact_name(value: str) -> str:
    text = re.sub(r"^https?://", "", str(value or "target"), flags=re.I)
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text)
    text = re.sub(r"\s+", "_", text).strip("._ ")
    return text or "target"


def normalize_http_target(target: str) -> str:
    parsed = urlparse(target.strip())
    if parsed.scheme in {"http", "https"}:
        return target.strip()
    return f"https://{target.strip().strip('/')}"


def simple_registered_domain(hostname: str) -> str:
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def is_external_host(request_host: str, page_host: str) -> bool:
    req = (request_host or "").lower()
    page = (page_host or "").lower()
    if not req or not page:
        return False
    if req == page or req.endswith("." + page):
        return False
    return simple_registered_domain(req) != simple_registered_domain(page)


def is_tracker_host(hostname: str) -> bool:
    lower = (hostname or "").lower()
    return any(keyword in lower for keyword in TRACKER_HOST_KEYWORDS)


def detect_cookie_consent_text(text: str) -> tuple[bool, list[str]]:
    lower = (text or "").lower()
    matches = [keyword for keyword in CONSENT_KEYWORDS if keyword in lower]
    consent_detected = ("cookie" in matches or "cookies" in matches or "consent" in matches) and any(
        keyword in matches for keyword in ("accept all", "reject all", "decline", "manage preferences", "privacy preferences")
    )
    return consent_detected, matches


def load_har_entries(har_path: Path) -> list[dict]:
    try:
        with har_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("log", {}).get("entries", [])
    except Exception:
        return []


def evaluate_har_cookie_consent(target_url: str, final_url: str, har_path: Path, body_text: str) -> str:
    final_host = urlparse(final_url or target_url).hostname or urlparse(target_url).hostname or ""
    entries = load_har_entries(har_path)
    external_entries = []
    tracker_entries = []
    cookie_setting_entries = []

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        host = urlparse(url).hostname or ""
        if not host:
            continue
        if is_external_host(host, final_host):
            external_entries.append((url, host))
        if is_tracker_host(host):
            tracker_entries.append((url, host))

        headers = response.get("headers", []) or []
        if any(str(header.get("name", "")).lower() == "set-cookie" for header in headers):
            cookie_setting_entries.append((url, host))

    consent_detected, consent_matches = detect_cookie_consent_text(body_text)
    external_before_choice = external_entries
    trackers_before_choice = tracker_entries

    if consent_detected and trackers_before_choice:
        verdict = "FAIL"
        reason = "Cookie consent UI was detected, but tracker-like requests loaded before any accept/decline action was taken."
    elif consent_detected and external_before_choice:
        verdict = "WARN"
        reason = "Cookie consent UI was detected, and external resources loaded before any accept/decline action was taken."
    elif consent_detected:
        verdict = "PASS"
        reason = "Cookie consent UI was detected and no external resources were observed before a consent choice."
    else:
        verdict = "WARN"
        reason = "No obvious cookie consent UI was detected during the first-load capture."

    def sample_lines(rows: list[tuple[str, str]], limit: int = 15) -> str:
        if not rows:
            return "  None observed."
        lines = []
        seen = set()
        for url, host in rows:
            if url in seen:
                continue
            seen.add(url)
            lines.append(f"  - {host}: {url}")
            if len(lines) >= limit:
                break
        extra = len({url for url, _ in rows}) - len(lines)
        if extra > 0:
            lines.append(f"  ... plus {extra} more.")
        return "\n".join(lines)

    return (
        "[HAR COOKIE CONSENT EVALUATION]\n"
        f"Target URL: {target_url}\n"
        f"Final URL: {final_url or '-'}\n"
        f"HAR File: {har_path}\n"
        f"Total HAR Requests: {len(entries)}\n"
        f"Consent UI Detected: {'YES' if consent_detected else 'NO'}\n"
        f"Consent Keywords Observed: {', '.join(consent_matches) if consent_matches else '-'}\n"
        f"External Requests Before Consent Choice: {len(external_before_choice)}\n"
        f"Tracker-Like Requests Before Consent Choice: {len(trackers_before_choice)}\n"
        f"Responses Setting Cookies During Capture: {len(cookie_setting_entries)}\n"
        f"Verdict: {verdict}\n"
        f"Reason: {reason}\n\n"
        "[External Requests Before Consent Choice]\n"
        f"{sample_lines(external_before_choice)}\n\n"
        "[Tracker-Like Requests Before Consent Choice]\n"
        f"{sample_lines(trackers_before_choice)}\n\n"
        "[Responses Setting Cookies]\n"
        f"{sample_lines(cookie_setting_entries)}"
    )


def run_har_cookie_consent(target: str) -> str:
    """
    Record first-load HAR traffic and check whether external/tracker calls happen before cookie consent.
    """
    target_url = normalize_http_target(target)
    output_dir = Path(default_reports_dir()) / "har"
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    har_path = output_dir / f"{timestamp}_{safe_artifact_name(target)}.har"

    print(f"  [*] HAR cookie consent capture {target_url}")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return (
            "[!] HAR capture requires Playwright.\n"
            f"    Import failed: {e}\n"
            "    Install the Playwright Chromium browser or reinstall PGS Metatron with browser support enabled."
        )

    final_url = ""
    body_text = ""
    try:
        with sync_playwright() as p:
            browser = None
            launch_errors = []
            for kwargs in (
                {"channel": "msedge", "headless": True},
                {"channel": "chrome", "headless": True},
                {"headless": True},
            ):
                try:
                    browser = p.chromium.launch(**kwargs)
                    break
                except PlaywrightError as e:
                    launch_errors.append(str(e).splitlines()[0])

            if not browser:
                return (
                    "[!] HAR capture could not launch a Chromium browser.\n"
                    "    Install Microsoft Edge or run: python -m playwright install chromium\n"
                    f"    Last errors: {' | '.join(launch_errors[-3:])}"
                )

            context = browser.new_context(
                ignore_https_errors=True,
                record_har_path=str(har_path),
                record_har_content="omit",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Metatron-HAR/1.0",
            )
            page = context.new_page()
            page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
            final_url = page.url
            page.wait_for_timeout(5000)
            try:
                body_text = page.locator("body").inner_text(timeout=3000)
            except Exception:
                body_text = page.content()[:50000]
            context.close()
            browser.close()
    except Exception as e:
        return f"[!] HAR cookie consent capture failed: {e}"

    return evaluate_har_cookie_consent(target_url, final_url, har_path, body_text)


def run_builtin_web_checks(target: str) -> str:
    """
    Fast built-in web checks for common server exposure and header issues.
    """
    outputs = []
    interesting_paths = [
        "/robots.txt",
        "/sitemap.xml",
        "/server-status",
        "/server-info",
        "/.git/config",
        "/.env",
        "/backup.zip",
        "/backup.tar.gz",
        "/admin/",
        "/login/",
        "/phpinfo.php",
        "/test.php",
        "/wp-admin/",
        "/wp-login.php",
    ]

    print(f"  [*] built-in web checks {target}")
    for base_url in target_urls(target):
        try:
            base_resp = requests.get(
                base_url,
                timeout=15,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Metatron-WebChecks/1.0"},
            )
            final_base = base_resp.url.rstrip("/")
            headers = base_resp.headers
            findings = [
                f"Base URL: {base_url}",
                f"Final URL: {base_resp.url}",
                f"Status: {base_resp.status_code}",
                f"Server: {headers.get('Server', '-')}",
                f"X-Powered-By: {headers.get('X-Powered-By', '-')}",
            ]

            missing_security = [
                name
                for name in (
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                )
                if name not in headers
            ]
            if missing_security:
                findings.append("Missing security headers: " + ", ".join(missing_security))

            try:
                options_resp = requests.options(final_base, timeout=10, verify=False)
                allow = options_resp.headers.get("Allow") or options_resp.headers.get("Public")
                if allow:
                    findings.append(f"Allowed HTTP methods: {allow}")
                    risky = [method for method in ("PUT", "DELETE", "TRACE", "CONNECT") if method in allow.upper()]
                    if risky:
                        findings.append("Risky HTTP methods advertised: " + ", ".join(risky))
            except Exception as e:
                findings.append(f"HTTP OPTIONS check failed: {e}")

            for path in interesting_paths:
                url = final_base + path
                try:
                    resp = requests.get(url, timeout=8, allow_redirects=False, verify=False)
                    if resp.status_code in {200, 401, 403}:
                        size = len(resp.content or b"")
                        finding = f"{path}: HTTP {resp.status_code}, {size} bytes"
                        if path == "/.git/config" and b"[core]" in resp.content[:500]:
                            finding += " - possible exposed Git repository"
                        if path == "/.env" and b"=" in resp.content[:500]:
                            finding += " - possible exposed environment file"
                        findings.append(finding)
                except Exception:
                    continue

            outputs.append("[BUILT-IN WEB CHECKS]\n" + "\n".join(f"  {item}" for item in findings))
        except requests.exceptions.ConnectionError as e:
            outputs.append(f"[BUILT-IN WEB CHECKS: {base_url}]\n[!] Connection failed: {e}")
        except requests.exceptions.Timeout:
            outputs.append(f"[BUILT-IN WEB CHECKS: {base_url}]\n[!] Timed out.")
        except Exception as e:
            outputs.append(f"[BUILT-IN WEB CHECKS: {base_url}]\n[!] Scan failed: {e}")

    return "\n\n".join(outputs)


def normalize_domain_target(target: str) -> str:
    parsed = urlparse(str(target or "").strip())
    if parsed.scheme:
        host = parsed.hostname or ""
    else:
        host = str(target or "").strip().split("/")[0].split(":")[0]
    return host.strip().strip(".")


def find_subfinder() -> str:
    candidates = [
        shutil.which("subfinder"),
        str(resource_path("subfinder.exe")),
        str(resource_path("subfinder")),
        str(SUBFINDER_INSTALL_DIR / "subfinder.exe"),
        str(SUBFINDER_INSTALL_DIR / "subfinder"),
        str(Path.home() / "go" / "bin" / "subfinder.exe"),
        str(Path.home() / "go" / "bin" / "subfinder"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return ""


def install_subfinder() -> str:
    go = shutil.which("go")
    if not go:
        return (
            "[!] Subfinder is not installed and Go was not found.\n"
            "    Install Go for Windows, then re-run this scan.\n"
            "    Metatron will install Subfinder into .tools\\subfinder\\bin when Go is available."
        )

    SUBFINDER_INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GOBIN"] = str(SUBFINDER_INSTALL_DIR)
    return run_tool(
        [go, "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
        timeout=900,
        env=env,
    )


def run_subfinder(target: str) -> str:
    """
    Subfinder — passive subdomain enumeration.
    """
    domain = normalize_domain_target(target)
    if not domain:
        return "[!] Subfinder failed: no domain was provided."

    subfinder = find_subfinder()
    install_output = ""
    if not subfinder:
        install_output = install_subfinder()
        subfinder = find_subfinder()
        if not subfinder:
            return (
                "[SUBFINDER SUBDOMAINS]\n"
                "[!] Subfinder is not installed and could not be installed automatically.\n\n"
                "[SUBFINDER INSTALLER OUTPUT]\n"
                f"{install_output}"
            )

    output_dir = Path(default_reports_dir()) / "subfinder"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{time.strftime('%Y%m%d_%H%M%S')}_{safe_artifact_name(domain)}.txt"
    command = [
        subfinder,
        "-d",
        domain,
        "-silent",
        "-duc",
        "-max-time",
        "10",
        "-o",
        str(output_path),
    ]
    print(f"  [*] subfinder {domain}")
    output = run_tool(command, timeout=900)
    if is_scan_abort(output):
        return ABORT_SCAN

    file_output = ""
    if output_path.exists():
        try:
            file_output = output_path.read_text(encoding="utf-8", errors="replace").strip()
        except Exception as e:
            file_output = f"[!] Could not read Subfinder output file: {e}"

    combined = "\n".join(part for part in (output.strip(), file_output.strip()) if part)
    if not combined:
        combined = "No subdomains found."

    if install_output:
        return (
            "[SUBFINDER INSTALLER OUTPUT]\n"
            f"{install_output}\n\n"
            "[SUBFINDER SUBDOMAINS]\n"
            f"{combined}\n\n"
            f"{check_subdomain_https_443(combined)}"
        )
    return (
        "[SUBFINDER SUBDOMAINS]\n"
        f"{combined}\n\n"
        f"{check_subdomain_https_443(combined)}"
    )


def extract_subfinder_domain_lines(text: str) -> list[str]:
    pattern = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    subdomains = []
    seen = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip().lower()
        if not line or not pattern.match(line) or line in seen:
            continue
        seen.add(line)
        subdomains.append(line)
    return subdomains


def check_subdomain_https_443(subfinder_output: str) -> str:
    subdomains = extract_subfinder_domain_lines(subfinder_output)
    if not subdomains:
        return "[SUBFINDER HTTPS 443 CHECK]\nNo subdomains to check."

    active = []
    other = []
    print(f"  [*] Checking {len(subdomains)} subdomains on TCP 443 with PowerShell")
    script = r"""
param($HostName)
$result = Test-NetConnection -ComputerName $HostName -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
if ($result) { "TRUE" } else { "FALSE" }
"""
    for subdomain in subdomains:
        result = run_tool(powershell_command(script, subdomain), timeout=12).strip().upper()
        if "TRUE" in result:
            active.append(subdomain)
        else:
            other.append(subdomain)

    def lines(rows: list[str]) -> str:
        return "\n".join(rows) if rows else "None"

    return (
        "[SUBFINDER HTTPS 443 CHECK]\n"
        "[ACTIVE SUBDOMAINS]\n"
        f"{lines(active)}\n\n"
        "[OTHER POTENTIAL SUBDOMAINS]\n"
        f"{lines(other)}"
    )


def run_smb_scanner(target: str) -> str:
    """
    SMB Scanner — local PowerShell scanner for TCP/445 and guest SMB enumeration.
    Accepts a single target IP/host or a CIDR range such as 192.168.11.0/24.
    """
    target_text = str(target or "").strip()
    if not target_text:
        return "[!] SMB Scanner failed: no target or CIDR range was provided."
    if not SMB_SCANNER_SCRIPT.exists():
        return f"[!] SMB Scanner script was not found: {SMB_SCANNER_SCRIPT}"

    output_dir = Path(default_reports_dir()) / "smb_scanner" / time.strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    command = powershell_command(
        f"& '{SMB_SCANNER_SCRIPT}' -Target $args[0] -OutputPath $args[1]",
        target_text,
        str(output_dir),
    )
    print(f"  [*] SMB Scanner {target_text}")
    output = run_tool(command, timeout=1800, cwd=str(output_dir))

    artifact_text = ""
    try:
        artifacts = []
        for path in sorted(output_dir.glob("*")):
            if path.is_file():
                content = path.read_text(encoding="utf-8", errors="replace").strip()
                artifacts.append(f"[{path.name}]\n{content or '(empty)'}")
        artifact_text = "\n\n".join(artifacts)
    except Exception as e:
        artifact_text = f"[!] Could not read SMB Scanner artifacts: {e}"

    parts = ["[SMB SCANNER OUTPUT]\n" + output]
    if artifact_text:
        parts.append("[SMB SCANNER RESULT FILES]\n" + artifact_text)
    parts.append(f"[SMB SCANNER ARTIFACTS]\n{output_dir}")
    return "\n\n".join(parts)


def read_limited_text(path: Path, max_chars: int = 12000) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n\n[...truncated {len(text) - max_chars} characters...]"


def remove_legacy_adrecon_script() -> None:
    legacy_dir = local_app_data_dir() / "tools" / "adrecon"
    legacy_script = legacy_dir / "ADRecon.ps1"
    try:
        if legacy_script.exists():
            legacy_script.unlink()
        if legacy_dir.exists() and not any(legacy_dir.iterdir()):
            legacy_dir.rmdir()
    except Exception:
        pass


def parse_ad_recon_options(target: str) -> dict[str, str]:
    options = {
        "method": "LDAP",
        "dc": "",
        "domain": "",
        "username": "",
        "password": "",
    }
    text = str(target or "").strip()
    if not text or text.lower() == "ad recon current domain":
        return options

    try:
        tokens = split_command(text)
    except Exception:
        tokens = text.split()

    aliases = {
        "-method": "method",
        "--method": "method",
        "/method": "method",
        "-dc": "dc",
        "--dc": "dc",
        "-domaincontroller": "dc",
        "--domain-controller": "dc",
        "--domaincontroller": "dc",
        "-server": "dc",
        "--server": "dc",
        "-domain": "domain",
        "--domain": "domain",
        "-username": "username",
        "--username": "username",
        "-user": "username",
        "--user": "username",
        "-u": "username",
        "-password": "password",
        "--password": "password",
        "-pass": "password",
        "--pass": "password",
        "-p": "password",
    }

    index = 0
    positional = []
    while index < len(tokens):
        token = tokens[index]
        lower = token.lower()
        if lower in aliases and index + 1 < len(tokens):
            options[aliases[lower]] = tokens[index + 1]
            index += 2
            continue
        if lower.startswith("--") and "=" in token:
            key, value = token.split("=", 1)
            mapped = aliases.get(key.lower())
            if mapped:
                options[mapped] = value
                index += 1
                continue
        positional.append(token)
        index += 1

    if positional and not options["dc"]:
        options["dc"] = positional[0]
    method = options["method"].strip().upper()
    options["method"] = "ADWS" if method == "ADWS" else "LDAP"
    return options


def ad_recon_target_label(options: dict[str, str]) -> str:
    pieces = [f"method={options.get('method') or 'LDAP'}"]
    if options.get("dc"):
        pieces.append(f"dc={options['dc']}")
    if options.get("domain"):
        pieces.append(f"domain={options['domain']}")
    if options.get("username"):
        pieces.append(f"username={options['username']}")
    if not any(options.get(key) for key in ("dc", "domain", "username")):
        pieces.append("current domain context")
    return ", ".join(pieces)


def run_native_ad_recon(options: dict[str, str], output_dir: Path) -> str:
    empty_arg = "__METATRON_EMPTY__"

    def ps_arg(value: str) -> str:
        text = str(value or "")
        return text if text else empty_arg

    ps_script = r"""
param(
    [string]$method = "LDAP",
    [string]$target = "",
    [string]$domain = "",
    [string]$username = "",
    [string]$password = "",
    [string]$output = ""
)
$ErrorActionPreference = "Continue"
function Resolve-MetatronArg($Value) {
    if ($Value -eq "__METATRON_EMPTY__") { return "" }
    return $Value
}
$method = Resolve-MetatronArg $method
$target = Resolve-MetatronArg $target
$domain = Resolve-MetatronArg $domain
$username = Resolve-MetatronArg $username
$password = Resolve-MetatronArg $password
$output = Resolve-MetatronArg $output
$method = ($method -as [string]).ToUpperInvariant()
New-Item -ItemType Directory -Force -Path $output | Out-Null
$textPath = Join-Path $output "native-ad-recon.txt"
$jsonPath = Join-Path $output "native-ad-recon.json"

function Write-Section($Title) {
    "`n[$Title]" | Tee-Object -FilePath $textPath -Append
}

function Convert-DomainToDn($DomainName) {
    if (-not $DomainName) { return "" }
    if ($DomainName -match "^DC=") { return $DomainName }
    return (($DomainName -split "\.") | ForEach-Object { "DC=$_" }) -join ","
}

function New-CredentialObject {
    if ($username -and $password) {
        $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
        return [Management.Automation.PSCredential]::new($username, $securePassword)
    }
    return $null
}

function New-LdapEntry($Path) {
    if ($username -and $password) {
        return [DirectoryServices.DirectoryEntry]::new($Path, $username, $password)
    }
    return [DirectoryServices.DirectoryEntry]::new($Path)
}

function Get-RootDse {
    if ($target) {
        return New-LdapEntry "LDAP://$target/RootDSE"
    }
    return New-LdapEntry "LDAP://RootDSE"
}

function New-Searcher($BaseDn) {
    if ($target) {
        $entry = New-LdapEntry "LDAP://$target/$BaseDn"
    } else {
        $entry = New-LdapEntry "LDAP://$BaseDn"
    }
    $searcher = [DirectoryServices.DirectorySearcher]::new($entry)
    $searcher.PageSize = 500
    return $searcher
}

function Add-Property($SearchResult, $Name) {
    $values = @($SearchResult.Properties[$Name] | ForEach-Object { [string]$_ })
    return ($values -join "; ")
}

"Native AD Recon" | Set-Content -Path $textPath
"Method: $method" | Tee-Object -FilePath $textPath -Append
"Target: $(if ($target) { $target } else { 'current domain context' })" | Tee-Object -FilePath $textPath -Append
"Domain: $(if ($domain) { $domain } else { '-' })" | Tee-Object -FilePath $textPath -Append
"Username: $(if ($username) { $username } else { 'current user' })" | Tee-Object -FilePath $textPath -Append
"Output: $output" | Tee-Object -FilePath $textPath -Append

$result = [ordered]@{
    Method = $method
    Target = if ($target) { $target } else { "current domain context" }
    DomainInput = $domain
    Username = if ($username) { $username } else { "current user" }
    Domain = @{}
    Counts = @{}
    DomainControllers = @()
    PasswordPolicy = @()
    Samples = [ordered]@{}
    Errors = @()
}

try {
    if ($method -eq "ADWS") {
        Import-Module ActiveDirectory -ErrorAction Stop
        $credential = New-CredentialObject
        $adParams = @{}
        if ($target) { $adParams.Server = $target }
        if ($credential) { $adParams.Credential = $credential }

        $domainInfo = if ($domain) {
            Get-ADDomain -Identity $domain @adParams
        } else {
            Get-ADDomain @adParams
        }
        $defaultNamingContext = [string]$domainInfo.DistinguishedName
        $result.Domain = [ordered]@{
            DNSRoot = [string]$domainInfo.DNSRoot
            NetBIOSName = [string]$domainInfo.NetBIOSName
            DistinguishedName = $defaultNamingContext
            PDCEmulator = [string]$domainInfo.PDCEmulator
        }

        Write-Section "Domain"
        $result.Domain.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" | Tee-Object -FilePath $textPath -Append }

        $countCommands = [ordered]@{
            Users = { @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user))" @adParams -ResultSetSize $null).Count }
            EnabledUsers = { @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" @adParams -ResultSetSize $null).Count }
            DisabledUsers = { @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" @adParams -ResultSetSize $null).Count }
            Groups = { @(Get-ADGroup -Filter * @adParams -ResultSetSize $null).Count }
            Computers = { @(Get-ADComputer -Filter * @adParams -ResultSetSize $null).Count }
            DomainControllers = { @(Get-ADDomainController -Filter * @adParams).Count }
            ServiceAccountsWithSPN = { @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" @adParams -ResultSetSize $null).Count }
            OUs = { @(Get-ADOrganizationalUnit -Filter * @adParams -ResultSetSize $null).Count }
            GPOs = { @(Get-ADObject -LDAPFilter "(objectClass=groupPolicyContainer)" @adParams -ResultSetSize $null).Count }
        }

        Write-Section "Object Counts"
        foreach ($name in $countCommands.Keys) {
            try {
                $count = & $countCommands[$name]
                $result.Counts[$name] = $count
                "$($name): $count" | Tee-Object -FilePath $textPath -Append
            } catch {
                $result.Errors += "$name count failed: $($_.Exception.Message)"
            }
        }

        Write-Section "Domain Controllers"
        foreach ($dc in Get-ADDomainController -Filter * @adParams) {
            $row = [ordered]@{
                Name = [string]$dc.Name
                HostName = [string]$dc.HostName
                Site = [string]$dc.Site
                OperatingSystem = [string]$dc.OperatingSystem
            }
            $result.DomainControllers += $row
            "$($row.Name)  $($row.HostName)  $($row.Site)  $($row.OperatingSystem)" | Tee-Object -FilePath $textPath -Append
        }

        Write-Section "Password Policy"
        $policy = Get-ADDefaultDomainPasswordPolicy @adParams
        $policyRows = $policy | Select-Object ComplexityEnabled, MinPasswordLength, MaxPasswordAge, MinPasswordAge, LockoutThreshold, LockoutDuration, LockoutObservationWindow
        $result.PasswordPolicy = @($policyRows)
        $policyRows | Format-List | Out-String | Tee-Object -FilePath $textPath -Append

        $samples = [ordered]@{
            RecentUsers = @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user))" @adParams -Properties DisplayName,Mail,LastLogonDate -ResultSetSize 50 |
                Select-Object SamAccountName, DisplayName, Mail, LastLogonDate)
            ServicePrincipalUsers = @(Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" @adParams -Properties ServicePrincipalName -ResultSetSize 50 |
                Select-Object SamAccountName, ServicePrincipalName)
            Computers = @(Get-ADComputer -Filter * @adParams -Properties DNSHostName,OperatingSystem -ResultSetSize 50 |
                Select-Object Name, DNSHostName, OperatingSystem)
            Groups = @(Get-ADGroup -Filter * @adParams -Properties Description -ResultSetSize 50 |
                Select-Object SamAccountName, Description)
        }

        foreach ($sampleName in $samples.Keys) {
            Write-Section "Sample $sampleName"
            $result.Samples[$sampleName] = @($samples[$sampleName])
            $samples[$sampleName] | Format-Table -AutoSize | Out-String -Width 4096 | Tee-Object -FilePath $textPath -Append
        }
    } else {
        $root = Get-RootDse
        $defaultNamingContext = [string]$root.defaultNamingContext
        if (-not $defaultNamingContext -and $domain) {
            $defaultNamingContext = Convert-DomainToDn $domain
        }
        if (-not $defaultNamingContext) {
            throw "Could not determine the domain naming context. Provide --domain or --dc, or run from a domain-connected user context."
        }
        $configurationNamingContext = [string]$root.configurationNamingContext
        $dnsHostName = [string]$root.dnsHostName
        $result.Domain = [ordered]@{
            DefaultNamingContext = $defaultNamingContext
            ConfigurationNamingContext = $configurationNamingContext
            ConnectedServer = $dnsHostName
        }

        Write-Section "Domain"
        $result.Domain.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" | Tee-Object -FilePath $textPath -Append }

        $countFilters = [ordered]@{
            Users = "(&(objectCategory=person)(objectClass=user))"
            EnabledUsers = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            DisabledUsers = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
            Groups = "(objectCategory=group)"
            Computers = "(objectCategory=computer)"
            DomainControllers = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            ServiceAccountsWithSPN = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
            OUs = "(objectClass=organizationalUnit)"
            GPOs = "(objectClass=groupPolicyContainer)"
        }

        Write-Section "Object Counts"
        foreach ($name in $countFilters.Keys) {
            try {
                $s = New-Searcher $defaultNamingContext
                $s.Filter = $countFilters[$name]
                $count = $s.FindAll().Count
                $result.Counts[$name] = $count
                "$($name): $count" | Tee-Object -FilePath $textPath -Append
            } catch {
                $result.Errors += "$name count failed: $($_.Exception.Message)"
            }
        }

        Write-Section "Domain Controllers"
        $dcSearcher = New-Searcher $defaultNamingContext
        $dcSearcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        @("name", "dnshostname", "operatingsystem", "lastlogontimestamp") | ForEach-Object { [void]$dcSearcher.PropertiesToLoad.Add($_) }
        foreach ($item in $dcSearcher.FindAll()) {
            $dc = [ordered]@{
                Name = Add-Property $item "name"
                DnsHostName = Add-Property $item "dnshostname"
                OperatingSystem = Add-Property $item "operatingsystem"
            }
            $result.DomainControllers += $dc
            "$($dc.Name)  $($dc.DnsHostName)  $($dc.OperatingSystem)" | Tee-Object -FilePath $textPath -Append
        }

        Write-Section "Password Policy"
        try {
            $domainEntry = if ($target) { New-LdapEntry "LDAP://$target/$defaultNamingContext" } else { New-LdapEntry "LDAP://$defaultNamingContext" }
            $policy = [ordered]@{
                minPwdLength = [string]$domainEntry.Properties["minPwdLength"].Value
                pwdHistoryLength = [string]$domainEntry.Properties["pwdHistoryLength"].Value
                lockoutThreshold = [string]$domainEntry.Properties["lockoutThreshold"].Value
                maxPwdAge = [string]$domainEntry.Properties["maxPwdAge"].Value
                minPwdAge = [string]$domainEntry.Properties["minPwdAge"].Value
            }
            $result.PasswordPolicy = @($policy)
            $policy.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" | Tee-Object -FilePath $textPath -Append }
        } catch {
            $result.Errors += "Password policy query failed: $($_.Exception.Message)"
        }

        $sampleDefinitions = [ordered]@{
            RecentUsers = @{
                Filter = "(&(objectCategory=person)(objectClass=user))"
                Properties = @("samaccountname", "displayname", "mail", "lastlogontimestamp")
            }
            ServicePrincipalUsers = @{
                Filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
                Properties = @("samaccountname", "serviceprincipalname")
            }
            Computers = @{
                Filter = "(objectCategory=computer)"
                Properties = @("name", "dnshostname", "operatingsystem")
            }
            Groups = @{
                Filter = "(objectCategory=group)"
                Properties = @("samaccountname", "description")
            }
        }

        foreach ($sampleName in $sampleDefinitions.Keys) {
            Write-Section "Sample $sampleName"
            $definition = $sampleDefinitions[$sampleName]
            $s = New-Searcher $defaultNamingContext
            $s.Filter = $definition.Filter
            $s.SizeLimit = 50
            foreach ($property in $definition.Properties) { [void]$s.PropertiesToLoad.Add($property) }
            $rows = @()
            foreach ($item in $s.FindAll()) {
                $row = [ordered]@{}
                foreach ($property in $definition.Properties) {
                    $row[$property] = Add-Property $item $property
                }
                $rows += [pscustomobject]$row
                (($row.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | ") | Tee-Object -FilePath $textPath -Append
            }
            $result.Samples[$sampleName] = @($rows)
        }
    }
} catch {
    $message = "Native AD recon failed: $($_.Exception.Message)"
    $result.Errors += $message
    Write-Section "Errors"
    $message | Tee-Object -FilePath $textPath -Append
}

$result | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
"""
    command = powershell_command(
        ps_script,
        ps_arg(options.get("method", "LDAP")),
        ps_arg(options.get("dc", "")),
        ps_arg(options.get("domain", "")),
        ps_arg(options.get("username", "")),
        ps_arg(options.get("password", "")),
        str(output_dir),
    )
    print(f"  [*] Native AD Recon {ad_recon_target_label(options)}")
    return run_tool(command, timeout=900, cwd=str(output_dir))


def run_ad_recon(target: str) -> str:
    """
    AD Recon — native Active Directory reconnaissance using LDAP or ADWS.
    Target may be blank when running from a domain-connected workstation.
    """
    options = parse_ad_recon_options(target)
    remove_legacy_adrecon_script()

    output_dir = Path(default_reports_dir()) / "ad_recon" / time.strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)
    output = run_native_ad_recon(options, output_dir)

    artifact_text = ""
    try:
        artifacts = []
        files = [path for path in sorted(output_dir.rglob("*")) if path.is_file()]
        for path in files[:30]:
            relative = path.relative_to(output_dir)
            if path.suffix.lower() in {".txt", ".log", ".csv", ".json", ".xml", ".html"}:
                artifacts.append(f"[{relative}]\n{read_limited_text(path)}")
            else:
                artifacts.append(f"[{relative}]\n(binary or unsupported preview)")
        if len(files) > 30:
            artifacts.append(f"[AD Recon artifact note]\n{len(files) - 30} additional file(s) were written under {output_dir}")
        artifact_text = "\n\n".join(artifacts)
    except Exception as e:
        artifact_text = f"[!] Could not read AD Recon artifacts: {e}"

    parts = ["[AD RECON OUTPUT]\n" + output]
    if artifact_text:
        parts.append("[AD RECON RESULT FILES]\n" + artifact_text)
    parts.append(f"[AD RECON ARTIFACTS]\n{output_dir}")
    return "\n\n".join(parts)


def run_pingcastle(target: str) -> str:
    """
    PingCastle - Active Directory security healthcheck using the staged PingCastle build.
    Target may be blank for the current domain, a DC/domain name, or raw PingCastle arguments.
    """
    target_text = str(target or "").strip()
    if target_text.lower() == "pingcastle current domain":
        target_text = ""
    if not PINGCASTLE_RUNNER_SCRIPT.exists():
        return f"[!] PingCastle runner was not found: {PINGCASTLE_RUNNER_SCRIPT}"

    output_dir = Path(default_reports_dir()) / "pingcastle" / time.strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=True)

    if target_text.startswith("-"):
        command = powershell_command(
            f"& '{PINGCASTLE_RUNNER_SCRIPT}' -Arguments $args[0] -OutputPath $args[1]",
            target_text,
            str(output_dir),
        )
        label = target_text
    else:
        command = powershell_command(
            f"& '{PINGCASTLE_RUNNER_SCRIPT}' -Target $args[0] -OutputPath $args[1]",
            target_text,
            str(output_dir),
        )
        label = target_text or "current domain"

    print(f"  [*] PingCastle {label}")
    output = run_tool(command, timeout=3600, cwd=str(output_dir))

    artifact_text = ""
    try:
        artifacts = []
        files = [path for path in sorted(output_dir.rglob("*")) if path.is_file()]
        for path in files[:30]:
            relative = path.relative_to(output_dir)
            if path.suffix.lower() in {".txt", ".log", ".csv", ".json", ".xml", ".html"}:
                artifacts.append(f"[{relative}]\n{read_limited_text(path)}")
            else:
                artifacts.append(f"[{relative}]\n(binary or unsupported preview)")
        if len(files) > 30:
            artifacts.append(f"[PingCastle artifact note]\n{len(files) - 30} additional file(s) were written under {output_dir}")
        artifact_text = "\n\n".join(artifacts)
    except Exception as e:
        artifact_text = f"[!] Could not read PingCastle artifacts: {e}"

    parts = ["[PINGCASTLE OUTPUT]\n" + output]
    if artifact_text:
        parts.append("[PINGCASTLE RESULT FILES]\n" + artifact_text)
    parts.append(f"[PINGCASTLE ARTIFACTS]\n{output_dir}")
    return "\n\n".join(parts)


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1": ("Nmap",         run_nmap),
    "2": ("Whois",        run_whois),
    "3": ("Whatweb",      run_whatweb),
    "4": ("Curl Headers", run_curl_headers),
    "5": ("Dig DNS",      run_dig),
    "6": ("SSLyze TLS",   run_sslyze),
    "7": ("HAR Cookie Consent", run_har_cookie_consent),
    "8": ("Subfinder Subdomains", run_subfinder),
}

INTERNAL_TOOLS_MENU = {
    "smb_scanner": ("SMB Scanner", run_smb_scanner),
    "ad_recon": ("AD Recon", run_ad_recon),
    "pingcastle": ("PingCastle", run_pingcastle),
    "nmap_custom": ("Nmap (Custom Scan)", run_nmap_custom),
}


def run_default_recon(target: str) -> dict | None:
    """
    Run the standard Windows-native recon pipeline.
    Returns a dict of {tool_name: output_string}.
    """
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)

    results = {}
    steps = [
        ("nmap", run_nmap),
        ("whois", run_whois),
        ("whatweb", run_whatweb),
        ("curl_headers", run_curl_headers),
        ("dig", run_dig),
        ("sslyze", run_sslyze),
        ("har_cookie_consent", run_har_cookie_consent),
        ("subfinder", run_subfinder),
    ]

    for key, func in steps:
        output = run_scan_step(func, target)
        if is_scan_abort(output):
            return None
        results[key] = output

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict, run_mode: str = "full", selected_tool: str = "") -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = (
        "[METATRON RUN MODE]\n"
        f"mode: {run_mode}\n"
        f"tool: {selected_tool or '-'}\n"
        "[/METATRON RUN MODE]\n"
    )
    for tool, data in results.items():
        header = f"[ {tool.upper()} OUTPUT ]"
        if run_mode == "single_tool":
            output += f"\n{header}\n"
        else:
            output += f"\n{'='*50}\n{header}\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


ALLOWED_TOOLS = {"nmap", "whois", "whatweb", "curl", "dig", "sslyze", "har"}

def run_tool_by_command(command_str: str) -> str:
    parts = split_command(command_str.strip())
    if not parts:
        return "[!] Empty command."
    
    # allowlist only — reject anything not in the list
    tool = executable_name(parts[0])
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"

    if IS_WINDOWS and tool == "dig":
        record_types = []
        target = ""
        valid_types = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"}
        for part in parts[1:]:
            value = part.strip()
            upper = value.upper()
            if value.startswith("+") or upper == "ANY":
                continue
            if upper in valid_types:
                record_types.append(upper)
            elif not target:
                target = value

        if not target:
            return "[!] DNS lookup failed: no target was provided."

        return run_windows_dns_lookup(target, record_types or None)

    if tool == "sslyze":
        sslyze_target = parts[-1] if len(parts) > 1 else ""
        if not sslyze_target:
            return "[!] SSLyze lookup failed: no target was provided."
        return run_sslyze(sslyze_target)

    if tool == "har":
        har_target = parts[-1] if len(parts) > 1 else ""
        if not har_target:
            return "[!] HAR capture failed: no target was provided."
        return run_har_cookie_consent(har_target)

    return run_tool(parts)

# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string.
    """
    while True:
        print("\n[ SELECT TOOLS TO RUN ]")
        print("  [a] Full Scan")
        for key, (name, _) in TOOLS_MENU.items():
            print(f"  [{key}] {name}")
        print("  [9] Back")
        print("  Press Ctrl+C while a scan is running to return to this menu.")

        try:
            choice = prompt("\nChoice(s) e.g. 1 2 4, or a: ").strip().lower()
        except MenuBack:
            return ""

        if choice == "a":
            results = run_default_recon(target)
            if results is None:
                continue
            web_output = run_scan_step(run_builtin_web_checks, target)
            if is_scan_abort(web_output):
                continue
            results["built_in_web_checks"] = web_output
            return format_recon_for_llm(results)

        if choice == "9":
            return ""

        selected_keys = choice.split()
        combined = {}
        aborted = False
        for key in selected_keys:
            if key in TOOLS_MENU:
                name, func = TOOLS_MENU[key]
                print(f"\n[*] Running {name}...")
                output = run_scan_step(func, target)
                if is_scan_abort(output):
                    aborted = True
                    break
                combined[name] = output
            else:
                print(f"[!] Unknown option: {key}")

        if aborted:
            continue

        if not combined:
            print("[!] No tools selected.")
            continue

        if len(combined) == 1 and len(selected_keys) == 1 and selected_keys[0] in TOOLS_MENU:
            selected_tool = next(iter(combined.keys()))
            return format_recon_for_llm(combined, run_mode="single_tool", selected_tool=selected_tool)

        return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    if results is not None:
        print(format_recon_for_llm(results))
