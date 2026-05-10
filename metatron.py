#!/usr/bin/env python3
"""
METATRON - metatron.py
Main CLI entry point. Wires db.py + tools.py + search.py + llm.py together.
Run with: python metatron.py
"""
from export import export_html, export_menu, export_pre_ai_package_from_raw, extract_subdomain_status
import ipaddress
import os
import sys
import re
import shutil
import webbrowser
from pathlib import Path
from urllib.parse import urlparse
from console_input import (
    KEY_CTRL_C,
    KEY_DOWN,
    KEY_ENTER,
    KEY_ESCAPE,
    KEY_UP,
    MenuBack,
    ask_exit_from_menu,
    pause,
    prompt,
    read_menu_key,
)
from platform_utils import clear_screen, database_service_hint, default_reports_dir
from db import (
    get_connection,
    create_session,
    save_vulnerability,
    save_fix,
    save_exploit,
    save_summary,
    get_domain_history,
    get_scans_for_domain,
    has_scans_for_domain,
    get_session,
    get_vulnerabilities,
    get_fixes,
    get_exploits,
    edit_vulnerability,
    edit_fix,
    edit_exploit,
    edit_summary_risk,
    delete_vulnerability,
    delete_exploit,
    delete_fix,
    delete_ai_results,
    delete_full_session,
    delete_domain_sessions,
    delete_all_sessions,
    print_session
)
from tools import interactive_tool_run
from llm import (
    analyse_target,
    configure_lm_studio_model,
    current_model_name,
    ensure_lm_studio_model,
    parse_exploits,
    parse_risk_level,
    parse_summary,
    parse_vulnerabilities,
)


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    clear_screen()
    print("""
\033[91m
██████╗  ██████╗ ███████╗      ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
██╔══██╗██╔════╝ ██╔════╝      ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
██████╔╝██║  ███╗███████╗█████╗██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
██╔═══╝ ██║   ██║╚════██║╚════╝██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
██║     ╚██████╔╝███████║      ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
╚═╝      ╚═════╝ ╚══════╝      ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m

\033[90mAI Penetration Testing Assistant  |  LM Studio local model  |  Windows/PowerShell ready\033[0m
\033[90m────────────────────────────────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")

def success(text):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text):
    print(f"\033[94m[*] {text}\033[0m")


class ScanComplete(Exception):
    def __init__(self, target: str, report_path: str = ""):
        self.target = target
        self.report_path = report_path
        super().__init__(target)


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


def save_ai_result(sl_no: int, result: dict):
    for vuln in result["vulnerabilities"]:
        vuln_id = save_vulnerability(
            sl_no,
            vuln["vuln_name"],
            vuln["severity"],
            vuln["port"],
            vuln["service"],
            vuln["description"]
        )
        if vuln.get("fix"):
            save_fix(sl_no, vuln_id, vuln["fix"], source="ai")
        success(f"Saved vuln: {vuln['vuln_name']} [{vuln['severity']}]")

    for exp in result["exploits"]:
        save_exploit(
            sl_no,
            exp["exploit_name"],
            exp["tool_used"],
            exp["payload"],
            exp["result"],
            exp["notes"]
        )
        success(f"Saved exploit: {exp['exploit_name']}")

    save_summary(
        sl_no,
        result["raw_scan"],
        result["full_response"],
        result["risk_level"]
    )


def auto_export_pre_ai_package(target: str, raw_scan: str, sl_no: int):
    try:
        output_dir = default_reports_dir()
        p1, p2 = export_pre_ai_package_from_raw(target, raw_scan, output_dir, sl_no=sl_no)
        success(f"Pre-AI JSON saved: {p1}")
        success(f"Pre-AI prompt saved: {p2}")
    except Exception as e:
        warn(f"Pre-AI export failed: {e}")


def auto_export_html_report(data: dict) -> str:
    try:
        output_dir = default_reports_dir()
        path = export_html(data, output_dir)
        success(f"HTML report saved: {path}")
        return path
    except Exception as e:
        warn(f"HTML report export failed: {e}")
        return ""


def open_report_file(path: str):
    if not path:
        return
    try:
        if os.name == "nt":
            os.startfile(path)
        else:
            webbrowser.open(Path(path).resolve().as_uri())
    except Exception as e:
        warn(f"Could not open HTML report automatically: {e}")


def is_single_subfinder_scan(raw_scan: str) -> bool:
    text = str(raw_scan or "")
    mode_match = "mode: single_tool" in text.lower()
    tool_match = "tool: subfinder" in text.lower()
    return mode_match and tool_match


def single_tool_name(raw_scan: str) -> str:
    match = re.search(r"(?im)^tool:\s*(.+)$", str(raw_scan or ""))
    return match.group(1).strip() if match else ""


def is_single_raw_only_scan(raw_scan: str) -> bool:
    text = str(raw_scan or "")
    return "mode: single_tool" in text.lower()


def save_raw_tool_result(sl_no: int, raw_scan: str, tool_name: str):
    save_summary(
        sl_no,
        raw_scan,
        f"{tool_name} raw output saved without AI analysis.",
        "UNKNOWN",
    )


def remove_subfinder_from_ai_input(raw_scan: str) -> str:
    """Keep Subfinder in saved raw output, but remove it from AI prompt input."""
    return re.sub(
        r"(?is)\n={10,}\n\[\s*SUBFINDER.*?OUTPUT\s*\]\n={10,}\n.*?(?=\n={10,}\n\[\s*.+?OUTPUT\s*\]\n={10,}|\Z)",
        "",
        str(raw_scan or ""),
    ).strip()


def normalize_target_host(target: str) -> str:
    text = str(target or "").strip().lower()
    parsed = urlparse(text)
    if parsed.scheme:
        host = parsed.hostname or ""
    else:
        host = text.split("/")[0].split(":")[0]
    return host.strip().strip(".")


def primary_domain_for_target(target: str) -> str:
    host = normalize_target_host(target)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def target_type_for_target(target: str, primary_domain: str) -> str:
    host = normalize_target_host(target)
    return "domain" if host == primary_domain else "subdomain"


def session_belongs_to_domain(sl_no: int, primary_domain: str) -> bool:
    return any(row[0] == sl_no for row in get_scans_for_domain(primary_domain))


def clear_lines(count: int):
    for idx in range(max(0, count)):
        sys.stdout.write("\r\033[2K")
        if idx < count - 1:
            sys.stdout.write("\033[F")
    sys.stdout.flush()


def visible_width(text: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def wrapped_line_count(text: str) -> int:
    columns = max(20, shutil.get_terminal_size((120, 30)).columns)
    total = 0
    for line in str(text).splitlines() or [""]:
        width = visible_width(line)
        total += max(1, (width + columns - 1) // columns)
    return total


def print_selectable_rows(rows, selected_idx: int, row_formatter):
    for idx, row in enumerate(rows, start=1):
        text = row_formatter(idx, row)
        if idx - 1 == selected_idx:
            print(f"\033[30;47m{text}\033[0m")
        else:
            print(text)


def arrow_select_or_command(rows, prompt_text: str, row_formatter, selected_idx: int = 0) -> tuple[str, int | None, int]:
    if not rows:
        return "back", None, selected_idx

    selected_idx = min(max(0, selected_idx), len(rows) - 1)

    if sys.stdin is None or not sys.stdin.isatty():
        try:
            typed = prompt(prompt_text)
        except MenuBack:
            return "back", None, selected_idx
        if not typed:
            return "back", None, selected_idx
        return "command", typed, selected_idx

    typed = []

    def render_menu() -> int:
        print_selectable_rows(rows, selected_idx, row_formatter)
        prompt_line = f"\033[36m{prompt_text}\033[0m{''.join(typed)}"
        print(prompt_line, end="", flush=True)
        return len(rows) + wrapped_line_count(f"{prompt_text}{''.join(typed)}")

    rendered_lines = render_menu()

    while True:
        key, ch = read_menu_key()
        if key == KEY_UP:
            selected_idx = (selected_idx - 1) % len(rows)
            clear_lines(rendered_lines)
            rendered_lines = render_menu()
            continue
        if key == KEY_DOWN:
            selected_idx = (selected_idx + 1) % len(rows)
            clear_lines(rendered_lines)
            rendered_lines = render_menu()
            continue
        if key == KEY_ENTER:
            print()
            command = "".join(typed).strip()
            if command:
                return "command", command, selected_idx
            return "select", selected_idx, selected_idx
        if key == KEY_ESCAPE:
            print()
            return "back", None, selected_idx
        if key == KEY_CTRL_C:
            ask_exit_from_menu()
            print(f"\033[36m{prompt_text}\033[0m{''.join(typed)}", end="", flush=True)
            rendered_lines = len(rows) + wrapped_line_count(f"{prompt_text}{''.join(typed)}")
            continue
        if ch in ("\b", "\x7f"):
            if typed:
                typed.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
                rendered_lines = len(rows) + wrapped_line_count(f"{prompt_text}{''.join(typed)}")
            continue
        if ch:
            typed.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()
            rendered_lines = len(rows) + wrapped_line_count(f"{prompt_text}{''.join(typed)}")


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def run_scan_for_target(target: str, primary_domain: str | None = None, parent_target: str | None = None, target_type: str | None = None):
    target = normalize_target_host(target)
    primary_domain = primary_domain or primary_domain_for_target(target)
    target_type = target_type or target_type_for_target(target, primary_domain)
    parent_target = parent_target or (primary_domain if target_type == "subdomain" else None)

    sl_no = create_session(target, primary_domain=primary_domain, parent_target=parent_target, target_type=target_type)
    success(f"Session created — SL# {sl_no}")

    divider(f"RECON — {target}")
    info("Choose recon tools to run:")
    try:
        raw_scan = interactive_tool_run(target)
    except KeyboardInterrupt:
        print()
        raw_scan = ""

    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        return False

    auto_export_pre_ai_package(target, raw_scan, sl_no)

    if is_single_raw_only_scan(raw_scan):
        tool_name = single_tool_name(raw_scan) or "Tool"
        divider("SAVING TO DATABASE")
        save_raw_tool_result(sl_no, raw_scan, tool_name)
        success(f"{tool_name} raw output saved. SL# {sl_no}")
        divider()

        data = get_session(sl_no)
        print_session(data)
        report_path = auto_export_html_report(data)
        raise ScanComplete(target, report_path)

    if not ensure_lm_studio_model():
        warn("No LM Studio model is available. Start LM Studio's local server and select a model first.")
        delete_full_session(sl_no)
        return False

    divider("AI ANALYSIS")
    ai_raw_scan = remove_subfinder_from_ai_input(raw_scan)
    result = analyse_target(target, ai_raw_scan)
    if str(result.get("full_response", "")).startswith("[!]"):
        error("AI analysis failed. This scan will not be saved as a completed report.")
        print(result["full_response"])
        delete_full_session(sl_no)
        return False
    result["raw_scan"] = raw_scan

    divider("SAVING TO DATABASE")
    save_ai_result(sl_no, result)

    success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    divider()

    data = get_session(sl_no)
    print_session(data)
    report_path = auto_export_html_report(data)
    raise ScanComplete(target, report_path)


def new_scan():
    divider("NEW SCAN")
    try:
        target = prompt("[?] Enter Target IP or Domain (or press Enter to go back): ")
    except MenuBack:
        return False
    if not target:
        warn("No target entered.")
        return False

    normalized = normalize_target_host(target)
    primary_domain = primary_domain_for_target(normalized)
    if has_scans_for_domain(primary_domain):
        warn(f"'{primary_domain}' already has saved scan history.")
        domain_history_menu(primary_domain)
        return True

    return run_scan_for_target(
        normalized,
        primary_domain=primary_domain,
        parent_target=primary_domain if normalized != primary_domain else None,
        target_type=target_type_for_target(normalized, primary_domain),
    )


def rerun_ai_analysis(sl_no: int):
    data = get_session(sl_no)
    if not data["history"]:
        error(f"SL# {sl_no} not found.")
        return
    if not data["summary"] or not data["summary"][2]:
        warn("This session does not have saved raw scan data to analyze.")
        return

    target = data["history"][1]
    raw_scan = data["summary"][2]

    if not ensure_lm_studio_model():
        warn("No LM Studio model is available. Start LM Studio's local server and select a model first.")
        return

    warn("This will replace the current AI vulnerabilities, fixes, exploits, and summary for this session.")
    if not confirm(f"Rerun AI analysis only for SL# {sl_no} using saved scan data?"):
        return

    divider("AI RE-ANALYSIS")
    auto_export_pre_ai_package(target, raw_scan, sl_no)
    ai_raw_scan = remove_subfinder_from_ai_input(raw_scan)
    result = analyse_target(target, ai_raw_scan)
    if str(result.get("full_response", "")).startswith("[!]"):
        error("AI re-analysis failed. Existing findings were not changed.")
        print(result["full_response"])
        return
    result["raw_scan"] = raw_scan

    divider("REPLACING AI RESULTS")
    delete_ai_results(sl_no)
    save_ai_result(sl_no, result)
    success(f"AI analysis rerun complete. SL# {sl_no} | Risk: {result['risk_level']}")


def print_domain_rows(rows):
    print("\n" + "─"*78)
    print(f"{'#':<5} {'DOMAIN':<32} {'LAST SCAN':<22} {'SCANS':<7} {'SUBDOMAIN SCANS'}")
    print("─"*78)
    for idx, row in enumerate(rows, start=1):
        print(f"{idx:<5} {str(row[0]):<32} {str(row[1]):<22} {str(row[2]):<7} {str(row[3] or 0)}")
    print()


def format_domain_row(idx: int, row) -> str:
    return f"{idx:<5} {str(row[0]):<32} {str(row[1]):<22} {str(row[2]):<7} {str(row[3] or 0)}"


def print_domain_rows_header():
    print("\n" + "─"*78)
    print(f"{'#':<5} {'DOMAIN':<32} {'LAST SCAN':<22} {'SCANS':<7} {'SUBDOMAIN SCANS'}")
    print("─"*78)


def scan_targets_for_domain(primary_domain: str) -> list[dict]:
    targets = []
    seen = set()
    for row in get_scans_for_domain(primary_domain):
        target = str(row[1] or "").strip()
        if not target or target in seen:
            continue
        seen.add(target)
        targets.append({
            "target": target,
            "target_type": str(row[4] or target_type_for_target(target, primary_domain)),
        })
    if not targets:
        targets.append({"target": primary_domain, "target_type": "domain"})
    return targets


def format_target_row(idx: int, target_info: dict) -> str:
    return f"  [{idx}] {target_info['target']} ({target_info['target_type']})"


def print_selected_target(targets: list[dict], selected_idx: int):
    if len(targets) <= 1:
        return
    print("\n[ Selected Target ]")
    print_selectable_rows(targets, selected_idx, format_target_row)
    print()


def print_domain_scans(primary_domain: str, target: str | None = None):
    rows = get_scans_for_domain(primary_domain)
    if target:
        rows = [row for row in rows if normalize_target_host(row[1]) == normalize_target_host(target)]
    print("\n" + "─"*92)
    print(f"{'SL#':<7} {'TARGET':<34} {'TYPE':<12} {'DATE':<22} {'STATUS'}")
    print("─"*92)
    for row in rows:
        print(f"{row[0]:<7} {str(row[1]):<34} {str(row[4] or 'domain'):<12} {str(row[2]):<22} {row[3]}")
    print()
    return rows


def discovered_subdomains_for_domain(primary_domain: str) -> tuple[list[str], list[str]]:
    active = []
    other = []
    seen_active = set()
    seen_other = set()

    for row in get_scans_for_domain(primary_domain):
        data = get_session(row[0])
        summary = data.get("summary")
        if not summary or not summary[2]:
            continue
        active_rows, other_rows = extract_subdomain_status(summary[2])
        for subdomain in active_rows:
            if subdomain not in seen_active:
                seen_active.add(subdomain)
                active.append(subdomain)
        for subdomain in other_rows:
            if subdomain not in seen_active and subdomain not in seen_other:
                seen_other.add(subdomain)
                other.append(subdomain)

    return active, other


def choose_scan_from_domain(primary_domain: str, action_label: str, target: str | None = None) -> int | None:
    clear_screen()
    divider(f"SELECT SCAN — {target or primary_domain}")
    rows = print_domain_scans(primary_domain, target=target)
    if not rows:
        warn("No scans recorded for this domain.")
        return None
    try:
        value = prompt(f"\nEnter SL# to {action_label} (or press Enter to go back): ")
    except MenuBack:
        return None
    if not value:
        return None
    if not value.isdigit():
        error("Invalid SL#.")
        return None
    sl_no = int(value)
    if not session_belongs_to_domain(sl_no, primary_domain):
        error(f"SL# {sl_no} does not belong to {primary_domain}.")
        return None
    if target and not any(row[0] == sl_no for row in rows):
        error(f"SL# {sl_no} does not belong to {target}.")
        return None
    return sl_no


def subdomain_menu(primary_domain: str):
    active, other = discovered_subdomains_for_domain(primary_domain)
    combined = [("active", item) for item in active] + [("other potential", item) for item in other]

    clear_screen()
    divider(f"SUBDOMAINS — {primary_domain}")
    if active:
        print("\n[ Active Subdomains ]")
        for idx, subdomain in enumerate(active, start=1):
            print(f"  [{idx}] {subdomain}")
    else:
        print("\n[ Active Subdomains ]\n  None recorded.")

    if other:
        offset = len(active)
        print("\n[ Other Potential Subdomains ]")
        for idx, subdomain in enumerate(other, start=1):
            print(f"  [{offset + idx}] {subdomain}")
    else:
        print("\n[ Other Potential Subdomains ]\n  None recorded.")

    if not combined:
        return

    try:
        choice = prompt("\nSelect a subdomain number to scan it (or press Enter to go back): ")
    except MenuBack:
        return
    if not choice:
        return
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(combined):
        error("Invalid subdomain selection.")
        return

    _, subdomain = combined[int(choice) - 1]
    run_scan_for_target(subdomain, primary_domain=primary_domain, parent_target=primary_domain, target_type="subdomain")


def domain_history_menu(primary_domain: str):
    selected_idx = 0
    while True:
        targets = scan_targets_for_domain(primary_domain)
        selected_idx = min(max(0, selected_idx), len(targets) - 1)

        if len(targets) > 1:
            clear_screen()
            divider(f"DOMAIN HISTORY — {primary_domain}")
            print("\n[ Targets ]")
            action, value, selected_idx = arrow_select_or_command(
                targets,
                "\nSelect Target Domain. ",
                format_target_row,
                selected_idx=selected_idx,
            )
            if action == "back":
                return
            if action == "command":
                command = str(value).strip()
                if not command.isdigit() or int(command) < 1 or int(command) > len(targets):
                    error("Invalid target selection.")
                    continue
                selected_idx = int(command) - 1

        selected_target_info = targets[selected_idx] if selected_idx < len(targets) else targets[0]
        selected_target = selected_target_info["target"]
        selected_type = selected_target_info["target_type"]

        try:
            clear_screen()
            divider(f"DOMAIN HISTORY — {primary_domain}")
            print_selected_target(targets, selected_idx)
            print_domain_scans(primary_domain, target=selected_target if len(targets) > 1 else None)
            print("  [1] List/select discovered subdomains")
            print(f"  [2] Scan this domain again ({selected_target})")
            print("  [3] Export a previous scan")
            print("  [4] Rerun AI analysis for a previous scan")
            print("  [5] Import external AI findings into a previous scan")
            print("  [6] Edit or delete a previous scan")
            print("  [9] Back")
            divider()

            choice = prompt("\nChoice: ")
        except MenuBack:
            if len(targets) > 1:
                continue
            return
        if choice == "1":
            try:
                subdomain_menu(primary_domain)
            except MenuBack:
                continue
        elif choice == "2":
            try:
                run_scan_for_target(
                    selected_target,
                    primary_domain=primary_domain,
                    parent_target=primary_domain if selected_type == "subdomain" else None,
                    target_type=selected_type,
                )
            except MenuBack:
                continue
        elif choice == "3":
            sl_no = choose_scan_from_domain(primary_domain, "export", target=selected_target)
            if sl_no:
                try:
                    export_menu(get_session(sl_no))
                except MenuBack:
                    continue
        elif choice == "4":
            sl_no = choose_scan_from_domain(primary_domain, "rerun AI analysis for", target=selected_target)
            if sl_no:
                try:
                    rerun_ai_analysis(sl_no)
                except MenuBack:
                    continue
        elif choice == "5":
            sl_no = choose_scan_from_domain(primary_domain, "import findings into", target=selected_target)
            if sl_no:
                try:
                    import_external_findings(sl_no)
                except MenuBack:
                    continue
        elif choice == "6":
            sl_no = choose_scan_from_domain(primary_domain, "edit/delete", target=selected_target)
            if sl_no:
                try:
                    edit_delete_menu(sl_no)
                except MenuBack:
                    continue
        elif choice == "9" or choice == "":
            return
        else:
            error("Invalid choice.")


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def view_history():
    selected_idx = 0
    while True:
        clear_screen()
        divider("SCAN HISTORY")
        rows = get_domain_history()

        if not rows:
            warn("No scans in database yet.")
            return

        print_domain_rows_header()
        prompt_text = "\nSelect a Domain or enter the domain # to view details (or press Escape to go back). Type 'DEL' and the domain number to delete a domain record, or 'DEL ALL' to delete all previous reports: "
        action, value, selected_idx = arrow_select_or_command(
            rows,
            prompt_text,
            format_domain_row,
            selected_idx=selected_idx,
        )
        if action == "back":
            return
        if action == "select":
            try:
                domain_history_menu(rows[int(value)][0])
            except MenuBack:
                continue
            continue

        command = str(value or "").strip()
        command_upper = command.upper()

        if command_upper == "DEL ALL":
            try:
                if confirm("WARNING: This will delete all previously stored reports. Are you sure?"):
                    delete_all_sessions()
            except MenuBack:
                pass
            continue

        if command_upper.startswith("DEL "):
            domain_no = command[4:].strip()
            if not domain_no.isdigit():
                error("Invalid delete command. Use DEL followed by the domain number.")
                continue

            idx = int(domain_no)
            if idx < 1 or idx > len(rows):
                error("Domain number not found.")
                continue
            primary_domain = rows[idx - 1][0]

            try:
                if confirm(f"Are you sure you want to delete domain record {primary_domain} and all of its scans?"):
                    delete_domain_sessions(primary_domain)
            except MenuBack:
                pass
            continue

        if not command.isdigit():
            error("Invalid domain number.")
            continue

        idx = int(command)
        if idx < 1 or idx > len(rows):
            error("Domain number not found.")
            continue

        try:
            domain_history_menu(rows[idx - 1][0])
        except MenuBack:
            continue


# ─────────────────────────────────────────────
# EXTERNAL FINDINGS IMPORT
# ─────────────────────────────────────────────

def read_external_findings_file(path: str) -> str:
    cleaned = path.strip().strip('"').strip("'")
    with open(cleaned, "r", encoding="utf-8-sig") as f:
        return f.read()


def import_external_findings(sl_no: int):
    divider(f"IMPORT EXTERNAL FINDINGS — SL# {sl_no}")
    try:
        path = prompt("Path to external AI findings text/markdown file: ")
    except MenuBack:
        return
    if not path:
        warn("No file selected.")
        return

    try:
        text = read_external_findings_file(path)
    except Exception as e:
        error(f"Could not read findings file: {e}")
        return

    vulns = parse_vulnerabilities(text)
    exploits = parse_exploits(text)
    risk = parse_risk_level(text)
    summary = parse_summary(text)

    if not vulns and not exploits and risk == "UNKNOWN":
        warn("No Metatron-formatted findings were found in that file.")
        warn("Expected lines like: VULN: ... | SEVERITY: ... | PORT: ... | SERVICE: ...")
        return

    print(f"Parsed {len(vulns)} vulnerabilities, {len(exploits)} exploits, risk={risk}.")
    if summary:
        print(f"Summary: {summary}")

    if not confirm("Import these findings?"):
        return

    for vuln in vulns:
        vuln_id = save_vulnerability(
            sl_no,
            vuln["vuln_name"],
            vuln["severity"],
            vuln["port"],
            vuln["service"],
            vuln["description"],
        )
        if vuln.get("fix"):
            save_fix(sl_no, vuln_id, vuln["fix"], source="external-ai")
        success(f"Imported vuln: {vuln['vuln_name']} [{vuln['severity']}]")

    for exp in exploits:
        save_exploit(
            sl_no,
            exp["exploit_name"],
            exp["tool_used"],
            exp["payload"],
            exp["result"],
            exp["notes"],
        )
        success(f"Imported exploit: {exp['exploit_name']}")

    if risk != "UNKNOWN":
        edit_summary_risk(sl_no, risk)

    success("External findings import complete.")


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        try:
            divider(f"EDIT / DELETE — SL# {sl_no}")
            print("  [1] Edit a vulnerability")
            print("  [2] Edit a fix")
            print("  [3] Edit an exploit")
            print("  [4] Edit risk level")
            print("  [5] Delete a vulnerability")
            print("  [6] Delete a fix")
            print("  [7] Delete an exploit")
            print("  [8] Delete FULL session (all tables)")
            print("  [9] Back")
            divider()

            choice = prompt("Choice: ")
        except MenuBack:
            return

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / port / service / description")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to edit: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)

        # ── EDIT EXPLOIT ──────────────────────
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits recorded for this session.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")

            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_exploit(int(eid), field, value)

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")

            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete vulnerability id={vid} and its linked fixes?"):
                delete_vulnerability(int(vid))

        # ── DELETE FIX ────────────────────────
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to delete: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))

        # ── DELETE EXPLOIT ────────────────────
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits to delete.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | result: {e[5]}")

            eid = prompt("Enter exploit id to delete: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete exploit id={eid}?"):
                delete_exploit(int(eid))

        # ── DELETE FULL SESSION ───────────────
        elif choice == "8":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session SL# {sl_no} wiped.")
                return   # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "9":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# DB CONNECTION CHECK
# ─────────────────────────────────────────────

def check_db():
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception as e:
        error(f"MariaDB connection failed: {e}")
        error(database_service_hint())
        return False


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    status_message = ""
    while True:
        try:
            banner()
            print(f"  \033[94mModel:\033[0m {current_model_name()}")
            divider()
            print("  \033[92m[1]\033[0m  New Scan")
            print("  \033[92m[2]\033[0m  View History")
            print("  \033[92m[3]\033[0m  Select LM Studio Model")
            print("  \033[92m[4]\033[0m  Exit")
            divider()
            if status_message:
                print(f"  \033[92m{status_message}\033[0m")

            choice = prompt("metatron> ")
            status_message = ""
        except MenuBack:
            continue

        if choice == "1":
            try:
                new_scan()
            except ScanComplete as completed:
                open_report_file(completed.report_path)
                status_message = f"Scan of {completed.target} complete."
                continue
            except MenuBack:
                continue
            pause()

        elif choice == "2":
            try:
                view_history()
            except ScanComplete as completed:
                open_report_file(completed.report_path)
                status_message = f"Scan of {completed.target} complete."
                continue
            except MenuBack:
                pass

        elif choice == "3":
            try:
                configure_lm_studio_model(force_prompt=True)
            except MenuBack:
                pass
            pause()

        elif choice == "4":
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if not check_db():
        sys.exit(1)
    configure_lm_studio_model()
    main_menu()
