#!/usr/bin/env python3

import os
import datetime
import html as html_lib
import re
import json
import base64
from console_input import MenuBack, prompt
from db import get_connection
from platform_utils import default_reports_dir, resource_path

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#27ae60",
    "unknown":  "#7f8c8d",
}

RISK_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "UNKNOWN":  "#7f8c8d",
}

REPORT_LOGO_PATHS = [
    str(resource_path("assets", "pgs-metatron-logo.png")),
]


def safe_filename_part(value) -> str:
    text = str(value or "report")
    text = text.replace("https://", "").replace("http://", "")
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", text)
    text = re.sub(r"\s+", "_", text).strip("._ ")
    return text or "report"


def html_text(value) -> str:
    return html_lib.escape(str(value or ""), quote=True)


def report_logo_data_uri() -> str:
    for logo_path in REPORT_LOGO_PATHS:
        try:
            with open(logo_path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("ascii")
            return f"data:image/png;base64,{encoded}"
        except OSError:
            continue
    return ""


def clean_cell(value, default="-") -> str:
    text = str(value or "").strip()
    return text if text else default


def vulnerability_map(data: dict) -> dict:
    return {v[0]: v for v in data.get("vulns", [])}


def normalized_key(*values) -> tuple[str, ...]:
    return tuple(re.sub(r"\s+", " ", str(value or "").strip()).lower() for value in values)


def parse_ai_vulnerability_headers(ai_text: str) -> list[tuple[str, str, str, str, str]]:
    rows = []
    seen = set()
    for raw_line in str(ai_text or "").splitlines():
        line = re.sub(r"\*+", "", raw_line).strip()
        if not line.startswith("VULN:"):
            continue

        vuln_name = ""
        severity = "unknown"
        port = "-"
        service = "-"
        for part in line.split("|"):
            part = part.strip()
            if part.startswith("VULN:"):
                vuln_name = part.replace("VULN:", "", 1).strip()
            elif part.startswith("SEVERITY:"):
                severity = part.replace("SEVERITY:", "", 1).strip()
            elif part.startswith("PORT:"):
                port = part.replace("PORT:", "", 1).strip()
            elif part.startswith("SERVICE:"):
                service = part.replace("SERVICE:", "", 1).strip()

        if not vuln_name:
            continue
        key = normalized_key(vuln_name, severity, port, service)
        if key in seen:
            continue
        seen.add(key)
        rows.append(("AI", vuln_name, severity, port, service))
    return rows


def unique_vulnerability_rows(data: dict, ai_text: str) -> list[tuple[str, str, str, str, str]]:
    rows = []
    seen = set()
    for v in data.get("vulns", []):
        row = (
            str(v[0]),
            clean_cell(v[2]),
            clean_cell(v[3], "unknown"),
            clean_cell(v[4]),
            clean_cell(v[5]),
        )
        key = normalized_key(row[1], row[2], row[3], row[4])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    for row in parse_ai_vulnerability_headers(ai_text):
        key = normalized_key(row[1], row[2], row[3], row[4])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)

    return rows


def unique_fix_rows(data: dict, vmap: dict) -> list[tuple[str, str, str, str, str, str]]:
    rows = []
    seen = set()
    for f in data.get("fixes", []):
        v = vmap.get(f[2])
        row = (
            clean_cell(f[2] or f[0]),
            clean_cell(v[2] if v else f"Vulnerability #{f[2]}"),
            clean_cell(v[3] if v else "-", "unknown"),
            clean_cell(v[4] if v else "-"),
            clean_cell(v[5] if v else "-"),
            clean_cell(f[3]),
        )
        key = normalized_key(row[1], row[2], row[3], row[4], row[5])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows


def unique_exploit_rows(data: dict) -> list[tuple[str, str, str, str, str, str]]:
    rows = []
    seen = set()
    for e in data.get("exploits", []):
        row = (
            clean_cell(e[0]),
            clean_cell(e[2]),
            clean_cell(e[3]),
            clean_cell(e[4]),
            clean_cell(e[5]),
            clean_cell(e[6]),
        )
        if normalized_key(row[1])[0] in {"n/a", "na", "not applicable", "-"}:
            continue
        key = normalized_key(*row[1:])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return rows


def ai_display_lines(text: str) -> list[str]:
    lines = []
    raw_lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    seen_vulns = set()
    seen_exploits = set()
    seen_risk = False
    seen_summary = False
    block_starters = ("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")

    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        if line.startswith("VULN:"):
            block = [line]
            j = i + 1
            while j < len(raw_lines) and not raw_lines[j].startswith(block_starters):
                block.append(raw_lines[j])
                j += 1
            key = normalized_key(*block)
            if key not in seen_vulns:
                seen_vulns.add(key)
                lines.extend(block)
            i = j
            continue
        if line.startswith("EXPLOIT:"):
            block = [line]
            j = i + 1
            while j < len(raw_lines) and not raw_lines[j].startswith(block_starters):
                block.append(raw_lines[j])
                j += 1
            key = normalized_key(*block)
            if key not in seen_exploits:
                seen_exploits.add(key)
                lines.extend(block)
            i = j
            continue
        if line.startswith("RISK_LEVEL:"):
            if not seen_risk:
                seen_risk = True
                lines.append(line)
            i += 1
            continue
        if line.startswith("SUMMARY:"):
            if not seen_summary:
                seen_summary = True
                lines.append(line)
            i += 1
            continue
        lines.append(line)
        i += 1

    return lines


def ai_summary_text(text: str) -> str:
    raw_lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    summary_lines = []
    capture = False
    block_starters = ("VULN:", "EXPLOIT:", "RISK_LEVEL:")

    for line in raw_lines:
        if line.startswith("SUMMARY:"):
            summary = line.replace("SUMMARY:", "", 1).strip()
            if summary:
                summary_lines.append(summary)
            capture = True
            continue
        if capture and line.startswith(block_starters):
            break
        if capture:
            summary_lines.append(line)

    return " ".join(summary_lines).strip()


def run_mode_from_raw_scan(raw_scan: str) -> tuple[str, str]:
    mode_match = re.search(r"(?im)^mode:\s*(.+)$", str(raw_scan or ""))
    tool_match = re.search(r"(?im)^tool:\s*(.+)$", str(raw_scan or ""))
    mode = mode_match.group(1).strip().lower() if mode_match else "full"
    tool = tool_match.group(1).strip() if tool_match else ""
    return mode, tool


def strip_run_mode_block(raw_scan: str) -> str:
    return re.sub(
        r"(?is)^\[METATRON RUN MODE\]\s*.*?\[/METATRON RUN MODE\]\s*",
        "",
        str(raw_scan or ""),
    ).strip()


def html_paragraphs(text: str) -> str:
    lines = [html_text(line.strip()) for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        return '<p style="color:#888">None recorded.</p>'
    return "".join(f"<p>{line}</p>" for line in lines)


def extract_har_cookie_evaluation(raw_scan: str) -> str:
    text = str(raw_scan or "")
    marker = "[HAR COOKIE CONSENT EVALUATION]"
    start = text.find(marker)
    if start == -1:
        return ""

    section = text[start:]
    next_header = re.search(r"\n={10,}\n\[ .+? OUTPUT \]\n={10,}", section)
    if next_header:
        section = section[:next_header.start()]

    lines = section.splitlines()
    captured = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if i > 0 and stripped.startswith("[") and stripped.endswith("]"):
            break
        if stripped.lower().startswith("har file:"):
            continue
        captured.append(line)

    return "\n".join(captured).strip()


def extract_smb_scanner_summary(raw_scan: str) -> str:
    text = extract_tool_output(raw_scan, "smb scanner") or str(raw_scan or "")
    marker_match = re.search(r"(?im)^\[SMB SCANNER SUMMARY\]\s*$", text)
    if not marker_match:
        return ""

    tail = text[marker_match.end():]
    next_section = re.search(
        r"(?im)^\[(?:SMB SCANNER JSON|SMB SCANNER RESULT FILES|SMB SCANNER ARTIFACTS|.+? OUTPUT)\]\s*$",
        tail,
    )
    if next_section:
        tail = tail[:next_section.start()]

    return (marker_match.group(0) + tail).strip()


def extract_subdomains(raw_scan: str) -> list[str]:
    subfinder = extract_tool_output(raw_scan, "subfinder")
    if not subfinder:
        return []

    marker = "[SUBFINDER SUBDOMAINS]"
    marker_index = subfinder.find(marker)
    if marker_index == -1:
        return []

    subfinder = subfinder[marker_index + len(marker):]
    next_section = re.search(r"(?im)^\[[^\]]+\]\s*$", subfinder)
    if next_section:
        subfinder = subfinder[:next_section.start()]

    subdomains = []
    seen = set()
    pattern = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    skip_prefixes = (
        "[!]",
        "[*]",
        "no subdomains found",
    )

    for raw_line in subfinder.splitlines():
        line = raw_line.strip()
        if not line or set(line) <= {"=", "-", "_"}:
            continue
        lower = line.lower()
        if lower.startswith(skip_prefixes):
            continue
        if not pattern.match(line):
            continue
        subdomain = line.lower()
        if subdomain in seen:
            continue
        seen.add(subdomain)
        subdomains.append(subdomain)

    return subdomains


def extract_subdomain_status(raw_scan: str) -> tuple[list[str], list[str]]:
    subfinder = extract_tool_output(raw_scan, "subfinder")
    all_subdomains = extract_subdomains(raw_scan)
    if not subfinder:
        return [], all_subdomains

    marker = "[SUBFINDER HTTPS 443 CHECK]"
    marker_index = subfinder.find(marker)
    if marker_index == -1:
        return [], all_subdomains

    section = subfinder[marker_index + len(marker):]
    next_section = re.search(r"(?im)^={10,}\s*$|^\[[^\]]+ OUTPUT\]\s*$", section)
    if next_section:
        section = section[:next_section.start()]

    active = []
    other = []
    current = ""
    seen_active = set()
    seen_other = set()
    pattern = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

    for raw_line in section.splitlines():
        line = raw_line.strip()
        upper = line.upper()
        if upper == "[ACTIVE SUBDOMAINS]":
            current = "active"
            continue
        if upper == "[OTHER POTENTIAL SUBDOMAINS]":
            current = "other"
            continue
        if not line or line.lower() == "none" or not pattern.match(line):
            continue

        subdomain = line.lower()
        if current == "active" and subdomain not in seen_active:
            seen_active.add(subdomain)
            active.append(subdomain)
        elif current == "other" and subdomain not in seen_other:
            seen_other.add(subdomain)
            other.append(subdomain)

    if not active and not other:
        return [], all_subdomains

    checked = seen_active | seen_other
    for subdomain in all_subdomains:
        if subdomain not in checked and subdomain not in seen_other:
            seen_other.add(subdomain)
            other.append(subdomain)

    return active, other


def extract_tool_output(raw_scan: str, tool_name: str) -> str:
    if not raw_scan:
        return ""

    lines = str(raw_scan).splitlines()
    capture = False
    captured = []
    header_pattern = re.compile(r"^\[\s*.+?\s+OUTPUT\s*\]$", re.IGNORECASE)
    wanted = tool_name.lower()

    for line in lines:
        stripped = line.strip()
        if header_pattern.match(stripped):
            if capture:
                break
            if wanted in stripped.lower():
                capture = True
                continue
        if capture:
            captured.append(line)

    while captured and (not captured[0].strip() or set(captured[0].strip()) <= {"="}):
        captured.pop(0)
    while captured and (not captured[-1].strip() or set(captured[-1].strip()) <= {"="}):
        captured.pop()

    return "\n".join(captured).strip()


def parse_sslyze_summary(raw_scan: str) -> list[tuple[str, str, str]]:
    sslyze = extract_tool_output(raw_scan, "sslyze")
    if not sslyze:
        return []

    rows = []
    current_section = "General"
    current_target = ""
    skipped_prefixes = (
        "usage:",
        "sslyze:",
        "python ",
        "[!]",
    )

    for raw_line in sslyze.splitlines():
        line = raw_line.strip()
        if not line or set(line) <= {"-", "=", "_"}:
            continue
        if line.lower().startswith(skipped_prefixes):
            rows.append(("Status", "Message", line))
            continue
        if line.startswith("SCAN RESULTS FOR "):
            current_target = line.replace("SCAN RESULTS FOR ", "").strip()
            rows.append(("Target", "Host", current_target))
            continue
        if line.endswith(":") and not line.startswith("*"):
            current_section = line.rstrip(":").strip()
            continue
        if line.startswith("* "):
            item = line[2:].strip()
            if ":" in item:
                label, detail = item.split(":", 1)
                rows.append((current_section, label.strip(), detail.strip()))
            else:
                rows.append((current_section, "Finding", item))
            continue
        if ":" in line:
            label, detail = line.split(":", 1)
            rows.append((current_section, label.strip(), detail.strip()))
            continue
        rows.append((current_section, current_target or "Detail", line))

    return rows


def group_sslyze_rows(rows: list[tuple[str, str, str]]) -> list[tuple[str, list[tuple[str, str]]]]:
    grouped = []
    index = {}
    for category, item, detail in rows:
        category = clean_cell(category, "General")
        item = clean_cell(item, "Detail")
        detail = clean_cell(detail)
        if category not in index:
            index[category] = []
            grouped.append((category, index[category]))
        index[category].append((item, detail))
    return grouped


def html_sslyze_report(rows: list[tuple[str, str, str]]) -> str:
    if not rows:
        return '<p style="color:#888">No SSLyze output recorded for this session.</p>'

    parts = ['<div class="ssl-report">']
    for category, items in group_sslyze_rows(rows):
        parts.append("<div class='ssl-group'>")
        parts.append(f"<h3>{html_text(category)}</h3>")
        parts.append("<dl>")
        for item, detail in items:
            parts.append(f"<dt>{html_text(item)}</dt><dd>{html_text(detail)}</dd>")
        parts.append("</dl></div>")
    parts.append("</div>")
    return "".join(parts)


def severity_html(severity: str) -> str:
    sev = clean_cell(severity, "unknown")
    sc = SEVERITY_COLORS.get(sev.lower(), "#7f8c8d")
    return f"<span style='color:{sc};font-weight:bold'>{html_text(sev.upper())}</span>"


def fetch_session(sl_no: int) -> dict:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    exploits = c.fetchall()
    c.execute("SELECT * FROM summary WHERE sl_no = %s ORDER BY id DESC LIMIT 1", (sl_no,))
    summary = c.fetchone()
    conn.close()
    return {"history": history, "vulns": vulns, "fixes": fixes,
            "exploits": exploits, "summary": summary}


def fetch_all_history():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def external_ai_instructions() -> str:
    return """You are reviewing raw Metatron reconnaissance data.
Identify only findings supported by the evidence. Do not invent ports, versions, CVEs, exploits, or impact.
If evidence is weak, mark severity LOW and say unconfirmed.

Return findings in this exact plain-text format:
VULN: <name> | SEVERITY: <critical|high|medium|low> | PORT: <port or n/a> | SERVICE: <service or n/a>
DESC: <evidence-based description>
FIX: <concrete mitigation>

EXPLOIT: <name> | TOOL: <tool or n/a> | PAYLOAD: <payload or description>
RESULT: <expected result or n/a>
NOTES: <evidence and caveats>

End with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence evidence-based summary>"""


def export_pre_ai_package_from_raw(target: str, raw_scan: str, output_dir: str, sl_no=None) -> tuple[str, str]:
    package_dir = os.path.join(output_dir, "pre_ai_packages")
    os.makedirs(package_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = safe_filename_part(target).replace(".", "_")
    prefix = f"metatron_pre_ai_SL{sl_no}_{safe}" if sl_no else f"metatron_pre_ai_{safe}_{timestamp}"
    json_path = os.path.join(package_dir, f"{prefix}.json")
    txt_path = os.path.join(package_dir, f"{prefix}.txt")

    package = {
        "format": "metatron-pre-ai-package-v1",
        "target": target,
        "sl_no": sl_no,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "instructions": external_ai_instructions(),
        "raw_recon": raw_scan,
    }

    with open(json_path, "w", encoding="utf-8", newline="") as f:
        json.dump(package, f, indent=2, ensure_ascii=False)

    with open(txt_path, "w", encoding="utf-8", newline="") as f:
        f.write("METATRON PRE-AI EVALUATION PACKAGE\n")
        f.write(f"Target: {target}\n")
        if sl_no:
            f.write(f"Session: SL# {sl_no}\n")
        f.write(f"Generated: {package['generated_at']}\n\n")
        f.write("[INSTRUCTIONS FOR EXTERNAL AI]\n")
        f.write(package["instructions"])
        f.write("\n\n[RAW RECON DATA]\n")
        f.write(raw_scan)

    return json_path, txt_path


def export_pre_ai_package(data: dict, output_dir: str) -> tuple[str, str]:
    h = data["history"]
    summary = data.get("summary")
    if not summary or not summary[2]:
        raise ValueError("No raw recon data is available for this session.")
    return export_pre_ai_package_from_raw(h[1], summary[2], output_dir, sl_no=h[0])


def export_html(data: dict, output_dir: str) -> str:
    h    = data["history"]
    sl   = h[0]
    tgt  = h[1]
    date = str(h[2])
    risk = data["summary"][4] if data["summary"] else "UNKNOWN"
    ai   = data["summary"][3] if data["summary"] else ""
    raw_scan = data["summary"][2] if data["summary"] else ""
    rc   = RISK_COLORS.get(risk.upper(), "#7f8c8d")
    vmap = vulnerability_map(data)
    vuln_display_rows = unique_vulnerability_rows(data, ai)
    fix_display_rows = unique_fix_rows(data, vmap)
    exploit_display_rows = unique_exploit_rows(data)
    executive_summary = ai_summary_text(ai)
    logo_src = report_logo_data_uri()
    run_mode, selected_tool = run_mode_from_raw_scan(raw_scan)
    single_tool_report = run_mode == "single_tool"
    display_raw_scan = strip_run_mode_block(raw_scan)
    cookie_compliance = extract_har_cookie_evaluation(display_raw_scan)
    active_subdomains, other_subdomains = extract_subdomain_status(display_raw_scan)
    cookie_compliance_section = f"""
<section>
  <h2>Cookie Compliance</h2>
  <pre class="scan-output">{html_text(cookie_compliance) if cookie_compliance else 'No HAR cookie consent evaluation recorded.'}</pre>
</section>
"""
    active_subdomain_items = "".join(
        f"<li><span>{idx}</span><code>{html_text(subdomain)}</code></li>"
        for idx, subdomain in enumerate(active_subdomains, start=1)
    )
    other_subdomain_items = "".join(
        f"<li><span>{idx}</span><code>{html_text(subdomain)}</code></li>"
        for idx, subdomain in enumerate(other_subdomains, start=1)
    )
    subdomains_section = f"""
<section>
  <h2>Subdomains</h2>
  <h3 class="subdomain-heading">Active Subdomains</h3>
  {'<ol class="subdomain-list">' + active_subdomain_items + '</ol>' if active_subdomains else '<p style="color:#888">No active subdomains recorded.</p>'}
  <h3 class="subdomain-heading">Other Potential Subdomains</h3>
  {'<ol class="subdomain-list">' + other_subdomain_items + '</ol>' if other_subdomains else '<p style="color:#888">No other potential subdomains recorded.</p>'}
</section>
"""

    os.makedirs(output_dir, exist_ok=True)
    safe = safe_filename_part(tgt).replace(".", "_")
    filename = os.path.join(output_dir, f"metatron_SL{sl}_{safe}.html")
    vuln_rows = ""
    for row_id, vuln_name, severity, port, service in vuln_display_rows:
        vuln_rows += (f"<tr><td>{html_text(row_id)}</td>"
                      f"<td>{html_text(vuln_name)}</td>"
                      f"<td>{severity_html(severity)}</td>"
                      f"<td>{html_text(port)}</td><td>{html_text(service)}</td></tr>")

    fix_rows = ""
    for vuln_id, vuln_name, severity, port, service, fix_text in fix_display_rows:
        fix_rows += (
            f"<tr><td>{html_text(vuln_id)}</td>"
            f"<td>{html_text(vuln_name)}</td>"
            f"<td>{severity_html(severity)}</td>"
            f"<td>{html_text(port)}</td>"
            f"<td>{html_text(service)}</td>"
            f"<td>{html_text(fix_text)}</td></tr>"
        )

    exp_rows = ""
    for exploit_id, exploit_name, tool_used, payload, result, notes in exploit_display_rows:
        exp_rows += (f"<tr><td>{html_text(exploit_id)}</td><td>{html_text(exploit_name)}</td>"
                     f"<td>{html_text(tool_used)}</td>"
                     f"<td>{html_text(payload)}</td>"
                     f"<td>{html_text(result)}</td>"
                     f"<td>{html_text(notes)}</td></tr>")

    if single_tool_report:
        meta_cards = f"""
  <div class="meta-card">
    <div class="label">Target</div>
    <div class="value">{html_text(tgt)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session</div>
    <div class="value">SL# {html_text(sl)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scan Date</div>
    <div class="value">{html_text(date)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Tool</div>
    <div class="value">{html_text(selected_tool or 'Single tool')}</div>
  </div>
"""
        selected_tool_lower = (selected_tool or "").lower()
        if "subfinder" in selected_tool_lower:
            report_sections = f"""
{subdomains_section}

<section>
  <h2>Scan Output</h2>
  <pre class="scan-output">{html_text(display_raw_scan) if display_raw_scan else 'No scan output recorded.'}</pre>
</section>
"""
        elif "har" in selected_tool_lower or "cookie consent" in selected_tool_lower:
            report_sections = f"""
<section>
  <h2>Tool Summary{f' - {html_text(selected_tool)}' if selected_tool else ''}</h2>
  <pre class="scan-output">{html_text(cookie_compliance) if cookie_compliance else 'No HAR cookie consent evaluation recorded.'}</pre>
</section>

<section>
  <h2>Scan Output</h2>
  <pre class="scan-output">{html_text(display_raw_scan) if display_raw_scan else 'No scan output recorded.'}</pre>
</section>
"""
        elif "smb scanner" in selected_tool_lower or "smbscanner" in selected_tool_lower or "smb_scanner" in selected_tool_lower:
            smb_summary = extract_smb_scanner_summary(display_raw_scan)
            report_sections = f"""
<section>
  <h2>Scan Output</h2>
  <pre class="scan-output">{html_text(smb_summary) if smb_summary else 'No SMB Scanner summary recorded.'}</pre>
</section>
"""
        else:
            report_sections = f"""
<section>
  <h2>Tool Summary{f' - {html_text(selected_tool)}' if selected_tool else ''}</h2>
  <div class="text-summary">
    {html_paragraphs(ai)}
  </div>
</section>

<section>
  <h2>Scan Output</h2>
  <pre class="scan-output">{html_text(display_raw_scan) if display_raw_scan else 'No scan output recorded.'}</pre>
</section>
"""
    else:
        meta_cards = f"""
  <div class="meta-card">
    <div class="label">Target</div>
    <div class="value">{html_text(tgt)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session</div>
    <div class="value">SL# {html_text(sl)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scan Date</div>
    <div class="value">{html_text(date)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Risk Level</div>
    <div class="value risk">{html_text(risk)}</div>
  </div>
"""
        report_sections = f"""
<section>
  <h2>Executive Summary</h2>
  <div class="exec-summary">
    {html_text(executive_summary) if executive_summary else '<span style="color:#888">No executive summary recorded.</span>'}
  </div>
</section>

<section>
  <h2>Vulnerabilities</h2>
  {'<table><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Port</th><th>Service</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>' if vuln_display_rows else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>Fixes &amp; Mitigations</h2>
  {'<table class="fix-table"><colgroup><col><col><col><col><col><col></colgroup><thead><tr><th>Vuln #</th><th>Vulnerability</th><th>Severity</th><th>Port</th><th>Service</th><th>Fix / Mitigation</th></tr></thead><tbody>' + fix_rows + '</tbody></table>' if fix_display_rows else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>Exploits Attempted</h2>
  {'<table class="exploit-table"><colgroup><col><col><col><col><col><col></colgroup><thead><tr><th>#</th><th>Exploit</th><th>Tool</th><th>Payload</th><th>Result</th><th>Notes</th></tr></thead><tbody>' + exp_rows + '</tbody></table>' if exploit_display_rows else '<p style="color:#888">None recorded.</p>'}
</section>

{cookie_compliance_section}

{subdomains_section}

<section>
  <h2>Scan Output</h2>
  <pre class="scan-output">{html_text(display_raw_scan) if display_raw_scan else 'No scan output recorded.'}</pre>
</section>
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Metatron Report — {html_text(tgt)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
html{{background:#0d0d0d;color:#e0e0e0}}
body{{font-family:'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;padding:30px}}
html,body,.container,.header,.meta-card,section,table,thead,tbody,tr,th,td,.scan-output,code,.detail-item{{
  -webkit-print-color-adjust:exact;
  print-color-adjust:exact;
  color-adjust:exact;
}}
.container{{max-width:960px;margin:auto}}
.header{{border-left:5px solid #c0392b;padding-left:16px;margin-bottom:30px}}
.report-logo{{display:block;width:420px;max-width:100%;height:96px;object-fit:cover;object-position:center}}
.header h1{{font-size:2.2em;color:#c0392b}}
.header p{{color:#888;font-size:.95em}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:30px}}
.meta-card{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:14px}}
.meta-card .label{{font-size:.75em;color:#888;text-transform:uppercase;margin-bottom:4px}}
.meta-card .value{{font-size:1.1em;font-weight:bold}}
.risk{{color:{rc}}}
section{{margin-bottom:30px}}
section h2{{font-size:1.2em;color:#c0392b;border-bottom:1px solid #333;
            padding-bottom:8px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:.88em}}
table.fix-table,table.exploit-table{{table-layout:fixed}}
table.fix-table col:nth-child(1){{width:8%}}
table.fix-table col:nth-child(2){{width:22%}}
table.fix-table col:nth-child(3){{width:14%}}
table.fix-table col:nth-child(4){{width:8%}}
table.fix-table col:nth-child(5){{width:14%}}
table.fix-table col:nth-child(6){{width:34%}}
table.exploit-table col:nth-child(1){{width:8%}}
table.exploit-table col:nth-child(2){{width:22%}}
table.exploit-table col:nth-child(3){{width:14%}}
table.exploit-table col:nth-child(4){{width:24%}}
table.exploit-table col:nth-child(5){{width:18%}}
table.exploit-table col:nth-child(6){{width:14%}}
th{{background:#1e1e1e;color:#aaa;text-align:left;padding:10px;
    font-size:.8em;text-transform:uppercase;border-bottom:2px solid #333}}
td{{padding:10px;border-bottom:1px solid #222;vertical-align:top;word-break:break-word}}
tr:hover td{{background:#1a1a1a}}
code{{background:#1e1e1e;padding:2px 6px;border-radius:3px;
      font-family:monospace;font-size:.85em;color:#e74c3c}}
.scan-output{{background:#111;border:1px solid #333;border-radius:6px;
              padding:16px;color:#ccc;font-family:Consolas,'Courier New',monospace;
              font-size:.78em;line-height:1.5;white-space:pre-wrap;word-break:break-word}}
.exec-summary{{background:#111;border:1px solid #333;border-left:5px solid #c0392b;border-radius:6px;
               padding:16px;font-size:.95em;line-height:1.7;color:#d7d7d7}}
.text-summary{{background:#111;border:1px solid #333;border-left:5px solid #c0392b;border-radius:6px;
               padding:16px;font-size:.95em;line-height:1.7;color:#d7d7d7}}
.text-summary p{{margin-bottom:8px}}
.detail-list{{display:grid;gap:12px;margin-top:14px}}
.detail-item{{background:#111;border:1px solid #333;border-radius:6px;padding:14px;line-height:1.6}}
.detail-item h3{{font-size:1em;margin-bottom:6px;color:#e0e0e0}}
.detail-item p{{font-size:.9em;color:#ccc;margin-bottom:6px}}
.subdomain-heading{{font-size:1em;color:#ddd;margin:16px 0 10px}}
.subdomain-list{{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:0;padding:0}}
.subdomain-list li{{display:grid;grid-template-columns:42px 1fr;align-items:center;background:#111;border:1px solid #333;border-radius:6px;padding:10px;min-width:0}}
.subdomain-list span{{color:#888;font-size:.8em}}
.subdomain-list code{{display:block;background:transparent;padding:0;color:#ddd;word-break:break-word}}
.footer{{text-align:center;color:#444;font-size:.78em;
         margin-top:40px;border-top:1px solid #222;padding-top:16px}}
a{{color:#555}}
@page{{size:A4;margin:12mm;background:#0d0d0d}}
@media print{{
  html,body{{background:#0d0d0d!important;color:#e0e0e0!important}}
  body{{padding:0!important}}
  .container{{max-width:none!important;margin:0!important;padding:0!important}}
  .meta-grid{{break-inside:avoid;page-break-inside:avoid}}
  .meta-card,tr{{break-inside:avoid;page-break-inside:avoid}}
  section,table{{break-inside:auto;page-break-inside:auto}}
  section h2{{break-after:avoid;page-break-after:avoid}}
  .scan-output{{background:#111!important;border-color:#333!important;color:#ccc!important;break-inside:auto;page-break-inside:auto}}
  .exec-summary{{background:#111!important;border-color:#333!important;border-left-color:#c0392b!important}}
  .text-summary{{background:#111!important;border-color:#333!important;border-left-color:#c0392b!important}}
  .detail-item{{break-inside:auto;page-break-inside:auto;background:#111!important;border-color:#333!important}}
  .subdomain-list{{grid-template-columns:1fr 1fr}}
  .subdomain-list li{{break-inside:avoid;page-break-inside:avoid;background:#111!important;border-color:#333!important}}
  thead{{display:table-header-group}}
  tfoot{{display:table-footer-group}}
  th{{background:#1e1e1e!important;color:#aaa!important}}
  td{{background:#0d0d0d;color:#e0e0e0}}
  tr:hover td{{background:transparent}}
  .meta-card{{background:#1a1a1a!important;border-color:#333!important}}
  code{{background:#1e1e1e!important;color:#e74c3c!important}}
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  {f'<img class="report-logo" src="{logo_src}" alt="PGS Metatron">' if logo_src else '<h1>PGS Metatron</h1>'}
</div>

<div class="meta-grid">
{meta_cards}
</div>

{report_sections}

<div class="footer">
  Generated by METATRON &mdash; For authorized use only.
</div>

</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8", newline="") as f:
        f.write(html)
    return filename


def export_menu(data: dict):
    if not data["history"]:
        print("[!] No session data to export.")
        return

    h   = data["history"]
    sl  = h[0]
    tgt = h[1]

    print(f"\n\033[33m{'─'*20} EXPORT SL#{sl} — {tgt} {'─'*20}\033[0m")
    print("  [1] HTML report")
    print("  [2] Pre-AI package")
    print("  [3] Back")
    print(f"\033[90m{'─'*60}\033[0m")

    try:
        choice = prompt("Export format: ")
    except MenuBack:
        return
    output_dir = default_reports_dir()
    os.makedirs(output_dir, exist_ok=True)

    if choice == "1":
        p = export_html(data, output_dir)
        print(f"\033[92m[+] HTML saved: {p}\033[0m")
    elif choice == "2":
        try:
            p1, p2 = export_pre_ai_package(data, output_dir)
            print(f"\033[92m[+] Pre-AI JSON : {p1}\033[0m")
            print(f"\033[92m[+] Pre-AI prompt: {p2}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Pre-AI export failed: {e}\033[0m")
    elif choice == "3":
        return
    else:
        print("\033[93m[!] Invalid choice.\033[0m")


if __name__ == "__main__":
    print("\n\033[91m    METATRON — Standalone HTML Report Exporter\033[0m")
    print("\033[90m    ─────────────────────────────────────\033[0m\n")

    rows = fetch_all_history()
    if not rows:
        print("[!] No sessions found in database.")
        exit()

    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()

    sl_input = prompt("Enter SL# to export: ")
    if not sl_input.isdigit():
        print("[!] Invalid SL#.")
        exit()

    data = fetch_session(int(sl_input))
    if not data["history"]:
        print(f"[!] SL# {sl_input} not found.")
        exit()

    export_menu(data)
