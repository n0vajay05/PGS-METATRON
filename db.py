#!/usr/bin/env python3
"""
METATRON - db.py
MariaDB connection + all read/write/edit/delete operations
Database: metatron
"""

import mysql.connector
from datetime import datetime
import json
import os
import ipaddress
from urllib.parse import urlparse
from credential_store import DB_PASSWORD_TARGET, read_secret, write_secret
from platform_utils import local_app_data_dir


_SCHEMA_COLUMNS_READY = False
CONFIG_PATH = local_app_data_dir() / "metatron_config.json"
DEFAULT_DB_SETTINGS = {
    "host": "localhost",
    "port": 3306,
    "user": "metatron",
    "password": "",
    "database": "metatron",
}


def fit_text(value, max_len: int) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def ip_primary_target(value) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    token = text.split()[0]
    parsed = urlparse(token)
    if parsed.scheme:
        host = parsed.hostname or ""
    else:
        host = token.split("/")[0].split(":")[0]
    host = host.strip().strip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return ""


def ensure_schema_columns(conn):
    """Widen older installs and add grouping fields for domain history."""
    global _SCHEMA_COLUMNS_READY
    if _SCHEMA_COLUMNS_READY:
        return

    c = conn.cursor()
    for statement in (
        "ALTER TABLE vulnerabilities MODIFY port VARCHAR(255)",
        "ALTER TABLE vulnerabilities MODIFY service VARCHAR(255)",
        "ALTER TABLE history ADD COLUMN primary_domain VARCHAR(255)",
        "ALTER TABLE history ADD COLUMN parent_target VARCHAR(255)",
        "ALTER TABLE history ADD COLUMN target_type VARCHAR(50) DEFAULT 'domain'",
    ):
        try:
            c.execute(statement)
        except mysql.connector.Error:
            pass
    try:
        c.execute("UPDATE history SET primary_domain = target WHERE primary_domain IS NULL OR primary_domain = ''")
        c.execute("UPDATE history SET target_type = 'domain' WHERE target_type IS NULL OR target_type = ''")
        c.execute("SELECT sl_no, target, primary_domain FROM history")
        for sl_no, target, primary_domain in c.fetchall():
            ip_primary = ip_primary_target(target)
            if ip_primary and primary_domain != ip_primary:
                c.execute(
                    "UPDATE history SET primary_domain = %s, parent_target = NULL, target_type = 'domain' WHERE sl_no = %s",
                    (ip_primary, sl_no),
                )
    except mysql.connector.Error:
        pass
    conn.commit()
    _SCHEMA_COLUMNS_READY = True


# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────

def _read_app_config() -> dict:
    try:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _write_app_config(data: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_database_settings() -> dict:
    data = _read_app_config()
    saved = data.get("database_settings", {})
    if not isinstance(saved, dict):
        saved = {}
    settings = {**DEFAULT_DB_SETTINGS, **saved}
    credential_password = read_secret(DB_PASSWORD_TARGET)
    if credential_password:
        settings["password"] = credential_password
    elif saved.get("password"):
        credential_password = str(saved.get("password") or "")
        try:
            write_secret(DB_PASSWORD_TARGET, credential_password, str(settings.get("user") or "metatron"))
            settings["password"] = credential_password
            saved.pop("password", None)
            data["database_settings"] = saved
            _write_app_config(data)
        except Exception:
            settings["password"] = credential_password

    env_map = {
        "host": "METATRON_DB_HOST",
        "port": "METATRON_DB_PORT",
        "user": "METATRON_DB_USER",
        "password": "METATRON_DB_PASSWORD",
        "database": "METATRON_DB_NAME",
    }
    for key, env_name in env_map.items():
        value = os.getenv(env_name)
        if value not in (None, ""):
            settings[key] = value

    try:
        settings["port"] = int(settings.get("port") or DEFAULT_DB_SETTINGS["port"])
    except (TypeError, ValueError):
        settings["port"] = DEFAULT_DB_SETTINGS["port"]
    return settings


def save_database_settings(
    host: str,
    port: int | str,
    user: str,
    password: str,
    database: str,
) -> dict:
    settings = {
        "host": str(host or DEFAULT_DB_SETTINGS["host"]).strip(),
        "port": int(port or DEFAULT_DB_SETTINGS["port"]),
        "user": str(user or DEFAULT_DB_SETTINGS["user"]).strip(),
        "database": str(database or DEFAULT_DB_SETTINGS["database"]).strip(),
    }
    if password:
        write_secret(DB_PASSWORD_TARGET, str(password), settings["user"])
    data = _read_app_config()
    data["database_settings"] = settings
    _write_app_config(data)
    return settings


def connect_with_settings(settings: dict):
    return mysql.connector.connect(
        host=settings.get("host", DEFAULT_DB_SETTINGS["host"]),
        port=int(settings.get("port") or DEFAULT_DB_SETTINGS["port"]),
        user=settings.get("user", DEFAULT_DB_SETTINGS["user"]),
        password=settings.get("password", DEFAULT_DB_SETTINGS["password"]),
        database=settings.get("database", DEFAULT_DB_SETTINGS["database"]),
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        use_unicode=True,
        connection_timeout=8,
    )


def test_database_settings(settings: dict | None = None) -> None:
    conn = connect_with_settings(settings or load_database_settings())
    conn.close()


def get_connection():
    """Returns a MariaDB connection using saved GUI settings."""
    return connect_with_settings(load_database_settings())


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str, primary_domain: str | None = None, parent_target: str | None = None, target_type: str = "domain") -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (target, scan_date, status, primary_domain, parent_target, target_type) VALUES (%s, %s, %s, %s, %s, %s)",
        (target, now, "active", primary_domain or target, parent_target, target_type)
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str) -> int:
    """Insert a vulnerability. Returns its id."""
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    sql = """
        INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    values = (
        sl_no,
        str(vuln_name or ""),
        fit_text(severity, 50),
        fit_text(port, 255),
        fit_text(service, 255),
        str(description or ""),
    )
    try:
        c.execute(sql, values)
    except mysql.connector.Error as e:
        if "Data too long" not in str(e):
            conn.close()
            raise
        legacy_values = (
            sl_no,
            str(vuln_name or ""),
            fit_text(severity, 50),
            fit_text(port, 20),
            fit_text(service, 100),
            str(description or ""),
        )
        c.execute(sql, legacy_values)
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (%s, %s, %s, %s)
    """, (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO exploits_attempted 
        (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        sl_no,
        str(exploit_name or "")[:1000],
        str(tool_used  or "")[:500],
        str(payload    or ""),
        str(result     or "")[:2000],
        str(notes      or "")
    ))
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Insert the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (%s, %s, %s, %s, %s)
    """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_domain_history():
    """Return one row per primary domain."""
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    c.execute("""
        SELECT
            primary_domain,
            MAX(scan_date) AS last_scan,
            COUNT(*) AS scan_count,
            SUM(CASE WHEN target_type = 'subdomain' THEN 1 ELSE 0 END) AS subdomain_scan_count
        FROM history
        GROUP BY primary_domain
        ORDER BY last_scan DESC
    """)
    rows = c.fetchall()
    conn.close()
    return rows


def get_scans_for_domain(primary_domain: str):
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    c.execute("""
        SELECT sl_no, target, scan_date, status, target_type, parent_target
        FROM history
        WHERE primary_domain = %s
        ORDER BY scan_date DESC, sl_no DESC
    """, (primary_domain,))
    rows = c.fetchall()
    conn.close()
    return rows


def has_scans_for_domain(primary_domain: str) -> bool:
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM history WHERE primary_domain = %s", (primary_domain,))
    count = c.fetchone()[0]
    conn.close()
    return count > 0


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    ensure_schema_columns(conn)
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

    return {
        "history":   history,
        "vulns":     vulns,
        "fixes":     fixes,
        "exploits":  exploits,
        "summary":   summary
    }


def get_vulnerabilities(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_exploits(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    if field == "severity":
        value = fit_text(value, 50)
    elif field == "port":
        value = fit_text(value, 255)
    elif field == "service":
        value = fit_text(value, 255)
    c.execute(
        f"UPDATE vulnerabilities SET {field} = %s WHERE id = %s",
        (value, vuln_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = %s WHERE id = %s", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE exploits_attempted SET {field} = %s WHERE id = %s",
        (value, exploit_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE summary SET risk_level = %s WHERE sl_no = %s", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = %s", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = %s", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploits_attempted WHERE id = %s", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = %s", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_ai_results(sl_no: int):
    """Delete AI-derived findings while keeping the scan history row intact."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes              WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM vulnerabilities    WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM summary            WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Previous AI analysis cleared for SL#{sl_no}.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all 5 tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


def delete_domain_sessions(primary_domain: str):
    """Delete every scan linked to a primary domain."""
    conn = get_connection()
    ensure_schema_columns(conn)
    c = conn.cursor()
    c.execute("SELECT sl_no FROM history WHERE primary_domain = %s", (primary_domain,))
    sl_numbers = [row[0] for row in c.fetchall()]
    for sl_no in sl_numbers:
        c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Deleted {len(sl_numbers)} scan(s) for domain {primary_domain}.")


def delete_all_sessions():
    """Wipe all saved scan sessions and their linked records."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes")
    c.execute("DELETE FROM exploits_attempted")
    c.execute("DELETE FROM vulnerabilities")
    c.execute("DELETE FROM summary")
    c.execute("DELETE FROM history")
    conn.commit()
    conn.close()
    print("[+] All saved reports deleted from all tables.")


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: metatron")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
