#!/usr/bin/env python3
"""
METATRON - metatron_gui.py
Native Windows GUI for the Metatron scanning workflow.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import re
import mysql.connector.plugins.mysql_native_password
import mysql.connector.plugins.caching_sha2_password
import mysql.connector.plugins.sha256_password
import queue
import subprocess
import sys
import threading
import traceback
import webbrowser
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import (
    BOTH,
    END,
    LEFT,
    RIGHT,
    VERTICAL,
    BooleanVar,
    StringVar,
    Tk,
    Toplevel,
    filedialog,
    simpledialog,
    messagebox,
)
from tkinter import ttk

import llm
from db import (
    create_session,
    delete_ai_results,
    delete_all_sessions,
    delete_domain_sessions,
    delete_exploit,
    delete_fix,
    delete_full_session,
    delete_vulnerability,
    edit_exploit,
    edit_fix,
    edit_summary_risk,
    edit_vulnerability,
    get_domain_history,
    get_exploits,
    get_fixes,
    get_scans_for_domain,
    get_session,
    get_vulnerabilities,
    has_scans_for_domain,
    load_database_settings,
    save_exploit,
    save_fix,
    save_summary,
    save_vulnerability,
    save_database_settings,
    test_database_settings,
)
from export import export_html, export_pre_ai_package, safe_filename_part
from llm import (
    analyse_target,
    parse_exploits,
    parse_risk_level,
    parse_summary,
    parse_vulnerabilities,
    run_mode_from_raw_scan,
)
from metatron import (
    auto_export_pre_ai_package,
    discovered_subdomains_for_domain,
    is_single_raw_only_scan,
    normalize_target_host,
    primary_domain_for_target,
    remove_subfinder_from_ai_input,
    save_ai_result,
    save_raw_tool_result,
    single_tool_name,
    target_type_for_target,
)
from platform_utils import database_service_hint, default_reports_dir, local_app_data_dir, resource_path
from tools import (
    INTERNAL_TOOLS_MENU,
    TOOLS_MENU,
    format_recon_for_llm,
    is_scan_abort,
    run_builtin_web_checks,
    run_default_recon,
    run_scan_step,
)


APP_TITLE = "PGS Metatron"
LOG_TRIM_LINES = 1500
SPLASH_DELAY_MS = 2000
SINGLE_INSTANCE_MUTEX_NAME = "Local\\PGS-Metatron-GUI"
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
GUI_STATE_PATH = local_app_data_dir() / "metatron_gui_state.json"
CRASH_LOG_PATH = local_app_data_dir() / "metatron_crash.log"
SINGLE_INSTANCE_MUTEX_HANDLE = None
SIDEBAR_DEFAULT_WIDTH = 360
SIDEBAR_MIN_WIDTH = 260
NETWORK_INFO_REFRESH_MS = 5000


GUI_TOOLS = OrderedDict((key, value) for key, value in TOOLS_MENU.items())
GUI_TOOLS["web"] = ("Website Vulnerability Scanner", run_builtin_web_checks)
GUI_EXTERNAL_TOOLS = GUI_TOOLS
GUI_INTERNAL_TOOLS = OrderedDict((key, value) for key, value in INTERNAL_TOOLS_MENU.items())
GUI_ALL_TOOLS = OrderedDict(list(GUI_EXTERNAL_TOOLS.items()) + list(GUI_INTERNAL_TOOLS.items()))
BLANK_TARGET_INTERNAL_TOOLS = {"ad_recon", "pingcastle"}
NMAP_CUSTOM_PRESETS = {
    "quiet": "-sS -Pn -T1 --top-ports 100 --open",
    "loud": "-sV -sC -T4 --open",
}
NMAP_EXTERNAL_FLAGS = "-sV -sC -T4 --open"


def write_crash_log(title: str, details: str):
    try:
        CRASH_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CRASH_LOG_PATH.open("a", encoding="utf-8", newline="") as f:
            f.write(f"\n[{datetime.now().isoformat(timespec='seconds')}] {title}\n")
            f.write(details.rstrip() + "\n")
    except Exception:
        pass


def install_exception_logging():
    def log_unhandled(exc_type, exc_value, exc_traceback):
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        write_crash_log("Unhandled exception", details)

    sys.excepthook = log_unhandled

    if hasattr(threading, "excepthook"):
        def log_thread_exception(args):
            details = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
            write_crash_log(f"Unhandled thread exception in {getattr(args.thread, 'name', 'thread')}", details)

        threading.excepthook = log_thread_exception


class QueueWriter:
    def __init__(self, output_queue: queue.Queue):
        self.output_queue = output_queue

    def write(self, text: str) -> int:
        if text:
            self.output_queue.put(("log", text))
        return len(text)

    def flush(self) -> None:
        return None


class HoverTooltip:
    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)
        widget.bind("<ButtonPress>", self.hide)

    def show(self, _event=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self.tip,
            text=self.text,
            justify="left",
            background="#111827",
            foreground="#ffffff",
            borderwidth=1,
            relief="solid",
            padx=8,
            pady=6,
            font=("Segoe UI", 9),
        )
        label.pack()

    def hide(self, _event=None):
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None


def grid_with_vertical_scrollbar(widget, row: int, column: int = 0, **grid_options):
    parent = widget.master
    scrollbar = ttk.Scrollbar(parent, orient=VERTICAL, command=widget.yview)
    widget.grid(row=row, column=column, **grid_options)
    scrollbar.grid(
        row=row,
        column=column + 1,
        sticky="ns",
        pady=grid_options.get("pady", 0),
    )
    widget.configure(yscrollcommand=scrollbar.set)
    return scrollbar


class TextDialog(Toplevel):
    def __init__(self, parent, title: str, text: str):
        super().__init__(parent)
        self.title(title)
        self.geometry("860x560")
        self.minsize(620, 360)
        self.transient(parent)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        frame = ttk.Frame(self, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        text_widget = tk_text(frame, wrap="word")
        grid_with_vertical_scrollbar(text_widget, 0, 0, sticky="nsew")
        text_widget.insert("1.0", text or "")
        text_widget.configure(state="disabled")

        ttk.Button(frame, text="Close", command=self.destroy).grid(row=1, column=0, sticky="e", pady=(8, 0))


def tk_text(parent, **kwargs):
    import tkinter as tk

    return tk.Text(
        parent,
        borderwidth=1,
        relief="solid",
        padx=8,
        pady=8,
        font=("Consolas", 10),
        **kwargs,
    )


class EditValueDialog(Toplevel):
    def __init__(self, parent, title: str, fields: list[tuple[str, str, bool]]):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.resizable(True, True)
        self.result: dict[str, str] | None = None
        self.widgets = {}

        frame = ttk.Frame(self, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        for row, (name, value, multiline) in enumerate(fields):
            ttk.Label(frame, text=name).grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=4)
            if multiline:
                widget = tk_text(frame, height=8, wrap="word")
                widget.insert("1.0", value or "")
            else:
                var = StringVar(value=value or "")
                widget = ttk.Entry(frame, textvariable=var)
                widget._metatron_var = var
            if multiline:
                grid_with_vertical_scrollbar(widget, row, 1, sticky="ew", pady=4)
            else:
                widget.grid(row=row, column=1, sticky="ew", pady=4)
            self.widgets[name] = (widget, multiline)

        buttons = ttk.Frame(frame)
        buttons.grid(row=len(fields), column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side=RIGHT)
        ttk.Button(buttons, text="Save", command=self._save).pack(side=RIGHT, padx=(0, 8))

        self.update_idletasks()
        width = max(520, self.winfo_reqwidth())
        height = min(620, max(180, self.winfo_reqheight()))
        self.geometry(f"{width}x{height}")

    def _save(self):
        values = {}
        for name, (widget, multiline) in self.widgets.items():
            if multiline:
                values[name] = widget.get("1.0", "end-1c")
            else:
                values[name] = widget._metatron_var.get()
        self.result = values
        self.destroy()


class ScanStopped(Exception):
    pass


class MetatronApp(Tk):
    def __init__(self):
        super().__init__(className="Metatron")
        self.withdraw()
        self.title(APP_TITLE)
        self.gui_state = self._load_gui_state()
        self.geometry(self.gui_state.get("geometry", "1180x760"))
        self.minsize(980, 640)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.icon_image_ref = None
        self.window_icon_path = resource_path("assets", "pgs_metatron_icon.ico")
        self._apply_window_icon()
        self.brand_image_ref = None
        self.splash_image_ref = None
        self.startup_splash = None

        self.output_queue: queue.Queue = queue.Queue()
        self.worker_thread: threading.Thread | None = None
        self.stop_requested = threading.Event()
        self.closing = False
        self.network_info_refreshing = False
        self.selected_domain = ""
        self.selected_domain_target = ""
        self.context_domain = ""
        self.context_parent_target = ""
        self.context_domain_item = ""
        self.context_session_id = None
        self.domain_item_map: dict[str, dict[str, str]] = {}
        self.domain_scan_marks: dict[str, int] = {}
        self.suppressed_subdomains: dict[str, set[str]] = {
            domain: set(items)
            for domain, items in self.gui_state.get("suppressed_subdomains", {}).items()
            if isinstance(items, list)
        }
        self.manual_subdomains: dict[str, set[str]] = {
            domain: set(items)
            for domain, items in self.gui_state.get("manual_subdomains", {}).items()
            if isinstance(items, list)
        }
        self.manual_subdomain_children: dict[str, set[str]] = {
            parent: set(items)
            for parent, items in self.gui_state.get("manual_subdomain_children", {}).items()
            if isinstance(items, list)
        }
        self.selected_session = None
        self.finding_index: dict[str, tuple[str, int]] = {}
        self.report_tabs: dict[str, dict] = {}
        self.selected_report_tab = ""
        self.html_reports_added = False
        self.notebook_tabs: dict[str, ttk.Frame] = {}
        self.notebook_tab_keys: dict[str, str] = {}
        self.dragged_notebook_tab = ""
        self.tool_vars: dict[str, BooleanVar] = {}
        self.tool_widgets: dict[str, dict] = {}
        self.nmap_custom_preset_vars: dict[str, BooleanVar] = {}
        self.nmap_custom_preset_widgets: list[tk.Checkbutton] = []
        self.checkbox_images: dict[str, tk.PhotoImage] = {}

        llm.apply_ai_settings(llm.load_ai_settings())

        self._configure_style()
        self._create_checkbox_images()
        self._show_startup_splash()
        self._build_menu()
        self._build_layout()
        self._poll_queue()
        self.refresh_all()
        self.refresh_network_info()
        self._set_status("Ready.")
        self.after(250, self._apply_window_icon)
        self.after(1000, self._apply_window_icon)
        self.after(SPLASH_DELAY_MS, self._finish_startup_splash)

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background="#f6f7f9")
        style.configure("TLabel", background="#f6f7f9", foreground="#1f2937")
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#111827")
        style.configure("Muted.TLabel", foreground="#6b7280")
        style.configure("Info.TLabelframe", background="#f6f7f9")
        style.configure("Info.TLabelframe.Label", background="#f6f7f9", foreground="#1f2937")
        style.configure("Status.TLabel", background="#111827", foreground="#ffffff", padding=(12, 8), font=("Segoe UI", 10))
        style.configure("Accent.TButton", padding=(10, 6))
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Vertical.TScrollbar", width=12, arrowsize=10)

    def _create_checkbox_images(self):
        try:
            from PIL import Image, ImageDraw, ImageTk

            def make(checked: bool):
                image = Image.new("RGBA", (24, 24), (0, 0, 0, 0))
                draw = ImageDraw.Draw(image)
                draw.rounded_rectangle((3, 3, 21, 21), radius=3, fill="#ffffff", outline="#4b5563", width=2)
                if checked:
                    draw.rounded_rectangle((7, 7, 17, 17), radius=2, fill="#c0392b")
                return ImageTk.PhotoImage(image)

            self.checkbox_images["unchecked"] = make(False)
            self.checkbox_images["checked"] = make(True)
        except Exception:
            self.checkbox_images = {}

    def _apply_window_icon(self):
        if self.window_icon_path.exists():
            try:
                self.iconbitmap(default=str(self.window_icon_path))
                self.iconbitmap(str(self.window_icon_path))
                return
            except Exception:
                pass

        icon_png = resource_path("assets", "metatron_icon.png")
        if icon_png.exists() and self.icon_image_ref is None:
            try:
                self.icon_image_ref = tk.PhotoImage(file=str(icon_png))
                self.iconphoto(True, self.icon_image_ref)
            except Exception:
                self.icon_image_ref = None

    def _create_brand_widget(self, parent):
        image_path = resource_path("assets", "pgs-metatron.png")
        if image_path.exists():
            try:
                from PIL import Image, ImageTk

                image = Image.open(image_path)
                image.thumbnail((338, 190), Image.Resampling.LANCZOS)
                self.brand_image_ref = ImageTk.PhotoImage(image)
                return ttk.Label(parent, image=self.brand_image_ref)
            except Exception as e:
                self._append_log(f"\nCould not load brand image: {e}\n") if hasattr(self, "log_text") else None
        return ttk.Label(parent, text="Metatron", style="Header.TLabel")

    def _show_startup_splash(self):
        image_path = resource_path("assets", "pgs-metatron-logo.png")
        splash = Toplevel(self)
        self.startup_splash = splash
        splash.overrideredirect(True)
        splash.configure(background="#050505")
        try:
            splash.attributes("-topmost", True)
        except Exception:
            pass

        try:
            from PIL import Image, ImageTk

            image = Image.open(image_path)
            image.thumbnail((720, 405), Image.Resampling.LANCZOS)
            self.splash_image_ref = ImageTk.PhotoImage(image)
            label = tk.Label(splash, image=self.splash_image_ref, borderwidth=0, background="#050505")
            width = self.splash_image_ref.width()
            height = self.splash_image_ref.height()
        except Exception:
            label = tk.Label(
                splash,
                text="PGS METATRON",
                font=("Segoe UI", 28, "bold"),
                foreground="#ff1f1f",
                background="#050505",
                padx=48,
                pady=28,
            )
            width = 520
            height = 150

        label.pack(fill=BOTH, expand=True)
        self.update_idletasks()
        screen_w = splash.winfo_screenwidth()
        screen_h = splash.winfo_screenheight()
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2)
        splash.geometry(f"{width}x{height}+{x}+{y}")
        splash.lift()
        try:
            self.update()
        except Exception:
            pass

    def _finish_startup_splash(self):
        splash = getattr(self, "startup_splash", None)
        if splash is not None:
            try:
                splash.destroy()
            except Exception:
                pass
            self.startup_splash = None
        self.deiconify()
        self._start_full_screen()
        self.lift()
        self.focus_force()
        self._apply_window_icon()

    def _load_gui_state(self) -> dict:
        try:
            if GUI_STATE_PATH.exists():
                data = json.loads(GUI_STATE_PATH.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
        return {}

    def _save_gui_state(self):
        state = {
            "geometry": self.geometry(),
            "sidebar_width": self._safe_sashpos(getattr(self, "outer_pane", None), 0),
            "main_sash": self._safe_sashpos(getattr(self, "main_pane", None), 0),
            "left_sash": self._safe_sashpos(getattr(self, "left_pane", None), 0),
            "session_details_width": self._safe_widget_size(getattr(self, "right_panel", None), "width"),
            "sessions_window_height": self._safe_widget_size(getattr(self, "session_panel", None), "height"),
            "notebook_tab_order": self._current_notebook_tab_order(),
            "manual_subdomains": {
                domain: sorted(items)
                for domain, items in self.manual_subdomains.items()
                if items
            },
            "manual_subdomain_children": {
                parent: sorted(items)
                for parent, items in self.manual_subdomain_children.items()
                if items
            },
            "suppressed_subdomains": {
                domain: sorted(items)
                for domain, items in self.suppressed_subdomains.items()
                if items
            },
        }
        try:
            GUI_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            GUI_STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except Exception as e:
            self._append_log(f"\nCould not save GUI state: {e}\n")

    def _safe_sashpos(self, pane, index: int):
        try:
            return pane.sashpos(index) if pane else None
        except Exception:
            return None

    def _safe_widget_size(self, widget, dimension: str):
        try:
            if not widget:
                return None
            value = widget.winfo_width() if dimension == "width" else widget.winfo_height()
            return value if value > 1 else None
        except Exception:
            return None

    def _start_full_screen(self):
        try:
            self.state("zoomed")
        except Exception:
            try:
                self.attributes("-zoomed", True)
            except Exception:
                pass

    def on_close(self):
        self.closing = True
        self._save_gui_state()
        self.destroy()

    def report_callback_exception(self, exc_type, exc_value, exc_traceback):
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        write_crash_log("Tk callback exception", details)
        try:
            self._append_log("\n[!] GUI callback error was written to the crash log.\n")
            self._set_status(f"GUI error logged: {CRASH_LOG_PATH}")
        except Exception:
            pass

    def _build_menu(self):
        import tkinter as tk

        menu = tk.Menu(self)
        self.config(menu=menu)

        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="Refresh", command=self.refresh_all)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menu.add_cascade(label="File", menu=file_menu)

        scan_menu = tk.Menu(menu, tearoff=0)
        scan_menu.add_command(label="Start Scan", command=self.start_scan)
        scan_menu.add_command(label="Select All Tools", command=lambda: self.set_all_tools(True))
        scan_menu.add_command(label="Clear Tool Selection", command=lambda: self.set_all_tools(False))
        menu.add_cascade(label="Scan", menu=scan_menu)

        history_menu = tk.Menu(menu, tearoff=0)
        history_menu.add_command(label="Export HTML Report", command=self.export_selected_html)
        history_menu.add_command(label="Export Pre-AI Package", command=self.export_selected_pre_ai)
        history_menu.add_command(label="Import External Findings", command=self.import_external_findings)
        history_menu.add_command(label="Rerun AI Analysis", command=self.rerun_ai_analysis)
        history_menu.add_separator()
        history_menu.add_command(label="Delete Selected Finding", command=self.delete_selected_finding)
        history_menu.add_command(label="Delete Selected Session", command=self.delete_selected_session)
        history_menu.add_command(label="Delete Selected Domain", command=self.delete_selected_domain)
        history_menu.add_command(label="Delete All Saved Reports", command=self.delete_everything)
        menu.add_cascade(label="History", menu=history_menu)

        model_menu = tk.Menu(menu, tearoff=0)
        model_menu.add_command(label="AI Model Settings", command=self.select_model)
        model_menu.add_command(label="Database Settings", command=self.check_database)
        menu.add_cascade(label="Tools", menu=model_menu)

        help_menu = tk.Menu(menu, tearoff=0)
        help_menu.add_command(label="Open Reports Folder", command=self.open_reports_folder)
        help_menu.add_command(label="About", command=self.show_about)
        menu.add_cascade(label="Help", menu=help_menu)

    def _build_layout(self):
        outer = ttk.Frame(self, padding=10)
        outer.pack(fill=BOTH, expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)

        outer_pane = ttk.PanedWindow(outer, orient="horizontal")
        self.outer_pane = outer_pane
        outer_pane.grid(row=0, column=0, sticky="nsew")

        sidebar_shell = ttk.Frame(outer_pane, width=SIDEBAR_DEFAULT_WIDTH)
        self.sidebar_shell = sidebar_shell
        sidebar_shell.grid_propagate(False)
        sidebar_shell.columnconfigure(0, weight=1)
        sidebar_shell.rowconfigure(0, weight=1)
        outer_pane.add(sidebar_shell, weight=0)

        sidebar = ttk.Frame(sidebar_shell)
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        sidebar.columnconfigure(0, weight=1)

        self._create_brand_widget(sidebar).grid(row=0, column=0, sticky="w")
        self.model_label = ttk.Label(sidebar, text="", style="Muted.TLabel")
        self.model_label.grid(row=1, column=0, sticky="w", pady=(2, 14))

        ttk.Label(sidebar, text="Target").grid(row=2, column=0, sticky="w")
        self.target_var = StringVar()
        self.target_entry = ttk.Entry(sidebar, textvariable=self.target_var)
        self.target_entry.grid(row=3, column=0, sticky="ew", pady=(2, 10))
        self.target_entry.bind("<Return>", lambda _event: self.start_scan())

        self.full_scan_var = BooleanVar(value=False)
        self.full_scan_check = self._create_large_checkbox(
            sidebar,
            "Full Scan (External and Web)",
            self.full_scan_var,
            self._sync_tool_state,
        )
        self.full_scan_check.grid(
            row=4, column=0, sticky="ew", pady=(0, 6)
        )

        tools_frame = ttk.LabelFrame(sidebar, text="Tools (External)")
        tools_frame.grid(row=5, column=0, sticky="ew")
        tools_frame.columnconfigure(0, weight=1)
        for row, (key, (name, _)) in enumerate(GUI_EXTERNAL_TOOLS.items()):
            var = BooleanVar(value=False)
            self.tool_vars[key] = var
            self._create_tool_checkbox(tools_frame, key, name, row)

        internal_tools_frame = ttk.LabelFrame(sidebar, text="Tools (Internal)")
        internal_tools_frame.grid(row=6, column=0, sticky="ew", pady=(8, 0))
        internal_tools_frame.columnconfigure(0, weight=1)
        for row, (key, (name, _)) in enumerate(GUI_INTERNAL_TOOLS.items()):
            var = BooleanVar(value=False)
            self.tool_vars[key] = var
            self._create_tool_checkbox(internal_tools_frame, key, name, row)

        self.save_raw_only_var = BooleanVar(value=False)
        self.save_raw_only_check = self._create_large_checkbox(
            sidebar,
            "Save raw output only",
            self.save_raw_only_var,
        )
        self.save_raw_only_check.grid(
            row=7, column=0, sticky="ew", pady=(10, 4)
        )

        button_row = ttk.Frame(sidebar)
        button_row.grid(row=8, column=0, sticky="ew", pady=(8, 6))
        button_row.columnconfigure(0, weight=1)
        button_row.columnconfigure(1, weight=1)
        ttk.Button(button_row, text="Start Scan", style="Accent.TButton", command=self.start_scan).grid(
            row=0, column=0, sticky="ew", padx=(0, 4)
        )
        ttk.Button(button_row, text="Refresh", command=self.refresh_all).grid(row=0, column=1, sticky="ew", padx=(4, 0))

        ttk.Separator(sidebar).grid(row=9, column=0, sticky="ew", pady=12)
        ttk.Button(sidebar, text="AI Model Settings", command=self.select_model).grid(row=10, column=0, sticky="ew")
        ttk.Button(sidebar, text="Database Settings", command=self.check_database).grid(row=11, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(sidebar, text="Open Reports Folder", command=self.open_reports_folder).grid(
            row=12, column=0, sticky="ew", pady=(6, 0)
        )

        self.progress = ttk.Progressbar(sidebar, mode="indeterminate")
        self.progress.grid(row=13, column=0, sticky="ew", pady=(16, 4))
        self.stop_scan_button = ttk.Button(sidebar, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_scan_button.grid(row=14, column=0, sticky="ew", pady=(4, 4))
        self.scan_progress_label_var = StringVar(value="")
        ttk.Label(sidebar, textvariable=self.scan_progress_label_var, style="Muted.TLabel").grid(
            row=15,
            column=0,
            sticky="w",
            pady=(0, 4),
        )
        content = ttk.Frame(outer_pane)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)
        outer_pane.add(content, weight=1)

        main = ttk.PanedWindow(content, orient="horizontal")
        self.main_pane = main
        main.grid(row=0, column=0, sticky="nsew")

        left = ttk.Frame(main)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        main.add(left, weight=2)

        right = ttk.Frame(main)
        self.right_panel = right
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        main.add(right, weight=3)

        left_pane = ttk.PanedWindow(left, orient="vertical")
        self.left_pane = left_pane
        left_pane.grid(row=0, column=0, sticky="nsew")

        domain_panel = ttk.Frame(left_pane)
        self.domain_panel = domain_panel
        domain_panel.columnconfigure(0, weight=1)
        domain_panel.rowconfigure(1, weight=1)
        left_pane.add(domain_panel, weight=1)

        session_panel = ttk.Frame(left_pane)
        self.session_panel = session_panel
        session_panel.columnconfigure(0, weight=1)
        session_panel.rowconfigure(1, weight=1)
        left_pane.add(session_panel, weight=1)

        ttk.Label(domain_panel, text="Domains", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.domain_tree = ttk.Treeview(
            domain_panel,
            columns=("last_scan", "scans", "subdomains"),
            show=("tree", "headings"),
            selectmode="extended",
            height=8,
        )
        for col, label, width in (
            ("last_scan", "Last scan", 140),
            ("scans", "Scans", 60),
            ("subdomains", "Subdomains", 130),
        ):
            self.domain_tree.heading(col, text=label)
            self.domain_tree.column(col, width=width, anchor="w")
        self.domain_tree.heading("#0", text="Domain")
        self.domain_tree.column("#0", width=230, anchor="w", stretch=True)
        grid_with_vertical_scrollbar(self.domain_tree, 1, 0, sticky="nsew", pady=(4, 4))
        self.domain_tree.bind("<<TreeviewSelect>>", self._on_domain_select)
        self.domain_tree.bind("<Button-1>", self._on_domain_click, add="+")
        self.domain_tree.bind("<Double-1>", self._on_domain_double_click)
        self.domain_tree.bind("<Button-3>", self._on_domain_right_click)

        domain_actions = ttk.Frame(domain_panel)
        domain_actions.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        ttk.Button(domain_actions, text="Delete Domain", command=self.delete_selected_domain).pack(side=LEFT)
        ttk.Button(domain_actions, text="Delete Subdomains", command=self.delete_selected_subdomains).pack(side=LEFT, padx=(6, 0))
        ttk.Button(
            domain_actions,
            text="Scan Domain With Selected Tools",
            command=self.start_scan_for_selected_domain,
        ).pack(side=LEFT, padx=(6, 0))

        self.domain_notice_var = StringVar(value="")
        ttk.Label(domain_panel, textvariable=self.domain_notice_var, style="Muted.TLabel").grid(
            row=3,
            column=0,
            sticky="w",
            pady=(0, 2),
        )

        self.domain_context_menu = tk.Menu(self, tearoff=0)
        self.domain_context_menu.add_command(label="Manually add a subdomain", command=self.manually_add_subdomain)
        self.domain_context_menu.add_command(label="Copy Domain Name", command=self.copy_context_domain_name)
        self.domain_context_menu.add_command(label="Scan Domain With Selected Tools", command=self.scan_context_domain_item)
        self.domain_context_menu.add_command(label="Delete", command=self.delete_context_domain_item)

        self.session_context_menu = tk.Menu(self, tearoff=0)
        self.session_context_menu.add_command(label="Open HTML Report", command=self.open_context_session_html_report)
        self.session_context_menu.add_command(label="Run new AI model analysis", command=self.run_context_session_ai_analysis)

        ttk.Label(session_panel, text="Sessions", style="Header.TLabel").grid(row=0, column=0, sticky="w")
        self.session_tree = ttk.Treeview(
            session_panel,
            columns=("sl_no", "target", "date", "type", "status"),
            show="headings",
            selectmode="browse",
            height=10,
        )
        for col, label, width in (
            ("sl_no", "SL#", 52),
            ("target", "Target", 190),
            ("date", "Date", 145),
            ("type", "Type", 80),
            ("status", "Status", 80),
        ):
            self.session_tree.heading(col, text=label)
            self.session_tree.column(col, width=width, anchor="w")
        grid_with_vertical_scrollbar(self.session_tree, 1, 0, sticky="nsew", pady=(4, 4))
        self.session_tree.bind("<<TreeviewSelect>>", self._on_session_select)
        self.session_tree.bind("<Button-3>", self._on_session_right_click)

        session_actions = ttk.Frame(session_panel)
        session_actions.grid(row=2, column=0, sticky="ew", pady=(0, 0))
        ttk.Button(session_actions, text="Delete Session", command=self.delete_selected_session).pack(side=LEFT)
        ttk.Button(
            session_actions,
            text="Start New Scan With Selected Tools",
            command=self.start_scan_for_selected_session,
        ).pack(side=LEFT, padx=(6, 0))

        self.network_info_var = StringVar(value="Network: loading...")
        self.system_info_var = StringVar(value="System: loading...")
        network_info_frame = ttk.LabelFrame(session_panel, text="System Information", style="Info.TLabelframe")
        network_info_frame.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        network_info_frame.columnconfigure(0, weight=1)
        network_info_frame.columnconfigure(1, weight=1)
        ttk.Label(
            network_info_frame,
            textvariable=self.network_info_var,
            style="Muted.TLabel",
            justify=LEFT,
        ).grid(row=0, column=0, sticky="nw", padx=(6, 14), pady=4)
        ttk.Label(
            network_info_frame,
            textvariable=self.system_info_var,
            style="Muted.TLabel",
            justify=LEFT,
        ).grid(row=0, column=1, sticky="nw", padx=(6, 6), pady=4)

        self.notebook = ttk.Notebook(right)
        self.notebook.grid(row=0, column=0, sticky="nsew")
        self.notebook.bind("<ButtonPress-1>", self._on_notebook_tab_press, add="+")
        self.notebook.bind("<ButtonRelease-1>", self._on_notebook_tab_release, add="+")

        details = ttk.Frame(self.notebook, padding=8)
        details.columnconfigure(0, weight=1)
        details.rowconfigure(2, weight=1)
        self.notebook.add(details, text="Session Details")
        self._register_reorderable_notebook_tab("details", details)

        self.session_title = ttk.Label(details, text="No session selected", style="Header.TLabel")
        self.session_title.grid(row=0, column=0, sticky="w")
        self.session_meta = ttk.Label(details, text="", style="Muted.TLabel")
        self.session_meta.grid(row=1, column=0, sticky="w", pady=(2, 8))

        self.findings_tree = ttk.Treeview(
            details,
            columns=("kind", "id", "severity", "name", "port_tool", "detail"),
            show="headings",
            selectmode="browse",
        )
        for col, label, width in (
            ("kind", "Type", 86),
            ("id", "ID", 48),
            ("severity", "Severity/Source", 112),
            ("name", "Name", 210),
            ("port_tool", "Port/Tool", 110),
            ("detail", "Details", 360),
        ):
            self.findings_tree.heading(col, text=label)
            self.findings_tree.column(col, width=width, anchor="w")
        grid_with_vertical_scrollbar(self.findings_tree, 2, 0, sticky="nsew")
        self.findings_tree.bind("<Double-1>", lambda _event: self.edit_selected_finding())

        detail_buttons = ttk.Frame(details)
        detail_buttons.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        for text, command in (
            ("Edit", self.edit_selected_finding),
            ("Delete", self.delete_selected_finding),
            ("Edit Risk", self.edit_selected_risk),
            ("Export HTML", self.export_selected_html),
            ("Pre-AI Package", self.export_selected_pre_ai),
            ("Import Findings", self.import_external_findings),
            ("Rerun AI", self.rerun_ai_analysis),
        ):
            ttk.Button(detail_buttons, text=text, command=command).pack(side=LEFT, padx=(0, 6))

        raw_tab = ttk.Frame(self.notebook, padding=8)
        raw_tab.columnconfigure(0, weight=1)
        raw_tab.rowconfigure(0, weight=1)
        self.notebook.add(raw_tab, text="Raw Scan")
        self._register_reorderable_notebook_tab("raw", raw_tab)
        self.raw_text = tk_text(raw_tab, wrap="none")
        grid_with_vertical_scrollbar(self.raw_text, 0, 0, sticky="nsew")

        ai_tab = ttk.Frame(self.notebook, padding=8)
        ai_tab.columnconfigure(0, weight=1)
        ai_tab.rowconfigure(0, weight=1)
        self.notebook.add(ai_tab, text="AI Analysis")
        self._register_reorderable_notebook_tab("ai", ai_tab)
        self.ai_text = tk_text(ai_tab, wrap="word")
        grid_with_vertical_scrollbar(self.ai_text, 0, 0, sticky="nsew")

        log_tab = ttk.Frame(self.notebook, padding=8)
        log_tab.columnconfigure(0, weight=1)
        log_tab.rowconfigure(0, weight=1)
        self.notebook.add(log_tab, text="Active Operations Log")
        self._register_reorderable_notebook_tab("log", log_tab)
        self.log_text = tk_text(log_tab, wrap="word")
        grid_with_vertical_scrollbar(self.log_text, 0, 0, sticky="nsew")
        self._restore_notebook_tab_order()

        self.html_reports_frame = ttk.Frame(self.notebook, padding=8)
        self.html_reports_frame.columnconfigure(0, weight=1)
        self.html_reports_frame.rowconfigure(1, weight=1)

        report_strip = ttk.Frame(self.html_reports_frame)
        report_strip.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        report_strip.columnconfigure(0, weight=1)
        self.report_tabs_canvas = tk.Canvas(report_strip, height=42, highlightthickness=0, background="#f6f7f9")
        self.report_tabs_canvas.grid(row=0, column=0, sticky="ew")
        self.report_tabs_scroll = ttk.Scrollbar(report_strip, orient="horizontal", command=self.report_tabs_canvas.xview)
        self.report_tabs_scroll.grid(row=1, column=0, sticky="ew")
        self.report_tabs_canvas.configure(xscrollcommand=self.report_tabs_scroll.set)
        self.report_tabs_inner = ttk.Frame(self.report_tabs_canvas)
        self.report_tabs_window = self.report_tabs_canvas.create_window((0, 0), window=self.report_tabs_inner, anchor="nw")
        self.report_tabs_inner.bind(
            "<Configure>",
            lambda _event: self.report_tabs_canvas.configure(scrollregion=self.report_tabs_canvas.bbox("all")),
        )
        self.report_tabs_canvas.bind(
            "<Configure>",
            lambda event: self.report_tabs_canvas.itemconfigure(self.report_tabs_window, height=event.height),
        )

        self.report_content_area = ttk.Frame(self.html_reports_frame)
        self.report_content_area.grid(row=1, column=0, sticky="nsew")
        self.report_content_area.columnconfigure(0, weight=1)
        self.report_content_area.rowconfigure(0, weight=1)

        self.status_var = StringVar(value="")
        self.status_frame = tk.Frame(self, background="#111827", height=40)
        self.status_frame.pack(fill="x", side="bottom")
        self.status_frame.pack_propagate(False)
        self.status_bar = tk.Label(
            self.status_frame,
            textvariable=self.status_var,
            anchor="w",
            background="#111827",
            foreground="#ffffff",
            font=("Segoe UI", 10),
            padx=12,
            pady=0,
        )
        self.status_bar.pack(fill=BOTH, expand=True)
        self._sync_tool_state()
        self.after(100, self._restore_pane_sizes)
        self.after(500, self._restore_pane_sizes)
        self.after(1200, self._restore_pane_sizes)

    def _restore_pane_sizes(self):
        sidebar_width = self.gui_state.get("sidebar_width")
        if not isinstance(sidebar_width, int) or sidebar_width < SIDEBAR_MIN_WIDTH:
            sidebar_width = SIDEBAR_DEFAULT_WIDTH
        try:
            total_width = self.outer_pane.winfo_width()
            if total_width > sidebar_width + 240:
                self.outer_pane.sashpos(0, sidebar_width)
        except Exception:
            pass

        right_width = self.gui_state.get("session_details_width")
        if isinstance(right_width, int) and right_width > 100:
            try:
                total_width = self.main_pane.winfo_width()
                if total_width > right_width + 120:
                    self.main_pane.sashpos(0, total_width - right_width)
            except Exception:
                pass
        else:
            self._restore_sash("main_pane", "main_sash")

        session_height = self.gui_state.get("sessions_window_height")
        if isinstance(session_height, int) and session_height > 100:
            try:
                total_height = self.left_pane.winfo_height()
                if total_height > session_height + 120:
                    self.left_pane.sashpos(0, total_height - session_height)
            except Exception:
                pass
        else:
            self._restore_sash("left_pane", "left_sash")

    def _restore_sash(self, pane_name: str, key: str):
        value = self.gui_state.get(key)
        if isinstance(value, int) and value > 0:
            try:
                getattr(self, pane_name).sashpos(0, value)
            except Exception:
                pass

    def _register_reorderable_notebook_tab(self, key: str, frame):
        self.notebook_tabs[key] = frame
        self.notebook_tab_keys[str(frame)] = key

    def _current_notebook_tab_order(self) -> list[str]:
        try:
            tabs = self.notebook.tabs()
        except Exception:
            return []
        order = []
        for tab_id in tabs:
            key = self.notebook_tab_keys.get(str(tab_id))
            if key:
                order.append(key)
        return order

    def _restore_notebook_tab_order(self):
        order = self.gui_state.get("notebook_tab_order")
        if not isinstance(order, list):
            return
        index = 0
        for key in order:
            frame = self.notebook_tabs.get(str(key))
            if frame:
                try:
                    self.notebook.insert(index, frame)
                    index += 1
                except Exception:
                    pass

    def _notebook_tab_at(self, x: int, y: int) -> str:
        try:
            self.notebook.identify(x, y)
            tab_id = self.notebook.tabs()[self.notebook.index(f"@{x},{y}")]
        except Exception:
            return ""
        return tab_id if self.notebook_tab_keys.get(str(tab_id)) else ""

    def _on_notebook_tab_press(self, event):
        self.dragged_notebook_tab = self._notebook_tab_at(event.x, event.y)

    def _on_notebook_tab_release(self, event):
        source_tab = self.dragged_notebook_tab
        self.dragged_notebook_tab = ""
        if not source_tab:
            return
        target_tab = self._notebook_tab_at(event.x, event.y)
        if not target_tab or target_tab == source_tab:
            return
        try:
            target_index = self.notebook.index(target_tab)
            self.notebook.insert(target_index, source_tab)
            self.notebook.select(source_tab)
            self._save_gui_state()
            self._set_status("Tab order saved.")
            return "break"
        except Exception:
            return

    def _set_status(self, message: str):
        self.status_var.set(message)

    def refresh_network_info(self):
        if self.closing or self.network_info_refreshing:
            return
        self.network_info_refreshing = True

        def load_info():
            script = r"""
$network = [ordered]@{
    Adapter = "unavailable"
    IPv4 = @()
    Gateways = @()
    DhcpServers = @()
    DnsServers = @()
}

$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1

if (-not $route) {
    $route = Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric, InterfaceMetric |
        Select-Object -First 1
}

if ($route) {
    $cfg = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
        Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex } |
        Select-Object -First 1
    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    if ($cfg) {
        $network.Adapter = $adapter.Name
        $network.IPv4 = @($cfg.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
        $network.Gateways = @($cfg.DefaultIPGateway)
        $network.DhcpServers = @($cfg.DHCPServer)
        $network.DnsServers = @($cfg.DNSServerSearchOrder)
    }
}

$osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$computerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
$gpu = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue |
    Where-Object { $_.Name } |
    Select-Object -First 1

$totalMemory = 0
$availableMemory = 0
if ($osInfo) {
    $totalMemory = [int64]$osInfo.TotalVisibleMemorySize * 1KB
    $availableMemory = [int64]$osInfo.FreePhysicalMemory * 1KB
}
if (($totalMemory -le 0) -and $computerInfo) {
    $totalMemory = [int64]$computerInfo.TotalPhysicalMemory
}
if ($availableMemory -le 0) {
    try {
        $availableMemory = [int64](Get-Counter '\Memory\Available Bytes' -ErrorAction Stop).CounterSamples[0].CookedValue
    } catch {
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
            $vbComputerInfo = [Microsoft.VisualBasic.Devices.ComputerInfo]::new()
            if ($totalMemory -le 0) { $totalMemory = [int64]$vbComputerInfo.TotalPhysicalMemory }
            $availableMemory = [int64]$vbComputerInfo.AvailablePhysicalMemory
        } catch {}
    }
}
$cpuName = if ($cpu) { $cpu.Name } else { "-" }
if ($cpuName -eq "-") {
    try {
        $registryCpu = Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop
        if ($registryCpu.ProcessorNameString) { $cpuName = $registryCpu.ProcessorNameString }
    } catch {}
}

[pscustomobject]@{
    Network = $network
    System = [ordered]@{
        SystemName = $env:COMPUTERNAME
        TotalMemoryBytes = $totalMemory
        AvailableMemoryBytes = $availableMemory
        GPU = if ($gpu) { $gpu.Name } else { "-" }
        CPU = $cpuName
    }
} | ConvertTo-Json -Compress -Depth 4
"""
            try:
                completed = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-Command",
                        script,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
                if completed.returncode != 0 or not completed.stdout.strip():
                    return "Network: unavailable", "System: unavailable"
                data = json.loads(completed.stdout.strip().splitlines()[-1])
                return self._format_network_info(data.get("Network") or data), self._format_system_info(data.get("System") or {})
            except Exception as e:
                return f"Network: unavailable ({e})", f"System: unavailable ({e})"

        def worker():
            try:
                network_text, system_text = load_info()
            except Exception:
                write_crash_log("System information refresh failed", traceback.format_exc())
                network_text, system_text = "Network: unavailable", "System: unavailable"
            self.output_queue.put(("network_info", (network_text, system_text)))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _format_network_info(self, data: dict) -> str:
        def values(name: str) -> str:
            value = data.get(name)
            if isinstance(value, list):
                rows = [str(item) for item in value if item]
            elif value:
                rows = [str(value)]
            else:
                rows = []
            return ", ".join(rows) if rows else "-"

        adapter = data.get("Adapter") or "primary adapter"
        return (
            f"Network ({adapter})\n"
            f"Local IP: {values('IPv4')}\n"
            f"Gateway: {values('Gateways')}\n"
            f"DHCP: {values('DhcpServers')}\n"
            f"DNS: {values('DnsServers')}"
        )

    def _format_system_info(self, data: dict) -> str:
        def memory(value) -> str:
            try:
                number = int(value or 0)
            except (TypeError, ValueError):
                number = 0
            if number <= 0:
                return "-"
            return f"{number / (1024 ** 3):.1f} GB"

        return (
            f"System Name: {data.get('SystemName') or '-'}\n"
            f"Total Memory: {memory(data.get('TotalMemoryBytes'))}\n"
            f"Available Memory: {memory(data.get('AvailableMemoryBytes'))}\n"
            f"GPU: {data.get('GPU') or '-'}\n"
            f"CPU: {data.get('CPU') or '-'}"
        )

    def _set_text(self, widget, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", END)
        widget.insert("1.0", text or "")
        widget.configure(state="disabled")

    def _append_log(self, text: str):
        self.log_text.configure(state="normal")
        self.log_text.insert(END, text)
        self.log_text.see(END)
        lines = int(float(self.log_text.index("end-1c").split(".")[0]))
        if lines > LOG_TRIM_LINES:
            self.log_text.delete("1.0", f"{lines - LOG_TRIM_LINES}.0")
        self.log_text.configure(state="disabled")

    def _create_large_checkbox(self, parent, text: str, variable: BooleanVar, command=None):
        kwargs = {}
        if self.checkbox_images:
            kwargs.update({
                "image": self.checkbox_images["unchecked"],
                "selectimage": self.checkbox_images["checked"],
                "compound": LEFT,
                "indicatoron": False,
            })

        check = tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            command=command,
            anchor="w",
            background="#f6f7f9",
            activebackground="#eef2f7",
            foreground="#1f2937",
            activeforeground="#111827",
            selectcolor="#f6f7f9",
            font=("Segoe UI", 10),
            padx=6,
            pady=4,
            borderwidth=0,
            highlightthickness=0,
            relief="flat",
            **kwargs,
        )
        return check

    def _create_info_icon(self, parent, tooltip_text: str, row: int, column: int = 1):
        icon = tk.Label(
            parent,
            text="i",
            width=2,
            background="#e5e7eb",
            foreground="#374151",
            activebackground="#dbe4f0",
            font=("Segoe UI", 9, "bold"),
            borderwidth=1,
            relief="solid",
            cursor="question_arrow",
        )
        icon.grid(row=row, column=column, sticky="e", padx=(6, 2), pady=3)
        HoverTooltip(icon, tooltip_text)
        return icon

    def _tool_flag_help(self, key: str) -> str:
        if key == "1":
            return f"Flags: {NMAP_EXTERNAL_FLAGS}"
        return ""

    def _create_tool_checkbox(self, parent, key: str, name: str, row: int):
        frame = tk.Frame(parent, background="#f6f7f9")
        frame.grid(row=row, column=0, sticky="ew", padx=4, pady=1)
        frame.columnconfigure(0, weight=1)

        check = self._create_large_checkbox(frame, name, self.tool_vars[key], self._manual_tool_selected)
        check.grid(row=0, column=0, sticky="ew")
        info_icon = None
        flag_help = self._tool_flag_help(key)
        if flag_help:
            info_icon = self._create_info_icon(frame, flag_help, 0)
        self.tool_widgets[key] = {"frame": frame, "check": check}
        if info_icon:
            self.tool_widgets[key]["info_icon"] = info_icon

        if key == "nmap_custom":
            preset_frame = tk.Frame(frame, background="#f6f7f9")
            preset_frame.grid(row=1, column=0, sticky="ew", padx=(26, 0), pady=(0, 3))
            preset_frame.columnconfigure(0, weight=1)
            presets = (
                ("quiet", "Quiet scan (Slower)"),
                ("loud", "Louder Scan (Faster)"),
            )
            for preset_row, (preset_key, preset_label) in enumerate(presets):
                var = BooleanVar(value=False)
                self.nmap_custom_preset_vars[preset_key] = var
                preset_check = self._create_large_checkbox(
                    preset_frame,
                    preset_label,
                    var,
                    lambda choice=preset_key: self._nmap_custom_preset_selected(choice),
                )
                preset_check.grid(row=preset_row, column=0, sticky="ew")
                self._create_info_icon(preset_frame, f"Flags: {NMAP_CUSTOM_PRESETS[preset_key]}", preset_row)
                self.nmap_custom_preset_widgets.append(preset_check)
            self.tool_widgets[key]["preset_frame"] = preset_frame

    def _refresh_tool_highlights(self):
        for key, widgets in self.tool_widgets.items():
            selected = bool(self.tool_vars.get(key) and self.tool_vars[key].get())
            bg = "#fff1f1" if selected else "#f6f7f9"
            fg = "#7f1d1d" if selected else "#1f2937"
            widgets["frame"].configure(background=bg)
            if widgets.get("preset_frame"):
                widgets["preset_frame"].configure(background=bg)
            widgets["check"].configure(
                background=bg,
                activebackground=bg,
                foreground=fg,
                selectcolor=bg,
            )
            if key == "nmap_custom":
                for preset_check in self.nmap_custom_preset_widgets:
                    preset_check.configure(
                        background=bg,
                        activebackground=bg,
                        selectcolor=bg,
                    )

    def _sync_tool_state(self):
        state = "disabled" if self.full_scan_var.get() else "normal"
        for widgets in self.tool_widgets.values():
            widgets["check"].configure(state=state)
        for preset_check in self.nmap_custom_preset_widgets:
            preset_check.configure(state=state)
        self._refresh_tool_highlights()

    def children_recursive(self):
        stack = list(self.winfo_children())
        while stack:
            child = stack.pop()
            yield child
            stack.extend(child.winfo_children())

    def _manual_tool_selected(self):
        if "nmap_custom" in self.tool_vars and not self.tool_vars["nmap_custom"].get():
            for var in self.nmap_custom_preset_vars.values():
                var.set(False)
        if any(var.get() for var in self.tool_vars.values()):
            self.full_scan_var.set(False)
        self._sync_tool_state()

    def _nmap_custom_preset_selected(self, selected_preset: str):
        selected_var = self.nmap_custom_preset_vars.get(selected_preset)
        if selected_var and selected_var.get():
            for preset_key, var in self.nmap_custom_preset_vars.items():
                if preset_key != selected_preset:
                    var.set(False)
            if "nmap_custom" in self.tool_vars:
                self.tool_vars["nmap_custom"].set(True)
        self._manual_tool_selected()

    def nmap_custom_target_text(self, target: str) -> str:
        parts = [str(target or "").strip()]
        for preset_key, args in NMAP_CUSTOM_PRESETS.items():
            preset_var = self.nmap_custom_preset_vars.get(preset_key)
            if preset_var and preset_var.get():
                parts.append(args)
        return " ".join(part for part in parts if part).strip()

    def scan_target_for_tool(self, target: str, tool_key: str) -> str:
        if tool_key == "nmap_custom":
            return self.nmap_custom_target_text(target)
        return target

    def set_all_tools(self, value: bool):
        self.full_scan_var.set(False)
        for var in self.tool_vars.values():
            var.set(value)
        if not value:
            for preset_var in self.nmap_custom_preset_vars.values():
                preset_var.set(False)
        self._sync_tool_state()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.output_queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "done":
                    self.worker_thread = None
                    self.progress.stop()
                    self.stop_scan_button.configure(state="disabled")
                    title, result, callback = payload
                    was_stopped = isinstance(result, dict) and bool(result.get("stopped"))
                    if was_stopped:
                        self._show_scan_stopped_message()
                    else:
                        self.scan_progress_label_var.set("")
                    self._set_status(f"{title} complete.")
                    if callback:
                        callback(result)
                elif kind == "error":
                    self.worker_thread = None
                    self.progress.stop()
                    self.stop_scan_button.configure(state="disabled")
                    self.scan_progress_label_var.set("")
                    title, error_text = payload
                    self._set_status(f"{title} failed.")
                    self._append_log("\n" + error_text + "\n")
                    messagebox.showerror(APP_TITLE, f"{title} failed. Details are in the Active Operations Log.")
                    self.refresh_all()
                elif kind == "network_info":
                    self.network_info_refreshing = False
                    network_text, system_text = payload
                    if not self.closing:
                        self.network_info_var.set(network_text)
                        self.system_info_var.set(system_text)
                        self.after(NETWORK_INFO_REFRESH_MS, self.refresh_network_info)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def run_worker(self, title: str, func, callback=None, cancellable: bool = False):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo(APP_TITLE, "Another operation is already running.")
            return

        def target():
            writer = QueueWriter(self.output_queue)
            try:
                with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                    print(f"\n=== {title} ===")
                    result = func()
                self.output_queue.put(("done", (title, result, callback)))
            except Exception:
                self.output_queue.put(("error", (title, traceback.format_exc())))

        self.notebook.select(self.log_text.master)
        self._set_status(f"{title} running...")
        self.stop_requested.clear()
        self.scan_progress_label_var.set("Scanning" if cancellable else "")
        self.stop_scan_button.configure(state="normal" if cancellable else "disabled")
        self.progress.start(12)
        self.worker_thread = threading.Thread(target=target, daemon=True)
        self.worker_thread.start()

    def stop_scan(self):
        if not self.worker_thread or not self.worker_thread.is_alive():
            return
        self.stop_requested.set()
        self.stop_scan_button.configure(state="disabled")
        self.scan_progress_label_var.set("Stopping scan...")

    def _show_scan_stopped_message(self):
        self.scan_progress_label_var.set("Scan Stopped!")
        self.after(3500, lambda: self.scan_progress_label_var.set(""))

    def refresh_all(self):
        self._refresh_model_label()
        try:
            domains = get_domain_history()
        except Exception as e:
            self._set_status("Database is not available.")
            self._append_log(f"\nDatabase connection failed: {e}\n{database_service_hint()}\n")
            domains = []

        selected = self.selected_domain
        self.domain_tree.delete(*self.domain_tree.get_children())
        self.domain_item_map.clear()
        for row in domains:
            domain = str(row[0])
            top_level_subdomains = self.visible_top_level_subdomains_for_domain(domain)
            active_count = len(self.all_visible_subdomains_for_domain(domain))
            scanned_count = int(row[3] or 0)
            if active_count:
                subdomain_label = f"{active_count} active"
                if scanned_count:
                    subdomain_label += f" / {scanned_count} scanned"
            elif scanned_count:
                subdomain_label = f"{scanned_count} scanned"
            else:
                subdomain_label = "-"

            display_name = f"{domain} ({active_count} active subdomains)" if active_count else domain
            domain_text = self._domain_label_text(domain, display_name)
            values = (str(row[1]), row[2], subdomain_label)
            self.domain_tree.insert(
                "",
                END,
                iid=domain,
                text=domain_text,
                image=self._domain_checkbox_image(domain),
                values=values,
                open=False,
            )
            self.domain_item_map[domain] = {"kind": "domain", "domain": domain, "target": domain}

            for subdomain in top_level_subdomains:
                source = "manual" if subdomain in self.manual_subdomains.get(domain, set()) else "active"
                self._insert_subdomain_item(domain, domain, subdomain, source)

        if selected and selected in self.domain_tree.get_children(""):
            self.domain_tree.selection_set(selected)
            self.domain_tree.focus(selected)
            self.selected_domain_target = selected
            self._load_domain(selected)
        elif domains:
            first = str(domains[0][0])
            self.domain_tree.selection_set(first)
            self.domain_tree.focus(first)
            self.selected_domain_target = first
            self._load_domain(first)
        else:
            self.session_tree.delete(*self.session_tree.get_children())
            self.selected_domain_target = ""
            self._clear_session()
        self._set_status("Ready.")

    def visible_top_level_subdomains_for_domain(self, domain: str) -> list[str]:
        active_subdomains, _other_subdomains = discovered_subdomains_for_domain(domain)
        combined = []
        seen = set()
        suppressed = self.suppressed_subdomains.get(domain, set())
        nested_targets = self.manual_nested_targets_for_domain(domain)
        for subdomain in list(active_subdomains) + sorted(self.manual_subdomains.get(domain, set())):
            normalized = normalize_target_host(subdomain)
            if not normalized or normalized in seen or normalized in suppressed or normalized in nested_targets:
                continue
            seen.add(normalized)
            combined.append(normalized)
        return combined

    def manual_nested_targets_for_domain(self, domain: str) -> set[str]:
        all_targets = {domain} | set(self.manual_subdomains.get(domain, set()))
        active_subdomains, _other_subdomains = discovered_subdomains_for_domain(domain)
        all_targets.update(active_subdomains)
        nested = set()
        changed = True
        while changed:
            changed = False
            for parent, children in self.manual_subdomain_children.items():
                if parent not in all_targets:
                    continue
                for child in children:
                    normalized = normalize_target_host(child)
                    if normalized and normalized not in all_targets:
                        all_targets.add(normalized)
                        nested.add(normalized)
                        changed = True
                    elif normalized:
                        nested.add(normalized)
        return nested

    def visible_children_for_parent(self, domain: str, parent: str) -> list[str]:
        suppressed = self.suppressed_subdomains.get(domain, set())
        children = []
        seen = set()
        for child in sorted(self.manual_subdomain_children.get(parent, set())):
            normalized = normalize_target_host(child)
            if not normalized or normalized in seen or normalized in suppressed:
                continue
            seen.add(normalized)
            children.append(normalized)
        return children

    def all_visible_subdomains_for_domain(self, domain: str) -> list[str]:
        visible = []
        seen = set()

        def add(target: str):
            if target and target not in seen:
                seen.add(target)
                visible.append(target)
                for child in self.visible_children_for_parent(domain, target):
                    add(child)

        for subdomain in self.visible_top_level_subdomains_for_domain(domain):
            add(subdomain)
        return visible

    def _insert_subdomain_item(self, parent_item: str, domain: str, subdomain: str, source: str):
        child_id = self._domain_child_id(domain, subdomain)
        if child_id in self.domain_item_map:
            return
        self.domain_tree.insert(
            parent_item,
            END,
            iid=child_id,
            text=self._domain_label_text(subdomain, subdomain),
            image=self._domain_checkbox_image(subdomain),
            values=("", "", f"{source} subdomain"),
        )
        self.domain_item_map[child_id] = {"kind": "subdomain", "domain": domain, "target": subdomain}
        for nested in self.visible_children_for_parent(domain, subdomain):
            self._insert_subdomain_item(child_id, domain, nested, "manual")

    def _check_text(self, target: str) -> str:
        return "■" if self.domain_scan_marks.get(target, 0) else "□"

    def _domain_checkbox_image(self, target: str):
        if not self.checkbox_images:
            return ""
        return self.checkbox_images["checked" if self.domain_scan_marks.get(target, 0) else "unchecked"]

    def _domain_label_text(self, target: str, display_name: str) -> str:
        if self.checkbox_images:
            return display_name
        return f"{self._check_text(target)} {display_name}"

    def _refresh_domain_item_text(self, item: str):
        mapping = self.domain_item_map.get(item)
        if not mapping:
            return
        target = mapping["target"]
        domain = mapping["domain"]
        if mapping["kind"] == "domain":
            active_count = len(self.all_visible_subdomains_for_domain(domain))
            display_name = f"{domain} ({active_count} active subdomains)" if active_count else domain
        else:
            display_name = target
        self.domain_tree.item(
            item,
            text=self._domain_label_text(target, display_name),
            image=self._domain_checkbox_image(target),
        )

    def _refresh_domain_checkmarks(self):
        for item in self.domain_item_map:
            self._refresh_domain_item_text(item)

    def _on_domain_click(self, event):
        item = self.domain_tree.identify_row(event.y)
        column = self.domain_tree.identify_column(event.x)
        if not item or column != "#0":
            return
        element = str(self.domain_tree.identify("element", event.x, event.y) or "").lower()
        if "indicator" in element:
            return
        if "image" in element:
            self._toggle_domain_scan_mark(item)
            return "break"
        bbox = self.domain_tree.bbox(item, "#0")
        if not bbox:
            return
        has_children = bool(self.domain_tree.get_children(item))
        check_left = bbox[0] + (22 if has_children else 0)
        check_right = check_left + (34 if self.checkbox_images else 32)
        if check_left <= event.x <= check_right:
            self._toggle_domain_scan_mark(item)
            return "break"

    def _toggle_domain_scan_mark(self, item: str):
        mapping = self.domain_item_map.get(item)
        if not mapping:
            return
        target = mapping["target"]
        if mapping["kind"] == "subdomain":
            self.domain_scan_marks[target] = 0 if self.domain_scan_marks.get(target, 0) else 1
            if not self.domain_scan_marks[target]:
                self.domain_scan_marks.pop(target, None)
            self.domain_notice_var.set("")
            self._refresh_domain_item_text(item)
            return

        domain = mapping["domain"]
        current = self.domain_scan_marks.get(domain, 0)
        next_state = {0: 1, 1: 2, 2: 0}.get(current, 0)
        self.domain_scan_marks[domain] = next_state
        if not next_state:
            self.domain_scan_marks.pop(domain, None)
            for child in self._descendant_domain_items(domain):
                child_mapping = self.domain_item_map.get(child)
                if child_mapping:
                    self.domain_scan_marks.pop(child_mapping["target"], None)
            self.domain_notice_var.set("")
        elif next_state == 1:
            self.domain_notice_var.set("")
        else:
            self.domain_tree.item(domain, open=True)
            for child in self._descendant_domain_items(domain):
                child_mapping = self.domain_item_map.get(child)
                if child_mapping:
                    self.domain_scan_marks[child_mapping["target"]] = 1
            self.domain_notice_var.set("All domains and subdomains will be scanned")
        self._refresh_domain_checkmarks()

    def _descendant_domain_items(self, item: str) -> list[str]:
        descendants = []
        for child in self.domain_tree.get_children(item):
            descendants.append(child)
            descendants.extend(self._descendant_domain_items(child))
        return descendants

    def _refresh_model_label(self):
        name = llm.current_model_name()
        provider = llm.current_provider_label()
        server = llm.current_base_url()
        self.model_label.configure(text=f"AI: {provider}\nModel: {name}\nEndpoint: {server}")

    def _on_domain_select(self, _event=None):
        selection = self.domain_tree.selection()
        if selection:
            item = selection[0]
            mapping = self.domain_item_map.get(item, {"domain": item, "target": item})
            self.selected_domain_target = mapping.get("target", mapping.get("domain", item))
            self._load_domain(mapping.get("domain", item))

    def _on_domain_double_click(self, event=None):
        item = self.domain_tree.identify_row(event.y) if event else ""
        if not item:
            return
        if event:
            element = str(self.domain_tree.identify("element", event.x, event.y) or "").lower()
            if "image" in element:
                return "break"
        mapping = self.domain_item_map.get(item)
        if not mapping or mapping.get("kind") != "domain":
            return
        self.domain_tree.item(item, open=not bool(self.domain_tree.item(item, "open")))
        return "break"

    def _on_domain_right_click(self, event):
        item = self.domain_tree.identify_row(event.y)
        if not item:
            return
        mapping = self.domain_item_map.get(item)
        if not mapping:
            return
        self.domain_tree.selection_set(item)
        self.domain_tree.focus(item)
        self._load_domain(mapping["domain"])
        self.selected_domain_target = mapping["target"]
        self.context_domain = mapping["domain"]
        self.context_parent_target = mapping["target"]
        self.context_domain_item = item
        try:
            self.domain_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.domain_context_menu.grab_release()
        return "break"

    def manually_add_subdomain(self):
        domain = getattr(self, "context_domain", "") or self.selected_domain
        parent_target = getattr(self, "context_parent_target", "") or domain
        if not domain:
            messagebox.showinfo(APP_TITLE, "Select a domain or subdomain first.")
            return
        value = simpledialog.askstring("Manually add a subdomain", f"Subdomain below {parent_target}:", parent=self)
        if not value:
            return
        subdomain = normalize_target_host(value)
        if not subdomain:
            messagebox.showwarning(APP_TITLE, "Enter a valid subdomain.")
            return
        if subdomain == parent_target or not subdomain.endswith("." + parent_target):
            if not messagebox.askyesno(APP_TITLE, f"'{subdomain}' is not under '{parent_target}'. Add it anyway?"):
                return
        if parent_target == domain:
            self.manual_subdomains.setdefault(domain, set()).add(subdomain)
        else:
            self.manual_subdomain_children.setdefault(parent_target, set()).add(subdomain)
        self.suppressed_subdomains.get(domain, set()).discard(subdomain)
        self._save_gui_state()
        self.refresh_all()
        self._open_domain_path(domain, subdomain)
        self._set_status(f"Added subdomain: {subdomain}")

    def copy_context_domain_name(self):
        item = getattr(self, "context_domain_item", "")
        mapping = self.domain_item_map.get(item)
        if not mapping:
            messagebox.showinfo(APP_TITLE, "Select a domain or subdomain first.")
            return
        target = mapping.get("target") or mapping.get("domain") or item
        try:
            self.clipboard_clear()
            self.clipboard_append(target)
            self.update_idletasks()
            self._set_status(f"Copied domain name: {target}")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Could not copy domain name.\n\n{e}")

    def scan_context_domain_item(self):
        item = getattr(self, "context_domain_item", "")
        mapping = self.domain_item_map.get(item)
        if not mapping:
            messagebox.showinfo(APP_TITLE, "Select a domain or subdomain first.")
            return
        target = mapping.get("target") or mapping.get("domain") or item
        self.selected_domain = mapping.get("domain", target)
        self.selected_domain_target = target
        self.target_var.set(target)
        self.start_scan_for_target(target)

    def delete_context_domain_item(self):
        item = getattr(self, "context_domain_item", "")
        mapping = self.domain_item_map.get(item)
        if not mapping:
            messagebox.showinfo(APP_TITLE, "Select a domain or subdomain first.")
            return
        self.domain_tree.selection_set(item)
        self.domain_tree.focus(item)
        if mapping.get("kind") == "domain":
            self.delete_selected_domain()
        else:
            self.delete_selected_subdomains()

    def _open_domain_path(self, domain: str, target: str):
        if domain in self.domain_tree.get_children(""):
            self.domain_tree.item(domain, open=True)
        path = []
        current = target
        while current and current != domain:
            parent = self._manual_parent_for_target(current)
            if not parent or parent in path:
                break
            path.append(parent)
            current = parent
        for parent in reversed(path):
            parent_item = domain if parent == domain else self._domain_child_id(domain, parent)
            if parent_item in self.domain_item_map:
                self.domain_tree.item(parent_item, open=True)

    def _manual_parent_for_target(self, target: str) -> str:
        for parent, children in self.manual_subdomain_children.items():
            if target in children:
                return parent
        return ""

    def _domain_child_id(self, domain: str, subdomain: str) -> str:
        return f"{domain}::active::{subdomain}"

    def _load_domain(self, domain: str):
        self.selected_domain = domain
        if not self.selected_domain_target:
            self.selected_domain_target = domain
        self.session_tree.delete(*self.session_tree.get_children())
        try:
            rows = get_scans_for_domain(domain)
        except Exception as e:
            self._append_log(f"\nCould not load sessions for {domain}: {e}\n")
            return
        for row in rows:
            sl_no, target, scan_date, status, target_type, _parent = row
            self.session_tree.insert(
                "",
                END,
                iid=str(sl_no),
                values=(sl_no, target, str(scan_date), target_type or "", status or ""),
            )
        if rows:
            first = str(rows[0][0])
            self.session_tree.selection_set(first)
            self.session_tree.focus(first)
            self._load_session(rows[0][0])
        else:
            self._clear_session()

    def _on_session_select(self, _event=None):
        selection = self.session_tree.selection()
        if selection:
            self._load_session(int(selection[0]))

    def _on_session_right_click(self, event):
        item = self.session_tree.identify_row(event.y)
        if not item:
            return
        self.session_tree.selection_set(item)
        self.session_tree.focus(item)
        self._load_session(int(item))
        self.context_session_id = int(item)
        try:
            self.session_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.session_context_menu.grab_release()
        return "break"

    def open_context_session_html_report(self):
        sl_no = self.context_session_id or self.selected_session
        if not sl_no:
            messagebox.showinfo(APP_TITLE, "Select a session first.")
            return
        data = get_session(int(sl_no))
        if not data["history"]:
            messagebox.showinfo(APP_TITLE, "That session is no longer available.")
            self.refresh_all()
            return
        path = self.expected_html_report_path(data)
        if os.path.exists(path):
            self.open_html_report_tab(path, data)
            return
        if not messagebox.askyesno(APP_TITLE, "Report not found, generate a new one?"):
            return

        def do_export():
            output_dir = default_reports_dir()
            os.makedirs(output_dir, exist_ok=True)
            generated_path = export_html(data, output_dir)
            print(f"[+] HTML report saved: {generated_path}")
            return generated_path

        self.run_worker(
            "Generating HTML report",
            do_export,
            lambda generated_path: self.open_html_report_tab(generated_path, data),
        )

    def run_context_session_ai_analysis(self):
        sl_no = self.context_session_id or self.selected_session
        if not sl_no:
            messagebox.showinfo(APP_TITLE, "Select a session first.")
            return
        self.rerun_ai_analysis(sl_no=int(sl_no))

    def _clear_session(self):
        self.selected_session = None
        self.finding_index.clear()
        self.session_title.configure(text="No session selected")
        self.session_meta.configure(text="")
        self.findings_tree.delete(*self.findings_tree.get_children())
        self._set_text(self.raw_text, "")
        self._set_text(self.ai_text, "")

    def _load_session(self, sl_no: int):
        try:
            data = get_session(sl_no)
        except Exception as e:
            self._append_log(f"\nCould not load SL#{sl_no}: {e}\n")
            return
        if not data["history"]:
            self._clear_session()
            return

        self.selected_session = sl_no
        h = data["history"]
        summary = data["summary"]
        risk = summary[4] if summary else "UNKNOWN"
        generated = summary[5] if summary and len(summary) > 5 else ""
        primary_domain = h[4] if len(h) > 4 else ""
        target_type = h[6] if len(h) > 6 else ""

        self.session_title.configure(text=f"SL#{h[0]} - {h[1]}")
        self.session_meta.configure(
            text=f"Risk: {risk or 'UNKNOWN'}    Date: {h[2]}    Type: {target_type or '-'}    Domain: {primary_domain or '-'}    Updated: {generated or '-'}"
        )
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.finding_index.clear()

        for vuln in data["vulns"]:
            item_id = f"vuln:{vuln[0]}"
            values = ("Vulnerability", vuln[0], str(vuln[3]).upper(), vuln[2], vuln[4], vuln[6])
            self.findings_tree.insert("", END, iid=item_id, values=values)
            self.finding_index[item_id] = ("vuln", vuln[0])

        for fix in data["fixes"]:
            item_id = f"fix:{fix[0]}"
            values = ("Fix", fix[0], fix[4], f"Vulnerability {fix[2]}", "", fix[3])
            self.findings_tree.insert("", END, iid=item_id, values=values)
            self.finding_index[item_id] = ("fix", fix[0])

        for exploit in data["exploits"]:
            item_id = f"exploit:{exploit[0]}"
            values = ("Exploit", exploit[0], "", exploit[2], exploit[3], exploit[5])
            self.findings_tree.insert("", END, iid=item_id, values=values)
            self.finding_index[item_id] = ("exploit", exploit[0])

        self._set_text(self.raw_text, summary[2] if summary else "")
        self._set_text(self.ai_text, summary[3] if summary else "")

    def expected_html_report_path(self, data: dict) -> str:
        h = data["history"]
        safe = safe_filename_part(h[1]).replace(".", "_")
        return os.path.join(default_reports_dir(), f"metatron_SL{h[0]}_{safe}.html")

    def ensure_html_reports_tab(self):
        if not self.html_reports_added:
            self.notebook.add(self.html_reports_frame, text="HTML Reports")
            self.html_reports_added = True

    def open_html_report_tab(self, path: str, data: dict | None = None):
        path = str(path)
        if not path or not os.path.exists(path):
            messagebox.showerror(APP_TITLE, "Report file was not found.")
            return
        if data is None:
            data = get_session(int(self.selected_session)) if self.selected_session else None
        target = "report"
        if data and data.get("history"):
            target = str(data["history"][1])
        report_id = path
        if report_id in self.report_tabs:
            self.select_report_tab(report_id)
            return

        self.ensure_html_reports_tab()

        label = f"HTML Report - {target}"
        tab_control = tk.Frame(self.report_tabs_inner, background="#e5e7eb", bd=1, relief="solid")
        tab_control.pack(side=LEFT, padx=(0, 6), pady=4)
        tab_button = tk.Button(
            tab_control,
            text=label,
            command=lambda rid=report_id: self.select_report_tab(rid),
            anchor="w",
            padx=10,
            pady=4,
            relief="flat",
            background="#f9fafb",
            activebackground="#eef2ff",
        )
        tab_button.pack(side=LEFT)
        close_button = tk.Button(
            tab_control,
            text="X",
            command=lambda rid=report_id: self.close_report_tab(rid),
            padx=8,
            pady=4,
            relief="flat",
            background="#f9fafb",
            activebackground="#fee2e2",
        )
        close_button.pack(side=LEFT)

        frame = ttk.Frame(self.report_content_area, padding=0)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        toolbar = ttk.Frame(frame)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(toolbar, text=Path(path).name, style="Muted.TLabel").pack(side=LEFT)
        ttk.Button(toolbar, text="Open Externally", command=lambda: self._open_path(path)).pack(side=RIGHT)

        rendered = self._try_render_html(frame, path)
        if not rendered:
            self._render_html_fallback(frame, path)

        self.report_tabs[report_id] = {
            "path": path,
            "frame": frame,
            "control": tab_control,
            "button": tab_button,
            "close": close_button,
        }
        self.select_report_tab(report_id)
        self._set_status(f"HTML report opened: {Path(path).name}")

    def select_report_tab(self, report_id: str):
        if report_id not in self.report_tabs:
            return
        self.ensure_html_reports_tab()
        self.notebook.select(self.html_reports_frame)
        self.selected_report_tab = report_id
        for current_id, tab in self.report_tabs.items():
            frame = tab["frame"]
            if current_id == report_id:
                frame.grid(row=0, column=0, sticky="nsew")
                tab["control"].configure(background="#9ca3af")
                tab["button"].configure(background="#ffffff")
                tab["close"].configure(background="#ffffff")
            else:
                frame.grid_forget()
                tab["control"].configure(background="#e5e7eb")
                tab["button"].configure(background="#f9fafb")
                tab["close"].configure(background="#f9fafb")
        self.report_tabs_canvas.update_idletasks()
        self.report_tabs_canvas.configure(scrollregion=self.report_tabs_canvas.bbox("all"))

    def close_report_tab(self, report_id: str):
        tab = self.report_tabs.pop(report_id, None)
        if not tab:
            return
        try:
            tab["frame"].destroy()
            tab["control"].destroy()
        except Exception:
            pass
        if self.selected_report_tab == report_id:
            self.selected_report_tab = ""
        if self.report_tabs:
            next_id = next(iter(self.report_tabs))
            self.select_report_tab(next_id)
        else:
            try:
                self.notebook.forget(self.html_reports_frame)
            except Exception:
                pass
            self.html_reports_added = False
            self.selected_report_tab = ""

    def _try_render_html(self, parent, path: str) -> bool:
        try:
            from tkinterweb import HtmlFrame
        except Exception as e:
            self._append_log(f"\nEmbedded HTML renderer is unavailable: {e}\n")
            return False
        try:
            html_frame = HtmlFrame(
                parent,
                messages_enabled=False,
                vertical_scrollbar=True,
                horizontal_scrollbar="auto",
                stylesheets_enabled=True,
                images_enabled=True,
            )
            html_frame.grid(row=1, column=0, sticky="nsew")
            html_frame.load_file(path)
            return True
        except Exception as e:
            self._append_log(f"\nEmbedded HTML renderer failed: {e}\n")
            return False

    def _render_html_fallback(self, parent, path: str):
        viewer = tk_text(parent, wrap="word")
        grid_with_vertical_scrollbar(viewer, 1, 0, sticky="nsew")
        try:
            html = Path(path).read_text(encoding="utf-8", errors="replace")
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(html, "html.parser")
                text = soup.get_text("\n", strip=True)
            except Exception:
                import re

                text = re.sub(r"<[^>]+>", " ", html)
                text = re.sub(r"\s+", " ", text)
            viewer.insert(
                "1.0",
                "Embedded HTML rendering is not available in this Python environment.\n"
                "Install or update the GUI dependencies so the tkinterweb renderer is available, then restart Metatron.\n"
                "The report text is shown below, and the Open Externally button can open the full styled report.\n\n"
                + text,
            )
        except Exception as e:
            viewer.insert("1.0", f"Could not read report file:\n{path}\n\n{e}")
        viewer.configure(state="disabled")

    def current_session_data(self) -> dict | None:
        if not self.selected_session:
            messagebox.showinfo(APP_TITLE, "Select a session first.")
            return None
        data = get_session(int(self.selected_session))
        if not data["history"]:
            messagebox.showinfo(APP_TITLE, "That session is no longer available.")
            self.refresh_all()
            return None
        return data

    def check_database(self):
        dialog = Toplevel(self)
        dialog.title("Database Settings")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("520x310")
        dialog.columnconfigure(0, weight=1)

        settings = load_database_settings()
        frame = ttk.Frame(dialog, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(1, weight=1)

        host_var = StringVar(value=str(settings.get("host", "localhost")))
        port_var = StringVar(value=str(settings.get("port", 3306)))
        database_var = StringVar(value=str(settings.get("database", "metatron")))
        user_var = StringVar(value=str(settings.get("user", "metatron")))
        password_var = StringVar(value=str(settings.get("password", "")))
        status_var = StringVar(value="Use Test Connection to verify these settings before saving.")

        fields = (
            ("Database address", host_var, False),
            ("Port", port_var, False),
            ("Database name", database_var, False),
            ("Username", user_var, False),
            ("Password", password_var, True),
        )
        for row, (label, var, secret) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=(0, 8))
            entry = ttk.Entry(frame, textvariable=var, show="*" if secret else "")
            entry.grid(row=row, column=1, sticky="ew", pady=(0, 8))

        ttk.Label(frame, textvariable=status_var, style="Muted.TLabel", wraplength=470).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(4, 8)
        )

        def collect_settings() -> dict | None:
            try:
                port = int(port_var.get().strip())
            except ValueError:
                messagebox.showerror(APP_TITLE, "Database port must be a number.")
                return None
            return {
                "host": host_var.get().strip() or "localhost",
                "port": port,
                "database": database_var.get().strip() or "metatron",
                "user": user_var.get().strip() or "metatron",
                "password": password_var.get(),
            }

        def test_connection():
            settings_to_test = collect_settings()
            if not settings_to_test:
                return

            def do_test():
                test_database_settings(settings_to_test)
                return settings_to_test

            def done(_settings):
                status_var.set("Database connection is ready.")
                self._set_status("Database connection is ready.")
                messagebox.showinfo(APP_TITLE, "Database connection is ready.")

            self.run_worker("Testing database connection", do_test, done)

        def save_settings():
            settings_to_save = collect_settings()
            if not settings_to_save:
                return
            save_database_settings(**settings_to_save)
            self._set_status("Database settings saved.")
            dialog.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(6, 0))
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side=RIGHT)
        ttk.Button(buttons, text="Save", command=save_settings).pack(side=RIGHT, padx=(0, 8))
        ttk.Button(buttons, text="Test Connection", command=test_connection).pack(side=RIGHT, padx=(0, 8))

    def select_model(self):
        dialog = Toplevel(self)
        dialog.title("AI Model Settings")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("840x560")
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(0, weight=1)

        frame = ttk.Frame(dialog, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)

        provider_labels = {"Local LLM": "local", "OpenAI": "openai", "Claude": "claude"}
        provider_names = {value: key for key, value in provider_labels.items()}
        settings = llm.load_ai_settings()
        provider_var = StringVar(value=provider_names.get(settings.get("ai_provider"), "Local LLM"))
        server_var = StringVar(value=llm.current_base_url())
        api_key_var = StringVar(
            value=settings.get("openai_api_key", "") if settings.get("ai_provider") == "openai"
            else settings.get("claude_api_key", "") if settings.get("ai_provider") == "claude"
            else ""
        )
        model_var = StringVar(value=llm.current_model_name() if llm.current_model_name() != "not selected" else "")
        status_var = StringVar(value="Choose a provider, enter the connection settings, then load or type a model name.")

        ttk.Label(frame, text="AI provider").grid(row=0, column=0, sticky="w", pady=(0, 8))
        provider_combo = ttk.Combobox(
            frame,
            textvariable=provider_var,
            values=list(provider_labels.keys()),
            state="readonly",
        )
        provider_combo.grid(row=0, column=1, sticky="ew", pady=(0, 8))

        ttk.Label(frame, text="Server address").grid(row=1, column=0, sticky="w", pady=(0, 8))
        server_entry = ttk.Entry(frame, textvariable=server_var)
        server_entry.grid(row=1, column=1, sticky="ew", pady=(0, 8))

        api_label = ttk.Label(frame, text="API key")
        api_label.grid(row=2, column=0, sticky="w", pady=(0, 8))
        api_entry = ttk.Entry(frame, textvariable=api_key_var, show="*")
        api_entry.grid(row=2, column=1, sticky="ew", pady=(0, 8))

        ttk.Label(frame, text="Selected model").grid(row=3, column=0, sticky="w", pady=(0, 8))
        model_entry = ttk.Entry(frame, textvariable=model_var)
        model_entry.grid(row=3, column=1, sticky="ew", pady=(0, 8))

        ttk.Label(frame, textvariable=status_var, style="Muted.TLabel", wraplength=780).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(2, 8)
        )

        list_frame = ttk.Frame(frame)
        list_frame.grid(row=7, column=0, columnspan=2, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        tree = ttk.Treeview(list_frame, columns=("model",), show="headings", selectmode="browse")
        tree.heading("model", text="Available models")
        tree.column("model", width=760)
        grid_with_vertical_scrollbar(tree, 0, 0, sticky="nsew")

        def populate_models(models: list[str]):
            tree.delete(*tree.get_children())
            if not models:
                status_var.set("No models were returned. You can still type a model name manually.")
                return
            for model in models:
                tree.insert("", END, iid=model, values=(model,))
            current = model_var.get().strip()
            if current in models:
                tree.selection_set(current)
                tree.focus(current)
            else:
                tree.selection_set(models[0])
                tree.focus(models[0])
                model_var.set(models[0])
            status_var.set(f"Loaded {len(models)} model(s).")

        def selected_provider_key() -> str:
            return provider_labels.get(provider_var.get(), "local")

        def provider_defaults(provider: str) -> tuple[str, str, str]:
            latest = llm.load_ai_settings()
            if provider == "openai":
                return latest.get("openai_base_url", "https://api.openai.com/v1"), latest.get("openai_api_key", ""), latest.get("openai_model", "")
            if provider == "claude":
                return latest.get("claude_base_url", "https://api.anthropic.com/v1"), latest.get("claude_api_key", ""), latest.get("claude_model", "")
            return latest.get("lm_studio_base_url", "http://localhost:1234/v1"), "", latest.get("lm_studio_model", "")

        def refresh_provider_fields(_event=None):
            provider = selected_provider_key()
            server, key, model = provider_defaults(provider)
            server_var.set(server)
            api_key_var.set(key)
            model_var.set(model)
            tree.delete(*tree.get_children())
            if provider == "local":
                api_entry.configure(state="disabled")
                status_var.set("Local LLM uses the existing LM Studio-compatible local server.")
            else:
                api_entry.configure(state="normal")
                status_var.set(f"{provider_var.get()} uses an online API key and model name.")

        def load_models_from_address():
            requested_url = server_var.get()
            requested_key = api_key_var.get()
            provider = selected_provider_key()

            def do_load():
                print(f"[*] Loading AI models from {requested_url}")
                models = llm.get_models_for_provider(provider, requested_url, requested_key)
                return models

            def done(models):
                populate_models(models)

            self.run_worker("Loading AI models", do_load, done)

        tree.bind("<<TreeviewSelect>>", lambda _event: model_var.set(tree.selection()[0]) if tree.selection() else None)
        provider_combo.bind("<<ComboboxSelected>>", refresh_provider_fields)

        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, columnspan=2, sticky="e", pady=(0, 8))
        ttk.Button(actions, text="Load Models", command=load_models_from_address).pack(side=RIGHT)

        def save_choice():
            model = model_var.get().strip()
            if not model:
                messagebox.showinfo(APP_TITLE, "Select a model first.")
                return
            provider = selected_provider_key()
            updates = {
                "ai_provider": provider,
                "lm_studio_base_url": settings.get("lm_studio_base_url", "http://localhost:1234/v1"),
                "lm_studio_model": settings.get("lm_studio_model", ""),
                "openai_base_url": settings.get("openai_base_url", "https://api.openai.com/v1"),
                "openai_api_key": settings.get("openai_api_key", ""),
                "openai_model": settings.get("openai_model", ""),
                "claude_base_url": settings.get("claude_base_url", "https://api.anthropic.com/v1"),
                "claude_api_key": settings.get("claude_api_key", ""),
                "claude_model": settings.get("claude_model", ""),
            }
            if provider == "openai":
                if not api_key_var.get().strip():
                    messagebox.showerror(APP_TITLE, "Enter an OpenAI API key before using OpenAI models.")
                    return
                updates.update(
                    openai_base_url=server_var.get(),
                    openai_api_key=api_key_var.get().strip(),
                    openai_model=model,
                )
            elif provider == "claude":
                if not api_key_var.get().strip():
                    messagebox.showerror(APP_TITLE, "Enter a Claude API key before using Claude models.")
                    return
                updates.update(
                    claude_base_url=server_var.get(),
                    claude_api_key=api_key_var.get().strip(),
                    claude_model=model,
                )
            else:
                updates.update(lm_studio_base_url=server_var.get(), lm_studio_model=model)
            llm.save_ai_settings(**updates)
            self._refresh_model_label()
            self._set_status(f"AI model selected: {model}")
            dialog.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side=RIGHT)
        ttk.Button(buttons, text="Use Settings", command=save_choice).pack(side=RIGHT, padx=(0, 8))

        refresh_provider_fields()

    def selected_tool_keys(self) -> list[str]:
        return [key for key, var in self.tool_vars.items() if var.get()]

    def start_scan(self):
        target = self.target_var.get().strip()
        tool_keys = self.selected_tool_keys()
        blank_target_tool_only = not self.full_scan_var.get() and len(tool_keys) == 1 and tool_keys[0] in BLANK_TARGET_INTERNAL_TOOLS
        if not target and not blank_target_tool_only:
            messagebox.showinfo(APP_TITLE, "Enter a target IP address or domain first.")
            return

        self.start_scan_for_target(target)

    def start_scan_for_selected_domain(self):
        if not self.selected_domain:
            messagebox.showinfo(APP_TITLE, "Select a domain first.")
            return
        checked_targets = self.checked_domain_scan_targets()
        if checked_targets:
            self.start_scan_for_targets(checked_targets)
            return
        target = self.selected_domain_target or self.selected_domain
        self.target_var.set(target)
        self.start_scan_for_target(target)

    def start_scan_for_selected_session(self):
        data = self.current_session_data()
        if not data:
            return
        target = normalize_target_host(data["history"][1])
        if not target:
            messagebox.showinfo(APP_TITLE, "The selected session does not have a usable target.")
            return
        self.target_var.set(target)
        self.start_scan_for_target(target)

    def start_scan_for_target(self, target: str):
        self.start_scan_for_targets([target])

    def checked_domain_scan_targets(self) -> list[str]:
        targets = []
        seen = set()

        def add(target: str):
            normalized = normalize_target_host(target)
            if normalized and normalized not in seen:
                seen.add(normalized)
                targets.append(normalized)

        for domain_item in self.domain_tree.get_children(""):
            mapping = self.domain_item_map.get(domain_item)
            if not mapping:
                continue
            domain = mapping["target"]
            if self.domain_scan_marks.get(domain, 0):
                add(domain)
            for child in self._descendant_domain_items(domain_item):
                child_mapping = self.domain_item_map.get(child)
                if child_mapping and self.domain_scan_marks.get(child_mapping["target"], 0):
                    add(child_mapping["target"])
        return targets

    def start_scan_for_targets(self, targets: list[str]):
        normalized_targets = []
        seen = set()
        for target in targets:
            normalized = str(target or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                normalized_targets.append(normalized)

        full_scan = self.full_scan_var.get()
        tool_keys = self.selected_tool_keys()
        blank_target_tool = tool_keys[0] if not full_scan and len(tool_keys) == 1 and tool_keys[0] in BLANK_TARGET_INTERNAL_TOOLS else ""
        if not normalized_targets:
            if blank_target_tool:
                normalized_targets = ["PingCastle current domain" if blank_target_tool == "pingcastle" else "AD Recon current domain"]
            else:
                messagebox.showinfo(APP_TITLE, "Enter a target IP address or domain first.")
                return
        if not full_scan and not tool_keys:
            messagebox.showinfo(APP_TITLE, "Choose Full scan or select one or more tools.")
            return
        if full_scan and not llm.has_selected_model():
            messagebox.showerror(APP_TITLE, "You must select an AI model before running a full scan.")
            return

        try:
            existing = [
                target
                for target in normalized_targets
                if has_scans_for_domain(primary_domain_for_target(self.scan_metadata_target(target)))
            ]
            if existing:
                target_word = "target already has" if len(existing) == 1 else "targets already have"
                proceed = messagebox.askyesno(
                    APP_TITLE,
                    f"{len(existing)} {target_word} saved scan history. Start another scan anyway?",
                )
                if not proceed:
                    return
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Database connection failed.\n\n{e}\n\n{database_service_hint()}")
            return

        if len(normalized_targets) > 1:
            if not messagebox.askyesno(
                APP_TITLE,
                f"Start scans for these {len(normalized_targets)} targets, one after another?\n\n{self._target_list_preview(normalized_targets)}",
            ):
                return

        def do_scan():
            results = []
            failures = []
            for idx, target in enumerate(normalized_targets, start=1):
                if self.stop_requested.is_set():
                    print("[!] Scan stopped before starting the next target.")
                    break
                print(f"\n=== Target {idx}/{len(normalized_targets)}: {target} ===")
                try:
                    results.append(self._run_scan(target, full_scan, tool_keys, self.save_raw_only_var.get()))
                except ScanStopped:
                    print("[!] Scan stopped by user.")
                    break
                except Exception as e:
                    failures.append((target, str(e)))
                    print(f"[!] Scan failed for {target}: {e}")
                    traceback.print_exc()
            stopped = self.stop_requested.is_set()
            if failures and not results and not stopped:
                raise RuntimeError("All selected scans failed.")
            return {"results": results, "failures": failures, "stopped": stopped}

        def after_scan(result):
            self.refresh_all()
            results = result.get("results", []) if isinstance(result, dict) else []
            failures = result.get("failures", []) if isinstance(result, dict) else []
            stopped = bool(result.get("stopped")) if isinstance(result, dict) else False
            message = "Scan stopped" if stopped else f"{len(results)} scan(s) complete"
            if failures:
                message += f"; {len(failures)} failed"
            message += "."
            self._set_status(message)
            if stopped:
                return
            for item in results:
                report_path = item.get("report_path", "")
                sl_no = item.get("sl_no")
                report_data = get_session(int(sl_no)) if sl_no else None
                if report_path:
                    self.open_html_report_tab(report_path, report_data)

        title = f"Scanning {normalized_targets[0]}" if len(normalized_targets) == 1 else f"Scanning {len(normalized_targets)} targets"
        self.run_worker(title, do_scan, after_scan, cancellable=True)

    def scan_metadata_target(self, target: str) -> str:
        parts = str(target or "").strip().split()
        return parts[0] if parts else str(target or "").strip()

    def _target_list_preview(self, targets: list[str], limit: int = 18) -> str:
        shown = targets[:limit]
        preview = "\n".join(f"- {target}" for target in shown)
        if len(targets) > limit:
            preview += f"\n- ...and {len(targets) - limit} more"
        return preview

    def _raise_if_scan_stopped(self):
        if self.stop_requested.is_set():
            raise ScanStopped()

    def _run_scan(self, target: str, full_scan: bool, tool_keys: list[str], raw_only: bool) -> dict:
        session_target = self.session_target_for_scan(target, full_scan, tool_keys)
        metadata_target = self.scan_metadata_target(session_target)
        primary_domain = primary_domain_for_target(metadata_target)
        target_type = target_type_for_target(metadata_target, primary_domain)
        parent_target = primary_domain if target_type == "subdomain" else None
        sl_no = create_session(session_target, primary_domain=primary_domain, parent_target=parent_target, target_type=target_type)
        print(f"[+] Session created: SL#{sl_no}")

        try:
            self._raise_if_scan_stopped()
            if full_scan:
                results = OrderedDict()
                for _key, (name, func) in GUI_EXTERNAL_TOOLS.items():
                    self._raise_if_scan_stopped()
                    print(f"\n[*] Running {name}...")
                    output = run_scan_step(func, target)
                    if is_scan_abort(output):
                        raise RuntimeError("Scan was aborted.")
                    results[name] = output
                self._raise_if_scan_stopped()
                raw_scan = format_recon_for_llm(results)
            else:
                results = OrderedDict()
                for key in tool_keys:
                    self._raise_if_scan_stopped()
                    name, func = GUI_ALL_TOOLS[key]
                    tool_target = self.scan_target_for_tool(target, key)
                    print(f"\n[*] Running {name}...")
                    output = run_scan_step(func, tool_target)
                    if is_scan_abort(output):
                        raise RuntimeError("Scan was aborted.")
                    results[name] = output
                self._raise_if_scan_stopped()
                selected_tool = next(iter(results.keys())) if len(results) == 1 else ""
                run_mode = "single_tool" if len(results) == 1 else "full"
                raw_scan = format_recon_for_llm(results, run_mode=run_mode, selected_tool=selected_tool)

            if not raw_scan.strip():
                raise RuntimeError("No scan data was collected.")

            auto_export_pre_ai_package(session_target, raw_scan, sl_no)
            self._raise_if_scan_stopped()

            has_internal_tool = any(key in GUI_INTERNAL_TOOLS for key in tool_keys)
            if raw_only or has_internal_tool or is_single_raw_only_scan(raw_scan):
                tool_name = single_tool_name(raw_scan) or "Raw scan"
                save_raw_tool_result(sl_no, raw_scan, tool_name)
                data = get_session(sl_no)
                report_path = export_html(data, default_reports_dir())
                print(f"[+] HTML report saved: {report_path}")
                return {"sl_no": sl_no, "report_path": report_path, "message": f"SL#{sl_no} saved with raw output."}

            if not llm.has_selected_model():
                raise RuntimeError("No AI model is selected. Select an AI model, then scan again.")

            self._raise_if_scan_stopped()
            print("\n[*] Starting AI analysis...")
            ai_raw_scan = remove_subfinder_from_ai_input(raw_scan)
            result = analyse_target(session_target, ai_raw_scan)
            self._raise_if_scan_stopped()
            if str(result.get("full_response", "")).startswith("[!]"):
                raise RuntimeError(result["full_response"])
            result["raw_scan"] = raw_scan
            save_ai_result(sl_no, result)

            data = get_session(sl_no)
            report_path = export_html(data, default_reports_dir())
            print(f"[+] HTML report saved: {report_path}")
            return {
                "sl_no": sl_no,
                "report_path": report_path,
                "message": f"SL#{sl_no} complete. Risk: {result['risk_level']}",
            }
        except Exception:
            delete_full_session(sl_no)
            raise

    def session_target_for_scan(self, target: str, full_scan: bool, tool_keys: list[str]) -> str:
        if full_scan or len(tool_keys) != 1 or tool_keys[0] not in BLANK_TARGET_INTERNAL_TOOLS:
            return target
        tool_key = tool_keys[0]
        text = str(target or "").strip()
        if tool_key == "ad_recon" and (not text or text == "AD Recon current domain"):
            return "AD Recon current domain"
        if tool_key == "pingcastle" and (not text or text == "PingCastle current domain"):
            return "PingCastle current domain"
        redacted = re.sub(
            r"(?i)(--password|-password|--pass|-pass|-p)(=|\s+)(\"[^\"]*\"|'[^']*'|\S+)",
            lambda match: f"{match.group(1)}{match.group(2)}<hidden>",
            text,
        )
        label = "PingCastle" if tool_key == "pingcastle" else "AD Recon"
        return f"{label} {redacted}"

    def export_selected_html(self):
        data = self.current_session_data()
        if not data:
            return

        def do_export():
            output_dir = default_reports_dir()
            os.makedirs(output_dir, exist_ok=True)
            path = export_html(data, output_dir)
            print(f"[+] HTML report saved: {path}")
            return path

        def done(path):
            self._set_status(f"HTML report saved: {path}")
            self.open_html_report_tab(path, data)

        self.run_worker("Exporting HTML report", do_export, done)

    def export_selected_pre_ai(self):
        data = self.current_session_data()
        if not data:
            return

        def do_export():
            output_dir = default_reports_dir()
            os.makedirs(output_dir, exist_ok=True)
            p1, p2 = export_pre_ai_package(data, output_dir)
            print(f"[+] Pre-AI JSON saved: {p1}")
            print(f"[+] Pre-AI prompt saved: {p2}")
            return p1, p2

        def done(paths):
            self._set_status(f"Pre-AI package saved: {paths[0]}")

        self.run_worker("Exporting Pre-AI package", do_export, done)

    def import_external_findings(self):
        data = self.current_session_data()
        if not data:
            return
        path = filedialog.askopenfilename(
            title="Select external findings file",
            filetypes=(("Text and Markdown", "*.txt *.md"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Could not read that file.\n\n{e}")
            return

        vulns = parse_vulnerabilities(text)
        exploits = parse_exploits(text)
        risk = parse_risk_level(text)
        summary = parse_summary(text)
        if not vulns and not exploits and risk == "UNKNOWN":
            messagebox.showwarning(APP_TITLE, "No Metatron-formatted findings were found in that file.")
            return

        proceed = messagebox.askyesno(
            APP_TITLE,
            f"Import {len(vulns)} vulnerabilities and {len(exploits)} exploits into SL#{self.selected_session}?",
        )
        if not proceed:
            return

        sl_no = int(self.selected_session)

        def do_import():
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
                print(f"[+] Imported vulnerability: {vuln['vuln_name']}")

            for exp in exploits:
                save_exploit(
                    sl_no,
                    exp["exploit_name"],
                    exp["tool_used"],
                    exp["payload"],
                    exp["result"],
                    exp["notes"],
                )
                print(f"[+] Imported exploit: {exp['exploit_name']}")

            if risk != "UNKNOWN":
                edit_summary_risk(sl_no, risk)
            if summary and not get_session(sl_no)["summary"]:
                save_summary(sl_no, "", summary, risk)
            return sl_no

        self.run_worker("Importing external findings", do_import, lambda _sl: self.refresh_all())

    def rerun_ai_analysis(self, sl_no: int | None = None):
        if sl_no is None:
            data = self.current_session_data()
            if not data:
                return
            sl_no = int(self.selected_session)
        else:
            data = get_session(int(sl_no))
            if not data["history"]:
                messagebox.showinfo(APP_TITLE, "That session is no longer available.")
                self.refresh_all()
                return
        if not data["summary"] or not data["summary"][2]:
            messagebox.showinfo(APP_TITLE, "This session does not have saved raw scan data to analyze.")
            return
        raw_scan = data["summary"][2]
        run_mode, _selected_tool = run_mode_from_raw_scan(raw_scan)
        if run_mode == "single_tool":
            messagebox.showerror(APP_TITLE, "This option cannot run on single tool session scans, only full scans")
            return
        if not llm.has_selected_model():
            messagebox.showinfo(APP_TITLE, "Select an AI model first.")
            return
        if not messagebox.askyesno(APP_TITLE, f"Replace AI results for SL#{sl_no}?"):
            return

        sl_no = int(sl_no)

        def do_rerun():
            session = get_session(sl_no)
            target = session["history"][1]
            raw_scan = session["summary"][2]
            auto_export_pre_ai_package(target, raw_scan, sl_no)
            result = analyse_target(target, remove_subfinder_from_ai_input(raw_scan))
            if str(result.get("full_response", "")).startswith("[!]"):
                raise RuntimeError(result["full_response"])
            result["raw_scan"] = raw_scan
            delete_ai_results(sl_no)
            save_ai_result(sl_no, result)
            print(f"[+] AI analysis complete for SL#{sl_no}. Risk: {result['risk_level']}")
            return sl_no

        def done(done_sl_no):
            self.refresh_all()
            try:
                self.session_tree.selection_set(str(done_sl_no))
                self.session_tree.focus(str(done_sl_no))
                self._load_session(int(done_sl_no))
            except Exception:
                pass

        self.run_worker("Rerunning AI analysis", do_rerun, done)

    def selected_finding(self) -> tuple[str, int] | None:
        selection = self.findings_tree.selection()
        if not selection:
            messagebox.showinfo(APP_TITLE, "Select a finding first.")
            return None
        return self.finding_index.get(selection[0])

    def edit_selected_finding(self):
        finding = self.selected_finding()
        if not finding or not self.selected_session:
            return
        kind, item_id = finding
        sl_no = int(self.selected_session)

        if kind == "vuln":
            row = next((v for v in get_vulnerabilities(sl_no) if v[0] == item_id), None)
            if not row:
                self.refresh_all()
                return
            fields = [
                ("vuln_name", row[2], False),
                ("severity", row[3], False),
                ("port", row[4], False),
                ("service", row[5], False),
                ("description", row[6], True),
            ]
            dialog = EditValueDialog(self, "Edit Vulnerability", fields)
            self.wait_window(dialog)
            if dialog.result:
                for field, value in dialog.result.items():
                    edit_vulnerability(item_id, field, value)
                self._load_session(sl_no)
        elif kind == "fix":
            row = next((f for f in get_fixes(sl_no) if f[0] == item_id), None)
            if not row:
                self.refresh_all()
                return
            dialog = EditValueDialog(self, "Edit Fix", [("fix_text", row[3], True)])
            self.wait_window(dialog)
            if dialog.result:
                edit_fix(item_id, dialog.result["fix_text"])
                self._load_session(sl_no)
        elif kind == "exploit":
            row = next((e for e in get_exploits(sl_no) if e[0] == item_id), None)
            if not row:
                self.refresh_all()
                return
            fields = [
                ("exploit_name", row[2], False),
                ("tool_used", row[3], False),
                ("payload", row[4], True),
                ("result", row[5], True),
                ("notes", row[6], True),
            ]
            dialog = EditValueDialog(self, "Edit Exploit", fields)
            self.wait_window(dialog)
            if dialog.result:
                for field, value in dialog.result.items():
                    edit_exploit(item_id, field, value)
                self._load_session(sl_no)

    def delete_selected_finding(self):
        finding = self.selected_finding()
        if not finding or not self.selected_session:
            return
        kind, item_id = finding
        if not messagebox.askyesno(APP_TITLE, f"Delete this {kind}?"):
            return
        if kind == "vuln":
            delete_vulnerability(item_id)
        elif kind == "fix":
            delete_fix(item_id)
        elif kind == "exploit":
            delete_exploit(item_id)
        self._load_session(int(self.selected_session))
        self._set_status("Finding deleted.")

    def edit_selected_risk(self):
        data = self.current_session_data()
        if not data:
            return
        current = data["summary"][4] if data["summary"] else "UNKNOWN"
        dialog = EditValueDialog(
            self,
            "Edit Risk Level",
            [("risk_level", current if current in SEVERITY_ORDER else "UNKNOWN", False)],
        )
        self.wait_window(dialog)
        if not dialog.result:
            return
        risk = dialog.result["risk_level"].strip().upper()
        if risk not in SEVERITY_ORDER:
            messagebox.showwarning(APP_TITLE, "Use one of: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.")
            return
        sl_no = int(self.selected_session)
        if data["summary"]:
            edit_summary_risk(sl_no, risk)
        else:
            save_summary(sl_no, "", "", risk)
        self._load_session(int(self.selected_session))
        self._set_status(f"Risk level updated to {risk}.")

    def delete_selected_session(self):
        if not self.selected_session:
            messagebox.showinfo(APP_TITLE, "Select a session first.")
            return
        sl_no = int(self.selected_session)
        if not messagebox.askyesno(APP_TITLE, f"Permanently delete SL#{sl_no}?"):
            return
        delete_full_session(sl_no)
        self.selected_session = None
        self.refresh_all()
        self._set_status(f"SL#{sl_no} deleted.")

    def delete_selected_domain(self):
        if not self.selected_domain:
            messagebox.showinfo(APP_TITLE, "Select a domain first.")
            return
        selection = self.domain_tree.selection()
        if selection:
            mapping = self.domain_item_map.get(selection[0])
            if mapping and mapping.get("kind") == "subdomain":
                messagebox.showerror(APP_TITLE, "Subdomain is selected, please select the top-level domain to delete.")
                return
        if not messagebox.askyesno(APP_TITLE, f"Delete all scans for {self.selected_domain}?"):
            return
        delete_domain_sessions(self.selected_domain)
        self.selected_domain = ""
        self.selected_domain_target = ""
        self.refresh_all()
        self._set_status("Domain scans deleted.")

    def delete_selected_subdomains(self):
        selected = self.domain_tree.selection()
        if selected and all(
            self.domain_item_map.get(item, {}).get("kind") == "domain"
            for item in selected
        ):
            messagebox.showerror(APP_TITLE, "Top-level domain is selected, please select a subdomain to delete.")
            return
        subdomains = []
        for item in selected:
            mapping = self.domain_item_map.get(item)
            if mapping and mapping.get("kind") == "subdomain":
                items_to_delete = [item] + self._descendant_domain_items(item)
                for delete_item in items_to_delete:
                    delete_mapping = self.domain_item_map.get(delete_item)
                    if delete_mapping and delete_mapping.get("kind") == "subdomain":
                        pair = (delete_mapping["domain"], delete_mapping["target"])
                        if pair not in subdomains:
                            subdomains.append(pair)

        if not subdomains:
            messagebox.showinfo(APP_TITLE, "Highlight one or more subdomains first. Hold Shift to select a range.")
            return

        names = "\n".join(f"- {target}" for _domain, target in subdomains[:12])
        if len(subdomains) > 12:
            names += f"\n- ...and {len(subdomains) - 12} more"
        if not messagebox.askyesno(APP_TITLE, f"Delete these subdomains from the Domains list?\n\n{names}"):
            return

        for domain, target in subdomains:
            self._remove_manual_subdomain_reference(domain, target)
            self.suppressed_subdomains.setdefault(domain, set()).add(target)
            self.domain_scan_marks.pop(target, None)

        if messagebox.askyesno(APP_TITLE, "Also delete saved scan sessions for the selected subdomains?"):
            deleted = 0
            targets_by_domain: dict[str, set[str]] = {}
            for domain, target in subdomains:
                targets_by_domain.setdefault(domain, set()).add(normalize_target_host(target))
            for domain, targets in targets_by_domain.items():
                for row in get_scans_for_domain(domain):
                    sl_no, target, _scan_date, _status, _target_type, _parent = row
                    if normalize_target_host(target) in targets:
                        delete_full_session(sl_no)
                        deleted += 1
            if deleted:
                self._append_log(f"\n[+] Deleted {deleted} saved subdomain scan session(s).\n")

        self._save_gui_state()
        self.refresh_all()
        self._set_status(f"Deleted {len(subdomains)} subdomain(s) from the Domains list.")

    def _remove_manual_subdomain_reference(self, domain: str, target: str):
        self.manual_subdomains.get(domain, set()).discard(target)
        for children in self.manual_subdomain_children.values():
            children.discard(target)
        self.manual_subdomain_children.pop(target, None)

    def delete_everything(self):
        if not messagebox.askyesno(APP_TITLE, "Delete all saved reports?"):
            return
        delete_all_sessions()
        self.selected_domain = ""
        self.selected_domain_target = ""
        self.selected_session = None
        self.refresh_all()
        self._set_status("All saved reports deleted.")

    def open_reports_folder(self):
        path = default_reports_dir()
        os.makedirs(path, exist_ok=True)
        self._open_path(path)

    def _open_path(self, path: str):
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                webbrowser.open(Path(path).resolve().as_uri())
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Could not open:\n{path}\n\n{e}")

    def show_about(self):
        messagebox.showinfo(
            APP_TITLE,
            "PGS Metatron\n\nAI-powered penetration testing assistant for authorized security work.\n"
            "Use the Scan, History, and Tools menus for the main workflow.",
        )


def set_windows_taskbar_icon_id():
    if os.name != "nt":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ProguideSystems.Metatron.GUI")
    except Exception:
        pass


def set_windows_dpi_awareness():
    if os.name != "nt":
        return

    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        set_context = getattr(user32, "SetProcessDpiAwarenessContext", None)
        if set_context:
            set_context.argtypes = [ctypes.c_void_p]
            set_context.restype = ctypes.c_bool
            # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
            if set_context(ctypes.c_void_p(-4)):
                return
    except Exception:
        pass

    try:
        shcore = ctypes.WinDLL("shcore", use_last_error=True)
        set_awareness = getattr(shcore, "SetProcessDpiAwareness", None)
        if set_awareness:
            set_awareness.argtypes = [ctypes.c_int]
            set_awareness.restype = ctypes.c_long
            # PROCESS_PER_MONITOR_DPI_AWARE
            result = set_awareness(2)
            if result in (0, -2147024891):  # S_OK or already set
                return
    except Exception:
        pass

    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def acquire_single_instance_lock() -> bool:
    global SINGLE_INSTANCE_MUTEX_HANDLE
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        handle = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX_NAME)
        if not handle:
            return True
        SINGLE_INSTANCE_MUTEX_HANDLE = handle
        return ctypes.get_last_error() != 183
    except Exception:
        return True


def main():
    install_exception_logging()
    set_windows_dpi_awareness()
    set_windows_taskbar_icon_id()
    if not acquire_single_instance_lock():
        root = Tk()
        root.withdraw()
        try:
            messagebox.showinfo(APP_TITLE, "PGS Metatron is already running.")
        finally:
            root.destroy()
        return
    try:
        app = MetatronApp()
        app.mainloop()
    except Exception:
        details = traceback.format_exc()
        write_crash_log("Fatal GUI crash", details)
        raise


if __name__ == "__main__":
    main()
