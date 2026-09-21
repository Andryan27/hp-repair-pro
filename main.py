from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import tkinter as tk
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_NAME = "AN tech"
APP_VERSION = "7.1.0 PRO"
APP_TAGLINE = "Professional Smartphone Diagnostic & Service Center"
# AUTO UPDATE CONFIG - ganti URL server kamu nanti
UPDATE_SERVER_URL = os.environ.get("ANTECH_UPDATE_URL", "https://raw.githubusercontent.com/Andryan27/hp-repair-pro/main/version.json")
UPDATE_DOWNLOAD_URL = "https://raw.githubusercontent.com/Andryan27/hp-repair-pro/main/app/main.py"
BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR / "tools"
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
DATA_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "antech.db"

C_ADB = Path(r"C:\platform-tools\adb.exe")
C_FASTBOOT = Path(r"C:\platform-tools\fastboot.exe")

ADB_EXE = C_ADB if C_ADB.exists() else TOOLS_DIR / "adb.exe"
FASTBOOT_EXE = C_FASTBOOT if C_FASTBOOT.exists() else TOOLS_DIR / "fastboot.exe"

SAFE_FASTBOOT_PARTITIONS = [
    "boot", "init_boot", "vendor_boot", "recovery", "dtbo", "vbmeta",
    "system", "system_a", "system_b", "vendor", "vendor_a", "vendor_b",
    "product", "product_a", "product_b", "odm", "odm_a", "odm_b",
    "super", "userdata", "cache"
]

DIAG_PROPS = [
    ("Manufacturer", "ro.product.manufacturer"),
    ("Model", "ro.product.model"),
    ("Device", "ro.product.device"),
    ("Android", "ro.build.version.release"),
    ("Security Patch", "ro.build.version.security_patch"),
    ("Fingerprint", "ro.build.fingerprint"),
    ("Slot", "ro.boot.slot_suffix"),
    ("Verified Boot", "ro.boot.verifiedbootstate"),
    ("Bootloader State", "ro.boot.flash.locked"),
    ("Baseband", "gsm.version.baseband"),
    ("Serial", "ro.serialno"),
]

MODE_META = {
    "ADB": ("Android Debug Bridge", "USB debugging / Android OS"),
    "FASTBOOT": ("Fastboot / Bootloader", "Bootloader service interface"),
    "EDL": ("Qualcomm Emergency Download", "Qualcomm 9008 interface"),
    "PRELOADER": ("MediaTek Preloader", "MediaTek download/preloader interface"),
    "BROM": ("MediaTek Boot ROM", "MediaTek BootROM interface"),
}


@dataclass
class DeviceInfo:
    mode: str
    serial: str = ""
    model: str = ""
    product: str = ""
    state: str = ""
    detail: str = ""
    connected_at: str = ""



# === JUDOL / MALWARE / ADWARE DEFINITIONS ===
JUDOL_KEYWORDS = [
    "slot", "gacor", "maxwin", "zeus", "pragmatic", "togel", "judol", "judi",
    "pinjol", "pinjaman", "adware", "casino", "bet", "sbobet", "mpo",
    "higgs", "domino", "scatter", "jackpot", "gates of olympus", "mahjong"
]

SUSPICIOUS_PACKAGES_PATTERNS = [
    "com.affinity", "com.lucky", "com.malware", "com.adware", "com.popad",
    "com.judi", "com.slot", "com.xads", "com.fake"
]

# Known adware system overlay packages
ADWARE_SYSTEM_INDICATORS = [
    "com.android.systemui.overlay", "com.wsandroid.suite", "com.coloros.safecenter"
]

# ---------- Windows process helpers ----------

def run_process(args: list[str], timeout: int = 20, cwd: Path | None = BASE_DIR) -> tuple[int, str]:
    """Windows-safe process runner. No shell, no Linux host utilities."""
    try:
        cp = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return cp.returncode, cp.stdout.strip()
    except FileNotFoundError:
        return 127, f"File tidak ditemukan: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "Perintah timeout."
    except Exception as exc:
        return 1, f"Error: {exc}"


def powershell(script: str, timeout: int = 15) -> tuple[int, str]:
    return run_process([
        "powershell.exe", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", script
    ], timeout=timeout)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def parse_version(value: str) -> tuple[int, ...]:
    """Parse semantic-ish versions safely: 7.1.0 PRO -> (7,1,0)."""
    nums = re.findall(r"\d+", value or "")
    return tuple(int(x) for x in nums[:4]) or (0,)


def version_is_newer(remote: str, current: str) -> bool:
    a, b = parse_version(remote), parse_version(current)
    n = max(len(a), len(b))
    return (a + (0,) * (n-len(a))) > (b + (0,) * (n-len(b)))


def shell_text(*parts: str) -> list[str]:
    """Build an ADB shell command without shell=True."""
    return ["shell", *[str(x) for x in parts]]


def parse_key_values(text: str) -> dict[str, str]:
    result = {}
    for line in (text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            result[k.strip()] = v.strip()
    return result


def classify_logcat(text: str) -> dict[str, list[str]]:
    """Rule-based crash/fault classifier; deliberately avoids claiming hardware failure."""
    patterns = {
        "Kernel/Boot": r"(kernel panic|watchdog|fatal exception|bootloop|subsystem restart|ssr)",
        "System Crash": r"(FATAL EXCEPTION|system_server.*(crash|died)|am_crash|system server.*fatal)",
        "App Crash": r"(FATAL EXCEPTION IN MAIN|AndroidRuntime.*FATAL EXCEPTION|am_crash)",
        "Storage": r"(I/O error|I/O error|mmc.*error|ufs.*error|fsck.*fail|eio|corrupt)",
        "Modem/Radio": r"(modem.*(fatal|crash|restart)|subsystem.*modem|qmi.*(error|fail)|radio.*crash)",
        "Display": r"(HwcComposer.*(failed|error)|SurfaceFlinger.*(fatal|error)|display.*(failed|error)|CWB.*error)",
        "Thermal": r"(thermal.*(critical|shutdown|overheat)|overheat|thermal throttling)",
    }
    out = {k: [] for k in patterns}
    lines = (text or "").splitlines()
    for line in lines:
        low = line.lower()
        for cat, pat in patterns.items():
            if re.search(pat, low, re.I):
                out[cat].append(line.strip())
    return out


class Database:
    def __init__(self, path: Path):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                customer TEXT,
                phone TEXT,
                technician TEXT,
                complaint TEXT,
                status TEXT DEFAULT 'OPEN'
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS device_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                mode TEXT,
                serial TEXT,
                model TEXT,
                product TEXT,
                state TEXT,
                detail TEXT
            )
        """)
        self.conn.commit()

    def add_log(self, category: str, message: str):
        with self.lock:
            self.conn.execute(
                "INSERT INTO logs(created_at, category, message) VALUES(?,?,?)",
                (datetime.now().isoformat(timespec="seconds"), category, message),
            )
            self.conn.commit()

    def add_device(self, d: DeviceInfo):
        with self.lock:
            self.conn.execute(
                "INSERT INTO device_history(created_at, mode, serial, model, product, state, detail) VALUES(?,?,?,?,?,?,?)",
                (datetime.now().isoformat(timespec="seconds"), d.mode, d.serial, d.model, d.product, d.state, d.detail),
            )
            self.conn.commit()

    def add_job(self, customer: str, phone: str, tech: str, complaint: str) -> int:
        with self.lock:
            cur = self.conn.execute(
                "INSERT INTO jobs(created_at, customer, phone, technician, complaint) VALUES(?,?,?,?,?)",
                (datetime.now().isoformat(timespec="seconds"), customer, phone, tech, complaint),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def recent_logs(self, limit: int = 400):
        with self.lock:
            return self.conn.execute(
                "SELECT created_at, category, message FROM logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def recent_jobs(self, limit: int = 30):
        with self.lock:
            return self.conn.execute(
                "SELECT id, created_at, customer, phone, technician, complaint, status FROM jobs ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()


# ---------- Detection ----------

class DeviceDetector:
    @staticmethod
    def adb() -> list[DeviceInfo]:
        if not ADB_EXE.exists():
            return []
        run_process([str(ADB_EXE), "start-server"], timeout=8)
        _, out = run_process([str(ADB_EXE), "devices", "-l"], timeout=8)
        found: list[DeviceInfo] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            kv = {}
            for p in parts[2:]:
                if ":" in p:
                    k, v = p.split(":", 1)
                    kv[k] = v
            found.append(DeviceInfo(
                mode="ADB",
                serial=serial,
                state=state,
                model=kv.get("model", "").replace("_", " "),
                product=kv.get("product", ""),
                detail=line,
                connected_at=datetime.now().strftime("%H:%M:%S"),
            ))
        return found

    @staticmethod
    def fastboot() -> list[DeviceInfo]:
        if not FASTBOOT_EXE.exists():
            return []
        _, out = run_process([str(FASTBOOT_EXE), "devices"], timeout=8)
        found: list[DeviceInfo] = []
        for line in out.splitlines():
            m = re.match(r"^([^\s]+)\s+fastboot\b", line.strip(), re.I)
            if not m:
                continue
            serial = m.group(1)
            _, prod = run_process([str(FASTBOOT_EXE), "-s", serial, "getvar", "product"], timeout=8)
            pm = re.search(r"product:\s*(\S+)", prod, re.I)
            found.append(DeviceInfo(
                mode="FASTBOOT", serial=serial,
                product=pm.group(1) if pm else "",
                state="connected", detail=line.strip(), connected_at=datetime.now().strftime("%H:%M:%S")
            ))
        return found

    @staticmethod
    def windows_usb_modes() -> list[DeviceInfo]:
        script = r'''
$devs = Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match '^USB\\' }
foreach ($d in $devs) {
  $name = [string]$d.Name
  $id = [string]$d.PNPDeviceID
  Write-Output ($name + "|||" + $id)
}
'''
        code, out = powershell(script)
        if code != 0:
            return []
        found: list[DeviceInfo] = []
        seen = set()
        for line in out.splitlines():
            if "|||" not in line:
                continue
            name, pnpid = line.split("|||", 1)
            hay = f"{name} {pnpid}".lower()
            mode = None
            if "vid_05c6&pid_9008" in hay or "qdloader 9008" in hay or "qualcomm hs-usb qdloader" in hay:
                mode = "EDL"
            elif "mediatek" in hay and ("preloader" in hay or "vcom" in hay):
                mode = "PRELOADER"
            elif "vid_0e8d" in hay and ("bootrom" in hay or "brom" in hay):
                mode = "BROM"
            elif "vid_0e8d" in hay and "preloader" in hay:
                mode = "PRELOADER"
            if mode:
                key = (mode, pnpid)
                if key not in seen:
                    seen.add(key)
                    found.append(DeviceInfo(
                        mode=mode, state="connected", detail=name.strip(), serial=pnpid.strip(),
                        connected_at=datetime.now().strftime("%H:%M:%S")
                    ))
        return found

    @classmethod
    def scan_all(cls) -> list[DeviceInfo]:
        result = []
        try:
            result.extend(cls.adb())
        except Exception:
            pass
        try:
            result.extend(cls.fastboot())
        except Exception:
            pass
        try:
            result.extend(cls.windows_usb_modes())
        except Exception:
            pass
        return result


# ---------- UI ----------

class ANTechApp(tk.Tk):
    BG = "#0b1220"
    PANEL = "#111b2d"
    PANEL_2 = "#162238"
    PANEL_3 = "#1a2a45"
    TEXT = "#e8eef8"
    MUTED = "#8fa2bf"
    ACCENT = "#27a8ff"
    ACCENT_2 = "#7a5cff"
    GREEN = "#24d28a"
    ORANGE = "#ffb648"
    RED = "#ff6b81"
    LINE = "#243555"

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION} — {APP_TAGLINE}")
        self.geometry("1440x900")
        self.minsize(1200, 760)
        self.configure(bg=self.BG)
        self.db = Database(DB_PATH)
        self.devices: list[DeviceInfo] = []
        self.selected_index: int | None = None
        self.current_tab = "Dashboard"
        self.scan_job = None
        self.auto_scan = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="System ready")
        self.device_count_var = tk.StringVar(value="0")
        self.adb_count_var = tk.StringVar(value="0")
        self.boot_count_var = tk.StringVar(value="0")
        self.alert_var = tk.StringVar(value="0")
        self.selected_mode_var = tk.StringVar(value="—")
        self.selected_id_var = tk.StringVar(value="No device selected")
        self.selected_model_var = tk.StringVar(value="—")
        self.selected_state_var = tk.StringVar(value="—")
        self.job_id_var = tk.StringVar(value="JOB —")
        self.customer_var = tk.StringVar()
        self.phone_var = tk.StringVar()
        self.tech_var = tk.StringVar(value="AN tech Operator")
        self.complaint_var = tk.StringVar()
        self.partition_var = tk.StringVar(value="boot")
        self.image_var = tk.StringVar()
        self.image_hash_var = tk.StringVar(value="SHA-256: —")
        self.hash_ok_var = tk.BooleanVar(value=False)
        # Battery Live Monitor vars
        self.batt_level_var = tk.StringVar(value="—")
        self.batt_volt_var = tk.StringVar(value="—")
        self.batt_current_var = tk.StringVar(value="—")
        self.batt_temp_var = tk.StringVar(value="—")
        self.batt_status_var = tk.StringVar(value="—")
        self.batt_health_var = tk.StringVar(value="—")
        self.batt_source_var = tk.StringVar(value="—")
        self.battery_monitoring = False

        self._setup_style()
        self._build_ui()
        self._load_jobs()
        self.after(600, self.scan_devices)
        self.after(2500, self._auto_scan_tick)
        self.after(5000, lambda: self.check_auto_update(silent=True))  # auto cek update 5 detik setelah buka, silent

    # --- Styling ---
    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=self.BG)
        style.configure("Card.TFrame", background=self.PANEL)
        style.configure("TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 9))
        style.configure("Header.TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 20, "bold"))
        style.configure("SubHeader.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 11, "bold"))
        style.configure("Metric.TLabel", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 22, "bold"))
        style.configure("Side.TButton", background=self.PANEL, foreground=self.TEXT, borderwidth=0, padding=(14, 12), anchor="w", font=("Segoe UI", 10))
        style.map("Side.TButton", background=[("active", self.PANEL_3)], foreground=[("active", "white")])
        style.configure("Primary.TButton", background=self.ACCENT, foreground="white", borderwidth=0, padding=(13, 8), font=("Segoe UI", 10, "bold"))
        style.map("Primary.TButton", background=[("active", "#4ab8ff")])
        style.configure("Ghost.TButton", background=self.PANEL_2, foreground=self.TEXT, borderwidth=0, padding=(11, 8), font=("Segoe UI", 9, "bold"))
        style.map("Ghost.TButton", background=[("active", self.PANEL_3)])
        style.configure("Danger.TButton", background="#54253a", foreground="#ffd7df", borderwidth=0, padding=(11, 8), font=("Segoe UI", 9, "bold"))
        style.configure("TEntry", fieldbackground=self.PANEL_2, foreground=self.TEXT, insertcolor=self.TEXT, borderwidth=0, padding=7)
        style.configure("TCombobox", fieldbackground=self.PANEL_2, foreground=self.TEXT, borderwidth=0, padding=7)
        style.configure("Treeview", background=self.PANEL, fieldbackground=self.PANEL, foreground=self.TEXT, rowheight=30, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=self.PANEL_3, foreground=self.MUTED, font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("Treeview", background=[("selected", "#214d79")], foreground=[("selected", "white")])
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.PANEL, foreground=self.MUTED, padding=(16, 8), font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.PANEL_3)], foreground=[("selected", "white")])
        style.configure("Horizontal.TProgressbar", troughcolor=self.PANEL_2, background=self.ACCENT, borderwidth=0)
        style.configure("TCheckbutton", background=self.BG, foreground=self.TEXT)

    def _card(self, parent, title: str, subtitle: str = "") -> ttk.Frame:
        outer = ttk.Frame(parent, style="Card.TFrame", padding=16)
        ttk.Label(outer, text=title, style="CardTitle.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(outer, text=subtitle, background=self.PANEL, foreground=self.MUTED).pack(anchor="w", pady=(3, 10))
        return outer

    def _build_ui(self):
        self._build_topbar()
        main = ttk.Frame(self, padding=(12, 0, 12, 12))
        main.pack(fill="both", expand=True)
        self.sidebar = ttk.Frame(main, style="Card.TFrame", width=210, padding=(8, 14))
        self.sidebar.pack(side="left", fill="y", padx=(0, 10))
        self.content = ttk.Frame(main)
        self.content.pack(side="left", fill="both", expand=True)
        self._build_sidebar()
        self._build_pages()
        self._build_statusbar()
        self.show_page("Dashboard")

    def _build_topbar(self):
        top = ttk.Frame(self, padding=(18, 14, 18, 10))
        top.pack(fill="x")
        brand = ttk.Frame(top)
        brand.pack(side="left")
        ttk.Label(brand, text="AN", foreground=self.ACCENT, background=self.BG, font=("Segoe UI", 19, "bold")).pack(side="left")
        ttk.Label(brand, text=" tech", foreground=self.TEXT, background=self.BG, font=("Segoe UI", 19, "bold")).pack(side="left")
        ttk.Label(brand, text="  PRO SERVICE CENTER", foreground=self.MUTED, background=self.BG, font=("Segoe UI", 9, "bold")).pack(side="left", pady=(6, 0))
        right = ttk.Frame(top)
        right.pack(side="right")
        self.top_device_badge = tk.Label(right, text="0 DEVICE", bg=self.PANEL_2, fg=self.TEXT, padx=12, pady=7, font=("Segoe UI", 9, "bold"))
        self.top_device_badge.pack(side="left", padx=(0, 8))
        ttk.Checkbutton(right, text="Auto Scan", variable=self.auto_scan).pack(side="left", padx=(0, 8))
        ttk.Button(right, text="↻  Scan", style="Primary.TButton", command=self.scan_devices).pack(side="left")

    def _build_sidebar(self):
        ttk.Label(self.sidebar, text="WORKSPACE", background=self.PANEL, foreground=self.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=8, pady=(2, 9))
        self.nav_buttons = {}
        for name, icon in [
            ("Dashboard", "▦"), ("Diagnostics", "⌁"), ("Service Center", "⚙"),
            ("Cleaner Judol", "🧹"), ("Firmware Lab", "▣"), ("Logs & Reports", "≡"), ("Settings", "⚙")
        ]:
            btn = ttk.Button(self.sidebar, text=f"{icon}   {name}", style="Side.TButton", command=lambda n=name: self.show_page(n))
            btn.pack(fill="x", pady=2)
            self.nav_buttons[name] = btn
        ttk.Separator(self.sidebar).pack(fill="x", pady=14)
        ttk.Label(self.sidebar, text="SAFETY", background=self.PANEL, foreground=self.MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=8, pady=(0, 8))
        tk.Label(self.sidebar, text="Built-in guardrails enabled\n• Official/user-supplied firmware\n• No IMEI / FRP bypass\n• No auth-bypass routines\n• Destructive actions require confirm", justify="left", bg=self.PANEL, fg=self.MUTED, font=("Segoe UI", 8), wraplength=175).pack(fill="x", padx=8)

    def _build_pages(self):
        self.pages: dict[str, ttk.Frame] = {}
        self.pages["Dashboard"] = self._dashboard_page()
        self.pages["Diagnostics"] = self._diagnostics_page()
        self.pages["Service Center"] = self._service_page()
        self.pages["Cleaner Judol"] = self._cleaner_page()
        self.pages["Firmware Lab"] = self._firmware_page()
        self.pages["Logs & Reports"] = self._logs_page()
        self.pages["Settings"] = self._settings_page()

    def _build_statusbar(self):
        bar = tk.Frame(self, bg="#080e18", height=28)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.status_var, bg="#080e18", fg=self.MUTED, font=("Segoe UI", 8)).pack(side="left", padx=12, pady=5)
        tk.Label(bar, text=f"{APP_NAME} {APP_VERSION} • Windows • Local Service Database", bg="#080e18", fg=self.MUTED, font=("Segoe UI", 8)).pack(side="right", padx=12)

    # --- Pages ---
    def _dashboard_page(self):
        f = ttk.Frame(self.content)
        head = ttk.Frame(f)
        head.pack(fill="x", pady=(2, 14))
        ttk.Label(head, text="Service Dashboard", style="Header.TLabel").pack(anchor="w")
        ttk.Label(head, text="Monitor perangkat, diagnosis cepat, dan workflow teknisi dalam satu tempat.", style="SubHeader.TLabel").pack(anchor="w")

        metrics = ttk.Frame(f)
        metrics.pack(fill="x", pady=(0, 12))
        cards = [
            ("Connected Devices", self.device_count_var, "USB interfaces detected"),
            ("ADB Devices", self.adb_count_var, "Android debug sessions"),
            ("Boot Interfaces", self.boot_count_var, "Fastboot / EDL / MTK"),
            ("Alerts", self.alert_var, "Actionable diagnostics"),
        ]
        for title, var, sub in cards:
            c = self._card(metrics, title)
            c.pack(side="left", fill="both", expand=True, padx=5)
            ttk.Label(c, textvariable=var, style="Metric.TLabel").pack(anchor="w")
            ttk.Label(c, text=sub, background=self.PANEL, foreground=self.MUTED).pack(anchor="w")

        lower = ttk.Frame(f)
        lower.pack(fill="both", expand=True)
        left = self._card(lower, "Live Device Monitor", "Klik perangkat untuk memuat diagnosis dan action context.")
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.dashboard_tree = self._device_tree(left)
        self.dashboard_tree.bind("<<TreeviewSelect>>", lambda e: self._sync_tree_selection(self.dashboard_tree))
        right = self._card(lower, "Selected Device", "Ringkasan interface yang aktif.")
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self._selected_summary(right)
        return f

    def _diagnostics_page(self):
        f = ttk.Frame(self.content)
        head = ttk.Frame(f)
        head.pack(fill="x", pady=(2, 12))
        ttk.Label(head, text="Smart Diagnostics", style="Header.TLabel").pack(anchor="w")
        ttk.Label(head, text="Analisis mode, Android properties, battery state, verified boot, dan logcat snapshot.", style="SubHeader.TLabel").pack(anchor="w")
        toolrow = ttk.Frame(f)
        toolrow.pack(fill="x", pady=(0, 10))
        ttk.Button(toolrow, text="Run Smart Diagnosis", style="Primary.TButton", command=self.auto_diagnose).pack(side="left")
        ttk.Button(toolrow, text="Refresh Properties", style="Ghost.TButton", command=self.adb_info).pack(side="left", padx=8)
        ttk.Button(toolrow, text="Logcat Snapshot", style="Ghost.TButton", command=self.adb_logcat).pack(side="left")
        ttk.Button(toolrow, text="Save Diagnostic Report", style="Ghost.TButton", command=self.export_report).pack(side="right")
        pane = ttk.Panedwindow(f, orient="horizontal")
        pane.pack(fill="both", expand=True)
        info = ttk.Frame(pane, padding=8)
        console = ttk.Frame(pane, padding=8)
        pane.add(info, weight=1)
        pane.add(console, weight=2)
        # Battery Live Monitor Card
        batt_card = self._card(info, "Battery Live Monitor (V/A/°C)", "Volt & Ampere saat HP colok PC/Charger - Live via ADB")
        batt_card.pack(fill="x", pady=(0,10))
        batt_grid = ttk.Frame(batt_card, style="Card.TFrame")
        batt_grid.pack(fill="x")
        def add_batt_row(label, var, r, c):
            ttk.Label(batt_grid, text=label, background=self.PANEL, foreground=self.MUTED, font=("Segoe UI", 8, "bold")).grid(row=r, column=c*2, sticky="w", pady=4, padx=(0,6))
            ttk.Label(batt_grid, textvariable=var, background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 10, "bold")).grid(row=r, column=c*2+1, sticky="w", pady=4, padx=(0,16))
        add_batt_row("Level", self.batt_level_var, 0, 0)
        add_batt_row("Voltage", self.batt_volt_var, 0, 1)
        add_batt_row("Current", self.batt_current_var, 1, 0)
        add_batt_row("Temp", self.batt_temp_var, 1, 1)
        add_batt_row("Status", self.batt_status_var, 2, 0)
        add_batt_row("Health", self.batt_health_var, 2, 1)
        add_batt_row("Source", self.batt_source_var, 3, 0)
        btn_row = ttk.Frame(batt_card, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(8,0))
        ttk.Button(btn_row, text="Read Battery", style="Ghost.TButton", command=self.read_battery_live).pack(side="left", padx=(0,6))
        ttk.Button(btn_row, text="Start Live Monitor", style="Ghost.TButton", command=self.start_battery_monitor).pack(side="left", padx=(0,6))
        ttk.Button(btn_row, text="Stop", style="Ghost.TButton", command=self.stop_battery_monitor).pack(side="left")

        box = self._card(info, "Health Indicators", "")
        box.pack(fill="both", expand=True)
        self.health_tree = ttk.Treeview(box, columns=("metric", "value", "status"), show="headings")
        for c, h, w in [("metric", "METRIC", 160), ("value", "VALUE", 140), ("status", "STATUS", 90)]:
            self.health_tree.heading(c, text=h)
            self.health_tree.column(c, width=w, anchor="w")
        self.health_tree.pack(fill="both", expand=True)
        cbox = self._card(console, "Diagnostic Console", "Output backend ADB / Fastboot / Windows USB detection.")
        cbox.pack(fill="both", expand=True)
        self.diag_console = self._text(cbox, height=30)
        return f

    def _service_page(self):
        f = ttk.Frame(self.content)
        ttk.Label(f, text="Service Center", style="Header.TLabel").pack(anchor="w", pady=(2, 3))
        ttk.Label(f, text="Buat job servis, jalankan tindakan terkendali, dan simpan jejak aktivitas teknisi.", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 12))
        top = ttk.Frame(f)
        top.pack(fill="x")
        job = self._card(top, "Service Job", "Data dasar tiket pekerjaan teknisi.")
        job.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self._form_row(job, "Customer", self.customer_var, 0)
        self._form_row(job, "Phone", self.phone_var, 1)
        self._form_row(job, "Technician", self.tech_var, 2)
        self._form_row(job, "Complaint", self.complaint_var, 3)
        ttk.Button(job, text="Create Job", style="Primary.TButton", command=self.create_job).pack(anchor="e", pady=(10, 0))

        actions = self._card(top, "Controlled Service Actions", "Action tersedia sesuai mode perangkat yang dipilih.")
        actions.pack(side="left", fill="both", expand=True, padx=(6, 0))
        btns = [
            ("ADB → System", lambda: self.adb_reboot("")),
            ("ADB → Recovery", lambda: self.adb_reboot("recovery")),
            ("ADB → Bootloader", lambda: self.adb_reboot("bootloader")),
            ("Fastboot Reboot", self.fastboot_reboot),
            ("Detect Lock Type", self.detect_lock_type),
            ("Factory Reset (Wipe Data)", self.factory_reset_wipe),
            ("Fastboot Wipe (fastboot -w)", self.factory_reset_fastboot_wipe),
            ("ADB Sideload ZIP", self.adb_sideload),
            ("ADB Packages", self.adb_packages),
        ]
        btn_frame = ttk.Frame(actions, style="Card.TFrame")
        btn_frame.pack(fill="x", pady=(4, 0))
        for i, (txt, cb) in enumerate(btns):
            ttk.Button(btn_frame, text=txt, style="Ghost.TButton", command=cb).grid(row=i // 2, column=i % 2, sticky="ew", padx=4, pady=4)
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)

        history = self._card(f, "Service History", "Job terakhir tersimpan di SQLite lokal.")
        history.pack(fill="both", expand=True, pady=(12, 0))
        cols = ("id", "created", "customer", "phone", "tech", "complaint", "status")
        self.jobs_tree = ttk.Treeview(history, columns=cols, show="headings", height=10)
        for c, h, w in [("id", "ID", 55), ("created", "CREATED", 145), ("customer", "CUSTOMER", 150), ("phone", "PHONE", 120), ("tech", "TECHNICIAN", 140), ("complaint", "COMPLAINT", 320), ("status", "STATUS", 85)]:
            self.jobs_tree.heading(c, text=h)
            self.jobs_tree.column(c, width=w, anchor="w")
        self.jobs_tree.pack(fill="both", expand=True)
        return f

    def _firmware_page(self):
        f = ttk.Frame(self.content)
        ttk.Label(f, text="Firmware Lab", style="Header.TLabel").pack(anchor="w", pady=(2, 3))
        ttk.Label(f, text="Controlled Fastboot flashing dengan image verification dan audit log.", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 12))
        main = ttk.Frame(f)
        main.pack(fill="both", expand=True)
        left = self._card(main, "Fastboot Flash Station", "Gunakan firmware yang cocok dengan model/region/perangkat.")
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ttk.Label(left, text="Partition", background=self.PANEL, foreground=self.MUTED).pack(anchor="w")
        ttk.Combobox(left, textvariable=self.partition_var, values=SAFE_FASTBOOT_PARTITIONS, state="readonly").pack(fill="x", pady=(4, 10))
        ttk.Label(left, text="Image file", background=self.PANEL, foreground=self.MUTED).pack(anchor="w")
        row = ttk.Frame(left, style="Card.TFrame")
        row.pack(fill="x", pady=(4, 8))
        ttk.Entry(row, textvariable=self.image_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Browse", style="Ghost.TButton", command=self.choose_image).pack(side="left", padx=(7, 0))
        ttk.Label(left, textvariable=self.image_hash_var, background=self.PANEL, foreground=self.MUTED).pack(anchor="w", pady=(2, 5))
        self.hash_progress = ttk.Progressbar(left, mode="indeterminate", style="Horizontal.TProgressbar")
        self.hash_progress.pack(fill="x", pady=(2, 10))
        ttk.Button(left, text="Calculate SHA-256", style="Ghost.TButton", command=self.calculate_hash).pack(fill="x", pady=4)
        ttk.Button(left, text="Flash Selected Partition", style="Primary.TButton", command=self.fastboot_flash).pack(fill="x", pady=4)
        ttk.Label(left, text="Guardrails: FRP bypass, IMEI modification, auth bypass, dan hidden persistence tidak disediakan.", background=self.PANEL, foreground=self.ORANGE, wraplength=470, justify="left").pack(anchor="w", pady=(14, 0))

        right = self._card(main, "Low-Level Interface Status", "EDL / Preloader / BROM detection-only pada versi ini.")
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.low_mode_list = tk.Listbox(right, bg=self.PANEL_2, fg=self.TEXT, selectbackground="#214d79", relief="flat", highlightthickness=0, font=("Segoe UI", 10), height=12)
        self.low_mode_list.pack(fill="both", expand=True)
        ttk.Label(right, text="Untuk low-level flashing, backend harus disesuaikan dengan chipset/vendor dan loader/DA resmi. AN tech tidak mencoba melewati Secure Boot/authentication.", background=self.PANEL, foreground=self.MUTED, wraplength=460, justify="left").pack(anchor="w", pady=(10, 0))
        return f

    def _logs_page(self):
        f = ttk.Frame(self.content)
        ttk.Label(f, text="Logs & Reports", style="Header.TLabel").pack(anchor="w", pady=(2, 3))
        ttk.Label(f, text="Audit trail operasi dan export report untuk dokumentasi servis.", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 12))
        toolbar = ttk.Frame(f)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="Refresh Logs", style="Ghost.TButton", command=self.refresh_logs).pack(side="left")
        ttk.Button(toolbar, text="Export Report", style="Primary.TButton", command=self.export_report).pack(side="right")
        box = self._card(f, "Activity Timeline")
        box.pack(fill="both", expand=True)
        self.logs_text = self._text(box, height=35)
        self.refresh_logs()
        return f


    def _cleaner_page(self):
        f = ttk.Frame(self.content)
        ttk.Label(f, text="Cleaner Judol / Iklan / Malware PRO", style="Header.TLabel").pack(anchor="w", pady=(2, 3))
        ttk.Label(f, text="Risk-based package audit untuk aplikasi mencurigakan/adware. Semua operasi ditargetkan ke ADB device yang dipilih.", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 12))
        
        top = ttk.Frame(f)
        top.pack(fill="x", pady=5)
        ttk.Button(top, text="🔍 Scan Cepat (App User)", style="Primary.TButton", command=lambda: self.scan_judol_cleaner(deep=False)).pack(side="left", padx=5)
        ttk.Button(top, text="🔬 Deep Scan (Semua App + Admin)", style="Ghost.TButton", command=lambda: self.scan_judol_cleaner(deep=True)).pack(side="left", padx=5)
        ttk.Button(top, text="🗑️ Hapus Terpilih", style="Danger.TButton", command=self.remove_selected_cleaner).pack(side="left", padx=10)
        ttk.Button(top, text="🛡️ Anti Iklan", command=self.disable_ads_system).pack(side="left", padx=5)

        # Tree
        cols = ("package", "risk", "reason", "version")
        self.cleaner_tree = ttk.Treeview(f, columns=cols, show="headings", height=18)
        self.cleaner_tree.heading("package", text="Package Name")
        self.cleaner_tree.heading("risk", text="Risk")
        self.cleaner_tree.heading("reason", text="Alasan Deteksi")
        self.cleaner_tree.heading("version", text="Versi")
        self.cleaner_tree.column("package", width=280)
        self.cleaner_tree.column("risk", width=60, anchor="center")
        self.cleaner_tree.column("reason", width=380)
        self.cleaner_tree.column("version", width=120)
        self.cleaner_tree.pack(fill="both", expand=True, pady=10)

        # Log text
        self.cleaner_text = self._text(f, height=10)
        self.cleaner_text.insert("1.0", "Siap scan...\n• Keyword: slot, gacor, maxwin, togel, judol, pinjol, casino, higgs domino\n• Cek Device Admin palsu & overlay pop-up\n\nColok HP > Scan Cepat\n")
        return f

    def _settings_page(self):
        f = ttk.Frame(self.content)
        ttk.Label(f, text="Settings", style="Header.TLabel").pack(anchor="w", pady=(2, 3))
        ttk.Label(f, text="Environment, tools, local storage, update integrity, and Windows-safe execution.", style="SubHeader.TLabel").pack(anchor="w", pady=(0, 12))
        box = self._card(f, "Environment")
        box.pack(fill="x")
        rows = [
            ("Platform Tools", str(TOOLS_DIR), ADB_EXE.exists() and FASTBOOT_EXE.exists()),
            ("Database", str(DB_PATH), DB_PATH.exists()),
            ("Reports", str(REPORT_DIR), True),
        ]
        env_frame = ttk.Frame(box, style="Card.TFrame")
        env_frame.pack(fill="x", pady=(4, 0))
        for i, (name, path, ok) in enumerate(rows):
            ttk.Label(env_frame, text=name, background=self.PANEL, foreground=self.MUTED).grid(row=i, column=0, sticky="w", pady=7)
            ttk.Label(env_frame, text=path, background=self.PANEL, foreground=self.TEXT).grid(row=i, column=1, sticky="w", padx=12)
            ttk.Label(env_frame, text="READY" if ok else "MISSING", background=self.PANEL, foreground=self.GREEN if ok else self.RED).grid(row=i, column=2, sticky="e", padx=8)
        env_frame.columnconfigure(1, weight=1)
        update_box = self._card(f, "Auto Update System")
        update_box.pack(fill="x", pady=(0,12))
        ttk.Label(update_box, text=f"Current Version: {APP_VERSION}", background=self.PANEL, foreground=self.TEXT, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(update_box, text=f"Server: {UPDATE_SERVER_URL}", background=self.PANEL, foreground=self.MUTED, wraplength=800).pack(anchor="w", pady=(4,8))
        row = ttk.Frame(update_box, style="Card.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Check Update Now", style="Primary.TButton", command=lambda: self.check_auto_update(silent=False)).pack(side="left", padx=(0,8))
        ttk.Button(row, text="Download Log (Copy-Paste Ready)", style="Ghost.TButton", command=lambda: self._save_text_to_file(self.logs_text) if hasattr(self, 'logs_text') else None).pack(side="left")
        ttk.Label(update_box, text="Fitur: Klik kanan di Diagnostic Console / Logs untuk Copy, Select All, Save. Auto update cek tiap buka aplikasi tanpa ubah desain.", background=self.PANEL, foreground=self.GREEN, wraplength=900, justify="left").pack(anchor="w", pady=(8,0))

        safety = self._card(f, "Production Notes")
        safety.pack(fill="x", pady=(12, 0))
        ttk.Label(safety, text="AN tech menggunakan subprocess tanpa shell=True dan tidak mengandalkan grep/head/awk. Semua parsing output dilakukan dengan Python regex/string processing agar sesuai dengan workflow Windows.", background=self.PANEL, foreground=self.TEXT, wraplength=950, justify="left").pack(anchor="w")
        return f

    # --- UI helpers ---
    def _device_tree(self, parent):
        cols = ("mode", "serial", "model", "product", "state")
        tree = ttk.Treeview(parent, columns=cols, show="headings", height=15)
        for c, h, w in [("mode", "MODE", 105), ("serial", "SERIAL / PNP ID", 250), ("model", "MODEL", 150), ("product", "PRODUCT", 130), ("state", "STATE", 110)]:
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w")
        tree.pack(fill="both", expand=True)
        return tree

    def _selected_summary(self, parent):
        box = tk.Frame(parent, bg=self.PANEL)
        box.pack(fill="x", pady=12)
        self._summary_kv(box, "Mode", self.selected_mode_var, 0)
        self._summary_kv(box, "Serial / PNP", self.selected_id_var, 1)
        self._summary_kv(box, "Model", self.selected_model_var, 2)
        self._summary_kv(box, "State", self.selected_state_var, 3)
        ttk.Separator(parent).pack(fill="x", pady=8)
        ttk.Label(parent, text="Recommended next action", background=self.PANEL, foreground=self.MUTED).pack(anchor="w")
        self.recommendation_label = tk.Label(parent, text="Scan a device to get context-aware recommendations.", bg=self.PANEL, fg=self.TEXT, justify="left", wraplength=450, font=("Segoe UI", 10))
        self.recommendation_label.pack(fill="x", anchor="w", pady=(6, 0))

    def _summary_kv(self, parent, label, var, row):
        tk.Label(parent, text=label, bg=self.PANEL, fg=self.MUTED, font=("Segoe UI", 9)).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=5)
        tk.Label(parent, textvariable=var, bg=self.PANEL, fg=self.TEXT, font=("Segoe UI", 9, "bold"), wraplength=340, justify="left").grid(row=row, column=1, sticky="w", pady=5)
        parent.columnconfigure(1, weight=1)

    def _form_row(self, parent, label: str, var: tk.StringVar, row: int):
        ttk.Label(parent, text=label, background=self.PANEL, foreground=self.MUTED).pack(anchor="w", pady=(5, 2))
        ttk.Entry(parent, textvariable=var).pack(fill="x")

    def _text(self, parent, height=16):
        t = tk.Text(parent, bg="#0a1220", fg=self.TEXT, insertbackground=self.TEXT, relief="flat", borderwidth=0, height=height, font=("Consolas", 9), wrap="word", undo=True)
        t.pack(fill="both", expand=True)
        # FITUR CANGGIH: Log bisa copy paste
        def make_menu(event_widget):
            menu = tk.Menu(event_widget, tearoff=0, bg=self.PANEL_2, fg=self.TEXT, activebackground=self.ACCENT)
            try:
                sel = event_widget.tag_ranges("sel")
                has_sel = bool(sel)
            except:
                has_sel = False
            if has_sel:
                menu.add_command(label="Copy (Ctrl+C)", command=lambda: event_widget.event_generate("<<Copy>>"))
            menu.add_command(label="Select All (Ctrl+A)", command=lambda: event_widget.tag_add("sel", "1.0", "end"))
            menu.add_separator()
            menu.add_command(label="Clear Log", command=lambda: event_widget.delete("1.0", "end"))
            menu.add_command(label="Save Log to File", command=lambda: self._save_text_to_file(event_widget))
            return menu
        
        def show_menu(e):
            m = make_menu(e.widget)
            m.tk_popup(e.x_root, e.y_root)
        
        t.bind("<Button-3>", show_menu)  # klik kanan
        t.bind("<Control-a>", lambda e: e.widget.tag_add("sel", "1.0", "end"))
        t.bind("<Control-A>", lambda e: e.widget.tag_add("sel", "1.0", "end"))
        return t

    def _save_text_to_file(self, widget):
        txt = widget.get("1.0", "end-1c")
        if not txt.strip():
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")], initialfile=f"ANtech_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            Path(path).write_text(txt, encoding="utf-8")
            self.log("LOG", f"Saved log to {path}")

    # --- navigation/state ---
    def show_page(self, name: str):
        self.current_tab = name
        for p in self.pages.values():
            p.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        for n, b in self.nav_buttons.items():
            b.configure(style="Primary.TButton" if n == name else "Side.TButton")
        if name == "Logs & Reports":
            self.refresh_logs()
        elif name == "Service Center":
            self._load_jobs()
        elif name == "Firmware Lab":
            self._refresh_low_modes()

    def log(self, category: str, msg: str):
        self.db.add_log(category, msg)
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {category}: {msg}"
        for widget in (getattr(self, "diag_console", None), getattr(self, "logs_text", None)):
            if widget is not None and widget.winfo_exists():
                widget.insert("end", line + "\n")
                widget.see("end")

    def run_async(self, func, label="Processing…"):
        self.status_var.set(label)
        def worker():
            try:
                func()
            except Exception as exc:
                self.after(0, lambda e=exc: self.log("ERROR", str(e)))
            finally:
                self.after(0, lambda: self.status_var.set("System ready"))
        threading.Thread(target=worker, daemon=True).start()

    # --- Device selection ---
    def _populate_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)
        for idx, d in enumerate(self.devices):
            tree.insert("", "end", iid=str(idx), values=(d.mode, d.serial, d.model, d.product, d.state))

    def _sync_tree_selection(self, tree):
        sel = tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if idx >= len(self.devices):
            return
        self.selected_index = idx
        d = self.devices[idx]
        self.selected_mode_var.set(d.mode)
        self.selected_id_var.set(d.serial or "—")
        self.selected_model_var.set(d.model or d.product or d.detail or "—")
        self.selected_state_var.set(d.state or "connected")
        rec = {
            "ADB": "Run Auto Diagnosis → cek battery, verified boot, security patch, slot, dan logcat.",
            "FASTBOOT": "Read getvar all → verify product/slot/bootloader state sebelum flashing.",
            "EDL": "Confirm Qualcomm driver/device identity. Low-level flashing requires matching authorized programmer.",
            "PRELOADER": "Confirm MediaTek driver and exact model/chipset before using a vendor-specific DA flow.",
            "BROM": "Confirm exact MediaTek model and official DA/auth path before any write operation.",
        }.get(d.mode, "Pilih perangkat untuk melanjutkan.")
        if hasattr(self, "recommendation_label"):
            self.recommendation_label.configure(text=rec)
        self.db.add_device(d)
        self.log("DEVICE", f"Selected {d.mode} | {d.serial or d.detail}")

    def selected(self, required_mode: str | None = None) -> DeviceInfo | None:
        # FIX: auto pilih device pertama kalau belum ada yang dipilih (konek langsung seperti aplikasi awal)
        if self.selected_index is None or self.selected_index >= len(self.devices):
            if self.devices:
                self.selected_index = 0
                try:
                    self.dashboard_tree.selection_set("0")
                    self._sync_tree_selection(self.dashboard_tree)
                except:
                    pass
            else:
                messagebox.showwarning(APP_NAME, "Pilih perangkat terlebih dahulu. Colok HP dan tunggu 2 detik sampai auto-detect.")
                return None
        d = self.devices[self.selected_index]
        if required_mode and d.mode != required_mode:
            # cari otomatis device dengan mode yang diminta kalau ada
            for idx, dev in enumerate(self.devices):
                if dev.mode == required_mode:
                    self.selected_index = idx
                    return dev
            messagebox.showwarning(APP_NAME, f"Fitur ini memerlukan mode {required_mode}. Mode saat ini: {d.mode}")
            return None
        return d

    def _find_by_tree(self, tree):
        sel = tree.selection()
        if sel:
            self.selected_index = int(sel[0])

    # --- Scanning ---
    def scan_devices(self):
        def work():
            devs = DeviceDetector.scan_all()
            # Simpan serial lama untuk deteksi perubahan
            old_serials = {d.serial for d in self.devices}
            new_serials = {d.serial for d in devs}
            self.devices = devs
            def update():
                # Jangan reset selected_index kalau device masih sama (biar konek langsung tetap)
                should_autoselect = self.selected_index is None or old_serials != new_serials
                self._populate_tree(self.dashboard_tree)
                self._refresh_low_modes()
                self.device_count_var.set(str(len(devs)))
                self.adb_count_var.set(str(sum(d.mode == "ADB" for d in devs)))
                self.boot_count_var.set(str(sum(d.mode in {"FASTBOOT", "EDL", "PRELOADER", "BROM"} for d in devs)))
                self.alert_var.set(str(sum(1 for d in devs if d.mode in {"EDL", "PRELOADER", "BROM"})))
                self.top_device_badge.configure(text=f"{len(devs)} DEVICE")
                if old_serials != new_serials:
                    self.log("SCAN", f"Detected {len(devs)} interface(s)")
                if devs and should_autoselect:
                    self.dashboard_tree.selection_set("0")
                    self._sync_tree_selection(self.dashboard_tree)
                    self.status_var.set(f"Auto-detect: {devs[0].mode} | {devs[0].serial}")
            self.after(0, update)
        self.run_async(work, "Scanning ADB / Fastboot / EDL / Preloader / BROM…")

    def _auto_scan_tick(self):
        # Auto scan tiap 2.5 detik seperti aplikasi awal, biar konek langsung
        if self.auto_scan.get():
            # hanya scan jika system ready atau ada perubahan USB (jangan scan pas flashing)
            if self.status_var.get() in ("System ready",) or "Auto-detect" in self.status_var.get() or "Detected" in self.status_var.get() or self.status_var.get().startswith("Scanning"):
                # silent scan tanpa spam log kalau device sama
                def silent_work():
                    devs = DeviceDetector.scan_all()
                    if {d.serial for d in devs} != {d.serial for d in self.devices}:
                        self.after(0, self.scan_devices)
                threading.Thread(target=silent_work, daemon=True).start()
        self.after(2500, self._auto_scan_tick)

    def _refresh_low_modes(self):
        if not hasattr(self, "low_mode_list"):
            return
        self.low_mode_list.delete(0, "end")
        lows = [d for d in self.devices if d.mode in {"EDL", "PRELOADER", "BROM"}]
        if not lows:
            self.low_mode_list.insert("end", "No low-level interface detected.")
            return
        for d in lows:
            label = f"[{d.mode}] {d.detail or d.serial}"
            self.low_mode_list.insert("end", label)

    # --- ADB ---
    def adb_cmd(self, d: DeviceInfo, extra: list[str], timeout=20):
        if d.mode != "ADB" or not d.serial:
            return 2, "Invalid ADB device selection."
        return run_process([str(ADB_EXE), "-s", d.serial] + extra, timeout=timeout)

    def _adb_shell(self, d: DeviceInfo, *parts: str, timeout=20):
        return self.adb_cmd(d, shell_text(*parts), timeout=timeout)

    def adb_info(self):
        d = self.selected("ADB")
        if not d:
            return
        def work():
            rows = []
            for label, prop in DIAG_PROPS:
                _, val = self.adb_cmd(d, ["shell", "getprop", prop], timeout=8)
                rows.append((label, prop, val.strip()))
            _, batt = self.adb_cmd(d, ["shell", "dumpsys", "battery"], timeout=8)
            text = "ANDROID PROPERTIES\n" + "\n".join(f"{a}: {c}" for a, _, c in rows)
            text += "\n\nBATTERY\n" + batt
            self.after(0, lambda: self._show_diag(text, rows))
        self.run_async(work, "Reading Android properties…")

    def _show_diag(self, text, rows):
        self.diag_console.insert("end", "\n" + text + "\n\n")
        self.diag_console.see("end")
        for item in self.health_tree.get_children():
            self.health_tree.delete(item)
        for label, prop, val in rows:
            status = "OK"
            if label == "Verified Boot" and val and val.lower() not in {"green", ""}:
                status = "CHECK"
            if label == "Bootloader State" and val == "0":
                status = "LOCKED"
            self.health_tree.insert("", "end", values=(label, val or "—", status))
        self.log("ADB INFO", f"Properties loaded for {self.selected_id_var.get()}")

    def adb_logcat(self):
        d = self.selected("ADB")
        if not d:
            return
        def work():
            _, out = self.adb_cmd(d, ["logcat", "-d", "-t", "500"], timeout=25)
            out = out[-30000:] if out else "No logcat output."
            self.after(0, lambda: self.diag_console.insert("end", "\nLOGCAT SNAPSHOT\n" + out + "\n"))
            self.after(0, lambda: self.log("LOGCAT", f"Snapshot {len(out)} characters"))
        self.run_async(work, "Capturing logcat snapshot…")

    def auto_diagnose(self):
        d = self.selected("ADB")
        if not d:
            return

        def work():
            props = {}
            for key, prop in DIAG_PROPS:
                _, val = self.adb_cmd(d, ["shell", "getprop", prop], timeout=8)
                props[key] = val.strip()

            _, batt = self._adb_shell(d, "dumpsys", "battery", timeout=8)
            _, mem = self._adb_shell(d, "cat", "/proc/meminfo", timeout=8)
            _, df = self._adb_shell(d, "df", "-k", timeout=8)
            _, uptime = self._adb_shell(d, "cat", "/proc/uptime", timeout=8)
            _, thermal = self._adb_shell(d, "dumpsys", "thermalservice", timeout=10)
            _, logcat = self.adb_cmd(d, ["logcat", "-d", "-t", "700"], timeout=30)

            level_m = re.search(r"level:\s*(\d+)", batt, re.I)
            temp_m = re.search(r"temperature:\s*(\d+)", batt, re.I)
            voltage_m = re.search(r"voltage:\s*(\d+)", batt, re.I)
            health_m = re.search(r"health:\s*(\d+)", batt, re.I)
            lvl = int(level_m.group(1)) if level_m else None
            temp = int(temp_m.group(1))/10 if temp_m else None
            voltage = int(voltage_m.group(1))/1000 if voltage_m else None
            health_map = {"1":"Unknown","2":"Good","3":"Overheat","4":"Dead","5":"Over voltage","6":"Failure","7":"Cold"}
            health = health_map.get(health_m.group(1), "Unknown") if health_m else "Unknown"

            findings = [
                ("ADB transport", "Connected", "OK"),
                ("Verified Boot", props.get("Verified Boot") or "unknown",
                 "OK" if props.get("Verified Boot","").lower() in {"green",""} else "CHECK"),
                ("Bootloader", "Locked" if props.get("Bootloader State") == "0" else "Unlocked/Unknown", "INFO"),
                ("Slot", props.get("Slot") or "unknown", "INFO"),
                ("Battery", f"{lvl}%" if lvl is not None else "unknown",
                 "LOW" if lvl is not None and lvl < 20 else "OK"),
                ("Battery Temp", f"{temp:.1f}°C" if temp is not None else "unknown",
                 "CHECK" if temp is not None and temp >= 45 else "OK"),
                ("Battery Health", health, "CHECK" if health not in {"Good","Unknown"} else "OK"),
                ("Battery Voltage", f"{voltage:.3f} V" if voltage is not None else "unknown", "INFO"),
            ]

            faults = classify_logcat(logcat)
            fault_counts = []
            for category, lines in faults.items():
                if lines:
                    # De-duplicate repeated lines while retaining evidence count.
                    unique = list(dict.fromkeys(lines))
                    status = "CHECK" if category in {"Kernel/Boot","System Crash","App Crash","Storage","Modem/Radio","Thermal"} else "INFO"
                    fault_counts.append((category, f"{len(lines)} hit(s)", status))
                    findings.append((category, f"{len(lines)} hit(s)", status))

            # Storage usage from df output; report only when a numeric percentage is found.
            for line in (df or "").splitlines():
                m = re.search(r"\s(\d+)%\s+\S+\s+\S+\s+\S+\s+\S+$", line.strip())
                if m:
                    used = int(m.group(1))
                    if used >= 95:
                        findings.append(("Storage Usage", f"{used}%", "CHECK"))
                    break

            summary = [f"SMART DIAGNOSIS — {d.serial}", f"Model: {d.model or d.product}", ""]
            for a, b, c in findings:
                summary.append(f"{a}: {b} [{c}]")

            summary.append("")
            if any(x[0] == "Storage" for x in findings):
                summary.append("Recommendation: inspect storage/UFS logs and back up customer data before write operations.")
            if any(x[0] == "Display" for x in findings):
                summary.append("Recommendation: verify display symptoms; log evidence alone does not prove LCD/OLED hardware failure.")
            if any(x[0] == "Modem/Radio" for x in findings):
                summary.append("Recommendation: check baseband/IMEI/SIM/network diagnostics before hardware replacement.")
            if any(x[0] in {"Kernel/Boot","System Crash"} for x in findings):
                summary.append("Recommendation: capture a larger logcat/bugreport and inspect crash timestamps before flashing.")
            if not fault_counts:
                summary.append("No high-confidence fatal crash pattern detected in the captured logcat window.")

            detail = (
                "\n\n=== SMART DIAGNOSTIC EVIDENCE ===\n"
                + "\n".join(summary)
                + "\n\n=== THERMAL SERVICE ===\n" + (thermal[-4000:] if thermal else "Unavailable")
                + "\n\n=== MEMORY ===\n" + (mem[:4000] if mem else "Unavailable")
                + "\n\n=== STORAGE (df -k) ===\n" + (df[:4000] if df else "Unavailable")
                + "\n\n=== UPTIME ===\n" + (uptime or "Unavailable")
                + "\n\n=== LOGCAT CLASSIFICATION ===\n"
            )
            for cat, lines in faults.items():
                if lines:
                    detail += f"\n[{cat}] {len(lines)} hit(s)\n" + "\n".join(list(dict.fromkeys(lines))[-8:]) + "\n"

            self.after(0, lambda: self._show_health_findings(findings, detail))
        self.run_async(work, "Running smart hardware/software diagnosis…")

    def _show_health_findings(self, findings, text):
        self.diag_console.insert("end", "\n" + text + "\n")
        self.diag_console.see("end")
        for item in self.health_tree.get_children():
            self.health_tree.delete(item)
        for metric, val, status in findings:
            self.health_tree.insert("", "end", values=(metric, val, status))
        self.alert_var.set(str(sum(1 for _, _, s in findings if s in {"CHECK", "LOW"})))
        self.log("DIAGNOSIS", text)

    def adb_reboot(self, target: str):
        d = self.selected("ADB")
        if not d:
            return
        label = target or "system"
        if not messagebox.askyesno(APP_NAME, f"Kirim reboot ke {label}?"):
            return
        def work():
            code, out = self.adb_cmd(d, ["reboot"] + ([target] if target else []), timeout=10)
            self.after(0, lambda: self.log("ADB", out or f"Reboot {label} code={code}"))
            self.after(0, lambda: self.after(1800, self.scan_devices))
        self.run_async(work, f"Rebooting to {label}…")

    def read_battery_live(self):
        d = self.selected("ADB")
        if not d:
            return
        def work():
            _, out = self.adb_cmd(d, ["shell", "dumpsys", "battery"], timeout=8)
            # parse
            level = re.search(r"level:\s*(\d+)", out)
            voltage = re.search(r"voltage:\s*(\d+)", out)  # mV
            temp = re.search(r"temperature:\s*(\d+)", out)  # tenth °C
            current = re.search(r"current now:\s*(-?\d+)", out)
            current_avg = re.search(r"current average:\s*(-?\d+)", out)
            charge_counter = re.search(r"Charge counter:\s*(\d+)", out)
            status = re.search(r"status:\s*(\d+)", out)
            health = re.search(r"health:\s*(\d+)", out)
            ac = re.search(r"AC powered:\s*(\w+)", out)
            usb = re.search(r"USB powered:\s*(\w+)", out)
            wireless = re.search(r"wireless powered:\s*(\w+)", out)
            
            status_map = {"1":"Unknown","2":"Charging","3":"Discharging","4":"Not charging","5":"Full"}
            health_map = {"1":"Unknown","2":"Good","3":"Overheat","4":"Dead","5":"Over voltage","6":"Failure","7":"Cold"}
            
            lvl = int(level.group(1)) if level else 0
            volt = int(voltage.group(1))/1000 if voltage else 0  # to V
            t = int(temp.group(1))/10 if temp else 0
            cur_raw = int(current.group(1)) if current else 0
            cur_avg_raw = int(current_avg.group(1)) if current_avg else 0
            # Android/OEMs differ on sign convention; status is authoritative for UI wording.
            cur = cur_raw / 1000
            cur_avg = cur_avg_raw / 1000
            st = status_map.get(status.group(1), "Unknown") if status else "Unknown"
            hl = health_map.get(health.group(1), "Unknown") if health else "Unknown"
            charge = int(charge_counter.group(1))/1000 if charge_counter else 0
            
            # charging source
            source = []
            if ac and ac.group(1).lower() == "true":
                source.append("AC")
            if usb and usb.group(1).lower() == "true":
                source.append("USB")
            if wireless and wireless.group(1).lower() == "true":
                source.append("Wireless")
            src_str = "+".join(source) if source else "Battery"
            
            summary = f"""BATTERY LIVE MONITOR - {d.serial}
Model: {d.model or d.product}
Level: {lvl}% | Status: {st} | Health: {hl}
Voltage: {volt:.3f} V ({int(voltage.group(1)) if voltage else 0} mV)
Current NOW: {cur:.3f} A ({int(current.group(1)) if current else 0} mA) {'Charging' if cur>0 else 'Discharging' if cur<0 else ''}
Current AVG: {cur_avg:.3f} A
Charge Counter: {charge:.0f} mAh
Temperature: {t:.1f} °C
Power Source: {src_str}

RAW DUMPSYS:
{out[:1200]}
"""
            self.after(0, lambda: self.log("BATTERY", f"{d.serial} {lvl}% {volt:.2f}V {cur:.2f}A {t:.1f}C {st}"))
            # Update UI labels if exist
            if hasattr(self, "batt_level_var"):
                self.after(0, lambda: self.batt_level_var.set(f"{lvl}%"))
                self.after(0, lambda: self.batt_volt_var.set(f"{volt:.3f} V"))
                self.after(0, lambda: self.batt_current_var.set(f"{cur:+.3f} A"))
                self.after(0, lambda: self.batt_temp_var.set(f"{t:.1f} °C"))
                self.after(0, lambda: self.batt_status_var.set(st))
                self.after(0, lambda: self.batt_health_var.set(hl))
                self.after(0, lambda: self.batt_source_var.set(src_str))
            self.after(0, lambda: self.diag_console.insert("end", "\n" + summary + "\n") if hasattr(self, "diag_console") else None)
            # Also show in separate window if called from dashboard
            if hasattr(self, "_show_info_window") and len(out) < 5000:
                pass
        self.run_async(work, "Reading battery…")

    def start_battery_monitor(self):
        d = self.selected("ADB")
        if not d:
            return
        self.battery_monitoring = True
        def loop():
            while getattr(self, "battery_monitoring", False):
                try:
                    _, out = self.adb_cmd(d, ["shell", "dumpsys", "battery"], timeout=8)
                    level = re.search(r"level:\s*(\d+)", out)
                    voltage = re.search(r"voltage:\s*(\d+)", out)
                    temp = re.search(r"temperature:\s*(\d+)", out)
                    current = re.search(r"current now:\s*(-?\d+)", out)
                    status = re.search(r"status:\s*(\d+)", out)
                    status_map = {"1":"Unknown","2":"Charging","3":"Discharging","4":"Not charging","5":"Full"}
                    if level and voltage and temp and current:
                        lvl = int(level.group(1))
                        volt = int(voltage.group(1))/1000
                        t = int(temp.group(1))/10
                        cur = int(current.group(1))/1000
                        st = status_map.get(status.group(1), "") if status else ""
                        self.after(0, lambda l=lvl, v=volt, c=cur, tt=t, s=st: self._update_batt_ui(l, v, c, tt, s))
                except:
                    pass
                time.sleep(2.5)
        threading.Thread(target=loop, daemon=True).start()
        self.log("BATTERY", f"Live monitor started for {d.serial}")

    def stop_battery_monitor(self):
        self.battery_monitoring = False
        self.log("BATTERY", "Live monitor stopped")

    def _update_batt_ui(self, level, volt, curr, temp, status):
        if hasattr(self, "batt_level_var"):
            self.batt_level_var.set(f"{level}%")
            self.batt_volt_var.set(f"{volt:.3f} V")
            self.batt_current_var.set(f"{curr:+.3f} A")
            self.batt_temp_var.set(f"{temp:.1f} °C")
            self.batt_status_var.set(status)

    def detect_lock_type(self):
        d = self.selected("ADB")
        if not d:
            return
        def work():
            # Deteksi Lock Type dari dumpsys (informasi saja, bukan bypass)
            _, trust = self.adb_cmd(d, ["shell", "dumpsys", "trust"], timeout=10)
            _, device_policy = self.adb_cmd(d, ["shell", "dumpsys", "device_policy"], timeout=10)
            _, lock_settings = self.adb_cmd(d, ["shell", "dumpsys", "lock_settings"], timeout=10)
            _, keyguard = self.adb_cmd(d, ["shell", "dumpsys", "window", "policy"], timeout=10)
            _, settings = self.adb_cmd(d, ["shell", "settings", "get", "secure", "lockscreen.password_type"], timeout=8)
            
            lock_type = "Tidak terdeteksi"
            password_type = settings.strip() if settings else ""
            # mapping password type Android
            type_map = {
                "0": "None / Swipe",
                "1": "Pattern",
                "2": "PIN",
                "3": "Password (Alphanumeric)",
                "4": "Password (Complex)",
                "65536": "Pattern",
                "131072": "PIN",
                "196608": "Password"
            }
            if password_type in type_map:
                lock_type = type_map[password_type]
            else:
                # fallback dari dumpsys
                low = (trust + device_policy + lock_settings).lower()
                if "pattern" in low:
                    lock_type = "Pattern"
                elif "pin" in low or "password quality 131072" in low or "numeric" in low:
                    lock_type = "PIN"
                elif "password" in low:
                    lock_type = "Password"
                elif "swipe" in low or "none" in low:
                    lock_type = "Swipe / None"
                # cek keyguard
                if "mshowinglockscreen=true" in keyguard.lower() or "msecure=true" in keyguard.lower():
                    if lock_type == "Tidak terdeteksi":
                        lock_type = "Locked (Type Unknown - need deeper dump)"
            
            summary = f"""LOCK TYPE DETECTION
Device: {d.serial}
Model: {d.model or d.product}
Detected Type: {lock_type}
Raw password_type value: {password_type or 'n/a'}

DUMPSYS SNIPPET:
{lock_settings[:800]}

DEVICE_POLICY SNIPPET:
{device_policy[:800]}
"""
            self.after(0, lambda: self.log("LOCK TYPE", f"{d.serial} -> {lock_type} (type={password_type})"))
            self.after(0, lambda: self.diag_console.insert("end", "\n" + summary + "\n") if hasattr(self, "diag_console") else None)
            self.after(0, lambda: self._show_info_window("Lock Type Detection", summary))
        self.run_async(work, "Detecting lock type…")

    def factory_reset_wipe(self):
        d = self.selected("ADB")
        if not d:
            return
        # Konfirmasi double + warning seperti diminta
        if not messagebox.askyesno("AN tech - Factory Reset", 
            f"FACTORY RESET - WIPE DATA\n\n"
            f"Device: {d.serial}\n"
            f"Model: {d.model or d.product or 'unknown'}\n\n"
            f"⚠️  SEMUA DATA AKAN HILANG!\n"
            f"• Foto, video, kontak, aplikasi akan terhapus\n"
            f"• Akun Google FRP mungkin masih aktif setelah reset\n"
            f"• Pastikan customer sudah setuju\n\n"
            f"Lanjutkan ke konfirmasi kedua?", icon="warning"):
            return
        if not messagebox.askyesno("AN tech - KONFIRMASI AKHIR", 
            f"KONFIRMASI AKHIR\n\n"
            f"Anda YAKIN ingin wipe data di:\n"
            f"{d.serial} ?\n\n"
            f"Ketik YA secara mental dan klik Yes.\n"
            f"Tindakan ini TIDAK BISA DIBATALKAN.", icon="warning"):
            return
        
        def work():
            # Step 1: Reboot to recovery
            self.after(0, lambda: self.log("WIPE", f"Rebooting {d.serial} to recovery for wipe..."))
            code, out = self.adb_cmd(d, ["reboot", "recovery"], timeout=10)
            self.after(0, lambda: self.log("WIPE", f"Reboot command code={code}. Tunggu device masuk recovery..."))
            # Tunggu 15 detik biar masuk recovery
            import time
            time.sleep(12)
            # Coba wipe via recovery command (official, bukan bypass)
            # Ini akan memicu wipe_data di recovery, resmi
            # Untuk device yang sudah di recovery, gunakan adb shell recovery --wipe_data atau wipe via fastboot nanti
            # Kita coba metode ADB sideload recovery command
            self.after(0, lambda: self.log("WIPE", "Jika device sudah di Recovery, pilih 'Wipe data/factory reset' secara manual.\nAtau lanjutkan dengan Fastboot: fastboot -w"))
            self.after(0, lambda: messagebox.showinfo("AN tech - Factory Reset", 
                f"Device {d.serial} sedang reboot ke Recovery.\n\n"
                f"LANGKAH SELANJUTNYA:\n"
                f"1. Di layar Recovery, pilih 'Wipe data/factory reset'\n"
                f"2. Konfirmasi 'Factory data reset'\n"
                f"3. Setelah selesai, pilih 'Reboot system now'\n\n"
                f"Alternatif Fastboot:\n"
                f"Jika device masuk Fastboot, gunakan 'fastboot -w' di Firmware Lab."))
        self.run_async(work, "Factory Reset - Rebooting to recovery…")

    def factory_reset_fastboot_wipe(self):
        d = self.selected("FASTBOOT")
        if not d:
            # coba cari fastboot device otomatis kalau lagi di fastboot
            for dev in self.devices:
                if dev.mode == "FASTBOOT":
                    d = dev
                    break
        if not d or d.mode != "FASTBOOT":
            messagebox.showwarning("AN tech", "Masuk ke Fastboot dulu untuk wipe via fastboot.\nDevice harus mode FASTBOOT.")
            return
        if not messagebox.askyesno("AN tech - Fastboot Wipe", 
            f"FASTBOOT WIPE (fastboot -w)\n\n"
            f"Device: {d.serial}\n\n"
            f"⚠️  SEMUA DATA AKAN HILANG!\n"
            f"Perintah: fastboot -w akan erase userdata + cache\n\n"
            f"Lanjutkan?", icon="warning"):
            return
        if not messagebox.askyesno("AN tech - KONFIRMASI", "Yakin wipe? TIDAK BISA BATAL.", icon="warning"):
            return
        def work():
            code, out = self.fastboot_cmd(d, ["-w"], timeout=120)
            self.after(0, lambda: self.log("FASTBOOT WIPE", f"code={code}\n{out}"))
            if code == 0:
                self.after(0, lambda: messagebox.showinfo("AN tech", f"Wipe {d.serial} berhasil. Reboot system."))
            else:
                self.after(0, lambda: messagebox.showerror("AN tech", f"Wipe gagal.\n{out[-2000:]}"))
        self.run_async(work, "Fastboot wipe…")

    def adb_packages(self):
        d = self.selected("ADB")
        if not d:
            return
        def work():
            _, out = self.adb_cmd(d, ["shell", "pm", "list", "packages", "-f"], timeout=20)
            self.after(0, lambda: self._show_info_window("Installed Packages", out or "No package list."))
            self.after(0, lambda: self.log("ADB", f"Package inventory captured: {len(out.splitlines())} packages"))
        self.run_async(work, "Reading Android package inventory…")

    # --- Fastboot ---
    def fastboot_cmd(self, d: DeviceInfo, extra: list[str], timeout=30):
        return run_process([str(FASTBOOT_EXE), "-s", d.serial] + extra, timeout=timeout)

    def fastboot_info(self):
        d = self.selected("FASTBOOT")
        if not d:
            return
        def work():
            _, out = self.fastboot_cmd(d, ["getvar", "all"], timeout=25)
            self.after(0, lambda: self._show_info_window("Fastboot getvar all", out))
            self.after(0, lambda: self.log("FASTBOOT INFO", out[-12000:]))
        self.run_async(work, "Reading fastboot variables…")

    def fastboot_reboot(self):
        d = self.selected("FASTBOOT")
        if not d:
            return
        def work():
            code, out = self.fastboot_cmd(d, ["reboot"], timeout=10)
            self.after(0, lambda: self.log("FASTBOOT", out or f"Reboot code={code}"))
            self.after(0, lambda: self.after(1800, self.scan_devices))
        self.run_async(work, "Rebooting fastboot device…")

    # --- Firmware ---
    def choose_image(self):
        path = filedialog.askopenfilename(title="Pilih firmware image", filetypes=[("Android image", "*.img *.bin"), ("All files", "*.*")])
        if path:
            self.image_var.set(path)
            self.hash_ok_var.set(False)
            self.image_hash_var.set("SHA-256: calculating…")
            self.calculate_hash()

    def calculate_hash(self):
        path = Path(self.image_var.get().strip())
        if not path.is_file():
            messagebox.showwarning(APP_NAME, "Pilih file firmware terlebih dahulu.")
            return
        def work():
            self.after(0, self.hash_progress.start, 10)
            digest = sha256_file(path)
            self.after(0, self.hash_progress.stop)
            self.after(0, lambda: self.image_hash_var.set(f"SHA-256: {digest}"))
            self.after(0, lambda: self.hash_ok_var.set(True))
            self.after(0, lambda: self.log("HASH", f"{path.name} → SHA-256 {digest}"))
        self.run_async(work, "Calculating SHA-256…")

    def fastboot_flash(self):
        d = self.selected("FASTBOOT")
        if not d:
            return
        part = self.partition_var.get().strip()
        image = Path(self.image_var.get().strip())
        if part not in SAFE_FASTBOOT_PARTITIONS:
            messagebox.showerror(APP_NAME, "Partition tidak diizinkan oleh built-in safe flasher.")
            return
        if not image.is_file():
            messagebox.showerror(APP_NAME, "Pilih image yang valid.")
            return
        if not self.hash_ok_var.get():
            if not messagebox.askyesno(APP_NAME, "SHA-256 belum dihitung. Tetap lanjut setelah verifikasi manual?"):
                return
        warning = (f"FLASH OPERATION\n\nDevice: {d.serial}\nProduct: {d.product or 'unknown'}\nPartition: {part}\nImage: {image.name}\n\n"
                   "Pastikan firmware cocok dengan model/region dan bootloader state. Tindakan flash dapat mengubah atau menghapus data.")
        if not messagebox.askyesno(APP_NAME, warning + "\n\nLanjutkan?", icon="warning"):
            return
        def work():
            self.after(0, lambda: self.log("FLASH", f"START {part} <= {image.name}"))
            code, out = self.fastboot_cmd(d, ["flash", part, str(image)], timeout=600)
            self.after(0, lambda: self.log("FLASH", f"END code={code}\n{out}"))
            if code == 0:
                self.after(0, lambda: messagebox.showinfo(APP_NAME, f"Flash {part} berhasil."))
            else:
                self.after(0, lambda: messagebox.showerror(APP_NAME, f"Flash {part} gagal.\n\n{out[-2500:]}"))
        self.run_async(work, f"Flashing {part}…")

    def adb_sideload(self):
        d = self.selected("ADB")
        if not d:
            return
        path = filedialog.askopenfilename(title="Pilih update ZIP", filetypes=[("ZIP", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        if not messagebox.askyesno(APP_NAME, "ADB sideload hanya bekerja ketika recovery siap menerima sideload. Lanjutkan?"):
            return
        def work():
            code, out = self.adb_cmd(d, ["sideload", path], timeout=1200)
            self.after(0, lambda: self.log("SIDELOAD", f"{Path(path).name} code={code}\n{out}"))
        self.run_async(work, "Running ADB sideload…")

    # --- Jobs, reports, logs ---
    def create_job(self):
        if not self.customer_var.get().strip():
            messagebox.showwarning(APP_NAME, "Nama customer wajib diisi.")
            return
        job_id = self.db.add_job(self.customer_var.get().strip(), self.phone_var.get().strip(), self.tech_var.get().strip(), self.complaint_var.get().strip())
        self.job_id_var.set(f"JOB {job_id:05d}")
        self.log("JOB", f"Created service job #{job_id}")
        self._load_jobs()
        messagebox.showinfo(APP_NAME, f"Job #{job_id} tersimpan.")

    def _load_jobs(self):
        if not hasattr(self, "jobs_tree"):
            return
        for x in self.jobs_tree.get_children():
            self.jobs_tree.delete(x)
        for row in self.db.recent_jobs():
            self.jobs_tree.insert("", "end", values=row)


    # ================== 7.0.0 PRO - JUDOL / MALWARE CLEANER ==================
    def scan_judol_cleaner(self, deep=False):
        """Targeted package-risk scan. Heuristics are evidence, not proof of malware."""
        d = self.selected("ADB")
        if not d:
            return

        def work():
            self.after(0, lambda: self.cleaner_text.delete("1.0", "end"))
            self.after(0, lambda: self.cleaner_text.insert("end", "🔍 Scanning aplikasi terinstall...\n\n"))

            flag = [] if deep else ["-3"]
            code, out = self.adb_cmd(d, ["shell", "pm", "list", "packages"] + flag, timeout=25)
            if code != 0:
                self.after(0, lambda: self.cleaner_text.insert("end", f"ADB error: {out}\n"))
                return
            pkgs = sorted({line.replace("package:", "").strip() for line in out.splitlines() if line.startswith("package:")})

            _, out_admin = self._adb_shell(d, "dumpsys", "device_policy", timeout=15)
            _, out_overlay = self._adb_shell(d, "cmd", "appops", "query-op", "SYSTEM_ALERT_WINDOW", "allow", timeout=15)

            found = []
            for pkg in pkgs:
                lower = pkg.lower()
                score = 0
                reasons = []
                hits = [kw for kw in JUDOL_KEYWORDS if kw in lower]
                if hits:
                    score += min(6, len(hits) * 2)
                    reasons.append("Package keyword: " + ", ".join(hits[:4]))
                if any(p in lower for p in SUSPICIOUS_PACKAGES_PATTERNS):
                    score += 3
                    reasons.append("Matches suspicious package pattern")
                if pkg in out_admin:
                    score += 2
                    reasons.append("Device Admin reference detected")
                if pkg in out_overlay:
                    score += 1
                    reasons.append("SYSTEM_ALERT_WINDOW allowed")
                # Do not flag solely because an app has an overlay permission.
                if score >= 3:
                    found.append((pkg, score, reasons))

            found.sort(key=lambda x: (-x[1], x[0]))
            self.after(0, lambda: [self.cleaner_tree.delete(i) for i in self.cleaner_tree.get_children()])

            if not found:
                msg = "✅ Tidak ditemukan package yang memenuhi threshold heuristik.\nCatatan: ini bukan antivirus proof-of-malware."
                self.after(0, lambda: self.cleaner_text.insert("end", msg + "\n"))
                self.after(0, lambda: self.status_var.set("System ready - Cleaner scan selesai"))
            else:
                def render():
                    self.cleaner_text.insert("end", f"⚠️ {len(found)} package memenuhi threshold heuristik:\n\n")
                    for pkg, score, reasons in found:
                        _, detail = self.adb_cmd(d, ["shell", "dumpsys", "package", pkg], timeout=10)
                        vm = re.search(r"versionName=([^\s]+)", detail or "")
                        vname = vm.group(1) if vm else ""
                        self.cleaner_tree.insert("", "end", values=(pkg, score, "; ".join(reasons), vname))
                        self.cleaner_text.insert("end", f"📦 {pkg} [{vname}] Risk {score}\n   - " + "\n   - ".join(reasons) + "\n\n")
                    self.cleaner_text.insert("end", "⚠️ Risk score adalah heuristik. Verifikasi package/signature sebelum menghapus system app.\n")
                    self.status_var.set(f"Cleaner: {len(found)} package perlu verifikasi")
                self.after(0, render)
            self.log("CLEANER", f"Scan {'deep' if deep else 'quick'} selesai: {len(found)} candidate(s) on {d.serial}")

        self.run_async(work, "Scanning package risk…")

    def remove_selected_cleaner(self):
        d = self.selected("ADB")
        if not d:
            return
        sel = self.cleaner_tree.selection()
        if not sel:
            messagebox.showwarning(APP_NAME, "Pilih aplikasi yang mau dihapus dulu di tabel.")
            return
        pkgs = [str(self.cleaner_tree.item(i)["values"][0]) for i in sel]
        if not messagebox.askyesno(APP_NAME, f"Hapus/uninstall untuk user 0?\n\n" + "\n".join(pkgs)):
            return

        def work():
            results = []
            for pkg in pkgs:
                self.log("CLEANER", f"Removing {pkg} from {d.serial}...")
                # First try user uninstall; never issue an unscoped uninstall against a random device.
                code, out = self.adb_cmd(d, ["shell", "pm", "uninstall", "--user", "0", pkg], timeout=30)
                if code != 0:
                    # For system apps, disable only after explicit user confirmation already given.
                    code2, out2 = self.adb_cmd(d, ["shell", "pm", "disable-user", "--user", "0", pkg], timeout=20)
                    results.append(f"{pkg}: uninstall failed; disable-user={code2}")
                else:
                    results.append(f"{pkg}: {out or 'uninstalled for user 0'}")
            self.after(0, lambda: self.cleaner_text.insert("end", "\n=== CLEANUP RESULT ===\n" + "\n".join(results) + "\n"))
            self.log("CLEANER", f"Cleanup finished: {len(pkgs)} package(s)")
            self.after(0, lambda: messagebox.showinfo(APP_NAME, "Pembersihan selesai. Periksa hasil dan lakukan reboot bila diperlukan."))

        self.run_async(work, "Removing selected packages…")

    def disable_ads_system(self):
        """Apply a conservative setting and report what was actually changed."""
        d = self.selected("ADB")
        if not d:
            return
        code, out = self._adb_shell(d, "settings", "put", "secure", "install_non_market_apps", "0", timeout=10)
        self.log("CLEANER", f"Non-market install restriction command code={code}")
        messagebox.showinfo(
            APP_NAME,
            "Perangkat ditargetkan secara spesifik.\n\n"
            "• Instalasi sumber tidak dikenal dibatasi bila ROM mendukung setting ini.\n"
            "• Izin overlay aplikasi mencurigakan harus diverifikasi per-package.\n"
            "• Tidak ada perubahan AppOps Play Store yang dipaksakan."
        )

    # ================== END CLEANER ==================


    def refresh_logs(self):
        if not hasattr(self, "logs_text"):
            return
        self.logs_text.delete("1.0", "end")
        for created, category, message in reversed(self.db.recent_logs()):
            self.logs_text.insert("end", f"[{created}] {category}\n{message}\n\n")

    def check_auto_update(self, silent=False):
        """Cek update dari server tanpa ubah desain - support EXE + PY"""
        def work():
            try:
                import urllib.request, sys
                self.after(0, lambda: self.status_var.set("Checking update..."))
                req = urllib.request.Request(UPDATE_SERVER_URL, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                remote_ver = data.get("version", "")
                is_frozen = getattr(sys, 'frozen', False)
                if is_frozen:
                    remote_url = data.get("exe_url", data.get("download_url", UPDATE_DOWNLOAD_URL))
                else:
                    remote_url = data.get("download_url", UPDATE_DOWNLOAD_URL)
                changelog = data.get("changelog", "Update tersedia")
                if not remote_ver:
                    raise ValueError("Version info kosong")
                # compare version simple
                if version_is_newer(remote_ver, APP_VERSION):
                    def ask():
                        if messagebox.askyesno(f"{APP_NAME} Update Tersedia", f"Versi baru: {remote_ver}\nVersi sekarang: {APP_VERSION}\n\nChangelog:\n{changelog}\n\nDownload dan update sekarang? (Aplikasi akan restart)"):
                            self._pending_update_sha256 = str(data.get("sha256", "") or "")
                            self.download_and_apply_update(remote_url, remote_ver)
                        else:
                            self.status_var.set("Update tersedia - skip")
                    self.after(0, ask)
                else:
                    self.after(0, lambda: self.log("UPDATE", f"Sudah versi terbaru {APP_VERSION}"))
                    if not silent:
                        self.after(0, lambda: messagebox.showinfo(APP_NAME, f"Sudah versi terbaru\n{APP_VERSION}"))
                    self.after(0, lambda: self.status_var.set("System ready"))
            except Exception as e:
                self.after(0, lambda: self.log("UPDATE", f"Check update gagal: {e}"))
                self.after(0, lambda: self.status_var.set("System ready"))
                if not silent:
                    self.after(0, lambda: messagebox.showwarning(APP_NAME, f"Gagal cek update:\n{e}\n\nPastikan server online."))
        threading.Thread(target=work, daemon=True).start()

    def download_and_apply_update(self, url, new_ver):
        def work():
            try:
                import urllib.request, shutil, sys
                self.after(0, lambda: self.status_var.set(f"Downloading {new_ver}..."))
                is_frozen = getattr(sys, 'frozen', False)
                if is_frozen or url.lower().endswith(".exe"):
                    # --- MODE EXE ---
                    current_exe = Path(sys.executable).resolve()
                    tmp_exe = current_exe.parent / f"AN_Tech_new_{new_ver.replace(' ', '_')}.exe"
                    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
                    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp_exe, "wb") as out:
                        shutil.copyfileobj(resp, out)
                    expected_hash = getattr(self, "_pending_update_sha256", "")
                    if expected_hash and sha256_file(tmp_exe).lower() != expected_hash.lower():
                        tmp_exe.unlink(missing_ok=True)
                        raise ValueError("SHA-256 update tidak cocok dengan manifest.")
                    # buat updater.bat untuk replace exe yang sedang jalan
                    bat_path = current_exe.parent / "updater.bat"
                    bat_content = f"""@echo off
timeout /t 2 /nobreak >nul
move /Y "{tmp_exe}" "{current_exe}"
start "" "{current_exe}"
del "%~f0"
"""
                    bat_path.write_text(bat_content, encoding="utf-8")
                    self.after(0, lambda: self.log("UPDATE", f"EXE {new_ver} downloaded, running updater"))
                    self.after(0, lambda: messagebox.showinfo(APP_NAME, f"Update {new_ver} berhasil didownload!\nAplikasi akan restart otomatis."))
                    self.after(0, lambda: subprocess.Popen([str(bat_path)], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
                    self.after(1000, lambda: self.destroy())
                else:
                    # --- MODE PY ---
                    tmp_path = BASE_DIR / "app" / f"main_new_{new_ver.replace(' ', '_')}.py"
                    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
                    with urllib.request.urlopen(req, timeout=30) as resp, open(tmp_path, "wb") as out:
                        shutil.copyfileobj(resp, out)
                    expected_hash = getattr(self, "_pending_update_sha256", "")
                    if expected_hash and sha256_file(tmp_path).lower() != expected_hash.lower():
                        tmp_path.unlink(missing_ok=True)
                        raise ValueError("SHA-256 update tidak cocok dengan manifest.")
                    current_file = Path(__file__).resolve()
                    backup = current_file.with_suffix(f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py")
                    shutil.copy(current_file, backup)
                    shutil.copy(tmp_path, current_file)
                    tmp_path.unlink(missing_ok=True)
                    self.after(0, lambda: self.log("UPDATE", f"Update {new_ver} berhasil, backup {backup.name}"))
                    self.after(0, lambda: messagebox.showinfo(APP_NAME, f"Update {new_ver} berhasil!\nAplikasi akan restart.\nBackup: {backup.name}"))
                    self.after(0, lambda: os.execl(sys.executable, sys.executable, str(current_file)))
            except Exception as e:
                self.after(0, lambda: self.log("UPDATE", f"Download update gagal: {e}"))
                self.after(0, lambda: messagebox.showerror(APP_NAME, f"Gagal download update:\n{e}"))
                self.after(0, lambda: self.status_var.set("System ready"))
        threading.Thread(target=work, daemon=True).start()

    def export_report(self):
        selected = self.devices[self.selected_index] if self.selected_index is not None and self.selected_index < len(self.devices) else None
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORT_DIR / f"AN_tech_report_{timestamp}.txt"
        payload = {
            "application": f"{APP_NAME} {APP_VERSION}",
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "job": {
                "customer": self.customer_var.get(), "phone": self.phone_var.get(),
                "technician": self.tech_var.get(), "complaint": self.complaint_var.get()
            },
            "selected_device": asdict(selected) if selected else None,
            "devices_seen": [asdict(d) for d in self.devices],
            "recent_logs": [dict(created_at=a, category=b, message=c) for a, b, c in self.db.recent_logs(120)],
            "tooling": {
                "adb_path": str(ADB_EXE),
                "fastboot_path": str(FASTBOOT_EXE),
                "adb_exists": ADB_EXE.exists(),
                "fastboot_exists": FASTBOOT_EXE.exists(),
                "python": os.environ.get("PYTHON_VERSION", ""),
            },
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self.log("REPORT", f"Exported {path.name}")
        messagebox.showinfo(APP_NAME, f"Report tersimpan:\n{path}")

    # --- helpers ---
    def _show_info_window(self, title, text):
        win = tk.Toplevel(self)
        win.title(f"{APP_NAME} — {title}")
        win.geometry("980x620")
        win.configure(bg=self.BG)
        tk.Label(win, text=title, bg=self.BG, fg=self.TEXT, font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=16, pady=(14, 8))
        t = tk.Text(win, bg="#0a1220", fg=self.TEXT, insertbackground=self.TEXT, relief="flat", font=("Consolas", 9), wrap="word")
        t.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        t.insert("1.0", text)
        t.configure(state="disabled")


if __name__ == "__main__":
    ANTechApp().mainloop()
