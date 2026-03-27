import csv
import hashlib
import json
import os
import re
import sys
import threading
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

# STYLE-1 fix: Type aliases to reduce line length
PatternList = List[Tuple[str, re.Pattern[str], float]]
PatternDict = Dict[str, PatternList]

if os.name == "nt":
    import ctypes
    import winreg
    from ctypes import wintypes

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QThread, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


@dataclass
class ProcmonEvent:
    time_of_day: str
    process_name: str
    pid: Optional[int]
    operation: str
    path: str
    result: str
    detail: str
    parent_pid: Optional[int] = None
    process_path: str = ""
    command_line: str = ""

    def __post_init__(self):
        # CODE-1 fix: store parsed detail as a plain instance attribute (not a
        # dataclass field) so asdict() never serialises this internal cache.
        self._parsed_detail: Optional[Dict[str, str]] = None

    @property
    def detail_dict(self) -> Dict[str, str]:
        """Lazily parse detail string into key-value dict."""
        if self._parsed_detail is None:
            self._parsed_detail = parse_detail(self.detail)
        return self._parsed_detail


@dataclass
class ProcessInfo:
    pid: int
    proc_name: str = ""
    image_path: str = ""
    command_line: str = ""
    start_time: str = ""
    end_time: str = ""


@dataclass
class ResidueCandidate:
    type: str
    path: str
    mapped_path: str
    raw_score: int
    score: int
    reasons: List[str]
    first_seen: str
    last_seen: str
    processes: List[str]
    operations: List[str]
    exists_now: Optional[bool] = None
    status: str = "review"
    category: str = "functional"
    cluster: str = "uncategorized"
    removal_layer: str = "review_queue"
    installer_cluster_id: Optional[str] = None
    subtree_class: str = "none"
    rename_family_id: Optional[str] = None
    vendor_family_id: Optional[str] = None
    service_branch_id: Optional[str] = None
    root_family_id: Optional[str] = None
    cluster_membership_count: int = 0


HELPER_PROCESSES = {
    "msiexec.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "dllhost.exe",
    "explorer.exe",
    "svchost.exe",
    "taskhostw.exe",
    "conhost.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
}

STOP_AT_PARENTS = {
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "lsass.exe",
    "system",
}

AVG_CSV_LINE_BYTES = 350

INTERESTING_OPERATIONS = {
    "CreateFile",
    "WriteFile",
    "CreateDirectory",
    "SetDispositionInformationFile",
    "SetRenameInformationFile",
    "SetBasicInformationFile",
    "RegCreateKey",
    "RegSetValue",
    "RegDeleteKey",
    "RegDeleteValue",
    "RegOpenKey",
    "RegQueryValue",
    "RegEnumKey",
    "RegEnumValue",
    "QueryOpen",
    "QueryDirectory",
    "QueryInformationFile",
    "Process Create",
    "Process Exit",
    "Load Image",
}

QUERY_ONLY_OPS = frozenset(
    {
        "RegOpenKey",
        "RegQueryValue",
        "RegEnumKey",
        "RegEnumValue",
        "QueryOpen",
        "QueryDirectory",
        "QueryInformationFile",
    }
)

WRITE_OPS = frozenset({"WriteFile", "CreateDirectory", "RegCreateKey", "RegSetValue"})
CREATE_LIKE_OPS = frozenset({"CreateDirectory", "RegCreateKey"})
RELATED_CHAIN_OPS = frozenset(
    {
        "WriteFile",
        "CreateDirectory",
        "RegCreateKey",
        "RegSetValue",
        "SetRenameInformationFile",
        "SetDispositionInformationFile",
    }
)
CREATEFILE_CREATE_RE = re.compile(r"Disposition:\s*(Create|Overwrite|CreateNew|Supersede)", re.IGNORECASE)
PERSISTENCE_BONUS = {
    "service": 22,
    "run_entry": 18,
    "scheduled_task": 20,
    "startup_shortcut": 16,
    "firewall_rule": 50,
}

LOW_VALUE_PATH_PREFIXES = [
    "C:\\Windows\\WinSxS\\",
    "C:\\Windows\\System32\\",
    "C:\\Windows\\Logs\\",
    "C:\\Windows\\Prefetch\\",
    "C:\\ProgramData\\Microsoft\\Search\\",
    "C:\\ProgramData\\Microsoft\\Windows Defender\\",
    "C:\\$Recycle.Bin\\",
    "C:\\System Volume Information\\",
]

LOW_VALUE_REG_PREFIXES = [
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing",
    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer",
    "HKLM\\SOFTWARE\\Microsoft\\Tracing",
]

UNINSTALL_KEY_PREFIXES = (
    "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\",
    "hkcu\\software\\microsoft\\windows\\currentversion\\uninstall\\",
    "hkey_local_machine\\software\\microsoft\\windows\\currentversion\\uninstall\\",
    "hkey_current_user\\software\\microsoft\\windows\\currentversion\\uninstall\\",
)

MUI_CACHE_PREFIXES = (
    "hkcu\\software\\classes\\local settings\\software\\microsoft\\windows\\shell\\muicache",
    "hkey_current_user\\software\\classes\\local settings\\software\\microsoft\\windows\\shell\\muicache",
)

BAM_PREFIXES = (
    "hklm\\system\\currentcontrolset\\services\\bam\\state\\usersettings\\",
    "hkey_local_machine\\system\\currentcontrolset\\services\\bam\\state\\usersettings\\",
)

FIREWALL_RULES_PREFIXES = (
    "hklm\\system\\currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy\\firewallrules",
    "hkey_local_machine\\system\\currentcontrolset\\services\\sharedaccess\\parameters\\firewallpolicy\\firewallrules",
)

WINDOWS_INSTALLER_PREFIX = "c:\\windows\\installer\\"

GUID_RE = re.compile(
    r"\{?[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\}?"
)

KNOWN_GENERIC_DIRS = {
    "temp",
    "tmp",
    "cache",
    "logs",
    "log",
    "bin",
    "data",
    "config",
    "plugins",
    "runtime",
    "resources",
    "assets",
    "updater",
}

SAFE_PATH_PREFIXES_FOR_REPORT = [
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\Users",
    "HKCU",
    "HKLM",
]

SAFE_PATH_REGEXES = [
    re.compile(r"^c:\\users\\[^\\]+\\desktop\\", re.IGNORECASE),
    re.compile(r"^c:\\users\\[^\\]+\\appdata\\roaming\\microsoft\\windows\\start menu\\", re.IGNORECASE),
    re.compile(r"^c:\\users\\[^\\]+\\appdata\\local\\programs\\", re.IGNORECASE),
    re.compile(r"^c:\\users\\[^\\]+\\appdata\\local\\temp\\", re.IGNORECASE),
    re.compile(r"^c:\\users\\[^\\]+\\appdata\\local\\crashdumps\\", re.IGNORECASE),
]

REGISTRY_SWEEP_PREFIXES = (
    "hkcr\\clsid\\",
    "hkcr\\interface\\",
    "hkcr\\typelib\\",
    "hkcr\\*\\shell\\",
    "hkcr\\directory\\shell\\",
    "hkcr\\drive\\shell\\",
    "hklm\\software\\classes\\",
    "hkcu\\software\\classes\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\app paths\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\runonce\\",
    "hkcu\\software\\microsoft\\windows\\currentversion\\runonce\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\explorer\\taskcache\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\shell extensions\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\explorer\\contextmenuhandlers\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\explorer\\fileexts\\",
    "hklm\\software\\microsoft\\windows\\currentversion\\installer\\userdata\\",
    "hklm\\system\\currentcontrolset\\services\\",
)

REGISTRY_EXPANSION_LIMITS = {
    "\\services\\": 1200,
    "\\taskcache\\": 1000,
    "\\clsid\\": 1000,
    "\\typelib\\": 800,
    "\\shell extensions\\": 800,
    "\\contextmenuhandlers\\": 600,
    "\\app paths\\": 400,
    "\\run\\": 300,
    "\\runonce\\": 300,
    "\\fileexts\\": 800,
    "\\installer\\userdata\\": 1000,
}

USERASSIST_PREFIXES = (
    "hkcu\\software\\microsoft\\windows\\currentversion\\explorer\\userassist\\",
    "hkey_current_user\\software\\microsoft\\windows\\currentversion\\explorer\\userassist\\",
)

REGISTRY_PREFIXES = (
    "hklm\\",
    "hkcu\\",
    "hkcr\\",
    "hku\\",
    "hkey_local_machine\\",
    "hkey_current_user\\",
    "hkey_classes_root\\",
    "hkey_users\\",
)

# PERF-4 fix: Move reg_root_map to module level to avoid recreating on every call
_REG_ROOT_MAP = {
    "hkey_local_machine\\": "hklm\\",
    "hkey_current_user\\": "hkcu\\",
    "hkey_classes_root\\": "hkcr\\",
    "hkey_users\\": "hku\\",
}

STOP_WORDS = {
    "exe",
    "dll",
    "tmp",
    "log",
    "txt",
    "mui",
    "com",
    "sys",
    "ini",
    "dat",
    "users",
    "local",
    "roaming",
    "appdata",
    "programdata",
    "program",
    "files",
    "windows",
    "system32",
    "software",
    "microsoft",
    "currentversion",
    "hklm",
    "hkcu",
    "hkcr",
}

# ──────────────────────────────────────────────
# Trusted signers for Authenticode verification
# ──────────────────────────────────────────────
TRUSTED_SIGNERS = {
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft code signing pca",
}

_signature_cache: Dict[str, Optional[str]] = {}  # str = company name, None = not trusted
_signature_cache_lock = threading.Lock()  # CODE-6: thread-safe access

# P1 fix: Real Authenticode verification via WinVerifyTrust
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = None
_wintrust_available = False
if os.name == "nt":
    try:
        import ctypes.wintypes as _wt

        class _WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", _wt.DWORD),
                ("pcwszFilePath", _wt.LPCWSTR),
                ("hFile", _wt.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class _GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", _wt.DWORD),
                ("Data2", _wt.WORD),
                ("Data3", _wt.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        class _WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", _wt.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", _wt.DWORD),
                ("fdwRevocationChecks", _wt.DWORD),
                ("dwUnionChoice", _wt.DWORD),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", _wt.DWORD),
                ("hWVTStateData", _wt.HANDLE),
                ("pwszURLReference", _wt.LPCWSTR),
                ("dwProvFlags", _wt.DWORD),
                ("dwUIContext", _wt.DWORD),
                ("pSignatureSettings", ctypes.c_void_p),
            ]

        _WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
            0xAAC56B, 0xCD44, 0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
        )
        # Test that wintrust.dll is loadable
        ctypes.windll.wintrust.WinVerifyTrust
        _wintrust_available = True
    except Exception:
        _wintrust_available = False

_authenticode_cache: Dict[str, Optional[bool]] = {}  # True = valid sig, False = invalid, None = error
_authenticode_cache_lock = threading.Lock()


# ──────────────────────────────────────────────
# Detail column structured parser
# ──────────────────────────────────────────────
def parse_detail(detail: str) -> Dict[str, str]:
    """
    Parse Procmon Detail column into key-value pairs.

    Procmon Detail format examples:
        "Desired Access: Read Data/List Directory, Disposition: Open, Options: Synchronous IO Non-Alert"
        "Type: REG_SZ, Length: 24, Data: C:\\Program Files\\App"
        "PID: 1234, Command line: app.exe --install"

    Returns dict like:
        {"Desired Access": "Read Data/List Directory", "Disposition": "Open", ...}
    """
    result: Dict[str, str] = {}
    if not detail:
        return result
    parts = re.split(r',\s*(?=[A-Za-z][A-Za-z\s]*:)', detail)
    for part in parts:
        part = part.strip()
        if ':' not in part:
            continue
        key, _, value = part.partition(':')
        key = key.strip()
        value = value.strip()
        if key and value:
            result[key] = value
    return result


# ──────────────────────────────────────────────
# WOW6432Node equivalents
# ──────────────────────────────────────────────
def get_wow64_equivalents(path: str) -> List[str]:
    """Return WOW64-equivalent paths for both filesystem and registry."""
    equivalents: List[str] = []
    lp = (path or "").lower()

    # Filesystem: Program Files <-> Program Files (x86)
    if "\\program files\\" in lp and "\\program files (x86)\\" not in lp:
        idx = lp.find("\\program files\\")
        equivalents.append(path[:idx] + "\\Program Files (x86)\\" + path[idx + len("\\Program Files\\"):])
    elif "\\program files (x86)\\" in lp:
        idx = lp.find("\\program files (x86)\\")
        equivalents.append(path[:idx] + "\\Program Files\\" + path[idx + len("\\Program Files (x86)\\"):])

    # Registry: SOFTWARE\X -> SOFTWARE\WOW6432Node\X and vice versa
    wow_node = "\\wow6432node\\"
    software_key = "\\software\\"
    if software_key in lp and wow_node not in lp:
        idx = lp.find(software_key)
        insert_pos = idx + len(software_key)
        equivalents.append(path[:insert_pos] + "WOW6432Node\\" + path[insert_pos:])
    elif wow_node in lp:
        # Remove \WOW6432Node\ — keep exactly one backslash separator
        # P11 fix: use a lambda to return literal single backslash
        equivalents.append(re.sub(r'\\WOW6432Node\\', lambda _: '\\', path, count=1, flags=re.IGNORECASE))

    return equivalents


# ──────────────────────────────────────────────
# Scoring config loader
# ──────────────────────────────────────────────
SCORING_CONFIG = {
    "thresholds": {"safe_delete": 80, "review": 55, "minimum_include": 10},
    "persistence_bonus": {"service": 22, "run_entry": 18, "scheduled_task": 20, "startup_shortcut": 16, "firewall_rule": 50},
    "location_scores": {"appdata": 12, "programdata": 10, "program_files": 14, "hkcu_software": 16, "uninstall_key": 24, "current_version_run": 18},
    "provenance": {"first_creator_related": 45, "first_writer_related": 35, "exclusively_touched": 20, "written_by_chain_no_token": 35, "no_non_related_writes": 10, "installer_cache_related": 30, "guid_correlation": 40},
    "depth_boost": {"depth_0_1": 55, "depth_2_3": 40, "depth_4_plus": 25},
    "match_scores": {"path_match_base": 50, "path_extra_per_term": 5, "path_extra_max": 15, "detail_match": 20},
    "activity": {"write_0": -8, "write_1_2": 5, "write_3_9": 10, "write_10_plus": 15, "created": 10, "modified": 8, "read_only": -5},
    "session": {"non_related_writer_window": 10, "location_proximity": 25},
    "penalties": {"low_value_area": -45, "microsoft_path_no_token": -30, "generic_dir": -10},
    "traces": {"prefetch_trace": 15, "execution_trace": 15},
    "special": {"firewall_rule_reference": 50, "checked_only_residue": 12, "helper_process_default_boost": 20, "direct_chain_default_boost": 60},
    "cluster_bonus": {"threshold_4": 10, "threshold_7": 20, "threshold_10": 30},
    "fusion": {"types_3_bonus": 25, "types_4_bonus": 40},
    "subtree": {"subtree_only_or_first_bonus": 15},
    "expansion": {"neighborhood_min_score": 55, "survivor_min_score": 55, "registry_branch_min_score": 50, "sibling_min_score": 40, "confirmed_root_min_score": 80, "vendor_sweep_base_score": 45, "mirrored_root_score": 55},
}


# ──────────────────────────────────────────────
# Trusted publisher check (via CompanyName in version info, NOT real Authenticode)
# NOTE: This is a lightweight heuristic — it reads CompanyName from the PE version
# resource, NOT from a cryptographic signature. A malicious file could spoof this.
# For real Authenticode verification, WinVerifyTrust API would be required.
# ──────────────────────────────────────────────
def check_company_name_trusted(file_path: str) -> Optional[str]:
    """
    Lightweight trusted-publisher check via PE version info CompanyName.
    Returns company name string if it matches a known trusted publisher, else None.
    NOTE: This does NOT verify a cryptographic Authenticode signature.
    """
    if os.name != "nt":
        return None
    if not os.path.isfile(file_path):
        return None

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in {".exe", ".dll", ".sys", ".ocx", ".msi", ".cat"}:
        return None

    # cache_key must be defined BEFORE the cache lookup (was missing — NameError fix)
    cache_key = file_path.lower()

    # Check cache (thread-safe)
    with _signature_cache_lock:
        if cache_key in _signature_cache:
            cached = _signature_cache[cache_key]
            return cached if isinstance(cached, str) else None

    try:
        info = read_file_version_info(file_path)
        company = (info.get("CompanyName") or "").strip()
        result: Optional[str] = company if company and company.lower() in TRUSTED_SIGNERS else None
        with _signature_cache_lock:
            _signature_cache[cache_key] = result
        return result
    except Exception:
        with _signature_cache_lock:
            _signature_cache[cache_key] = None
        return None


# Keep old name as alias for backwards compatibility
verify_authenticode_signature = check_company_name_trusted


def verify_authenticode_wintrust(file_path: str) -> Optional[bool]:
    """P1 fix: Real Authenticode verification using WinVerifyTrust API.
    Returns True if the file has a valid cryptographic signature,
    False if invalid/unsigned, None if verification is unavailable."""
    if not _wintrust_available or os.name != "nt":
        return None
    if not os.path.isfile(file_path):
        return None

    cache_key = file_path.lower()
    with _authenticode_cache_lock:
        if cache_key in _authenticode_cache:
            return _authenticode_cache[cache_key]

    try:
        file_info = _WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = _WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        trust_data.dwUIChoice = 2  # WTD_UI_NONE
        trust_data.fdwRevocationChecks = 0  # WTD_REVOKE_NONE (fast)
        trust_data.dwUnionChoice = 1  # WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = 0  # WTD_STATEACTION_IGNORE
        trust_data.dwProvFlags = 0x00000010  # WTD_CACHE_ONLY_URL_RETRIEVAL (offline)

        result = ctypes.windll.wintrust.WinVerifyTrust(
            None,  # INVALID_HANDLE_VALUE would be -1, None works for desktop
            ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data),
        )
        is_valid = (result == 0)  # S_OK = valid signature
        with _authenticode_cache_lock:
            _authenticode_cache[cache_key] = is_valid
        return is_valid
    except Exception:
        with _authenticode_cache_lock:
            _authenticode_cache[cache_key] = None
        return None


def is_trusted_signed(file_path: str) -> bool:
    """P1 fix: Check if a file is trusted — uses real Authenticode first,
    falls back to CompanyName heuristic only if WinVerifyTrust unavailable."""
    # Step 1: Try real Authenticode verification
    authenticode_result = verify_authenticode_wintrust(file_path)
    if authenticode_result is True:
        return True
    if authenticode_result is False:
        return False  # Explicitly unsigned/invalid — do NOT trust CompanyName either

    # Step 2: Fallback to CompanyName heuristic (WinVerifyTrust unavailable)
    signer = check_company_name_trusted(file_path)
    if not signer:
        return False
    return signer.strip().lower() in TRUSTED_SIGNERS


def normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def safe_int(value: str) -> Optional[int]:
    try:
        return int(str(value).strip())
    except Exception:
        return None


def normalize_proc_name(name: str) -> str:
    return (name or "").strip().lower()


def normalize_path(path: str) -> str:
    p = (path or "").strip().strip('"')
    p = p.replace("/", "\\")
    # EDGE-2 fix: Preserve UNC prefix
    is_unc = p.startswith("\\\\")
    p = re.sub(r"\\+", r"\\", p)
    if is_unc:
        p = "\\" + p  # Restore double backslash for UNC paths
    return p


_NORM_LOW_VALUE_PATHS = [normalize_path(prefix).lower() for prefix in LOW_VALUE_PATH_PREFIXES]
_NORM_LOW_VALUE_REGS = [normalize_path(prefix).lower() for prefix in LOW_VALUE_REG_PREFIXES]
_NORM_SAFE_PREFIXES = [normalize_path(prefix).lower() for prefix in SAFE_PATH_PREFIXES_FOR_REPORT]


def split_tokens(text: str) -> List[str]:
    text = re.sub(r"[^A-Za-z0-9]+", " ", text or "")
    out: List[str] = []
    for token in text.split():
        token = token.strip().lower()
        if len(token) < 3:
            continue
        if token in STOP_WORDS:
            continue
        out.append(token)
    return out


def rot13(text: str) -> str:
    return text.translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        )
    )


def compile_term_patterns(
    terms: List[str],
    mode_filter: Optional[Set[str]] = None,
) -> Dict[str, List[Tuple[str, re.Pattern[str], float]]]:
    active_modes = mode_filter or {"exact", "substring", "segment", "rot13"}
    patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]] = {
        "exact": [],
        "substring": [],
        "segment": [],
        "rot13": [],
    }
    seen: Set[Tuple[str, str]] = set()
    for term in terms:
        clean = (term or "").strip()
        if len(clean) < 2:
            continue
        norm = clean.lower()

        key = (norm, "exact")
        if key not in seen and "exact" in active_modes:
            seen.add(key)
            patterns["exact"].append((norm, re.compile(rf"\b{re.escape(clean)}\b", re.IGNORECASE), 1.0))

        key = (norm, "substring")
        if key not in seen and "substring" in active_modes:
            seen.add(key)
            patterns["substring"].append((norm, re.compile(re.escape(clean), re.IGNORECASE), 0.6))

        key = (norm, "segment")
        if key not in seen and "segment" in active_modes:
            seen.add(key)
            patterns["segment"].append(
                (
                    norm,
                    re.compile(rf"(?:^|[\\/\.\-_]){re.escape(clean)}(?:$|[\\/\.\-_])", re.IGNORECASE),
                    0.4,
                )
            )

        if "rot13" in active_modes:
            rot = rot13(clean)
            key = (rot.lower(), "rot13")
            if key not in seen:
                seen.add(key)
                patterns["rot13"].append((norm, re.compile(re.escape(rot), re.IGNORECASE), 0.8))
    return patterns


def merge_term_patterns(
    base: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    extra: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
) -> Dict[str, List[Tuple[str, re.Pattern[str], float]]]:
    merged: Dict[str, List[Tuple[str, re.Pattern[str], float]]] = {
        "exact": list(base.get("exact", [])),
        "substring": list(base.get("substring", [])),
        "segment": list(base.get("segment", [])),
        "rot13": list(base.get("rot13", [])),
    }
    seen = {
        mode: {(term, pattern.pattern, weight) for term, pattern, weight in merged.get(mode, [])}
        for mode in merged
    }
    for mode, items in extra.items():
        for term, pattern, weight in items:
            sig = (term, pattern.pattern, weight)
            if sig in seen[mode]:
                continue
            seen[mode].add(sig)
            merged[mode].append((term, pattern, weight))
    return merged


def token_hits(text: str, patterns: PatternDict, allow_rot13: bool = False) -> List[Tuple[str, str, float]]:
    sample = text or ""
    hits: List[Tuple[str, str, float]] = []
    for mode in ["exact", "substring", "segment"]:
        for term, pattern, weight in patterns.get(mode, []):
            if pattern.search(sample):
                hits.append((term, mode, weight))
    if allow_rot13:
        for term, pattern, weight in patterns.get("rot13", []):
            if pattern.search(sample):
                hits.append((term, "rot13", weight))
    return hits


def token_hit_terms(text: str, patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]], allow_rot13: bool = False) -> List[str]:
    terms: List[str] = []
    seen: Set[str] = set()
    for term, _, _ in token_hits(text, patterns, allow_rot13=allow_rot13):
        if term in seen:
            continue
        seen.add(term)
        terms.append(term)
    return terms


def token_hit_weight(text: str, patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]], allow_rot13: bool = False) -> float:
    hits = token_hits(text, patterns, allow_rot13=allow_rot13)
    if not hits:
        return 0.0
    return max(weight for _, _, weight in hits)


def parse_procmon_time_to_dt(value: str) -> Optional[datetime]:
    text = (value or "").strip()
    if not text:
        return None
    for fmt in ["%I:%M:%S.%f %p", "%I:%M:%S %p", "%H:%M:%S.%f", "%H:%M:%S"]:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def read_file_version_info(path: str) -> Dict[str, str]:
    """Read CompanyName and ProductName from PE version resource.
    Tries all available translation code pages instead of hardcoding 040904B0."""
    if os.name != "nt":
        return {}
    try:
        dummy = wintypes.DWORD(0)
        size = ctypes.windll.version.GetFileVersionInfoSizeW(path, ctypes.byref(dummy))
        if size == 0:
            return {}
        data = (ctypes.c_byte * size)()
        ok = ctypes.windll.version.GetFileVersionInfoW(path, 0, size, ctypes.byref(data))
        if not ok:
            return {}

        # Read available translations instead of hardcoding 040904B0
        trans_ptr = ctypes.c_void_p()
        trans_len = wintypes.UINT(0)
        ctypes.windll.version.VerQueryValueW(
            ctypes.byref(data), "\\VarFileInfo\\Translation",
            ctypes.byref(trans_ptr), ctypes.byref(trans_len)
        )
        code_pages: List[str] = []
        if trans_ptr.value and trans_len.value >= 4:
            num = trans_len.value // 4
            arr = (ctypes.c_uint16 * (num * 2)).from_address(trans_ptr.value)
            for i in range(num):
                lang = arr[i * 2]
                cp = arr[i * 2 + 1]
                code_pages.append(f"{lang:04X}{cp:04X}")
        if not code_pages:
            code_pages = ["040904B0"]  # fallback: US English Unicode

        out: Dict[str, str] = {}
        for cp in code_pages:
            for key in ["CompanyName", "ProductName"]:
                if key in out:
                    continue
                query = f"\\StringFileInfo\\{cp}\\{key}"
                value_ptr = ctypes.c_void_p()
                value_len = wintypes.UINT(0)
                ok2 = ctypes.windll.version.VerQueryValueW(
                    ctypes.byref(data),
                    query,
                    ctypes.byref(value_ptr),
                    ctypes.byref(value_len),
                )
                if ok2 and value_ptr.value and value_len.value:
                    out[key] = ctypes.wstring_at(value_ptr.value, value_len.value - 1)
        return out
    except Exception:
        return {}


def path_is_low_value(path: str) -> bool:
    lp = (path or "").lower()
    for prefix in _NORM_LOW_VALUE_PATHS:
        if lp.startswith(prefix):
            return True
    for prefix in _NORM_LOW_VALUE_REGS:
        if lp.startswith(prefix):
            return True
    return False


def path_has_safe_prefix(path: str) -> bool:
    lp = (path or "").lower()
    if any(lp.startswith(prefix) for prefix in _NORM_SAFE_PREFIXES):
        return True
    return any(rx.match(lp) for rx in SAFE_PATH_REGEXES)


def _replace_ci(text: str, old: str, new: str) -> str:
    idx = text.lower().find(old.lower())
    if idx < 0:
        return text
    return text[:idx] + new + text[idx + len(old) :]


def get_current_username() -> str:
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        name = Path(user_profile).name.strip()
        if name:
            return name
    return (os.environ.get("USERNAME", "") or "").strip()


def map_sandbox_user_path(path: str) -> str:
    p = path or ""
    username = get_current_username()
    if not username:
        return p
    lower_p = p.lower()
    if any(lower_p.startswith(prefix) for prefix in REGISTRY_PREFIXES):
        return p
    mapped = p
    mapped = _replace_ci(mapped, "C:\\Users\\WDAGUtilityAccount\\", f"C:\\Users\\{username}\\")
    mapped = _replace_ci(mapped, "C:\\Users\\Default\\", f"C:\\Users\\{username}\\")
    return mapped


def path_looks_sandbox(path: str) -> bool:
    lp = (path or "").lower()
    return "\\users\\wdagutilityaccount\\" in lp or "\\users\\default\\" in lp


def detect_item_type(path: str) -> str:
    lp = (path or "").lower()
    if any(lp.startswith(prefix) for prefix in USERASSIST_PREFIXES):
        return "execution_trace"
    if any(lp.startswith(prefix) for prefix in MUI_CACHE_PREFIXES) or any(lp.startswith(prefix) for prefix in BAM_PREFIXES):
        return "execution_trace"
    if "\\prefetch\\" in lp and lp.endswith(".pf"):
        return "prefetch_trace"
    if lp.startswith("c:\\programdata\\microsoft\\windows\\wer\\reportarchive\\") or "\\crashdumps\\" in lp:
        return "crash_dump"
    if any(lp.startswith(prefix) for prefix in FIREWALL_RULES_PREFIXES):
        return "firewall_rule"
    if lp.startswith("hkcr\\clsid\\"):
        return "clsid"
    if lp.startswith("hkcr\\typelib\\"):
        return "typelib"
    if "\\contextmenuhandlers\\" in lp:
        return "context_menu"
    if "\\protocol\\handler" in lp:
        return "protocol_handler"
    if "\\shell extensions\\" in lp:
        return "shell_extension"
    if "\\openwith" in lp or "\\fileexts\\" in lp:
        return "file_association"
    if lp.startswith("hklm\\system\\currentcontrolset\\services\\") or lp.startswith(
        "hkey_local_machine\\system\\currentcontrolset\\services\\"
    ):
        return "service"
    if "\\currentversion\\run" in lp:
        return "run_entry"
    if lp.startswith("c:\\windows\\system32\\tasks\\"):
        return "scheduled_task"
    if lp.endswith(".lnk") and (
        "\\start menu\\programs\\startup\\" in lp or "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\" in lp
    ):
        return "startup_shortcut"
    # LOGIC-2 fix: check uninstall_key BEFORE the generic reg_key catch-all
    # LOGIC-3 fix: Use UNINSTALL_KEY_PREFIXES for more precise detection
    if any(lp.startswith(prefix) for prefix in UNINSTALL_KEY_PREFIXES):
        return "uninstall_key"
    if any(lp.startswith(prefix) for prefix in REGISTRY_PREFIXES):
        return "reg_key"
    if lp.endswith(".lnk"):
        return "shortcut"
    if lp.startswith(WINDOWS_INSTALLER_PREFIX):
        return "installer_cache"
    if lp.endswith((".db", ".sqlite")):
        return "database"
    if lp.endswith((".json", ".ini", ".xml", ".yaml", ".yml")):
        return "config"
    if lp.endswith(".log"):
        return "log"
    if lp.endswith((".exe", ".dll")):
        return "binary"
    if lp.endswith(".cache"):
        return "cache"
    if re.search(r"\\[^\\]+\.[a-z0-9]{1,6}$", lp):
        return "file"
    return "dir"


def category_from_type(item_type: str) -> str:
    if item_type in {
        "service",
        "run_entry",
        "scheduled_task",
        "startup_shortcut",
        "firewall_rule",
        "shell_extension",
        "context_menu",
        "protocol_handler",
    }:
        return "persistence"
    if item_type in {"execution_trace", "prefetch_trace", "crash_dump"}:
        return "execution_trace"
    if item_type in {"installer_cache", "uninstall_key", "clsid", "typelib"}:
        return "installer_bookkeeping"
    if item_type in {"config", "database", "cache", "log"}:
        return "user_data"
    return "functional"


def cluster_from_path(path: str) -> str:
    lp = (path or "").lower()
    if any(lp.startswith(prefix) for prefix in REGISTRY_PREFIXES):
        return "registry"
    if lp.startswith("c:\\program files"):
        return "program_files"
    if lp.startswith("c:\\programdata\\"):
        return "program_data"
    if "\\appdata\\" in lp:
        return "app_data"
    if lp.startswith(WINDOWS_INSTALLER_PREFIX):
        return "installer_cache"
    if "\\prefetch\\" in lp or any(lp.startswith(prefix) for prefix in MUI_CACHE_PREFIXES) or any(lp.startswith(prefix) for prefix in BAM_PREFIXES):
        return "execution_traces"
    return "other"


def _detect_encoding(csv_path: str) -> str:
    with open(csv_path, "rb") as bf:
        bom = bf.read(4)
    if bom[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "utf-16"
    if bom[:3] == b"\xef\xbb\xbf":
        return "utf-8-sig"
    return "utf-8-sig"


class ProcmonCsvLoader:
    REQUIRED_FIELD_ALIASES = {
        "Time of Day": ("Time of Day", "Date & Time"),
        "Process Name": ("Process Name",),
        "PID": ("PID", "Process ID"),
        "Operation": ("Operation",),
        "Path": ("Path",),
        "Result": ("Result",),
        "Detail": ("Detail",),
    }

    @classmethod
    def load_csv(
        cls,
        csv_path: str,
        progress_cb: Optional[Callable[[int, str], None]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> List[ProcmonEvent]:
        events: List[ProcmonEvent] = []
        encoding = _detect_encoding(csv_path)
        total_size = os.path.getsize(csv_path)
        estimated_lines = max(1, total_size // AVG_CSV_LINE_BYTES)

        with open(csv_path, "r", encoding=encoding, errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            headers = set(reader.fieldnames or [])
            missing = [
                canonical
                for canonical, aliases in cls.REQUIRED_FIELD_ALIASES.items()
                if not any(alias in headers for alias in aliases)
            ]
            if missing:
                raise ValueError(f"CSV-də lazımi sütunlar yoxdur: {', '.join(sorted(missing))}")

            for line_idx, row in enumerate(reader, start=1):
                if cancel_cb and cancel_cb():
                    raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
                if progress_cb and line_idx % 2000 == 0:
                    progress = min(99, int((line_idx / estimated_lines) * 100))
                    progress_cb(progress, f"CSV oxunur... {line_idx:,} sətir")

                event = ProcmonEvent(
                    time_of_day=normalize_spaces(row.get("Time of Day") or row.get("Date & Time") or ""),
                    process_name=normalize_spaces(row.get("Process Name", "")),
                    pid=safe_int(row.get("PID") or row.get("Process ID") or ""),
                    operation=normalize_spaces(row.get("Operation", "")),
                    path=normalize_path(row.get("Path", "")),
                    result=normalize_spaces(row.get("Result", "")),
                    detail=normalize_spaces(row.get("Detail", "")),
                    parent_pid=safe_int(row.get("Parent PID", "")),
                    process_path=normalize_path(row.get("Process Path") or row.get("Image Path") or ""),
                    command_line=normalize_spaces(row.get("Command Line", "")),
                )
                # PERF-6 fix: Filter uninteresting operations during CSV loading to reduce memory usage
                if event.operation in INTERESTING_OPERATIONS:
                    events.append(event)

        if progress_cb:
            progress_cb(100, f"CSV yükləndi: {len(events):,} sətir")
        return events


class ProcmonAnalyzer:
    def __init__(
        self,
        events: List[ProcmonEvent],
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
        scoring_config: Optional[dict] = None,
    ):
        self.config = scoring_config or SCORING_CONFIG
        self.events = events
        self.by_pid: Dict[int, List[ProcmonEvent]] = defaultdict(list)
        self.children_by_pid: Dict[int, Set[int]] = defaultdict(set)
        self.parent_by_pid: Dict[int, int] = {}
        self.proc_names_by_pid: Dict[int, str] = {}
        self.pid_all_text: Dict[int, str] = {}
        self.process_info_by_pid: Dict[int, ProcessInfo] = {}
        self.rename_map: Dict[str, str] = {}
        self.rename_reverse_map: Dict[str, Set[str]] = defaultdict(set)
        self.rename_edges: List[Tuple[str, str, Optional[int], str]] = []
        self.path_facts: Dict[str, Dict[str, object]] = {}
        self.path_family_facts: Dict[str, Dict[str, object]] = {}
        self._index_events(cancel_cb=cancel_cb, progress_cb=progress_cb)

    def _index_events(
        self,
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        pid_unique_paths: Dict[int, Set[str]] = defaultdict(set)
        pid_parts: Dict[int, Set[str]] = defaultdict(set)
        total_events = max(1, len(self.events))

        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 5000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 50000 == 0:
                progress = min(99, int((idx / total_events) * 100))
                progress_cb(progress, f"İndeksləmə... {idx:,}/{total_events:,}")
            if ev.pid is not None:
                self.by_pid[ev.pid].append(ev)
                info = self.process_info_by_pid.setdefault(ev.pid, ProcessInfo(pid=ev.pid))
                if ev.process_name:
                    info.proc_name = ev.process_name
                if ev.process_path:
                    info.image_path = ev.process_path
                if ev.command_line:
                    info.command_line = ev.command_line
                if not info.start_time and ev.time_of_day:
                    info.start_time = ev.time_of_day
                if ev.operation == "Process Exit" and ev.time_of_day:
                    info.end_time = ev.time_of_day

                stored_name = self.proc_names_by_pid.get(ev.pid)
                if stored_name is None:
                    if ev.process_name:
                        self.proc_names_by_pid[ev.pid] = ev.process_name
                elif ev.process_name and normalize_proc_name(ev.process_name) != normalize_proc_name(stored_name):
                    self.proc_names_by_pid[ev.pid] = ev.process_name
                    # LOGIC-1 fix: PID reuse detected — clear accumulated text for this PID
                    pid_parts[ev.pid] = set()
                    pid_unique_paths[ev.pid] = set()
                    if ev.parent_pid is not None:
                        old_parent = self.parent_by_pid.get(ev.pid)
                        if old_parent is not None and old_parent != ev.parent_pid:
                            self.children_by_pid[old_parent].discard(ev.pid)
                        self.parent_by_pid[ev.pid] = ev.parent_pid
                        self.children_by_pid[ev.parent_pid].add(ev.pid)
                if ev.parent_pid is not None and ev.pid not in self.parent_by_pid:
                    self.parent_by_pid[ev.pid] = ev.parent_pid
                    self.children_by_pid[ev.parent_pid].add(ev.pid)
                if ev.process_path:
                    pid_parts[ev.pid].add(ev.process_path.lower())
                if ev.command_line:
                    pid_parts[ev.pid].add(ev.command_line.lower())
                if ev.detail:
                    pid_parts[ev.pid].add(ev.detail.lower())
                    pid_parts[ev.pid].update(split_tokens(ev.detail))
                if ev.path:
                    pid_unique_paths[ev.pid].add(ev.path)
            if ev.operation == "Process Create":
                parent = ev.pid
                child = self._extract_child_pid(ev.detail)
                child_name = self._extract_child_name(ev.path, ev.detail)
                if parent is not None and child is not None:
                    old_parent = self.parent_by_pid.get(child)
                    if old_parent is not None and old_parent != parent:
                        self.children_by_pid[old_parent].discard(child)
                    self.children_by_pid[parent].add(child)
                    self.parent_by_pid[child] = parent
                    child_info = self.process_info_by_pid.setdefault(child, ProcessInfo(pid=child))
                    if ev.time_of_day:
                        child_info.start_time = ev.time_of_day
                    child_info.proc_name = child_name or child_info.proc_name
                    if child_name:
                        self.proc_names_by_pid[child] = child_name
            if ev.operation == "SetRenameInformationFile" and ev.path:
                target = self._extract_rename_target(ev.detail)
                if target:
                    src = ev.path
                    dst = target
                    src_id = self._canonical_path(src)
                    dst_id = self._canonical_path(dst)
                    if src_id and dst_id:
                        self.rename_map[src_id] = dst_id
                        self.rename_reverse_map[dst_id].add(src_id)
                    self.rename_edges.append((src, dst, ev.pid, ev.time_of_day))

        for pid in self.by_pid:
            parts = pid_parts.get(pid, set()).copy()
            proc = self.proc_names_by_pid.get(pid, "")
            if proc:
                parts.add(proc.lower())
            for p in pid_unique_paths.get(pid, set()):
                parts.update(seg for seg in p.lower().split("\\") if seg)
            self.pid_all_text[pid] = " ".join(parts)

        for pid, info in self.process_info_by_pid.items():
            if not info.proc_name:
                info.proc_name = self.proc_names_by_pid.get(pid, "")
        if progress_cb:
            progress_cb(100, "İndeksləmə tamamlandı")

    @staticmethod
    def _extract_child_pid(detail: str) -> Optional[int]:
        match = re.search(r"PID:\s*(\d+)", detail or "", re.IGNORECASE)
        if match:
            return safe_int(match.group(1))
        return None

    @staticmethod
    def _extract_child_name(path: str, detail: str) -> str:
        if path:
            base = os.path.basename(path)
            if base:
                return base
        match = re.search(r"Command line:\s*([^,]+)", detail or "", re.IGNORECASE)
        if match:
            return os.path.basename(match.group(1).strip().strip('"'))
        return ""

    @staticmethod
    def _extract_rename_target(detail: str) -> str:
        match = re.search(r"FileName:\s*([^,]+)", detail or "", re.IGNORECASE)
        if not match:
            return ""
        return normalize_path(match.group(1).strip().strip('"'))

    def canonical_artifact_key(self, path: str) -> Tuple[str, str]:
        # Identity key: normalize path shape but do not collapse rename family.
        p = normalize_path(path).lower().rstrip("\\")
        if not p:
            return "unknown", ""
        for long_root, short_root in _REG_ROOT_MAP.items():
            if p.startswith(long_root):
                p = short_root + p[len(long_root) :]
                break

        artifact_type = "registry" if any(p.startswith(prefix) for prefix in REGISTRY_PREFIXES) else "filesystem"
        return artifact_type, p

    def _canonical_path(self, path: str) -> str:
        return self.canonical_artifact_key(path)[1]

    def _family_canonical_path(self, path: str) -> str:
        return self._family_canonical_path_from_key(self._canonical_path(path))

    def _family_canonical_path_from_key(self, canonical: str) -> str:
        """PERF-3 fix: accept a pre-computed canonical key to avoid a second
        _canonical_path() call in hot loops like _build_path_provenance_index."""
        current = canonical
        if not current:
            return ""
        visited: Set[str] = set()
        while current and current not in visited:
            visited.add(current)
            nxt = self.rename_map.get(current)
            if not nxt:
                break
            current = nxt
        return current

    def _build_path_provenance_index(
        self,
        related_pids: Set[int],
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
    ) -> None:
        facts: Dict[str, Dict[str, object]] = {}
        family_facts: Dict[str, Dict[str, object]] = {}

        def ensure(key: str) -> Dict[str, object]:
            if key not in facts:
                facts[key] = {
                    "first_creator_pid": None,
                    "first_writer_pid": None,
                    "writer_pids": set(),
                    "touched_pids": set(),
                    "related_write_count": 0,
                    "non_related_write_count": 0,
                    "create_count": 0,
                    "rename_in": [],
                    "rename_out": [],
                }
            return facts[key]

        def ensure_family(key: str) -> Dict[str, object]:
            if key not in family_facts:
                family_facts[key] = {
                    "first_creator_pid": None,
                    "first_writer_pid": None,
                    "writer_pids": set(),
                    "touched_pids": set(),
                    "related_write_count": 0,
                    "non_related_write_count": 0,
                    "create_count": 0,
                    "rename_in": [],
                    "rename_out": [],
                }
            return family_facts[key]

        def apply_to_fact(item: Dict[str, object], ev: ProcmonEvent, is_creator: bool, is_writer: bool):
            if ev.pid is not None:
                cast_set = item["touched_pids"]
                if isinstance(cast_set, set):
                    cast_set.add(ev.pid)
            if is_creator:
                item["create_count"] = int(item["create_count"]) + 1
                if item["first_creator_pid"] is None:
                    item["first_creator_pid"] = ev.pid
            if is_writer:
                if ev.pid is not None:
                    writer_set = item["writer_pids"]
                    if isinstance(writer_set, set):
                        writer_set.add(ev.pid)
                if item["first_writer_pid"] is None:
                    item["first_writer_pid"] = ev.pid
                if ev.pid is not None and ev.pid in related_pids:
                    item["related_write_count"] = int(item["related_write_count"]) + 1
                else:
                    item["non_related_write_count"] = int(item["non_related_write_count"]) + 1

        total_events = max(1, len(self.events))
        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 4000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 5000 == 0:
                progress_cb(min(99, int((idx / total_events) * 100)),
                            f"Yol indeksi qurulur... {idx:,}/{total_events:,}")
            if not ev.path:
                continue
            member_key = self._canonical_path(ev.path)
            # PERF-3 fix: reuse already-computed member_key instead of calling
            # _family_canonical_path (which would call _canonical_path a second time).
            family_key = self._family_canonical_path_from_key(member_key)
            if not member_key:
                continue
            item = ensure(member_key)
            fam_item = ensure_family(family_key or member_key)

            is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
            is_creator = is_create_disposition or ev.operation in CREATE_LIKE_OPS
            is_writer = ev.operation in WRITE_OPS or is_create_disposition or ev.operation in {"SetRenameInformationFile", "SetDispositionInformationFile"}

            apply_to_fact(item, ev, is_creator, is_writer)
            apply_to_fact(fam_item, ev, is_creator, is_writer)

        for src, dst, _, _ in self.rename_edges:
            src_member = self._canonical_path(src)
            dst_member = self._canonical_path(dst)
            src_family = self._family_canonical_path(src)
            dst_family = self._family_canonical_path(dst)
            if src_member:
                ensure(src_member)["rename_out"].append(normalize_path(dst))
            if dst_member:
                ensure(dst_member)["rename_in"].append(normalize_path(src))
            if src_family:
                ensure_family(src_family)["rename_out"].append(normalize_path(dst))
            if dst_family:
                ensure_family(dst_family)["rename_in"].append(normalize_path(src))

        self.path_facts = facts
        self.path_family_facts = family_facts

    def build_related_pid_set(
        self,
        term_patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    ) -> Tuple[Set[int], Set[int], Set[int], Dict[int, int]]:
        roots: Set[int] = set()

        for pid in self.by_pid:
            proc_name = normalize_proc_name(self.proc_names_by_pid.get(pid, ""))
            if proc_name in STOP_AT_PARENTS:
                continue
            text = self.pid_all_text.get(pid, "")
            if token_hits(text, term_patterns):
                roots.add(pid)

        root_seed_pids = set(roots)
        for pid in list(roots):
            current = pid
            visited_up = {pid}
            while current in self.parent_by_pid:
                parent = self.parent_by_pid[current]
                if parent in visited_up:
                    break
                visited_up.add(parent)
                parent_name = normalize_proc_name(self.proc_names_by_pid.get(parent, ""))
                if parent_name in STOP_AT_PARENTS:
                    break
                if parent in roots:
                    break
                roots.add(parent)
                current = parent

        expanded = set(roots)
        depth_by_pid: Dict[int, int] = {pid: 0 for pid in roots}
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            for child in self.children_by_pid.get(current, set()):
                if child not in expanded:
                    expanded.add(child)
                    depth_by_pid[child] = depth_by_pid.get(current, 0) + 1
                    queue.append(child)
        descendants_only = expanded - root_seed_pids
        return expanded, root_seed_pids, descendants_only, depth_by_pid

    def _discover_dynamic_terms(self, term_patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]]) -> List[str]:
        discovered: Set[str] = set()
        for ev in self.events:
            lp = (ev.path or "").lower()
            if not any(lp.startswith(prefix) for prefix in UNINSTALL_KEY_PREFIXES):
                continue
            if not (token_hits(ev.path or "", term_patterns) or token_hits(ev.detail or "", term_patterns)):
                continue
            value_text = ev.detail or ""
            for match in re.finditer(r"([A-Za-z]:\\[^,;\"]+)", value_text):
                extracted = normalize_path(match.group(1).strip())
                if not extracted:
                    continue
                if extracted.lower().endswith(".exe"):
                    extracted = normalize_path(os.path.dirname(extracted))
                if extracted:
                    discovered.add(extracted)
        return sorted(discovered)

    def _extract_execution_trace_aliases(self) -> List[str]:
        aliases: Set[str] = set()
        for ev in self.events:
            lp = (ev.path or "").lower()
            if "\\prefetch\\" in lp and lp.endswith(".pf"):
                m = re.search(r"\\([^\\]+)\.exe-[0-9a-f]+\.pf$", lp)
                if m:
                    aliases.update(split_tokens(m.group(1)))
            if any(lp.startswith(prefix) for prefix in USERASSIST_PREFIXES):
                decoded = rot13(ev.path or "") + " " + rot13(ev.detail or "")
                aliases.update(split_tokens(decoded))
            if any(lp.startswith(prefix) for prefix in MUI_CACHE_PREFIXES):
                aliases.update(split_tokens(ev.detail or ""))
            if any(lp.startswith(prefix) for prefix in BAM_PREFIXES):
                aliases.update(split_tokens(ev.path or ""))
                aliases.update(split_tokens(ev.detail or ""))
        return sorted(aliases)

    def _collect_related_guids(self, related_pids: Set[int]) -> Set[str]:
        guids: Set[str] = set()
        for ev in self.events:
            if ev.pid is None or ev.pid not in related_pids:
                continue
            # BUG-1 fix: only scan registry paths and events that have a non-empty detail
            has_registry_path = (ev.path or "").lower().startswith(REGISTRY_PREFIXES)
            has_detail = bool(ev.detail)
            if not has_registry_path and not has_detail:
                continue
            for text in [ev.path or "", ev.detail or ""]:
                for found in GUID_RE.findall(text):
                    guids.add(found.strip("{}").lower())
        return guids

    def _expand_grouped_with_guid_hits(
        self,
        grouped: Dict[Tuple[str, str], List[ProcmonEvent]],
        guid_tokens: Set[str],
        group_display_path: Optional[Dict[Tuple[str, str], str]] = None,
        cancel_cb: Optional[Callable[[], bool]] = None,
    ) -> None:
        if not guid_tokens:
            return
        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 4000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if not ev.path:
                continue
            sample = f"{ev.path} {ev.detail}".lower()
            if any(guid in sample for guid in guid_tokens):
                key = self.canonical_artifact_key(ev.path)
                if not key[1]:
                    continue
                grouped[key].append(ev)
                if group_display_path is not None:
                    group_display_path.setdefault(key, ev.path)

    def analyze_residue(
        self,
        root_terms: List[str],
        direct_boost: int = 60,
        helper_boost: int = 20,
        cancel_cb: Optional[Callable[[], bool]] = None,
        progress_cb: Optional[Callable[[int, str], None]] = None,
        enrich_file_metadata: bool = True,
    ) -> List[ResidueCandidate]:
        root_terms = [token.lower().strip() for token in root_terms if token.strip()]
        if not root_terms:
            return []

        # Sub-phase allocation within analyze_residue (progress_cb 0-100%):
        #   0-7   : term expansion
        #   7-15  : provenance index building
        #   15-16 : related path identification
        #   16-40 : event filtering
        #   40-42 : GUID expansion
        #   42-80 : group analysis
        #   80-99 : post-processing enrichment
        if progress_cb:
            progress_cb(1, "Terminlər genişləndirilir...")

        seed_patterns = compile_term_patterns(root_terms)
        dynamic_locations = self._discover_dynamic_terms(seed_patterns)
        exec_aliases = self._extract_execution_trace_aliases()
        pass1_terms = self._dedupe_terms(root_terms + dynamic_locations + exec_aliases)
        pass1_patterns = compile_term_patterns(pass1_terms)
        related_pids, _, descendants_only, depth_by_pid = self.build_related_pid_set(pass1_patterns)

        if progress_cb:
            progress_cb(3, "Əlaqəli terminlər toplanır...")

        suggested_detail = self.collect_suggested_terms_detailed(related_pids, [], pass1_terms)
        chain_terms = [x["term"] for x in suggested_detail]
        pass2_terms = self._dedupe_terms(pass1_terms + chain_terms)

        final_patterns = compile_term_patterns(pass2_terms)
        related_pids, _, descendants_only, depth_by_pid = self.build_related_pid_set(final_patterns)

        if progress_cb:
            progress_cb(5, "Termin genişləndirilməsi tamamlanır...")

        pass3_suggested_detail = self.collect_suggested_terms_detailed(related_pids, [], pass2_terms)
        trusted_terms = [item["term"] for item in pass3_suggested_detail if item.get("trust_level") == "trusted"]
        moderate_terms = [item["term"] for item in pass3_suggested_detail if item.get("trust_level") == "moderate"]
        if len(trusted_terms) + len(moderate_terms) >= 3:
            trusted_patterns = compile_term_patterns(self._dedupe_terms(pass2_terms + trusted_terms))
            moderate_patterns = compile_term_patterns(self._dedupe_terms(moderate_terms), mode_filter={"substring"})
            final_patterns = merge_term_patterns(trusted_patterns, moderate_patterns)
            related_pids, _, descendants_only, depth_by_pid = self.build_related_pid_set(final_patterns)

        if progress_cb:
            progress_cb(7, "Yol mənbə indeksi qurulur...")

        session_start, session_end = self._build_session_time_window(related_pids)
        self._build_path_provenance_index(
            related_pids,
            cancel_cb=cancel_cb,
            progress_cb=lambda pct, txt: progress_cb(7 + min(7, int(pct * 8 / 100)), txt) if progress_cb else None,
        )

        grouped: Dict[Tuple[str, str], List[ProcmonEvent]] = defaultdict(list)
        group_display_path: Dict[Tuple[str, str], str] = {}
        created_dirs_by_chain: Set[str] = set()

        if progress_cb:
            progress_cb(15, "Əlaqəli yollar müəyyən edilir...")

        related_parent_dirs: Set[str] = set()
        related_parent_reg: Set[str] = set()
        for pid in related_pids:
            for ev in self.by_pid.get(pid, []):
                if not ev.path:
                    continue
                _, canon = self.canonical_artifact_key(ev.path)
                if any(canon.startswith(prefix) for prefix in REGISTRY_PREFIXES):
                    parent_reg = normalize_path(os.path.dirname(canon)).lower()
                    if parent_reg:
                        related_parent_reg.add(parent_reg)
                else:
                    parent_dir = normalize_path(os.path.dirname(canon)).lower()
                    if parent_dir:
                        related_parent_dirs.add(parent_dir)

        if progress_cb:
            progress_cb(16, "Hadisələr süzülür...")

        total_events = max(1, len(self.events))
        for idx, ev in enumerate(self.events, start=1):
            if cancel_cb and idx % 2000 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 5000 == 0:
                progress_cb(16 + min(23, int((idx / total_events) * 24)),
                            f"Hadisələr süzülür... {idx:,}/{total_events:,}")
            if not ev.path or ev.operation not in INTERESTING_OPERATIONS:
                continue

            canonical_key = self.canonical_artifact_key(ev.path)
            if not canonical_key[1]:
                continue
            lp = canonical_key[1]
            is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
            is_related_write = ev.pid is not None and ev.pid in related_pids and (ev.operation in RELATED_CHAIN_OPS or is_create_disposition)
            is_installer_path = lp.startswith(WINDOWS_INSTALLER_PREFIX)
            reg_sweep = any(lp.startswith(prefix) for prefix in REGISTRY_SWEEP_PREFIXES)
            path_hit = bool(token_hits(lp, final_patterns, allow_rot13=False))
            detail_hit = bool(token_hits(ev.detail or "", final_patterns, allow_rot13=any(lp.startswith(prefix) for prefix in USERASSIST_PREFIXES)))

            if is_related_write:
                grouped[canonical_key].append(ev)
                group_display_path.setdefault(canonical_key, ev.path)
                if ev.operation == "CreateDirectory" and ev.pid is not None and ev.pid in related_pids:
                    created_dirs_by_chain.add(canonical_key[1])
                continue

            if not (path_has_safe_prefix(ev.path) or is_installer_path or reg_sweep or path_hit or detail_hit):
                continue
            grouped[canonical_key].append(ev)
            group_display_path.setdefault(canonical_key, ev.path)

        if progress_cb:
            progress_cb(40, "GUID əlaqələri yoxlanılır...")

        related_guids = self._collect_related_guids(related_pids)
        self._expand_grouped_with_guid_hits(grouped, related_guids, group_display_path=group_display_path, cancel_cb=cancel_cb)

        if progress_cb:
            progress_cb(42, f"Qruplar analiz olunur... (0/{len(grouped):,})")

        results: List[ResidueCandidate] = []
        total_groups = max(1, len(grouped))
        for idx, (group_key, evs) in enumerate(grouped.items(), start=1):
            if cancel_cb and idx % 500 == 0 and cancel_cb():
                raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
            if progress_cb and idx % 200 == 0:
                progress_cb(42 + min(37, int((idx / total_groups) * 38)),
                            f"Qruplar analiz olunur... {idx:,}/{total_groups:,}")

            path = group_display_path.get(group_key, evs[0].path if evs else group_key[1])
            lp = group_key[1]
            raw_score = 0
            reasons: List[str] = []
            proc_set = sorted({e.process_name for e in evs if e.process_name})
            # BUG-4 fix: renamed op_set -> op_list (sorted() returns a list, not a set)
            op_list = sorted({e.operation for e in evs if e.operation})
            first_seen = evs[0].time_of_day
            last_seen = evs[-1].time_of_day

            path_weight = token_hit_weight(lp, final_patterns)
            path_token_terms = token_hit_terms(lp, final_patterns)
            detail_match = False
            write_count = 0
            facts = self.path_facts.get(group_key[1], {})
            writer_pids: Set[int] = set(facts.get("writer_pids", set()))
            first_writer_pid: Optional[int] = facts.get("first_writer_pid")
            last_writer_pid: Optional[int] = None
            first_creator_pid: Optional[int] = facts.get("first_creator_pid")
            touched_pids: Set[int] = set(facts.get("touched_pids", set()))
            related_write_count = int(facts.get("related_write_count", 0) or 0)
            non_related_write_count = int(facts.get("non_related_write_count", 0) or 0)
            created_flag = bool(facts.get("create_count", 0))
            modified_flag = False
            read_only = True
            non_related_writer_in_window = False
            location_proximity_hit = False

            for ev in evs:
                allow_rot13 = any(lp.startswith(prefix) for prefix in USERASSIST_PREFIXES)
                if token_hits(ev.detail or "", final_patterns, allow_rot13=allow_rot13):
                    detail_match = True
                is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
                is_write = ev.operation in WRITE_OPS or is_create_disposition
                if is_write:
                    read_only = False
                    write_count += 1
                    if ev.pid is not None:
                        last_writer_pid = ev.pid
                if ev.operation in WRITE_OPS or ev.operation in {"RegDeleteKey", "RegDeleteValue", "SetDispositionInformationFile"}:
                    modified_flag = True
                if session_start and session_end and ev.pid not in related_pids and is_write:
                    ev_dt = parse_procmon_time_to_dt(ev.time_of_day)
                    if ev_dt and session_start <= ev_dt <= session_end:
                        non_related_writer_in_window = True
                if session_start and session_end and is_write:
                    ev_dt = parse_procmon_time_to_dt(ev.time_of_day)
                    if ev_dt and session_start <= ev_dt <= session_end:
                        parent_ref = normalize_path(os.path.dirname(lp)).lower()
                        if any(lp.startswith(prefix) for prefix in ("c:\\users\\", "c:\\programdata\\", "hkcu\\software\\")) and (
                            parent_ref in related_parent_dirs or parent_ref in related_parent_reg
                        ):
                            location_proximity_hit = True

            is_prefetch_trace = "\\prefetch\\" in lp and lp.endswith(".pf")
            execution_trace_hit = (
                any(lp.startswith(prefix) for prefix in MUI_CACHE_PREFIXES)
                or any(lp.startswith(prefix) for prefix in BAM_PREFIXES)
                or any(lp.startswith(prefix) for prefix in USERASSIST_PREFIXES)
            ) and (path_weight > 0 or detail_match)

            if path_is_low_value(path):
                if is_prefetch_trace and path_weight > 0:
                    raw_score += self.config["traces"]["prefetch_trace"]
                    reasons.append("prefetch execution trace")
                elif execution_trace_hit:
                    raw_score += self.config["traces"]["execution_trace"]
                    reasons.append("execution trace hit")
                else:
                    raw_score += self.config["penalties"]["low_value_area"]
                    reasons.append("low-value system area")

            if path_token_terms:
                base_add = self.config["match_scores"]["path_match_base"]
                weighted_add = int(base_add * path_weight)
                extra_max = self.config["match_scores"]["path_extra_max"]
                extra_per = self.config["match_scores"]["path_extra_per_term"]
                add = weighted_add + min(extra_max, max(0, len(path_token_terms) - 1) * extra_per)
                raw_score += add
                reasons.append(f"path match: {', '.join(path_token_terms[:4])}")

            if detail_match:
                raw_score += self.config["match_scores"]["detail_match"]
                reasons.append("token found in detail/value data")
                if any(lp.startswith(prefix) for prefix in USERASSIST_PREFIXES):
                    reasons.append("UserAssist ROT13 match (decoded)")

            if any(lp.startswith(prefix) for prefix in FIREWALL_RULES_PREFIXES) and any(token_hits(ev.detail or "", final_patterns) for ev in evs):
                raw_score += self.config["special"]["firewall_rule_reference"]
                reasons.append("firewall rule references target app")

            loc = self.config["location_scores"]
            if "\\appdata\\" in lp:
                raw_score += loc["appdata"]
            if lp.startswith("c:\\programdata\\"):
                raw_score += loc["programdata"]
            if lp.startswith("c:\\program files"):
                raw_score += loc["program_files"]
            if lp.startswith("hkcu\\software\\"):
                raw_score += loc["hkcu_software"]
            if "\\currentversion\\uninstall\\" in lp:
                raw_score += loc["uninstall_key"]
            if "\\currentversion\\run" in lp:
                raw_score += loc["current_version_run"]

            item_type = detect_item_type(path)
            cfg_persistence = self.config["persistence_bonus"]
            if item_type in cfg_persistence:
                raw_score += cfg_persistence[item_type]
                reasons.append(f"persistence type: {item_type}")

            if lp.startswith(WINDOWS_INSTALLER_PREFIX) and related_write_count > 0:
                raw_score += self.config["provenance"]["installer_cache_related"]
                reasons.append("windows installer cache touched by related chain")

            if any(guid in lp for guid in related_guids):
                raw_score += self.config["provenance"]["guid_correlation"]
                reasons.append("GUID/CLSID correlation from related chain")

            related_events = [ev for ev in evs if ev.pid is not None and ev.pid in related_pids]
            if related_events:
                first_pid_depth = 0
                first_hit = related_events[0]
                if first_hit.pid is not None:
                    first_pid_depth = depth_by_pid.get(first_hit.pid, 0)
                db = self.config["depth_boost"]
                depth_boost_val = db["depth_0_1"] if first_pid_depth <= 1 else db["depth_2_3"] if first_pid_depth <= 3 else db["depth_4_plus"]
                raw_score += depth_boost_val
                if first_hit.pid in descendants_only:
                    reasons.append(f"created by installer descendant PID {first_hit.pid} ({first_hit.process_name or '?'}) depth={first_pid_depth}")
                else:
                    reasons.append(f"direct chain: {first_hit.process_name or '?'} depth={first_pid_depth}")

            related_writer_count = sum(1 for pid in writer_pids if pid in related_pids)
            total_writer_count = max(1, len(writer_pids)) if writer_pids else 0
            subtree_class = "none"
            if touched_pids and all(pid in related_pids for pid in touched_pids) and writer_pids:
                subtree_class = "subtree_only"
            elif first_creator_pid is not None and first_creator_pid in related_pids:
                subtree_class = "subtree_first"
            elif writer_pids and (related_writer_count / total_writer_count) >= 0.7:
                subtree_class = "subtree_dominant"

            prov = self.config["provenance"]
            if first_creator_pid is not None and first_creator_pid in related_pids:
                raw_score += prov["first_creator_related"]
                reasons.append("object first created by related chain")
            elif first_writer_pid is not None and first_writer_pid in related_pids:
                raw_score += prov["first_writer_related"]
                reasons.append("object first written by related chain")

            if touched_pids and all(pid in related_pids for pid in touched_pids):
                raw_score += prov["exclusively_touched"]
                reasons.append("exclusively touched by related chain")

            if not path_token_terms and related_write_count > 0:
                raw_score += prov["written_by_chain_no_token"]
                reasons.append("written by chain without token")

            if related_write_count > 0 and non_related_write_count == 0:
                raw_score += prov["no_non_related_writes"]
                reasons.append("provenance: no non-related writes")

            helper_hit = any(
                normalize_proc_name(ev.process_name) in HELPER_PROCESSES and (bool(path_token_terms) or bool(token_hits(ev.detail or "", final_patterns)))
                for ev in evs
            )
            if helper_hit:
                raw_score += helper_boost
                reasons.append("helper-process correlation")

            act = self.config["activity"]
            if write_count == 0:
                raw_score += act["write_0"]
                reasons.append("only read/query activity")
            elif write_count <= 2:
                raw_score += act["write_1_2"]
            elif write_count <= 9:
                raw_score += act["write_3_9"]
            else:
                raw_score += act["write_10_plus"]

            if created_flag:
                raw_score += act["created"]
            if modified_flag:
                raw_score += act["modified"]
            if read_only:
                raw_score += act["read_only"]

            # BUG-3 fix: compute is_create_disposition per-event inside the loop
            for ev in evs:
                detail_kv = ev.detail_dict
                ev_is_create_disposition = ev.operation == "CreateFile" and CREATEFILE_CREATE_RE.search(ev.detail or "") is not None
                desired_access = detail_kv.get("Desired Access", "").lower()
                if ev.operation == "CreateFile" and desired_access and not ev_is_create_disposition:
                    if ("write" not in desired_access and "delete" not in desired_access
                            and "generic all" not in desired_access and "generic write" not in desired_access):
                        raw_score -= 10
                        reasons.append("read-only access (no write intent)")
                        break
                if ev.operation == "SetDispositionInformationFile":
                    if detail_kv.get("Delete", "").lower() == "true":
                        raw_score -= 15
                        reasons.append("object was deleted during session (Delete: True)")
                        break

            sess = self.config["session"]
            if non_related_writer_in_window:
                raw_score += sess["non_related_writer_window"]
                reasons.append("write occurred inside install session window")
            if location_proximity_hit:
                raw_score += sess["location_proximity"]
                reasons.append("session-window + location proximity to related subtree")

            if first_writer_pid is not None:
                reasons.append(f"first_writer={first_writer_pid}:{self.proc_names_by_pid.get(first_writer_pid, '?')}")
            if last_writer_pid is not None and last_writer_pid != first_writer_pid:
                reasons.append(f"last_writer={last_writer_pid}:{self.proc_names_by_pid.get(last_writer_pid, '?')}")

            pen = self.config["penalties"]
            if "microsoft" in lp and not path_token_terms:
                raw_score += pen["microsoft_path_no_token"]
            base_tokens = split_tokens(os.path.basename(path))
            if base_tokens and all(token in KNOWN_GENERIC_DIRS for token in base_tokens):
                raw_score += pen["generic_dir"]

            mapped = map_sandbox_user_path(path)
            exists_now = self._path_exists(mapped) if not path_looks_sandbox(path) or mapped != path else None
            if path_looks_sandbox(path) and mapped == path:
                reasons.append("sandbox path could not be mapped to current user")

            for src in self._resolve_full_rename_chain(path, reverse=True)[:2]:
                if src.lower() != path.lower():
                    reasons.append(f"renamed from {src}")
            chain_forward = self._resolve_full_rename_chain(path)
            if len(chain_forward) > 1:
                reasons.append("rename chain: " + " -> ".join(chain_forward[:4]))

            checked_only = (
                bool(op_list)
                and all(op in QUERY_ONLY_OPS for op in op_list)
                and write_count == 0
                and first_creator_pid is None
                and first_writer_pid is None
                and (bool(path_token_terms) or detail_match or bool(related_events))
            )
            if checked_only:
                raw_score += self.config["special"]["checked_only_residue"]
                reasons.append("checked-only residue: installer observed preexisting artifact")

            candidate = ResidueCandidate(
                type=item_type,
                path=path,
                mapped_path=mapped,
                raw_score=raw_score,
                score=max(0, min(raw_score, 100)),
                reasons=self._unique_compact(reasons),
                first_seen=first_seen,
                last_seen=last_seen,
                processes=proc_set,
                operations=op_list,
                exists_now=exists_now,
                status=self._status_from_score(raw_score, exists_now, subtree_class, checked_only=checked_only),
                category=category_from_type(item_type),
                cluster=cluster_from_path(path),
                subtree_class=subtree_class,
            )
            if raw_score >= 10:
                results.append(candidate)

        if progress_cb:
            progress_cb(80, "Rename variantları yoxlanılır...")
        results = self._add_rename_dest_candidates(results)

        if progress_cb:
            progress_cb(82, "Ana qovluq namizədləri əlavə olunur...")
        results = self._add_parent_directory_candidates(results, created_dirs_by_chain)

        if progress_cb:
            progress_cb(84, "Vendor ailəsi yoxlanılır...")
        results = self._proactive_vendor_family_sweep(results)

        if progress_cb:
            progress_cb(86, "Təsdiqlənmiş köklərdən genişlənmə...")
        results = self._flood_fill_from_confirmed_roots(results, created_dirs_by_chain)

        if progress_cb:
            progress_cb(90, "Fayl metadata-sı yoxlanılır...")
        if enrich_file_metadata:
            self._enrich_candidates_with_file_metadata(results, final_patterns)

        if progress_cb:
            progress_cb(95, "Klasterlər təyin olunur...")
        # Installer/family IDs must be assigned before cluster bonus.
        self._assign_installer_clusters(results)
        self._assign_family_clusters(results)
        self._apply_cluster_bonus(results)
        results = self._merge_by_mapped_path(results)
        self._assign_removal_layers(results)

        if progress_cb:
            progress_cb(99, "Nəticələr sıralanır...")
        results.sort(key=lambda x: (x.raw_score, x.exists_now is True), reverse=True)
        return results

    @staticmethod
    def _dedupe_terms(terms: List[str]) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()
        for term in terms:
            key = (term or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    def _resolve_full_rename_chain(self, path: str, reverse: bool = False) -> List[str]:
        current = self._canonical_path(path)
        visited: Set[str] = set()
        chain: List[str] = [normalize_path(path)]
        while current and current not in visited:
            visited.add(current)
            if reverse:
                prevs = sorted(self.rename_reverse_map.get(current, set()))
                if not prevs:
                    break
                nxt = prevs[0]
            else:
                nxt = self.rename_map.get(current)
                if not nxt:
                    break
            chain.append(normalize_path(nxt))
            current = self._canonical_path(nxt)
        return chain

    @staticmethod
    def _extension_multiplier(path: str) -> float:
        lp = (path or "").lower()
        if lp.endswith((".config", ".json", ".xml", ".yaml", ".yml", ".ini", ".db", ".sqlite")):
            return 0.7
        if lp.endswith((".dll", ".exe")):
            return 0.6
        if lp.endswith((".log", ".cache", ".tmp")):
            return 0.5
        return 0.3

    def _build_candidate_from_path(
        self,
        path: str,
        raw_score: int,
        reason: str,
        first_seen: str,
        last_seen: str,
        processes: List[str],
        operations: List[str],
    ) -> ResidueCandidate:
        mapped = map_sandbox_user_path(path)
        exists_now = self._path_exists(mapped)
        item_type = detect_item_type(path)
        return ResidueCandidate(
            type=item_type,
            path=path,
            mapped_path=mapped,
            raw_score=raw_score,
            score=max(0, min(raw_score, 100)),
            reasons=self._unique_compact([reason]),
            first_seen=first_seen,
            last_seen=last_seen,
            processes=processes,
            operations=operations,
            exists_now=exists_now,
            status=self._status_from_score(raw_score, exists_now),
            category=category_from_type(item_type),
            cluster=cluster_from_path(path),
            removal_layer=self._removal_layer_from_candidate(category_from_type(item_type), self._status_from_score(raw_score, exists_now), reason),
        )

    def _registry_to_winreg_root(self, path: str) -> Tuple[Optional[int], str]:
        raw = (path or "")
        if "\\" not in raw:
            return None, ""
        root_name, sub = raw.split("\\", 1)
        mapping = {
            "HKCU": winreg.HKEY_CURRENT_USER if os.name == "nt" else None,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER if os.name == "nt" else None,
            "HKLM": winreg.HKEY_LOCAL_MACHINE if os.name == "nt" else None,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE if os.name == "nt" else None,
            "HKCR": winreg.HKEY_CLASSES_ROOT if os.name == "nt" else None,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT if os.name == "nt" else None,
            "HKU": winreg.HKEY_USERS if os.name == "nt" else None,
            "HKEY_USERS": winreg.HKEY_USERS if os.name == "nt" else None,
        }
        return mapping.get(root_name.upper()), sub

    def _enumerate_registry_branch(self, root_path: str, max_items: int = 600) -> List[str]:
        if os.name != "nt":
            return []
        root, sub = self._registry_to_winreg_root(root_path)
        if root is None or not sub:
            return []
        out: List[str] = []
        skipped_access_denied: List[str] = []  # CODE-4: track access-denied paths
        queue = deque([sub])
        visited: Set[str] = set()
        while queue and len(out) < max_items:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            full = f"{root_path.split(chr(92), 1)[0]}\\{current}"
            out.append(full)
            try:
                with winreg.OpenKey(root, current) as key:
                    idx = 0
                    while True:
                        try:
                            value_name, _, _ = winreg.EnumValue(key, idx)
                            out.append(f"{full}\\{value_name}")
                            idx += 1
                            if len(out) >= max_items:
                                break
                        except OSError:
                            break
                    cidx = 0
                    while True:
                        try:
                            child = winreg.EnumKey(key, cidx)
                            queue.append(f"{current}\\{child}")
                            cidx += 1
                        except OSError:
                            break
            except OSError as exc:
                # CODE-4 fix: log access-denied paths separately from not-found
                if getattr(exc, "winerror", None) == 5:  # ERROR_ACCESS_DENIED
                    skipped_access_denied.append(full)
                continue
        return out

    @staticmethod
    def _derive_vendor_root(path: str) -> str:
        p = normalize_path(path)
        parts = [x for x in p.split("\\") if x]
        if len(parts) < 3:
            return ""
        if parts[0].lower().endswith(":") and parts[1].lower() in {"programdata", "program files", "program files (x86)", "users"}:
            if parts[1].lower() == "users" and len(parts) >= 4:
                # LOGIC-5 fix: Only treat Users paths with AppData as vendor roots
                if len(parts) >= 5 and parts[3].lower() == "appdata":
                    return "\\".join(parts[:6]) if len(parts) >= 6 else "\\".join(parts[:5])
                # For other Users paths, return dirname instead
                return normalize_path(os.path.dirname(path))
            return "\\".join(parts[:3])
        return normalize_path(os.path.dirname(path))

    def _mirror_vendor_roots(self, vendor_root: str) -> List[str]:
        root = normalize_path(vendor_root)
        if not root:
            return []
        parts = [x for x in root.split("\\") if x]
        if len(parts) < 3:
            return [root]
        drive = parts[0]
        second = parts[1].lower()
        out: Set[str] = {root}

        # LOGIC-6 fix: handle Users path separately BEFORE setting vendor from parts[2]
        if second == "users" and len(parts) >= 5:
            user_name = parts[2]  # e.g. "John"
            # parts[3] = AppData, parts[4] = Local/Roaming, parts[5] = vendor
            vendor_name = parts[5] if parts[4].lower() in {"roaming", "local"} and len(parts) > 5 else parts[4]
            user_base = f"{drive}\\Users\\{user_name}"
            out.add(f"{user_base}\\AppData\\Roaming\\{vendor_name}")
            out.add(f"{user_base}\\AppData\\Local\\{vendor_name}")
            out.add(f"{drive}\\ProgramData\\{vendor_name}")
            out.add(f"{drive}\\Program Files\\{vendor_name}")
            out.add(f"{drive}\\Program Files (x86)\\{vendor_name}")
        else:
            vendor = parts[2]  # e.g. "VendorApp" under ProgramData / Program Files
            out.add(f"{drive}\\ProgramData\\{vendor}")
            out.add(f"{drive}\\Program Files\\{vendor}")
            out.add(f"{drive}\\Program Files (x86)\\{vendor}")
            users_root = f"{drive}\\Users"
            if os.path.isdir(users_root):
                try:
                    for user in os.listdir(users_root):
                        user_base = f"{users_root}\\{user}"
                        out.add(f"{user_base}\\AppData\\Roaming\\{vendor}")
                        out.add(f"{user_base}\\AppData\\Local\\{vendor}")
                except OSError:
                    pass
        return sorted({normalize_path(x) for x in out if x})

    @staticmethod
    def _walk_with_generic_reset(base_dir: str, max_depth: int = 4):
        """Walk directory tree respecting max_depth, with a grace extension for generic dirs.
        CODE-5 fix: cap extension to max 2 extra levels to prevent runaway recursion."""
        for root, dirs, files in os.walk(base_dir):
            rel = root[len(base_dir):].lstrip(os.sep)
            parts = [p for p in rel.split(os.sep) if p]
            depth = len(parts)
            if depth >= max_depth:
                generic_indices = [i for i, part in enumerate(parts) if part.lower() in KNOWN_GENERIC_DIRS]
                if generic_indices:
                    # Only extend past max_depth by at most 2 levels after the last generic dir
                    depth_after_generic = depth - (generic_indices[-1] + 1)
                    if depth_after_generic >= 2:  # was: max_depth (too permissive)
                        dirs[:] = []
                else:
                    dirs[:] = []
            yield root, dirs, files

    @staticmethod
    def _extract_vendor_token(path: str) -> str:
        parts = [p for p in normalize_path(path).split("\\") if p]
        if len(parts) >= 3 and parts[0].endswith(":") and parts[1].lower() in {"programdata", "program files", "program files (x86)"}:
            return parts[2].lower()
        if len(parts) >= 6 and parts[0].endswith(":") and parts[1].lower() == "users" and parts[3].lower() == "appdata":
            return parts[5].lower() if parts[4].lower() in {"roaming", "local"} and len(parts) > 5 else parts[4].lower()
        return ""

    def _proactive_vendor_family_sweep(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        vendor_tokens: Set[str] = set()
        for candidate in candidates:
            token = self._extract_vendor_token(candidate.path)
            if token and token not in STOP_WORDS:
                vendor_tokens.add(token)

        users_root = "C:\\Users"
        for vendor in sorted(vendor_tokens):
            probe_paths = {
                f"C:\\ProgramData\\{vendor}",
                f"C:\\Program Files\\{vendor}",
                f"C:\\Program Files (x86)\\{vendor}",
            }
            if os.path.isdir(users_root):
                try:
                    for user in os.listdir(users_root):
                        probe_paths.add(f"{users_root}\\{user}\\AppData\\Roaming\\{vendor}")
                        probe_paths.add(f"{users_root}\\{user}\\AppData\\Local\\{vendor}")
                        probe_paths.add(f"{users_root}\\{user}\\AppData\\Local\\Programs\\{vendor}")
                except OSError:
                    pass

            for path in probe_paths:
                normalized = normalize_path(path)
                if not os.path.isdir(normalized):
                    continue
                key = ("dir", normalized.lower())
                if key in seen:
                    continue
                raw_score = 45
                candidate = self._build_candidate_from_path(
                    normalized,
                    raw_score,
                    f"vendor family proactive sweep: {vendor}",
                    "",
                    "",
                    [],
                    ["VendorFamilySweep"],
                )
                out.append(candidate)
                seen.add(key)
        return out

    def _flood_fill_from_confirmed_roots(
        self,
        candidates: List[ResidueCandidate],
        created_dirs_by_chain: Set[str],
        max_iterations: int = 3,
    ) -> List[ResidueCandidate]:
        out = list(candidates)
        for _ in range(max_iterations):
            before = len(out)
            out = self._expand_confirmed_root_clusters(out)
            out = self._expand_neighborhood(out)
            out = self._expand_survivors(out)
            out = self._expand_confirmed_registry_branches(out)
            out = self._expand_siblings(out)
            out = self._add_parent_directory_candidates(out, created_dirs_by_chain)
            if len(out) == before:
                break
        return out

    def _expand_confirmed_root_clusters(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        by_path = {(c.mapped_path or c.path).lower(): c for c in out if (c.mapped_path or c.path)}
        queue = deque([c for c in out if c.raw_score >= 80])
        visited: Set[str] = set()
        while queue:
            root = queue.popleft()
            root_key = (root.mapped_path or root.path).lower()
            if root_key in visited:
                continue
            visited.add(root_key)
            for cand in list(out):
                if cand is root:
                    continue
                related = False
                if root.vendor_family_id and cand.vendor_family_id == root.vendor_family_id:
                    related = True
                if root.service_branch_id and cand.service_branch_id == root.service_branch_id:
                    related = True
                if root.rename_family_id and cand.rename_family_id == root.rename_family_id:
                    related = True
                if root.installer_cluster_id and cand.installer_cluster_id == root.installer_cluster_id:
                    related = True
                if not related:
                    continue
                if cand.raw_score < 70:
                    cand.raw_score = min(100, cand.raw_score + 20)
                    cand.score = max(0, min(cand.raw_score, 100))
                    cand.reasons = self._unique_compact(cand.reasons + ["confirmed root cluster flood-fill"])
                    cand.status = self._status_from_score(cand.raw_score, cand.exists_now, cand.subtree_class)
            vendor_root = self._derive_vendor_root(root.mapped_path or root.path)
            for mirror in self._mirror_vendor_roots(vendor_root):
                m = normalize_path(mirror)
                key = m.lower()
                if not m or key in by_path:
                    continue
                if not os.path.exists(m):
                    continue
                new_candidate = self._build_candidate_from_path(
                    m,
                    55,
                    "mirrored root from confirmed cluster",
                    root.first_seen,
                    root.last_seen,
                    root.processes,
                    ["ConfirmedRootMirror"],
                )
                out.append(new_candidate)
                by_path[key] = new_candidate
                queue.append(new_candidate)
        return out

    def _expand_neighborhood(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}

        # PERF-1 fix: build a prefix-based index of events by registry path prefix
        # to avoid full O(n) scan for every reg_key candidate
        reg_events_by_prefix: Dict[str, List] = defaultdict(list)
        for ev in self.events:
            if ev.path and ev.path.lower().startswith(REGISTRY_PREFIXES):
                lp = ev.path.lower()
                prefix = lp[:64]  # bucket by first 64 chars
                # Extract the registry root prefix for better matching
                root_end = lp.find("\\", 5)
                if root_end > 0:
                    prefix_key = lp[:root_end + 1]
                else:
                    prefix_key = prefix
                reg_events_by_prefix[prefix_key].append(ev)

        for candidate in list(candidates):
            if candidate.raw_score < 55:
                continue
            if candidate.exists_now is not True:
                continue
            if candidate.type == "reg_key":
                parent = normalize_path(os.path.dirname(candidate.path))
                if parent:
                    parent_lower = parent.lower()
                    # Use the prefix index to find matching events efficiently
                    matching_events = []
                    for prefix_key, evs in reg_events_by_prefix.items():
                        if parent_lower.startswith(prefix_key):
                            matching_events.extend(evs)
                    
                    for ev in matching_events:
                        if not ev.path or not ev.path.lower().startswith(parent_lower):
                            continue
                        t = detect_item_type(ev.path)
                        mapped = map_sandbox_user_path(ev.path)
                        key = (t, mapped.lower())
                        if key in seen:
                            continue
                        raw_score = max(30, candidate.raw_score // 2)
                        new_item = self._build_candidate_from_path(
                            ev.path,
                            raw_score,
                            f"neighborhood of confirmed residue: {parent}",
                            ev.time_of_day,
                            ev.time_of_day,
                            [ev.process_name] if ev.process_name else [],
                            [ev.operation] if ev.operation else [],
                        )
                        out.append(new_item)
                        seen.add(key)
                continue
            if candidate.type not in {"dir", "file", "config", "database", "cache", "log", "binary"}:
                continue
            root_dir = candidate.mapped_path if candidate.type == "dir" else os.path.dirname(candidate.mapped_path)
            if not root_dir:
                continue
            vendor_root = self._derive_vendor_root(root_dir)
            scan_roots = self._mirror_vendor_roots(vendor_root) if vendor_root else [root_dir]
            for scan_root in scan_roots:
                if not os.path.isdir(scan_root):
                    continue
                for base, dirs, files in self._walk_with_generic_reset(scan_root, max_depth=4):
                    for name in files:
                        fp = normalize_path(os.path.join(base, name))
                        # Skip trusted-signed system files (Təklif 3)
                        if is_trusted_signed(fp):
                            continue
                        t = detect_item_type(fp)
                        key = (t, fp.lower())
                        if key in seen:
                            continue
                        mult = self._extension_multiplier(fp)
                        raw_score = max(30, int(candidate.raw_score * mult))
                        new_item = self._build_candidate_from_path(
                            fp,
                            raw_score,
                            f"neighborhood of confirmed residue: {scan_root}",
                            candidate.first_seen,
                            candidate.last_seen,
                            candidate.processes,
                            ["NeighborhoodScan"],
                        )
                        out.append(new_item)
                        seen.add(key)
        return out

    def _expand_survivors(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        for candidate in list(candidates):
            if candidate.exists_now is not True or candidate.raw_score < 55:
                continue
            if candidate.type in {"dir", "file", "config", "database", "cache", "log", "binary"}:
                base_dir = candidate.mapped_path if candidate.type == "dir" else os.path.dirname(candidate.mapped_path)
                if not base_dir:
                    continue
                vendor_root = self._derive_vendor_root(base_dir)
                scan_roots = self._mirror_vendor_roots(vendor_root) if vendor_root else [base_dir]
                for scan_root in scan_roots:
                    if not os.path.isdir(scan_root):
                        continue
                    for root, dirs, files in self._walk_with_generic_reset(scan_root, max_depth=4):
                        for fname in files:
                            fp = normalize_path(os.path.join(root, fname))
                            # Skip trusted-signed system files (Təklif 3)
                            if is_trusted_signed(fp):
                                continue
                            t = detect_item_type(fp)
                            key = (t, fp.lower())
                            if key in seen:
                                continue
                            raw_score = max(30, int(candidate.raw_score * self._extension_multiplier(fp)))
                            out.append(
                                self._build_candidate_from_path(
                                    fp,
                                    raw_score,
                                    f"live survivor expansion: {scan_root}",
                                    candidate.first_seen,
                                    candidate.last_seen,
                                    candidate.processes,
                                    ["SurvivorScan"],
                                )
                            )
                            seen.add(key)
            elif candidate.type == "reg_key":
                for reg_path in self._enumerate_registry_branch(candidate.path):
                    t = detect_item_type(reg_path)
                    mapped = map_sandbox_user_path(reg_path)
                    key = (t, mapped.lower())
                    if key in seen:
                        continue
                    raw_score = max(30, int(candidate.raw_score * 0.5))
                    out.append(
                        self._build_candidate_from_path(
                            reg_path,
                            raw_score,
                            f"live survivor expansion: {candidate.path}",
                            candidate.first_seen,
                            candidate.last_seen,
                            candidate.processes,
                            ["RegistrySurvivorScan"],
                        )
                    )
                    seen.add(key)
        return out

    def _expand_confirmed_registry_branches(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        for candidate in list(candidates):
            if candidate.raw_score < 50:
                continue
            if candidate.type not in {"reg_key", "service", "run_entry", "clsid", "typelib", "context_menu", "shell_extension", "protocol_handler"}:
                continue
            lp = (candidate.path or "").lower()
            if not any(lp.startswith(prefix) for prefix in REGISTRY_PREFIXES):
                continue
            max_items = 600
            for marker, limit in REGISTRY_EXPANSION_LIMITS.items():
                if marker in lp:
                    max_items = limit
                    break
            for reg_path in self._enumerate_registry_branch(candidate.path, max_items=max_items):
                item_type = detect_item_type(reg_path)
                mapped = map_sandbox_user_path(reg_path)
                key = (item_type, mapped.lower())
                if key in seen:
                    continue
                raw_score = max(35, int(candidate.raw_score * 0.55))
                out.append(
                    self._build_candidate_from_path(
                        reg_path,
                        raw_score,
                        f"registry branch sweep from confirmed residue: {candidate.path}",
                        candidate.first_seen,
                        candidate.last_seen,
                        candidate.processes,
                        ["RegistryBranchSweep"],
                    )
                )
                seen.add(key)
        return out

    def _expand_siblings(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        out = list(candidates)
        seen = {(c.type, (c.mapped_path or c.path).lower()) for c in out if (c.mapped_path or c.path)}
        for candidate in list(candidates):
            if candidate.raw_score < 40:
                continue
            if candidate.type in {"file", "config", "database", "cache", "log", "binary", "shortcut"} and candidate.exists_now is True:
                folder = os.path.dirname(candidate.mapped_path)
                base = os.path.splitext(os.path.basename(candidate.mapped_path))[0].lower()
                if not folder or not base or not os.path.isdir(folder):
                    continue
                try:
                    for name in os.listdir(folder):
                        if not name.lower().startswith(base + "."):
                            continue
                        fp = normalize_path(os.path.join(folder, name))
                        t = detect_item_type(fp)
                        key = (t, fp.lower())
                        if key in seen:
                            continue
                        raw_score = max(30, int(candidate.raw_score * 0.5))
                        out.append(
                            self._build_candidate_from_path(
                                fp,
                                raw_score,
                                f"sibling of confirmed residue: {candidate.mapped_path}",
                                candidate.first_seen,
                                candidate.last_seen,
                                candidate.processes,
                                ["SiblingScan"],
                            )
                        )
                        seen.add(key)
                except OSError:
                    continue
            elif candidate.type in {"reg_key", "service", "run_entry", "clsid", "typelib", "context_menu", "shell_extension", "protocol_handler", "file_association", "firewall_rule"}:
                parent = normalize_path(os.path.dirname(candidate.path))
                if not parent:
                    continue
                for reg_path in self._enumerate_registry_branch(parent, max_items=200):
                    t = detect_item_type(reg_path)
                    mapped = map_sandbox_user_path(reg_path)
                    key = (t, mapped.lower())
                    if key in seen:
                        continue
                    raw_score = max(30, int(candidate.raw_score * 0.5))
                    out.append(
                        self._build_candidate_from_path(
                            reg_path,
                            raw_score,
                            f"sibling of confirmed residue: {candidate.path}",
                            candidate.first_seen,
                            candidate.last_seen,
                            candidate.processes,
                            ["RegistrySiblingScan"],
                        )
                    )
                    seen.add(key)
        return out

    def _assign_family_clusters(self, candidates: List[ResidueCandidate]) -> None:
        for candidate in candidates:
            vendor_token = self._extract_vendor_token(candidate.path)
            if vendor_token and vendor_token not in STOP_WORDS:
                candidate.vendor_family_id = vendor_token

            lp = (candidate.path or "").lower()
            if "\\services\\" in lp:
                candidate.service_branch_id = lp.split("\\services\\", 1)[0] + "\\services\\"

            candidate.root_family_id = candidate.vendor_family_id or candidate.service_branch_id or candidate.rename_family_id or candidate.installer_cluster_id

    def _apply_cluster_bonus(self, candidates: List[ResidueCandidate]) -> None:
        clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        installer_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        vendor_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        service_branch_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        rename_family_clusters: Dict[str, List[ResidueCandidate]] = defaultdict(list)
        membership: Dict[int, Set[str]] = defaultdict(set)
        for candidate in candidates:
            parent = os.path.dirname((candidate.mapped_path or candidate.path))
            if candidate.type == "reg_key":
                parent = os.path.dirname(candidate.path)
            if parent:
                clusters[parent.lower()].append(candidate)
            if candidate.installer_cluster_id:
                installer_clusters[candidate.installer_cluster_id.lower()].append(candidate)
            if candidate.rename_family_id:
                rename_family_clusters[candidate.rename_family_id.lower()].append(candidate)
            if candidate.vendor_family_id:
                vendor_clusters[candidate.vendor_family_id.lower()].append(candidate)
            if candidate.service_branch_id:
                service_branch_clusters[candidate.service_branch_id.lower()].append(candidate)

        def apply_bonus(items: List[ResidueCandidate], reason_label: str):
            count = len(items)
            if count < 4:
                return
            cb = self.config["cluster_bonus"]
            bonus = cb["threshold_4"]
            if count >= 10:
                bonus = cb["threshold_10"]
            elif count >= 7:
                bonus = cb["threshold_7"]
            for item in items:
                item.raw_score += bonus
                item.score = max(0, min(item.raw_score, 100))
                item.reasons = self._unique_compact(item.reasons + [f"cluster bonus: {count} items in {reason_label}"])
                item.status = self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                membership[id(item)].add(reason_label)

        for _, items in clusters.items():
            apply_bonus(items, "same directory/branch")
        for _, items in installer_clusters.items():
            apply_bonus(items, "installer cluster")
        for token, items in vendor_clusters.items():
            apply_bonus(items, f"vendor family '{token}'")
        for _, items in service_branch_clusters.items():
            apply_bonus(items, "service registry branch")
        for _, items in rename_family_clusters.items():
            apply_bonus(items, "rename family")

        for item in candidates:
            if item.subtree_class in {"subtree_only", "subtree_first"}:
                item.raw_score += self.config["subtree"]["subtree_only_or_first_bonus"]
                item.score = max(0, min(item.raw_score, 100))
                item.reasons = self._unique_compact(item.reasons + [f"subtree bonus: {item.subtree_class}"])
                item.status = self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                membership[id(item)].add("subtree")

        fus = self.config["fusion"]
        for item in candidates:
            kinds = membership.get(id(item), set())
            item.cluster_membership_count = len(kinds)
            if len(kinds) >= 4:
                item.raw_score += fus["types_4_bonus"]
                item.status = "safe_to_delete" if item.exists_now is True else self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                item.reasons = self._unique_compact(item.reasons + [f"multi-evidence fusion: {len(kinds)} cluster types"])
            elif len(kinds) >= 3:
                item.raw_score += fus["types_3_bonus"]
                item.status = self._status_from_score(item.raw_score, item.exists_now, item.subtree_class)
                item.reasons = self._unique_compact(item.reasons + [f"multi-evidence fusion: {len(kinds)} cluster types"])
            item.score = max(0, min(item.raw_score, 100))

    def _status_from_score(
        self,
        raw_score: int,
        exists_now: Optional[bool],
        subtree_class: str = "none",
        checked_only: bool = False,
    ) -> str:
        if checked_only:
            if exists_now is False:
                return "already_gone"
            return "checked_only"
        cfg_t = self.config["thresholds"]
        safe_threshold = cfg_t["safe_delete"]
        review_threshold = cfg_t["review"]
        if subtree_class == "subtree_only":
            safe_threshold -= 10
            review_threshold -= 10
        if raw_score >= safe_threshold:
            if exists_now is True:
                return "safe_to_delete"
            if exists_now is False:
                return "already_gone"
            return "review"
        if raw_score >= review_threshold:
            if exists_now is False:
                return "already_gone"
            return "review"
        return "ignore"

    def _build_session_time_window(self, related_pids: Set[int]) -> Tuple[Optional[datetime], Optional[datetime]]:
        starts: List[datetime] = []
        ends: List[datetime] = []
        for pid in related_pids:
            info = self.process_info_by_pid.get(pid)
            if not info:
                continue
            start_dt = parse_procmon_time_to_dt(info.start_time)
            end_dt = parse_procmon_time_to_dt(info.end_time)
            if start_dt:
                starts.append(start_dt)
            if end_dt:
                ends.append(end_dt)
            elif start_dt:
                ends.append(start_dt)
        if not starts:
            return None, None
        return min(starts), max(ends) if ends else max(starts)

    def _add_rename_dest_candidates(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        by_path = {self._canonical_path(c.path): c for c in candidates if self._canonical_path(c.path)}
        out = list(candidates)
        rename_context: Dict[str, Tuple[Optional[int], str, str]] = {}
        rename_family_by_path: Dict[str, str] = {}
        for src, dst, pid, t in self.rename_edges:
            src_k = self._canonical_path(src)
            dst_k = self._canonical_path(dst)
            rename_context[src_k] = (pid, t, normalize_path(os.path.dirname(src)).lower())
            rename_context[dst_k] = (pid, t, normalize_path(os.path.dirname(dst)).lower())

        for src in self.rename_map:
            chain = self._resolve_full_rename_chain(src)
            if not chain:
                continue
            family_id = hashlib.md5(chain[0].lower().encode("utf-8")).hexdigest()[:12]
            for item in chain:
                rename_family_by_path[self._canonical_path(item)] = family_id

        for candidate in out:
            family = rename_family_by_path.get(self._canonical_path(candidate.path))
            if family:
                candidate.rename_family_id = family

        def add_candidate_from_chain(base: ResidueCandidate, chain_item: str, step_idx: int, total_steps: int, reason: str):
            key = self._canonical_path(chain_item)
            if key in by_path:
                return
            mapped = map_sandbox_user_path(chain_item)
            exists_now = self._path_exists(mapped)
            raw_score = max(40, base.raw_score - (step_idx * 5))
            family_id = rename_family_by_path.get(key) or base.rename_family_id
            cand = ResidueCandidate(
                type=detect_item_type(chain_item),
                path=chain_item,
                mapped_path=mapped,
                raw_score=raw_score,
                score=max(0, min(raw_score, 100)),
                reasons=self._unique_compact(base.reasons + [reason, f"rename chain step {step_idx}/{total_steps}"]),
                first_seen=base.first_seen,
                last_seen=base.last_seen,
                processes=base.processes,
                operations=sorted(set(base.operations) | {"SetRenameInformationFile"}),
                exists_now=exists_now,
                status=self._status_from_score(raw_score, exists_now),
                category=category_from_type(detect_item_type(chain_item)),
                cluster=cluster_from_path(chain_item),
                rename_family_id=family_id,
            )
            out.append(cand)
            by_path[key] = cand

        def add_parent_dir(base: ResidueCandidate, item_path: str):
            parent = normalize_path(os.path.dirname(item_path))
            key = self._canonical_path(parent)
            if not parent or key in by_path:
                return
            mapped = map_sandbox_user_path(parent)
            exists_now = self._path_exists(mapped)
            raw_score = max(30, base.raw_score - 15)
            family_id = rename_family_by_path.get(self._canonical_path(item_path)) or base.rename_family_id
            cand = ResidueCandidate(
                type="dir",
                path=parent,
                mapped_path=mapped,
                raw_score=raw_score,
                score=max(0, min(raw_score, 100)),
                reasons=self._unique_compact(base.reasons + [f"rename chain parent directory: {parent}"]),
                first_seen=base.first_seen,
                last_seen=base.last_seen,
                processes=base.processes,
                operations=sorted(set(base.operations) | {"SetRenameInformationFile"}),
                exists_now=exists_now,
                status=self._status_from_score(raw_score, exists_now),
                category=category_from_type("dir"),
                cluster=cluster_from_path(parent),
                rename_family_id=family_id,
            )
            out.append(cand)
            by_path[key] = cand

        for source_lc, dest in self.rename_map.items():
            src = by_path.get(self._canonical_path(source_lc))
            if not src:
                continue
            chain = self._resolve_full_rename_chain(src.path)
            total_steps = max(1, len(chain) - 1)
            for step_idx, chain_item in enumerate(chain[1:], start=1):
                add_candidate_from_chain(src, chain_item, step_idx, total_steps, f"renamed from {src.path}")
                add_parent_dir(src, chain_item)

        for candidate in list(out):
            reverse_chain = self._resolve_full_rename_chain(candidate.path, reverse=True)
            if len(reverse_chain) <= 1:
                continue
            total_steps = max(1, len(reverse_chain) - 1)
            for step_idx, source_path in enumerate(reverse_chain[1:], start=1):
                add_candidate_from_chain(candidate, source_path, step_idx, total_steps, f"renamed to {candidate.path}")
                add_parent_dir(candidate, source_path)

        # LOGIC-4 fix: instead of O(n*m), group write events by PID and by parent dir
        # so we only look at events that are plausibly near each rename context path.
        # Build two indexes: pid -> [events], parent_dir -> [events]
        write_events_by_pid: Dict[Optional[int], List] = defaultdict(list)
        write_events_by_parent: Dict[str, List] = defaultdict(list)
        for ev in self.events:
            if ev.path and (ev.operation in WRITE_OPS or ev.operation == "CreateFile"):
                write_events_by_pid[ev.pid].append(ev)
                ev_par = normalize_path(os.path.dirname(ev.path)).lower()
                if ev_par:
                    write_events_by_parent[ev_par].append(ev)

        for path_lc, base in list(by_path.items()):
            if path_lc not in rename_context:
                continue
            pid, ts, base_parent = rename_context[path_lc]
            base_dt = parse_procmon_time_to_dt(ts)
            # Candidate events: same PID + same parent dir (union, deduped)
            candidate_evs: Dict[int, object] = {}
            if pid is not None:
                for ev in write_events_by_pid.get(pid, []):
                    candidate_evs[id(ev)] = ev
            if base_parent:
                for ev in write_events_by_parent.get(base_parent, []):
                    candidate_evs[id(ev)] = ev
            for ev in candidate_evs.values():
                ev_dt = parse_procmon_time_to_dt(ev.time_of_day)
                if base_dt and ev_dt:
                    window = 5.0 if (pid is not None and ev.pid == pid) else 3.0
                    if abs((ev_dt - base_dt).total_seconds()) > window:
                        continue
                key = self._canonical_path(ev.path)
                if key in by_path:
                    continue
                add_candidate_from_chain(base, ev.path, 1, 1, f"temporal sibling near rename by PID {pid}")
        return out

    def _add_parent_directory_candidates(self, candidates: List[ResidueCandidate], created_dirs_by_chain: Set[str]) -> List[ResidueCandidate]:
        existing = {(c.type, self._canonical_path(c.path)) for c in candidates}
        out = list(candidates)
        for candidate in list(candidates):
            parent = normalize_path(os.path.dirname(candidate.path))
            if not parent:
                continue
            key = ("dir", self._canonical_path(parent))
            if key in existing:
                continue
            if self._canonical_path(parent) not in created_dirs_by_chain:
                continue
            raw_score = 25
            mapped = map_sandbox_user_path(parent)
            exists_now = self._path_exists(mapped)
            out.append(
                ResidueCandidate(
                    type="dir",
                    path=parent,
                    mapped_path=mapped,
                    raw_score=raw_score,
                    score=max(0, min(raw_score, 100)),
                    reasons=self._unique_compact([f"parent directory of confirmed residue: {candidate.path}"]),
                    first_seen=candidate.first_seen,
                    last_seen=candidate.last_seen,
                    processes=candidate.processes,
                    operations=["CreateDirectory"],
                    exists_now=exists_now,
                    status=self._status_from_score(raw_score, exists_now),
                )
            )
            existing.add(key)
        return out

    def _enrich_candidates_with_file_metadata(
        self,
        candidates: List[ResidueCandidate],
        term_patterns: Dict[str, List[Tuple[str, re.Pattern[str], float]]],
    ) -> None:
        for candidate in candidates:
            if candidate.exists_now is not True:
                continue
            if candidate.type not in {"file", "binary"}:
                continue

            # Authenticode / trusted publisher check (Təklif 3)
            if is_trusted_signed(candidate.mapped_path):
                candidate.status = "ignore"
                candidate.raw_score = max(0, candidate.raw_score - 50)
                candidate.score = max(0, min(candidate.raw_score, 100))
                candidate.reasons = self._unique_compact(
                    candidate.reasons + ["PROTECTED: signed by trusted publisher"]
                )
                continue  # Never touch signed system files

            info = read_file_version_info(candidate.mapped_path)
            if not info:
                continue
            metadata_text = " ".join(v for v in [info.get("CompanyName", ""), info.get("ProductName", "")] if v)
            if not metadata_text:
                continue
            candidate.reasons = self._unique_compact(candidate.reasons + [f"metadata: {metadata_text}"])
            if token_hits(metadata_text, term_patterns):
                candidate.raw_score += 25
                candidate.score = max(0, min(candidate.raw_score, 100))
                candidate.status = self._status_from_score(candidate.raw_score, candidate.exists_now, candidate.subtree_class)

    def _assign_installer_clusters(self, candidates: List[ResidueCandidate]) -> None:
        for candidate in candidates:
            path_text = f"{candidate.path} {' '.join(candidate.reasons)}"
            match = GUID_RE.search(path_text)
            if match:
                candidate.installer_cluster_id = match.group(0).strip("{}").lower()
                continue
            lp = (candidate.path or "").lower()
            if candidate.category == "execution_trace":
                pf_match = re.search(r"\\([^\\]+)\.exe-[0-9a-f]+\.pf$", lp)
                if pf_match:
                    candidate.installer_cluster_id = pf_match.group(1).lower()
                    continue
                for token in split_tokens(lp):
                    if token not in STOP_WORDS:
                        candidate.installer_cluster_id = token
                        break
                if candidate.installer_cluster_id:
                    continue
            if "\\uninstall\\" in lp:
                parts = lp.split("\\uninstall\\", 1)
                if len(parts) > 1 and parts[1]:
                    candidate.installer_cluster_id = parts[1].split("\\")[0][:64]

    @staticmethod
    def _removal_layer_from_candidate(category: str, status: str, reason_blob: str) -> str:
        blob = (reason_blob or "").lower()
        if status == "safe_to_delete":
            return "confirmed_residue"
        if "live survivor expansion" in blob:
            return "live_survivor_expansion"
        if "neighborhood" in blob or "sibling of" in blob:
            return "aggressive_neighborhood"
        if status == "weak_but_related":
            return "weak_but_related"
        if category == "persistence":
            return "persistence_residue"
        if category == "installer_bookkeeping":
            return "installer_bookkeeping"
        if category == "execution_trace":
            return "execution_trace"
        if category == "user_data":
            return "user_data"
        return "review_queue"

    def _assign_removal_layers(self, candidates: List[ResidueCandidate]) -> None:
        for candidate in candidates:
            candidate.removal_layer = self._removal_layer_from_candidate(candidate.category, candidate.status, " ".join(candidate.reasons))

    def _merge_by_mapped_path(self, candidates: List[ResidueCandidate]) -> List[ResidueCandidate]:
        merged: Dict[tuple, ResidueCandidate] = {}
        merge_counts: Dict[tuple, int] = defaultdict(int)
        for candidate in candidates:
            artifact_type, canonical_path = self.canonical_artifact_key(candidate.mapped_path or candidate.path)
            key = (candidate.type, artifact_type, canonical_path)
            existing = merged.get(key)
            if existing is None:
                merged[key] = candidate
                continue
            merge_counts[key] += 1
            if candidate.raw_score > existing.raw_score:
                existing.path = candidate.path
                existing.mapped_path = candidate.mapped_path
            existing.raw_score = max(existing.raw_score, candidate.raw_score)
            existing.score = max(existing.score, candidate.score)
            existing.first_seen = min(existing.first_seen, candidate.first_seen, key=self._time_sort_key)
            existing.last_seen = max(existing.last_seen, candidate.last_seen, key=self._time_sort_key)
            if existing.exists_now is not True and candidate.exists_now is True:
                existing.exists_now = True
            elif existing.exists_now is None and candidate.exists_now is False:
                existing.exists_now = False
            existing.processes = sorted(set(existing.processes) | set(candidate.processes))
            existing.operations = sorted(set(existing.operations) | set(candidate.operations))
            existing.reasons = self._unique_compact(existing.reasons + candidate.reasons)
            if not existing.installer_cluster_id and candidate.installer_cluster_id:
                existing.installer_cluster_id = candidate.installer_cluster_id
            if existing.subtree_class == "none" and candidate.subtree_class != "none":
                existing.subtree_class = candidate.subtree_class
            if not existing.rename_family_id and candidate.rename_family_id:
                existing.rename_family_id = candidate.rename_family_id
            if not existing.vendor_family_id and candidate.vendor_family_id:
                existing.vendor_family_id = candidate.vendor_family_id
            if not existing.service_branch_id and candidate.service_branch_id:
                existing.service_branch_id = candidate.service_branch_id
            if not existing.root_family_id and candidate.root_family_id:
                existing.root_family_id = candidate.root_family_id
            existing.cluster_membership_count = max(existing.cluster_membership_count, candidate.cluster_membership_count)
            if existing.removal_layer == "review_queue" and candidate.removal_layer != "review_queue":
                existing.removal_layer = candidate.removal_layer

        for key, count in merge_counts.items():
            merged[key].reasons = self._unique_compact(merged[key].reasons + [f"merged {count + 1} entries with same canonical artifact key"])
            merged[key].status = self._status_from_score(merged[key].raw_score, merged[key].exists_now, merged[key].subtree_class)
            merged[key].score = max(0, min(merged[key].raw_score, 100))
            merged[key].removal_layer = self._removal_layer_from_candidate(merged[key].category, merged[key].status, " ".join(merged[key].reasons))
        return list(merged.values())

    @staticmethod
    def _time_sort_key(value: str) -> str:
        """Sort key for Procmon time strings. Uses datetime parse to handle 12-hour AM/PM correctly."""
        dt = parse_procmon_time_to_dt(value)
        if dt:
            return dt.strftime("%H:%M:%S.%f")
        # Fallback: raw string — pad single-digit hours so string sort works
        text = (value or "").strip()
        if not text:
            return text
        # Handle both 12-hour (e.g. "9:30:00 AM") and 24-hour (e.g. "9:30:00") raw strings
        # Convert AM/PM so that "12:xx AM" < "1:xx PM" etc.
        upper = text.upper()
        is_pm = upper.endswith(" PM")
        is_am = upper.endswith(" AM")
        if is_pm or is_am:
            time_part = text[:-3].strip()
            try:
                h, rest = time_part.split(":", 1)
                h = int(h)
                if is_am and h == 12:
                    h = 0
                elif is_pm and h != 12:
                    h += 12
                return f"{h:02d}:{rest}"
            except (ValueError, IndexError):
                pass
        # Plain 24-hour or unparseable — just zero-pad leading hour digit
        if text[0].isdigit() and ":" in text:
            hour, rest = text.split(":", 1)
            if len(hour) == 1:
                return f"0{hour}:{rest}"
        return text

    def _registry_path_exists(self, path: str) -> Optional[bool]:
        """P2 fix: Distinguish access-denied from not-found.
        Returns True if key/value exists, False if confirmed not found,
        None if access was denied or check is inconclusive."""
        if os.name != "nt":
            return None
        root, sub = self._registry_to_winreg_root(path)
        if root is None or not sub:
            return None
        sub = sub.strip("\\")
        if not sub:
            return None
        saw_access_denied = False
        saw_not_found = False
        try:
            # Try all WOW64 access modes: native, 32-bit view, 64-bit view
            for access_flag in [winreg.KEY_READ, winreg.KEY_READ | winreg.KEY_WOW64_32KEY, winreg.KEY_READ | winreg.KEY_WOW64_64KEY]:
                try:
                    with winreg.OpenKey(root, sub, 0, access_flag):
                        return True
                except OSError as exc:
                    winerr = getattr(exc, "winerror", None)
                    if winerr in (2, 3):  # ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
                        saw_not_found = True
                    elif winerr == 5:  # ERROR_ACCESS_DENIED
                        saw_access_denied = True
                    # Other errors: continue to next access flag

            # Try as value name
            if "\\" in sub:
                parent, leaf = sub.rsplit("\\", 1)
                for access_flag in [winreg.KEY_READ, winreg.KEY_READ | winreg.KEY_WOW64_32KEY, winreg.KEY_READ | winreg.KEY_WOW64_64KEY]:
                    try:
                        with winreg.OpenKey(root, parent, 0, access_flag) as key:
                            winreg.QueryValueEx(key, leaf)
                            return True
                    except OSError as exc:
                        winerr = getattr(exc, "winerror", None)
                        if winerr in (2, 3):
                            saw_not_found = True
                        elif winerr == 5:
                            saw_access_denied = True
                        continue
            # P2 fix: if we only saw access denied (never confirmed not-found),
            # return None (unknown) instead of False (doesn't exist)
            if saw_access_denied and not saw_not_found:
                return None
            return False
        except Exception:
            return None

    def _path_exists(self, path: str) -> Optional[bool]:
        if not path:
            return None
        lp = (path or "").lower()
        try:
            if any(lp.startswith(prefix) for prefix in REGISTRY_PREFIXES):
                result = self._registry_path_exists(path)
                if result is True:
                    return True
                # Check WOW64 equivalents for registry
                for eq_path in get_wow64_equivalents(path):
                    eq_result = self._registry_path_exists(eq_path)
                    if eq_result is True:
                        return True
                return result
            # Filesystem check
            result = os.path.exists(path)
            if result:
                return True
            # Check WOW64 equivalents for filesystem (Program Files <-> Program Files (x86))
            for eq_path in get_wow64_equivalents(path):
                if os.path.exists(eq_path):
                    return True
            return result
        except Exception:
            return None

    @staticmethod
    def _unique_compact(items: List[str]) -> List[str]:
        out = []
        seen = set()
        for item in items:
            key = item.lower().strip()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out[:12]  # LOGIC-4 fix: Increased from 8 to 12

    def extract_vendor_aliases(self, related_pids: Set[int], residues: List[ResidueCandidate]) -> List[str]:
        aliases: Set[str] = set()
        for residue in residues:
            token = self._extract_vendor_token(residue.path)
            if token and token not in STOP_WORDS:
                aliases.add(token)
        for pid in related_pids:
            info = self.process_info_by_pid.get(pid)
            if not info:
                continue
            for token in split_tokens(info.image_path) + split_tokens(info.command_line):
                if token not in STOP_WORDS:
                    aliases.add(token)
        for ev in self.events:
            lp = (ev.path or "").lower()
            if any(lp.startswith(prefix) for prefix in UNINSTALL_KEY_PREFIXES):
                for token in split_tokens(ev.detail or ""):
                    if token not in STOP_WORDS:
                        aliases.add(token)
            if "\\services\\" in lp:
                service_name = lp.split("\\services\\", 1)[-1].split("\\", 1)[0]
                aliases.update(split_tokens(service_name))
                aliases.update(split_tokens(ev.detail or ""))
            token = self._extract_vendor_token(ev.path or "")
            if token and token not in STOP_WORDS:
                aliases.add(token)
        return sorted(aliases)

    def collect_suggested_terms_detailed(
        self,
        related_pids: Set[int],
        residues: List[ResidueCandidate],
        root_terms: List[str],
    ) -> List[Dict[str, object]]:
        seen = {term.lower() for term in root_terms}
        weighted: Dict[str, int] = defaultdict(int)
        term_type: Dict[str, str] = {}

        def add_token(token: str, weight: int, token_kind: str):
            tok = token.lower().strip()
            if not tok or tok in seen:
                return
            weighted[tok] += weight
            if tok not in term_type or weighted[tok] >= 20:
                term_type[tok] = token_kind

        for token in self.extract_vendor_aliases(related_pids, residues):
            add_token(token, 20, "vendor_token")

        for pid in related_pids:
            info = self.process_info_by_pid.get(pid)
            if not info:
                continue
            for token in split_tokens(info.proc_name):
                add_token(token, 14, "service_token")
            for token in split_tokens(info.image_path):
                add_token(token, 10, "product_token")
            for token in split_tokens(info.command_line):
                add_token(token, 8, "product_token")

        for residue in residues:
            for token in split_tokens(residue.path):
                add_token(token, 7, "path_token")

        for ev in self.events:
            if ev.pid is not None and ev.pid not in related_pids:
                continue
            detail_lower = (ev.detail or "").lower()
            detail_tokens = split_tokens(ev.detail)
            if "publisher" in detail_lower or "company" in detail_lower:
                for token in detail_tokens:
                    add_token(token, 18, "company_token")
            elif "displayname" in detail_lower or "uninstall" in (ev.path or "").lower():
                for token in detail_tokens:
                    add_token(token, 16, "uninstall_token")
            else:
                for token in detail_tokens:
                    add_token(token, 6, "product_token")

        typed_order = ["vendor_token", "company_token", "uninstall_token", "service_token", "product_token", "path_token"]
        output: List[str] = []
        taken: Set[str] = set()
        for kind in typed_order:
            picks = [t for t, k in term_type.items() if k == kind]
            picks.sort(key=lambda t: weighted[t], reverse=True)
            for token in picks[:2]:
                if token in taken:
                    continue
                taken.add(token)
                output.append(token)

        for token, _ in sorted(weighted.items(), key=lambda item: item[1], reverse=True):
            if token in taken:
                continue
            output.append(token)
            taken.add(token)
            if len(output) >= 20:
                break

        detailed: List[Dict[str, object]] = []
        for token in output[:20]:
            kind = term_type.get(token, "product_token")
            weight = weighted.get(token, 0)
            trust_level = "weak"
            if kind in {"vendor_token", "company_token", "service_token"} and weight >= 14:
                trust_level = "trusted"
            elif kind in {"uninstall_token", "product_token"} and weight >= 10:
                trust_level = "moderate"
            detailed.append({"term": token, "weight": weight, "kind": kind, "trust_level": trust_level})
        return detailed

    def collect_suggested_terms(
        self,
        related_pids: Set[int],
        residues: List[ResidueCandidate],
        root_terms: List[str],
    ) -> List[str]:
        return [item["term"] for item in self.collect_suggested_terms_detailed(related_pids, residues, root_terms)]


class GenericTableModel(QAbstractTableModel):
    def __init__(self, rows: List[dict], headers: List[str]):
        super().__init__()
        self.rows = rows
        self.headers = headers

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self.rows[index.row()]
        key = self.headers[index.column()]
        value = row.get(key, "")
        if role == Qt.DisplayRole:
            if isinstance(value, list):
                return "; ".join(map(str, value))
            return str(value)
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignLeft | Qt.AlignVCenter)
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.headers[section]
        return section + 1


class AnalysisWorker(QObject):
    progress = Signal(int, str)
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, csv_path: str, selected_terms: List[str], min_score: int):
        super().__init__()
        self.csv_path = csv_path
        self.selected_terms = selected_terms
        self.min_score = min_score
        self._cancel_event = threading.Event()

    def cancel(self):
        self._cancel_event.set()

    def is_cancelled(self) -> bool:
        return self._cancel_event.is_set()

    def _emit_phased(self, phase_start: int, phase_end: int, local_pct: int, text: str):
        local = max(0, min(100, int(local_pct)))
        global_pct = phase_start + int((phase_end - phase_start) * (local / 100.0))
        self.progress.emit(min(99, global_pct), text)

    @staticmethod
    def _dedupe_terms_case_insensitive(terms: List[str]) -> List[str]:
        unique: List[str] = []
        seen: Set[str] = set()
        for term in terms:
            key = term.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            unique.append(term.strip())
        return unique

    def run(self):
        try:
            self.progress.emit(1, "CSV yüklənir...")
            events = ProcmonCsvLoader.load_csv(
                self.csv_path,
                progress_cb=lambda pct, txt: self._emit_phased(0, 40, pct, txt),
                cancel_cb=self.is_cancelled,
            )
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return
            self.progress.emit(40, "CSV oxundu")

            self.progress.emit(41, "Analiz üçün indekslər hazırlanır...")
            analyzer = ProcmonAnalyzer(
                events,
                cancel_cb=self.is_cancelled,
                progress_cb=lambda pct, txt: self._emit_phased(41, 55, pct, txt),
            )
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return

            root_terms = self._dedupe_terms_case_insensitive(self.selected_terms)
            if not root_terms:
                raise RuntimeError("Proqram adı daxil edin.")
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return

            self.progress.emit(56, f"İzlər analiz olunur: {', '.join(root_terms)}")
            residues = analyzer.analyze_residue(
                root_terms=root_terms,
                cancel_cb=self.is_cancelled,
                progress_cb=lambda pct, txt: self._emit_phased(56, 95, pct, txt),
            )

            self.progress.emit(96, "Nəticələr filtr olunur...")
            weak_min_score = max(10, self.min_score - 30)
            strong_residues: List[ResidueCandidate] = []
            weak_residues: List[ResidueCandidate] = []
            for residue in residues:
                if residue.raw_score >= self.min_score:
                    strong_residues.append(residue)
                    continue
                if residue.status == "checked_only":
                    strong_residues.append(residue)
                    continue
                reason_blob = " ".join(residue.reasons).lower()
                is_field_related = (
                    residue.subtree_class in {"subtree_only", "subtree_first"}
                    or bool(residue.rename_family_id)
                    or bool(residue.installer_cluster_id)
                    or residue.cluster_membership_count >= 2
                )
                is_reason_related = any(
                    marker in reason_blob
                    for marker in (
                        "direct chain",
                        "written by chain",
                        "renamed from",
                        "guid/clsid correlation",
                        "neighborhood of confirmed residue",
                        "sibling of",
                        "created by installer descendant",
                        "live survivor expansion",
                        "registry branch sweep",
                        "vendor family proactive sweep",
                        "installer cluster",
                        "cluster bonus",
                        "firewall rule",
                        "windows installer cache",
                    )
                )
                if is_field_related or is_reason_related:
                    residue.status = "weak_but_related"
                    residue.removal_layer = "weak_but_related"
                    strong_residues.append(residue)
                    continue
                if weak_min_score <= residue.raw_score < self.min_score:
                    weak_residues.append(residue)
            residues = strong_residues

            self.progress.emit(97, "Tövsiyə olunan terminlər toplanır...")
            term_patterns = compile_term_patterns(root_terms)
            related_pids, _, _, _ = analyzer.build_related_pid_set(term_patterns)
            suggested_terms = analyzer.collect_suggested_terms(related_pids, residues, root_terms)
            if self.is_cancelled():
                self.failed.emit("İstifadəçi tərəfindən ləğv edildi.")
                return

            self.progress.emit(99, "Nəticələr hazırlanır...")
            payload = {
                "selected_terms": root_terms,
                "suggested_terms": suggested_terms,
                "residues": [asdict(x) for x in residues],
                "weak_residues": [asdict(x) for x in weak_residues],
                "summary": {
                    "events": len(events),
                    "residue_count": len(residues),
                    "weak_residue_count": len(weak_residues),
                    "safe_to_delete": sum(1 for x in residues if x.status == "safe_to_delete"),
                    "weak_but_related": sum(1 for x in residues if x.status == "weak_but_related"),
                    "review": sum(1 for x in residues if x.status == "review"),
                    "already_gone": sum(1 for x in residues if x.status == "already_gone"),
                    "ignore": sum(1 for x in residues if x.status == "ignore"),
                    "exists_check_note": (
                        "exists_now yoxlaması cari cihazda aparılır; CSV başqa mühitdən toplanıbsa nəticə fərqli ola bilər."
                    ),
                },
            }
            self.progress.emit(100, "Analiz tamamlandı")
            self.finished.emit(payload)
        except Exception as exc:
            self.failed.emit(str(exc))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Procmon Residue Analyzer")
        self.resize(1450, 860)

        self.current_payload: Optional[dict] = None
        self.thread: Optional[QThread] = None
        self.worker: Optional[AnalysisWorker] = None

        self.csv_path_edit = QLineEdit()
        self.csv_path_edit.setPlaceholderText("Procmon CSV seç")
        self.browse_btn = QPushButton("CSV seç")
        self.analyze_btn = QPushButton("Analiz et")
        self.terms_edit = QLineEdit()
        self.terms_edit.setPlaceholderText("məs: verdent")
        self.min_score_spin = QSpinBox()
        self.min_score_spin.setRange(0, 100)
        self.min_score_spin.setValue(40)
        self.progress = QProgressBar()
        self.status_text = QLabel("Hazır")

        self.residue_table = QTableView()
        self.details_box = QPlainTextEdit()
        self.details_box.setReadOnly(True)
        self.log_box = QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self._last_progress_log_bucket = -1

        self._build_ui()
        self._wire_events()

    def closeEvent(self, event):
        """P6 fix: Override closeEvent with safe cooperative shutdown.
        Never calls QThread.terminate() — relies on cancel event and graceful timeout."""
        if self.thread and self.thread.isRunning():
            if self.worker:
                self.worker.cancel()
            self.thread.quit()
            if not self.thread.wait(10000):  # Wait up to 10 seconds for cooperative shutdown
                # P6 fix: Do NOT call terminate() — log warning and let OS clean up on exit
                import sys
                print("WARNING: Analysis thread did not stop within 10s; detaching.", file=sys.stderr)
                # Disconnect signals to prevent callbacks after window is destroyed
                try:
                    self.thread.finished.disconnect()
                except RuntimeError:
                    pass
        event.accept()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        controls = QGroupBox("Giriş")
        form = QFormLayout(controls)

        csv_row = QHBoxLayout()
        csv_row.addWidget(self.csv_path_edit, 1)
        csv_row.addWidget(self.browse_btn)
        form.addRow("CSV", csv_row)
        form.addRow("Proqram adı", self.terms_edit)
        form.addRow("Minimum skor", self.min_score_spin)
        form.addRow("", self.analyze_btn)

        main_layout.addWidget(controls)
        main_layout.addWidget(self.progress)
        main_layout.addWidget(self.status_text)

        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        tabs = QTabWidget()

        residues_tab = QWidget()
        residues_layout = QVBoxLayout(residues_tab)
        residues_layout.addWidget(QLabel("Tapılmış izlər"))
        residues_layout.addWidget(self.residue_table)

        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        logs_layout.addWidget(QLabel("İş jurnalı"))
        logs_layout.addWidget(self.log_box)

        tabs.addTab(residues_tab, "İzlər")
        tabs.addTab(logs_tab, "Log")
        left_layout.addWidget(tabs)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(QLabel("Seçilmiş sətrin detalları"))
        right_layout.addWidget(self.details_box)
        splitter.addWidget(right)
        splitter.setSizes([1000, 450])

        main_layout.addWidget(splitter, 1)

        menu = self.menuBar().addMenu("Fayl")
        export_json = QAction("JSON export", self)
        export_txt = QAction("TXT hesabat export", self)
        menu.addAction(export_json)
        menu.addAction(export_txt)
        export_json.triggered.connect(self.export_json)
        export_txt.triggered.connect(self.export_txt)

        # Configure residue table
        self.residue_table.setSelectionBehavior(QTableView.SelectRows)
        self.residue_table.setSelectionMode(QTableView.SingleSelection)
        self.residue_table.horizontalHeader().setStretchLastSection(True)
        self.residue_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.residue_table.setAlternatingRowColors(True)

    def _wire_events(self):
        self.browse_btn.clicked.connect(self.choose_csv)
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.residue_table.clicked.connect(self.on_residue_row_clicked)

    def choose_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Procmon CSV seç", "", "CSV Files (*.csv)")
        if path:
            self.csv_path_edit.setText(path)

    def log(self, text: str):
        self.log_box.appendPlainText(text)
        self.status_text.setText(text)

    def start_analysis(self):
        csv_path = self.csv_path_edit.text().strip()
        if not csv_path or not os.path.isfile(csv_path):
            QMessageBox.warning(self, "Səhv", "Düzgün CSV faylı seç.")
            return

        program_name = self.terms_edit.text().strip()
        if not program_name:
            QMessageBox.warning(self, "Səhv", "Bir proqram adı daxil et.")
            return
        if "," in program_name:
            QMessageBox.warning(self, "Səhv", "Yalnız 1 proqram adı yazın (vergül istifadə etməyin).")
            return

        if self.thread and self.thread.isRunning():
            if self.worker:
                self.worker.cancel()
            self.analyze_btn.setText("Ləğv edilir...")
            self.analyze_btn.setEnabled(False)
            self.log("Əvvəlki analiz ləğv edilir...")
            return

        selected_terms = [program_name]
        min_score = self.min_score_spin.value()

        self.analyze_btn.setText("Ləğv et")
        self.analyze_btn.setEnabled(True)
        self.progress.setValue(0)
        self.log_box.clear()
        self._last_progress_log_bucket = -1
        self.details_box.clear()
        self.log("Analiz başlayır...")

        self.thread = QThread(self)
        self.worker = AnalysisWorker(csv_path, selected_terms, min_score)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.finished.connect(self.thread.quit)
        self.worker.failed.connect(self.thread.quit)
        self.thread.finished.connect(self._on_thread_finished)
        self.thread.start()

    def _on_thread_finished(self):
        self.analyze_btn.setText("Analiz et")
        self.analyze_btn.setEnabled(True)
        app = QApplication.instance()
        if self.worker:
            if app:
                self.worker.moveToThread(app.thread())
            self.worker.deleteLater()
        if self.thread:
            self.thread.deleteLater()
        self.thread = None
        self.worker = None

    def on_progress(self, value: int, text: str):
        self.progress.setValue(value)
        self.status_text.setText(text)
        bucket = max(0, min(10, value // 10))
        if bucket != self._last_progress_log_bucket:
            self._last_progress_log_bucket = bucket
            self.log_box.appendPlainText(text)

    def on_finished(self, payload: dict):
        self.current_payload = payload
        self.progress.setValue(100)
        self.log(
            f"Hazır. Event: {payload['summary']['events']:,} | İz: {payload['summary']['residue_count']:,} | "
            f"Safe: {payload['summary']['safe_to_delete']:,} | Review: {payload['summary']['review']:,} | "
            f"Gone: {payload['summary']['already_gone']:,} | Ignore: {payload['summary'].get('ignore', 0):,} | "
            f"WeakRel: {payload['summary'].get('weak_but_related', 0):,} | Weak: {payload['summary'].get('weak_residue_count', 0):,}"
        )

        self.residue_table.setModel(
            GenericTableModel(
                payload.get("residues", []),
                [
                    "status",
                    "removal_layer",
                    "category",
                    "cluster",
                    "installer_cluster_id",
                    "raw_score",
                    "score",
                    "type",
                    "path",
                    "mapped_path",
                    "exists_now",
                    "processes",
                    "operations",
                    "reasons",
                ],
            )
        )

        selected_terms = payload.get("selected_terms", [])
        suggested_terms = payload.get("suggested_terms", [])
        note = payload.get("summary", {}).get("exists_check_note", "")
        details = "İstifadə olunan terminlər:\n- " + "\n- ".join(selected_terms)
        if suggested_terms:
            details += "\n\nTövsiyə olunan əlavə terminlər:\n- " + "\n- ".join(suggested_terms)
        details += f"\n\nQeyd: {note}"
        self.details_box.setPlainText(details)

    def on_failed(self, message: str):
        self.progress.setValue(0)
        if "ləğv edildi" in (message or "").lower():
            self.log(message)
            return
        QMessageBox.critical(self, "Xəta", message)
        self.log(f"Xəta: {message}")

    def on_residue_row_clicked(self, index: QModelIndex):
        if not self.current_payload:
            return
        row = index.row()
        items = self.current_payload.get("residues", [])
        if 0 <= row < len(items):
            item = items[row]
            self.details_box.setPlainText(json.dumps(item, ensure_ascii=False, indent=2))

    def export_json(self):
        if not self.current_payload:
            QMessageBox.information(self, "Məlumat", "Əvvəl analiz et.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "JSON saxla", "residual_candidates.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.current_payload, f, ensure_ascii=False, indent=2)
            self.log(f"JSON saxlanıldı: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Xəta", f"Fayl yazıla bilmədi: {exc}")

    def export_txt(self):
        if not self.current_payload:
            QMessageBox.information(self, "Məlumat", "Əvvəl analiz et.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "TXT hesabat saxla", "residue_report.txt", "Text Files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                summary = self.current_payload["summary"]
                f.write("Procmon Residue Analyzer Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"Events: {summary['events']:,}\n")
                f.write(f"Residues: {summary['residue_count']:,}\n")
                f.write(f"Safe to delete: {summary['safe_to_delete']:,}\n")
                f.write(f"Review: {summary['review']:,}\n")
                f.write(f"Already gone: {summary.get('already_gone', 0):,}\n")
                f.write(f"Ignore: {summary.get('ignore', 0):,}\n")
                f.write(f"Note: {summary.get('exists_check_note', '')}\n")
                f.write("\nSelected terms:\n")
                for token in self.current_payload.get("selected_terms", []):
                    f.write(f"- {token}\n")
                suggested = self.current_payload.get("suggested_terms", [])
                if suggested:
                    f.write("\nSuggested terms:\n")
                    for token in suggested:
                        f.write(f"- {token}\n")
                residues = self.current_payload.get("residues", [])
                normal_residues = [x for x in residues if x.get("category") != "execution_trace"]
                trace_residues = [x for x in residues if x.get("category") == "execution_trace"]

                f.write("\nResidues:\n")
                for item in normal_residues:
                    f.write("-" * 60 + "\n")
                    f.write(f"Status: {item['status']}\n")
                    f.write(f"Removal layer: {item.get('removal_layer', 'review_queue')}\n")
                    f.write(f"Raw score: {item['raw_score']}\n")
                    f.write(f"Score: {item['score']}\n")
                    f.write(f"Type: {item['type']}\n")
                    f.write(f"Category: {item.get('category', 'functional')}\n")
                    f.write(f"Cluster: {item.get('cluster', 'uncategorized')}\n")
                    f.write(f"Installer cluster: {item.get('installer_cluster_id')}\n")
                    f.write(f"Path: {item['path']}\n")
                    f.write(f"Mapped: {item['mapped_path']}\n")
                    f.write(f"Exists now: {item['exists_now']}\n")
                    f.write(f"Processes: {', '.join(item['processes'])}\n")
                    f.write(f"Operations: {', '.join(item['operations'])}\n")
                    f.write("Reasons:\n")
                    for reason in item["reasons"]:
                        f.write(f"  * {reason}\n")

                if trace_residues:
                    f.write("\nExecution traces (functional residue deyil):\n")
                    for item in trace_residues:
                        f.write("-" * 60 + "\n")
                        f.write(f"Status: {item['status']}\n")
                        f.write(f"Type: {item['type']}\n")
                        f.write(f"Path: {item['path']}\n")
                        f.write(f"Reasons: {'; '.join(item.get('reasons', []))}\n")
                weak_items = self.current_payload.get("weak_residues", [])
                if weak_items:
                    f.write("\nWeak but related residues:\n")
                    for item in weak_items:
                        f.write("-" * 60 + "\n")
                        f.write(f"Status: {item['status']}\n")
                        f.write(f"Raw score: {item['raw_score']}\n")
                        f.write(f"Type: {item['type']}\n")
                        f.write(f"Path: {item['path']}\n")
            self.log(f"TXT hesabat saxlanıldı: {path}")
        except OSError as exc:
            QMessageBox.critical(self, "Xəta", f"Fayl yazıla bilmədi: {exc}")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Procmon Residue Analyzer")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
