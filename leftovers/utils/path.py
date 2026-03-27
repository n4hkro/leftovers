"""Path normalization, classification, and detection utilities."""

import os
import re
from pathlib import Path
from typing import List

from leftovers.constants.paths import (
    BAM_PREFIXES,
    FIREWALL_RULES_PREFIXES,
    LOW_VALUE_PATH_PREFIXES,
    LOW_VALUE_REG_PREFIXES,
    MUI_CACHE_PREFIXES,
    REGISTRY_PREFIXES,
    SAFE_PATH_PREFIXES_FOR_REPORT,
    SAFE_PATH_REGEXES,
    UNINSTALL_KEY_PREFIXES,
    USERASSIST_PREFIXES,
    WINDOWS_INSTALLER_PREFIX,
)


_MULTI_BACKSLASH_RE = re.compile(r"\\+")


def normalize_path(path: str) -> str:
    p = (path or "").strip().strip('"')
    p = p.replace("/", "\\")
    # EDGE-2 fix: Preserve UNC prefix
    is_unc = p.startswith("\\\\")
    p = _MULTI_BACKSLASH_RE.sub(r"\\", p)
    if is_unc:
        p = "\\" + p  # Restore double backslash for UNC paths
    return p


# Pre-normalized prefix tuples for fast startswith() lookups
_NORM_LOW_VALUE_PATHS = tuple(normalize_path(prefix).lower() for prefix in LOW_VALUE_PATH_PREFIXES)
_NORM_LOW_VALUE_REGS = tuple(normalize_path(prefix).lower() for prefix in LOW_VALUE_REG_PREFIXES)
_NORM_SAFE_PREFIXES = tuple(normalize_path(prefix).lower() for prefix in SAFE_PATH_PREFIXES_FOR_REPORT)


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


def path_is_low_value(path: str) -> bool:
    lp = (path or "").lower()
    return lp.startswith(_NORM_LOW_VALUE_PATHS) or lp.startswith(_NORM_LOW_VALUE_REGS)


def path_has_safe_prefix(path: str) -> bool:
    lp = (path or "").lower()
    if lp.startswith(_NORM_SAFE_PREFIXES):
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
    if lower_p.startswith(REGISTRY_PREFIXES):
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
    if lp.startswith(USERASSIST_PREFIXES):
        return "execution_trace"
    if lp.startswith(MUI_CACHE_PREFIXES) or lp.startswith(BAM_PREFIXES):
        return "execution_trace"
    if "\\prefetch\\" in lp and lp.endswith(".pf"):
        return "prefetch_trace"
    if lp.startswith("c:\\programdata\\microsoft\\windows\\wer\\reportarchive\\") or "\\crashdumps\\" in lp:
        return "crash_dump"
    if lp.startswith(FIREWALL_RULES_PREFIXES):
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
    if lp.startswith(UNINSTALL_KEY_PREFIXES):
        return "uninstall_key"
    if lp.startswith(REGISTRY_PREFIXES):
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
    if lp.startswith(REGISTRY_PREFIXES):
        return "registry"
    if lp.startswith("c:\\program files"):
        return "program_files"
    if lp.startswith("c:\\programdata\\"):
        return "program_data"
    if "\\appdata\\" in lp:
        return "app_data"
    if lp.startswith(WINDOWS_INSTALLER_PREFIX):
        return "installer_cache"
    if "\\prefetch\\" in lp or lp.startswith(MUI_CACHE_PREFIXES) or lp.startswith(BAM_PREFIXES):
        return "execution_traces"
    return "other"
