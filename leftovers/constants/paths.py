"""Path and registry prefix constants."""

import re

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

# PERF-4 fix: Module-level map to avoid recreating on every call
_REG_ROOT_MAP = {
    "hkey_local_machine\\": "hklm\\",
    "hkey_current_user\\": "hkcu\\",
    "hkey_classes_root\\": "hkcr\\",
    "hkey_users\\": "hku\\",
}
