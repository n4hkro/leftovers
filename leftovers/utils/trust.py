"""Trust and Authenticode verification utilities."""

import ctypes
import os
import threading
from typing import Dict, Optional

from leftovers.constants.trust import TRUSTED_SIGNERS

_signature_cache: Dict[str, Optional[str]] = {}  # str = company name, None = not trusted
_signature_cache_lock = threading.Lock()  # CODE-6: thread-safe access

# P1 fix: Real Authenticode verification via WinVerifyTrust
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = None
_wintrust_available = False
_WINTRUST_FILE_INFO = None
_WINTRUST_DATA = None

if os.name == "nt":
    try:
        import ctypes.wintypes as _wt
        from ctypes import wintypes

        class _WintrustFileInfo(ctypes.Structure):
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

        class _WintrustData(ctypes.Structure):
            _fields_ = [
                ("cbStruct", _wt.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", _wt.DWORD),
                ("fdwRevocationChecks", _wt.DWORD),
                ("dwUnionChoice", _wt.DWORD),
                ("pFile", ctypes.POINTER(_WintrustFileInfo)),
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
        _WINTRUST_FILE_INFO = _WintrustFileInfo
        _WINTRUST_DATA = _WintrustData
        # Test that wintrust.dll is loadable
        ctypes.windll.wintrust.WinVerifyTrust
        _wintrust_available = True
    except Exception:
        _wintrust_available = False

_authenticode_cache: Dict[str, Optional[bool]] = {}  # True = valid sig, False = invalid, None = error
_authenticode_cache_lock = threading.Lock()


def read_file_version_info(path: str) -> Dict[str, str]:
    """Read CompanyName and ProductName from PE version resource.
    Tries all available translation code pages instead of hardcoding 040904B0."""
    if os.name != "nt":
        return {}
    try:
        from ctypes import wintypes
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
        code_pages: list = []
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
