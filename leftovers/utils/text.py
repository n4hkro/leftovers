"""Text processing utilities."""

import re
from datetime import datetime
from typing import Dict, List, Optional

from leftovers.constants.trust import STOP_WORDS

# Pre-compiled regexes for hot-path functions
_DETAIL_SPLIT_RE = re.compile(r',\s*(?=[A-Za-z][A-Za-z\s]*:)')
_SPACES_RE = re.compile(r"\s+")
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_TIME_FORMATS = ["%I:%M:%S.%f %p", "%I:%M:%S %p", "%H:%M:%S.%f", "%H:%M:%S"]


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
    parts = _DETAIL_SPLIT_RE.split(detail)
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


def normalize_spaces(text: str) -> str:
    return _SPACES_RE.sub(" ", (text or "").strip())


def safe_int(value: str) -> Optional[int]:
    try:
        return int(str(value).strip())
    except Exception:
        return None


def normalize_proc_name(name: str) -> str:
    return (name or "").strip().lower()


def split_tokens(text: str) -> List[str]:
    text = _NON_ALNUM_RE.sub(" ", text or "")
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
    return text.translate(_ROT13_TABLE)


# Cache the last successful time format to try it first next time
_last_time_fmt: Optional[str] = None


def parse_procmon_time_to_dt(value: str) -> Optional[datetime]:
    global _last_time_fmt
    text = (value or "").strip()
    if not text:
        return None
    # Try the last successful format first for speed
    if _last_time_fmt is not None:
        try:
            return datetime.strptime(text, _last_time_fmt)
        except ValueError:
            pass
    for fmt in _TIME_FORMATS:
        try:
            result = datetime.strptime(text, fmt)
            _last_time_fmt = fmt
            return result
        except ValueError:
            continue
    return None
