"""Text processing utilities."""

import re
from datetime import datetime
from typing import Dict, List, Optional

from leftovers.constants.trust import STOP_WORDS


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


def normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def safe_int(value: str) -> Optional[int]:
    try:
        return int(str(value).strip())
    except Exception:
        return None


def normalize_proc_name(name: str) -> str:
    return (name or "").strip().lower()


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
