"""Procmon CSV file loader with encoding detection and field alias support."""

import csv
import os
from typing import Callable, List, Optional

from leftovers.constants.operations import AVG_CSV_LINE_BYTES, INTERESTING_OPERATIONS
from leftovers.models.event import ProcmonEvent
from leftovers.utils.path import normalize_path
from leftovers.utils.text import normalize_spaces, safe_int


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
