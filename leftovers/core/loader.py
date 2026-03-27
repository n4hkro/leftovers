"""Procmon CSV file loader with encoding detection and field alias support."""

import csv
import os
from typing import Callable, Dict, List, Optional, Tuple

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


# All field names the loader can use, grouped by canonical name.
_FIELD_ALIASES: Dict[str, Tuple[str, ...]] = {
    "Time of Day": ("Time of Day", "Date & Time"),
    "Process Name": ("Process Name",),
    "PID": ("PID", "Process ID"),
    "Operation": ("Operation",),
    "Path": ("Path",),
    "Result": ("Result",),
    "Detail": ("Detail",),
    "Parent PID": ("Parent PID",),
    "Process Path": ("Process Path", "Image Path"),
    "Command Line": ("Command Line",),
}


def _build_column_index(
    headers: List[str],
) -> Dict[str, int]:
    """Map canonical field names to their column index in the CSV header row."""
    header_to_idx = {h: i for i, h in enumerate(headers)}
    col: Dict[str, int] = {}
    for canonical, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            if alias in header_to_idx:
                col[canonical] = header_to_idx[alias]
                break
    return col


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
            reader = csv.reader(f)
            try:
                headers = next(reader)
            except StopIteration:
                raise ValueError("CSV faylı boşdur")

            header_set = set(headers)
            missing = [
                canonical
                for canonical, aliases in cls.REQUIRED_FIELD_ALIASES.items()
                if not any(alias in header_set for alias in aliases)
            ]
            if missing:
                raise ValueError(f"CSV-də lazımi sütunlar yoxdur: {', '.join(sorted(missing))}")

            col = _build_column_index(headers)
            ncols = len(headers)

            # Pre-resolve column indices (use -1 as sentinel for missing optional columns)
            _i_time = col.get("Time of Day", -1)
            _i_proc = col.get("Process Name", -1)
            _i_pid = col.get("PID", -1)
            _i_op = col.get("Operation", -1)
            _i_path = col.get("Path", -1)
            _i_result = col.get("Result", -1)
            _i_detail = col.get("Detail", -1)
            _i_ppid = col.get("Parent PID", -1)
            _i_ppath = col.get("Process Path", -1)
            _i_cmdline = col.get("Command Line", -1)

            # Local references for speed in tight loop
            _norm_sp = normalize_spaces
            _norm_path = normalize_path
            _safe_int = safe_int
            _interesting = INTERESTING_OPERATIONS
            _Event = ProcmonEvent
            _append = events.append

            for line_idx, row in enumerate(reader, start=1):
                if cancel_cb and line_idx % 5000 == 0 and cancel_cb():
                    raise RuntimeError("İstifadəçi tərəfindən ləğv edildi.")
                if progress_cb and line_idx % 5000 == 0:
                    progress = min(99, int((line_idx / estimated_lines) * 100))
                    progress_cb(progress, f"CSV oxunur... {line_idx:,} sətir")

                # Guard against short rows
                if len(row) < ncols:
                    row.extend([""] * (ncols - len(row)))

                # Fast pre-check: skip rows whose operation is not interesting
                op_raw = row[_i_op] if _i_op >= 0 else ""
                op = _norm_sp(op_raw)
                if op not in _interesting:
                    continue

                event = _Event(
                    time_of_day=_norm_sp(row[_i_time]) if _i_time >= 0 else "",
                    process_name=_norm_sp(row[_i_proc]) if _i_proc >= 0 else "",
                    pid=_safe_int(row[_i_pid]) if _i_pid >= 0 else None,
                    operation=op,
                    path=_norm_path(row[_i_path]) if _i_path >= 0 else "",
                    result=_norm_sp(row[_i_result]) if _i_result >= 0 else "",
                    detail=_norm_sp(row[_i_detail]) if _i_detail >= 0 else "",
                    parent_pid=_safe_int(row[_i_ppid]) if _i_ppid >= 0 else None,
                    process_path=_norm_path(row[_i_ppath]) if _i_ppath >= 0 else "",
                    command_line=_norm_sp(row[_i_cmdline]) if _i_cmdline >= 0 else "",
                )
                _append(event)

        if progress_cb:
            progress_cb(100, f"CSV yükləndi: {len(events):,} sətir")
        return events
