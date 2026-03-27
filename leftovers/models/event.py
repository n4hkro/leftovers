"""ProcmonEvent dataclass – a single Procmon trace event."""

from dataclasses import dataclass, field
from typing import Dict, Optional

from leftovers.utils.text import parse_detail


@dataclass(slots=True)
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
    # Internal cache — not a public API field.  Using field(init=False,
    # repr=False) keeps it out of __init__ / __repr__ while still having a
    # slot allocated for it (required by slots=True).
    _parsed_detail: Optional[Dict[str, str]] = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def detail_dict(self) -> Dict[str, str]:
        """Lazily parse detail string into key-value dict."""
        if self._parsed_detail is None:
            self._parsed_detail = parse_detail(self.detail)
        return self._parsed_detail
