"""ProcmonEvent dataclass – a single Procmon trace event."""

from dataclasses import dataclass
from typing import Dict, Optional

from leftovers.utils.text import parse_detail


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
