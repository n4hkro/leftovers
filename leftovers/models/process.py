"""ProcessInfo dataclass – metadata for a traced process."""

from dataclasses import dataclass


@dataclass(slots=True)
class ProcessInfo:
    pid: int
    proc_name: str = ""
    image_path: str = ""
    command_line: str = ""
    start_time: str = ""
    end_time: str = ""
