"""Process and operation related constants."""

import re

AVG_CSV_LINE_BYTES = 350

HELPER_PROCESSES = {
    "msiexec.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "dllhost.exe",
    "explorer.exe",
    "svchost.exe",
    "taskhostw.exe",
    "conhost.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
}

STOP_AT_PARENTS = {
    "explorer.exe",
    "services.exe",
    "svchost.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "lsass.exe",
    "system",
}

INTERESTING_OPERATIONS = frozenset({
    "CreateFile",
    "WriteFile",
    "CreateDirectory",
    "SetDispositionInformationFile",
    "SetRenameInformationFile",
    "SetBasicInformationFile",
    "RegCreateKey",
    "RegSetValue",
    "RegDeleteKey",
    "RegDeleteValue",
    "RegOpenKey",
    "RegQueryValue",
    "RegEnumKey",
    "RegEnumValue",
    "QueryOpen",
    "QueryDirectory",
    "QueryInformationFile",
    "Process Create",
    "Process Exit",
    "Load Image",
})

QUERY_ONLY_OPS = frozenset(
    {
        "RegOpenKey",
        "RegQueryValue",
        "RegEnumKey",
        "RegEnumValue",
        "QueryOpen",
        "QueryDirectory",
        "QueryInformationFile",
    }
)

WRITE_OPS = frozenset({"WriteFile", "CreateDirectory", "RegCreateKey", "RegSetValue"})
CREATE_LIKE_OPS = frozenset({"CreateDirectory", "RegCreateKey"})
RELATED_CHAIN_OPS = frozenset(
    {
        "WriteFile",
        "CreateDirectory",
        "RegCreateKey",
        "RegSetValue",
        "SetRenameInformationFile",
        "SetDispositionInformationFile",
    }
)
CREATEFILE_CREATE_RE = re.compile(r"Disposition:\s*(Create|Overwrite|CreateNew|Supersede)", re.IGNORECASE)
