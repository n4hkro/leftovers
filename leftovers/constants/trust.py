"""Trust-related constants: trusted signers and stop words."""

TRUSTED_SIGNERS = {
    "microsoft windows",
    "microsoft corporation",
    "microsoft windows publisher",
    "microsoft code signing pca",
}

STOP_WORDS = {
    "exe",
    "dll",
    "tmp",
    "log",
    "txt",
    "mui",
    "com",
    "sys",
    "ini",
    "dat",
    "users",
    "local",
    "roaming",
    "appdata",
    "programdata",
    "program",
    "files",
    "windows",
    "system32",
    "software",
    "microsoft",
    "currentversion",
    "hklm",
    "hkcu",
    "hkcr",
}
