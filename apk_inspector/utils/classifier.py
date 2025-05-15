# apk_inspector/utils/classifier.py

from pathlib import Path
import re

SENSITIVE_KEYWORDS = {"token", "secret", "key", "passwd", "credentials", "auth", "cert", "shadow"}
SYSTEM_PATHS = ["/system/", "/vendor/", "/proc/", "/sys/", "/data/misc/", "/dev/"]
HIDDEN_PATTERNS = ["/.", ".tmp", "/.nomedia", "/.hidden"]
CONFIG_EXTENSIONS = {".json", ".xml", ".ini", ".conf", ".cfg"}
APP_STORAGE_ROOTS = ["/sdcard/", "/storage/emulated/0/", "/data/data/"]

def classify_path(path: str) -> str:
    if not path:
        return "unknown"

    path = path.strip().lower()
    p = Path(path)

    if any(s in path for s in SENSITIVE_KEYWORDS):
        return "sensitive"

    if any(path.startswith(root) for root in SYSTEM_PATHS):
        return "system_access"

    if any(part.startswith('.') for part in p.parts if part):  # hidden folders or files
        return "obfuscated_write"

    if p.suffix in CONFIG_EXTENSIONS:
        return "config"

    if any(path.startswith(root) for root in APP_STORAGE_ROOTS):
        return "app_storage"

    return "general"
