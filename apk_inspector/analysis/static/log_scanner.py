import re
from pathlib import Path

LOGGING_PATTERNS = [
    r'Log\.d\s*\(\s*".*?"\s*,\s*".*?"\s*\)',  # Log.d("TAG", "message")
    r'Log\.i\s*\(\s*".*?"\s*,\s*".*?"\s*\)',
    r'Log\.e\s*\(\s*".*?"\s*,\s*".*?"\s*\)',
    r'System\.out\.println\s*\(.*?\)',        # println()
]

SENSITIVE_HINTS = [
    "password", "passwd", "pwd",
    "secret", "api_key", "token",
    "auth", "jwt", "bearer"
]

def scan_logs_for_secrets(decompiled_dir: Path) -> list:
    results = []

    for file in decompiled_dir.rglob("*.smali"):
        try:
            content = file.read_text(errors="ignore").lower()
            for line in content.splitlines():
                if any(p in line for p in ["log", "println"]):
                    for hint in SENSITIVE_HINTS:
                        if hint in line:
                            results.append({
                                "file": str(file.relative_to(decompiled_dir)),
                                "line": line.strip(),
                                "hint": hint
                            })
        except Exception as e:
            print(f"[WARN] Error scanning file {file}: {e}")
    
    return results
