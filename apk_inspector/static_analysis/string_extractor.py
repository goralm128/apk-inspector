import re
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    r"http:\/\/[a-z0-9.-]+",
    r"https:\/\/[a-z0-9.-]+",
    r"\d{1,3}(?:\.\d{1,3}){3}",   # IP address
    r"AKIA[0-9A-Z]{16}",         # AWS key
    r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
]

def extract_suspicious_strings(decompiled_dir: Path) -> list:
    results = []

    for file in decompiled_dir.rglob("*.smali"):
        try:
            content = file.read_text(errors="ignore")
            for pattern in SUSPICIOUS_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    results.append({
                        "file": str(file.relative_to(decompiled_dir)),
                        "pattern": pattern,
                        "matches": matches
                    })
        except Exception as e:
            print(f"[WARN] Failed reading file {file}: {e}")
    
    return results
