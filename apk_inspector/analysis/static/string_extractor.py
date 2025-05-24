import re
import math
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    r"http:\/\/[a-z0-9.-]+",
    r"https:\/\/[a-z0-9.-]+",
    r"\d{1,3}(?:\.\d{1,3}){3}",
    r"AKIA[0-9A-Z]{16}",
    r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    r"[A-Za-z0-9+/]{20,}={0,2}",  # base64-like
    r"\b(?:0x)?[0-9a-fA-F]{32,}\b",  # hex strings
]

def string_entropy(s: str) -> float:
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_suspicious_strings(decompiled_dir: Path) -> list:
    results = []

    for file in decompiled_dir.rglob("*.smali"):
        try:
            content = file.read_text(errors="ignore")
            for pattern in SUSPICIOUS_PATTERNS:
                for match in re.findall(pattern, content):
                    entropy = string_entropy(match)
                    results.append({
                        "file": str(file.relative_to(decompiled_dir)),
                        "pattern": pattern,
                        "match": match,
                        "entropy": round(entropy, 2)
                    })
        except Exception as e:
            print(f"[WARN] Failed reading file {file}: {e}")
    
    return results
