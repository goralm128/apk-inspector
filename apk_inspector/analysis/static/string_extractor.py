import re
import math
from pathlib import Path
from typing import List, Dict

SUSPICIOUS_PATTERNS = [
    ("url_http", r"http:\/\/[a-z0-9.\-]+"),
    ("url_https", r"https:\/\/[a-z0-9.\-]+"),
    ("ip_address", r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    ("bearer_token", r"Bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    ("base64_string", r"[A-Za-z0-9+/]{20,}={0,2}"),
    ("hex_string", r"\b(?:0x)?[0-9a-fA-F]{32,}\b"),
]

def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_suspicious_strings(decompiled_dir: Path) -> List[Dict[str, str]]:
    results = []
    seen_matches = set()  # for deduplication

    for file in decompiled_dir.rglob("*.smali"):
        try:
            content = file.read_text(errors="ignore")

            for label, pattern in SUSPICIOUS_PATTERNS:
                for match in re.findall(pattern, content):
                    if (label, match) in seen_matches:
                        continue  # skip duplicates
                    seen_matches.add((label, match))

                    entropy = string_entropy(match)
                    results.append({
                        "file": str(file.relative_to(decompiled_dir)),
                        "type": label,
                        "match": match,
                        "entropy": round(entropy, 2)
                    })

        except Exception as e:
            print(f"[WARN] Failed reading file {file}: {e}")

    return results
