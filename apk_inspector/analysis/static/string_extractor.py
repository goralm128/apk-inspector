import os
import sys
import re
import math
from pathlib import Path
from typing import List, Dict
from apk_inspector.utils.logger import get_logger

logger = get_logger()

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


def safe_read_file(file_path: Path) -> str:
    try:
        # Workaround for long paths on Windows
        if sys.platform.startswith("win"):
            long_path = f"\\\\?\\{file_path.resolve()}"
        else:
            long_path = str(file_path.resolve())

        with open(long_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    except FileNotFoundError:
        logger.warning(f"[STRING EXTRACTOR] File not found: {file_path}")
    except OSError as e:
        logger.error(f"[STRING EXTRACTOR] OS error reading {file_path}: {e}")
    except Exception as e:
        logger.error(f"[STRING EXTRACTOR] Unexpected error reading {file_path}: {e}")

    return ""  # Fallback if file can't be read


def extract_suspicious_strings(decompiled_dir: Path) -> List[Dict[str, str]]:
    results = []
    seen_matches = set()

    if not decompiled_dir.exists():
        logger.error(f"[STRING EXTRACTOR] Provided path does not exist: {decompiled_dir}")
        return results

    for file in decompiled_dir.rglob("*.smali"):
        content = safe_read_file(file)
        if not content:
            continue

        for label, pattern in SUSPICIOUS_PATTERNS:
            for match in re.findall(pattern, content):
                if (label, match) in seen_matches:
                    continue
                seen_matches.add((label, match))

                entropy = string_entropy(match)
                results.append({
                    "file": str(file.relative_to(decompiled_dir)),
                    "type": label,
                    "match": match,
                    "entropy": round(entropy, 2)
                })

    logger.info(f"[STRING EXTRACTOR] Completed with {len(results)} suspicious strings found.")
    return results
