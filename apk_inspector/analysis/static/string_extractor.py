from pathlib import Path
from typing import List, Dict, Optional, Literal
import re
import math
import sys
from androguard.misc import AnalyzeAPK
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

ANALYZED_EXTENSIONS = {".smali", ".txt", ".json", ".xml", ".conf", ".ini", ".yml", ".dat"}


def string_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log2(p) for p in prob)


def classify_confidence(entropy: float) -> str:
    if entropy > 3.5:
        return "high"
    if entropy > 2.5:
        return "medium"
    return "low"


def safe_read_file(file_path: Path) -> str:
    try:
        long_path = f"\\\\?\\{file_path.resolve()}" if sys.platform.startswith("win") else str(file_path.resolve())
        with open(long_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as ex:
        logger.warning(f"[STRING EXTRACTOR] Failed to read {file_path}: {ex}")
        return ""


def extract_suspicious_strings(
    source: Path,
    backend: Literal["apktool", "androguard"]
) -> List[Dict[str, str]]:
    """
    Extract suspicious strings from either:
    - Decompiled folder (apktool)
    - APK binary via Androguard
    """
    results = []
    seen_matches = set()

    if backend == "apktool":
        if not source.exists():
            logger.error(f"[STRING EXTRACTOR] Path does not exist: {source}")
            return results

        for file in source.rglob("*"):
            if not file.is_file() or file.suffix.lower() not in ANALYZED_EXTENSIONS:
                continue

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
                        "file": str(file.relative_to(source)),
                        "type": label,
                        "match": match,
                        "entropy": round(entropy, 2),
                        "confidence": classify_confidence(entropy)
                    })

    elif backend == "androguard":
        try:
            _, dalvik_vms, _ = AnalyzeAPK(str(source))
            all_strings = set()
            
            for dvm in dalvik_vms:
                try:
                    all_strings.update(dvm.get_strings())
                except Exception as ex:
                    logger.warning(f"[STRING EXTRACTOR] Failed to extract strings from DEX: {ex}")

            for s in all_strings:
                if not s or not any(c.isalnum() for c in s):
                    continue
                
                for label, pattern in SUSPICIOUS_PATTERNS:
                        for match in re.findall(pattern, s):
                            if (label, match) in seen_matches:
                                continue
                            seen_matches.add((label, match))
                            entropy = string_entropy(match)
                            results.append({
                                "file": "classes.dex",
                                "type": label,
                                "match": match,
                                "entropy": round(entropy, 2),
                                "confidence": classify_confidence(entropy)
                            })
            
        except Exception as ex:
            logger.warning(f"[STRING EXTRACTOR] Failed to extract strings via Androguard: {ex}")

    logger.info(f"[STRING EXTRACTOR] Found {len(results)} suspicious strings.")
    return results
