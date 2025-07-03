from pathlib import Path
from typing import List
import logging

def find_suspicious_payloads(base_dir: Path, logger: logging.Logger, min_size_kb=10) -> List[dict]:
    suspicious_exts = {'.enc', '.dex', '.bin', '.dat'}
    min_size_bytes = min_size_kb * 1024
    warnings = []

    for file_path in base_dir.rglob("*"):
        if not file_path.is_file():
            continue

        ext = file_path.suffix.lower()
        size = file_path.stat().st_size

        if ext in suspicious_exts or size >= min_size_bytes:
            try:
                with file_path.open("rb") as f:
                    sample = f.read(512)
                entropy_score = sum(1 for b in sample if b > 127 or b == 0) / len(sample) if sample else 0
            except Exception as e:
                logger.warning(f"[PayloadScan] Failed to read {file_path}: {e}")
                entropy_score = 0

            warnings.append({
                "type": "suspicious_payload",
                "message": f"Suspicious file: {file_path.name}",
                "path": str(file_path.relative_to(base_dir)),
                "size": size,
                "entropy": round(entropy_score, 2),
                "confidence": "high" if ext in suspicious_exts and entropy_score > 0.6 else "medium"
            })

    return warnings
