import subprocess
import re
from pathlib import Path
from datetime import datetime, timezone
from apk_inspector.utils.logger import get_logger

logger = get_logger()

WEAK_ALGOS = {"SHA1", "MD5"}
DEBUG_CN_PATTERN = re.compile(r"CN=Android Debug")

def extract_cert_field(output: str, field: str) -> str:
    match = re.search(f"{field}: (.+)", output)
    return match.group(1).strip() if match else None

def parse_date(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, "%a %b %d %H:%M:%S %Z %Y")
    except Exception:
        return None

def analyze_certificate(apk_path: Path) -> dict:
    try:
        cmd = ["keytool", "-printcert", "-jarfile", str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout
        cert_blocks = output.strip().split("Owner:")

        parsed_certs = []
        now = datetime.now(timezone.utc)
        weak_algo_found = False
        debug_cert_found = False
        expired = False

        for block in cert_blocks:
            if not block.strip():
                continue
            owner = extract_cert_field(block, "Owner")
            valid_from = extract_cert_field(block, "Valid from")
            valid_to = extract_cert_field(block, "Valid until")
            sig_algo = extract_cert_field(block, "Signature algorithm")
            fingerprint = extract_cert_field(block, "SHA256")

            valid_from_dt = parse_date(valid_from)
            valid_to_dt = parse_date(valid_to)

            weak = any(algo in sig_algo.upper() for algo in WEAK_ALGOS) if sig_algo else False
            debug = bool(DEBUG_CN_PATTERN.search(owner or ""))
            expired_cert = valid_to_dt and valid_to_dt < now

            weak_algo_found |= weak
            debug_cert_found |= debug
            expired |= expired_cert

            parsed_certs.append({
                "owner": owner,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "signature_algorithm": sig_algo,
                "sha256_fingerprint": fingerprint,
                "is_debug_cert": debug,
                "is_weak_algo": weak,
                "is_expired": expired_cert
            })

        return {
            "valid": result.returncode == 0,
            "cert_chain": parsed_certs,
            "chain_length": len(parsed_certs),
            "uses_sha1": weak_algo_found,
            "debug_cert": debug_cert_found,
            "has_expired_cert": expired,
            "raw_output": output if debug_cert_found or weak_algo_found or expired else None
        }

    except Exception as ex:
        logger.error(f"[CERT ANALYZER] Failed to analyze certificate for {apk_path}: {ex}")
        return {}
