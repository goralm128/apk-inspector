import subprocess
import re
from pathlib import Path

def extract_cert_field(output: str, field: str) -> str:
    match = re.search(f"{field}: (.+)", output)
    return match.group(1).strip() if match else None

def analyze_certificate(apk_path: Path) -> dict:
    try:
        cmd = ["keytool", "-printcert", "-jarfile", str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        output = result.stdout
        suspicious = "CN=Android Debug" in output or "Signature algorithm: SHA1" in output

        return {
            "valid": result.returncode == 0,
            "debug_cert": "CN=Android Debug" in output,
            "uses_sha1": "Signature algorithm: SHA1" in output,
            "issuer": extract_cert_field(output, "Owner"),
            "valid_from": extract_cert_field(output, "Valid from"),
            "valid_to": extract_cert_field(output, "Valid until"),
            "sha256_fingerprint": extract_cert_field(output, "SHA256"),
            "raw_output": output if suspicious else None
        }

    except Exception as e:
        print(f"[ERROR] Certificate analysis failed: {e}")
        return {}
