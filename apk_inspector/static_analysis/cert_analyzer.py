import subprocess
from pathlib import Path

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
            "raw_output": output if suspicious else None
        }

    except Exception as e:
        print(f"[ERROR] Certificate analysis failed: {e}")
        return {}
