from apk_inspector.static_analysis.manifest_analyzer import analyze_manifest
from apk_inspector.static_analysis.string_extractor import extract_suspicious_strings
from apk_inspector.static_analysis.cert_analyzer import analyze_certificate
from pathlib import Path

def run_static_analysis(apk_path: Path, decompiled_path: Path) -> dict:
    manifest = analyze_manifest(decompiled_path / "AndroidManifest.xml")
    strings = extract_suspicious_strings(decompiled_path)
    cert = analyze_certificate(apk_path)

    return {
        "manifest_analysis": manifest,
        "string_matches": strings,
        "certificate": cert
    }
