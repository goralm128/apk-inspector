from apk_inspector.analysis.static.manifest_analyzer import analyze_manifest
from apk_inspector.analysis.static.string_extractor import extract_suspicious_strings
from apk_inspector.analysis.static.cert_analyzer import analyze_certificate
from apk_inspector.analysis.static.static_runner import run_static_analysis
from pathlib import Path
import tempfile
import shutil

def test_manifest_analysis_valid():
    manifest_file = Path("tests/sample/decompiled/AndroidManifest.xml")
    result = analyze_manifest(manifest_file)
    assert "permissions" in result
    assert isinstance(result["permissions"], list)

def test_string_extraction_on_known_input():
    smali_file = Path("tests/sample/MainActivity.smali")
    matches = extract_suspicious_strings(smali_file.parent)
    assert any("http" in m["pattern"] for m in matches)

def test_certificate_analysis_fake_apk():
    apk_file = Path("tests/sample/fake.apk")  # Create or mock this
    result = analyze_certificate(apk_file)
    assert isinstance(result, dict)
    assert "valid" in result

def test_static_runner_combines_all():
    apk = Path("tests/sample/fake.apk")
    decompiled = Path("tests/sample/decompiled/")
    result = run_static_analysis(apk, decompiled)
    assert "manifest_analysis" in result
    assert "string_matches" in result
    assert "certificate" in result
