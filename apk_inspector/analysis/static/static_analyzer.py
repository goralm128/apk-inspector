from pathlib import Path
from apk_inspector.analysis.static.manifest_analyzer import analyze_manifest
from apk_inspector.analysis.static.string_extractor import extract_suspicious_strings
from apk_inspector.analysis.static.cert_analyzer import analyze_certificate
from apk_inspector.core.decompiler import decompile_apk

class StaticAnalyzer:
    def __init__(self, report_saver, logger):
        self.report_saver = report_saver
        self.logger = logger

    def analyze(self, apk_path: Path) -> dict:
        package_name = apk_path.stem
        self.logger.info(f"[{package_name}] Running static analysis.")

        # Decompile and extract
        decompiled_path = self.report_saver.get_decompile_path(package_name)
        decompile_apk(apk_path, decompiled_path)

        manifest = analyze_manifest(decompiled_path / "AndroidManifest.xml")
        strings = extract_suspicious_strings(decompiled_path)
        cert = analyze_certificate(apk_path)

        static_report = {
            "manifest_analysis": manifest,
            "string_matches": strings,
            "certificate": cert
        }

        self.logger.debug(f"[{package_name}] Static analysis complete.")
        return static_report
