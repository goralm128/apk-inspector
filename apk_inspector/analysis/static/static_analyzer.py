from pathlib import Path
from apk_inspector.analysis.static.manifest_analyzer import analyze_manifest
from apk_inspector.analysis.static.string_extractor import extract_suspicious_strings
from apk_inspector.analysis.static.cert_analyzer import analyze_certificate

class StaticAnalyzer:
    def __init__(self, report_saver, logger):
        self.report_saver = report_saver
        self.logger = logger

    def analyze(self, apk_path: Path, decompiled_path: Path) -> dict:
        package_name = apk_path.stem
        self.logger.info(f"[{package_name}] Running static analysis.")

        if not decompiled_path.exists():
            self.logger.error(f"[{package_name}] Decompiled path does not exist: {decompiled_path}")
            return {}

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

