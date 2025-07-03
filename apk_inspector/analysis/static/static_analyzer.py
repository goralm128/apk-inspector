from pathlib import Path
from typing import Optional, Literal
from androguard.misc import AnalyzeAPK
from apk_inspector.analysis.static.manifest_analyzer import analyze_manifest
from apk_inspector.analysis.static.string_extractor import extract_suspicious_strings
from apk_inspector.analysis.static.cert_analyzer import analyze_certificate
from apk_inspector.analysis.static.res_parser import analyze_strings_xml
from apk_inspector.analysis.static.log_scanner import scan_logs_for_secrets
from apk_inspector.analysis.static.payload_scanner import find_suspicious_payloads
from apk_inspector.analysis.static.static_analysis_result import StaticAnalysisResult

class StaticAnalyzer:
    def __init__(self, logger):
        self.logger = logger

    def analyze(
        self,
        apk_path: Path,
        decompiled_path: Path,
        backend: Literal["apktool", "androguard"]
    ) -> StaticAnalysisResult:
        package_name = apk_path.stem
        self.logger.info(f"[{package_name}] Static analysis using {backend} backend")

        if not decompiled_path.exists():
            self.logger.error(f"[{package_name}] Decompiled path does not exist: {decompiled_path}")
            return StaticAnalysisResult()

        # --- Manifest Analysis ---
        manifest_result = analyze_manifest(decompiled_path / "AndroidManifest.xml")
        manifest_warnings = manifest_result.pop("manifest_warnings", [])

        # --- Suspicious Strings ---
        suspicious_strings = []
        suspicious_strings = extract_suspicious_strings(
            source=apk_path if backend == "androguard" else decompiled_path,
            backend=backend
        )

        string_warnings = [
            {
                "type": "suspicious_string",
                "message": f"{s['type']} match: {s['match']}",
                "file": s["file"],
                "confidence": s["confidence"]
            }
            for s in suspicious_strings if s["confidence"] in ("high", "medium")
        ]

        # --- Certificate Analysis ---
        cert_info = analyze_certificate(apk_path)
        cert_warnings = []
        if cert_info.get("debug_cert"):
            cert_warnings.append({"type": "debug_cert", "message": "Signed with debug certificate"})
        if cert_info.get("uses_sha1"):
            cert_warnings.append({"type": "weak_signature", "message": "Uses SHA1 — weak signature algorithm"})
        if cert_info.get("has_expired_cert"):
            cert_warnings.append({"type": "expired_cert", "message": "Certificate is expired"})
            
        payload_warnings = find_suspicious_payloads(decompiled_path, self.logger)

        static_warnings = manifest_warnings + string_warnings + cert_warnings + payload_warnings

        # --- Resource Strings (ApkTool only) ---
        strings_xml_issues = []
        if backend == "apktool":
            strings_xml_path = decompiled_path / "res" / "values" / "strings.xml"
            if strings_xml_path.exists():
                strings_xml_issues = analyze_strings_xml(strings_xml_path)

        # --- Log Scanner (ApkTool only) ---
        log_secrets = scan_logs_for_secrets(decompiled_path) if backend == "apktool" else []

        self.logger.debug(f"[{package_name}] Static analysis completed successfully.")

        return StaticAnalysisResult(
            manifest_analysis=manifest_result,
            static_warnings=static_warnings,
            string_matches=suspicious_strings,
            certificate=cert_info,
            strings_xml_issues=strings_xml_issues,
            log_leaks=log_secrets
        )
