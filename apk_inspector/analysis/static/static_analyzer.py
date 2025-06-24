from pathlib import Path
from apk_inspector.analysis.static.manifest_analyzer import analyze_manifest
from apk_inspector.analysis.static.string_extractor import extract_suspicious_strings
from apk_inspector.analysis.static.cert_analyzer import analyze_certificate
from apk_inspector.analysis.static.res_parser import analyze_strings_xml
from apk_inspector.analysis.static.log_scanner import scan_logs_for_secrets
from apk_inspector.analysis.static.static_analysis_result import StaticAnalysisResult

class StaticAnalyzer:
    def __init__(self, logger):
        self.logger = logger

    def analyze(self, apk_path: Path, decompiled_path: Path) -> StaticAnalysisResult:
        package_name = apk_path.stem
        self.logger.info(f"[{package_name}] Running static analysis.")

        if not decompiled_path.exists():
            self.logger.error(f"[{package_name}] Decompiled path does not exist: {decompiled_path}")
            return StaticAnalysisResult()

        # Analyze AndroidManifest.xml, extract permissions and components
        manifest_result = analyze_manifest(decompiled_path / "AndroidManifest.xml")
        manifest_warnings = manifest_result.pop("manifest_warnings", [])
        
        # Extract suspicious strings from smali files
        suspicious_strings = extract_suspicious_strings(decompiled_path)
        string_warnings = [
            {
                "type": "suspicious_string",
                "message": f"{s['type']} match: {s['match']}",
                "file": s["file"],
                "confidence": s["confidence"]
            }
            for s in suspicious_strings if s["confidence"] in ("high", "medium")
        ]
        
        # Analyze the APK certificate
        cert_info  = analyze_certificate(apk_path)
        cert_warnings = []
        if cert_info.get("debug_cert"):
            cert_warnings.append({"type": "debug_cert", "message": "Signed with debug certificate"})
        if cert_info.get("uses_sha1"):
            cert_warnings.append({"type": "weak_signature", "message": "Uses SHA1 — weak signature algorithm"})
        if cert_info.get("has_expired_cert"):
            cert_warnings.append({"type": "expired_cert", "message": "Certificate is expired"})

        static_warnings = manifest_warnings + string_warnings + cert_warnings

        # Analyze res/values/strings.xml
        self.logger.info(f"[{package_name}] Analyzing strings.xml for sensitive data.")
        strings_xml_path = decompiled_path / "res" / "values" / "strings.xml"
        strings_xml_issues = []
        if strings_xml_path.exists():
            self.logger.info(f"[{package_name}] Analyzing strings.xml for sensitive data.")
            strings_xml_issues = analyze_strings_xml(strings_xml_path)
            
        # Scan logs for sensitive information
        self.logger.info(f"[{package_name}] Scanning logs for secrets.")
        log_secrets = scan_logs_for_secrets(decompiled_path)

        self.logger.debug(f"[{package_name}] Static analysis complete.")
        
        return StaticAnalysisResult(
            manifest_analysis=manifest_result,
            static_warnings=static_warnings,
            string_matches=suspicious_strings,
            certificate=cert_info,
            strings_xml_issues=strings_xml_issues,
            log_leaks=log_secrets
        )

