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
        # Extract suspicious strings from smali files
        suspicious_strings = extract_suspicious_strings(decompiled_path)
        # Analyze the APK certificate
        cert_info  = analyze_certificate(apk_path)

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
            string_matches=suspicious_strings,
            certificate=cert_info,
            strings_xml_issues=strings_xml_issues,
            log_leaks=log_secrets
        )

