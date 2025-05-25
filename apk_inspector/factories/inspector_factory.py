from pathlib import Path
from apk_inspector.core.core_controller import APKInspector
from apk_inspector.reports.report_saver import ReportSaver
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.core.yara_scanner import YaraScanner
from apk_inspector.rules.rule_loader import load_rules_from_yaml 
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.rules.rule_utils import validate_rules_yaml
from apk_inspector.analysis.static.static_analyzer import StaticAnalyzer
from apk_inspector.reports.report_builder import APKReportBuilder
from apk_inspector.utils.logger import setup_logger
from typing import Optional


def create_apk_inspector(
    apk_path: Path,
    hooks_dir: Path,
    output_dir: Path,
    verbose: bool = False,
    report_saver: Optional[ReportSaver] = None 
) -> APKInspector:
    """
    Factory to configure and return an APKInspector instance.
    """
    logger = setup_logger(verbose)
    report_saver = report_saver or ReportSaver(output_root=output_dir, logger=logger)
    apk_manager = APKManager(logger=logger)

    # Static and YARA tools
    static_analyzer = StaticAnalyzer(report_saver=report_saver, logger=logger)
    yara_scanner = YaraScanner(rules_dir=Path("yara_rules"))

    # Rules engine setup
    rules_path = Path("rule_configs/rules.yaml")
    validate_rules_yaml(rules_path)
    rules = load_rules_from_yaml(rules_path)
    rule_engine = RuleEngine(rules)

    # Create report builder
    pkg_name = apk_manager.get_package_name(apk_path)
    report_builder = APKReportBuilder(package=pkg_name, apk_path=apk_path)

    # Initialize inspector
    return APKInspector(
        static_analyzer=static_analyzer,
        yara_scanner=yara_scanner,
        rule_engine=rule_engine,
        report_builder=report_builder,
        report_saver=report_saver,
        apk_path=apk_path,
        hooks_dir=hooks_dir,
        logger=logger
    )
