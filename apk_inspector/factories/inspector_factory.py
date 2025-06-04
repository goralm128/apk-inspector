from pathlib import Path
from apk_inspector.core.apk_inspector import APKInspector
from apk_inspector.core.apk_manager import APKManager
from apk_inspector.analysis.yara_scanner import YaraScanner
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.rules.rule_loader import load_rules_from_yaml 
from apk_inspector.rules.rule_utils import validate_rules_yaml
from apk_inspector.analysis.static.static_analyzer import StaticAnalyzer
from apk_inspector.reports.report_builder import APKReportBuilder
from apk_inspector.utils.logger import get_logger
from apk_inspector.core.workspace_manager import WorkspaceManager
from apk_inspector.config.defaults import DEFAULT_RULES_PATH, DEFAULT_SCORING_PROFILE_PATH


def create_apk_inspector(
    apk_path: Path,
    hooks_dir: Path,
    run_dir: Path,
    verbose: bool = False,
    yara_rules_path: Path = Path("yara_rules"),
    rule_yaml_path: Path = DEFAULT_RULES_PATH,
    timeout: int = 120
) -> APKInspector:
    """
    Factory to configure and return an APKInspector instance.
    """

    # Logger
    logger = get_logger()

    logger.info(f"Creating APKInspector with run dir {run_dir} and APK path {apk_path}")
    workspace = WorkspaceManager(run_dir=run_dir)

    # APK manager to extract package name
    apk_manager = APKManager(logger=logger)
    package_name = apk_manager.get_package_name(apk_path)

    # Analyzer components
    static_analyzer = StaticAnalyzer(logger=logger)
    yara_scanner = YaraScanner(rules_dir=yara_rules_path)

    # Rule engine
    validate_rules_yaml(rule_yaml_path)
    rules = load_rules_from_yaml(rule_yaml_path)
    rule_engine = RuleEngine(rules, scoring_profile_path=DEFAULT_SCORING_PROFILE_PATH)

    # Builder
    report_builder = APKReportBuilder(package=package_name, apk_path=apk_path, rule_engine=rule_engine)

    # Compose inspector
    return APKInspector(
        apk_path=apk_path,
        hooks_dir=hooks_dir,
        static_analyzer=static_analyzer,
        yara_scanner=yara_scanner,
        rule_engine=rule_engine,
        report_builder=report_builder,
        workspace=workspace,
        logger=logger,
        timeout=timeout
    )
