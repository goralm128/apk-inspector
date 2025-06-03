from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent         # → apk_inspector/
ROOT_DIR = BASE_DIR.parent                                # → project root
RULES_DIR = BASE_DIR / "rules"                            # → apk_inspector/rules
CONFIG_DIR = BASE_DIR / "config"                          # → apk_inspector/config
CONFIG_RULES_DIR = ROOT_DIR / "rule_configs"              # → rule_configs/

# Defaults
DEFAULT_RULES_PATH = CONFIG_RULES_DIR / "rules.yaml"      # → rule_configs/rules.yaml
DEFAULT_SCORING_PROFILE_PATH = CONFIG_DIR / "scoring_profile.yaml"
DEFAULT_REPORT_DIR = ROOT_DIR / "reports"                 # adjust if reports/ is elsewhere

DEFAULT_DYNAMIC_SUMMARY = {
    "total_events": 0,
    "high_risk_events": 0,
    "network_connections": 0,
    "file_operations": 0,
    "crypto_operations": 0,
    "reflection_usage": 0,
    "native_code_usage": 0,
    "accessibility_service_usage": 0
}

