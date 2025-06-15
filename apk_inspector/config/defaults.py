from pathlib import Path

# ─── Directory Structure ─────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent         # → apk_inspector/
ROOT_DIR = BASE_DIR.parent                                # → project root
RULES_DIR = BASE_DIR / "rules"                            # → apk_inspector/rules
CONFIG_DIR = BASE_DIR / "config"                          # → apk_inspector/config
CONFIG_RULES_DIR = RULES_DIR / "rule_configs"             # → apk_inspector/rules/rule_configs

# ─── Default File Paths ─────────────────────────────────────
DEFAULT_RULES_PATH = CONFIG_RULES_DIR / "rules.yaml"      # → apk_inspector/rules/rule_configs/rules.yaml
DEFAULT_SCORING_PROFILE_PATH = CONFIG_DIR / "scoring_profile.yaml"
DEFAULT_REPORT_DIR = ROOT_DIR / "reports"                 # Update if reports are stored elsewhere
DEFAULT_APK_DIR = ROOT_DIR / "apks"


# ─── Dynamic Analysis Summary Defaults ──────────────────────
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

def get_apk_path(package_name: str) -> Path:
    return DEFAULT_APK_DIR / f"{package_name}.apk"
