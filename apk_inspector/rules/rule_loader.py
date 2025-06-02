import yaml
from pathlib import Path
from typing import List
from apk_inspector.rules.rule_utils import safe_lambda
from apk_inspector.rules.rule_engine import Rule  # make sure Rule is only a dataclass
from apk_inspector.utils.logger import get_logger

logger = get_logger()

def load_rules_from_yaml(yaml_path: Path) -> List[Rule]:
    with yaml_path.open(encoding="utf-8") as f:
        raw_rules = yaml.safe_load(f)

    rules = []
    for entry in raw_rules:
        try:
            rules.append(Rule(
                id=entry["id"],
                description=entry["description"],
                category=entry["category"],
                weight=entry["weight"],
                condition=safe_lambda(entry["condition"]),
                tags=entry.get("tags", []),
                cvss=entry.get("cvss", 0.0),
                severity=entry.get("severity", "medium"),
            ))
        except Exception as e:
            logger.error(f"Failed to load rule {entry.get('id', 'UNKNOWN')}: {e}")
            
    return rules
