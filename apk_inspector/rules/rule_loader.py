import yaml
from pathlib import Path
from typing import List
from apk_inspector.rules.rule_utils import safe_lambda
from apk_inspector.rules.rule_engine import Rule
from apk_inspector.utils.logger import get_logger

logger = get_logger()

def load_rules_from_yaml(yaml_path: Path) -> List[Rule]:
    with yaml_path.open(encoding="utf-8") as f:
        raw_rules = yaml.safe_load(f)

    rules = []
    for entry in raw_rules:
        rule_id = entry.get("id", "UNKNOWN")
        try:
            # Build the safe lambda
            condition_fn = safe_lambda(entry["condition"])

            # Dry run on dummy input
            test_event = {"data": "example.com"}
            _ = condition_fn(test_event)

            rule = Rule(
                id=entry["id"],
                description=entry["description"],
                category=entry["category"],
                weight=entry["weight"],
                condition=condition_fn,
                tags=entry.get("tags", []),
                cvss=entry.get("cvss", 0.0),
                severity=entry.get("severity", "medium"),
                disabled=False
            )
        except Exception as e:
            logger.warning(f"[!] Rule {rule_id} disabled due to error: {e}")
            rule = Rule(
                id=entry.get("id", "UNKNOWN"),
                description=entry.get("description", "Invalid rule"),
                category=entry.get("category", "uncategorized"),
                weight=0,
                condition=lambda e: False,  # Always false
                tags=entry.get("tags", []),
                cvss=0.0,
                severity="low",
                disabled=True
            )

        rules.append(rule)

    logger.info(f"[✓] Loaded {len(rules)} rules ({sum(1 for r in rules if r.disabled)} disabled)")
    return rules
