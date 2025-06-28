from pathlib import Path
from typing import List
import yaml

from apk_inspector.rules.rule_utils import safe_lambda, validate_rule_schema, SafeEvent
from apk_inspector.rules.rule_engine import Rule
from apk_inspector.utils.logger import get_logger

logger = get_logger()

def load_rules_from_yaml(yaml_path: Path) -> List[Rule]:
    try:
        with yaml_path.open(encoding="utf-8") as f:
            raw_rules = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"[load_rules_from_yaml] Failed to load YAML: {e}")
        return []

    if not isinstance(raw_rules, list):
        logger.error(f"[✗] Expected list of rules in {yaml_path}, got: {type(raw_rules).__name__}")
        return []

    rules: List[Rule] = []
    skipped = 0
    test_event = SafeEvent({
        "data": "",
        "tags": [],
        "path": "",
        "hook": "",
        "category": "",
        "metadata": {"cert_pinning": False},
        "args": {"arg0": ""},
        "stack": "",
        "event": "",
        "length": 0,
        "path_type": "",
        "address": {"is_private": True},
    })

    for entry in raw_rules:
        rule_id = entry.get("id", "UNKNOWN")

        if not validate_rule_schema(entry):
            logger.warning(f"[!] Rule {rule_id} skipped: missing required fields")
            skipped += 1
            continue

        entry.setdefault("tags", [])
        entry.setdefault("cvss", 0.0)
        entry.setdefault("severity", "medium")

        try:
            condition_fn = safe_lambda(entry["condition"], rule_id=rule_id)
            _ = condition_fn(test_event)  # test run

            rule = Rule(
                id=entry["id"],
                description=entry["description"],
                category=entry["category"],
                weight=entry["weight"],
                condition=condition_fn,
                tags=entry["tags"],
                cvss=entry["cvss"],
                severity=entry["severity"],
                disabled=False
            )
            rules.append(rule)

        except Exception as ex:
            logger.warning(f"[!] Rule {rule_id} error: {ex} → {entry.get('condition')}")
            skipped += 1
            continue

    logger.info(f"[✓] Loaded {len(rules)} rules ({skipped} skipped)")
    return rules
