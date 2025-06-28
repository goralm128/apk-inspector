import ast
import jsonschema
import yaml
from pathlib import Path
from collections import defaultdict
from apk_inspector.utils.logger import get_logger

logger = get_logger()

# Safe built-ins for condition evaluation
SAFE_BUILTINS = {
    "any": any,
    "all": all,
    "len": len,
    "sum": sum,
    "min": min,
    "max": max,
    "sorted": sorted,
    "set": set,
    "str": str,
    "int": int,
    "float": float,
    "bool": bool
}

# JSON schema for validating rules.yaml structure
RULES_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["id", "description", "category", "weight", "condition", "tags", "cvss", "severity"],
        "properties": {
            "id": {"type": "string"},
            "description": {"type": "string"},
            "category": {"type": "string"},
            "weight": {"type": "integer", "minimum": 0},
            "condition": {"type": "string"},
            "tags": {
                "type": "array",
                "items": {"type": "string"}
            },
            "cvss": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 10.0
            },
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"]
            }
        },
        "additionalProperties": False
    }
}

def validate_rules_yaml(yaml_path: Path) -> None:
    """
    Validates rules.yaml against RULES_SCHEMA.
    Raises on invalid format or schema mismatch.
    """
    try:
        content = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=content, schema=RULES_SCHEMA)
        logger.info(f"[✓] {yaml_path.name} is structurally valid with {len(content)} rules.")
    except jsonschema.ValidationError as ve:
        logger.error(f"[ERROR] Rule schema validation failed: {ve.message}")
        raise
    except yaml.YAMLError as ye:
        logger.error(f"[ERROR] Malformed YAML in {yaml_path.name}: {ye.problem_mark} – {ye.problem}")
        raise


def default_for_key(key):
    if key in {"tags", "stack"}:
        return []
    elif key in {"path", "hook", "event", "category", "data"}:
        return ""
    elif key == "metadata":
        return {"cert_pinning": False}
    elif key == "args":
        return {"arg0": ""}
    elif key == "address":
        return {"is_private": True}
    elif key == "length":
        return 0
    elif key == "path_type":
        return ""
    return None


class SafeEvent(dict):
    """Wraps event dict to return safe defaults (empty list/str/dict) on get."""
    def __getitem__(self, key):
        if key not in self:
            return wrap_value(default_for_key(key))
        return wrap_value(super().__getitem__(key))

    def get(self, key, default=None):
        return wrap_value(super().get(key, default_for_key(key)))


def wrap_value(val):
    if isinstance(val, dict):
        return SafeEvent({k: wrap_value(v) for k, v in val.items()})
    if isinstance(val, list):
        return [wrap_value(x) for x in val]
    return val


def safe_lambda(condition: str, rule_id: str = "unknown"):
    """
    Compiles a rule condition into a safe lambda function.
    Returns a lambda that evaluates the condition safely with default values.
    """
    try:
        ast.parse(condition, mode="eval")
    except SyntaxError as e:
        logger.error(f"[safe_lambda] Syntax error in rule {rule_id}: {condition} – {e}")
        return lambda event: False

    def func(event):
        try:
            if not isinstance(event, dict):
                return False
            safe_event = SafeEvent(event)
            return bool(eval(
                condition,
                {"__builtins__": None, **SAFE_BUILTINS},
                {"event": safe_event}
            ))
        except Exception as ex:
            logger.debug(f"[safe_lambda] Rule {rule_id}: {ex} – condition: {condition}")
            return False

    return func


def validate_rule_schema(rule_dict: dict) -> bool:
    """
    Quick check for minimal rule completeness before deeper validation.
    """
    required = {"id", "description", "category", "condition", "weight", "tags", "cvss", "severity"}
    missing = required - rule_dict.keys()
    if missing:
        logger.error(f"[validate_rule_schema] Missing fields in rule: {missing}")
        return False
    return True
