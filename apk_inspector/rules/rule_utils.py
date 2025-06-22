import ast
import jsonschema
import yaml
from pathlib import Path
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
        logger.error(f"[ERROR] Malformed YAML in {yaml_path.name}: {ye}")
        raise

def safe_lambda(condition: str):
    """
    Securely compiles and returns a lambda that evaluates 'condition' on an event dict.
    It parses the expression first, and wraps eval() with builtin safety and exception capture.
    """
    try:
        ast.parse(condition, mode="eval")
    except SyntaxError as e:
        logger.error(f"[safe_lambda] Syntax error in rule condition: {condition} – {e}")
        return lambda event: False

    def func(event):
        try:
            return bool(eval(condition, {"__builtins__": None, **SAFE_BUILTINS}, {"event": event}))
        except Exception as ex:
            logger.warning(f"[safe_lambda] Error evaluating rule condition: {ex} – {condition}")
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
