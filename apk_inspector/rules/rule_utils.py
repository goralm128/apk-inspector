import jsonschema
import yaml
from pathlib import Path
from apk_inspector.utils.logger import get_logger

logger = get_logger()

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


# Define the JSON schema for the rules.yaml file
# This schema is strict and requires all fields to be present and correctly typed.
RULES_SCHEMA = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["id", "description", "category", "weight", "condition", "tags", "cvss", "severity"],
        "properties": {
            "id": {"type": "string"},
            "description": {"type": "string"},
            "category": {"type": "string"},
            "weight": {"type": "number", "minimum": 0},
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
        }
    }
}

def validate_rules_yaml(yaml_path: Path) -> None:
    """
    Validates the rules.yaml file against a strict JSON schema.

    :param yaml_path: Path to the YAML rules file.
    :raises jsonschema.ValidationError: if the schema is invalid.
    :raises yaml.YAMLError: if YAML is malformed.
    """
    try:
        rules = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=rules, schema=RULES_SCHEMA)
        logger.info(f"[✓] {yaml_path.name} is valid with {len(rules)} rules.")
    except jsonschema.exceptions.ValidationError as ve:
        logger.error(f"[ERROR] Rule schema validation failed: {ve.message}")
        raise
    except yaml.YAMLError as ye:
        logger.error(f"[ERROR] Invalid YAML syntax in {yaml_path.name}: {ye}")
        raise


def safe_lambda(condition: str):
    def func(event):
        return eval(condition, {"__builtins__": None, **SAFE_BUILTINS}, {"event": event})
    return func

def validate_rule_schema(rule_dict: dict) -> bool:
    required = {"id", "description", "category", "condition", "weight"}
    return required.issubset(rule_dict.keys())


