import jsonschema
import yaml
from pathlib import Path

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
        print(f"[✓] {yaml_path.name} is valid with {len(rules)} rules.")
    except jsonschema.exceptions.ValidationError as ve:
        print(f"[ERROR] Rule schema validation failed: {ve.message}")
        raise
    except yaml.YAMLError as ye:
        print(f"[ERROR] Invalid YAML syntax: {ye}")
        raise
