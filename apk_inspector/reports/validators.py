
def validate_report_structure(report: dict) -> bool:
    """
    Placeholder: Checks if the report has minimum required keys.
    Replace with strict schema or Pydantic later if needed.
    """
    required_keys = {"apk_metadata", "static_analysis", "dynamic_analysis", "classification"}
    missing = required_keys - report.keys()
    return not missing
