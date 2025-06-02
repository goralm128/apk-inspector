from typing import List, Dict, Any
from apk_inspector.reports.models import YaraMatch

def convert_matches(matches: List[YaraMatch]) -> List[Dict[str, Any]]:
    """
    Convert YaraMatch objects to plain serializable dictionaries.
    """
    return [m.to_dict() for m in matches]
