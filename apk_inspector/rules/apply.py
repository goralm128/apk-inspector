from typing import List, Tuple, Dict, Any

def apply_rules(events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    total_score = 0
    reasons = []
    for event in events:
        for rule in rules:
            try:
                if eval(rule['condition'], {"event": event}):
                    total_score += rule.get("weight", 0)
                    reasons.append(rule.get("description", "Triggered rule"))
            except Exception as e:
                # Optional: log evaluation error
                continue
    return total_score, reasons

