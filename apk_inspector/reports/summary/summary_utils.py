from collections import Counter

def _summarize_triggered_rules(rule_results: List[dict]) -> Dict[str, int]:
    return dict(Counter(r["rule_id"] for r in rule_results))