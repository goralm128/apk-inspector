from collections import defaultdict
from typing import List, Dict
from apk_inspector.reports.models import TriggeredRuleResult

def summarize_triggered_rules(results: List[TriggeredRuleResult]) -> Dict[str, Dict[str, int]]:
    summary = defaultdict(lambda: defaultdict(int))

    for result in results:
        rule_id = result.rule_id
        severity = result.severity.lower()
        summary[rule_id][severity] += 1

    return {rid: dict(sev_map) for rid, sev_map in summary.items()}
