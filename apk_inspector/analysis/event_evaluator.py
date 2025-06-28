from math import log2
from apk_inspector.reports.models import TriggeredRuleResult
from apk_inspector.utils.logger import get_logger
from apk_inspector.rules.rule_model import Rule

logger = get_logger()

class EventEvaluator:
    MAX_EVENT_SCORE = 100

    def __init__(self, rules, known_tags, severity_map, category_map, tag_score_map):
        self.rules = rules
        self.known_tags = known_tags
        self.severity_map = severity_map
        self.category_map = category_map
        self.tag_score_map = tag_score_map

    def evaluate_event(self, event):
        total_bonus = 0
        triggered_results = []
        matched_per_category = {}
        event_id = event.get("event_id", "<no-id>")

        for rule in self.rules:
            if rule.disabled:
                logger.debug(f"[Rule] Skipping disabled rule: {rule.id}")
                continue

            self._validate_rule(rule)

            try:
                if rule.condition(event):
                    cat = rule.category.lower()
                    matched_per_category.setdefault(cat, []).append(rule)
            except Exception as ex:
                logger.warning(f"[RuleEvaluator] Rule {rule.id} failed on event {event_id}: {ex}")

        for cat, rules in matched_per_category.items():
            count = len(rules)
            for rule in rules:
                base_score = self._calculate_bonus(rule)
                if base_score <= 0:
                    continue

                damp_factor = 1.0 / (1 + log2(count)) if count > 1 else 1.0
                dampened = int(base_score * damp_factor)
                capped = min(dampened, self.MAX_EVENT_SCORE - total_bonus)
                if capped <= 0:
                    continue

                total_bonus += capped

                result = TriggeredRuleResult(
                    rule_id=rule.id,
                    severity=rule.severity,
                    severity_score=self.severity_map.get(rule.severity.lower(), 0),
                    cvss=rule.cvss,
                    weight=rule.weight,
                    bonus=capped,
                    description=rule.description,
                    tags=rule.tags,
                    category=rule.category,
                    event_id=event_id,
                    rule_source="dynamic"
                )

                triggered_results.append(result)
                logger.debug(f"[RuleEvaluator] Triggered: {rule.id} → base={base_score}, dampened={dampened}, final={capped}")

        if not triggered_results:
            return None

        metadata = event.setdefault("metadata", {})
        metadata["triggered_rules"] = [r.rule_id for r in triggered_results]
        metadata["triggered_rule_details"] = [r.__dict__ for r in triggered_results]

        return total_bonus, triggered_results

    def _validate_rule(self, rule):
        unknown_tags = [t for t in rule.tags if t not in self.known_tags]
        if rule.category.lower() not in self.category_map:
            logger.debug(f"[RuleValidator] Unknown category: {rule.category} in rule {rule.id}")
        if unknown_tags:
            logger.debug(f"[RuleValidator] Unknown tags in rule {rule.id}: {unknown_tags}")

    def _calculate_bonus(self, rule):
        base = rule.weight
        sev_bonus = self.severity_map.get(rule.severity.lower(), 0)
        tag_bonus = sum(self.tag_score_map.get(t, 0) for t in rule.tags)
        cat_bonus = self.category_map.get(rule.category.lower(), 0)
        total = base + sev_bonus + tag_bonus + cat_bonus
        return total + int(rule.cvss) if rule.cvss > 0 else total
