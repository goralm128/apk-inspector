from collections import Counter
from typing import List, Dict


class JustificationAnalyzer:
    def __init__(self, justifications: List[Dict]):
        self.justifications = justifications or []

    def top_tags(self, n: int = 5) -> List[str]:
        tag_counter = Counter()
        for j in self.justifications:
            tags = j.get("tag_matches", [])
            if isinstance(tags, list):
                tag_counter.update(tags)
        return [t for t, _ in tag_counter.most_common(n)]

    def top_sources(self, n: int = 5) -> List[str]:
        src_counter = Counter(
            j.get("source", "unknown")
            for j in self.justifications
            if isinstance(j, dict) and j.get("source")
        )
        return [s for s, _ in src_counter.most_common(n)]

    def top_classifications(self, n: int = 5) -> List[str]:
        classification_counter = Counter(
            j.get("classification", "unknown")
            for j in self.justifications
        )
        return [cls for cls, _ in classification_counter.most_common(n)]

    def classification_distribution(self) -> Dict[str, int]:
        return dict(Counter(j.get("classification", "unknown") for j in self.justifications))
