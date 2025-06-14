from typing import Dict, List, Any
import json

import re

class TagInferencer:
    def __init__(self, tag_rules: Dict[str, List[str]], use_regex: bool = True):
        self.tag_rules = tag_rules
        self.use_regex = use_regex

    def infer_tags(self, event: Dict[str, Any]) -> List[str]:
        inferred_tags = []
        event_str = json.dumps(event, default=str).lower()

        for tag, patterns in self.tag_rules.items():
            for pattern in patterns:
                if self.use_regex:
                    if re.search(pattern, event_str):
                        inferred_tags.append(tag)
                        break
                else:
                    if pattern in event_str:
                        inferred_tags.append(tag)
                        break

        return list(set(inferred_tags))

