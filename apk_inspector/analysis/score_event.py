
import json
import os
from typing import Dict, Any, Union, Tuple, List, TypedDict

# --- Configuration ---

CONFIG_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'event_score_map.json')

LABEL_MALICIOUS = "malicious"
LABEL_SUSPICIOUS = "suspicious"
LABEL_BENIGN = "benign"

THRESHOLD_MALICIOUS = 50
THRESHOLD_SUSPICIOUS = 20

LABEL_THRESHOLDS = [
    (LABEL_MALICIOUS, THRESHOLD_MALICIOUS),
    (LABEL_SUSPICIOUS, THRESHOLD_SUSPICIOUS)
]


# --- Types ---

class Justification(TypedDict):
    source: str
    category_score: int
    tags_score: int
    classification_bonus: int
    tag_matches: List[str]
    classification: str


# --- Load Config ---

if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"Missing scoring config: {CONFIG_PATH}")

with open(CONFIG_PATH, encoding='utf-8') as f:
    SCORE_MAP = json.load(f)

if not isinstance(SCORE_MAP, dict) or not SCORE_MAP:
    raise RuntimeError("SCORE_MAP is invalid or empty. Check event_score_map.json")


# --- Main Scoring Function ---

def score_event(
    event: Dict[str, Any],
    return_justification: bool = False
) -> Union[
    Tuple[int, str],
    Tuple[int, str, Justification]
]:
    score = 0

    # Base justification structure
    justification: Justification = {
        "source": event.get("source", ""),
        "category_score": 0,
        "tags_score": 0,
        "classification_bonus": 0,
        "tag_matches": [],
        "classification": event.get("classification", "")
    }

    # Source + category scoring
    category = event.get("category", "")
    source = event.get("source", "")
    if category and source:
        cat_score = SCORE_MAP.get(category, {}).get(source)
        if cat_score:
            score += cat_score
            justification["category_score"] = cat_score

    # Tag-based scoring
    for tag in event.get("tags", []):
        tag_score = SCORE_MAP.get("tags", {}).get(tag, 0)
        if tag_score:
            score += tag_score
            justification["tags_score"] += tag_score
            justification["tag_matches"].append(tag)

    # Classification bonus
    classification = event.get("classification", "")
    if isinstance(classification, str):
        cls_score = SCORE_MAP.get("classification_bonus", {}).get(classification, 0)
        if cls_score:
            score += cls_score
            justification["classification_bonus"] = cls_score

    # Labeling logic
    for label_name, threshold in LABEL_THRESHOLDS:
        if score >= threshold:
            label = label_name
            break
    else:
        label = LABEL_BENIGN

    if return_justification:
        return score, label, justification
    return score, label
