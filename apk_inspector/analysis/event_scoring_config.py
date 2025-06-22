
import json
import os
from typing import List, TypedDict

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
