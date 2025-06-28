from typing import List, Dict, Tuple
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from ipaddress import ip_address
from copy import deepcopy
from apk_inspector.utils.logger import get_logger

logger = get_logger()

NOISE_THRESHOLD = 20

# ───────────────────────────────────────────────
# IP Utilities
# ───────────────────────────────────────────────

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        logger.warning(f"[IP Check] Invalid IP: {ip_str}")
        return False

# ───────────────────────────────────────────────
# Event Deduplication & Fingerprinting
# ───────────────────────────────────────────────

def fingerprint(event: Dict[str, any]) -> str:
    cat = event.get("category", "")
    if cat == "filesystem" and event.get("path"):
        return f"fs:{event['path']}"
    if "ip" in event:
        return f"net:{event.get('action')}:{event['ip']}:{event.get('port', '')}"
    return f"{event.get('action')}:{cat}"

def deduplicate_events(events: List[Dict[str, any]]) -> List[Dict[str, any]]:
    seen = {}
    for event in events:
        key = fingerprint(event)
        now = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        score = event.get("score", 0)

        if key in seen:
            entry = seen[key]
            meta = entry.setdefault("metadata", {})
            meta["count"] += 1
            meta["last_seen"] = now
            entry["score"] = entry.get("score", 0) + score

            if "tags" in event:
                entry.setdefault("tags", [])
                entry["tags"] = list(set(entry["tags"]) | set(event["tags"]))

            if meta["count"] == NOISE_THRESHOLD:
                meta["noisy"] = True
                logger.debug(f"[Deduplication] Event '{key}' marked as noisy")

        else:
            cloned = deepcopy(event)
            meta = cloned.setdefault("metadata", {})
            meta["count"] = 1
            meta["first_seen"] = now
            meta["last_seen"] = now
            seen[key] = cloned

    return list(seen.values())

# ───────────────────────────────────────────────
# Event Aggregation
# ───────────────────────────────────────────────

def _collapse_group(events: List[Dict[str, any]]) -> Dict[str, any]:
    base = dict(events[0])
    base["metadata"] = dict(base.get("metadata", {}))
    base["metadata"]["count"] = len(events)
    return base

def aggregate_events(events: List[Dict[str, any]], window_ms: int = 100) -> List[Dict[str, any]]:
    if not events:
        return []

    for e in events:
        ts = e.get("timestamp")
        if isinstance(ts, str):
            e["timestamp"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif ts is None:
            e["timestamp"] = datetime.now(timezone.utc)

    grouped: Dict[Tuple, List[Dict[str, any]]] = defaultdict(list)
    result = []

    events.sort(key=lambda e: e["timestamp"])

    prev_key = None
    prev_time = None

    for event in events:
        key = (event["action"], event.get("path"), event.get("category"))
        now = event["timestamp"]
        if prev_key == key and prev_time and (now - prev_time) <= timedelta(milliseconds=window_ms):
            grouped[key].append(event)
        else:
            if prev_key and grouped[prev_key]:
                result.append(_collapse_group(grouped[prev_key]))
                grouped[prev_key] = []
            grouped[key].append(event)
            prev_key = key
            prev_time = now

    if prev_key and grouped[prev_key]:
        result.append(_collapse_group(grouped[prev_key]))

    return result
