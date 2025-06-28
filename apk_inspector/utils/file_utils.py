
from ipaddress import ip_address
from datetime import datetime
from copy import deepcopy
from datetime import timezone
from apk_inspector.utils.logger import get_logger

logger = get_logger()

NOISE_THRESHOLD = 20

def is_private_ip(ip_str):
    try:
        ip = ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        logger.warning(f"[IP Check] Invalid IP: {ip_str}")
        return False

def fingerprint(event):
    cat = event.get("category", "")
    if cat == "filesystem" and event.get("path"):
        return f"fs:{event['path']}"
    if "ip" in event:
        return f"net:{event.get('action')}:{event['ip']}:{event.get('port', '')}"
    return f"{event.get('action')}:{cat}"

def deduplicate_events(events):
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
