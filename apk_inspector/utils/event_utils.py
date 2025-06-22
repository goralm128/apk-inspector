from typing import List, Dict, Tuple
from datetime import datetime, timedelta
from collections import defaultdict


def _collapse_group(events: List[Dict[str, any]]) -> Dict[str, any]:
    """
    Collapse a group of similar events into a single one with a count field.
    Assumes all events in the group are of the same type.
    """
    base = dict(events[0])  # clone to avoid mutating input
    base["metadata"] = dict(base.get("metadata", {}))
    base["metadata"]["count"] = len(events)
    return base


def aggregate_events(events: List[Dict[str, any]], window_ms: int = 100) -> List[Dict[str, any]]:
    """
    Groups events that share the same (action, name, fd, category)
    within a given time window (default 100ms).

    Args:
        events: List of event dicts (typically from Frida).
        window_ms: Maximum time window to aggregate within (in milliseconds).

    Returns:
        Aggregated list of event dicts.
    """
    if not events:
        return []

    # Ensure all timestamps are datetime objects
    for e in events:
        ts = e.get("timestamp")
        if isinstance(ts, str):
            e["timestamp"] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        elif ts is None:
            # Assign current time if timestamp is missing
            e["timestamp"] = datetime.utcnow()

    # Group by (action, name, fd, category)
    grouped: Dict[Tuple, List[Dict[str, any]]] = defaultdict(list)
    result = []

    events.sort(key=lambda e: e["timestamp"])

    prev_key = None
    prev_time = None

    for event in events:
        md = event.get("metadata", {})
        key = (event["action"], md.get("name"), md.get("fd"), md.get("category"))

        now = event["timestamp"]
        if prev_key == key and prev_time and (now - prev_time) <= timedelta(milliseconds=window_ms):
            grouped[key].append(event)
        else:
            # Flush the last group
            if prev_key and grouped[prev_key]:
                result.append(_collapse_group(grouped[prev_key]))
                grouped[prev_key] = []

            # Start new group
            grouped[key].append(event)
            prev_key = key
            prev_time = now

    # Flush remaining
    if prev_key and grouped[prev_key]:
        result.append(_collapse_group(grouped[prev_key]))

    return result
