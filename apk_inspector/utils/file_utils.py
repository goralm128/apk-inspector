import json
import logging
from pathlib import Path
from ipaddress import ip_address, ip_network

logger = logging.getLogger("APKInspector")

# ───────────────────────────────────────────────
# Utility: Check if an IP is private/local
# ───────────────────────────────────────────────

def is_private_ip(ip_str):
    try:
        ip = ip_address(ip_str)
        return ip.is_private
    except ValueError:
        logger.warning(f"Invalid IP address: {ip_str}")
        return False

# ───────────────────────────────────────────────
# Utility: Deduplicate captured events
# ───────────────────────────────────────────────

def deduplicate_events(events):
    seen = set()
    deduped = []
    for event in events:
        key = json.dumps(event, sort_keys=True)
        if key not in seen:
            deduped.append(event)
            seen.add(key)
    return deduped