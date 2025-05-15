import json
import ipaddress

def clear_output_file(path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("[]")

def write_results(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False
    
def deduplicate_events(events, drop_failed_recvfrom=True, drop_af_unix=True):
    seen = set()
    deduped = []

    for event in events:
        if drop_failed_recvfrom and event.get("event") == "recvfrom" and event.get("length") == -1:
            continue

        address = event.get("address", {})
        if drop_af_unix and address.get("family") == "AF_UNIX":
            continue

        # use `path` if available (e.g., from read/write events)
        key = (
            event.get("event"),
            event.get("fd"),
            event.get("path"),  # Use path instead of serialized address when available
            event.get("length"),
            event.get("data"),
        )

        if key not in seen:
            seen.add(key)
            deduped.append(event)

    return deduped
