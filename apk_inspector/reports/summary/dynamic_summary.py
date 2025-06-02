from typing import List, Dict, Any

def is_high_risk_event(event: Dict[str, Any]) -> bool:
    hook = event.get("hook", "")
    metadata = event.get("metadata", {})
    category = metadata.get("category", "")
    sensitive = metadata.get("sensitive", False)

    high_risk_hooks = {
        "execve", "fork", "system", "dlopen", "popen",
        "CreateProcessW", "AccessibilityService",
        "AccessibilityNodeInfo.performAction", "Class.forName", "Method.invoke"
    }

    high_risk_categories = {"accessibility_abuse", "native_injection", "reflection"}

    return (
        sensitive or
        hook in high_risk_hooks or
        category in high_risk_categories
    )


def summarize_dynamic_events(events: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "total_events": len(events),
        "high_risk_events": 0,
        "network_connections": 0,
        "file_operations": 0,
        "crypto_operations": 0,
        "reflection_usage": 0,
        "native_code_usage": 0,
        "accessibility_service_usage": 0
    }

    for e in events:
        metadata = e.get("metadata", {})
        category = metadata.get("category", "")
        
        if category == "network":
            summary["network_connections"] += 1
        elif category == "filesystem":
            summary["file_operations"] += 1
        elif category == "crypto_usage":
            summary["crypto_operations"] += 1
        elif category == "reflection":
            summary["reflection_usage"] += 1
        elif category == "native_injection":
            summary["native_code_usage"] += 1
        elif category == "accessibility_abuse":
            summary["accessibility_service_usage"] += 1

    return summary
