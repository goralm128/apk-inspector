from typing import Dict, List, Any
from apk_inspector.analysis.tag_inferencer.base import BaseTagInferencer

class ManifestTagInferencer(BaseTagInferencer):
    def __init__(self):
        self.permission_tags = {
            "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility",
            "android.permission.SYSTEM_ALERT_WINDOW": "overlay",
            "android.permission.QUERY_ALL_PACKAGES": "privilege",
            "android.permission.SEND_SMS": "exfiltration",
            "android.permission.READ_SMS": "exfiltration",
            "android.permission.RECEIVE_SMS": "exfiltration",
        }

    def infer_tags(self, manifest_analysis: Dict[str, Any]) -> List[str]:
        tags = []

        for perm in manifest_analysis.get("suspicious_permissions", []):
            if perm in self.permission_tags:
                tags.append(self.permission_tags[perm])

        if manifest_analysis.get("has_accessibility_service"):
            tags.append("accessibility")
        if manifest_analysis.get("is_obfuscated_package"):
            tags.append("obfuscation")
        if manifest_analysis.get("risky_components"):
            tags.append("privilege")

        return list(set(tags))
