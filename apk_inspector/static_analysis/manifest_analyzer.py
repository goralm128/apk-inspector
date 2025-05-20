from xml.etree import ElementTree as ET
from pathlib import Path

def analyze_manifest(manifest_path: Path) -> dict:
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = [elem.attrib["{http://schemas.android.com/apk/res/android}name"]
                       for elem in root.findall("uses-permission")]
        
        activities = [a.attrib.get("{http://schemas.android.com/apk/res/android}name", "unknown")
                      for a in root.findall(".//activity")]

        dangerous_perms = [p for p in permissions if "SMS" in p or "READ_CONTACTS" in p]

        return {
            "permissions": permissions,
            "dangerous_permissions": dangerous_perms,
            "activities": activities
        }

    except Exception as e:
        print(f"[ERROR] Failed to parse AndroidManifest.xml: {e}")
        return {}
