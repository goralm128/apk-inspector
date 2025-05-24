from xml.etree import ElementTree as ET
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"

def get_attrib(elem, attrib_name):
    return elem.attrib.get(f"{{{ANDROID_NS}}}{attrib_name}", None)

def analyze_manifest(manifest_path: Path) -> dict:
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = [get_attrib(elem, "name") for elem in root.findall("uses-permission") if get_attrib(elem, "name")]

        components = {"activities": [], "services": [], "receivers": [], "providers": []}
        dangerous_perms = [p for p in permissions if any(k in p for k in ["SMS", "CONTACT", "LOCATION", "CAMERA"])]

        for tag in components:
            for elem in root.findall(f".//{tag[:-1]}"):  # activity/service/receiver/provider
                entry = {
                    "name": get_attrib(elem, "name"),
                    "exported": get_attrib(elem, "exported") == "true",
                    "intent_filters": []
                }
                for intent in elem.findall("intent-filter"):
                    actions = [get_attrib(a, "name") for a in intent.findall("action") if get_attrib(a, "name")]
                    entry["intent_filters"].extend(actions)
                components[tag].append(entry)

        return {
            "permissions": permissions,
            "dangerous_permissions": dangerous_perms,
            "components": components
        }

    except Exception as e:
        print(f"[ERROR] Failed to parse AndroidManifest.xml: {e}")
        return {}
