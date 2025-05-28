from xml.etree import ElementTree as ET
from pathlib import Path
from typing import List, Dict

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Dangerous permissions (can be extended later)
DANGEROUS_KEYWORDS = {"SMS", "CONTACT", "LOCATION", "CAMERA", "MICROPHONE", "CALL", "PHONE", "RECORD_AUDIO"}

def get_android_attrib(elem: ET.Element, name: str) -> str:
    return elem.attrib.get(f"{{{ANDROID_NS}}}{name}", "")

def extract_permissions(root: ET.Element) -> List[str]:
    return [
        get_android_attrib(perm, "name")
        for perm in root.findall("uses-permission")
        if get_android_attrib(perm, "name")
    ]

def identify_dangerous_permissions(permissions: List[str]) -> List[str]:
    return [p for p in permissions if any(keyword in p.upper() for keyword in DANGEROUS_KEYWORDS)]

def extract_components(root: ET.Element) -> Dict[str, List[Dict]]:
    tag_map = {
        "activities": "activity",
        "services": "service",
        "receivers": "receiver",
        "providers": "provider"
    }

    components = {}

    for group_name, tag_name in tag_map.items():
        components[group_name] = []
        for elem in root.findall(f".//{tag_name}"):
            comp = {
                "name": get_android_attrib(elem, "name"),
                "exported": get_android_attrib(elem, "exported") == "true",
                "intent_filters": []
            }
            for intent in elem.findall("intent-filter"):
                actions = [
                    get_android_attrib(a, "name")
                    for a in intent.findall("action")
                    if get_android_attrib(a, "name")
                ]
                comp["intent_filters"].extend(actions)
            components[group_name].append(comp)

    return components

def analyze_manifest(manifest_path: Path) -> dict:
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = extract_permissions(root)
        dangerous_perms = identify_dangerous_permissions(permissions)
        components = extract_components(root)

        return {
            "permissions": permissions,
            "dangerous_permissions": dangerous_perms,
            "components": components
        }

    except Exception as e:
        print(f"[ERROR] Failed to parse AndroidManifest.xml: {e}")
        return {}
