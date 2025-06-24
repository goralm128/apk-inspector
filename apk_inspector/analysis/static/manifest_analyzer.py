from xml.etree import ElementTree as ET
from pathlib import Path
from typing import List, Dict
import re

from apk_inspector.utils.logger import get_logger

logger = get_logger()

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Dangerous permissions 
ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS"
}

SUSPICIOUS_PERMISSIONS = {
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
}

HIGH_RISK_ACTIONS = {
    "android.provider.Telephony.SMS_RECEIVED",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.SEND",
    "android.intent.action.RESPOND_VIA_MESSAGE",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.QUICKBOOT_POWERON",
}

def get_android_attrib(elem: ET.Element, name: str) -> str:
    return elem.attrib.get(f"{{{ANDROID_NS}}}{name}", "")

def extract_permissions(root: ET.Element) -> List[str]:
    return [
        get_android_attrib(perm, "name")
        for perm in root.findall("uses-permission")
        if get_android_attrib(perm, "name")
    ]

def identify_dangerous_permissions(permissions: List[str]) -> List[str]:
    return [p for p in permissions if p in ANDROID_DANGEROUS_PERMISSIONS]

def identify_suspicious_permissions(permissions: List[str]) -> List[str]:
    return [p for p in permissions if p in SUSPICIOUS_PERMISSIONS]

def is_obfuscated_package(package_name: str) -> bool:
    return bool(re.fullmatch(r'[a-z]+\.[a-z0-9]{10,}\.[a-z0-9]{10,}', package_name))

def detect_accessibility_service(root: ET.Element) -> bool:
    for service in root.findall(".//service"):
        permission = get_android_attrib(service, "permission")
        if permission == "android.permission.BIND_ACCESSIBILITY_SERVICE":
            for intent in service.findall("intent-filter"):
                for action in intent.findall("action"):
                    if get_android_attrib(action, "name") == "android.accessibilityservice.AccessibilityService":
                        return True
    return False

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

def identify_exposed_risky_components(components: Dict[str, List[Dict]]) -> List[Dict]:
    risky = []
    for group in components.values():
        for comp in group:
            if comp["exported"] and any(a in HIGH_RISK_ACTIONS for a in comp["intent_filters"]):
                risky.append(comp)
    return risky

def extract_manifest_warnings(root: ET.Element) -> List[Dict[str, str]]:
    warnings = []
    app_node = root.find("application")

    if app_node is not None:
        if get_android_attrib(app_node, "debuggable") == "true":
            warnings.append({"type": "debuggable", "message": "App is debuggable — can be exploited."})
        if get_android_attrib(app_node, "allowBackup") == "true":
            warnings.append({"type": "allow_backup", "message": "Backup is allowed — risk of data leakage."})
        shared_user_id = app_node.attrib.get("sharedUserId")
        if shared_user_id:
            warnings.append({"type": "shared_user_id", "message": f"App uses sharedUserId: {shared_user_id}"})
    return warnings

def analyze_manifest(manifest_path: Path) -> dict:
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = extract_permissions(root)
        dangerous_perms = identify_dangerous_permissions(permissions)
        suspicious_perms = identify_suspicious_permissions(permissions)
        components = extract_components(root)
        risky_components = identify_exposed_risky_components(components)
        accessibility_abuse = detect_accessibility_service(root)
        package_name = root.attrib.get("package", "")
        obfuscated = is_obfuscated_package(package_name)
        manifest_warnings = extract_manifest_warnings(root)

        return {
            "package_name": package_name,
            "permissions": permissions,
            "dangerous_permissions": dangerous_perms,
            "suspicious_permissions": suspicious_perms,
            "components": components,
            "risky_components": risky_components,
            "has_accessibility_service": accessibility_abuse,
            "is_obfuscated_package": obfuscated,
            "manifest_warnings": manifest_warnings
        }

    except Exception as ex:
        logger.error(f"[MANIFEST ANALYZER] Failed to analyze manifest at {manifest_path}: {ex}")
        return {}
