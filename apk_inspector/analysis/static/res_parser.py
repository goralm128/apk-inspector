from xml.etree import ElementTree as ET
from pathlib import Path
from typing import List, Dict


def analyze_strings_xml(path: Path) -> List[Dict[str, str]]:
    strings_path = path / "res" / "values" / "strings.xml"
    results = []

    if not strings_path.exists():
        return results

    try:
        tree = ET.parse(strings_path)
        root = tree.getroot()

        for string_tag in root.findall("string"):
            name = string_tag.attrib.get("name", "")
            value = (string_tag.text or "").strip()

            if not value:
                continue

            # Identify likely sensitive entries
            if any(k in name.lower() for k in [
                "api_key", "google_api_key", "app_id", "crash", "token", "bucket", "firebase", "key", "secret"
            ]):
                results.append({
                    "key": name,
                    "value": value
                })

    except Exception as e:
        print(f"[WARN] Failed to parse strings.xml: {e}")

    return results
