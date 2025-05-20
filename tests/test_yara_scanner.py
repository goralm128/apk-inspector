from pathlib import Path
from apk_inspector.utils.yara_scanner import scan_with_yara

def test_yara_matches_key():
    base_path = Path(__file__).parent
    rule_path = base_path / "test_rules"
    target_path = base_path / "test_files"

    matches = scan_with_yara(target_path, rule_path)
    assert len(matches) > 0
    assert "AWS_Test_Key" in matches[0]["matches"]
