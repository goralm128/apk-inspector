from pathlib import Path
from apk_inspector.core.yara_scanner import YaraScanner

def test_yara_matches_key():
    base_path = Path(__file__).parent
    rule_path = base_path / "test_rules"
    target_path = base_path / "test_files"

    scanner = YaraScanner(rules_dir=rule_path)
    matches = scanner.scan_directory(target_path)

    assert len(matches) > 0
    assert "AWS_Test_Key" in matches[0]["matches"]
