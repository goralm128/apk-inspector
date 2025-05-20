import os
import zipfile
from pathlib import Path

# Constants
AWS_KEY = "AKIA1234567890ABCDEF"
RULE_NAME = "AWS_Test_Key"

# === S === Single-responsibility functions ===

def create_decompiled_structure(base_dir: Path):
    """Creates a sample decompiled Android structure with a manifest and smali."""
    decompiled_dir = base_dir / "decompiled"
    smali_dir = decompiled_dir / "smali"
    smali_dir.mkdir(parents=True, exist_ok=True)

    manifest_content = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.fakeapp">
    <uses-permission android:name="android.permission.READ_SMS"/>
    <application>
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>'''
    (decompiled_dir / "AndroidManifest.xml").write_text(manifest_content, encoding="utf-8")

    smali_content = f'''.class public Lcom/test/fakeapp/MainActivity;
.super Ljava/lang/Object;

.method public onCreate()V
    .registers 2
    const-string v0, "http://example.com/api/upload"
    return-void
.end method
'''
    (smali_dir / "MainActivity.smali").write_text(smali_content, encoding="utf-8")
    print(f"[✓] Decompiled folder created at: {decompiled_dir.resolve()}")


def build_fake_apk(base_dir: Path):
    """Builds a fake APK zip from basic placeholders."""
    apk_dir = base_dir / "fake_apk_content"
    apk_file = base_dir / "fake.apk"
    apk_dir.mkdir(exist_ok=True)

    (apk_dir / "AndroidManifest.xml").write_text("Fake manifest", encoding="utf-8")
    (apk_dir / "classes.dex").write_text("DEX", encoding="utf-8")
    (apk_dir / "res").mkdir(exist_ok=True)

    with zipfile.ZipFile(apk_file, "w") as zipf:
        for file in apk_dir.rglob("*"):
            if file.is_file():
                zipf.write(file, arcname=file.relative_to(apk_dir))

    print(f"[✓] Fake APK built at: {apk_file.resolve()}")


def create_test_yara_rule(rule_dir: Path):
    """Creates a test YARA rule that detects a fake AWS key."""
    rule_dir.mkdir(parents=True, exist_ok=True)
    rule_content = f'''
rule {RULE_NAME}
{{
  strings:
    $key = /AKIA[0-9A-Z]{{16}}/
  condition:
    $key
}}
'''
    rule_file = rule_dir / "aws_test.yar"
    rule_file.write_text(rule_content.strip(), encoding="utf-8")
    print(f"[✓] YARA rule written to: {rule_file.resolve()}")


def create_test_yara_target_file(target_dir: Path):
    """Creates a file containing a string to be matched by the YARA rule."""
    target_dir.mkdir(parents=True, exist_ok=True)
    test_file = target_dir / "fake_creds.txt"
    test_file.write_text(f"This file contains a hardcoded AWS key: {AWS_KEY}", encoding="utf-8")
    print(f"[✓] Test target file written to: {test_file.resolve()}")


# === D === Dependency inversion: main() orchestrates high-level actions ===
def main():
    base_dir = Path("tests/sample")
    rule_dir = Path("tests/test_rules")
    target_dir = Path("tests/test_files")

    base_dir.mkdir(parents=True, exist_ok=True)

    create_decompiled_structure(base_dir)
    build_fake_apk(base_dir)
    create_test_yara_rule(rule_dir)
    create_test_yara_target_file(target_dir)


if __name__ == "__main__":
    main()
