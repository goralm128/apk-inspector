import pytest
from apk_inspector.analysis.data_classifier import classify_path

@pytest.mark.parametrize("path,expected", [
    ("/data/data/com.example/token.txt", "sensitive"),
    ("/data/data/com.example/secret.xml", "sensitive"),
    ("/sdcard/key.pem", "sensitive"),
    ("/data/data/com.example/app/config.json", "config"),
    ("/storage/emulated/0/settings.json", "config"),
    ("/data/data/com.example/config.xml", "config"),
    ("/sdcard/DCIM/photo.jpg", "app_storage"),
    ("/system/lib/libc.so", "system_access"),
    ("", "unknown"),
    (None, "unknown"),
    ("/data/data/com.example/random.bin", "app_storage"),
    ("/unknown/path/to/file", "general")
])
def test_classify_path(path, expected):
    assert classify_path(path) == expected
