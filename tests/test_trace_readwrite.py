import pytest
from apk_inspector.utils.file_utils import deduplicate_events
from apk_inspector.analysis.data_classifier import classify_path

sample_events = [
    {
        "event": "read",
        "fd": 3,
        "length": 128,
        "data": "/data/data/com.example/config.json"
    },
    {
        "event": "write",
        "fd": 3,
        "length": 256,
        "data": "fake config data"
    }
]

def test_classify_file_events():
    # Simulate Frida emitting file paths
    events = [{"path": e["data"]} for e in sample_events if "data" in e]
    for event in events:
        event["classification"] = classify_path(event["path"])

    classifications = [e["classification"] for e in events]
    assert "config" in classifications or "app_storage" in classifications

def test_deduplicate_events():
    duplicate_events = sample_events + [sample_events[0]]
    result = deduplicate_events(duplicate_events)
    assert len(result) == len(sample_events)
