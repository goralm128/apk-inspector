import pytest
from argparse import Namespace
from apk_inspector.cli import parse_args
from pathlib import Path

def test_parse_args_valid(monkeypatch):
    test_args = [
        "prog",
        "--hook", "open",
        "--timeout", "15",
        "--include-private"
    ]
    monkeypatch.setattr("sys.argv", test_args)

    hooks_dir = Path("apk_inspector/frida_hooks")
    args = parse_args(hooks_dir)

    assert isinstance(args, Namespace)
    assert args.hook == "open"
    assert args.timeout == 15
    assert args.include_private is True

def test_parse_args_missing_hook(monkeypatch):
    test_args = ["prog"]
    monkeypatch.setattr("sys.argv", test_args)

    hooks_dir = Path("apk_inspector/frida_hooks")

    with pytest.raises(SystemExit):
        parse_args(hooks_dir)
