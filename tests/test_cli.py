import pytest
from argparse import Namespace
from apk_inspector.cli import parse_args
from pathlib import Path

def test_parse_args_valid(monkeypatch):
    test_args = [
        "prog",
        "--hook", "readwrite",
        "--timeout", "15",
        "--include-private",
        "--apk-dir", "samples",
        "--output-dir", "results",
        "--verbose"
    ]
    monkeypatch.setattr("sys.argv", test_args)

    args = parse_args(["readwrite", "network"])

    assert isinstance(args, Namespace)
    assert args.hook == "readwrite"
    assert args.timeout == 15
    assert args.include_private is True
    assert Path(args.apk_dir) == Path("samples")
    assert Path(args.output_dir) == Path("results")
    assert args.verbose is True

def test_parse_args_missing_hook(monkeypatch):
    test_args = ["prog"]
    monkeypatch.setattr("sys.argv", test_args)

    with pytest.raises(SystemExit):  # argparse exits on missing required args
        parse_args(["readwrite", "network"])

def test_parse_args_defaults(monkeypatch):
    test_args = [
        "prog",
        "--hook", "network"
    ]
    monkeypatch.setattr("sys.argv", test_args)

    args = parse_args(["readwrite", "network"])

    assert args.hook == "network"
    assert args.timeout == 10        # Default
    assert args.include_private is False
    assert Path(args.apk_dir) == Path("apks")
    assert Path(args.output_dir) == Path("output")
    assert args.verbose is False

def test_invalid_hook(monkeypatch):
    test_args = [
        "prog",
        "--hook", "nonexistent"
    ]
    monkeypatch.setattr("sys.argv", test_args)

    with pytest.raises(SystemExit):  # argparse should reject this
        parse_args(["readwrite", "network"])


