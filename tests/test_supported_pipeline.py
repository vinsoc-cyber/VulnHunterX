# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Regression coverage for the supported pipeline after fuzzing removal."""

from __future__ import annotations

import importlib
import importlib.util
import logging
import runpy
import sys
from dataclasses import fields
from pathlib import Path
from unittest.mock import Mock

import pytest

from vuln_hunter_x.cli import commands
from vuln_hunter_x.cli.main import create_parser
from vuln_hunter_x.core.config import PathsConfig, load_config

cli = importlib.import_module("vuln_hunter_x.cli.main")
REPO_ROOT = Path(__file__).resolve().parents[1]
REMOVED_COMMANDS = (
    "build-sanitized",
    "extract-fuzz-context",
    "generate-fuzz-drivers",
    "fuzz-run",
)
EXAMPLES = ("pipeline_c.py", "pipeline_cpp.py", "pipeline_zlib.py", "run_all_pipelines.py")


@pytest.mark.parametrize("command", REMOVED_COMMANDS)
def test_removed_command_fails_with_remaining_choices(command, capsys):
    with pytest.raises(SystemExit) as error:
        create_parser().parse_args([command, "--repo", "demo"])
    assert error.value.code == 2
    message = capsys.readouterr().err
    assert "invalid choice" in message and command in message
    assert "scan" in message and "report" in message
    assert all(name not in create_parser().format_help() for name in REMOVED_COMMANDS)


@pytest.mark.parametrize(
    ("command", "handler"),
    [
        ("prepare", "cmd_prepare"),
        ("clone", "cmd_prepare"),
        ("analyze", "cmd_analyze"),
        ("verify", "cmd_verify"),
        ("report", "cmd_report"),
        ("info", "cmd_info"),
        ("check-env", "cmd_check_env"),
        ("scan", "cmd_scan"),
        ("interactive", "cmd_interactive"),
        ("wizard", "cmd_interactive"),
    ],
)
def test_supported_command_dispatches(command, handler, monkeypatch):
    action = Mock(return_value=17)
    monkeypatch.setattr(cli, handler, action)
    monkeypatch.setattr(cli, "load_dotenv", lambda: None)
    assert cli.main([command]) == 17
    action.assert_called_once()
    assert action.call_args.args[0].command == command


@pytest.mark.parametrize(
    "lang", ["c", "cpp", "python", "javascript", "php", "java", "go", "csharp"]
)
def test_scan_preserves_languages_and_local_target(lang, tmp_path, monkeypatch):
    stages = []

    def stage(name):
        def run(args):
            stages.append((name, args))
            return 0

        return run

    for name in ("prepare", "analyze", "verify", "report"):
        monkeypatch.setattr(commands, f"cmd_{name}", stage(name))
    args = create_parser().parse_args(
        ["scan", "--local-path", str(tmp_path), "--name", "demo", "--lang", lang]
    )
    assert commands.cmd_scan(args) == 0
    assert [name for name, _ in stages] == ["prepare", "analyze", "verify", "report"]
    for _, args in stages[:3]:
        assert args.local_path == tmp_path and args.name == "demo" and args.lang == lang
    assert stages[-1][1].repo == "demo" and stages[-1][1].lang == lang


@pytest.mark.parametrize(("tool", "expected"), [("codeql", 1), ("opengrep", 0)])
def test_scan_preserves_source_only_fallback(tool, expected, tmp_path, monkeypatch):
    monkeypatch.setattr(commands, "cmd_prepare", lambda args: 1)
    analyze = Mock(return_value=0)
    monkeypatch.setattr(commands, "cmd_analyze", analyze)
    args = create_parser().parse_args(
        ["scan", "--local-path", str(tmp_path), "--lang", "python", "--tool", tool, "--skip-verify"]
    )
    assert commands.cmd_scan(args) == expected
    assert analyze.call_count == (1 if tool == "opengrep" else 0)


@pytest.mark.parametrize("legacy", [{"max_fix_iterations": "PRIVATE-SETTING"}, None, []])
def test_legacy_yaml_warns_without_parsing_or_logging_values(legacy, tmp_path, caplog):
    import yaml

    path = tmp_path / "config" / "settings.yaml"
    path.parent.mkdir()
    path.write_text(yaml.safe_dump({"fuzz": legacy, "jobs": 2}), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="vuln_hunter_x.core.config"):
        config = load_config(path)
    assert config.verification.jobs == 2
    assert not hasattr(config, "fuzz")
    assert "'fuzz' configuration section is ignored" in caplog.text
    assert "PRIVATE-SETTING" not in caplog.text


@pytest.mark.parametrize("legacy", ["PRIVATE-SETTING", "", "123"])
def test_legacy_environment_is_ignored_without_logging_values(legacy, monkeypatch, caplog):
    monkeypatch.setenv("MAX_FIX_ITERATIONS", legacy)
    with caplog.at_level(logging.WARNING, logger="vuln_hunter_x.core.config"):
        config = load_config()
    assert not hasattr(config, "fuzz")
    assert "MAX_FIX_ITERATIONS is ignored" in caplog.text
    assert "PRIVATE-SETTING" not in caplog.text
    assert "123" not in caplog.text


def test_current_configuration_and_merge_keep_supported_settings(monkeypatch, caplog):
    monkeypatch.delenv("MAX_FIX_ITERATIONS", raising=False)
    config = load_config(REPO_ROOT / "config" / "confirm_findings.yaml", REPO_ROOT)
    config.llm.request_timeout = 12
    config.llm.num_retries = 3
    config.verification.self_consistency_samples = 3
    config.output.persist_raw_response = True
    merged = config.merge_with_args(provider="ollama", jobs=2)
    assert merged.llm.provider == "ollama"
    assert merged.llm.request_timeout == 12 and merged.llm.num_retries == 3
    assert merged.verification.jobs == 2 and merged.verification.self_consistency_samples == 3
    assert merged.output.persist_raw_response is True
    assert merged.paths == config.paths
    assert not hasattr(merged, "fuzz")
    assert "ignored" not in caplog.text


def test_repository_paths_cover_only_supported_artifacts(tmp_path):
    paths = PathsConfig(output_dir=tmp_path).repo_paths("cpp", "demo")
    root = tmp_path / "cpp" / "demo"
    assert {field.name for field in fields(paths)} == {
        "root",
        "database",
        "sarif_file",
        "context",
        "verification_results",
    }
    assert paths.root == root and paths.database == root / "database"
    assert paths.sarif_file == root / "demo.sarif"
    assert paths.context == root / "context"
    assert paths.verification_results == root / "verification_results"
    assert not root.exists()


def test_removed_python_api_cannot_be_imported():
    assert importlib.util.find_spec("vuln_hunter_x.fuzz") is None
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("vuln_hunter_x.fuzz")
    config = importlib.import_module("vuln_hunter_x.core.config")
    assert not hasattr(config, "FuzzConfig")


@pytest.mark.parametrize("example", EXAMPLES)
@pytest.mark.parametrize("flag", ["--fuzz", "--fuzz-timeout", "--fuzz-max-time"])
def test_examples_reject_removed_options_before_any_work(example, flag, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [example, flag])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(REPO_ROOT / "examples" / example), run_name="__main__")
    assert error.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_batch_example_preserves_verification_options(tmp_path, monkeypatch):
    script = runpy.run_path(str(REPO_ROOT / "examples/run_all_pipelines.py"))
    run_pipeline = script["run_pipeline"]
    for name in ("stage_clone", "stage_analyze", "stage_extract_context"):
        monkeypatch.setitem(run_pipeline.__globals__, name, Mock(return_value=("DRY-RUN", "")))
    verify = Mock(return_value=("DRY-RUN", "Would verify"))
    monkeypatch.setitem(run_pipeline.__globals__, "stage_verify", verify)
    stats = run_pipeline(
        [{"name": "demo", "language": "cpp"}],
        dry_run=True,
        base_path=tmp_path,
        verify_limit=7,
        max_iterations=9,
    )
    assert stats["successful"] == 1 and stats["failed"] == 0
    verify.assert_called_once_with(
        "demo", lang="cpp", limit=7, max_iterations=9, force=False, dry_run=True, base_path=tmp_path
    )
    assert set(stats["repos"]["demo"]) == {"language", "clone", "analyze", "extract", "verify"}
