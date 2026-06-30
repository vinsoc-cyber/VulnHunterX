import json
import pytest
from modes import version_ab as v


def _args(**kw):
    base = {"targets": None, "config": None, "previous": None, "current": "1.0.0@test",
            "compare_only": False, "no_compare": False, "force": False,
            "no_keep_output": True, "dry_run": False, "timestamp": "T"}
    base.update(kw)
    return type("A", (), base)()


def _panel(bench, target="dvcp"):
    sr = bench / "test_case" / target / "scanner_result"
    sr.mkdir(parents=True)
    (bench / "test_case" / target / "metadata.json").write_text(json.dumps(
        {"repo_url": "U", "sha": "S", "lang": "c", "name": target, "scanner": "codeql"}))
    (bench / "test_case" / target / "ground_truth.json").write_text(json.dumps(["r@f.c:1"]))
    (sr / f"{target}.sarif").write_text("SARIF")
    (bench / "config" / "version_ab").mkdir(parents=True)
    (bench / "config" / "version_ab" / "config.yaml").write_text(
        "provider: openai\nmodel: gpt-5.5\ntemperature: 0\nmax_cost: 25\nmax_iterations: 5\n")


def test_run_scores_target(tmp_path, monkeypatch):
    bench = tmp_path / "benchmark"
    (bench / "src").mkdir(parents=True)
    _panel(bench)

    def fake_run(self, meta, src, cfg, raw_dir, sarif, ctx):
        from pathlib import Path
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        (Path(raw_dir) / "x.json").write_text(json.dumps({
            "finding": {"rule_id": "r", "file": "f.c", "start_line": 1},
            "verdict": "True Positive", "confidence": "High", "cost_usd": 0.2}))
        return 0.2

    monkeypatch.setattr(v.Harness, "fetch", lambda self, meta, dest: dest)
    monkeypatch.setattr(v.Harness, "run", fake_run)

    rc = v.run(_args(config=str(bench / "config" / "version_ab" / "config.yaml")), bench)
    assert rc == 0
    score = json.loads((bench / "result" / "version_ab" / "1.0.0@test" / "dvcp" / "score.json").read_text())
    assert score["aggregates"]["recall"] == 1.0
    # top-level rollup written
    assert (bench / "result" / "version_ab" / "1.0.0@test" / "score.json").exists()


def test_collision_refused(tmp_path):
    bench = tmp_path / "benchmark"
    (bench / "src").mkdir(parents=True)
    _panel(bench)
    (bench / "result" / "version_ab" / "1.0.0@test").mkdir(parents=True)
    with pytest.raises(SystemExit):
        v.run(_args(config=str(bench / "config" / "version_ab" / "config.yaml"), no_compare=True), bench)
