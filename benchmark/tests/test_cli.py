import json
from pathlib import Path
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
    (sr / f"{target}.sarif").write_text(json.dumps({"runs": [{"results": [
        {"ruleId": "r", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "f.c"}, "region": {"startLine": 1}}}]}]}]}))
    cfg = bench / "config"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / f"{v.DEFAULT_CONFIG}.yaml").write_text(
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

    rc = v.run(_args(), bench)   # config=None -> default config/<DEFAULT_CONFIG>.yaml
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
        v.run(_args(no_compare=True), bench)


def test_dry_run_skips_collision_guard(tmp_path):
    bench = tmp_path / "benchmark"
    (bench / "src").mkdir(parents=True)
    _panel(bench)
    (bench / "result" / "version_ab" / "1.0.0@test").mkdir(parents=True)  # would collide
    rc = v.run(_args(dry_run=True, no_compare=True), bench)
    assert rc == 0  # dry-run is exempt from the collision guard


def test_run_isolates_target_failure(tmp_path, monkeypatch):
    bench = tmp_path / "benchmark"
    (bench / "src").mkdir(parents=True)
    _panel(bench, "a_bad")    # sorts first → fails first
    _panel(bench, "b_good")   # must still be scored after the failure

    def fake_run(self, meta, src, cfg, raw_dir, sarif, ctx):
        if meta["name"] == "a_bad":
            raise RuntimeError("verify blew up")
        Path(raw_dir).mkdir(parents=True, exist_ok=True)
        (Path(raw_dir) / "x.json").write_text(json.dumps({
            "finding": {"rule_id": "r", "file": "f.c", "start_line": 1},
            "verdict": "True Positive", "confidence": "High", "cost_usd": 0.2}))
        return 0.2

    monkeypatch.setattr(v.Harness, "fetch", lambda self, meta, dest: dest)
    monkeypatch.setattr(v.Harness, "run", fake_run)

    rc = v.run(_args(no_compare=True), bench)
    assert rc == 1  # a target failed → non-zero exit
    base = bench / "result" / "version_ab" / "1.0.0@test"
    assert (base / "b_good" / "score.json").exists()      # other target still scored
    assert not (base / "a_bad" / "score.json").exists()   # failed target wrote no score


def test_config_path_resolution(tmp_path):
    bench = tmp_path / "benchmark"
    assert v.config_path(None, bench) == bench / "config" / f"{v.DEFAULT_CONFIG}.yaml"  # default
    assert v.config_path("codex-mini-temp0-iter3", bench) == bench / "config" / "codex-mini-temp0-iter3.yaml"
    # dotted model id (gpt-5.5) -> .suffix is non-empty but it's still a bare name
    assert v.config_path("openai-gpt-5.5-temp0-iter5", bench) == bench / "config" / "openai-gpt-5.5-temp0-iter5.yaml"
    assert v.config_path("sub/dir.yaml", bench) == Path("sub/dir.yaml")   # path part -> literal
    assert v.config_path("/abs/x.yaml", bench) == Path("/abs/x.yaml")     # absolute -> literal


def test_load_config_requires_result_knobs(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text("provider: openai\nmodel: m\ntemperature: 0\nmax_iterations: 5\n")
    assert v.load_config(good)["max_cost"] is None        # operational default still filled in
    bad = tmp_path / "bad.yaml"
    bad.write_text("provider: openai\nmodel: m\ntemperature: 0\n")   # missing max_iterations
    with pytest.raises(SystemExit):
        v.load_config(bad)
    with pytest.raises(SystemExit):
        v.load_config(tmp_path / "missing.yaml")           # not found
