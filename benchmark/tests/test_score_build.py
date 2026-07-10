import json
from modes import version_ab as v


def _verdict(rule, file, line, verdict, cost=0.1, conf="High", **extra):
    d = {"finding": {"rule_id": rule, "file": file, "start_line": line},
         "verdict": verdict, "confidence": conf, "cost_usd": cost}
    d.update(extra)
    return d


def test_build_score(tmp_path):
    raw = tmp_path / "raw"; raw.mkdir()
    (raw / "a.json").write_text(json.dumps(_verdict("cpp/double-free", "imgRead.c", 62, "True Positive")))
    (raw / "b.json").write_text(json.dumps(_verdict("cpp/leak", "imgRead.c", 10, "True Positive")))
    (raw / "summary_x.json").write_text("{}")  # must be ignored
    real = {("cpp/double-free", "imgRead.c", 62)}
    meta = {"version": "1.0.0@aaa", "provider": "openai", "model": "gpt-5.5",
            "temperature": 0, "panel_hash": "sha256:x", "timestamp": "T"}

    score = v.build_score(raw, real, meta)

    assert score["meta"] == meta
    by = {(f["rule"], f["file"], f["line"]): f for f in score["findings"]}
    assert by[("cpp/double-free", "imgRead.c", 62)]["truth"] == "real"
    assert by[("cpp/double-free", "imgRead.c", 62)]["grade"] == "CORRECT"
    assert by[("cpp/leak", "imgRead.c", 10)]["truth"] == "not-real"
    assert by[("cpp/leak", "imgRead.c", 10)]["grade"] == "FALSE-ALARM"
    assert score["aggregates"]["n_real"] == 1
    assert score["aggregates"]["recall"] == 1.0
    assert score["aggregates"]["precision"] == 0.5


def test_load_real_keys(tmp_path):
    gt = tmp_path / "ground_truth.json"
    gt.write_text(json.dumps(["cpp/double-free@imgRead.c:62", "js/xss@app/x.js:5"]))
    keys = v.load_real_keys(gt)
    assert ("cpp/double-free", "imgRead.c", 62) in keys
    assert ("js/xss", "app/x.js", 5) in keys


def test_panel_hash_excludes_ground_truth(tmp_path):
    tc = tmp_path / "dvcp"; (tc / "scanner_result").mkdir(parents=True)
    (tc / "metadata.json").write_text("{}")
    (tc / "scanner_result" / "dvcp.sarif").write_text("SARIF")
    (tc / "ground_truth.json").write_text("[]")
    h1 = v.panel_hash(tc)
    (tc / "ground_truth.json").write_text('["x@y:1"]')      # oracle change → no effect
    assert v.panel_hash(tc) == h1
    (tc / "scanner_result" / "dvcp.sarif").write_text("SARIF2")  # input change → effect
    assert v.panel_hash(tc) != h1


def test_build_score_error_stub(tmp_path):
    raw = tmp_path / "raw"; raw.mkdir()
    (raw / "a.json").write_text(json.dumps(_verdict("cpp/double-free", "imgRead.c", 62, "True Positive")))
    (raw / "b.json").write_text(json.dumps(_verdict("cpp/leak", "imgRead.c", 91, "ERROR", cost=0.0)))
    real = {("cpp/double-free", "imgRead.c", 62), ("cpp/leak", "imgRead.c", 91)}
    score = v.build_score(raw, real, {"version": "1.0.0@aaa"})
    by = {(f["rule"], f["file"], f["line"]): f for f in score["findings"]}
    assert by[("cpp/leak", "imgRead.c", 91)]["grade"] == "error"   # still listed
    a = score["aggregates"]
    assert a["n_error"] == 1 and a["n_error_real"] == 1
    assert a["n_real"] == 2       # oracle total unchanged
    assert a["recall"] == 1.0     # tp_real 1 / (2 - 1 errored real)
    assert "resources" in score


def test_build_score_has_resources(tmp_path):
    raw = tmp_path / "raw"; raw.mkdir()
    (raw / "a.json").write_text(json.dumps(_verdict(
        "cpp/df", "x.c", 1, "True Positive",
        input_tokens=1000, output_tokens=100, cached_input_tokens=800,
        elapsed_seconds=5.0, iterations=3)))
    score = v.build_score(raw, {("cpp/df", "x.c", 1)}, {"version": "1"})
    assert score["resources"]["input_tokens"] == 1000
    assert score["resources"]["iterations_mean"] == 3.0
    f0 = score["findings"][0]
    assert f0["input_tokens"] == 1000 and f0["iterations"] == 3
