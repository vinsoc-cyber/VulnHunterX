import json
from modes import version_ab as v


def _verdict(rule, file, line, verdict, cost=0.1, conf="High"):
    return {"finding": {"rule_id": rule, "file": file, "start_line": line},
            "verdict": verdict, "confidence": conf, "cost_usd": cost}


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
