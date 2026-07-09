from modes import version_ab as v


def test_render_score():
    score = {
        "meta": {"version": "1.0.0@a", "model": "gpt-5.5", "temperature": 0,
                 "panel_hash": "sha256:xxxxxxxxxxxxxxxx", "timestamp": "T"},
        "findings": [{"rule": "r", "file": "f.c", "line": 1, "truth": "real",
                      "verdict": "TP", "grade": "CORRECT", "confidence": "High"}],
        "aggregates": {"precision": 1.0, "recall": 1.0, "tp_total": 1, "tp_real": 1,
                       "false_alarm": 0, "n_real": 1, "n_not_real": 0, "cost_usd": 0.1},
    }
    md = v.render_score_md(score)
    assert "1.0.0@a" in md and "r@f.c:1" in md and "100%" in md


def test_render_compare():
    churn = {"previous": "1.0.0@a", "current": "1.0.0@b",
             "flips": [{"rule": "r", "file": "f.c", "line": 1, "truth": "real",
                        "previous": "FP", "current": "TP", "direction": "IMPROVE",
                        "prev_conf": "Low", "cur_conf": "High"}],
             "totals": {"flips": 1, "improve": 1, "regress": 0, "neutral": 0},
             "deltas": {"precision": 0.0, "recall": 1.0}, "timestamp": "T"}
    md = v.render_compare_md(churn)
    assert "1.0.0@a" in md and "IMPROVE" in md and "r@f.c:1" in md


def test_rollup_score():
    s1 = {"meta": {"panel_hash": "sha256:aaaa"},
          "findings": [{"rule": "r", "file": "f.c", "line": 1, "truth": "real",
                        "verdict": "TP", "cost_usd": 1.0}],
          "aggregates": {"n_real": 1}}
    s2 = {"meta": {"panel_hash": "sha256:bbbb"},
          "findings": [{"rule": "r", "file": "g.c", "line": 2, "truth": "real",
                        "verdict": "FP", "cost_usd": 1.0}],
          "aggregates": {"n_real": 1}}
    roll = v.rollup_score({"a": s1, "b": s2}, {"version": "1.0.0@a"})
    assert roll["aggregates"]["n_real"] == 2
    assert roll["aggregates"]["recall"] == 0.5
    assert roll["aggregates"]["cost_usd"] == 2.0
    # per-target breakdown carried on the rollup, each tagged with its panel hash
    assert set(roll["targets"]) == {"a", "b"}
    assert roll["targets"]["a"]["panel_hash"] == "sha256:aaaa"
    assert all(f["target"] in {"a", "b"} for f in roll["findings"])


def test_rollup_resources():
    s1 = {"meta": {"panel_hash": "sha256:aaaa"},
          "findings": [{"rule": "r", "file": "f.c", "line": 1, "truth": "real",
                        "verdict": "TP", "cost_usd": 1.0, "input_tokens": 1000,
                        "output_tokens": 100, "cached_input_tokens": 800,
                        "elapsed_seconds": 5.0, "iterations": 3}],
          "aggregates": {"n_real": 1},
          "resources": {"input_tokens": 1000}}
    roll = v.rollup_score({"a": s1}, {"version": "1.0.0@a"})
    assert roll["resources"]["input_tokens"] == 1000
    assert roll["targets"]["a"]["resources"]["input_tokens"] == 1000


def test_render_rollup_md():
    s1 = {"meta": {"panel_hash": "sha256:" + "a" * 32, "version": "1.0.0@x"},
          "findings": [{"rule": "r", "file": "f.c", "line": 1, "truth": "real",
                        "verdict": "TP", "grade": "CORRECT", "confidence": "High",
                        "cost_usd": 1.0}],
          "aggregates": {"precision": 1.0, "recall": 1.0, "tp_total": 1, "tp_real": 1,
                         "false_alarm": 0, "n_real": 1, "n_not_real": 0, "cost_usd": 1.0}}
    roll = v.rollup_score({"dvcp": s1}, {"version": "1.0.0@x", "model": "gpt-5.5",
                                         "temperature": 0, "timestamp": "T"})
    md = v.render_score_md(roll)
    assert "## Per target" in md and "dvcp" in md
    assert "sha256:" in md          # real per-target panel hash, not a placeholder
    assert "panel `?…`" not in md   # rollup header must not show a bogus single panel


def test_render_score_resources_line():
    score = {
        "meta": {"version": "1.0.0@a", "model": "gpt-5.5", "temperature": 0,
                 "panel_hash": "sha256:xxxx", "timestamp": "T"},
        "findings": [],
        "aggregates": {"precision": 1.0, "recall": 1.0, "tp_total": 1, "tp_real": 1,
                       "false_alarm": 0, "n_real": 1, "n_not_real": 0, "n_abstain": 2,
                       "n_error": 1, "cost_usd": 0.1},
        "resources": {"input_tokens": 1_250_000, "output_tokens": 84_000,
                      "cached_input_tokens": 900_000, "cache_hit_ratio": 0.72,
                      "elapsed_seconds": 640.2, "iterations_mean": 3.1, "iterations_total": 92},
    }
    md = v.render_score_md(score)
    assert "NMD 2" in md and "err 1" in md
    assert "1.25M in" in md and "72%" in md and "μ3.1" in md


def test_render_rollup_resources_table():
    s1 = {"meta": {"panel_hash": "sha256:" + "a" * 32, "version": "1.0.0@x"},
          "findings": [{"rule": "r", "file": "f.c", "line": 1, "truth": "real",
                        "verdict": "TP", "grade": "CORRECT", "confidence": "High",
                        "cost_usd": 1.0, "input_tokens": 1000, "output_tokens": 100,
                        "cached_input_tokens": 800, "elapsed_seconds": 5.0, "iterations": 3}],
          "aggregates": {"precision": 1.0, "recall": 1.0, "tp_total": 1, "tp_real": 1,
                         "false_alarm": 0, "n_real": 1, "n_not_real": 0, "n_abstain": 0,
                         "n_error": 0, "cost_usd": 1.0},
          "resources": {"input_tokens": 1000, "output_tokens": 100, "cached_input_tokens": 800,
                        "cache_hit_ratio": 0.8, "elapsed_seconds": 5.0, "iterations_mean": 3.0,
                        "iterations_total": 3}}
    roll = v.rollup_score({"dvcp": s1}, {"version": "1.0.0@x", "model": "gpt-5.5",
                                         "temperature": 0, "timestamp": "T"})
    md = v.render_score_md(roll)
    assert "## Per target — correctness" in md
    assert "## Per target — resources" in md
    assert "1k" in md   # 1000 input tokens formatted


def test_render_compare_resource_deltas():
    churn = {"previous": "1.0.0@a", "current": "1.0.0@b", "flips": [],
             "totals": {"flips": 0, "improve": 0, "regress": 0, "neutral": 0},
             "deltas": {"precision": 0.0, "recall": 0.0},
             "resource_deltas": {"cost_usd": 0.5, "input_tokens": 500, "output_tokens": 20,
                                 "cached_input_tokens": 400, "cache_hit_ratio": 0.1,
                                 "elapsed_seconds": 4.0, "iterations_mean": 0.5,
                                 "n_error": 1, "n_abstain": -2},
             "timestamp": "T"}
    md = v.render_compare_md(churn)
    assert "## Resource deltas" in md and "non-gating" in md
    assert "+500" in md and "+0.5" in md and "-2" in md


def test_render_compare_no_resource_deltas():
    churn = {"previous": "1.0.0@a", "current": "1.0.0@b", "flips": [],
             "totals": {"flips": 0, "improve": 0, "regress": 0, "neutral": 0},
             "deltas": {"precision": 0.0, "recall": 0.0}, "timestamp": "T"}
    md = v.render_compare_md(churn)
    assert "## Resource deltas" not in md   # absent section, no crash
