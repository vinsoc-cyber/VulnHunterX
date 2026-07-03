import json
from pathlib import Path
from modes import version_ab as v


def test_fetch_clones_then_checks_out(tmp_path, monkeypatch):
    calls = []
    h = v.Harness(tmp_path)
    monkeypatch.setattr(h, "_invoke", lambda cmd, cwd=None: calls.append(cmd))
    h.fetch({"repo_url": "URL", "sha": "SHA"}, tmp_path / "clone")
    assert calls[0][:2] == ["git", "clone"] and "URL" in calls[0]
    assert calls[1][:2] == ["git", "-C"] and "SHA" in calls[1]


def test_run_collects_verdicts_and_sums_cost(tmp_path, monkeypatch):
    root = tmp_path
    h = v.Harness(root)
    vr = root / "output" / "c" / "dvcp" / "verification_results"
    vr.mkdir(parents=True)

    def fake(cmd, cwd=None):
        (vr / "x.json").write_text(json.dumps({
            "finding": {"rule_id": "r", "file": "f.c", "start_line": 1},
            "verdict": "True Positive", "confidence": "High", "cost_usd": 0.5}))
        (vr / "summary_y.json").write_text("{}")  # must be skipped

    monkeypatch.setattr(h, "_invoke", fake)
    raw = tmp_path / "raw"
    cost = h.run({"lang": "c", "name": "dvcp"}, tmp_path / "src",
                 {"provider": "openai", "model": "gpt-5.5", "temperature": 0,
                  "max_iterations": 5, "output_dir": str(root)},
                 raw, root / "s.sarif", None)
    assert cost == 0.5
    assert sorted(p.name for p in raw.glob("*.json")) == ["x.json"]


def test_run_engine_work_defaults_under_raw_dir(tmp_path, monkeypatch):
    """No output_dir -> engine works under <raw_dir>/_engine, persisting with it."""
    h = v.Harness(tmp_path)
    seen = {}

    def fake(cmd, cwd=None):
        seen["cwd"] = cwd
        vr = Path(cwd) / "output" / "c" / "dvcp" / "verification_results"
        vr.mkdir(parents=True)
        (vr / "x.json").write_text(json.dumps({
            "finding": {"rule_id": "r", "file": "f.c", "start_line": 1},
            "verdict": "True Positive", "confidence": "High", "cost_usd": 0.5}))

    monkeypatch.setattr(h, "_invoke", fake)
    raw = tmp_path / "raw"
    cost = h.run({"lang": "c", "name": "dvcp"}, tmp_path / "src",
                 {"provider": "openai", "model": "gpt-5.5", "temperature": 0,
                  "max_iterations": 5}, raw, tmp_path / "s.sarif", None)
    assert cost == 0.5
    assert Path(seen["cwd"]) == raw / "_engine"   # engine ran beside the kept verdicts
    assert (raw / "x.json").exists()              # verdict copied flat into raw_dir


def test_run_creates_output_dir_when_target_has_no_context(tmp_path, monkeypatch):
    """The engine opens output/llm_conversations.md relative to cwd; the harness
    must create work/output even when a target has no context dir (e.g. dvwa)."""
    h = v.Harness(tmp_path)

    def fake(cmd, cwd=None):
        assert (Path(cwd) / "output").is_dir(), "harness did not create work/output"
        vr = Path(cwd) / "output" / "php" / "dvwa" / "verification_results"
        vr.mkdir(parents=True)
        (vr / "x.json").write_text(json.dumps({
            "finding": {"rule_id": "r", "file": "f.php", "start_line": 1},
            "verdict": "True Positive", "confidence": "High", "cost_usd": 0.1}))

    monkeypatch.setattr(h, "_invoke", fake)
    raw = tmp_path / "raw"
    cost = h.run({"lang": "php", "name": "dvwa"}, tmp_path / "src",
                 {"provider": "openai", "model": "gpt-5.5", "temperature": 0,
                  "max_iterations": 5}, raw, tmp_path / "s.sarif", None)  # context_dir=None
    assert cost == 0.1


def test_write_verdicts_persists_reasoning_and_skips_errors(tmp_path):
    """One markdown per graded finding, carrying its reasoning; error stubs
    (provider 503) are skipped, and their file is never created."""
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "ok.json").write_text(json.dumps({
        "finding": {"rule_id": "cpp/double-free", "file": "imgRead.c", "start_line": 62},
        "verdict": "True Positive", "confidence": "High", "confidence_score": 0.95,
        "iterations": 1, "reasoning": "buff1 is freed twice on a file-controlled path.",
        "answers": ["Step 1: input from argv[1].", "Step 2: reaches second free."],
        "data_flow": "argv[1] -> free -> free", "context_needed": []}))
    (raw / "err.json").write_text(json.dumps({
        "finding": {"rule_id": "js/xss", "file": "app.js", "start_line": 10},
        "verdict": "Error", "reasoning": "LLM call failed: ServiceUnavailableError",
        "answers": [], "cost_usd": 0.0}))
    (raw / "summary_x.json").write_text("{}")  # must be ignored

    real = {("cpp/double-free", "imgRead.c", 62)}
    dest = tmp_path / "verdicts"
    n = v.write_verdicts(raw, real, dest)

    assert n == 1
    assert sorted(p.name for p in dest.glob("*.md")) == ["ok.md"]
    md = (dest / "ok.md").read_text()
    assert "cpp/double-free" in md and "imgRead.c:62" in md
    assert "**Verdict:** TP" in md and "**Truth:** real" in md and "**Grade:** CORRECT" in md
    assert "buff1 is freed twice" in md          # reasoning
    assert "Step 1: input from argv[1]." in md   # answers
    assert "argv[1] -> free -> free" in md        # data_flow


def test_write_verdicts_leaves_existing_when_only_errors(tmp_path):
    """An all-error re-run returns 0 and does not wipe previously good verdicts."""
    dest = tmp_path / "verdicts"
    dest.mkdir()
    (dest / "keep.md").write_text("prior good reasoning")
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "err.json").write_text(json.dumps({
        "finding": {"rule_id": "r", "file": "f", "start_line": 1},
        "verdict": "Error", "reasoning": "boom", "answers": []}))

    assert v.write_verdicts(raw, set(), dest) == 0
    assert (dest / "keep.md").read_text() == "prior good reasoning"


def test_run_passes_jobs_flag_only_when_configured(tmp_path, monkeypatch):
    """cfg['jobs'] -> engine gets `--jobs N`; absent -> flag omitted (engine default)."""
    h = v.Harness(tmp_path)
    seen = {}

    def fake(cmd, cwd=None):
        seen["cmd"] = cmd
        (Path(cwd) / "output" / "c" / "dvcp" / "verification_results").mkdir(parents=True)

    monkeypatch.setattr(h, "_invoke", fake)
    base = {"provider": "openai", "model": "gpt-5.5", "temperature": 0, "max_iterations": 5}

    h.run({"lang": "c", "name": "dvcp"}, tmp_path / "src", {**base, "jobs": 10},
          tmp_path / "r1", tmp_path / "s.sarif", None)
    assert "--jobs" in seen["cmd"] and seen["cmd"][seen["cmd"].index("--jobs") + 1] == "10"

    h.run({"lang": "c", "name": "dvcp"}, tmp_path / "src", base,
          tmp_path / "r2", tmp_path / "s.sarif", None)
    assert "--jobs" not in seen["cmd"]
