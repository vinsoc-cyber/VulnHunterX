import json
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
                 {"provider": "openai", "model": "gpt-5.5", "temperature": 0, "max_iterations": 5},
                 raw, root / "s.sarif", None)
    assert cost == 0.5
    assert sorted(p.name for p in raw.glob("*.json")) == ["x.json"]
