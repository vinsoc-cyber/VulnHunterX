# Benchmark Resource Metrics + Honest Error Accounting — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-target token/time/iteration accounting to the `version_ab` benchmark and fix the bug where errored findings are silently graded as abstentions.

**Architecture:** All engine code lives in one module, `benchmark/src/modes/version_ab.py`. We add a shared `is_real_verdict` predicate, a new `resources` block (via a pure `summarize_resources` function) sibling to the existing `aggregates`, error-aware grading/aggregation, and rendering for two per-target tables plus a non-gating compare section. Metrics flow through the per-finding list so both aggregators stay pure functions of `findings`.

**Tech Stack:** Python 3.12, pytest. No new dependencies.

## Global Constraints

- **All code changes are in one file:** `benchmark/src/modes/version_ab.py`. Anchors below are by function name (current line ranges are hints; they shift as edits land).
- **Test runner (every task):** `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/ --no-cov` (the worktree has no `.venv`; use the main checkout's interpreter). Tests import the module as `from modes import version_ab as v` (path wired by `benchmark/tests/conftest.py`).
- **Non-gating:** `CONFOUND_KEYS` must NOT gain any token/time/iteration key. Resource deltas are informational only.
- **Back-compat:** comparing against an older `score.json` with no `resources` block / no `n_abstain`/`n_error` must degrade gracefully (deltas → `None`/`n/a`), never crash.
- **Determinism:** tests feed synthetic raw JSON / finding dicts with fixed values, so they stay deterministic though the metrics are non-deterministic in real runs.
- **Baseline:** 42 tests currently pass. Every task keeps the whole suite green.

---

### Task 1: Shared `is_real_verdict` predicate + error-aware `grade`

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — add `is_real_verdict` (after `normalize_verdict`, ~L27); edit `grade` (~L29-35); edit `write_verdicts` inline predicate (~L162).
- Test: `benchmark/tests/test_grading.py`

**Interfaces:**
- Produces: `is_real_verdict(nv: str) -> bool` (True for `"TP"`/`"FP"`/`"NMD"`); `grade(verdict, truth)` now returns `"error"` for non-real verdicts.

- [ ] **Step 1: Write the failing tests** — append to `benchmark/tests/test_grading.py`:

```python
def test_is_real_verdict():
    assert v.is_real_verdict("TP") and v.is_real_verdict("FP") and v.is_real_verdict("NMD")
    assert not v.is_real_verdict("ERROR")
    assert not v.is_real_verdict("?")


def test_grade_error_stub():
    # a verdict that isn't TP/FP/NMD is an error stub -> "error", NOT "abstain"
    assert v.grade("ERROR", "real") == "error"
    assert v.grade("", "not-real") == "error"
    assert v.grade("503 Service Unavailable", "real") == "error"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_grading.py -q --no-cov`
Expected: FAIL — `AttributeError: module ... has no attribute 'is_real_verdict'`.

- [ ] **Step 3: Add the predicate and rewrite `grade`.** Insert `is_real_verdict` immediately after `normalize_verdict`, and replace the `grade` body:

```python
def is_real_verdict(nv: str) -> bool:
    """True when the finding produced a real verdict (not an error stub)."""
    return nv in ("TP", "FP", "NMD")


def grade(verdict: str, truth: str) -> str:
    n = normalize_verdict(verdict)
    if not is_real_verdict(n):
        return "error"
    if truth == "real":
        return "CORRECT" if n == "TP" else ("MISS" if n == "FP" else "abstain")
    if truth == "not-real":
        return "CORRECT" if n == "FP" else ("FALSE-ALARM" if n == "TP" else "abstain")
    return "?"
```

- [ ] **Step 4: Use the shared predicate in `write_verdicts`.** In `write_verdicts`, replace the line `if nv not in ("TP", "FP", "NMD"):  # error stub — not real reasoning` with:

```python
        if not is_real_verdict(nv):  # error stub — not real reasoning
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_grading.py -q --no-cov`
Expected: PASS (existing `test_grade_real`/`test_grade_not_real` still pass — NMD still `abstain`).

- [ ] **Step 6: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_grading.py
git commit -m "feat(benchmark): shared is_real_verdict predicate; grade error stubs as 'error'"
```

---

### Task 2: `aggregate` — abstain/error counts + error-adjusted recall

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — `aggregate` (~L38-49).
- Test: `benchmark/tests/test_grading.py`

**Interfaces:**
- Consumes: `is_real_verdict` (Task 1).
- Produces: `aggregate(findings, n_real)` return dict gains `n_abstain`, `n_error`, `n_error_real`; `recall` divisor is `n_real - n_error_real`; `n_real` unchanged (oracle total).

- [ ] **Step 1: Write the failing test** — append to `benchmark/tests/test_grading.py`:

```python
def test_aggregate_excludes_errors_from_recall():
    findings = [
        {"truth": "real", "verdict": "TP", "cost_usd": 1.0},
        {"truth": "real", "verdict": "ERROR", "cost_usd": 0.0},    # errored real
        {"truth": "not-real", "verdict": "NMD", "cost_usd": 1.0},  # genuine abstain
    ]
    a = v.aggregate(findings, n_real=2)
    assert a["n_error"] == 1 and a["n_error_real"] == 1
    assert a["n_abstain"] == 1
    assert a["n_real"] == 2          # oracle total unchanged
    assert a["recall"] == 1.0        # tp_real 1 / (n_real 2 - 1 errored real)
    assert a["precision"] == 1.0     # tp_real 1 / tp_total 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_grading.py::test_aggregate_excludes_errors_from_recall -q --no-cov`
Expected: FAIL — `KeyError: 'n_error'`.

- [ ] **Step 3: Rewrite `aggregate`:**

```python
def aggregate(findings: list[dict], n_real: int) -> dict:
    def nv(f):
        return normalize_verdict(f["verdict"])
    tp_total = sum(1 for f in findings if nv(f) == "TP")
    tp_real = sum(1 for f in findings if f["truth"] == "real" and nv(f) == "TP")
    false_alarm = sum(1 for f in findings if f["truth"] == "not-real" and nv(f) == "TP")
    n_not_real = sum(1 for f in findings if f["truth"] == "not-real")
    n_abstain = sum(1 for f in findings if nv(f) == "NMD")
    n_error = sum(1 for f in findings if not is_real_verdict(nv(f)))
    n_error_real = sum(1 for f in findings if f["truth"] == "real" and not is_real_verdict(nv(f)))
    recall_denom = n_real - n_error_real
    cost = round(sum((f.get("cost_usd") or 0.0) for f in findings), 4)
    return {
        "tp_total": tp_total, "tp_real": tp_real, "false_alarm": false_alarm,
        "precision": (tp_real / tp_total) if tp_total else None,
        "recall": (tp_real / recall_denom) if recall_denom > 0 else None,
        "n_real": n_real, "n_not_real": n_not_real,
        "n_abstain": n_abstain, "n_error": n_error, "n_error_real": n_error_real,
        "cost_usd": cost,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_grading.py -q --no-cov`
Expected: PASS (existing `test_aggregate` still green — with no errors, `recall_denom == n_real`, new keys are additive).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_grading.py
git commit -m "feat(benchmark): aggregate counts abstain/error and excludes errored reals from recall"
```

---

### Task 3: `summarize_resources` pure function

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — add `summarize_resources` after `aggregate`.
- Test: `benchmark/tests/test_resources.py` (new)

**Interfaces:**
- Consumes: `is_real_verdict`, `normalize_verdict`.
- Produces: `summarize_resources(findings: list[dict]) -> dict` with keys `input_tokens`, `output_tokens`, `cached_input_tokens`, `cache_hit_ratio`, `elapsed_seconds`, `iterations_total`, `iterations_mean`.

- [ ] **Step 1: Write the failing tests** — create `benchmark/tests/test_resources.py`:

```python
from modes import version_ab as v


def _rf(verdict, inp, out, cached, elapsed, iters):
    return {"verdict": verdict, "truth": "real", "input_tokens": inp,
            "output_tokens": out, "cached_input_tokens": cached,
            "elapsed_seconds": elapsed, "iterations": iters}


def test_summarize_resources_sums_all_but_iters_over_completed():
    findings = [
        _rf("TP", 1000, 100, 800, 12.0, 3),
        _rf("NMD", 500, 50, 250, 4.0, 2),
        _rf("ERROR", 200, 0, 0, 1.0, 9),   # error: tokens/time counted, iterations NOT
    ]
    r = v.summarize_resources(findings)
    assert r["input_tokens"] == 1700
    assert r["output_tokens"] == 150
    assert r["cached_input_tokens"] == 1050
    assert r["cache_hit_ratio"] == round(1050 / 1700, 4)
    assert r["elapsed_seconds"] == 17.0
    assert r["iterations_total"] == 5      # 3 + 2; error's 9 excluded
    assert r["iterations_mean"] == 2.5     # 5 / 2 completed


def test_summarize_resources_zero_guards():
    r = v.summarize_resources([])
    assert r["cache_hit_ratio"] == 0.0 and r["iterations_mean"] == 0.0
    assert r["input_tokens"] == 0 and r["iterations_total"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_resources.py -q --no-cov`
Expected: FAIL — `AttributeError: ... has no attribute 'summarize_resources'`.

- [ ] **Step 3: Add `summarize_resources`** after `aggregate`:

```python
def summarize_resources(findings: list[dict]) -> dict:
    """Roll up non-deterministic resource metrics. Tokens/time/cost sum over all
    findings (errors still consume resources); iterations only over completed
    (non-error) findings, whose loop count is meaningful. elapsed_seconds is a
    sum of per-finding model time, NOT wall-clock (findings may run concurrently)."""
    def s(key):
        return sum((f.get(key) or 0) for f in findings)
    input_tokens = s("input_tokens")
    cached = s("cached_input_tokens")
    completed = [f for f in findings if is_real_verdict(normalize_verdict(f["verdict"]))]
    iters_total = sum((f.get("iterations") or 0) for f in completed)
    return {
        "input_tokens": input_tokens,
        "output_tokens": s("output_tokens"),
        "cached_input_tokens": cached,
        "cache_hit_ratio": round(cached / input_tokens, 4) if input_tokens else 0.0,
        "elapsed_seconds": round(sum((f.get("elapsed_seconds") or 0.0) for f in findings), 1),
        "iterations_total": iters_total,
        "iterations_mean": round(iters_total / len(completed), 2) if completed else 0.0,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_resources.py -q --no-cov`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_resources.py
git commit -m "feat(benchmark): summarize_resources rolls up tokens/time/iterations"
```

---

### Task 4: `build_score` — per-finding resource fields + resources block

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — `build_score` (~L111-127).
- Test: `benchmark/tests/test_score_build.py`

**Interfaces:**
- Consumes: `aggregate` (Task 2), `summarize_resources` (Task 3), `grade` (Task 1).
- Produces: `build_score(...)` return dict gains a `resources` block; each `findings[]` entry gains `input_tokens`, `output_tokens`, `cached_input_tokens`, `elapsed_seconds`, `iterations`.

- [ ] **Step 1: Extend the `_verdict` helper and write failing tests.** In `benchmark/tests/test_score_build.py`, replace the `_verdict` helper with a variant that accepts extra raw fields, then append two tests:

```python
def _verdict(rule, file, line, verdict, cost=0.1, conf="High", **extra):
    d = {"finding": {"rule_id": rule, "file": file, "start_line": line},
         "verdict": verdict, "confidence": conf, "cost_usd": cost}
    d.update(extra)
    return d


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_score_build.py -q --no-cov`
Expected: FAIL — `KeyError: 'resources'` (and missing per-finding token fields).

- [ ] **Step 3: Rewrite `build_score`:**

```python
def build_score(raw_dir: Path, real_keys: set, meta: dict) -> dict:
    findings = []
    for jf in sorted(Path(raw_dir).glob("*.json")):
        if jf.name.startswith(("summary_", "report")):
            continue
        j = json.loads(jf.read_text())
        f = j["finding"]
        rule, file, line = f["rule_id"].strip(), str(f["file"]).strip(), int(f["start_line"])
        truth = "real" if (rule, file, line) in real_keys else "not-real"
        nv = normalize_verdict(j.get("verdict", "?"))
        findings.append({
            "rule": rule, "file": file, "line": line,
            "verdict": nv, "confidence": j.get("confidence"),
            "cost_usd": j.get("cost_usd") or 0.0,
            "input_tokens": j.get("input_tokens") or 0,
            "output_tokens": j.get("output_tokens") or 0,
            "cached_input_tokens": j.get("cached_input_tokens") or 0,
            "elapsed_seconds": j.get("elapsed_seconds") or 0.0,
            "iterations": j.get("iterations") or 0,
            "truth": truth, "grade": grade(nv, truth),
        })
    return {"meta": meta, "findings": findings,
            "aggregates": aggregate(findings, len(real_keys)),
            "resources": summarize_resources(findings)}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_score_build.py -q --no-cov`
Expected: PASS (existing `test_build_score` still green).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_score_build.py
git commit -m "feat(benchmark): build_score emits resources block + per-finding resource fields"
```

---

### Task 5: `rollup_score` — roll resources + carry per-target resources

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — `rollup_score` (~L300-306).
- Test: `benchmark/tests/test_render.py`

**Interfaces:**
- Consumes: `summarize_resources` (Task 3).
- Produces: `rollup_score(...)` return dict gains a top-level `resources` block; each entry in `targets` gains a `resources` sub-dict.

- [ ] **Step 1: Write the failing test** — append to `benchmark/tests/test_render.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_render.py::test_rollup_resources -q --no-cov`
Expected: FAIL — `KeyError: 'resources'`.

- [ ] **Step 3: Rewrite `rollup_score`:**

```python
def rollup_score(scores: dict, meta: dict) -> dict:
    findings = [{**f, "target": t} for t, s in scores.items() for f in s["findings"]]
    targets = {t: {**s["aggregates"], "panel_hash": s.get("meta", {}).get("panel_hash"),
                   "resources": s.get("resources", {})}
               for t, s in scores.items()}
    n_real = sum(s["aggregates"]["n_real"] for s in scores.values())
    return {"meta": meta, "targets": targets, "findings": findings,
            "aggregates": aggregate(findings, n_real),
            "resources": summarize_resources(findings)}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_render.py -q --no-cov`
Expected: PASS (existing `test_rollup_score` still green — `summarize_resources` tolerates findings without token fields via `.get(...) or 0`).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_render.py
git commit -m "feat(benchmark): rollup_score aggregates resources across targets"
```

---

### Task 6: `compare_scores` / `rollup_compare` — non-gating resource deltas

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — add `resource_deltas` helper + delta-key tuples; edit `compare_scores` return (~L223-228); edit `rollup_compare` signature+return (~L309-318); wire rollup call in `run` (~L587-592).
- Test: `benchmark/tests/test_compare.py`

**Interfaces:**
- Consumes: aggregates with `n_error`/`n_abstain`/`cost_usd` (Task 2), `resources` block (Tasks 3–5).
- Produces: `resource_deltas(previous, current) -> dict`; `compare_scores(...)` return gains `resource_deltas`; `rollup_compare(churns, prev_label, cur_label, deltas, res_deltas, timestamp)` (new positional `res_deltas` before `timestamp`).

- [ ] **Step 1: Extend the `_score` helper and write failing tests.** In `benchmark/tests/test_compare.py`, replace `_score` to accept an optional `resources`, then append two tests:

```python
def _score(version, findings, model="gpt-5.5", iters=5, resources=None):
    n_real = sum(1 for f in findings if f["truth"] == "real")
    meta = {"version": version, "provider": "openai", "model": model, "temperature": 0,
            "max_iterations": iters, "panel_hash": "sha256:x", "timestamp": "T"}
    s = {"meta": meta, "findings": findings, "aggregates": v.aggregate(findings, n_real)}
    if resources is not None:
        s["resources"] = resources
    return s


def test_compare_resource_deltas():
    pr = {"input_tokens": 1000, "output_tokens": 100, "cached_input_tokens": 500,
          "cache_hit_ratio": 0.5, "elapsed_seconds": 10.0, "iterations_mean": 3.0}
    cr = {"input_tokens": 1500, "output_tokens": 120, "cached_input_tokens": 900,
          "cache_hit_ratio": 0.6, "elapsed_seconds": 14.0, "iterations_mean": 3.5}
    prev = _score("1.0.0@a", [_f("r", "f.c", 1, "real", "TP")], resources=pr)
    cur = _score("1.0.0@b", [_f("r", "f.c", 1, "real", "TP")], resources=cr)
    rd = v.compare_scores(prev, cur, "T")["resource_deltas"]
    assert rd["input_tokens"] == 500
    assert rd["elapsed_seconds"] == 4.0
    assert rd["cache_hit_ratio"] == 0.1
    assert rd["cost_usd"] == 0.0 and rd["n_error"] == 0 and rd["n_abstain"] == 0


def test_compare_resource_deltas_missing_previous():
    prev = _score("1.0.0@a", [_f("r", "f.c", 1, "real", "TP")])   # no resources block
    cur = _score("1.0.0@b", [_f("r", "f.c", 1, "real", "TP")],
                 resources={"input_tokens": 100, "output_tokens": 10, "cached_input_tokens": 0,
                            "cache_hit_ratio": 0.0, "elapsed_seconds": 1.0, "iterations_mean": 1.0})
    rd = v.compare_scores(prev, cur, "T")["resource_deltas"]
    assert rd["input_tokens"] is None    # missing on previous -> None, no crash
    assert rd["n_error"] == 0            # both aggregates carry n_error=0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_compare.py -q --no-cov`
Expected: FAIL — `KeyError: 'resource_deltas'`.

- [ ] **Step 3: Add the delta-key tuples and helper.** Immediately after the `CONFOUND_KEYS`/`REQUIRED_KEYS`/`DEFAULT_CONFIG` block, add:

```python
RESOURCE_DELTA_KEYS = ("input_tokens", "output_tokens", "cached_input_tokens",
                       "cache_hit_ratio", "elapsed_seconds", "iterations_mean")
COUNT_DELTA_KEYS = ("cost_usd", "n_error", "n_abstain")  # read from aggregates


def resource_deltas(previous: dict, current: dict) -> dict:
    """Non-gating info deltas for resource + count metrics. A key missing on
    either side (e.g. an older score.json with no resources block) -> None."""
    pr, cr = previous.get("resources") or {}, current.get("resources") or {}
    pa, ca = previous.get("aggregates") or {}, current.get("aggregates") or {}

    def d(a, b):
        return None if (a is None or b is None) else round(b - a, 4)
    out = {k: d(pr.get(k), cr.get(k)) for k in RESOURCE_DELTA_KEYS}
    out.update({k: d(pa.get(k), ca.get(k)) for k in COUNT_DELTA_KEYS})
    return out
```

- [ ] **Step 4: Add `resource_deltas` to `compare_scores` output.** In the `compare_scores` return dict, add the key before `"timestamp"`:

```python
        "deltas": {"precision": delta("precision"), "recall": delta("recall")},
        "resource_deltas": resource_deltas(previous, current),
        "timestamp": timestamp,
```

- [ ] **Step 5: Thread resource deltas through `rollup_compare` and `run`.** Change the `rollup_compare` signature and return:

```python
def rollup_compare(churns: list, prev_label: str, cur_label: str, deltas: dict,
                   res_deltas: dict, timestamp: str) -> dict:
    flips = [f for c in churns for f in c["flips"]]
    totals = {
        "flips": len(flips),
        "improve": sum(1 for f in flips if f["direction"] == "IMPROVE"),
        "regress": sum(1 for f in flips if f["direction"] == "REGRESS"),
        "neutral": sum(1 for f in flips if f["direction"] == "neutral"),
    }
    return {"previous": prev_label, "current": cur_label, "flips": flips,
            "totals": totals, "deltas": deltas, "resource_deltas": res_deltas,
            "timestamp": timestamp}
```

Then in `run`, replace the rollup-compare block (currently building `deltas` and calling `rollup_compare`) with:

```python
        if churns:
            deltas = {"precision": _rollup_delta(roll, prev_label, result_root, "precision"),
                      "recall": _rollup_delta(roll, prev_label, result_root, "recall")}
            prev_roll_path = result_root / prev_label / "score.json"
            prev_roll = json.loads(prev_roll_path.read_text()) if prev_roll_path.exists() else {}
            rc = rollup_compare(list(churns.values()), prev_label, current, deltas,
                                resource_deltas(prev_roll, roll), now)
            (cur_dir / f"compare_vs_{prev_label}.json").write_text(json.dumps(rc, indent=2))
            (cur_dir / f"compare_vs_{prev_label}.md").write_text(scorer.render_compare(rc))
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_compare.py benchmark/tests/test_cli.py -q --no-cov`
Expected: PASS (existing compare + CLI tests still green; confound guard unchanged).

- [ ] **Step 7: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_compare.py
git commit -m "feat(benchmark): non-gating resource deltas in compare + rollup compare"
```

---

### Task 7: `render_score_md` — resources summary line + two per-target tables

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — add `_fmt_tokens` + `_res_summary` helpers (near `_pct`/`_panel_short`, ~L231-237); edit `render_score_md` (~L240-273).
- Test: `benchmark/tests/test_render.py`

**Interfaces:**
- Consumes: score dicts with `aggregates` (n_abstain/n_error) + `resources`; rollup `targets[t]["resources"]`.
- Produces: `_fmt_tokens(n) -> str`, `_res_summary(res: dict) -> str`; unchanged `render_score_md` signature.

- [ ] **Step 1: Write the failing tests** — append to `benchmark/tests/test_render.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_render.py -q --no-cov`
Expected: FAIL — resources line / resources table assertions not found.

- [ ] **Step 3: Add formatting helpers** next to `_pct`/`_panel_short`:

```python
def _fmt_tokens(n) -> str:
    n = n or 0
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}k"
    return str(n)


def _res_summary(res: dict) -> str:
    return (f"{_fmt_tokens(res.get('input_tokens'))} in / "
            f"{_fmt_tokens(res.get('output_tokens'))} out · "
            f"cache {_pct(res.get('cache_hit_ratio'))} · "
            f"{res.get('elapsed_seconds', 0)}s model-time · "
            f"iters μ{res.get('iterations_mean', 0)}")
```

- [ ] **Step 4: Rewrite `render_score_md`:**

```python
def render_score_md(score: dict) -> str:
    m, a = score["meta"], score["aggregates"]
    res = score.get("resources") or {}
    is_roll = "targets" in score
    meta_line = f"Model `{m.get('model')}` · temp `{m.get('temperature')}` · "
    if not is_roll:  # a rollup spans many panels — no single hash (per-target table below)
        meta_line += f"panel `{_panel_short(m.get('panel_hash'))}` · "
    meta_line += str(m.get("timestamp"))
    lines = [
        f"# Score — {m['version']}", "", meta_line, "",
        f"precision **{_pct(a['precision'])}** · recall **{_pct(a['recall'])}** · "
        f"TP {a['tp_total']} (real {a['tp_real']}, false-alarm {a['false_alarm']}) · "
        f"real {a['n_real']} · not-real {a['n_not_real']} · NMD {a.get('n_abstain', 0)} · "
        f"err {a.get('n_error', 0)} · ${a['cost_usd']}",
        f"_resources:_ {_res_summary(res)}", "",
    ]
    if is_roll:
        lines += ["| target | finding | truth | verdict | grade | conf |",
                  "|---|---|---|---|---|---|"]
        for f in score["findings"]:
            lines.append(f"| {f.get('target', '')} | {f['rule']}@{f['file']}:{f['line']} | "
                         f"{f['truth']} | {f['verdict']} | {f['grade']} | {f['confidence']} |")
        lines += ["", "## Per target — correctness",
                  "| target | precision | recall | TP (real/FA) | real | not-real | NMD | err | panel |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for t, ta in score["targets"].items():
            lines.append(
                f"| {t} | {_pct(ta.get('precision'))} | {_pct(ta.get('recall'))} | "
                f"{ta.get('tp_total')} ({ta.get('tp_real')}/{ta.get('false_alarm')}) | "
                f"{ta.get('n_real')} | {ta.get('n_not_real')} | {ta.get('n_abstain', 0)} | "
                f"{ta.get('n_error', 0)} | {_panel_short(ta.get('panel_hash'))} |")
        lines += ["", "## Per target — resources",
                  "| target | in-tok | out-tok | cache% | time(s) | itersμ | cost |",
                  "|---|---|---|---|---|---|---|"]
        for t, ta in score["targets"].items():
            tr = ta.get("resources") or {}
            lines.append(
                f"| {t} | {_fmt_tokens(tr.get('input_tokens'))} | "
                f"{_fmt_tokens(tr.get('output_tokens'))} | {_pct(tr.get('cache_hit_ratio'))} | "
                f"{tr.get('elapsed_seconds', 0)} | {tr.get('iterations_mean', 0)} | "
                f"${ta.get('cost_usd')} |")
    else:
        lines += ["| finding | truth | verdict | grade | conf |", "|---|---|---|---|---|"]
        for f in score["findings"]:
            lines.append(f"| {f['rule']}@{f['file']}:{f['line']} | {f['truth']} | "
                         f"{f['verdict']} | {f['grade']} | {f['confidence']} |")
    return "\n".join(lines) + "\n"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_render.py -q --no-cov`
Expected: PASS (existing `test_render_score` / `test_render_rollup_md` still green — `"## Per target"` is a substring of `"## Per target — correctness"`; `.get` defaults tolerate old-shape dicts).

- [ ] **Step 6: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_render.py
git commit -m "feat(benchmark): render resources summary + per-target correctness/resources tables"
```

---

### Task 8: `render_compare_md` — resource-deltas section

**Files:**
- Modify: `benchmark/src/modes/version_ab.py` — `render_compare_md` (~L276-297).
- Test: `benchmark/tests/test_render.py`

**Interfaces:**
- Consumes: churn dicts with optional `resource_deltas` (Task 6).
- Produces: unchanged `render_compare_md` signature; renders a `## Resource deltas` section only when `resource_deltas` is present and non-empty.

- [ ] **Step 1: Write the failing tests** — append to `benchmark/tests/test_render.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/test_render.py::test_render_compare_resource_deltas -q --no-cov`
Expected: FAIL — `"## Resource deltas"` not found.

- [ ] **Step 3: Rewrite `render_compare_md`** (add the section after the flips block, before `return`):

```python
def render_compare_md(churn: dict) -> str:
    t, d = churn["totals"], churn["deltas"]

    def signed(x):
        return "n/a" if x is None else f"{x:+.0%}"

    lines = [
        f"# Compare — {churn['previous']} → {churn['current']}", "",
        f"Δprecision **{signed(d.get('precision'))}** · Δrecall **{signed(d.get('recall'))}** · "
        f"{churn['timestamp']}", "",
        f"## Flips: {t['flips']} (improve {t['improve']} · regress {t['regress']} · "
        f"neutral {t['neutral']})", "",
    ]
    if churn["flips"]:
        lines += ["| finding | truth | prev → cur | dir | conf |", "|---|---|---|---|---|"]
        for f in churn["flips"]:
            lines.append(f"| {f['rule']}@{f['file']}:{f['line']} | {f['truth']} | "
                         f"{f['previous']} → {f['current']} | {f['direction']} | "
                         f"{f['prev_conf']}→{f['cur_conf']} |")
    else:
        lines.append("_No verdict changed._")
    rd = churn.get("resource_deltas") or {}
    if rd:
        def sd(x):
            return "n/a" if x is None else f"{x:+g}"
        lines += ["", "## Resource deltas", "",
                  "_Informational, non-gating — run-to-run variance is expected._", "",
                  f"Δcost `{sd(rd.get('cost_usd'))}` · Δin-tok `{sd(rd.get('input_tokens'))}` · "
                  f"Δout-tok `{sd(rd.get('output_tokens'))}` · "
                  f"Δcache-ratio `{sd(rd.get('cache_hit_ratio'))}` · "
                  f"Δtime `{sd(rd.get('elapsed_seconds'))}` · "
                  f"Δitersμ `{sd(rd.get('iterations_mean'))}` · "
                  f"Δn_error `{sd(rd.get('n_error'))}` · Δn_abstain `{sd(rd.get('n_abstain'))}`"]
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run the full benchmark suite to verify everything passes**

Run: `/home/thanhvc4/project/VulnHunterX/.venv/bin/python -m pytest benchmark/tests/ -q --no-cov`
Expected: PASS — all tests green (42 baseline + the new ones; none regressed).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/modes/version_ab.py benchmark/tests/test_render.py
git commit -m "feat(benchmark): render non-gating resource-deltas section in compare view"
```

---

## Notes for the implementer

- Work top-to-bottom: Task 2 needs Task 1's `is_real_verdict`; Tasks 4–5 need Tasks 2–3; Task 6 needs the new aggregate keys + resources block; Tasks 7–8 render what 2–6 produce.
- No docs to update: `benchmark/README.md` does not enumerate `score.json` keys or `score.md` columns (verified `grep -n "aggregates\|cost_usd\|Per target\|resources" benchmark/README.md` → no matches), so this change is code + tests only.
- Do NOT touch `CONFOUND_KEYS`. Resource metrics are non-deterministic and must never gate a comparison.
