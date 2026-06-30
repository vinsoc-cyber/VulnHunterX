"""versionab — version-A/B verifier benchmark mode."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import harness
import scoring


def normalize_verdict(v: str) -> str:
    s = (v or "").strip().lower()
    if s == "tp" or "true positive" in s:
        return "TP"
    if s == "fp" or "false positive" in s:
        return "FP"
    if s == "nmd" or "more data" in s or "needs more" in s:
        return "NMD"
    return (v or "?").strip().upper()


def grade(verdict: str, truth: str) -> str:
    n = normalize_verdict(verdict)
    if truth == "real":
        return "CORRECT" if n == "TP" else ("MISS" if n == "FP" else "abstain")
    if truth == "not-real":
        return "CORRECT" if n == "FP" else ("FALSE-ALARM" if n == "TP" else "abstain")
    return "?"


def aggregate(findings: list[dict], n_real: int) -> dict:
    tp_total = sum(1 for f in findings if normalize_verdict(f["verdict"]) == "TP")
    tp_real = sum(1 for f in findings if f["truth"] == "real" and normalize_verdict(f["verdict"]) == "TP")
    false_alarm = sum(1 for f in findings if f["truth"] == "not-real" and normalize_verdict(f["verdict"]) == "TP")
    n_not_real = sum(1 for f in findings if f["truth"] == "not-real")
    cost = round(sum((f.get("cost_usd") or 0.0) for f in findings), 4)
    return {
        "tp_total": tp_total, "tp_real": tp_real, "false_alarm": false_alarm,
        "precision": (tp_real / tp_total) if tp_total else None,
        "recall": (tp_real / n_real) if n_real else None,
        "n_real": n_real, "n_not_real": n_not_real, "cost_usd": cost,
    }


def classify_flip(prev_v: str, cur_v: str, truth: str) -> str:
    pc, cc = grade(prev_v, truth), grade(cur_v, truth)
    if cc == "CORRECT" and pc != "CORRECT":
        return "IMPROVE"
    if pc == "CORRECT" and cc != "CORRECT":
        return "REGRESS"
    return "neutral"


def load_real_keys(gt_path: Path) -> set:
    real = set()
    for k in json.loads(Path(gt_path).read_text()):
        rule, rest = k.rsplit("@", 1)
        file, line = rest.rsplit(":", 1)
        real.add((rule.strip(), file.strip(), int(line)))
    return real


def panel_hash(test_case_dir: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(Path(test_case_dir).rglob("*")):
        if f.is_file() and f.name != "ground_truth.json":
            h.update(str(f.relative_to(test_case_dir)).encode())
            h.update(f.read_bytes())
    return "sha256:" + h.hexdigest()[:32]


def sarif_result_keys(sarif_path) -> set[tuple]:
    s = json.loads(Path(sarif_path).read_text())
    keys = set()
    for run in s.get("runs", []):
        for res in run.get("results", []):
            rid = res.get("ruleId")
            for loc in res.get("locations", []):
                pl = loc.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri")
                line = pl.get("region", {}).get("startLine")
                if uri is None or line is None:
                    continue
                keys.add((rid, uri, line))
    return keys


def validate_panel(test_case_dir) -> None:
    tc = Path(test_case_dir)
    app = tc.name
    real_keys = load_real_keys(tc / "ground_truth.json")
    sarif_keys = sarif_result_keys(tc / "scanner_result" / f"{app}.sarif")
    problems = []
    problems += [f"absolute oracle path: {r}@{f}:{ln}"
                 for (r, f, ln) in sorted(real_keys) if str(f).startswith("/")]
    problems += [f"absolute SARIF uri: {uri}"
                 for uri in sorted({u for (_r, u, _l) in sarif_keys}) if str(uri).startswith("/")]
    problems += [f"oracle key not in SARIF: {r}@{f}:{ln}"
                 for (r, f, ln) in sorted(real_keys) if (r, f, ln) not in sarif_keys]
    if problems:
        sys.exit(f"ERROR: panel '{app}' failed validation:\n  " + "\n  ".join(problems))


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
            "truth": truth, "grade": grade(nv, truth),
        })
    return {"meta": meta, "findings": findings, "aggregates": aggregate(findings, len(real_keys))}


CONFOUND_KEYS = ("provider", "model", "temperature", "panel_hash")


class ConfoundError(Exception):
    pass


def compare_scores(previous: dict, current: dict, timestamp: str) -> dict:
    for k in CONFOUND_KEYS:
        if previous["meta"].get(k) != current["meta"].get(k):
            raise ConfoundError(
                f"{k}: previous={previous['meta'].get(k)!r} current={current['meta'].get(k)!r}")

    prev = {(f["rule"], f["file"], f["line"]): f for f in previous["findings"]}
    cur = {(f["rule"], f["file"], f["line"]): f for f in current["findings"]}

    flips = []
    for key in sorted(set(prev) | set(cur)):
        pf, cf = prev.get(key), cur.get(key)
        pv = pf["verdict"] if pf else "—"
        cv = cf["verdict"] if cf else "—"
        if pv == cv:
            continue
        truth = (cf or pf)["truth"]
        flips.append({
            "rule": key[0], "file": key[1], "line": key[2], "truth": truth,
            "previous": pv, "current": cv,
            "prev_conf": pf["confidence"] if pf else None,
            "cur_conf": cf["confidence"] if cf else None,
            "direction": classify_flip(pv, cv, truth),
        })

    def delta(metric):
        a = previous["aggregates"].get(metric)
        b = current["aggregates"].get(metric)
        return None if (a is None or b is None) else round(b - a, 4)

    totals = {
        "flips": len(flips),
        "improve": sum(1 for f in flips if f["direction"] == "IMPROVE"),
        "regress": sum(1 for f in flips if f["direction"] == "REGRESS"),
        "neutral": sum(1 for f in flips if f["direction"] == "neutral"),
    }
    return {
        "previous": previous["meta"]["version"], "current": current["meta"]["version"],
        "flips": flips, "totals": totals,
        "deltas": {"precision": delta("precision"), "recall": delta("recall")},
        "timestamp": timestamp,
    }


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def _panel_short(h) -> str:
    s = str(h or "")
    return (s[:16] + "…") if s else "—"


def render_score_md(score: dict) -> str:
    m, a = score["meta"], score["aggregates"]
    is_roll = "targets" in score
    meta_line = f"Model `{m.get('model')}` · temp `{m.get('temperature')}` · "
    if not is_roll:  # a rollup spans many panels — no single hash (per-target table below)
        meta_line += f"panel `{_panel_short(m.get('panel_hash'))}` · "
    meta_line += str(m.get("timestamp"))
    lines = [
        f"# Score — {m['version']}", "", meta_line, "",
        f"precision **{_pct(a['precision'])}** · recall **{_pct(a['recall'])}** · "
        f"TP {a['tp_total']} (real {a['tp_real']}, false-alarm {a['false_alarm']}) · "
        f"real {a['n_real']} · not-real {a['n_not_real']} · ${a['cost_usd']}", "",
    ]
    if is_roll:
        lines += ["| target | finding | truth | verdict | grade | conf |",
                  "|---|---|---|---|---|---|"]
        for f in score["findings"]:
            lines.append(f"| {f.get('target', '')} | {f['rule']}@{f['file']}:{f['line']} | "
                         f"{f['truth']} | {f['verdict']} | {f['grade']} | {f['confidence']} |")
        lines += ["", "## Per target",
                  "| target | precision | recall | TP (real/FA) | real | not-real | cost | panel |",
                  "|---|---|---|---|---|---|---|---|"]
        for t, ta in score["targets"].items():
            lines.append(
                f"| {t} | {_pct(ta.get('precision'))} | {_pct(ta.get('recall'))} | "
                f"{ta.get('tp_total')} ({ta.get('tp_real')}/{ta.get('false_alarm')}) | "
                f"{ta.get('n_real')} | {ta.get('n_not_real')} | ${ta.get('cost_usd')} | "
                f"{_panel_short(ta.get('panel_hash'))} |")
    else:
        lines += ["| finding | truth | verdict | grade | conf |", "|---|---|---|---|---|"]
        for f in score["findings"]:
            lines.append(f"| {f['rule']}@{f['file']}:{f['line']} | {f['truth']} | "
                         f"{f['verdict']} | {f['grade']} | {f['confidence']} |")
    return "\n".join(lines) + "\n"


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
    return "\n".join(lines) + "\n"


def rollup_score(scores: dict, meta: dict) -> dict:
    findings = [{**f, "target": t} for t, s in scores.items() for f in s["findings"]]
    targets = {t: {**s["aggregates"], "panel_hash": s.get("meta", {}).get("panel_hash")}
               for t, s in scores.items()}
    n_real = sum(s["aggregates"]["n_real"] for s in scores.values())
    return {"meta": meta, "targets": targets, "findings": findings,
            "aggregates": aggregate(findings, n_real)}


def rollup_compare(churns: list, prev_label: str, cur_label: str, deltas: dict, timestamp: str) -> dict:
    flips = [f for c in churns for f in c["flips"]]
    totals = {
        "flips": len(flips),
        "improve": sum(1 for f in flips if f["direction"] == "IMPROVE"),
        "regress": sum(1 for f in flips if f["direction"] == "REGRESS"),
        "neutral": sum(1 for f in flips if f["direction"] == "neutral"),
    }
    return {"previous": prev_label, "current": cur_label, "flips": flips,
            "totals": totals, "deltas": deltas, "timestamp": timestamp}


class Harness(harness.Harness):
    def __init__(self, root: Path):
        self.root = Path(root)  # repo root: engine writes output/<lang>/<name>/ here

    def _invoke(self, cmd, cwd=None):  # subprocess seam (patched in tests)
        subprocess.run(cmd, check=True, cwd=cwd)

    def fetch(self, meta: dict, dest: Path) -> Path:
        dest = Path(dest)
        self._invoke(["git", "clone", "--quiet", meta["repo_url"], str(dest)])
        self._invoke(["git", "-C", str(dest), "checkout", "--quiet", meta["sha"]])
        return dest

    def _work_dir(self, cfg, raw_dir: Path) -> Path:
        """Engine cwd: it writes its output/ tree, repos/ symlinks and LLM logs
        here. Default = <raw_dir>/_engine, so it persists or is discarded together
        with the kept verdicts (governed by --keep-output). cfg['output_dir']
        (relative -> repo root, or absolute) redirects it elsewhere."""
        out = cfg.get("output_dir")
        if out:
            work = Path(out)
            return work if work.is_absolute() else self.root / work
        return Path(raw_dir) / "_engine"

    def run(self, meta, src, cfg, raw_dir, sarif, context_dir):
        lang, name = meta["lang"], meta["name"]
        raw_dir = Path(raw_dir)
        work = self._work_dir(cfg, raw_dir)
        work.mkdir(parents=True, exist_ok=True)
        eng = work / "output" / lang / name
        if context_dir and Path(context_dir).is_dir():
            dst = eng / "context"
            if dst.exists():
                shutil.rmtree(dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(context_dir, dst)
        vr = eng / "verification_results"
        if vr.exists():
            for old in vr.glob("*.json"):
                old.unlink()
        cmd = [sys.executable, "-m", "vuln_hunter_x.cli.main", "verify",
               "--sarif", str(sarif), "--local-path", str(src),
               "--name", name, "--lang", lang,
               "--provider", cfg["provider"], "--model", cfg["model"],
               "--temperature", str(cfg["temperature"]),
               "--max-iterations", str(cfg["max_iterations"]), "-q"]
        self._invoke(cmd, cwd=str(work))
        raw_dir.mkdir(parents=True, exist_ok=True)
        cost = 0.0
        for jf in sorted(vr.glob("*.json")):
            if jf.name.startswith(("summary_", "report")):
                continue
            j = json.loads(jf.read_text())
            (raw_dir / jf.name).write_text(json.dumps(j, indent=2))
            cost += j.get("cost_usd") or 0.0
        shutil.rmtree(work / "repos", ignore_errors=True)  # drop dangling clone symlink
        return round(cost, 4)


class Scorer(scoring.Scorer):
    def score(self, raw_dir, real_keys, meta):
        return build_score(raw_dir, real_keys, meta)

    def compare(self, previous, current, timestamp):
        return compare_scores(previous, current, timestamp)

    def render_score(self, score):
        return render_score_md(score)

    def render_compare(self, churn):
        return render_compare_md(churn)


def add_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--targets", default=None, help="comma list; default = all of test_case/")
    p.add_argument("--config", default=None, help="path to config.yaml")
    p.add_argument("--previous", default=None, help="baseline VER@SHA (default: most recent other)")
    p.add_argument("--current", default=None, help="current label (default: {__version__}@{short-sha})")
    p.add_argument("--compare-only", action="store_true", help="recompute churn from existing score.json")
    p.add_argument("--no-compare", action="store_true", help="run + score only")
    p.add_argument("--force", action="store_true", help="overwrite an existing version dir")
    p.add_argument("--no-keep-output", action="store_true", help="discard raw output after scoring")
    p.add_argument("--timestamp", default=None, help=argparse.SUPPRESS)  # test determinism


def load_config(path) -> dict:
    import yaml
    cfg = yaml.safe_load(Path(path).read_text())
    cfg.setdefault("max_iterations", 5)
    cfg.setdefault("max_cost", None)
    return cfg


def current_label(repo_root) -> str:
    from vuln_hunter_x import __version__
    sha = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()
    return f"{__version__}@{sha}"


def resolve_previous(previous_arg, result_root: Path, current: str):
    if previous_arg:
        return previous_arg
    result_root = Path(result_root)
    if not result_root.is_dir():
        return None
    candidates = []
    for d in result_root.iterdir():
        if d.name == current or not (d / "score.json").exists():
            continue
        try:
            ts = json.loads((d / "score.json").read_text())["meta"]["timestamp"]
        except Exception:
            ts = ""
        candidates.append((ts, d.name))
    return max(candidates)[1] if candidates else None


def _rollup_delta(cur_roll, prev_label, result_root: Path, metric):
    p = Path(result_root) / prev_label / "score.json"
    if not p.exists():
        return None
    a = json.loads(p.read_text())["aggregates"].get(metric)
    b = cur_roll["aggregates"].get(metric)
    return None if (a is None or b is None) else round(b - a, 4)


def run(args, bench_root) -> int:
    bench_root = Path(bench_root)
    repo_root = bench_root.parent
    test_case = bench_root / "test_case"
    result_root = bench_root / "result" / "version_ab"
    output_root = bench_root / "output" / "version_ab"
    cfg_path = Path(args.config) if args.config else bench_root / "config" / "version_ab" / "config.yaml"
    cfg = load_config(cfg_path)

    if not test_case.is_dir():
        sys.exit(f"ERROR: test_case dir not found: {test_case}")
    if args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    else:
        targets = sorted(p.name for p in test_case.iterdir() if (p / "metadata.json").exists())
    if not targets:
        sys.exit("ERROR: no targets found under test_case/.")

    current = args.current or current_label(repo_root)
    cur_dir = result_root / current
    if cur_dir.exists() and not args.force and not args.compare_only and not args.dry_run:
        sys.exit(f"ERROR: {cur_dir} already exists. Bump __version__, or pass --force to overwrite.")

    hns, scorer = Harness(repo_root), Scorer()
    now = args.timestamp or datetime.datetime.now().isoformat(timespec="seconds")
    prev_label = resolve_previous(args.previous, result_root, current)
    total_cost = 0.0
    scores, churns = {}, {}
    failed_targets = []

    for target in targets:
        tc = test_case / target
        if not (tc / "metadata.json").exists():
            sys.exit(f"ERROR: test_case/{target}/metadata.json not found.")
        meta_t = json.loads((tc / "metadata.json").read_text())
        real_keys = load_real_keys(tc / "ground_truth.json")
        score_meta = {"version": current, "provider": cfg["provider"], "model": cfg["model"],
                      "temperature": cfg["temperature"], "panel_hash": panel_hash(tc), "timestamp": now}
        tdir = cur_dir / target

        try:
            if args.compare_only:
                sp = tdir / "score.json"
                if not sp.exists():
                    sys.exit(f"ERROR: --compare-only: {sp} not found. Score this version first.")
                score = json.loads(sp.read_text())
            elif args.dry_run:
                print(f"[dry-run] {target}: clone {meta_t['repo_url']}@{meta_t['sha']} → "
                      f"verify {target}.sarif (provider={cfg['provider']} model={cfg['model']} "
                      f"temp={cfg['temperature']})")
                continue
            else:
                validate_panel(tc)
                sarif = tc / "scanner_result" / f"{target}.sarif"
                ctx = tc / "scanner_result" / "context"
                keep = not args.no_keep_output
                raw_dir = (output_root / current / target) if keep \
                    else Path(tempfile.mkdtemp(prefix="vab_raw_"))
                clone = Path(tempfile.mkdtemp(prefix="vab_src_")) / target
                try:
                    hns.fetch(meta_t, clone)
                    cost = hns.run(meta_t, clone, cfg, raw_dir, sarif, ctx if ctx.is_dir() else None)
                    total_cost += cost
                    score = scorer.score(raw_dir, real_keys, score_meta)
                    tdir.mkdir(parents=True, exist_ok=True)
                    (tdir / "score.json").write_text(json.dumps(score, indent=2))
                    (tdir / "score.md").write_text(scorer.render_score(score))
                    a = score["aggregates"]
                    print(f"[{target}] precision={_pct(a['precision'])} recall={_pct(a['recall'])} ${cost}")
                finally:  # always reclaim temp clone + (when discarding) temp raw_dir
                    shutil.rmtree(clone.parent, ignore_errors=True)
                    if not keep:
                        shutil.rmtree(raw_dir, ignore_errors=True)
                if cfg.get("max_cost") and total_cost > cfg["max_cost"]:
                    sys.exit(f"ERROR: max_cost ${cfg['max_cost']} exceeded (${total_cost:.2f}).")
        except Exception as e:
            print(f"[{target}] FAILED: {e}")
            failed_targets.append(target)
            continue

        scores[target] = score

        if not args.no_compare:
            if not prev_label:
                print(f"[{target}] no previous version found; skipping compare.")
                continue
            prev_path = result_root / prev_label / target / "score.json"
            if not prev_path.exists():
                print(f"[{target}] previous {prev_label} has no score for this target; skipping.")
                continue
            try:
                churn = scorer.compare(json.loads(prev_path.read_text()), score, now)
            except ConfoundError as e:
                sys.exit(f"ERROR: confound guard — {e}")
            churns[target] = churn
            tdir.mkdir(parents=True, exist_ok=True)
            (tdir / f"compare_vs_{prev_label}.json").write_text(json.dumps(churn, indent=2))
            (tdir / f"compare_vs_{prev_label}.md").write_text(scorer.render_compare(churn))

    if args.dry_run:
        return 0

    if scores:
        roll = rollup_score(scores, {"version": current, "provider": cfg["provider"],
                                     "model": cfg["model"], "temperature": cfg["temperature"],
                                     "timestamp": now})
        cur_dir.mkdir(parents=True, exist_ok=True)
        (cur_dir / "score.json").write_text(json.dumps(roll, indent=2))
        (cur_dir / "score.md").write_text(scorer.render_score(roll))
        if churns:
            deltas = {"precision": _rollup_delta(roll, prev_label, result_root, "precision"),
                      "recall": _rollup_delta(roll, prev_label, result_root, "recall")}
            rc = rollup_compare(list(churns.values()), prev_label, current, deltas, now)
            (cur_dir / f"compare_vs_{prev_label}.json").write_text(json.dumps(rc, indent=2))
            (cur_dir / f"compare_vs_{prev_label}.md").write_text(scorer.render_compare(rc))
    return 1 if failed_targets else 0
