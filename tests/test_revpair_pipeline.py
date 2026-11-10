# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""End-to-end tests of the revision-pair builder on synthetic git repositories.

No scanner, network or LLM is used: a fake :class:`AnalyzerBackend` runs a tiny
regex "scanner" over each revision's worktree and writes canned SARIF.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP
from benchmarks.builders.revpair.alert_key import Alert, enclosing_function, match_alerts
from benchmarks.builders.revpair.checkout import (
    CheckoutError,
    RevisionCheckout,
    repo_slug,
    revision_name,
    validate_repo_url,
    validate_sha,
)
from benchmarks.builders.revpair.hunks import parse_unified_diff
from benchmarks.builders.revpair.label import cwe_matches
from benchmarks.builders.revpair.manifest import (
    load_manifest,
    verify_manifest,
    write_attrition,
    write_manifest,
)
from benchmarks.builders.revpair.runner import (
    AnalysisRequest,
    AttritionLog,
    BuildRefusedError,
    FixSpec,
    RevisionRef,
    ScannerBackend,
    StaleRevisionError,
    analyze_revision,
    ensure_revision_marker,
    needs_build,
    process_fix,
    sarif_path_for,
)
from vuln_hunter_x.core.types import Finding

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not available")


# ── synthetic repositories ────────────────────────────────────────────────


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


def _commit(repo: Path, files: dict[str, str | None], msg: str) -> str:
    for rel, text in files.items():
        p = repo / rel
        if text is None:
            _git(repo, "rm", "-q", rel)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        _git(repo, "add", rel)
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def _init(tmp_path: Path, name: str = "upstream") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    return repo


VULN_APP = """\
import subprocess


def helper(x):
    return x + 1


def run(cmd):
    print(cmd)
    subprocess.call(cmd, shell=True)
    return 0


def other(path):
    os_system(path)
"""

FIX_APP = """\
import shlex
import subprocess

# Inserted lines shift everything below; matching must survive the shift.


def helper(x):
    return x + 1


def run(cmd):
    print(cmd)
    subprocess.call(shlex.split(cmd))
    return 0


def other(path):
    os_system(path)
"""


# ── fake scanner backend ──────────────────────────────────────────────────

# (rule_id, regex, cwe tag, file-level precondition regex or None)
_RULES: list[tuple[str, str, str, str | None]] = [
    # Sink line edited by the fix, CWE matches CVE → silver-tp.
    ("py/command-line-injection", r"shell=True", "external/cwe/cwe-078", None),
    # Same edited line, unrelated CWE → silver-tp-weak (cwe-mismatch).
    ("py/dangerous-call-arg", r"call\(cmd,", "external/cwe/cwe-676", None),
    # Unchanged line in the changed function, vanishes with the fix → weak (function-only).
    ("py/log-tainted", r"print\(cmd\)", "external/cwe/cwe-078", r"shell=True"),
    # Unchanged line in an untouched function that also vanishes → ambiguous.
    ("py/helper-smell", r"return x \+ 1", "external/cwe/cwe-078", r"shell=True"),
    # Edited line, but the rule still fires on its replacement → ambiguous.
    ("py/subprocess-any", r"subprocess\.call", "external/cwe/cwe-078", None),
    # Untouched function, survives the fix → persistent (FP).
    ("py/os-system", r"os_system\(", "external/cwe/cwe-078", None),
    # Only on the fix side → new-on-fix-side.
    ("py/shlex-import", r"^import shlex", "external/cwe/cwe-020", None),
]


class FakeBackend:
    """Regex 'scanner' writing CodeQL-shaped SARIF to the product's paths."""

    def __init__(self, fingerprints: bool = False) -> None:
        self.calls: list[AnalysisRequest] = []
        self.fingerprints = fingerprints

    def describe(self, tool: str, lang: str, profile: str) -> dict[str, Any]:
        return {"tool": tool, "version": "fake 1.0", "profile": profile, "rules": {}}

    def analyze(self, request: AnalysisRequest) -> Path:
        self.calls.append(request)
        results: list[dict[str, Any]] = []
        for path in sorted(request.source_dir.rglob("*.py")):
            rel = path.relative_to(request.source_dir).as_posix()
            text = path.read_text(encoding="utf-8")
            for rule_id, rx, _tag, pre in _RULES:
                if pre and not re.search(pre, text):
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    if re.search(rx, line):
                        res: dict[str, Any] = {
                            "ruleId": rule_id,
                            "message": {"text": f"{rule_id} hit"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": rel},
                                        "region": {
                                            "startLine": i,
                                            "startColumn": 1,
                                            "snippet": {"text": line},
                                        },
                                    }
                                }
                            ],
                        }
                        if self.fingerprints:
                            res["partialFingerprints"] = {
                                "primaryLocationLineHash": f"{rule_id}:{rel}:{line.strip()}:1"
                            }
                        results.append(res)
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {"id": r, "properties": {"tags": ["security", tag]}}
                                for r, _rx, tag, _pre in _RULES
                            ],
                        }
                    },
                    "results": results,
                }
            ],
        }
        out = sarif_path_for(request.output_dir, request.tool, request.lang, request.name)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif), encoding="utf-8")
        return out


def _spec(repo: Path, fix_sha: str, **kw: Any) -> FixSpec:
    data = {
        "cve_id": "CVE-2099-0001",
        "cve_published": "2099-01-01",
        "repo_url": str(repo),
        "lang": "python",
        "cwe": "CWE-78",
        "fix_sha": fix_sha,
        "repo": "demo",
    }
    data.update(kw)
    return FixSpec.from_dict(data, allow_local=True)


def _run(tmp_path: Path, spec: FixSpec, backend: FakeBackend | None = None):
    attrition = AttritionLog()
    entries = process_fix(
        spec,
        checkout=RevisionCheckout(tmp_path / "cache", allow_local=True),
        backend=backend or FakeBackend(),
        tools=["codeql"],
        profile="standard",
        output_dir=tmp_path / "output",
        attrition=attrition,
        repos_dir=tmp_path / "repos",
    )
    return entries, attrition


@pytest.fixture()
def cve_repo(tmp_path: Path) -> tuple[Path, str, str]:
    repo = _init(tmp_path)
    parent = _commit(repo, {"app.py": VULN_APP}, "vulnerable")
    fix = _commit(repo, {"app.py": FIX_APP}, "fix CVE")
    return repo, parent, fix


# ── tier assignment ───────────────────────────────────────────────────────


def test_tiers_assigned(tmp_path: Path, cve_repo: tuple[Path, str, str]) -> None:
    repo, parent, fix = cve_repo
    entries, attrition = _run(tmp_path, _spec(repo, fix))
    by_rule = {e.rule_id: e for e in entries}

    tp = by_rule["py/command-line-injection"]
    assert tp.label == LABEL_TP
    assert tp.metadata["label_tier"] == "silver-tp"
    assert tp.metadata["cwe_match"] == "exact"
    assert tp.sink_line == tp.start_line == 10
    assert tp.file_path == "app.py"
    assert tp.function_name == "run"
    assert "shell=True" in tp.code_snippet

    weak_cwe = by_rule["py/dangerous-call-arg"]
    assert weak_cwe.label == LABEL_TP
    assert weak_cwe.metadata["label_tier"] == "silver-tp-weak"
    assert weak_cwe.metadata["label_reason"].endswith("cwe-mismatch")

    weak_fn = by_rule["py/log-tainted"]
    assert weak_fn.metadata["label_tier"] == "silver-tp-weak"
    assert weak_fn.metadata["touch"] == "function"

    fp = by_rule["py/os-system"]
    assert fp.label == LABEL_FP
    assert fp.metadata["label_tier"] == "persistent"
    assert fp.metadata["label_note"] == "persistent alert, not confirmed FP"
    assert fp.metadata["match_kind"] == "primary"  # survived the 3-line shift

    # Ambiguous outcomes are excluded from the manifest but counted.
    assert "py/helper-smell" not in by_rule
    assert "py/subprocess-any" not in by_rule
    assert "py/shlex-import" not in by_rule
    reasons = {(r["tier"], r["reason"]) for r in attrition.records if r["step"] == "label"}
    assert ("ambiguous", "disappears-without-touching-fix") in reasons
    assert ("ambiguous", "touches-fix-but-persists:hunk") in reasons
    assert ("ambiguous", "new-on-fix-side") in reasons

    for e in entries:
        md = e.metadata
        assert md["label_source"] == "auto-diff"
        assert md["adjudication"] == "pending"
        assert md["cve_id"] == "CVE-2099-0001"
        assert md["cve_published"] == "2099-01-01"
        assert md["parent_sha"] == parent and md["fix_sha"] == fix
        assert md["repo_name"] == f"demo__{parent[:8]}"
        assert md["finding"]["rule_id"] == e.rule_id
        assert md["primary_key"][0] == "CodeQL"
        assert md["scanner"]["version"] == "fake 1.0"


def test_outputs_marked_and_wired(tmp_path: Path, cve_repo: tuple[Path, str, str]) -> None:
    repo, parent, fix = cve_repo
    backend = FakeBackend()
    _run(tmp_path, _spec(repo, fix), backend)
    for sha in (parent, fix):
        name = f"demo__{sha[:8]}"
        rev_dir = tmp_path / "output" / "python" / name
        assert (rev_dir / "REVISION").read_text().strip() == sha
        link = tmp_path / "repos" / "python" / name
        assert link.is_symlink() and (link / "app.py").is_file()
    assert len(backend.calls) == 2
    # Idempotent re-run: SARIF reused, no new scanner calls, same entries.
    entries2, _ = _run(tmp_path, _spec(repo, fix), backend)
    assert len(backend.calls) == 2
    assert {e.rule_id for e in entries2} >= {"py/command-line-injection", "py/os-system"}


def test_renamed_file_alert_matched(tmp_path: Path) -> None:
    repo = _init(tmp_path)
    body = "def other(path):\n    os_system(path)\n\n\ndef run(cmd):\n    a = 1\n" + (
        "    x = 0\n" * 12
    )
    _commit(repo, {"pkg/old_name.py": body}, "v1")
    fixed = "# header\n# header 2\n" + body.replace("a = 1", "a = 2")
    fix = _commit(repo, {"pkg/old_name.py": None, "pkg/new_name.py": fixed}, "rename+fix")
    entries, _ = _run(tmp_path, _spec(repo, fix))
    (fp,) = [e for e in entries if e.rule_id == "py/os-system"]
    assert fp.label == LABEL_FP
    assert fp.file_path == "pkg/old_name.py"  # vulnerable-revision path
    assert fp.metadata["match_kind"] == "primary"


def test_fingerprint_secondary_key_matches() -> None:
    def alert(text: str, line: int, fp: str) -> Alert:
        f = Finding("r", "m", "a.c", line, line, "x", "c", tool="CodeQL")
        return Alert(f, "a.c", "CodeQL", "r", line, line, "f", text, fp)

    diff = parse_unified_diff("")
    m = match_alerts([alert("foo(x)", 3, "h:1")], [alert("foo( x )x", 9, "h:1")], diff)
    assert [how for _a, _b, how in m.pairs] == ["fingerprint"]


def test_line_mapping_fallback_matches() -> None:
    diff = parse_unified_diff(
        "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -0,0 +1,2 @@\n+x\n+y\n"
    )

    def alert(text: str, line: int) -> Alert:
        f = Finding("r", "m", "a.c", line, line, "x", "c", tool="Semgrep")
        return Alert(f, "a.c", "Semgrep", "r", line, line, "", text)

    m = match_alerts([alert("old text", 5)], [alert("reformatted", 7)], diff)
    assert [how for _a, _b, how in m.pairs] == ["line"]


# ── guards and validation ─────────────────────────────────────────────────


def test_stale_revision_guard(tmp_path: Path, cve_repo: tuple[Path, str, str]) -> None:
    repo, parent, fix = cve_repo
    rev_dir = tmp_path / "out" / "python" / f"demo__{parent[:8]}"
    ensure_revision_marker(rev_dir, parent)
    ensure_revision_marker(rev_dir, parent)  # idempotent
    with pytest.raises(StaleRevisionError):
        ensure_revision_marker(rev_dir, fix)

    unknown = tmp_path / "out" / "python" / "unmarked"
    (unknown / "database").mkdir(parents=True)
    with pytest.raises(StaleRevisionError):
        ensure_revision_marker(unknown, parent)

    # analyze_revision refuses before invoking any scanner.
    (rev_dir / "REVISION").write_text("f" * 40 + "\n")
    backend = FakeBackend()
    with pytest.raises(StaleRevisionError):
        analyze_revision(
            _spec(repo, fix),
            RevisionRef("demo", parent, repo),
            ["codeql"],
            "standard",
            backend=backend,
            output_dir=tmp_path / "out",
            attrition=AttritionLog(),
        )
    assert backend.calls == []


def test_build_refused_for_compiled_langs(tmp_path: Path) -> None:
    assert needs_build("c", None) and needs_build("go", None)
    assert not needs_build("python", "make") and not needs_build("csharp", None)
    assert needs_build("csharp", "dotnet build")

    def req(lang: str, build: str | None = None) -> AnalysisRequest:
        return AnalysisRequest(
            "codeql", lang, "n__00000000", "0" * 40, tmp_path, tmp_path, "s", build
        )

    strict = ScannerBackend(repos_dir=tmp_path)
    with pytest.raises(BuildRefusedError):
        strict._build_plan(req("c", "make"))
    with pytest.raises(BuildRefusedError):
        strict._build_plan(req("java"))
    assert strict._build_plan(req("python")) == (None, "none")

    permissive = ScannerBackend(repos_dir=tmp_path, allow_build=True)
    assert permissive._build_plan(req("cpp", "make -j2")) == ("make -j2", "spec")
    with pytest.raises(BuildRefusedError):
        permissive._build_plan(req("c"))  # nothing detected in tmp_path
    (tmp_path / "Makefile").write_text("all:\n")
    assert permissive._build_plan(req("c")) == ("make", "auto-detect-allowlist")
    assert permissive._build_plan(req("go")) == (None, "codeql-autobuild")


def test_build_refusal_recorded_in_attrition(tmp_path: Path) -> None:
    class RefusingBackend(FakeBackend):
        def analyze(self, request: AnalysisRequest) -> Path:
            raise BuildRefusedError("compiled")

    attrition = AttritionLog()
    spec = FixSpec("CVE-1", "https://example.com/o/p", "c", "CWE-787", "a" * 40, repo="p")
    res = analyze_revision(
        spec,
        RevisionRef("p", "a" * 40, tmp_path),
        ["codeql"],
        "standard",
        backend=RefusingBackend(),
        output_dir=tmp_path / "out",
        attrition=attrition,
    )
    assert "codeql" not in res.sarifs
    assert attrition.records[0]["reason"] == "build-refused"
    assert attrition.records[0]["lang"] == "c" and attrition.records[0]["cwe"] == "CWE-787"


def test_sha_and_url_validation(tmp_path: Path) -> None:
    assert validate_sha("ABCDEF1") == "abcdef1"
    for bad in ("", "xyz1234", "abc", "a" * 41, "HEAD", "--upload-pack=x", "abcdef1;rm"):
        with pytest.raises(ValueError):
            validate_sha(bad)
    assert validate_repo_url("https://github.com/owner/proj.git")
    assert validate_repo_url("git://example.org/a/b")
    for bad in (
        "http://github.com/o/p",
        "ssh://git@github.com/o/p",
        "git@github.com:o/p.git",
        "-uhttps://x/y",
        "https://user:pw@github.com/o/p",
        "https://github.com/o/p?x=1",
        "https://github.com/../etc",
        "ext::sh -c id",
        "file:///etc",
    ):
        with pytest.raises(ValueError):
            validate_repo_url(bad)
    with pytest.raises(ValueError):
        validate_repo_url(str(tmp_path))  # local paths need allow_local
    assert validate_repo_url(str(tmp_path), allow_local=True) == str(tmp_path.resolve())
    assert repo_slug("https://github.com/owner/proj.git") == "owner_proj"
    assert revision_name("owner_proj", "0123456789abcdef") == "owner_proj__01234567"
    with pytest.raises(ValueError):
        FixSpec.from_dict(
            {
                "cve_id": "C",
                "repo_url": "https://h/o/p",
                "lang": "cobol",
                "cwe": "1",
                "fix_sha": "a" * 40,
            }
        )


def test_merge_commit_rejected_without_parent(tmp_path: Path) -> None:
    repo = _init(tmp_path)
    base = _commit(repo, {"a.py": "a = 1\n"}, "base")
    _git(repo, "checkout", "-q", "-b", "side")
    side = _commit(repo, {"b.py": "b = 1\n"}, "side")
    _git(repo, "checkout", "-q", "main")
    _commit(repo, {"c.py": "c = 1\n"}, "main")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    merge = _git(repo, "rev-parse", "HEAD")

    co = RevisionCheckout(tmp_path / "cache", allow_local=True)
    with pytest.raises(CheckoutError, match="merge commit"):
        co.prepare(str(repo), merge)
    pair = co.prepare(str(repo), merge, parent_sha=side)
    assert pair.parent_sha == side and pair.fix_sha == merge
    assert (pair.vuln_dir / "b.py").is_file() and not (pair.vuln_dir / "c.py").exists()
    # Idempotent: a second prepare reuses mirror + worktrees.
    again = co.prepare(str(repo), merge[:10], parent_sha=side[:10])
    assert again.vuln_dir == pair.vuln_dir and again.fix_sha == merge
    assert base  # silence unused


def test_root_commit_and_missing_commit(tmp_path: Path) -> None:
    repo = _init(tmp_path)
    root = _commit(repo, {"a.py": "a = 1\n"}, "root")
    co = RevisionCheckout(tmp_path / "cache", allow_local=True)
    with pytest.raises(CheckoutError, match="root commit"):
        co.prepare(str(repo), root)
    with pytest.raises(CheckoutError):
        co.prepare(str(repo), "deadbeef" * 5)


def test_enclosing_function_heuristic() -> None:
    py = ["class A:", "    def m(self):", "        if x:", "            y()", "z = 1"]
    assert enclosing_function(py, 4, "python") == "m"
    assert enclosing_function(py, 5, "python") == ""
    c = ["static int", "parse_hdr(char *p, int n)", "{", "    if (n > 4) {", "    memcpy(a, p, n);"]
    assert enclosing_function(c, 5, "c") == "parse_hdr"
    js = ["export async function handler(req, res) {", "  res.send(req.query.x);", "}"]
    assert enclosing_function(js, 2, "javascript") == "handler"
    go = ["func (s *Srv) Serve(w http.ResponseWriter) {", "\tw.Write(b)", "}"]
    assert enclosing_function(go, 2, "go") == "Serve"


def test_cwe_family_matching() -> None:
    def alert(rule: str, cwes: list[str]) -> Alert:
        f = Finding(rule, "m", "a.c", 1, 1, "x", "c", tool="CodeQL", cwe_ids=cwes)
        return Alert(f, "a.c", "CodeQL", rule, 1, 1)

    assert cwe_matches("CWE-787", alert("cpp/x", ["CWE-787"])) == "exact"
    assert cwe_matches("787", alert("cpp/x", ["CWE-120"])) == "family"
    assert cwe_matches("CWE-78", alert("py/command-line-injection", [])) == "exact"
    assert cwe_matches("CWE-77", alert("py/command-line-injection", [])) == "family"
    assert cwe_matches("CWE-79", alert("cpp/x", ["CWE-787"])) == ""


# ── manifest + CLI ────────────────────────────────────────────────────────


def test_manifest_roundtrip(tmp_path: Path, cve_repo: tuple[Path, str, str]) -> None:
    repo, _parent, fix = cve_repo
    entries, attrition = _run(tmp_path, _spec(repo, fix))
    path = tmp_path / "m" / "revpair_manifest.jsonl"
    digest = write_manifest(entries, path)
    assert verify_manifest(path)
    assert Path(f"{path}.sha256").read_text().split()[0] == digest
    loaded = load_manifest(path)
    assert sorted(e.id for e in loaded) == sorted(e.id for e in entries)
    assert len({e.id for e in entries}) == len(entries)
    # Deterministic bytes.
    write_manifest(list(reversed(entries)), tmp_path / "m2.jsonl")
    assert (tmp_path / "m2.jsonl").read_bytes() == path.read_bytes()
    path.write_text(path.read_text() + "\n")
    assert not verify_manifest(path)

    write_attrition(attrition, tmp_path / "attr.json")
    data = json.loads((tmp_path / "attr.json").read_text())
    tiers = data["totals"]["by_tier"]
    assert tiers["silver-tp"] == 1 and tiers["persistent"] == 1 and tiers["ambiguous"] >= 3
    row = next(c for c in data["counts"] if c["tier"] == "silver-tp")
    assert row["lang"] == "python" and row["cwe"] == "CWE-78" and row["tool"] == "codeql"


def test_cli_dry_run(tmp_path: Path, cve_repo: tuple[Path, str, str]) -> None:
    from benchmarks.scripts.build_revpair_manifest import main

    repo, _parent, fix = cve_repo
    specs = tmp_path / "fixes.jsonl"
    specs.write_text(
        json.dumps(
            {
                "cve_id": "CVE-2099-0001",
                "repo_url": str(repo),
                "lang": "python",
                "cwe": "CWE-78",
                "fix_sha": fix,
            }
        )
        + "\n"
        + json.dumps({"cve_id": "CVE-bad", "repo_url": "http://insecure/o/p"})
        + "\n",
        encoding="utf-8",
    )
    rc = main(
        [
            "--input",
            str(specs),
            "--dry-run",
            "--allow-local-repos",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output-dir",
            str(tmp_path / "out"),
            "--scan-output",
            str(tmp_path / "scan"),
            "--repos-dir",
            str(tmp_path / "repos"),
        ]
    )
    assert rc == 0
    data = json.loads((tmp_path / "out" / "revpair_attrition.json").read_text())
    reasons = {r["reason"] for r in data["records"]}
    assert {"invalid-spec", "dry-run-ok"} <= reasons
    assert not (tmp_path / "scan").exists()  # no scanners in dry-run
