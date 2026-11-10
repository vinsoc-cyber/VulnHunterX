# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-revision scanner orchestration and per-fix labelling pipeline.

Each revision is analysed under the workspace name ``<repo>__<sha8>`` so the
outputs land in the usual ``output/<lang>/<name>/`` layout (and, when a
``repos_dir`` is given, ``repos/<lang>/<name>`` is symlinked to the worktree
exactly like ``--local-path`` mode, so later verification has full-repo
context).

Stale-output guard: ``RepositoryManager.clone_and_create_db`` silently reuses
an existing CodeQL database. Before any analysis we therefore write
``output/<lang>/<name>/REVISION`` containing the full commit SHA and raise
:class:`StaleRevisionError` if that file already names another commit, or if
the directory already holds outputs of unknown provenance (no REVISION file).

Build isolation: interpreted languages need no build. Compiled languages
(C, C++, Java, Go; C# only when a build command is supplied — otherwise CodeQL
runs buildless) execute target-controlled build code during CodeQL database
creation, so the default backend refuses them unless ``allow_build=True``.
Build commands come only from the fix spec's ``build_command`` field or the
fixed template allowlist of ``codeql.repository.detect_build_command`` (C/C++)
/ CodeQL autobuild (Java/Go) — never from model output (``ask_llm`` is always
off). With ``build_container=IMAGE`` the whole ``codeql database create`` runs
inside ``docker run --rm --network none`` (the image must provide ``codeql``
and the build toolchain). Semgrep/OpenGrep never build. Every refusal or
failure is recorded in the :class:`AttritionLog` rather than skipped silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.builders.revpair.alert_key import SourceCache, build_alerts, match_alerts
from benchmarks.builders.revpair.checkout import (
    CheckoutError,
    RevisionCheckout,
    RevisionPair,
    revision_name,
    validate_repo_url,
    validate_sha,
)
from benchmarks.builders.revpair.label import (
    TIER_AMBIGUOUS,
    FixContext,
    TierDecision,
    build_entries,
    classify,
    normalize_cwe,
    touched_functions,
)

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG_DIR = REPO_ROOT / "config"
REVISION_FILE = "REVISION"

SUPPORTED_TOOLS = ("codeql", "semgrep", "opengrep")
SUPPORTED_LANGS = ("c", "cpp", "python", "javascript", "php", "java", "go", "csharp")
COMPILED_LANGS = frozenset({"c", "cpp", "java", "go"})
_SARIF_SUFFIX = {"codeql": "", "semgrep": "_semgrep", "opengrep": "_opengrep"}
_VERSION_TIMEOUT = 60


class StaleRevisionError(RuntimeError):
    """An output directory already belongs to a different (or unknown) revision."""


class BuildRefusedError(RuntimeError):
    """A compiled-language build was requested without explicit authorisation."""


class AnalysisError(RuntimeError):
    """A scanner run failed."""


# ── fix specs ─────────────────────────────────────────────────────────────


@dataclass
class FixSpec:
    """One CVE fix commit to process (schema: see build_revpair_manifest.py)."""

    cve_id: str
    repo_url: str
    lang: str
    cwe: str
    fix_sha: str
    parent_sha: str | None = None
    cve_published: str | None = None
    build_command: str | None = None
    repo: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, allow_local: bool = False) -> FixSpec:
        """Validate and build a spec; raises :class:`ValueError` on bad input."""
        if not isinstance(data, dict):
            raise ValueError("fix spec must be a JSON object")
        missing = [k for k in ("cve_id", "repo_url", "lang", "cwe", "fix_sha") if not data.get(k)]
        if missing:
            raise ValueError(f"fix spec missing required field(s): {', '.join(missing)}")
        lang = str(data["lang"]).lower()
        if lang not in SUPPORTED_LANGS:
            raise ValueError(f"unsupported lang {lang!r}")
        parent = data.get("parent_sha")
        build = data.get("build_command")
        if build is not None and (not isinstance(build, str) or "\n" in build):
            raise ValueError("build_command must be a single-line string")
        return cls(
            cve_id=str(data["cve_id"]),
            repo_url=validate_repo_url(str(data["repo_url"]), allow_local=allow_local),
            lang=lang,
            cwe=normalize_cwe(str(data["cwe"])),
            fix_sha=validate_sha(str(data["fix_sha"])),
            parent_sha=validate_sha(str(parent)) if parent else None,
            cve_published=str(data["cve_published"]) if data.get("cve_published") else None,
            build_command=build or None,
            repo=str(data["repo"]) if data.get("repo") else None,
        )


# ── attrition ─────────────────────────────────────────────────────────────


@dataclass
class AttritionLog:
    """Every drop, failure and labelling outcome, for funnel accounting."""

    records: list[dict[str, Any]] = field(default_factory=list)
    run_info: dict[str, Any] = field(default_factory=dict)

    def record(
        self,
        step: str,
        reason: str,
        *,
        cve_id: str = "",
        lang: str = "",
        cwe: str = "",
        tool: str = "",
        tier: str = "",
        detail: str = "",
    ) -> None:
        self.records.append(
            {
                "step": step,
                "reason": reason,
                "cve_id": cve_id,
                "lang": lang,
                "cwe": cwe,
                "tool": tool,
                "tier": tier,
                "detail": detail[:500],
            }
        )

    def counts(self) -> list[dict[str, Any]]:
        """Counts per (step, lang, cwe, tool, tier, reason)."""
        keys = ("step", "lang", "cwe", "tool", "tier", "reason")
        c = Counter(tuple(r[k] for k in keys) for r in self.records)
        return [dict(zip(keys, k, strict=True), count=n) for k, n in sorted(c.items())]

    def to_dict(self) -> dict[str, Any]:
        by_step = Counter(r["step"] for r in self.records)
        by_tier = Counter(r["tier"] for r in self.records if r["tier"])
        return {
            "run": self.run_info,
            "totals": {"by_step": dict(sorted(by_step.items())), "by_tier": dict(by_tier)},
            "counts": self.counts(),
            "records": self.records,
        }


# ── revision workspace ────────────────────────────────────────────────────


@dataclass
class RevisionRef:
    repo: str
    sha: str
    worktree: Path

    @property
    def name(self) -> str:
        return revision_name(self.repo, self.sha)


def sarif_path_for(output_dir: Path, tool: str, lang: str, name: str) -> Path:
    """Where the product's analyzers write SARIF for ``tool``."""
    return output_dir / lang / name / f"{name}{_SARIF_SUFFIX[tool]}.sarif"


def ensure_revision_marker(rev_dir: Path, sha: str) -> None:
    """Create/verify ``rev_dir/REVISION``; raise on a mismatch or unknown outputs."""
    sha = validate_sha(sha)
    marker = rev_dir / REVISION_FILE
    if marker.is_file():
        recorded = marker.read_text(encoding="utf-8").strip().lower()
        if recorded != sha:
            raise StaleRevisionError(
                f"{rev_dir} holds outputs for {recorded[:12] or '<empty>'}, not {sha[:12]}; "
                "refusing to reuse them (move the directory aside)"
            )
        return
    if rev_dir.is_dir() and any(rev_dir.iterdir()):
        raise StaleRevisionError(
            f"{rev_dir} already contains outputs without a {REVISION_FILE} marker; "
            "refusing to reuse a database/SARIF of unknown revision"
        )
    rev_dir.mkdir(parents=True, exist_ok=True)
    marker.write_text(sha + "\n", encoding="utf-8")


# ── analyzer backends ─────────────────────────────────────────────────────


@dataclass
class AnalysisRequest:
    tool: str
    lang: str
    name: str
    sha: str
    source_dir: Path
    output_dir: Path
    profile: str
    build_command: str | None = None


class AnalyzerBackend(Protocol):
    """Runs one scanner on one revision and returns the SARIF path."""

    def analyze(self, request: AnalysisRequest) -> Path: ...

    def describe(self, tool: str, lang: str, profile: str) -> dict[str, Any]:
        """Tool version + rule-pack identifiers (must be identical across revisions)."""
        ...


def needs_build(lang: str, build_command: str | None) -> bool:
    return lang in COMPILED_LANGS or (lang == "csharp" and bool(build_command))


def _is_registry_config(c: str) -> bool:
    return c == "auto" or c.startswith(("p/", "r/")) or ":" in c


def _absolutize(c: str) -> str:
    if not c or _is_registry_config(c) or Path(c).is_absolute():
        return c
    return str(REPO_ROOT / c)


def _digest_path(path: Path, limit: int = 20000) -> str:
    """sha256 over rule files under ``path`` (identifies a local rule pack)."""
    h = hashlib.sha256()
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    for p in files[:limit]:
        h.update(str(p.relative_to(path) if path.is_dir() else p.name).encode("utf-8"))
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def _tool_version(binary: str) -> str:
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=_VERSION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"
    out = (proc.stdout or proc.stderr or "").strip()
    if proc.returncode != 0 or not out:
        return ""
    return out.splitlines()[0]


class ScannerBackend:
    """Default backend: the product's own CodeQL/Semgrep/OpenGrep adapters."""

    def __init__(
        self,
        *,
        repos_dir: Path,
        allow_build: bool = False,
        build_container: str | None = None,
        codeql_path: str | None = None,
    ) -> None:
        self.repos_dir = Path(repos_dir)
        self.allow_build = allow_build
        self.build_container = build_container
        self.codeql_path = codeql_path or os.environ.get("CODEQL_PATH", "codeql")
        self._describe_cache: dict[tuple[str, str, str], dict[str, Any]] = {}

    # rules -----------------------------------------------------------------

    def _profile(self, profile: str) -> Any:
        from vuln_hunter_x.core.rule_profiles import RuleProfileManager

        return RuleProfileManager(CONFIG_DIR / "rule_categories.yaml").get_profile(profile)

    def resolve_rules(self, tool: str, lang: str, profile: str) -> dict[str, Any]:
        """Same resolution as ``cli.commands.cmd_analyze`` for one (tool, lang)."""
        prof = self._profile(profile)
        if tool == "codeql":
            from vuln_hunter_x.codeql.analysis import CodeQLAnalyzer

            suite = CodeQLAnalyzer.suite_for_language(lang, prof.codeql_suite_suffix)
            extras: list[str] = []
            if prof.include_custom_codeql:
                ql_lang = "cpp" if lang in ("c", "cpp") else lang
                custom = CONFIG_DIR / "codeql-custom" / ql_lang / "suite.qls"
                src_dir = custom.parent / "src"
                if custom.is_file() and src_dir.is_dir() and any(src_dir.glob("*.ql")):
                    extras.append(str(custom))
            return {"suite": suite, "extra_suites": extras}
        # Private helper reused deliberately so revpair scans use exactly the
        # product's Semgrep/OpenGrep config expansion (incl. ${LANG} templates).
        from vuln_hunter_x.cli.commands import _expand_per_repo_configs

        base = prof.semgrep_configs if tool == "semgrep" else prof.opengrep_configs
        ns = argparse.Namespace(
            _profile_language_specific_configs=prof.language_specific_configs,
            _profile_custom_semgrep_path=_absolutize(prof.custom_semgrep_path),
        )
        configs = _expand_per_repo_configs(ns, [_absolutize(c) for c in base], lang, engine=tool)
        return {"configs": configs}

    def _binary(self, tool: str) -> str:
        if tool == "codeql":
            return self.codeql_path
        from vuln_hunter_x.opengrep.analyzer import OpenGrepAnalyzer
        from vuln_hunter_x.semgrep.analyzer import SemgrepAnalyzer

        cls = SemgrepAnalyzer if tool == "semgrep" else OpenGrepAnalyzer
        return os.environ.get(cls.ENV_VAR, cls.DEFAULT_BINARY)

    def describe(self, tool: str, lang: str, profile: str) -> dict[str, Any]:
        key = (tool, lang, profile)
        if key not in self._describe_cache:
            rules = self.resolve_rules(tool, lang, profile)
            digests = {}
            for c in rules.get("configs", []) + rules.get("extra_suites", []):
                if not _is_registry_config(c) and Path(c).exists():
                    digests[c] = _digest_path(Path(c))
            self._describe_cache[key] = {
                "tool": tool,
                "version": _tool_version(self._binary(tool)),
                "profile": profile,
                "rules": rules,
                "local_rule_digests": digests,
                "floating_registry_configs": [
                    c for c in rules.get("configs", []) if _is_registry_config(c)
                ],
            }
        return self._describe_cache[key]

    # analysis --------------------------------------------------------------

    def analyze(self, request: AnalysisRequest) -> Path:
        rules = self.resolve_rules(request.tool, request.lang, request.profile)
        if request.tool == "codeql":
            return self._run_codeql(request, rules)
        from vuln_hunter_x.opengrep.analyzer import OpenGrepAnalyzer
        from vuln_hunter_x.semgrep.analyzer import SemgrepAnalyzer

        cls = SemgrepAnalyzer if request.tool == "semgrep" else OpenGrepAnalyzer
        analyzer = cls(output_dir=request.output_dir)
        ok, path, msg = analyzer.run_analysis(
            request.source_dir, request.lang, request.name, request.output_dir, rules["configs"]
        )
        if not ok or path is None:
            raise AnalysisError(msg)
        return path

    def _build_plan(self, request: AnalysisRequest) -> tuple[str | None, str]:
        """Return ``(build_command, source)`` or raise :class:`BuildRefusedError`."""
        if not needs_build(request.lang, request.build_command):
            return None, "none"
        if not self.allow_build:
            raise BuildRefusedError(
                f"{request.lang} CodeQL database creation runs target build code; "
                "pass --allow-build (ideally with --build-container IMAGE)"
            )
        if request.build_command:
            return request.build_command, "spec"
        if request.lang in ("c", "cpp"):
            from vuln_hunter_x.codeql.repository import detect_build_command

            detected = detect_build_command(request.source_dir, request.lang)
            if not detected:
                raise BuildRefusedError(
                    "no build_command in spec and no allowlisted build system detected"
                )
            return detected, "auto-detect-allowlist"
        return None, "codeql-autobuild"

    def _run_codeql(self, request: AnalysisRequest, rules: dict[str, Any]) -> Path:
        from vuln_hunter_x.codeql.analysis import CodeQLAnalyzer

        build_command, _source = self._build_plan(request)
        rev_dir = request.output_dir / request.lang / request.name
        db_path = rev_dir / "database"
        if self.build_container and needs_build(request.lang, request.build_command):
            self._create_db_in_container(request, build_command, rev_dir)
        else:
            from vuln_hunter_x.codeql.repository import RepositoryManager

            mgr = RepositoryManager(self.repos_dir, request.output_dir, self.codeql_path)
            ok, msg = mgr.clone_and_create_db(
                request.name,
                url="",
                language=request.lang,
                build_command=build_command,
                local_path=request.source_dir,
                skip_clone=True,
                ask_llm=False,
            )
            if not ok:
                raise AnalysisError(f"database creation failed: {msg}")
        analyzer = CodeQLAnalyzer(codeql_path=self.codeql_path, output_dir=request.output_dir)
        ok, path, msg = analyzer.run_analysis(
            db_path,
            request.lang,
            request.name,
            suite=rules["suite"],
            extra_suites=rules["extra_suites"],
        )
        if not ok or path is None:
            raise AnalysisError(msg)
        return path

    def _create_db_in_container(
        self, request: AnalysisRequest, build_command: str | None, rev_dir: Path
    ) -> None:
        from vuln_hunter_x.core.constants import TIMEOUT_CODEQL_DB_CREATE

        if shutil.which("docker") is None:
            raise AnalysisError("docker not found for --build-container")
        if (rev_dir / "database").exists():
            return  # REVISION marker already guarantees it belongs to this sha
        ql_lang = "cpp" if request.lang in ("c", "cpp") else request.lang
        argv = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{request.source_dir.resolve()}:/src",
            "-v",
            f"{rev_dir.resolve()}:/out",
            "-w",
            "/src",
            str(self.build_container),
            "codeql",
            "database",
            "create",
            "/out/database",
            f"--language={ql_lang}",
            "--source-root=/src",
        ]
        if build_command:
            script = rev_dir / "build.sh"
            script.write_text(f"#!/bin/sh\nset -e\n{build_command}\n", encoding="utf-8")
            script.chmod(0o755)
            argv.append("--command=/out/build.sh")
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_CODEQL_DB_CREATE,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AnalysisError("containerised database creation timed out") from exc
        if proc.returncode != 0:
            shutil.rmtree(rev_dir / "database", ignore_errors=True)
            raise AnalysisError(f"containerised build failed: {(proc.stderr or '')[-800:]}")


# ── per-revision analysis ─────────────────────────────────────────────────


@dataclass
class RevisionAnalysis:
    name: str
    sha: str
    sarifs: dict[str, Path] = field(default_factory=dict)
    scanners: dict[str, dict[str, Any]] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)


def _wire_repo(repos_dir: Path, lang: str, name: str, worktree: Path) -> None:
    from vuln_hunter_x.cli.commands import _wire_local_path

    err = _wire_local_path(repos_dir, lang, name, worktree.resolve())
    if err:
        raise StaleRevisionError(err)


def analyze_revision(
    spec: FixSpec,
    revision: RevisionRef,
    tools: list[str],
    profile: str,
    *,
    backend: AnalyzerBackend,
    output_dir: Path,
    attrition: AttritionLog,
    repos_dir: Path | None = None,
    force: bool = False,
) -> RevisionAnalysis:
    """Scan one revision with every tool; failures are recorded, not raised.

    :class:`StaleRevisionError` *is* raised: reusing another revision's
    database would silently corrupt every label of this fix.
    """
    name = revision.name
    rev_dir = output_dir / spec.lang / name
    ensure_revision_marker(rev_dir, revision.sha)
    if repos_dir is not None:
        _wire_repo(repos_dir, spec.lang, name, revision.worktree)
    result = RevisionAnalysis(name=name, sha=revision.sha)
    for tool in tools:
        common = {"cve_id": spec.cve_id, "lang": spec.lang, "cwe": spec.cwe, "tool": tool}
        try:
            result.scanners[tool] = backend.describe(tool, spec.lang, profile)
            cached = sarif_path_for(output_dir, tool, spec.lang, name)
            if cached.is_file() and not force:
                result.sarifs[tool] = cached
                continue
            request = AnalysisRequest(
                tool=tool,
                lang=spec.lang,
                name=name,
                sha=revision.sha,
                source_dir=revision.worktree,
                output_dir=output_dir,
                profile=profile,
                build_command=spec.build_command,
            )
            result.sarifs[tool] = backend.analyze(request)
        except BuildRefusedError as exc:
            result.failures[tool] = f"build-refused: {exc}"
            attrition.record("analyze", "build-refused", detail=f"{name}: {exc}", **common)
        except (AnalysisError, OSError, ValueError) as exc:
            result.failures[tool] = f"analysis-failed: {exc}"
            attrition.record("analyze", "analysis-failed", detail=f"{name}: {exc}", **common)
    return result


# ── per-fix pipeline ──────────────────────────────────────────────────────


def _load_sarif(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _record_decision(attrition: AttritionLog, spec: FixSpec, tool: str, d: TierDecision) -> None:
    attrition.record(
        "label",
        d.reason,
        cve_id=spec.cve_id,
        lang=spec.lang,
        cwe=spec.cwe,
        tool=tool,
        tier=d.tier,
        detail=f"{d.alert.path}:{d.alert.start_line} {d.alert.rule_id}",
    )


def label_tool(
    spec: FixSpec,
    pair: RevisionPair,
    tool: str,
    vuln_sarif: Path,
    fix_sarif: Path,
    scanner_info: dict[str, Any],
    attrition: AttritionLog,
) -> list[GroundTruthEntry]:
    """Parse both SARIFs of one tool, match, classify and emit entries."""
    from vuln_hunter_x.sarif.parser import SarifParser

    diff = pair.diff()
    vuln_src = SourceCache(pair.vuln_dir)
    fix_src = SourceCache(pair.fix_dir)
    vuln_findings = SarifParser(vuln_sarif).parse_findings(lang=spec.lang, repo_name=pair.vuln_name)
    fix_findings = SarifParser(fix_sarif).parse_findings(lang=spec.lang, repo_name=pair.fix_name)
    vuln_alerts = build_alerts(vuln_findings, _load_sarif(vuln_sarif), vuln_src)
    fix_alerts = build_alerts(fix_findings, _load_sarif(fix_sarif), fix_src)
    match = match_alerts(vuln_alerts, fix_alerts, diff)
    decisions = classify(match, diff, spec.cwe, touched_functions(diff, vuln_src, spec.lang))
    for d in decisions:
        _record_decision(attrition, spec, tool, d)
    for b in match.fix_unmatched:
        attrition.record(
            "label",
            "new-on-fix-side",
            cve_id=spec.cve_id,
            lang=spec.lang,
            cwe=spec.cwe,
            tool=tool,
            tier=TIER_AMBIGUOUS,
            detail=f"{b.path}:{b.start_line} {b.rule_id}",
        )
    ctx = FixContext(
        cve_id=spec.cve_id,
        cwe=spec.cwe,
        lang=spec.lang,
        repo=pair.repo,
        repo_url=pair.repo_url,
        parent_sha=pair.parent_sha,
        fix_sha=pair.fix_sha,
        vuln_name=pair.vuln_name,
        fix_name=pair.fix_name,
        cve_published=spec.cve_published,
    )
    entries = build_entries(decisions, ctx, vuln_src)
    for e in entries:
        e.metadata["scanner"] = scanner_info
    return entries


def process_fix(
    spec: FixSpec,
    *,
    checkout: RevisionCheckout,
    backend: AnalyzerBackend | None,
    tools: list[str],
    profile: str,
    output_dir: Path,
    attrition: AttritionLog,
    repos_dir: Path | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> list[GroundTruthEntry]:
    """Checkout → diff → scan both revisions → label. Never raises for one fix
    except :class:`StaleRevisionError` (a workspace integrity problem)."""
    common = {"cve_id": spec.cve_id, "lang": spec.lang, "cwe": spec.cwe}
    try:
        pair = checkout.prepare(spec.repo_url, spec.fix_sha, spec.parent_sha, repo=spec.repo)
    except (CheckoutError, ValueError) as exc:
        attrition.record("checkout", "checkout-failed", detail=str(exc), **common)
        return []
    diff = pair.diff()
    if not any(fd.hunks for fd in diff.files):
        attrition.record("diff", "no-text-hunks", detail=pair.fix_sha, **common)
        return []
    if dry_run or backend is None:
        attrition.record(
            "diff", "dry-run-ok", detail=f"{len(diff.files)} file(s) changed", **common
        )
        return []
    vuln = analyze_revision(
        spec,
        RevisionRef(pair.repo, pair.parent_sha, pair.vuln_dir),
        tools,
        profile,
        backend=backend,
        output_dir=output_dir,
        attrition=attrition,
        repos_dir=repos_dir,
        force=force,
    )
    fixed = analyze_revision(
        spec,
        RevisionRef(pair.repo, pair.fix_sha, pair.fix_dir),
        tools,
        profile,
        backend=backend,
        output_dir=output_dir,
        attrition=attrition,
        repos_dir=repos_dir,
        force=force,
    )
    entries: list[GroundTruthEntry] = []
    for tool in tools:
        if tool not in vuln.sarifs or tool not in fixed.sarifs:
            attrition.record(
                "pair",
                "revision-missing-sarif",
                tool=tool,
                detail=vuln.failures.get(tool) or fixed.failures.get(tool) or "",
                **common,
            )
            continue
        if vuln.scanners.get(tool) != fixed.scanners.get(tool):
            attrition.record("pair", "scanner-config-mismatch", tool=tool, **common)
            continue
        try:
            entries.extend(
                label_tool(
                    spec,
                    pair,
                    tool,
                    vuln.sarifs[tool],
                    fixed.sarifs[tool],
                    vuln.scanners.get(tool, {}),
                    attrition,
                )
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            attrition.record("parse", "sarif-unreadable", tool=tool, detail=str(exc), **common)
    return entries
