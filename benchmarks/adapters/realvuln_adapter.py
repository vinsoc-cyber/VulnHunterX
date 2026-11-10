# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the RealVuln Benchmark dataset.

Repo: https://github.com/kolega-ai/Real-Vuln-Benchmark (MIT)

This is the substitute we adopted in lieu of SastBench, whose public
repository URL was not findable at integration time. RealVuln has the
same shape (real CVEs as TPs + FP traps) and a documented JSON schema.

Dataset layout:
    Real-Vuln-Benchmark/
    ├── ground-truth/<repo_id>/ground-truth.json
    └── (optionally) per-repo working trees the user has checked out

Each ground-truth.json contains:
    {
        "schema_version": ...,
        "repo_id": ..., "repo_url": ..., "commit_sha": ...,
        "language": "python", ...
        "findings": [
            {
                "id": "...", "is_vulnerable": true|false,
                "primary_cwe": "CWE-89" | "89",
                "file": "path/to/file.py",
                "location": {"start_line": ..., "end_line": ..., "function": ...},
                "evidence": {"source": "cve|semgrep", "cve_id": "...", ...}
            },
            ...
        ]
    }

Label rule:
    is_vulnerable == True  → LABEL_TP
    is_vulnerable == False → LABEL_FP   (FP "trap" sample)

Code snippet extraction is best-effort. If a working tree exists at
``<repos_cache>/<repo_id>`` (the user is responsible for checking out
the correct commit), the adapter reads the function lines from disk.
Otherwise it leaves ``code_snippet=""`` and tags the entry; downstream
approaches that need source must skip these. A test caller can pass
an in-memory snippet via ``code_resolver``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_bool,
    register_adapter,
)

logger = logging.getLogger(__name__)


_SAFE_REPO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")

# RealVuln marks FP "traps" as ``is_vulnerable: false`` entries. The schema has
# no dedicated trap flag; provenance lives in ``evidence.source``. Manually
# reviewed entries (e.g. ``manual_review``) are the curated traps; entries
# derived from a scanner run are "natural" FPs. Anything else is "unknown".
_TRAP_SOURCES = frozenset({"manual_review", "manual", "human", "trap", "curated"})
_NATURAL_SOURCES = frozenset(
    {"semgrep", "codeql", "bandit", "scanner", "sast", "opengrep", "snyk", "sonarqube"}
)


def _fp_origin(finding: dict, evidence: dict) -> str:
    """Classify an FP entry as "trap" | "natural" | "unknown" (heuristic)."""
    explicit = finding.get("fp_origin") or ("trap" if finding.get("trap") is True else "")
    if explicit in ("trap", "natural"):
        return str(explicit)
    src = str(evidence.get("source") or "").strip().lower()
    if src in _TRAP_SOURCES:
        return "trap"
    if src in _NATURAL_SOURCES:
        return "natural"
    return "unknown"


def _run_vcs(args: list[str], cwd: Path | None, timeout: int) -> bool:
    exe = shutil.which("git")
    if not exe:
        return False
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        r = subprocess.run(  # noqa: S603
            [exe, *args], cwd=cwd, env=env, timeout=timeout,
            capture_output=True, check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return r.returncode == 0


def _checkout_commit(
    repo_dir: Path, repo_id: str, repo_url: str, sha: str, clone: bool
) -> str:
    """Check out ``sha`` in ``repo_dir``. Returns a status string.

    No shell. Only touches an existing clone, unless ``clone`` is true and
    ``repo_url`` (from the dataset's own ground truth) is an https URL.
    """
    if not _SAFE_REPO_ID_RE.match(repo_id):
        return "skipped:unsafe_repo_id"
    if not _SHA_RE.match(sha):
        return "skipped:invalid_sha"
    if not (repo_dir / ".git").exists():
        if not clone:
            return "skipped:not_a_clone"
        u = urlparse(repo_url)
        if u.scheme != "https" or not u.netloc or any(c.isspace() for c in repo_url):
            return "skipped:non_https_url"
        if repo_dir.exists() and any(repo_dir.iterdir()):
            return "skipped:cache_dir_not_empty"
        repo_dir.parent.mkdir(parents=True, exist_ok=True)
        if not _run_vcs(["clone", "--quiet", "--", repo_url, str(repo_dir)], None, 600):
            return "failed:clone"
    if not _run_vcs(["cat-file", "-e", f"{sha}^{{commit}}"], repo_dir, 30) and not _run_vcs(
        ["fetch", "--quiet", "origin", sha], repo_dir, 300
    ):
        return "failed:fetch"
    if not _run_vcs(["checkout", "--quiet", "--detach", sha], repo_dir, 60):
        return "failed:checkout"
    return "ok"


# (repo_id, finding) -> snippet  (used in tests; production reads from disk)
CodeResolver = Callable[[str, dict], str]


def _normalize_cwe(raw: str | int | None) -> str:
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    if s.upper().startswith("CWE-"):
        return s.upper()
    return f"CWE-{s}"


def _read_lines(path: Path, start: int, end: int, pad: int = 0) -> str:
    """Read lines [start, end] inclusive (1-indexed) with optional padding."""
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    s = max(0, start - 1 - pad)
    e = min(len(lines), end + pad)
    return "\n".join(lines[s:e])


@register_adapter
class RealVulnAdapter(DatasetAdapter):
    """Parse RealVuln Benchmark ground-truth JSON files into GroundTruthEntry.

    Args:
        dataset_path: Root of the cloned Real-Vuln-Benchmark repository.
        repos_cache: Optional directory containing checked-out source trees
            keyed by repo_id. If absent, snippets are left empty.
            Programmatic-only — not exposed via the registry CLI.
        code_resolver: Optional callable for tests to inject snippets.
            Programmatic-only — not exposed via the registry CLI.
    """

    name = "realvuln"
    langs = ("python",)
    family = "cve"
    option_schema = {
        "checkout": OptionSpec(
            _to_bool,
            default=False,
            help="Check out each repo's commit_sha in an EXISTING clone under "
            "<repos_cache>/<repo_id> (fetch/checkout, no shell).",
        ),
        "clone": OptionSpec(
            _to_bool,
            default=False,
            help="With checkout=true: also clone missing repos from the https "
            "repo_url in the dataset's ground truth. Uses the network.",
        ),
    }
    install_url = "https://github.com/kolega-ai/Real-Vuln-Benchmark.git"
    expected_files = ("ground-truth",)

    def __init__(
        self,
        dataset_path: Path,
        repos_cache: Path | None = None,
        code_resolver: CodeResolver | None = None,
    ) -> None:
        self.dataset_path = Path(dataset_path)
        self.repos_cache = (
            Path(repos_cache) if repos_cache else self.dataset_path / "_repos"
        )
        self.code_resolver = code_resolver

    def _ground_truth_files(self) -> list[Path]:
        gt_root = self.dataset_path / "ground-truth"
        if not gt_root.is_dir():
            raise FileNotFoundError(
                f"No ground-truth/ under {self.dataset_path}; "
                "is this a RealVuln Benchmark checkout?"
            )
        return sorted(gt_root.rglob("ground-truth.json"))

    def _resolve_snippet(
        self, repo_id: str, finding: dict, file_rel: str, start: int, end: int
    ) -> tuple[str, str]:
        """Return (snippet, source_kind) for the finding."""
        if self.code_resolver is not None:
            return self.code_resolver(repo_id, finding) or "", "resolver"
        if start <= 0 or end < start:
            return "", "missing"
        repo_root = self.repos_cache / repo_id
        candidate = repo_root / file_rel
        snippet = _read_lines(candidate, start, end, pad=2)
        if snippet:
            return snippet, "checkout"
        # Fallback: ±50 line window on the same file (still empty if no checkout)
        snippet = _read_lines(candidate, start, end, pad=50)
        return snippet, "window" if snippet else "missing"

    def load(
        self, limit: int = 0, checkout: bool = False, clone: bool = False
    ) -> list[GroundTruthEntry]:
        entries: list[GroundTruthEntry] = []
        for gt_path in self._ground_truth_files():
            try:
                manifest = json.loads(gt_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Skipping %s: %s", gt_path, exc)
                continue

            repo_id = str(manifest.get("repo_id") or gt_path.parent.name)
            commit = str(manifest.get("commit_sha") or "")
            lang = str(manifest.get("language") or "").lower() or "python"
            checkout_status = ""
            if checkout:
                checkout_status = _checkout_commit(
                    self.repos_cache / repo_id,
                    repo_id,
                    str(manifest.get("repo_url") or ""),
                    commit,
                    clone,
                )
                logger.info("RealVuln checkout %s: %s", repo_id, checkout_status)

            for f in manifest.get("findings", []):
                is_vuln = bool(f.get("is_vulnerable"))
                label = LABEL_TP if is_vuln else LABEL_FP

                cwe_id = _normalize_cwe(f.get("primary_cwe"))
                if not cwe_id:
                    continue

                location = f.get("location") or {}
                start_line = int(location.get("start_line") or 0)
                end_line = int(location.get("end_line") or start_line)
                func_name = str(location.get("function") or "")
                file_rel = str(f.get("file") or "")

                snippet, snippet_kind = self._resolve_snippet(
                    repo_id, f, file_rel, start_line, end_line
                )

                evidence = f.get("evidence") or {}
                finding_id = str(f.get("id") or f"{repo_id}-{len(entries)}")

                entries.append(
                    GroundTruthEntry(
                        id=f"realvuln-{repo_id}-{finding_id}",
                        source_dataset="realvuln",
                        cwe_id=cwe_id,
                        rule_id=primary_rule_for_lang(cwe_id, lang),
                        file_path=file_rel,
                        function_name=func_name,
                        start_line=start_line or 1,
                        # RealVuln carries real per-finding location lines, so it
                        # is line-anchored (verifier-track); other datasets are
                        # function-granularity and stay unanchored (#125).
                        sink_line=start_line or None,
                        lang=lang,
                        label=label,
                        code_snippet=snippet,
                        metadata={
                            **({"fp_origin": _fp_origin(f, evidence)} if not is_vuln else {}),
                            **({"checkout": checkout_status} if checkout else {}),
                            "repo_id": repo_id,
                            "commit_sha": commit,
                            "end_line": end_line,
                            "evidence_source": str(evidence.get("source") or ""),
                            "cve_id": str(evidence.get("cve_id") or ""),
                            "snippet_kind": snippet_kind,
                            "vulnerability_class": str(
                                f.get("vulnerability_class") or ""
                            ),
                        },
                    )
                )

                if limit and len(entries) >= limit:
                    return entries

        logger.info(
            "RealVuln: loaded %d entries from %s",
            len(entries), self.dataset_path,
        )
        return entries
