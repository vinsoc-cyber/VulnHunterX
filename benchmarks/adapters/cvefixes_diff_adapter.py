# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the frozen CVEfixes revision-pair alert manifest.

The manifest is produced offline by ``benchmarks/scripts/build_revpair_manifest.py``
(from fix specs selected by ``benchmarks/builders/cvefixes_select.py``). It is a
JSONL file with one serialized ``GroundTruthEntry`` per line (a ``.json`` list
is accepted too). Each entry's ``metadata`` carries ``label_tier`` (e.g.
``silver-tp``, ``silver-tp-weak``, ``persistent``, ``ambiguous``),
``label_source``, ``adjudication``, ``cve_published`` and ``repo_name``.

Integrity: if ``<manifest>.sha256`` exists it is verified (sha256 hex digest,
optionally followed by a filename). A mismatch logs a warning and is recorded
in ``metadata["manifest_sha256_status"]`` of every entry. Entries with tier
``ambiguous`` are never loaded, whatever ``tiers`` asks for.

Default manifest lookup: newest ``cvefixes-*.jsonl`` under
``<dataset_path>/manifests`` or ``<dataset_path>``, then under the repo's
``benchmarks/manifests`` and ``output/revpair`` (the builder's default).
Manifest content is untrusted data.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import ClassVar

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_csv_list,
    register_adapter,
)

logger = logging.getLogger(__name__)

DEFAULT_TIERS = ("silver-tp", "silver-tp-weak", "persistent")
NEVER_LOADED_TIERS = frozenset({"ambiguous"})
_REPO_MANIFESTS = Path(__file__).resolve().parents[1] / "manifests"
# Default --output-dir of build_revpair_manifest.py (gitignored).
_BUILDER_OUTPUT = Path(__file__).resolve().parents[2] / "output" / "revpair"


def _newest(dirs: list[Path]) -> Path | None:
    found: list[Path] = []
    for d in dirs:
        if d.is_dir():
            found.extend(p for p in d.glob("cvefixes-*.jsonl") if p.is_file())
    if not found:
        return None
    return max(found, key=lambda p: (p.stat().st_mtime, p.name))


def verify_sha256_sidecar(manifest: Path) -> str:
    """Return 'ok' | 'mismatch' | 'absent' | 'unreadable'."""
    sidecar = manifest.with_name(manifest.name + ".sha256")
    if not sidecar.is_file():
        return "absent"
    try:
        expected = sidecar.read_text(encoding="utf-8").split()[0].lower()
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    except (OSError, IndexError):
        return "unreadable"
    return "ok" if digest == expected else "mismatch"


@register_adapter
class CVEfixesDiffAdapter(DatasetAdapter):
    """Load the frozen CVEfixes revision-pair alert manifest."""

    name = "cvefixes-diff"
    langs = ("python", "javascript", "php", "go", "java", "c", "cpp")
    family = "cve"
    option_schema: ClassVar[dict[str, OptionSpec]] = {
        "manifest": OptionSpec(
            coerce=str,
            default="",
            help="Path to frozen manifest JSONL (default: newest cvefixes-*.jsonl)",
        ),
        "tiers": OptionSpec(
            coerce=_to_csv_list,
            default=list(DEFAULT_TIERS),
            help="Comma-separated label tiers to keep "
            "(default: silver-tp,silver-tp-weak,persistent; 'ambiguous' is never loaded)",
        ),
        "lang": OptionSpec(
            coerce=_to_csv_list,
            default=[],
            help="Comma-separated language filter (default: all)",
        ),
    }
    install_url = "https://zenodo.org/records/4476563"
    expected_files = ()

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _resolve_manifest(self, manifest: str) -> Path:
        if manifest:
            p = Path(manifest)
            if not p.is_file():
                raise FileNotFoundError(f"manifest not found: {p}")
            return p
        p = _newest(
            [
                self.dataset_path / "manifests",
                self.dataset_path,
                _REPO_MANIFESTS,
                _BUILDER_OUTPUT,
            ]
        )
        if p is None:
            raise FileNotFoundError(
                f"No cvefixes-*.jsonl manifest under {self.dataset_path} or "
                f"{_REPO_MANIFESTS}; build one with "
                "benchmarks/scripts/build_revpair_manifest.py or pass manifest=<path>"
            )
        return p

    @staticmethod
    def _read(path: Path) -> list[dict]:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            data = json.loads(text)
            return data if isinstance(data, list) else [data]
        rows = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("%s:%d: skipping malformed line: %s", path, n, exc)
        return rows

    def load(
        self,
        limit: int = 0,
        manifest: str = "",
        tiers: list[str] | None = None,
        lang: list[str] | None = None,
    ) -> list[GroundTruthEntry]:
        path = self._resolve_manifest(manifest)
        status = verify_sha256_sidecar(path)
        if status in ("mismatch", "unreadable"):
            logger.warning("manifest sha256 sidecar %s for %s", status, path)
        keep_tiers = {t for t in (tiers or DEFAULT_TIERS)} - NEVER_LOADED_TIERS
        langs = set(lang or [])

        entries: list[GroundTruthEntry] = []
        for row in self._read(path):
            try:
                e = GroundTruthEntry.from_dict(row)
            except (KeyError, ValueError, TypeError) as exc:
                logger.warning("skipping invalid manifest entry: %s", exc)
                continue
            tier = str(e.metadata.get("label_tier", ""))
            if tier in NEVER_LOADED_TIERS or tier not in keep_tiers:
                continue
            if langs and e.lang not in langs:
                continue
            if e.sink_line is None:
                continue  # manifest entries are line-anchored by construction
            e.metadata = {
                **e.metadata,
                "manifest_path": str(path),
                "manifest_sha256_status": status,
            }
            entries.append(e)
            if limit and len(entries) >= limit:
                break
        logger.info("cvefixes-diff: loaded %d entries from %s", len(entries), path)
        return entries
