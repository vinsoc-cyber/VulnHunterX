# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Frozen manifest output for the revision-pair builder.

* ``<manifest>.jsonl`` — one ``GroundTruthEntry.to_dict()`` per line, sorted
  by id, keys sorted, so identical inputs produce byte-identical files.
  (``ground_truth.save_entries`` writes a single JSON array; JSONL is used here
  so large manifests can be streamed and diffed line by line.
  :func:`load_manifest` reads it back into ``GroundTruthEntry`` objects.)
* ``<manifest>.jsonl.sha256`` — ``sha256sum``-compatible digest line.
* ``<attrition>.json`` — funnel counts per step × lang × CWE × tool × tier.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.builders.revpair.runner import AttritionLog


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(entries: list[GroundTruthEntry], path: Path) -> str:
    """Write the JSONL manifest and its ``.sha256`` sidecar; return the digest."""
    dupes = {i for i, n in Counter(e.id for e in entries).items() if n > 1}
    if dupes:
        raise ValueError(f"duplicate entry ids: {sorted(dupes)[:5]}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        for e in sorted(entries, key=lambda e: e.id):
            fh.write(json.dumps(e.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)
    digest = _sha256_file(path)
    Path(f"{path}.sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def verify_manifest(path: Path) -> bool:
    """True iff ``path`` matches its ``.sha256`` sidecar."""
    sidecar = Path(f"{path}.sha256")
    if not sidecar.is_file():
        return False
    expected = sidecar.read_text(encoding="utf-8").split()[0]
    return expected == _sha256_file(path)


def load_manifest(path: Path) -> list[GroundTruthEntry]:
    """Read a JSONL manifest back into entries."""
    out: list[GroundTruthEntry] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                out.append(GroundTruthEntry.from_dict(json.loads(line)))
    return out


def write_attrition(attrition: AttritionLog, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(attrition.to_dict(), fh, indent=2, sort_keys=True)
        fh.write("\n")
