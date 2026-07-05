from __future__ import annotations
from pathlib import Path


class Harness:
    """Fetch a target's source and run the tool, producing a raw-output dir."""

    def fetch(self, meta: dict, dest: Path) -> Path:
        raise NotImplementedError

    def run(self, meta: dict, src: Path, cfg: dict, raw_dir: Path,
            sarif: Path, context_dir: Path | None) -> float:
        raise NotImplementedError
