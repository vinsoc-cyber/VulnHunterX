from __future__ import annotations
from pathlib import Path


class Scorer:
    """Grade a raw-output dir against an oracle and diff two scores."""

    def score(self, raw_dir: Path, real_keys: set, meta: dict) -> dict:
        raise NotImplementedError

    def compare(self, previous: dict, current: dict, timestamp: str) -> dict:
        raise NotImplementedError

    def render_score(self, score: dict) -> str:
        raise NotImplementedError

    def render_compare(self, churn: dict) -> str:
        raise NotImplementedError
