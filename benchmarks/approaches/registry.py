# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Benchmark-approach registry — mirrors ``benchmarks.adapters.registry``.

Replaces the hard-coded if/else in
``benchmarks/scripts/run_benchmark.py:_build_approach`` with a registry
dispatch. Each approach declares its own ``option_schema`` so the CLI's
``--approach-option`` flag can validate and coerce values, and so
unsupported knobs warn instead of being silently dropped (the prior
behaviour for e.g. ``--use-slicing`` on ``raw-sast``).

Required dependencies on common LLM kwargs (``provider``, ``model``,
``dry_run``) are passed positionally via the shared ``LLMConfig`` dataclass
in this module, not through the option schema — they aren't per-approach
toggles, they're invocation context.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.adapters.registry import OptionSpec, _to_bool
from benchmarks.approaches.base import BenchmarkApproach, BenchmarkResult

logger = logging.getLogger(__name__)


@dataclass
class LLMConfig:
    """Invocation-time LLM context shared by every LLM-backed approach.

    Approaches that aren't LLM-backed (``raw-sast``) ignore this and the
    registry doesn't require them to accept it.
    """

    provider: str = "openai"
    model: str = "gpt-4o"
    dry_run: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class RegisteredApproach(BenchmarkApproach, ABC):
    """Base for registry-aware approaches.

    Subclass ``BenchmarkApproach`` so the ABC ``.evaluate()`` contract is
    still enforced. Adds class-level metadata read by the registry.
    """

    # ── Class-level metadata (override in subclasses) ──
    name: ClassVar[str] = ""
    requires_llm: ClassVar[bool] = True
    is_baseline: ClassVar[bool] = False  # raw-sast = True; LLM approaches = False
    option_schema: ClassVar[dict[str, OptionSpec]] = {}

    @classmethod
    @abstractmethod
    def from_options(
        cls,
        llm: LLMConfig | None,
        options: dict[str, Any],
    ) -> RegisteredApproach:
        """Construct an instance from validated CLI options.

        Each subclass picks the options it cares about. Unknown keys are
        already filtered by the dispatcher (see ``build_approach`` below).
        """
        ...


_REGISTRY: dict[str, type[RegisteredApproach]] = {}


def register_approach(cls: type[RegisteredApproach]) -> type[RegisteredApproach]:
    """Decorator: register a RegisteredApproach subclass by its ``name``."""
    if not issubclass(cls, RegisteredApproach):
        raise TypeError(f"{cls!r} must inherit RegisteredApproach")
    if not cls.name:
        raise ValueError(f"{cls.__name__} must declare a non-empty class attr 'name'")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(
            f"duplicate approach registration for name {cls.name!r}: "
            f"{_REGISTRY[cls.name].__name__} vs {cls.__name__}"
        )
    _REGISTRY[cls.name] = cls
    return cls


def get_approach(name: str) -> type[RegisteredApproach]:
    """Resolve a name to an approach class. Raises ``KeyError`` on miss."""
    _ensure_loaded()
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown approach {name!r}; registered: {sorted(_REGISTRY)}"
        ) from exc


def all_approach_names() -> list[str]:
    """All registered approach names, sorted."""
    _ensure_loaded()
    return sorted(_REGISTRY)


def coerce_approach_options(
    name: str, options: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Validate and coerce options against the approach's ``option_schema``."""
    cls = get_approach(name)
    valid: dict[str, Any] = {}
    ignored: list[str] = []
    for key, raw in options.items():
        spec = cls.option_schema.get(key)
        if spec is None:
            ignored.append(key)
            continue
        try:
            valid[key] = spec.coerce(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"option {key}={raw!r} for approach {name!r}: {exc}"
            ) from exc
    return valid, ignored


def build_approach(
    name: str,
    llm: LLMConfig | None = None,
    options: dict[str, Any] | None = None,
) -> RegisteredApproach:
    """Single entry point: resolve approach, coerce options, instantiate."""
    cls = get_approach(name)
    valid, ignored = coerce_approach_options(name, options or {})
    if ignored:
        logger.warning(
            "ignored unknown options for approach %s: %s "
            "(valid keys: %s)",
            name,
            ignored,
            sorted(cls.option_schema),
        )
    return cls.from_options(llm, valid)


_LOADED = False


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    for modname in (
        "benchmarks.approaches.raw_sast",
        "benchmarks.approaches.vulnhunterx",
        "benchmarks.approaches.ablation",
    ):
        try:
            __import__(modname)
        except Exception:  # noqa: BLE001
            logger.warning("failed to import approach module %s", modname, exc_info=True)


__all__ = [
    "LLMConfig",
    "RegisteredApproach",
    "register_approach",
    "get_approach",
    "all_approach_names",
    "coerce_approach_options",
    "build_approach",
    "_to_bool",
    "OptionSpec",
    "BenchmarkResult",
    "GroundTruthEntry",
]
