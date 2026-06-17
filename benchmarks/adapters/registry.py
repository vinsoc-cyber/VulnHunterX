# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Dataset adapter registry — replaces the hard-coded if/else dispatch in
``benchmarks/scripts/run_benchmark.py:_load_dataset`` and the parallel
``DATASETS`` dict in ``setup_datasets.py``.

Adding a new dataset is now a one-file change: implement the adapter,
declare ``name`` / ``langs`` / ``option_schema``, decorate with
``@register_adapter``. The CLI dispatcher resolves by name, validates
options against ``option_schema`` (warning on unknowns instead of silent
acceptance), and forwards.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from benchmarks.adapters.ground_truth import GroundTruthEntry

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OptionSpec:
    """A single dataset-adapter option declaration.

    ``coerce`` is applied to CLI-string values before forwarding to the
    adapter. Use ``str``, ``int``, ``float``, or ``_to_bool`` from this
    module. For list-of-string options (e.g. ``cwes``) pass a callable
    that splits ``"CWE-89,CWE-94"``-style values.
    """

    coerce: Any                  # callable: str -> typed value
    default: Any = None
    help: str = ""


def _to_bool(s: str) -> bool:
    if isinstance(s, bool):
        return s
    v = str(s).strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError(f"cannot coerce {s!r} to bool")


def _to_csv_list(s: str) -> list[str]:
    if isinstance(s, list):
        return [str(x) for x in s]
    return [piece.strip() for piece in str(s).split(",") if piece.strip()]


class DatasetAdapter(ABC):
    """Base class every dataset adapter must inherit.

    Concrete adapters declare class-level metadata so the registry can
    dispatch CLI requests, validate options, and (eventually) drive
    ``setup_datasets.py`` from the same source. Instances are constructed
    by the dispatcher as ``Adapter(dataset_path)``.
    """

    # ── Class-level metadata (override in subclasses) ──
    name: ClassVar[str] = ""
    langs: ClassVar[tuple[str, ...]] = ()
    family: ClassVar[str] = ""  # e.g. "owasp", "cve" — used by the "all"/family aliases
    option_schema: ClassVar[dict[str, OptionSpec]] = {}
    # ``install_url`` and ``expected_files`` are read by setup_datasets.py
    # via the manifest, not from these class attributes — kept here as
    # documentation hooks for adapter authors.
    install_url: ClassVar[str | None] = None
    expected_files: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def __init__(self, dataset_path: Path) -> None: ...

    @abstractmethod
    def load(self, limit: int = 0, **options: Any) -> list[GroundTruthEntry]:
        """Load entries from the dataset. Concrete signature accepts only
        options declared in this class's ``option_schema``."""
        ...


_REGISTRY: dict[str, type[DatasetAdapter]] = {}


def register_adapter(cls: type[DatasetAdapter]) -> type[DatasetAdapter]:
    """Decorator: register a DatasetAdapter subclass by its ``name``."""
    if not issubclass(cls, DatasetAdapter):
        raise TypeError(f"{cls!r} must inherit DatasetAdapter")
    if not cls.name:
        raise ValueError(f"{cls.__name__} must declare a non-empty class attr 'name'")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(
            f"duplicate dataset adapter registration for name {cls.name!r}: "
            f"{_REGISTRY[cls.name].__name__} vs {cls.__name__}"
        )
    _REGISTRY[cls.name] = cls
    return cls


def get_adapter(name: str) -> type[DatasetAdapter]:
    """Resolve a name to an adapter class. Raises ``KeyError`` on miss."""
    _ensure_loaded()
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown dataset {name!r}; registered: {sorted(_REGISTRY)}"
        ) from exc


def all_adapter_names() -> list[str]:
    """All registered dataset names, sorted."""
    _ensure_loaded()
    return sorted(_REGISTRY)


def adapters_in_family(family: str) -> list[str]:
    """All registered dataset names whose ``family`` matches.

    Used to expand aliases like ``--dataset owasp`` to all OWASP adapters
    without hard-coding a list.
    """
    _ensure_loaded()
    return sorted(
        name for name, cls in _REGISTRY.items() if cls.family == family
    )


def coerce_options(
    name: str, options: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Validate and coerce a free-form options dict against the adapter's
    ``option_schema``.

    Returns ``(valid_options, ignored_keys)``. Ignored keys are NOT raised
    — they emit a logger warning at the call site. Coercion failures DO
    raise ``ValueError`` so a user typo doesn't silently produce wrong
    results.
    """
    cls = get_adapter(name)
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
                f"option {key}={raw!r} for dataset {name!r}: {exc}"
            ) from exc
    return valid, ignored


def load_dataset(
    name: str,
    dataset_path: Path,
    limit: int = 0,
    options: dict[str, Any] | None = None,
) -> list[GroundTruthEntry]:
    """Single entry point: resolve adapter, coerce options, call .load().

    Caller-supplied options that aren't in the adapter's ``option_schema``
    are warned about and dropped — preserves the historic behaviour of
    not crashing on unknown flags, but makes leakage visible.
    """
    cls = get_adapter(name)
    valid, ignored = coerce_options(name, options or {})
    if ignored:
        logger.warning(
            "ignored unknown dataset options for %s: %s "
            "(valid keys: %s)",
            name,
            ignored,
            sorted(cls.option_schema),
        )
    return cls(dataset_path).load(limit=limit, **valid)


# ── Lazy import-time loading ─────────────────────────────────────────
# Concrete adapter modules import this module to call @register_adapter.
# To avoid circular imports, the adapter modules are imported lazily
# the first time a registry query happens.

_LOADED = False


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True  # set first so re-entry from imports doesn't recurse
    # Import each adapter module for its side-effect (@register_adapter).
    # Modules that fail to import are skipped with a warning — keeps the
    # registry usable for the others.
    for modname in (
        "benchmarks.adapters.diversevul_adapter",
        "benchmarks.adapters.juliet_adapter",
        "benchmarks.adapters.secllmholmes_adapter",
        "benchmarks.adapters.realvuln_adapter",
        "benchmarks.adapters.owasp_benchmark_adapter",
        "benchmarks.adapters.security_rules_adapter",
        "benchmarks.adapters.openvuln_adapter",
    ):
        try:
            __import__(modname)
        except Exception:  # noqa: BLE001
            logger.warning("failed to import adapter module %s", modname, exc_info=True)


# Re-exports
__all__ = [
    "DatasetAdapter",
    "OptionSpec",
    "register_adapter",
    "get_adapter",
    "all_adapter_names",
    "adapters_in_family",
    "coerce_options",
    "load_dataset",
    "_to_bool",
    "_to_csv_list",
]
