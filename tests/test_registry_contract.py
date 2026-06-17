# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Contract tests for the dataset-adapter and benchmark-approach registries.

Both registries replace if/else dispatch chains in
``benchmarks/scripts/run_benchmark.py``. These tests iterate the registry
(not a hard-coded list of names) and assert each registered class
satisfies its respective ABC. Adding a new adapter/approach automatically
expands the test surface — no separate test PR required.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_bool,
    _to_csv_list,
    all_adapter_names,
    coerce_options,
    get_adapter,
    load_dataset,
    register_adapter,
)
from benchmarks.approaches.registry import (
    LLMConfig,
    RegisteredApproach,
    all_approach_names,
    build_approach,
    coerce_approach_options,
    get_approach,
    register_approach,
)
from benchmarks.approaches.base import BenchmarkResult


# ── Adapter contract ─────────────────────────────────────────────────


@pytest.mark.parametrize("name", all_adapter_names())
def test_adapter_inherits_abc(name: str):
    cls = get_adapter(name)
    assert issubclass(cls, DatasetAdapter), f"{cls.__name__} must inherit DatasetAdapter"


@pytest.mark.parametrize("name", all_adapter_names())
def test_adapter_declares_metadata(name: str):
    cls = get_adapter(name)
    assert cls.name == name, f"{cls.__name__}.name {cls.name!r} != registry key {name!r}"
    assert isinstance(cls.langs, tuple) and cls.langs, (
        f"{cls.__name__}.langs must be a non-empty tuple"
    )
    assert isinstance(cls.option_schema, dict), (
        f"{cls.__name__}.option_schema must be a dict"
    )


@pytest.mark.parametrize("name", all_adapter_names())
def test_adapter_option_specs_are_well_formed(name: str):
    """Every option in option_schema must be an OptionSpec with a callable coerce."""
    cls = get_adapter(name)
    for opt_name, spec in cls.option_schema.items():
        assert isinstance(spec, OptionSpec), (
            f"{cls.__name__}.option_schema[{opt_name!r}] must be an OptionSpec"
        )
        assert callable(spec.coerce), (
            f"{cls.__name__}.option_schema[{opt_name!r}].coerce must be callable"
        )


def test_adapter_registry_rejects_duplicate():
    """Re-registering the same class is a no-op; re-registering a DIFFERENT
    class under an existing name raises. Locks the deduplication invariant."""

    class _Duplicate(DatasetAdapter):
        name = "diversevul"  # already taken
        langs = ("c",)
        option_schema: dict = {}

        def __init__(self, dataset_path):  # noqa: ANN001
            self.dataset_path = dataset_path

        def load(self, limit=0, **kwargs):
            return []

    with pytest.raises(ValueError, match="duplicate"):
        register_adapter(_Duplicate)


def test_adapter_registry_unknown_name():
    with pytest.raises(KeyError, match="unknown dataset"):
        get_adapter("not-a-real-dataset")


def test_coerce_options_separates_valid_and_ignored():
    valid, ignored = coerce_options(
        "diversevul",
        {"negative_fraction": "0.5", "bogus_key": "x"},
    )
    assert valid == {"negative_fraction": 0.5}
    assert ignored == ["bogus_key"]


def test_coerce_options_raises_on_bad_value():
    with pytest.raises(ValueError):
        coerce_options("diversevul", {"negative_fraction": "not a float"})


def test_to_bool_and_csv_list_helpers():
    assert _to_bool("true") is True
    assert _to_bool("False") is False
    assert _to_bool("1") is True
    with pytest.raises(ValueError):
        _to_bool("maybe")
    assert _to_csv_list("a,b, c") == ["a", "b", "c"]
    assert _to_csv_list("") == []


def test_load_dataset_warns_on_unknown_option(caplog, tmp_path):
    # Use an empty tmp dir — the adapter raises after the warning fires.
    # We assert on the warning regardless of whether load() succeeds.
    with caplog.at_level("WARNING"):
        with pytest.raises(Exception):  # noqa: BLE001 — any error after the warning
            load_dataset("diversevul", tmp_path, options={"bogus": "x"})
    assert any("ignored" in r.message for r in caplog.records)


# ── Approach contract ────────────────────────────────────────────────


@pytest.mark.parametrize("name", all_approach_names())
def test_approach_inherits_abc(name: str):
    cls = get_approach(name)
    assert issubclass(cls, RegisteredApproach)


@pytest.mark.parametrize("name", all_approach_names())
def test_approach_declares_metadata(name: str):
    cls = get_approach(name)
    assert cls.name == name
    assert isinstance(cls.is_baseline, bool)
    assert isinstance(cls.requires_llm, bool)
    assert isinstance(cls.option_schema, dict)


@pytest.mark.parametrize("name", all_approach_names())
def test_approach_option_specs_are_well_formed(name: str):
    cls = get_approach(name)
    for opt_name, spec in cls.option_schema.items():
        assert isinstance(spec, OptionSpec)
        assert callable(spec.coerce)


@pytest.mark.parametrize("name", all_approach_names())
def test_approach_from_options_returns_self_type(name: str):
    """``from_options`` must return an instance of the class itself, not a
    base class — protects against accidental ABC misuse."""
    cls = get_approach(name)
    inst = cls.from_options(LLMConfig(dry_run=True), {})
    assert isinstance(inst, cls)


def test_build_approach_warns_on_unknown_option(caplog):
    with caplog.at_level("WARNING"):
        inst = build_approach(
            "raw-sast",
            llm=LLMConfig(dry_run=True),
            options={"max_iterations": "5"},  # unknown for raw-sast
        )
    assert any("ignored" in r.message for r in caplog.records)
    # Approach still instantiates despite the warning.
    assert inst is not None


def test_coerce_approach_options_round_trip():
    valid, ignored = coerce_approach_options(
        "vulnhunterx",
        {"max_iterations": "4", "force_decision": "false", "garbage": "x"},
    )
    assert valid == {"max_iterations": 4, "force_decision": False}
    assert ignored == ["garbage"]


# ── Family aliases (registry tags) ───────────────────────────────────


def test_adapter_family_owasp_expands():
    from benchmarks.adapters.registry import adapters_in_family
    names = adapters_in_family("owasp")
    assert "owasp-java" in names
    assert "owasp-python" in names


def test_adapter_family_unknown_returns_empty():
    from benchmarks.adapters.registry import adapters_in_family
    assert adapters_in_family("not-a-family") == []
