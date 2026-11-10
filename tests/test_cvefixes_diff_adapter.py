# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for the cvefixes-diff manifest adapter."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest

from benchmarks.adapters.cvefixes_diff_adapter import CVEfixesDiffAdapter
from benchmarks.adapters.registry import all_adapter_names, get_adapter

FIXTURE = (
    Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures" / "cvefixes-diff_sample.json"
)


def _manifest(tmp_path: Path, extra_tiers=("ambiguous",)) -> Path:
    rows = json.loads(FIXTURE.read_text())
    for i, t in enumerate(extra_tiers):
        r = dict(rows[0])
        r["id"] = f"extra-{i}"
        r["metadata"] = {**rows[0]["metadata"], "label_tier": t}
        rows.append(r)
    p = tmp_path / "cvefixes-20260101.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return p


def test_registered():
    assert "cvefixes-diff" in all_adapter_names()
    cls = get_adapter("cvefixes-diff")
    assert cls.family == "cve"
    assert {"manifest", "tiers", "lang"} <= set(cls.option_schema)


def test_load_default_tiers_excludes_ambiguous(tmp_path):
    m = _manifest(tmp_path)
    entries = CVEfixesDiffAdapter(tmp_path).load(manifest=str(m))
    assert len(entries) == 6
    assert all(e.sink_line is not None for e in entries)
    assert all(e.metadata["label_tier"] != "ambiguous" for e in entries)
    assert {"label_source", "adjudication", "cve_published", "repo_name"} <= set(
        entries[0].metadata
    )


def test_ambiguous_never_loaded_even_if_requested(tmp_path):
    m = _manifest(tmp_path)
    entries = CVEfixesDiffAdapter(tmp_path).load(manifest=str(m), tiers=["ambiguous", "silver-tp"])
    assert entries and {e.metadata["label_tier"] for e in entries} == {"silver-tp"}


def test_tier_and_lang_filter_and_limit(tmp_path):
    m = _manifest(tmp_path)
    ad = CVEfixesDiffAdapter(tmp_path)
    assert len(ad.load(manifest=str(m), tiers=["persistent"])) == 2
    assert {e.lang for e in ad.load(manifest=str(m), lang=["php"])} == {"php"}
    assert len(ad.load(manifest=str(m), limit=2)) == 2


def test_sha256_sidecar(tmp_path, caplog):
    m = _manifest(tmp_path)
    side = m.with_name(m.name + ".sha256")
    side.write_text(hashlib.sha256(m.read_bytes()).hexdigest() + f"  {m.name}\n")
    ok = CVEfixesDiffAdapter(tmp_path).load(manifest=str(m))
    assert {e.metadata["manifest_sha256_status"] for e in ok} == {"ok"}
    side.write_text("0" * 64 + "\n")
    with caplog.at_level(logging.WARNING):
        bad = CVEfixesDiffAdapter(tmp_path).load(manifest=str(m))
    assert {e.metadata["manifest_sha256_status"] for e in bad} == {"mismatch"}
    assert "mismatch" in caplog.text
    side.unlink()
    none = CVEfixesDiffAdapter(tmp_path).load(manifest=str(m))
    assert {e.metadata["manifest_sha256_status"] for e in none} == {"absent"}


def test_default_manifest_picks_newest(tmp_path):
    old = tmp_path / "cvefixes-old.jsonl"
    old.write_text("")
    new = _manifest(tmp_path)
    import os

    os.utime(old, (1, 1))
    entries = CVEfixesDiffAdapter(tmp_path).load()
    assert len(entries) == 6
    assert entries[0].metadata["manifest_path"] == str(new)


def test_missing_manifest(tmp_path, monkeypatch):
    import benchmarks.adapters.cvefixes_diff_adapter as mod

    monkeypatch.setattr(mod, "_REPO_MANIFESTS", tmp_path / "none")
    with pytest.raises(FileNotFoundError):
        CVEfixesDiffAdapter(tmp_path).load()
