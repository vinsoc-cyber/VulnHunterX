# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 VinSOC Cyber

"""Paths to read-only framework resources in a checkout or wheel installation."""

from __future__ import annotations

from pathlib import Path

_PACKAGE = Path(__file__).resolve().parents[1]
BUNDLED_CONFIG = _PACKAGE / "resources"
if not BUNDLED_CONFIG.is_dir() and _PACKAGE.parent.name == "src":
    BUNDLED_CONFIG = _PACKAGE.parent.parent / "config"
