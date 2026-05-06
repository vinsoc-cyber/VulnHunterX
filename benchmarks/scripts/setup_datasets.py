#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Download and set up benchmark datasets.

Usage:
    python benchmarks/scripts/setup_datasets.py [--dataset secllmholmes|juliet|diversevul|all]
    python benchmarks/scripts/setup_datasets.py --list
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

DATASETS_DIR = Path(__file__).resolve().parents[1] / "datasets"

# Dataset configurations
DATASETS: dict[str, dict] = {
    "secllmholmes": {
        "description": "SecLLMHolmes: 228 C/C++ & Python scenarios (8 CWE classes)",
        "type": "git",
        "url": "https://github.com/ai4cloudops/SecLLMHolmes",
        "target_dir": DATASETS_DIR / "secllmholmes",
        "disk_mb": 50,
    },
    "juliet": {
        "description": "Juliet C/C++ 1.3.1: 64K test cases across ~180 CWEs (NIST SARD)",
        "type": "zip",
        "url": "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip",
        "target_dir": DATASETS_DIR / "juliet",
        "disk_mb": 600,
    },
    "owasp-java": {
        "description": "OWASP BenchmarkJava v1.2: ~2,740 Java test cases, 11 CWE categories (GPL-2.0)",
        "type": "git",
        "url": "https://github.com/OWASP-Benchmark/BenchmarkJava",
        "target_dir": DATASETS_DIR / "owasp-benchmark-java",
        "disk_mb": 200,
    },
    "owasp-python": {
        "description": "OWASP BenchmarkPython v0.1: ~1,230 Python test cases (GPL-3.0)",
        "type": "git",
        "url": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "target_dir": DATASETS_DIR / "owasp-benchmark-python",
        "disk_mb": 80,
    },
    "diversevul": {
        "description": "DiverseVul: 349K C/C++ functions with real CVE-backed labels (150 CWEs)",
        "type": "gdrive",
        # Google Drive file ID from https://github.com/wagner-group/diversevul README
        "gdrive_id": "12IWKhmLhq7qn5B_iXgn5YerOQtkH-6RG",
        "filename": "diversevul.json",
        "target_dir": DATASETS_DIR / "diversevul",
        "disk_mb": 2000,
    },
}


def _git_clone(url: str, target: Path) -> None:
    if target.exists():
        logger.info("Already exists, pulling latest: %s", target)
        subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], check=True)
    else:
        logger.info("Cloning %s → %s", url, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", url, str(target)], check=True)


def _download_gdrive(file_id: str, filename: str, target: Path) -> None:
    """Download a file from Google Drive using gdown."""
    out_path = target / filename
    if out_path.exists():
        logger.info("Already exists: %s", out_path)
        return
    target.mkdir(parents=True, exist_ok=True)
    try:
        import gdown  # type: ignore[import]
    except ImportError:
        logger.info("gdown not found, installing…")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "gdown"],
            check=True,
        )
        import gdown  # type: ignore[import]
    logger.info("Downloading Google Drive file %s → %s", file_id, out_path)
    url = f"https://drive.google.com/uc?id={file_id}"
    gdown.download(url, str(out_path), quiet=False)


def _download_and_extract(url: str, target: Path) -> None:
    if target.exists() and any(target.iterdir()):
        logger.info("Already exists: %s", target)
        return
    target.mkdir(parents=True, exist_ok=True)
    zip_path = target / "_download.zip"
    logger.info("Downloading %s …", url)
    urllib.request.urlretrieve(url, zip_path)  # noqa: S310
    logger.info("Extracting to %s …", target)
    import os
    import shutil
    import zipfile
    target_resolved = target.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.infolist():
            # Compute the final path and ensure it stays within target_resolved
            member_path = (target_resolved / member.filename).resolve()
            common = os.path.commonpath([str(target_resolved), str(member_path)])
            if common != str(target_resolved):
                raise ValueError(f"Unsafe path in ZIP file: {member.filename!r}")
            if member.is_dir():
                member_path.mkdir(parents=True, exist_ok=True)
            else:
                member_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member, "r") as src, open(member_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
    zip_path.unlink()
    logger.info("Done: %s", target)


def setup_dataset(name: str) -> bool:
    cfg = DATASETS[name]
    logger.info("Setting up %s (~%d MB) …", name, cfg["disk_mb"])
    try:
        if cfg["type"] == "git":
            _git_clone(cfg["url"], cfg["target_dir"])
        elif cfg["type"] == "zip":
            _download_and_extract(cfg["url"], cfg["target_dir"])
        elif cfg["type"] == "gdrive":
            _download_gdrive(cfg["gdrive_id"], cfg["filename"], cfg["target_dir"])
        else:
            logger.error("Unknown dataset type: %s", cfg["type"])
            return False
        logger.info("✓ %s ready at %s", name, cfg["target_dir"])
        return True
    except Exception as exc:
        logger.error("Failed to set up %s: %s", name, exc)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        choices=[*DATASETS, "all"],
        default="all",
        help="Which dataset to download (default: all)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available datasets and exit",
    )
    args = parser.parse_args()

    if args.list:
        for name, cfg in DATASETS.items():
            print(f"  {name:20s}  {cfg['description']}  ({cfg['disk_mb']} MB)")
        return 0

    names = list(DATASETS.keys()) if args.dataset == "all" else [args.dataset]
    total_mb = sum(DATASETS[n]["disk_mb"] for n in names)
    logger.info(
        "Will download: %s  (approx %d MB total)", ", ".join(names), total_mb
    )

    ok = all(setup_dataset(n) for n in names)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
