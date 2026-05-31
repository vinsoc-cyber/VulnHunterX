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

import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

_BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
DATASETS_DIR = _BENCHMARKS_DIR / "datasets"
_MANIFEST_PATH = _BENCHMARKS_DIR / "datasets.yaml"

# NIST SARD (and many CDNs) reject the default "Python-urllib/x.y" User-Agent
# with HTTP 403 Forbidden. Send a browser-like UA so zip downloads succeed.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _load_manifest() -> dict[str, dict]:
    """Load the install manifest from datasets.yaml and resolve target_dir.

    The manifest stores ``dirname`` (the on-disk directory name); we
    compute ``target_dir`` from it relative to ``DATASETS_DIR``. This
    keeps the YAML free of absolute paths.
    """
    with _MANIFEST_PATH.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    out: dict[str, dict] = {}
    for name, cfg in (raw.get("datasets") or {}).items():
        resolved = dict(cfg)
        resolved["target_dir"] = DATASETS_DIR / cfg["dirname"]
        out[name] = resolved
    return out


DATASETS: dict[str, dict] = _load_manifest()


def _git_clone(url: str, target: Path) -> None:
    if target.exists():
        logger.info("Already exists, pulling latest: %s", target)
        subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], check=True)
    else:
        logger.info("Cloning %s → %s", url, target)
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", url, str(target)], check=True)


def _ensure_gdown():  # type: ignore[no-untyped-def]
    """Import gdown, installing it into the current venv if missing.

    Prefers ``uv pip install`` because this project uses uv, whose venvs ship
    without pip — so ``python -m pip install`` raises "No module named pip".
    Falls back to pip, then ensurepip+pip, then a clear actionable error.
    """
    try:
        import gdown  # type: ignore[import]

        return gdown
    except ImportError:
        pass

    logger.info("gdown not found, installing…")
    import shutil as _shutil

    commands: list[list[str]] = []
    uv = _shutil.which("uv")
    if uv:
        commands.append([uv, "pip", "install", "--python", sys.executable, "--quiet", "gdown"])
    commands.append([sys.executable, "-m", "pip", "install", "--quiet", "gdown"])

    last_err: Exception | None = None
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
            import gdown  # type: ignore[import]

            return gdown
        except (subprocess.CalledProcessError, FileNotFoundError, ImportError) as exc:
            last_err = exc

    # Last resort: bootstrap pip into the venv via ensurepip, then install.
    try:
        subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=True)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "gdown"], check=True
        )
        import gdown  # type: ignore[import]

        return gdown
    except (subprocess.CalledProcessError, FileNotFoundError, ImportError) as exc:
        last_err = exc

    raise RuntimeError(
        "Could not install 'gdown' automatically. Install it manually, then re-run:\n"
        "  uv pip install gdown      (recommended — this project uses uv)\n"
        "  pip install gdown\n"
        f"(last error: {last_err})"
    )


def _download_gdrive(file_id: str, filename: str, target: Path) -> None:
    """Download a file from Google Drive using gdown."""
    out_path = target / filename
    if out_path.exists():
        logger.info("Already exists: %s", out_path)
        return
    target.mkdir(parents=True, exist_ok=True)
    gdown = _ensure_gdown()
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
    import os
    import shutil
    import zipfile

    # Use an explicit Request with a browser User-Agent (urlretrieve sends the
    # default Python-urllib UA, which NIST SARD rejects with HTTP 403). urlopen
    # follows redirects; stream to disk so large suites don't buffer in memory.
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, zip_path.open("wb") as out:  # noqa: S310
        shutil.copyfileobj(resp, out)
    logger.info("Extracting to %s …", target)
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
        elif cfg["type"] == "builtin":
            logger.info("✓ %s is in-repo (no download needed)", name)
            return True
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
