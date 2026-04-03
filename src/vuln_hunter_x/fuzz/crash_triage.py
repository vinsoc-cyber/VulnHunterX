"""
Crash triage and deduplication for fuzzing results.

Re-runs crash inputs to extract ASan/UBSan stack traces, deduplicates by
stack hash, and classifies crash severity.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ASan error type → severity mapping
_SEVERITY_MAP: dict[str, str] = {
    "heap-buffer-overflow": "Critical",
    "stack-buffer-overflow": "High",
    "heap-use-after-free": "Critical",
    "double-free": "Critical",
    "use-after-poison": "High",
    "global-buffer-overflow": "High",
    "stack-use-after-return": "High",
    "heap-use-after-scope": "High",
    "null-dereference": "Medium",
    "SEGV": "Medium",
    "undefined-behavior": "Medium",
    "signed-integer-overflow": "Low",
    "unsigned-integer-overflow": "Low",
    "shift-exponent": "Low",
    "divide-by-zero": "Medium",
}

_ASAN_ERROR_RE = re.compile(r"ERROR:\s*(?:Address|Leak|Memory)Sanitizer:\s*(\S+)")
_UBSAN_ERROR_RE = re.compile(r"runtime error:\s*(.+?)(?:\n|$)")
_STACK_FRAME_RE = re.compile(r"#\d+\s+\S+\s+in\s+(\S+)")


@dataclass
class CrashInfo:
    """Information about a single crash after triage."""

    crash_file: str
    crash_type: str
    severity: str
    stack_hash: str
    faulting_function: str
    top_frames: list[str] = field(default_factory=list)
    raw_trace: str = ""

    def to_dict(self) -> dict:
        return {
            "crash_file": self.crash_file,
            "crash_type": self.crash_type,
            "severity": self.severity,
            "stack_hash": self.stack_hash,
            "faulting_function": self.faulting_function,
            "top_frames": self.top_frames,
        }


def _extract_stack_trace(stderr: str) -> tuple[str, str, list[str]]:
    """Extract crash type, faulting function, and top stack frames from ASan/UBSan output.

    Returns (crash_type, faulting_function, top_frames).
    """
    crash_type = "unknown"
    # Try ASan error
    m = _ASAN_ERROR_RE.search(stderr)
    if m:
        crash_type = m.group(1)
    else:
        # Try UBSan error
        m = _UBSAN_ERROR_RE.search(stderr)
        if m:
            crash_type = m.group(1).strip()

    # Extract stack frames
    frames = _STACK_FRAME_RE.findall(stderr)
    top_frames = frames[:10]
    faulting_function = frames[0] if frames else "unknown"

    return crash_type, faulting_function, top_frames


def _compute_stack_hash(top_frames: list[str], depth: int = 5) -> str:
    """Hash the top N stack frames (function names only) for deduplication."""
    key = "|".join(top_frames[:depth])
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def triage_crash(
    binary_path: Path,
    crash_file: Path,
    timeout_sec: int = 30,
) -> CrashInfo | None:
    """Re-run binary with crash input to extract ASan/UBSan stack trace.

    Args:
        binary_path: Path to the fuzz binary.
        crash_file: Path to the crash input file.
        timeout_sec: Timeout for re-running the binary.

    Returns:
        CrashInfo with extracted metadata, or None on failure.
    """
    if not binary_path.is_file() or not crash_file.is_file():
        return None

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"

    try:
        r = subprocess.run(
            [str(binary_path), str(crash_file)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )
        stderr = r.stderr or ""
    except subprocess.TimeoutExpired:
        return CrashInfo(
            crash_file=str(crash_file),
            crash_type="timeout",
            severity="Low",
            stack_hash="timeout",
            faulting_function="unknown",
            raw_trace="Triage timed out",
        )
    except Exception as e:
        logger.debug("Failed to triage crash %s: %s", crash_file, e)
        return None

    crash_type, faulting_fn, top_frames = _extract_stack_trace(stderr)
    stack_hash = _compute_stack_hash(top_frames)

    # Map crash type to severity
    severity = "Medium"
    for pattern, sev in _SEVERITY_MAP.items():
        if pattern.lower() in crash_type.lower():
            severity = sev
            break

    return CrashInfo(
        crash_file=str(crash_file),
        crash_type=crash_type,
        severity=severity,
        stack_hash=stack_hash,
        faulting_function=faulting_fn,
        top_frames=top_frames,
        raw_trace=stderr[-2000:],
    )


def triage_and_dedup(
    binary_path: Path,
    crash_files: list[Path],
    timeout_sec: int = 30,
) -> list[CrashInfo]:
    """Triage all crash files and deduplicate by stack hash.

    Returns one CrashInfo per unique crash signature (deduplicated).
    """
    all_crashes: list[CrashInfo] = []
    for cf in crash_files:
        info = triage_crash(binary_path, cf, timeout_sec=timeout_sec)
        if info:
            all_crashes.append(info)

    # Deduplicate by stack_hash — keep first occurrence
    seen: set[str] = set()
    unique: list[CrashInfo] = []
    for crash in all_crashes:
        if crash.stack_hash not in seen:
            seen.add(crash.stack_hash)
            unique.append(crash)

    return unique
