# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for crash_triage: parsing, dedup, and severity classification."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.fuzz.crash_triage import (
    CrashInfo,
    _compute_stack_hash,
    _extract_stack_trace,
    triage_and_dedup,
    triage_crash,
)

# ---------------------------------------------------------------------------
# Representative ASan/UBSan stderr samples
# ---------------------------------------------------------------------------

ASAN_HEAP_BUFFER_OVERFLOW = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x55a1b2c3d4e5 in parse_input src/parser.c:42
    #1 0x55a1b2c3d5e6 in process_packet src/network.c:100
    #2 0x55a1b2c3d6f7 in main src/main.c:200
SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:42 in parse_input
"""

ASAN_USE_AFTER_FREE = """\
=================================================================
==99999==ERROR: AddressSanitizer: heap-use-after-free on address 0xcafebabe
READ of size 8 at 0xcafebabe thread T0
    #0 0x400abc in free_node src/tree.c:88
    #1 0x400def in destroy_tree src/tree.c:120
SUMMARY: AddressSanitizer: heap-use-after-free src/tree.c:88 in free_node
"""

ASAN_DOUBLE_FREE = """\
==77777==ERROR: AddressSanitizer: double-free on address 0xbeefdead
    #0 0x401000 in cleanup src/cleanup.c:15
    #1 0x401100 in main src/main.c:50
"""

ASAN_NULL_DEREF = """\
==55555==ERROR: AddressSanitizer: null-dereference
    #0 0x501000 in deref_ptr src/ptr.c:9
    #1 0x501100 in run src/runner.c:33
"""

ASAN_SEGV = """\
==11111==ERROR: AddressSanitizer: SEGV on unknown address
    #0 0x601000 in segfault_fn src/fault.c:1
"""

UBSAN_SIGNED_OVERFLOW = """\
src/math.c:23:15: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x700001 in compute src/math.c:23
    #1 0x700002 in entry src/main.c:10
"""

UBSAN_DIVIDE_BY_ZERO = """\
src/calc.c:7:5: runtime error: division by zero
    #0 0x800001 in divide src/calc.c:7
"""

ASAN_NO_FRAMES = """\
==22222==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x0
"""

EMPTY_STDERR = ""


# ---------------------------------------------------------------------------
# _extract_stack_trace
# ---------------------------------------------------------------------------


class TestExtractStackTrace:
    def test_asan_heap_buffer_overflow(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(ASAN_HEAP_BUFFER_OVERFLOW)
        assert crash_type == "heap-buffer-overflow"
        assert faulting_fn == "parse_input"
        assert frames == ["parse_input", "process_packet", "main"]

    def test_asan_use_after_free(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(ASAN_USE_AFTER_FREE)
        assert crash_type == "heap-use-after-free"
        assert faulting_fn == "free_node"
        assert frames == ["free_node", "destroy_tree"]

    def test_asan_double_free(self):
        crash_type, _, _ = _extract_stack_trace(ASAN_DOUBLE_FREE)
        assert crash_type == "double-free"

    def test_asan_null_dereference(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(ASAN_NULL_DEREF)
        assert crash_type == "null-dereference"
        assert faulting_fn == "deref_ptr"

    def test_asan_segv(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(ASAN_SEGV)
        assert crash_type == "SEGV"
        assert faulting_fn == "segfault_fn"

    def test_ubsan_signed_overflow(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(UBSAN_SIGNED_OVERFLOW)
        # UBSan message is extracted (ASan pattern doesn't match)
        assert "signed integer overflow" in crash_type
        assert faulting_fn == "compute"
        assert frames[0] == "compute"

    def test_ubsan_divide_by_zero(self):
        crash_type, faulting_fn, _ = _extract_stack_trace(UBSAN_DIVIDE_BY_ZERO)
        assert "division by zero" in crash_type
        assert faulting_fn == "divide"

    def test_no_frames_returns_unknown_faulting_fn(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(ASAN_NO_FRAMES)
        assert crash_type == "heap-buffer-overflow"
        assert faulting_fn == "unknown"
        assert frames == []

    def test_empty_stderr_returns_unknown(self):
        crash_type, faulting_fn, frames = _extract_stack_trace(EMPTY_STDERR)
        assert crash_type == "unknown"
        assert faulting_fn == "unknown"
        assert frames == []

    def test_top_frames_capped_at_10(self):
        # Build stderr with 15 stack frames
        frame_lines = "\n".join(
            f"    #{ i} 0x{i:06x} in fn_{i} src/a.c:{i}" for i in range(15)
        )
        stderr = f"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n{frame_lines}\n"
        _, _, frames = _extract_stack_trace(stderr)
        assert len(frames) == 10


# ---------------------------------------------------------------------------
# _compute_stack_hash
# ---------------------------------------------------------------------------


class TestComputeStackHash:
    def test_same_frames_produce_same_hash(self):
        frames = ["parse_input", "process_packet", "main"]
        assert _compute_stack_hash(frames) == _compute_stack_hash(frames)

    def test_different_frames_produce_different_hash(self):
        frames_a = ["parse_input", "process_packet", "main"]
        frames_b = ["free_node", "destroy_tree", "main"]
        assert _compute_stack_hash(frames_a) != _compute_stack_hash(frames_b)

    def test_empty_frames_returns_hash(self):
        h = _compute_stack_hash([])
        assert isinstance(h, str) and len(h) == 16

    def test_hash_length_is_16_chars(self):
        frames = ["fn_a", "fn_b", "fn_c"]
        assert len(_compute_stack_hash(frames)) == 16

    def test_depth_parameter_limits_frames_used(self):
        frames = ["a", "b", "c", "d", "e", "f"]
        hash_depth2 = _compute_stack_hash(frames, depth=2)
        hash_depth3 = _compute_stack_hash(frames, depth=3)
        # Different depths → different hashes
        assert hash_depth2 != hash_depth3
        # Same first 2 frames subset
        assert hash_depth2 == _compute_stack_hash(["a", "b", "extra", "ignored"], depth=2)


# ---------------------------------------------------------------------------
# Severity mapping (via triage_crash / direct logic)
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    """Verify that crash types map to the expected severity levels."""

    _CASES = [
        ("heap-buffer-overflow", "Critical"),
        ("heap-use-after-free", "Critical"),
        ("double-free", "Critical"),
        ("stack-buffer-overflow", "High"),
        ("use-after-poison", "High"),
        ("global-buffer-overflow", "High"),
        ("stack-use-after-return", "High"),
        ("heap-use-after-scope", "High"),
        ("null-dereference", "Medium"),
        ("SEGV", "Medium"),
        ("undefined-behavior", "Medium"),
        ("divide-by-zero", "Medium"),
        ("signed-integer-overflow", "Low"),
        ("unsigned-integer-overflow", "Low"),
        ("shift-exponent", "Low"),
    ]

    @pytest.mark.parametrize("crash_type,expected_severity", _CASES)
    def test_severity(self, crash_type: str, expected_severity: str, tmp_path: Path):
        """Triage a synthetic crash and verify the severity label."""
        binary = tmp_path / "fuzz_target"
        binary.touch()
        crash_file = tmp_path / "crash-001"
        crash_file.touch()

        asan_err_line = f"==1==ERROR: AddressSanitizer: {crash_type}\n"
        frame_line = "    #0 0x123456 in some_fn src/a.c:1\n"
        fake_stderr = asan_err_line + frame_line

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stderr = fake_stderr
            mock_run.return_value = mock_result

            info = triage_crash(binary, crash_file)

        assert info is not None
        assert info.severity == expected_severity

    def test_unknown_crash_type_defaults_to_medium(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()
        crash_file = tmp_path / "crash-001"
        crash_file.touch()

        fake_stderr = "==1==ERROR: AddressSanitizer: some-weird-new-error\n    #0 0x1 in fn src/a.c:1\n"
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stderr = fake_stderr
            mock_run.return_value = mock_result

            info = triage_crash(binary, crash_file)

        assert info is not None
        assert info.severity == "Medium"


# ---------------------------------------------------------------------------
# triage_crash
# ---------------------------------------------------------------------------


class TestTriageCrash:
    def test_returns_none_for_missing_binary(self, tmp_path: Path):
        crash_file = tmp_path / "crash-001"
        crash_file.touch()
        result = triage_crash(tmp_path / "nonexistent", crash_file)
        assert result is None

    def test_returns_none_for_missing_crash_file(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()
        result = triage_crash(binary, tmp_path / "nonexistent")
        assert result is None

    def test_returns_crash_info_on_success(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()
        crash_file = tmp_path / "crash-001"
        crash_file.touch()

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stderr = ASAN_HEAP_BUFFER_OVERFLOW
            mock_run.return_value = mock_result

            info = triage_crash(binary, crash_file)

        assert info is not None
        assert isinstance(info, CrashInfo)
        assert info.crash_type == "heap-buffer-overflow"
        assert info.severity == "Critical"
        assert info.faulting_function == "parse_input"
        assert info.top_frames == ["parse_input", "process_packet", "main"]
        assert len(info.stack_hash) == 16
        assert str(crash_file) in info.crash_file

    def test_returns_timeout_crash_info_on_timeout(self, tmp_path: Path):
        import subprocess

        binary = tmp_path / "fuzz_target"
        binary.touch()
        crash_file = tmp_path / "crash-001"
        crash_file.touch()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[str(binary)], timeout=30)):
            info = triage_crash(binary, crash_file)

        assert info is not None
        assert info.crash_type == "timeout"
        assert info.severity == "Low"
        assert info.stack_hash == "timeout"

    def test_returns_none_on_unexpected_exception(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()
        crash_file = tmp_path / "crash-001"
        crash_file.touch()

        with patch("subprocess.run", side_effect=OSError("exec failed")):
            info = triage_crash(binary, crash_file)

        assert info is None

    def test_raw_trace_truncated_to_2000_chars(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()
        crash_file = tmp_path / "crash-001"
        crash_file.touch()

        long_stderr = "x" * 5000
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stderr = long_stderr
            mock_run.return_value = mock_result

            info = triage_crash(binary, crash_file)

        assert info is not None
        assert len(info.raw_trace) <= 2000


# ---------------------------------------------------------------------------
# triage_and_dedup
# ---------------------------------------------------------------------------


class TestTriageAndDedup:
    def _make_crash_info(self, crash_type: str, hash_suffix: str, path: str = "c1") -> CrashInfo:
        return CrashInfo(
            crash_file=path,
            crash_type=crash_type,
            severity="High",
            stack_hash=f"hash{hash_suffix}",
            faulting_function="fn",
            top_frames=["fn"],
        )

    def test_deduplicates_identical_stack_hashes(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()

        crash_files = [tmp_path / f"crash-{i:03d}" for i in range(3)]
        for cf in crash_files:
            cf.touch()

        # All three crashes produce the same stack trace / hash
        common_stderr = ASAN_HEAP_BUFFER_OVERFLOW

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stderr = common_stderr
            mock_run.return_value = mock_result

            result = triage_and_dedup(binary, crash_files)

        # Despite 3 inputs, only 1 unique crash (same hash)
        assert len(result) == 1
        assert result[0].crash_type == "heap-buffer-overflow"

    def test_keeps_distinct_stack_hashes(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()

        crash_files = [tmp_path / f"crash-{i:03d}" for i in range(2)]
        for cf in crash_files:
            cf.touch()

        sterrs = [ASAN_HEAP_BUFFER_OVERFLOW, ASAN_USE_AFTER_FREE]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(stderr=s) for s in sterrs
            ]
            result = triage_and_dedup(binary, crash_files)

        assert len(result) == 2

    def test_empty_crash_list_returns_empty(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()
        result = triage_and_dedup(binary, [])
        assert result == []

    def test_skips_failed_triages(self, tmp_path: Path):
        binary = tmp_path / "fuzz_target"
        binary.touch()

        crash_files = [tmp_path / f"crash-{i:03d}" for i in range(2)]
        for cf in crash_files:
            cf.touch()

        with patch("subprocess.run") as mock_run:
            # First call succeeds, second raises OSError → triage_crash returns None
            mock_run.side_effect = [
                MagicMock(stderr=ASAN_HEAP_BUFFER_OVERFLOW),
                OSError("exec failed"),
            ]
            result = triage_and_dedup(binary, crash_files)

        assert len(result) == 1


# ---------------------------------------------------------------------------
# CrashInfo.to_dict
# ---------------------------------------------------------------------------


class TestCrashInfoToDict:
    def test_to_dict_contains_expected_keys(self):
        info = CrashInfo(
            crash_file="input/crash-001",
            crash_type="heap-buffer-overflow",
            severity="Critical",
            stack_hash="abcd1234abcd1234",
            faulting_function="parse_input",
            top_frames=["parse_input", "main"],
        )
        d = info.to_dict()
        assert d["crash_file"] == "input/crash-001"
        assert d["crash_type"] == "heap-buffer-overflow"
        assert d["severity"] == "Critical"
        assert d["stack_hash"] == "abcd1234abcd1234"
        assert d["faulting_function"] == "parse_input"
        assert d["top_frames"] == ["parse_input", "main"]

    def test_to_dict_does_not_include_raw_trace(self):
        info = CrashInfo(
            crash_file="c",
            crash_type="t",
            severity="Low",
            stack_hash="h",
            faulting_function="f",
            raw_trace="lots of output",
        )
        assert "raw_trace" not in info.to_dict()
