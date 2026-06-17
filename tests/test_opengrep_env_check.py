# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for OpenGrep environment check."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vuln_hunter_x.cli.env import check_opengrep


class TestCheckOpenGrep:
    def test_found_on_path(self):
        with (
            patch("vuln_hunter_x.cli.env.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.cli.env.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="1.100.0\n", stderr="")
            ok, msg = check_opengrep("opengrep")

        assert ok is True
        assert "1.100.0" in msg

    def test_not_on_path(self):
        with patch("vuln_hunter_x.cli.env.shutil.which", return_value=None):
            ok, msg = check_opengrep("opengrep")

        assert ok is False
        assert "not on PATH" in msg or "OPENGREP_PATH" in msg

    def test_custom_path_not_found(self):
        with (
            patch("vuln_hunter_x.cli.env.os.path.isfile", return_value=False),
            patch("vuln_hunter_x.cli.env.shutil.which", return_value=None),
        ):
            ok, msg = check_opengrep("/custom/opengrep")

        assert ok is False
        assert "OPENGREP_PATH" in msg

    def test_version_check_fails(self):
        with (
            patch("vuln_hunter_x.cli.env.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.cli.env.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="unknown command"
            )
            ok, msg = check_opengrep("opengrep")

        assert ok is False
        assert "failed" in msg.lower()

    def test_version_check_timeout(self):
        import subprocess

        with (
            patch("vuln_hunter_x.cli.env.shutil.which", return_value="/usr/bin/opengrep"),
            patch(
                "vuln_hunter_x.cli.env.subprocess.run",
                side_effect=subprocess.TimeoutExpired("opengrep", 10),
            ),
        ):
            ok, msg = check_opengrep("opengrep")

        assert ok is False
        assert "timed out" in msg.lower()
