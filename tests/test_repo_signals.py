# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Tests for repo-level verifier signals (framework + unwired detection)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from vuln_hunter_x.context import repo_signals as rs


@pytest.fixture()
def fake_repo(tmp_path: Path) -> Path:
    """A minimal aiohttp-style repo with a disabled middleware + a live method."""
    (tmp_path / "requirements.txt").write_text("aiohttp==3.5.3\naiohttp-jinja2==1.1.0\n")
    (tmp_path / "app.py").write_text(textwrap.dedent("""
        from aiohttp import web
        from mw import session_middleware

        app = web.Application(middlewares=[
            session_middleware,
            # csrf_middleware,
        ])
    """))
    (tmp_path / "mw.py").write_text(textwrap.dedent("""
        async def session_middleware(request, handler):
            return await handler(request)

        async def csrf_middleware(request, handler):
            return await handler(request)
    """))
    (tmp_path / "dao.py").write_text(textwrap.dedent("""
        # create connection to the database
        async def create(conn, name):
            await conn.execute("INSERT ... '%s'" % name)
    """))
    (tmp_path / "views.py").write_text(textwrap.dedent("""
        from dao import create

        async def handler(conn, name):
            await create(conn, name)
    """))
    return tmp_path


def test_detect_frameworks(fake_repo: Path) -> None:
    rs.detect_frameworks.cache_clear()
    fws = rs.detect_frameworks_for(fake_repo / "app.py", "python")
    assert "aiohttp" in fws


def test_commented_out_symbol_flags_disabled_middleware(fake_repo: Path) -> None:
    rs._commented_identifier_index.cache_clear()
    rs._live_called_index.cache_clear()
    # csrf_middleware is only referenced on a commented-out line → unwired.
    assert rs.commented_out_symbol(fake_repo / "mw.py", "csrf_middleware", "python")


def test_commented_out_symbol_ignores_prose_comment_word(fake_repo: Path) -> None:
    rs._commented_identifier_index.cache_clear()
    rs._live_called_index.cache_clear()
    # "create" appears in a prose comment ("# create connection ...") but is a
    # live, called method — must NOT be flagged as unwired (regression guard:
    # this false signal previously downgraded a real SQL-injection finding).
    assert not rs.commented_out_symbol(fake_repo / "dao.py", "create", "python")


def test_commented_out_symbol_false_for_active_symbol(fake_repo: Path) -> None:
    rs._commented_identifier_index.cache_clear()
    rs._live_called_index.cache_clear()
    assert not rs.commented_out_symbol(fake_repo / "mw.py", "session_middleware", "python")


def test_commented_out_symbol_safe_on_anonymous(tmp_path: Path) -> None:
    assert not rs.commented_out_symbol(tmp_path / "x.py", "<unknown>", "python")
    assert not rs.commented_out_symbol(tmp_path / "x.py", "", "python")
