# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for the CVEfixes fix-commit selector (tiny synthetic SQLite DB)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from benchmarks.builders import cvefixes_select as cs

P = "d" * 40


def _sha(c: str) -> str:
    return c * 40


def _build(path: Path) -> Path:
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE fixes(cve_id TEXT, hash TEXT, repo_url TEXT);
        CREATE TABLE commits(hash TEXT, repo_url TEXT, parents TEXT);
        CREATE TABLE file_change(file_change_id TEXT, hash TEXT, filename TEXT,
                                 new_path TEXT, programming_language TEXT);
        CREATE TABLE cve(cve_id TEXT, published_date TEXT);
        CREATE TABLE cwe_classification(cve_id TEXT, cwe_id TEXT);
        """
    )

    def add(cve, h, repo, parents, files, pub, cwes):
        con.execute("INSERT INTO fixes VALUES (?,?,?)", (cve, h, repo))
        con.execute("INSERT INTO commits VALUES (?,?,?)", (h, repo, parents))
        for i, (fn, lang) in enumerate(files):
            con.execute(
                "INSERT INTO file_change VALUES (?,?,?,?,?)",
                (f"{h}{i}", h, fn.split("/")[-1], fn, lang),
            )
        con.execute("INSERT INTO cve VALUES (?,?)", (cve, pub))
        for c in cwes:
            con.execute("INSERT INTO cwe_classification VALUES (?,?)", (cve, c))

    gh = "https://github.com/acme/"
    add(
        "CVE-1",
        _sha("1"),
        gh + "a",
        f"['{P}']",
        [("a.py", "Python")],
        "2023-01-05T00:00",
        ["CWE-89"],
    )
    add(
        "CVE-2",
        _sha("2"),
        gh + "b",
        f"['{P}']",
        [("b.js", "TypeScript")],
        "2020-01-05",
        ["NVD-CWE-Other", "CWE-79"],
    )
    add("CVE-3", _sha("3"), gh + "c", f"['{P}']", [("c.php", "PHP")], "2022-05-05", ["CWE-89"])
    add(
        "CVE-4",
        _sha("4"),
        "git@github.com:acme/d.git",
        f"['{P}']",
        [("d.py", "Python")],
        "2023-01-05",
        ["CWE-89"],
    )
    add(
        "CVE-5",
        _sha("5"),
        gh + "e",
        f"['{P}', '{'q' * 40}']",
        [("e.py", "Python")],
        "2023-01-05",
        ["CWE-89"],
    )
    add(
        "CVE-6",
        _sha("6"),
        gh + "f",
        f"['{P}']",
        [(f"f{i}.py", "Python") for i in range(5)],
        "2023-01-05",
        ["CWE-89"],
    )
    add("CVE-7", _sha("7"), gh + "g", f"['{P}']", [("g.rb", "Ruby")], "2023-01-05", ["CWE-89"])
    add("CVE-8", _sha("8"), gh + "h", f"['{P}']", [("h.py", "Python")], "2023-01-05", ["CWE-9999"])
    add(
        "CVE-9",
        _sha("9"),
        "file:///etc",
        f"['{P}']",
        [("i.py", "Python")],
        "2023-01-05",
        ["CWE-89"],
    )
    # CVE-10: two fix commits -> dropped
    add("CVE-10", _sha("a"), gh + "j", f"['{P}']", [("j.py", "Python")], "2023-01-05", ["CWE-89"])
    con.execute("INSERT INTO fixes VALUES ('CVE-10', ?, ?)", (_sha("b"), gh + "j"))
    con.commit()
    con.close()
    return path


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    return _build(tmp_path / "cvefixes.db")


def test_selection_and_attrition(db: Path):
    specs, attr = cs.select_fixes(db, langs=["python", "javascript", "php"], max_files=3)
    assert [s["cve_id"] for s in specs] == ["CVE-1", "CVE-2", "CVE-3"]
    s1 = specs[0]
    assert s1 == {
        "cve_id": "CVE-1",
        "cve_published": "2023-01-05",
        "repo_url": "https://github.com/acme/a",
        "lang": "python",
        "cwe": "CWE-89",
        "fix_sha": _sha("1"),
        "parent_sha": P,
        "changed_files": ["a.py"],
        "source": "cvefixes",
    }
    assert specs[1]["lang"] == "javascript" and specs[1]["cwe"] == "CWE-79"
    assert attr["single_fix_commit"] == 1
    assert attr["valid_repo_url"] == 2
    assert attr["single_parent"] == 1
    assert attr["files_le_max"] == 1
    assert attr["language_match"] == 1
    assert attr["cwe_covered"] == 1
    table = cs.format_attrition(attr, len(specs))
    assert "selected" in table and "single_parent" in table


def test_published_window(db: Path):
    specs, attr = cs.select_fixes(db, published_after="2021-01-01", published_before="2022-12-31")
    assert [s["cve_id"] for s in specs] == ["CVE-3"]
    assert attr["published_window"] >= 2


def test_caps_and_determinism(db: Path):
    a, _ = cs.select_fixes(db, langs=["python", "javascript", "php"], per_lang=1, seed=7)
    b, _ = cs.select_fixes(db, langs=["python", "javascript", "php"], per_lang=1, seed=7)
    assert a == b
    assert sorted(s["lang"] for s in a) == ["javascript", "php", "python"]
    c, attr = cs.select_fixes(db, langs=["python"], per_cwe=1)
    assert len(c) == 1


def test_db_opened_read_only(db: Path):
    con = cs.open_ro(db)
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM fixes")
    con.close()


def test_unsupported_lang(db: Path):
    with pytest.raises(ValueError):
        cs.select_fixes(db, langs=["cobol"])


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://github.com/a/b", True),
        ("https://gitlab.com/a/b", True),
        ("http://github.com/a/b", False),
        ("ssh://git@github.com/a/b", False),
        ("file:///a/b", False),
        ("https://evil.example/a/b", False),
        ("https://user:pw@github.com/a/b", False),
        ("https://github.com/a", False),
    ],
)
def test_valid_repo_url(url, ok):
    assert cs.valid_repo_url(url) is ok


def test_parse_parents():
    assert cs.parse_parents("['abc1234']") == ["abc1234"]
    assert cs.parse_parents('["a1b2c3d", "e4f5a6b"]') == ["a1b2c3d", "e4f5a6b"]
    assert cs.parse_parents("") == []


def test_cli(db: Path, tmp_path: Path, capsys):
    out = tmp_path / "o" / "fixes.jsonl"
    rc = cs.main(["--db", str(db), "--out", str(out), "--langs", "python"])
    assert rc == 0
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["cve_id"] for r in rows] == ["CVE-1"]
    assert "selected" in capsys.readouterr().out
    assert cs.main(["--db", str(tmp_path / "missing.db"), "--out", str(out)]) == 2
