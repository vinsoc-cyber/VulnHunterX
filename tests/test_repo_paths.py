"""Fail-closed, repo-scoped source path resolution (#156)."""

from pathlib import Path

from vuln_hunter_x.context.repo_paths import resolve_repo_file, resolve_repo_root


def _write(base: Path, lang: str, repo: str, rel: str, content: str = "x") -> None:
    p = base / lang / repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_resolves_within_named_repo_only(tmp_path):
    _write(tmp_path, "python", "repoA", "app.py", "A")
    _write(tmp_path, "python", "repoB", "app.py", "B")
    a = resolve_repo_file(tmp_path, "python", "repoA", "app.py")
    b = resolve_repo_file(tmp_path, "python", "repoB", "app.py")
    assert a is not None and a.read_text() == "A"
    assert b is not None and b.read_text() == "B"


def test_missing_file_in_named_repo_returns_none_no_sibling_scan(tmp_path):
    _write(tmp_path, "python", "repoB", "only_here.py")  # sibling has it
    assert resolve_repo_file(tmp_path, "python", "repoA", "only_here.py") is None


def test_empty_repo_name_fails_closed(tmp_path):
    _write(tmp_path, "python", "repoA", "app.py")
    assert resolve_repo_file(tmp_path, "python", "", "app.py") is None
    assert resolve_repo_root(tmp_path, "python", "") is None


def test_path_traversal_blocked(tmp_path):
    _write(tmp_path, "python", "repoA", "app.py")
    _write(tmp_path, "python", "repoB", "secret.py")
    assert resolve_repo_file(tmp_path, "python", "repoA", "../repoB/secret.py") is None


def test_symlinked_repo_root_is_followed(tmp_path):
    real = tmp_path / "checkout"
    real.mkdir()
    (real / "app.py").write_text("S")
    (tmp_path / "python").mkdir()
    (tmp_path / "python" / "repoA").symlink_to(real, target_is_directory=True)
    f = resolve_repo_file(tmp_path, "python", "repoA", "app.py")
    assert f is not None and f.read_text() == "S"


def test_repo_root_named_only(tmp_path):
    (tmp_path / "python" / "repoA").mkdir(parents=True)
    (tmp_path / "python" / "repoB").mkdir(parents=True)
    assert resolve_repo_root(tmp_path, "python", "repoA") == tmp_path / "python" / "repoA"
    assert resolve_repo_root(tmp_path, "python", "missing") is None
