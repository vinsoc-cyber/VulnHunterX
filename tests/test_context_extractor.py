"""ContextExtractor.get_context slice-containment tests (issue #118 follow-up)."""
import textwrap
from pathlib import Path

from vuln_hunter_x.context.extractor import ContextExtractor


def _write(tmp_path: Path, lang: str, repo: str, rel: str, content: str) -> None:
    p = tmp_path / lang / repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def test_flagged_line_after_closed_function_is_still_in_slice(tmp_path):
    # Backward regex search finds `helper` (a real C signature) as the enclosing
    # function; its block closes at line 3, but the flagged line is 5. Before the
    # fix get_context returns [1,3] (line 5 omitted); the slice must contain line 5.
    content = textwrap.dedent(
        """\
        void helper(int x) {
            do_thing(x);
        }
        int global_flag = 1;
        dangerous_sink(global_flag);
        """
    )
    _write(tmp_path, "c", "demo", "mod.c", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("mod.c", 5, "c", repo_name="demo")
    assert ctx.start_line <= 5 <= ctx.end_line


def test_healthy_function_slice_is_unchanged(tmp_path):
    # A function that DOES contain the flagged line keeps its exact bounds.
    content = textwrap.dedent(
        """\
        int main(void) {
            int a = read_input();
            sink(a);
            return 0;
        }
        """
    )
    _write(tmp_path, "c", "demo", "main.c", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("main.c", 3, "c", repo_name="demo")
    assert (ctx.start_line, ctx.end_line) == (1, 5)
    assert ctx.function_name == "main"


def test_functionless_file_window_contains_flagged_line(tmp_path):
    # No function match anywhere → window fallback, which contains the line.
    content = "\n".join(f"stmt_{i}();" for i in range(1, 41)) + "\n"
    _write(tmp_path, "php", "app", "script.php", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("script.php", 30, "php", repo_name="app")
    assert ctx.start_line <= 30 <= ctx.end_line


def test_line_past_eof_does_not_claim_containment(tmp_path):
    # Flagged line beyond the file → the slice must not falsely span it
    # (this is the residual case that flows to NMD via the force-decision guard).
    content = "a();\nb();\nc();\n"
    _write(tmp_path, "c", "demo", "short.c", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("short.c", 999, "c", repo_name="demo")
    assert not (ctx.start_line <= 999 <= ctx.end_line)


def test_same_relative_path_resolves_within_own_repo(tmp_path):
    # Two repos share app.py; each finding must read its OWN repo's source and
    # the per-repo cache must not serve repoA's path to repoB (#156).
    _write(tmp_path, "python", "repoA", "app.py", "A_SOURCE\n" * 3)
    _write(tmp_path, "python", "repoB", "app.py", "B_SOURCE\n" * 3)
    ex = ContextExtractor(repos_base=tmp_path)
    a = ex.get_context("app.py", 1, "python", repo_name="repoA")
    b = ex.get_context("app.py", 1, "python", repo_name="repoB")
    assert "A_SOURCE" in a.code and "B_SOURCE" not in a.code
    assert "B_SOURCE" in b.code and "A_SOURCE" not in b.code


def test_empty_repo_name_yields_fallback_not_sibling(tmp_path):
    # No repo identity → fail-closed → placeholder, never a sibling repo's source.
    _write(tmp_path, "python", "repoA", "app.py", "SECRET\n")
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("app.py", 1, "python")  # no repo_name
    assert "SECRET" not in ctx.code


def _write_functions_csv(output_dir: Path, lang: str, repo: str, rows: list[tuple]) -> Path:
    ctx = output_dir / lang / repo / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    path = ctx / "functions.csv"
    lines = ["name,file,start_line,end_line"] + [",".join(map(str, r)) for r in rows]
    path.write_text("\n".join(lines) + "\n")
    return path


def test_python_regex_fallback_ignores_dict_literal_braces(tmp_path):
    # Brace counting used to "close" the function on the dict-literal line,
    # dropping the flagged line out of the slice and losing the function name.
    content = textwrap.dedent(
        """\
        def f(x):
            d = {"a": 1}
            y = x + 1
            return eval(y)

        def g():
            pass
        """
    )
    _write(tmp_path, "python", "demo", "m.py", content)
    ex = ContextExtractor(repos_base=tmp_path)
    ctx = ex.get_context("m.py", 4, "python", repo_name="demo")
    assert ctx.function_name == "f"
    # Ends before `def g` (the indentation walk keeps the trailing blank line).
    assert ctx.start_line == 1 and 4 <= ctx.end_line < 6


def test_csv_lookup_returns_innermost_function(tmp_path):
    repos = tmp_path / "repos"
    out = tmp_path / "output"
    _write(repos, "javascript", "demo", "app.js", "\n".join(f"// {i}" for i in range(1, 41)))
    _write_functions_csv(
        out, "javascript", "demo", [("wrapper", "app.js", 1, 40), ("handler", "app.js", 10, 20)]
    )
    ex = ContextExtractor(repos_base=repos, output_dir=out)
    ctx = ex.get_context("app.js", 15, "javascript", repo_name="demo")
    assert ctx.function_name == "handler"
    assert (ctx.start_line, ctx.end_line) == (10, 20)
    # Outside the inner function, the outer one still encloses.
    assert ex.get_context("app.js", 30, "javascript", repo_name="demo").function_name == "wrapper"


def test_functions_csv_is_loaded_once_per_repo(tmp_path):
    repos = tmp_path / "repos"
    out = tmp_path / "output"
    _write(repos, "c", "demo", "a.c", "\n".join(f"// {i}" for i in range(1, 11)))
    csv_path = _write_functions_csv(out, "c", "demo", [("fn", "a.c", 2, 8)])
    ex = ContextExtractor(repos_base=repos, output_dir=out)
    assert ex.get_context("a.c", 5, "c", repo_name="demo").function_name == "fn"
    csv_path.unlink()  # a cached index must not re-read the CSV
    assert ex.get_context("a.c", 6, "c", repo_name="demo").function_name == "fn"
    ex.clear_cache()
    assert ex.get_context("a.c", 6, "c", repo_name="demo").function_name != "fn"
