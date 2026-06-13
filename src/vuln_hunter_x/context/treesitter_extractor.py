# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Extract context information from source code using tree-sitter."""

from __future__ import annotations

import csv
from pathlib import Path

import tree_sitter

# Query types by language (mirrors codeql/context_extractor.py QUERIES_BY_LANG)
QUERIES_BY_LANG: dict[str, list[str]] = {
    "c": ["functions", "callers", "structs", "globals", "macros"],
    "cpp": ["functions", "callers", "structs", "globals", "macros"],
    "python": ["functions", "callers", "classes"],
    "javascript": ["functions", "callers", "classes"],
    "php": ["functions", "callers", "classes"],
    "java": ["functions", "callers", "classes"],
    "go": ["functions", "callers", "classes"],
    "csharp": ["functions", "callers", "classes"],
}

# File extensions per language
LANG_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h"),
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs"),
    "java": (".java",),
    "php": (".php",),
    "go": (".go",),
    "csharp": (".cs",),
}

# CSV field definitions per query type
CSV_FIELDS: dict[str, list[str]] = {
    "functions": ["name", "file", "start_line", "end_line", "param_count"],
    "callers": [
        "callee_name",
        "callee_file",
        "caller_name",
        "caller_file",
        "caller_start_line",
        "caller_end_line",
    ],
    "classes": ["name", "file", "start_line", "end_line"],
    "structs": ["name", "file", "start_line", "end_line", "member_name"],
    "globals": ["name", "file", "start_line", "end_line", "type"],
    "macros": ["name", "file", "line", "body"],
}


def _get_language(lang: str) -> tree_sitter.Language:
    """Load tree-sitter language for the given language code."""
    lang_modules: dict[str, str] = {
        "c": "tree_sitter_c",
        "cpp": "tree_sitter_cpp",
        "python": "tree_sitter_python",
        "javascript": "tree_sitter_javascript",
        "java": "tree_sitter_java",
        "php": "tree_sitter_php",
        "go": "tree_sitter_go",
        "csharp": "tree_sitter_c_sharp",
    }
    module_name = lang_modules[lang]
    import importlib

    mod = importlib.import_module(module_name)
    # tree-sitter-php exports language_php() instead of language()
    lang_func = getattr(mod, "language", None) or getattr(mod, f"language_{lang}", None)
    if lang_func is None:
        raise ValueError(f"No language function found in {module_name}")
    return tree_sitter.Language(lang_func())


def _get_node_text(node: tree_sitter.Node) -> str:
    """Get the text of a tree-sitter node."""
    return node.text.decode("utf-8", errors="replace") if node.text else ""


def _find_child_by_type(node: tree_sitter.Node, *types: str) -> tree_sitter.Node | None:
    """Find the first child of node matching any of the given types."""
    for child in node.children:
        if child.type in types:
            return child
    return None


def _find_enclosing_function(node: tree_sitter.Node) -> tree_sitter.Node | None:
    """Walk up the tree to find the enclosing function definition."""
    func_types = {
        "function_definition",
        "function_declaration",
        "method_declaration",
        "method_definition",
        "arrow_function",
    }
    current = node.parent
    while current is not None:
        if current.type in func_types:
            return current
        current = current.parent
    return None


def _count_params(node: tree_sitter.Node) -> int:
    """Count parameters in a function definition node."""
    # Search for parameter_list in the node and its immediate children (e.g. function_declarator)
    param_list = _find_param_list(node)
    if param_list is None:
        return 0
    count = 0
    for child in param_list.children:
        if child.type in (
            "parameter_declaration",
            "parameter",
            "identifier",
            "typed_parameter",
            "default_parameter",
            "typed_default_parameter",
            "list_splat_pattern",
            "dictionary_splat_pattern",
            "formal_parameter",
            "spread_element",
            "required_parameter",
            "optional_parameter",
            "rest_parameter",
        ):
            count += 1
    return count


def _find_param_list(node: tree_sitter.Node) -> tree_sitter.Node | None:
    """Find the parameter list node, searching recursively through declarators."""
    param_types = ("parameter_list", "parameters", "formal_parameters", "simple_formal_parameters")
    result = _find_child_by_type(node, *param_types)
    if result is not None:
        return result
    # Look inside declarator children (C/C++ nests params in function_declarator)
    for child in node.children:
        if "declarator" in child.type:
            result = _find_child_by_type(child, *param_types)
            if result is not None:
                return result
    return None


def _get_func_name(node: tree_sitter.Node, lang: str) -> str | None:
    """Extract function name from a function definition node."""
    # C#: the method/constructor name is in the "name" field. Using the first
    # identifier child would wrongly pick up the return-type identifier that
    # precedes the name (e.g. `public Foo Bar()` → "Foo").
    if lang == "csharp":
        name_node = node.child_by_field_name("name")
        if name_node:
            return _get_node_text(name_node)

    # Try declarator first (C/C++)
    declarator = _find_child_by_type(node, "function_declarator")
    if declarator:
        name_node = _find_child_by_type(
            declarator, "identifier", "qualified_identifier", "field_identifier", "destructor_name"
        )
        if name_node:
            return _get_node_text(name_node)

    # Direct name child (Python, JS, Java, PHP)
    name_node = _find_child_by_type(node, "identifier", "name", "property_identifier")
    if name_node:
        return _get_node_text(name_node)

    return None


def _walk_tree(node: tree_sitter.Node, *types: str):
    """Yield all descendant nodes matching the given types."""
    if node.type in types:
        yield node
    for child in node.children:
        yield from _walk_tree(child, *types)


def discover_repos_for_context(
    output_dir: Path,
    repos_dir: Path,
) -> list[tuple[Path, str, str]]:
    """
    Discover repos that have SARIF output and source code but no CodeQL database.

    Returns:
        List of (repo_source_path, lang, repo_name) tuples.
    """
    results: list[tuple[Path, str, str]] = []
    if not output_dir.is_dir():
        return results

    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name.lower()
        if lang not in QUERIES_BY_LANG:
            continue

        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            repo_name = repo_dir.name

            # Must have at least one SARIF file
            sarif_files = list(repo_dir.glob("*.sarif"))
            if not sarif_files:
                continue

            # Must NOT have a valid CodeQL database (log/ alone may be from a failed attempt)
            db_dir = repo_dir / "database"
            if (db_dir / "codeql-database.yml").exists():
                continue

            # Must have source code
            repo_src = repos_dir / lang / repo_name
            if not repo_src.is_dir():
                continue

            results.append((repo_src, lang, repo_name))

    return results


class TreeSitterContextExtractor:
    """Extract context CSVs from source code using tree-sitter."""

    def __init__(self, repos_dir: Path, output_dir: Path) -> None:
        self.repos_dir = repos_dir
        self.output_dir = output_dir
        self._parsers: dict[str, tree_sitter.Parser] = {}

    def _get_parser(self, lang: str) -> tree_sitter.Parser:
        """Get or create a tree-sitter parser for the language."""
        if lang not in self._parsers:
            parser = tree_sitter.Parser(_get_language(lang))
            self._parsers[lang] = parser
        return self._parsers[lang]

    def _collect_source_files(self, lang: str, repo_path: Path) -> list[Path]:
        """Collect all source files for the language in the repo."""
        extensions = LANG_EXTENSIONS.get(lang, ())
        files: list[Path] = []
        for ext in extensions:
            files.extend(repo_path.rglob(f"*{ext}"))
        return sorted(files)

    @staticmethod
    def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
        """Write rows to a CSV file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()
            writer.writerows(rows)

    def _parse_file(self, parser: tree_sitter.Parser, file_path: Path) -> tree_sitter.Tree | None:
        """Parse a file and return its tree, or None on failure."""
        try:
            source = file_path.read_bytes()
            return parser.parse(source)
        except (OSError, UnicodeDecodeError):
            return None

    # ── Function extraction ──────────────────────────────────────────

    def _extract_functions(
        self,
        parser: tree_sitter.Parser,
        lang: str,
        source_files: list[Path],
        repo_root: Path,
    ) -> list[dict]:
        func_node_types = {
            "c": ("function_definition",),
            "cpp": ("function_definition",),
            "python": ("function_definition",),
            "javascript": ("function_declaration", "method_definition"),
            "java": ("method_declaration",),
            "php": ("function_definition", "method_declaration"),
            "go": ("function_declaration", "method_declaration"),
            "csharp": (
                "method_declaration",
                "constructor_declaration",
                "local_function_statement",
            ),
        }
        types = func_node_types.get(lang, ("function_definition",))
        rows: list[dict] = []

        for fpath in source_files:
            tree = self._parse_file(parser, fpath)
            if tree is None:
                continue
            rel = str(fpath.relative_to(repo_root))
            for node in _walk_tree(tree.root_node, *types):
                name = _get_func_name(node, lang)
                if not name:
                    continue
                rows.append(
                    {
                        "name": name,
                        "file": rel,
                        "start_line": node.start_point.row + 1,
                        "end_line": node.end_point.row + 1,
                        "param_count": _count_params(node),
                    }
                )
        return rows

    # ── Caller extraction ────────────────────────────────────────────

    def _extract_callers(
        self,
        parser: tree_sitter.Parser,
        lang: str,
        source_files: list[Path],
        repo_root: Path,
        func_map: dict[str, tuple[str, int, int]],
    ) -> list[dict]:
        """Extract caller→callee relationships via call_expression nodes."""
        call_node_types = {
            "c": ("call_expression",),
            "cpp": ("call_expression",),
            "python": ("call",),
            "javascript": ("call_expression",),
            "java": ("method_invocation",),
            "php": ("function_call_expression",),
            "go": ("call_expression",),
            "csharp": ("invocation_expression",),
        }
        types = call_node_types.get(lang, ("call_expression",))
        rows: list[dict] = []

        for fpath in source_files:
            tree = self._parse_file(parser, fpath)
            if tree is None:
                continue
            rel = str(fpath.relative_to(repo_root))

            for node in _walk_tree(tree.root_node, *types):
                callee_name = self._get_callee_name(node, lang)
                if not callee_name:
                    continue

                enclosing = _find_enclosing_function(node)
                if enclosing is None:
                    continue

                caller_name = _get_func_name(enclosing, lang)
                if not caller_name:
                    continue

                callee_file = ""
                if callee_name in func_map:
                    callee_file = func_map[callee_name][0]

                rows.append(
                    {
                        "callee_name": callee_name,
                        "callee_file": callee_file,
                        "caller_name": caller_name,
                        "caller_file": rel,
                        "caller_start_line": enclosing.start_point.row + 1,
                        "caller_end_line": enclosing.end_point.row + 1,
                    }
                )
        return rows

    @staticmethod
    def _get_callee_name(node: tree_sitter.Node, lang: str) -> str | None:
        """Extract the callee function name from a call node."""
        if not node.children:
            return None

        # C#: invocation_expression exposes the called expression in the
        # "function" field — either a bare identifier (`Foo()`) or a
        # member_access_expression (`obj.Method()`) whose "name" field holds
        # the method.
        if lang == "csharp":
            fn = node.child_by_field_name("function")
            if fn is None:
                return None
            if fn.type == "identifier":
                return _get_node_text(fn)
            name_node = fn.child_by_field_name("name")
            if name_node:
                return _get_node_text(name_node)
            return None

        func_node = node.children[0]

        # Simple identifier: foo()
        if func_node.type == "identifier":
            return _get_node_text(func_node)

        # Member access: obj.method() or obj->method()
        if func_node.type in (
            "member_expression",
            "field_expression",
            "attribute",
            "scoped_identifier",
        ):
            # Get the rightmost identifier (the method name)
            for child in reversed(func_node.children):
                if child.type in (
                    "identifier",
                    "property_identifier",
                    "field_identifier",
                    "name",
                ):
                    return _get_node_text(child)

        # Java method_invocation: first child is the name
        if lang == "java" and func_node.type == "identifier":
            return _get_node_text(func_node)

        # PHP: function name node
        if lang == "php":
            name_node = _find_child_by_type(node, "name", "qualified_name")
            if name_node:
                return _get_node_text(name_node)

        return None

    # ── Class extraction ─────────────────────────────────────────────

    def _extract_classes(
        self,
        parser: tree_sitter.Parser,
        lang: str,
        source_files: list[Path],
        repo_root: Path,
    ) -> list[dict]:
        class_node_types = {
            "python": ("class_definition",),
            "javascript": ("class_declaration",),
            "java": ("class_declaration",),
            "php": ("class_declaration",),
            "go": ("type_declaration",),
            "csharp": (
                "class_declaration",
                "interface_declaration",
                "struct_declaration",
                "record_declaration",
            ),
        }
        types = class_node_types.get(lang, ("class_declaration",))
        rows: list[dict] = []

        for fpath in source_files:
            tree = self._parse_file(parser, fpath)
            if tree is None:
                continue
            rel = str(fpath.relative_to(repo_root))
            for node in _walk_tree(tree.root_node, *types):
                name_node = node.child_by_field_name("name") or _find_child_by_type(
                    node, "identifier", "name"
                )
                if name_node is None:
                    continue
                rows.append(
                    {
                        "name": _get_node_text(name_node),
                        "file": rel,
                        "start_line": node.start_point.row + 1,
                        "end_line": node.end_point.row + 1,
                    }
                )
        return rows

    # ── Struct extraction (C/C++ only) ───────────────────────────────

    def _extract_structs(
        self,
        parser: tree_sitter.Parser,
        lang: str,
        source_files: list[Path],
        repo_root: Path,
    ) -> list[dict]:
        rows: list[dict] = []
        for fpath in source_files:
            tree = self._parse_file(parser, fpath)
            if tree is None:
                continue
            rel = str(fpath.relative_to(repo_root))
            for node in _walk_tree(tree.root_node, "struct_specifier"):
                name_node = _find_child_by_type(node, "type_identifier")
                if name_node is None:
                    continue
                struct_name = _get_node_text(name_node)

                # Find field_declaration children for member names
                body = _find_child_by_type(node, "field_declaration_list")
                if body is None:
                    continue

                for field in body.children:
                    if field.type != "field_declaration":
                        continue
                    field_name_node = _find_child_by_type(field, "field_identifier", "identifier")
                    member_name = _get_node_text(field_name_node) if field_name_node else ""
                    rows.append(
                        {
                            "name": struct_name,
                            "file": rel,
                            "start_line": node.start_point.row + 1,
                            "end_line": node.end_point.row + 1,
                            "member_name": member_name,
                        }
                    )
        return rows

    # ── Global variable extraction (C/C++ only) ─────────────────────

    def _extract_globals(
        self,
        parser: tree_sitter.Parser,
        lang: str,
        source_files: list[Path],
        repo_root: Path,
    ) -> list[dict]:
        rows: list[dict] = []
        for fpath in source_files:
            tree = self._parse_file(parser, fpath)
            if tree is None:
                continue
            rel = str(fpath.relative_to(repo_root))

            for node in tree.root_node.children:
                if node.type != "declaration":
                    continue
                # Extract type
                type_node = _find_child_by_type(
                    node,
                    "primitive_type",
                    "type_identifier",
                    "sized_type_specifier",
                    "struct_specifier",
                    "enum_specifier",
                )
                type_text = _get_node_text(type_node) if type_node else ""

                # Check for qualifiers like const/static
                for child in node.children:
                    if child.type in ("storage_class_specifier", "type_qualifier"):
                        type_text = _get_node_text(child) + " " + type_text

                # Extract declarator name
                declarator = _find_child_by_type(
                    node,
                    "init_declarator",
                    "identifier",
                )
                if declarator is None:
                    continue
                if declarator.type == "init_declarator":
                    name_node = _find_child_by_type(declarator, "identifier")
                else:
                    name_node = declarator

                if name_node is None:
                    continue

                rows.append(
                    {
                        "name": _get_node_text(name_node),
                        "file": rel,
                        "start_line": node.start_point.row + 1,
                        "end_line": node.end_point.row + 1,
                        "type": type_text.strip(),
                    }
                )
        return rows

    # ── Macro extraction (C/C++ only) ────────────────────────────────

    def _extract_macros(
        self,
        parser: tree_sitter.Parser,
        lang: str,
        source_files: list[Path],
        repo_root: Path,
    ) -> list[dict]:
        rows: list[dict] = []
        for fpath in source_files:
            tree = self._parse_file(parser, fpath)
            if tree is None:
                continue
            rel = str(fpath.relative_to(repo_root))
            for node in _walk_tree(tree.root_node, "preproc_def", "preproc_function_def"):
                name_node = _find_child_by_type(node, "identifier")
                if name_node is None:
                    continue
                # Body is the preproc_arg child
                body_node = _find_child_by_type(node, "preproc_arg")
                body = _get_node_text(body_node).strip() if body_node else ""
                rows.append(
                    {
                        "name": _get_node_text(name_node),
                        "file": rel,
                        "line": node.start_point.row + 1,
                        "body": body,
                    }
                )
        return rows

    # ── Orchestration ────────────────────────────────────────────────

    def extract_for_repo(
        self,
        lang: str,
        repo_name: str,
        dry_run: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """Extract all context CSVs for a single repo.

        Returns:
            Dict mapping query name to (success, message).
        """
        repo_path = self.repos_dir / lang / repo_name
        context_dir = self.output_dir / lang / repo_name / "context"
        query_types = QUERIES_BY_LANG.get(lang, [])
        results: dict[str, tuple[bool, str]] = {}

        parser = self._get_parser(lang)
        source_files = self._collect_source_files(lang, repo_path)

        if not source_files:
            for qt in query_types:
                results[qt] = (False, "No source files found")
            return results

        # Functions first (needed for callers func_map)
        func_rows: list[dict] = []
        func_map: dict[str, tuple[str, int, int]] = {}

        if "functions" in query_types:
            if dry_run:
                results["functions"] = (True, "[dry-run] would extract functions")
            else:
                func_rows = self._extract_functions(parser, lang, source_files, repo_path)
                self._write_csv(context_dir / "functions.csv", func_rows, CSV_FIELDS["functions"])
                results["functions"] = (True, f"{len(func_rows)} functions")
                # Build func_map for caller resolution
                for row in func_rows:
                    func_map[row["name"]] = (row["file"], row["start_line"], row["end_line"])

        # Remaining query types
        extractors: dict[str, tuple] = {
            "callers": (self._extract_callers, (parser, lang, source_files, repo_path, func_map)),
            "classes": (self._extract_classes, (parser, lang, source_files, repo_path)),
            "structs": (self._extract_structs, (parser, lang, source_files, repo_path)),
            "globals": (self._extract_globals, (parser, lang, source_files, repo_path)),
            "macros": (self._extract_macros, (parser, lang, source_files, repo_path)),
        }

        for qt in query_types:
            if qt == "functions":
                continue
            if qt not in extractors:
                continue

            if dry_run:
                results[qt] = (True, f"[dry-run] would extract {qt}")
                continue

            method, method_args = extractors[qt]
            rows = method(*method_args)
            self._write_csv(context_dir / f"{qt}.csv", rows, CSV_FIELDS[qt])
            results[qt] = (True, f"{len(rows)} {qt}")

        return results

    def extract_all(
        self,
        lang_filter: str | None = None,
        repo_filter: str | None = None,
        dry_run: bool = False,
    ) -> list[tuple[str, str, dict[str, tuple[bool, str]]]]:
        """Extract context for all discovered repos.

        Returns:
            List of (repo_name, lang, results_dict) tuples.
        """
        repos = discover_repos_for_context(self.output_dir, self.repos_dir)

        if lang_filter:
            repos = [(p, lg, n) for p, lg, n in repos if lg == lang_filter]
        if repo_filter:
            repos = [(p, lg, n) for p, lg, n in repos if n.lower() == repo_filter.lower()]

        all_results: list[tuple[str, str, dict[str, tuple[bool, str]]]] = []
        for _repo_path, lang, repo_name in repos:
            results = self.extract_for_repo(lang, repo_name, dry_run)
            all_results.append((repo_name, lang, results))

        return all_results
