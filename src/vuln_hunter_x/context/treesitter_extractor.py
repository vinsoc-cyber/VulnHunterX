# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Extract context information from source code using tree-sitter."""

from __future__ import annotations

import csv
import os
from collections.abc import Iterator
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
    # TypeScript repos are indexed under "javascript" (as CodeQL does); .ts/.tsx
    # are parsed with the TypeScript grammars (see GRAMMAR_BY_EXTENSION).
    "javascript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
    "java": (".java",),
    "php": (".php",),
    "go": (".go",),
    "csharp": (".cs",),
}

# Files whose grammar differs from their index language. TypeScript is a JS
# superset syntactically, but the JavaScript grammar cannot parse type
# annotations, so each extension gets its own grammar while the rows land in
# the same javascript index.
GRAMMAR_BY_EXTENSION: dict[str, dict[str, str]] = {
    "javascript": {
        ".ts": "typescript",
        ".mts": "typescript",
        ".cts": "typescript",
        ".tsx": "tsx",
    },
}

# Directories never indexed: VCS metadata and installed JS dependencies. Both
# CodeQL's JavaScript extractor and the repo grep in ContextProvider skip
# node_modules; indexing it would bury the project's own symbols under
# third-party homonyms.
_SKIP_DIRS = frozenset({".git", "node_modules"})

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

# Function-like nodes per language. The SAME set defines both functions.csv rows
# and the enclosing function a call is attributed to, so the two CSVs agree.
# Anonymous forms (arrow functions, lambdas, closures) are included: they are
# named after their binding (`const h = () => ...`) when there is one, and
# otherwise skipped — a call inside them is attributed to the nearest NAMED
# enclosing function instead of being dropped.
FUNC_NODE_TYPES: dict[str, frozenset[str]] = {
    "c": frozenset({"function_definition"}),
    "cpp": frozenset({"function_definition", "lambda_expression"}),
    "python": frozenset({"function_definition", "lambda"}),
    "javascript": frozenset(
        {
            "function_declaration",
            "generator_function_declaration",
            "method_definition",
            "function_expression",
            "function",  # older grammars' name for function_expression
            "generator_function",
            "arrow_function",
        }
    ),
    "java": frozenset({"method_declaration", "constructor_declaration", "lambda_expression"}),
    "php": frozenset(
        {
            "function_definition",
            "method_declaration",
            "anonymous_function",
            "anonymous_function_creation_expression",
            "arrow_function",
        }
    ),
    "go": frozenset({"function_declaration", "method_declaration", "func_literal"}),
    "csharp": frozenset(
        {
            "method_declaration",
            "constructor_declaration",
            "local_function_statement",
            "lambda_expression",
        }
    ),
}

# Call nodes per language.
CALL_NODE_TYPES: dict[str, frozenset[str]] = {
    "c": frozenset({"call_expression"}),
    "cpp": frozenset({"call_expression"}),
    "python": frozenset({"call"}),
    "javascript": frozenset({"call_expression"}),
    "java": frozenset({"method_invocation"}),
    "php": frozenset(
        {
            "function_call_expression",
            "member_call_expression",
            "nullsafe_member_call_expression",
            "scoped_call_expression",
        }
    ),
    "go": frozenset({"call_expression"}),
    "csharp": frozenset({"invocation_expression"}),
}

CLASS_NODE_TYPES: dict[str, frozenset[str]] = {
    "python": frozenset({"class_definition"}),
    "javascript": frozenset(
        {
            "class_declaration",
            "class",
            # TypeScript: abstract bases and interfaces describe DTO / request
            # shapes that `struct:` / source_type lookups need.
            "abstract_class_declaration",
            "interface_declaration",
        }
    ),
    "java": frozenset(
        {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"}
    ),
    "php": frozenset({"class_declaration", "interface_declaration", "trait_declaration"}),
    "go": frozenset({"type_spec"}),
    "csharp": frozenset(
        {
            "class_declaration",
            "interface_declaration",
            "struct_declaration",
            "record_declaration",
        }
    ),
}

# C/C++ aggregate specifiers indexed into structs.csv.
_STRUCT_SPECIFIERS = frozenset({"struct_specifier", "union_specifier", "class_specifier"})

# Declarator wrappers unwrapped to reach the declared identifier.
_DECLARATOR_WRAPPERS = frozenset(
    {
        "init_declarator",
        "pointer_declarator",
        "array_declarator",
        "parenthesized_declarator",
        "reference_declarator",
        "attributed_declarator",
    }
)

# Preprocessor / linkage / namespace containers whose children are still
# file-scope declarations.
_C_SCOPE_CONTAINERS = frozenset(
    {
        "preproc_if",
        "preproc_ifdef",
        "preproc_else",
        "preproc_elif",
        "preproc_elifdef",
        "linkage_specification",
        "declaration_list",
        "namespace_definition",
    }
)


def _get_language(lang: str) -> tree_sitter.Language:
    """Load the tree-sitter grammar for a language or grammar key.

    Besides the index languages this accepts ``typescript`` and ``tsx``, the two
    grammars shipped by ``tree-sitter-typescript``.
    """
    if lang in ("typescript", "tsx"):
        import tree_sitter_typescript

        return tree_sitter.Language(getattr(tree_sitter_typescript, f"language_{lang}")())
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


def _get_node_text(node: tree_sitter.Node | None) -> str:
    """Get the text of a tree-sitter node."""
    if node is None:
        return ""
    return node.text.decode("utf-8", errors="replace") if node.text else ""


def _find_child_by_type(node: tree_sitter.Node, *types: str) -> tree_sitter.Node | None:
    """Find the first child of node matching any of the given types."""
    for child in node.children:
        if child.type in types:
            return child
    return None


def _iter_nodes(root: tree_sitter.Node) -> Iterator[tree_sitter.Node]:
    """Pre-order walk of every node under ``root`` (inclusive), iteratively.

    Iterative so a deeply nested tree (minified bundles, generated code) cannot
    exhaust Python's recursion limit and abort extraction for the whole repo.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _walk_tree(node: tree_sitter.Node, *types: str) -> Iterator[tree_sitter.Node]:
    """Yield all descendant nodes (inclusive) matching the given types."""
    wanted = frozenset(types)
    for n in _iter_nodes(node):
        if n.type in wanted:
            yield n


# ── Name resolution ──────────────────────────────────────────────────


def _last_segment(node: tree_sitter.Node | None) -> tree_sitter.Node | None:
    """Unqualify a C++/PHP name: ``ns::Cls::m`` / ``\\N\\f`` / ``tf<int>`` → the
    trailing simple name, matching CodeQL ``getName()``."""
    while node is not None and node.type in (
        "qualified_identifier",
        "qualified_name",
        "template_function",
        "template_method",
        "scoped_identifier",
    ):
        nxt = node.child_by_field_name("name")
        if nxt is None:
            named = [c for c in node.named_children]
            nxt = named[-1] if named else None
        if nxt is None or nxt == node:
            break
        node = nxt
    return node


def _c_declarator_name(decl: tree_sitter.Node | None) -> tree_sitter.Node | None:
    """Descend a C/C++ declarator chain to the declared name node."""
    seen = 0
    while decl is not None and seen < 64:
        seen += 1
        if decl.type in (
            "identifier",
            "field_identifier",
            "type_identifier",
            "destructor_name",
            "operator_name",
        ):
            return decl
        if decl.type in ("qualified_identifier", "template_function"):
            return _last_segment(decl)
        inner = decl.child_by_field_name("declarator")
        if inner is None:
            inner = _find_child_by_type(
                decl,
                "identifier",
                "field_identifier",
                "qualified_identifier",
                "destructor_name",
                "operator_name",
                *_DECLARATOR_WRAPPERS,
                "function_declarator",
            )
        decl = inner
    return None


def _binding_name(node: tree_sitter.Node) -> str | None:
    """Name an anonymous function after what it is bound to, if anything.

    ``const h = () => {}`` → ``h``; ``obj.m = function () {}`` → ``m``;
    ``{ k: () => 1 }`` → ``k``; Python ``f = lambda x: x`` → ``f``. A callback
    passed as an argument has no binding and stays anonymous.
    """
    parent = node.parent
    if parent is None:
        return None
    ptype = parent.type
    target: tree_sitter.Node | None = None
    if ptype == "variable_declarator":
        target = parent.child_by_field_name("name")
    elif ptype in ("assignment_expression", "assignment", "augmented_assignment_expression"):
        if parent.child_by_field_name("right") != node:
            return None
        target = parent.child_by_field_name("left")
    elif ptype in ("pair", "public_field_definition", "field_definition"):
        target = parent.child_by_field_name("key") or parent.child_by_field_name("property")
    if target is None:
        return None
    if target.type in ("member_expression", "attribute"):
        target = target.child_by_field_name("property") or target.child_by_field_name("attribute")
    if target is None or target.type not in (
        "identifier",
        "property_identifier",
        "private_property_identifier",
        "string",
    ):
        return None
    text = _get_node_text(target).strip("'\"`")
    return text or None


def _get_func_name(node: tree_sitter.Node, lang: str) -> str | None:
    """Extract the function name from a function-like node, or None if anonymous."""
    if lang in ("c", "cpp") and node.type == "function_definition":
        name_node = _c_declarator_name(node.child_by_field_name("declarator"))
        if name_node is not None:
            return _get_node_text(name_node) or None
        return None

    # Grammar-declared name field (Python, JS, Java, Go, PHP, C#). Taken from the
    # field — never "first identifier child" — so an arrow function's parameter
    # (`x => x`) or a C# return type (`public Foo Bar()`) is not misread as a name.
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        text = _get_node_text(_last_segment(name_node))
        if text:
            return text

    return _binding_name(node)


def _find_enclosing_function(
    node: tree_sitter.Node, lang: str
) -> tuple[tree_sitter.Node, str] | None:
    """Nearest NAMED function-like ancestor of ``node`` and its name.

    Unnamed functions (callbacks passed as arguments) are walked through, so a
    call inside ``app.get('/', (req, res) => exec(...))`` within ``outer`` is
    attributed to ``outer`` rather than dropped.
    """
    func_types = FUNC_NODE_TYPES.get(lang, frozenset({"function_definition"}))
    current = node.parent
    while current is not None:
        if current.type in func_types:
            name = _get_func_name(current, lang)
            if name:
                return current, name
        current = current.parent
    return None


def _count_params(node: tree_sitter.Node) -> int:
    """Count parameters in a function definition node."""
    # Single-parameter arrow function without parentheses: `x => x + 1`.
    if node.type == "arrow_function" and node.child_by_field_name("parameter") is not None:
        return 1
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
            "simple_parameter",
            "variadic_parameter",
            "variadic_parameter_declaration",
            "optional_parameter_declaration",
            "assignment_pattern",
            "object_pattern",
            "array_pattern",
        ):
            count += 1
    return count


def _find_param_list(node: tree_sitter.Node) -> tree_sitter.Node | None:
    """Find the parameter list node, searching through C/C++ declarator chains."""
    param_types = (
        "parameter_list",
        "parameters",
        "formal_parameters",
        "simple_formal_parameters",
        "lambda_parameters",
    )
    result = _find_child_by_type(node, *param_types)
    if result is not None:
        return result
    # C/C++ nest params in function_declarator, possibly under pointer wrappers
    # (`char *f(int a)` → pointer_declarator → function_declarator).
    decl = node.child_by_field_name("declarator")
    depth = 0
    while decl is not None and depth < 16:
        depth += 1
        result = _find_child_by_type(decl, *param_types)
        if result is not None:
            return result
        decl = decl.child_by_field_name("declarator")
    return None


def _callee_from_expr(expr: tree_sitter.Node | None) -> str | None:
    """Name of the function denoted by a call's callee expression."""
    if expr is None:
        return None
    t = expr.type
    if t in ("identifier", "name", "field_identifier", "property_identifier"):
        return _get_node_text(expr) or None
    if t in ("qualified_identifier", "qualified_name", "template_function", "scoped_identifier"):
        last = _last_segment(expr)
        return _get_node_text(last) or None if last is not None and last != expr else None
    # obj.m / obj->m / obj.m (Python) / pkg.F (Go)
    for field in ("property", "field", "attribute"):
        sub = expr.child_by_field_name(field)
        if sub is not None and t in (
            "member_expression",
            "field_expression",
            "attribute",
            "selector_expression",
        ):
            return _callee_from_expr(sub)
    if t == "parenthesized_expression":
        inner = [c for c in expr.named_children]
        return _callee_from_expr(inner[0]) if len(inner) == 1 else None
    # Fallback for grammar variants: rightmost simple name child.
    for child in reversed(expr.children):
        if child.type in ("identifier", "property_identifier", "field_identifier", "name"):
            return _get_node_text(child) or None
    return None


def _get_callee_name(node: tree_sitter.Node, lang: str) -> str | None:
    """Extract the callee function name from a call node."""
    if not node.children:
        return None

    # Calls that carry the method in a `name` field: Java `obj.m()`, PHP
    # `$o->m()` / `A::m()`. The object is NOT the callee (Java's first child
    # used to be read as the callee, recording `stmt` for `stmt.executeQuery()`).
    if node.type in (
        "method_invocation",
        "member_call_expression",
        "nullsafe_member_call_expression",
        "scoped_call_expression",
    ):
        return _callee_from_expr(node.child_by_field_name("name"))

    # C#: invocation_expression exposes the called expression in "function" —
    # a bare identifier (`Foo()`) or member access (`obj.Method()`) whose "name"
    # field holds the method.
    if lang == "csharp":
        fn = node.child_by_field_name("function")
        if fn is None:
            return None
        if fn.type == "identifier":
            return _get_node_text(fn)
        name_node = fn.child_by_field_name("name")
        if name_node is not None:
            return _get_node_text(_last_segment(name_node)) or None
        return None

    fn = node.child_by_field_name("function") or node.children[0]
    return _callee_from_expr(fn)


# ── Discovery ────────────────────────────────────────────────────────


def discover_repos_for_context(
    output_dir: Path,
    repos_dir: Path,
) -> list[tuple[Path, str, str]]:
    """
    Discover repos that have SARIF output and source code.

    Returns every source+SARIF candidate regardless of CodeQL DB presence.
    Backend preference — prefer CodeQL where it actually covers the repo — is
    applied by the caller's ``auto`` dedup, not here, so that an explicit
    tree-sitter request is honoured and a language CodeQL cannot extract
    context for (e.g. C#) is still reachable when a DB happens to exist.

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
        """Get or create a tree-sitter parser for a language or grammar key."""
        if lang not in self._parsers:
            parser = tree_sitter.Parser(_get_language(lang))
            self._parsers[lang] = parser
        return self._parsers[lang]

    def _parser_for(self, lang: str, path: Path) -> tree_sitter.Parser:
        """Parser for one file of the ``lang`` index, chosen by its extension."""
        grammar = GRAMMAR_BY_EXTENSION.get(lang, {}).get(path.suffix.lower(), lang)
        return self._get_parser(grammar)

    def _collect_source_files(self, lang: str, repo_path: Path) -> list[Path]:
        """Collect all source files for the language in the repo.

        Prunes ``_SKIP_DIRS`` during the walk (rather than filtering after an
        rglob) so a large node_modules tree is never traversed.
        """
        extensions = LANG_EXTENSIONS.get(lang, ())
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if fname.endswith(extensions):
                    files.append(Path(dirpath) / fname)
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

    # ── Per-tree extractors ──────────────────────────────────────────

    @staticmethod
    def _functions_in(tree: tree_sitter.Tree, lang: str, rel: str) -> list[dict]:
        types = FUNC_NODE_TYPES.get(lang, frozenset({"function_definition"}))
        rows: list[dict] = []
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

    @staticmethod
    def _calls_in(tree: tree_sitter.Tree, lang: str, rel: str) -> list[dict]:
        """Caller→callee rows; ``callee_file`` is resolved after all files are seen."""
        types = CALL_NODE_TYPES.get(lang, frozenset({"call_expression"}))
        rows: list[dict] = []
        for node in _walk_tree(tree.root_node, *types):
            callee_name = _get_callee_name(node, lang)
            if not callee_name:
                continue
            enclosing = _find_enclosing_function(node, lang)
            if enclosing is None:
                continue
            func_node, caller_name = enclosing
            rows.append(
                {
                    "callee_name": callee_name,
                    "callee_file": "",
                    "caller_name": caller_name,
                    "caller_file": rel,
                    "caller_start_line": func_node.start_point.row + 1,
                    "caller_end_line": func_node.end_point.row + 1,
                }
            )
        return rows

    @staticmethod
    def _classes_in(tree: tree_sitter.Tree, lang: str, rel: str) -> list[dict]:
        types = CLASS_NODE_TYPES.get(lang, frozenset({"class_declaration"}))
        rows: list[dict] = []
        for node in _walk_tree(tree.root_node, *types):
            name_node = node.child_by_field_name("name") or _find_child_by_type(
                node, "identifier", "name", "type_identifier"
            )
            name = _get_node_text(name_node) if name_node is not None else ""
            if not name and node.type == "class":
                name = _binding_name(node) or ""
            if not name:
                continue
            rows.append(
                {
                    "name": name,
                    "file": rel,
                    "start_line": node.start_point.row + 1,
                    "end_line": node.end_point.row + 1,
                }
            )
        return rows

    @staticmethod
    def _member_names(body: tree_sitter.Node) -> list[str]:
        members: list[str] = []
        for field in body.children:
            if field.type != "field_declaration":
                continue
            decls = field.children_by_field_name("declarator")
            if not decls:
                members.append("")
                continue
            for decl in decls:
                members.append(_get_node_text(_c_declarator_name(decl)))
        return members or [""]

    @classmethod
    def _structs_in(cls, tree: tree_sitter.Tree, lang: str, rel: str) -> list[dict]:
        """One row per member of each struct/union/class definition.

        Indexed under the tag name AND every typedef alias, so both
        ``struct:foo`` and ``struct:foo_t`` resolve, and an anonymous
        ``typedef struct { ... } Msg;`` is found as ``Msg``.
        """
        rows: list[dict] = []
        for node in _walk_tree(tree.root_node, *_STRUCT_SPECIFIERS):
            body = node.child_by_field_name("body") or _find_child_by_type(
                node, "field_declaration_list"
            )
            if body is None:
                continue  # forward declaration / elaborated type use
            names: list[tuple[str, tree_sitter.Node]] = []
            tag = node.child_by_field_name("name") or _find_child_by_type(node, "type_identifier")
            if tag is not None:
                names.append((_get_node_text(_last_segment(tag)), node))
            parent = node.parent
            if parent is not None and parent.type == "type_definition":
                for decl in parent.children_by_field_name("declarator"):
                    alias = _c_declarator_name(decl)
                    if alias is not None:
                        names.append((_get_node_text(alias), parent))
            members = cls._member_names(body)
            for struct_name, span in names:
                if not struct_name:
                    continue
                for member in members:
                    rows.append(
                        {
                            "name": struct_name,
                            "file": rel,
                            "start_line": span.start_point.row + 1,
                            "end_line": span.end_point.row + 1,
                            "member_name": member,
                        }
                    )
        return rows

    @staticmethod
    def _file_scope_declarations(root: tree_sitter.Node) -> Iterator[tree_sitter.Node]:
        """File-scope ``declaration`` nodes, including those nested in
        ``#if``/``#ifdef`` blocks, ``extern "C" {}`` and namespaces."""
        stack = list(reversed(root.children))
        while stack:
            node = stack.pop()
            if node.type == "declaration":
                yield node
            elif node.type in _C_SCOPE_CONTAINERS:
                stack.extend(reversed(node.children))

    @classmethod
    def _globals_in(cls, tree: tree_sitter.Tree, lang: str, rel: str) -> list[dict]:
        rows: list[dict] = []
        for node in cls._file_scope_declarations(tree.root_node):
            type_node = node.child_by_field_name("type")
            base_type = _get_node_text(type_node)
            qualifiers = [
                _get_node_text(c)
                for c in node.children
                if c.type in ("storage_class_specifier", "type_qualifier")
            ]
            for decl in node.children_by_field_name("declarator"):
                # Skip prototypes: `int f(int);` is a declaration, not a global.
                probe: tree_sitter.Node | None = decl
                is_function = False
                pointer_depth = 0
                while probe is not None and probe.type not in ("identifier",):
                    if probe.type == "function_declarator":
                        is_function = True
                        break
                    if probe.type == "pointer_declarator":
                        pointer_depth += 1
                    probe = probe.child_by_field_name("declarator")
                if is_function:
                    continue
                name_node = _c_declarator_name(decl)
                if name_node is None:
                    continue
                type_text = " ".join([*qualifiers, base_type]).strip()
                if pointer_depth:
                    type_text = f"{type_text} {'*' * pointer_depth}".strip()
                rows.append(
                    {
                        "name": _get_node_text(name_node),
                        "file": rel,
                        "start_line": node.start_point.row + 1,
                        "end_line": node.end_point.row + 1,
                        "type": type_text,
                    }
                )
        return rows

    @staticmethod
    def _macros_in(tree: tree_sitter.Tree, lang: str, rel: str) -> list[dict]:
        rows: list[dict] = []
        for node in _walk_tree(tree.root_node, "preproc_def", "preproc_function_def"):
            name_node = node.child_by_field_name("name") or _find_child_by_type(node, "identifier")
            if name_node is None:
                continue
            body_node = node.child_by_field_name("value") or _find_child_by_type(
                node, "preproc_arg"
            )
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

    @staticmethod
    def _resolve_callee_files(caller_rows: list[dict], func_rows: list[dict]) -> None:
        """Fill ``callee_file`` only when the callee name has ONE defining file.

        A bare name defined in several files cannot be bound to one definition
        without type resolution; guessing (the old last-definition-wins map)
        attached callers to the wrong homonym. ``""`` keeps such rows out of
        file-qualified lookups, which then fail closed.
        """
        files_by_name: dict[str, set[str]] = {}
        for row in func_rows:
            files_by_name.setdefault(row["name"], set()).add(row["file"])
        for row in caller_rows:
            files = files_by_name.get(row["callee_name"])
            row["callee_file"] = next(iter(files)) if files and len(files) == 1 else ""

    # ── Orchestration ────────────────────────────────────────────────

    def extract_for_repo(
        self,
        lang: str,
        repo_name: str,
        dry_run: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """Extract all context CSVs for a single repo.

        Each source file is parsed exactly once; every enabled extractor runs
        over that one tree.

        Returns:
            Dict mapping query name to (success, message).
        """
        repo_path = self.repos_dir / lang / repo_name
        context_dir = self.output_dir / lang / repo_name / "context"
        query_types = QUERIES_BY_LANG.get(lang, [])
        results: dict[str, tuple[bool, str]] = {}

        source_files = self._collect_source_files(lang, repo_path)

        if not source_files:
            for qt in query_types:
                results[qt] = (False, "No source files found")
            return results

        if dry_run:
            for qt in query_types:
                results[qt] = (True, f"[dry-run] would extract {qt}")
            return results

        per_tree = {
            "functions": self._functions_in,
            "callers": self._calls_in,
            "classes": self._classes_in,
            "structs": self._structs_in,
            "globals": self._globals_in,
            "macros": self._macros_in,
        }
        active = [qt for qt in query_types if qt in per_tree]
        rows_by_query: dict[str, list[dict]] = {qt: [] for qt in active}

        for fpath in source_files:
            tree = self._parse_file(self._parser_for(lang, fpath), fpath)
            if tree is None:
                continue
            rel = fpath.relative_to(repo_path).as_posix()
            for qt in active:
                rows_by_query[qt].extend(per_tree[qt](tree, lang, rel))

        if "callers" in rows_by_query:
            self._resolve_callee_files(rows_by_query["callers"], rows_by_query.get("functions", []))

        for qt in active:
            rows = rows_by_query[qt]
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
