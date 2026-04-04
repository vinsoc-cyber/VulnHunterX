"""
Stage 7.3: Generate libFuzzer harness source (.cc) from target and context.

Uses template-based generation with two strategies:
- **Library/object targets**: standard extern linkage with forward declaration.
- **Static function targets**: source-inclusion (``#include "file.c"``) with
  ``#define main`` trick to avoid linker conflicts — inspired by Futag.

Type-aware generation:
- **Enums**: ``PickValueInArray`` with actual enum constants (from enums.csv).
- **Typedefs**: Resolved to underlying type before struct/enum lookup.
- **Buffer+size pairs**: Correlated so size derives from actual buffer length.
- **FILE***: ``fmemopen()`` with fuzzed content instead of nullptr.
- **Char arrays**: Filled with fuzzed data via ``ConsumeBytesAsString``.
"""

from __future__ import annotations

import re
from pathlib import Path

# Names that suggest a parameter is a buffer length
_SIZE_NAME_HINTS = frozenset({
    "len", "length", "size", "sz", "count", "n", "nbytes",
    "cb", "num", "buflen", "bufsize", "datalen", "datasize",
    "inlen", "outlen", "srclen", "dstlen",
})

# Max buffer size to avoid OOM in generated harnesses
_MAX_BUFFER_SIZE = 4096


def _include_line(inc_text: str) -> str:
    """Turn include_text from CSV (e.g. <foo.h> or \"bar.h\") into #include line."""
    s = (inc_text or "").strip()
    if not s:
        return ""
    if s.startswith("<") and s.endswith(">"):
        return f"#include {s}"
    if s.startswith('"') and s.endswith('"'):
        return f"#include {s}"
    return f'#include "{s}"'


def _resolve_type(base_type: str, typedef_map: dict[str, str], max_depth: int = 5) -> str:
    """Follow typedef chain to resolve the underlying type name.

    Strips ``enum``/``struct`` prefixes from the resolved type so it can be
    looked up in enum_defs/struct_defs maps.  Stops after *max_depth* hops
    or on a cycle.
    """
    seen: set[str] = set()
    current = base_type
    while current in typedef_map and max_depth > 0 and current not in seen:
        seen.add(current)
        underlying = typedef_map[current]
        current = underlying.replace("enum ", "").replace("struct ", "").strip()
        max_depth -= 1
    return current


def _enum_consumption(
    enum_name: str,
    enum_values: list[dict[str, str]],
    provider_var: str = "provider",
) -> str:
    """Generate a ``PickValueInArray`` expression for an enum type."""
    member_names = [e.get("member", "") for e in enum_values if e.get("member")]
    if not member_names:
        return f"{provider_var}.ConsumeIntegral<uint32_t>()"
    if len(member_names) == 1:
        return f"({enum_name})({member_names[0]})"
    int_values = ", ".join(f"(int){m}" for m in member_names)
    return f"({enum_name})({provider_var}.PickValueInArray({{{int_values}}}))"


def _member_consumption(
    member_type: str,
    provider_var: str = "provider",
    enum_defs: dict[str, list[dict[str, str]]] | None = None,
    typedef_map: dict[str, str] | None = None,
) -> str:
    """Map a struct member's actual type to the correct FuzzedDataProvider call."""
    t = member_type.lower().strip()

    # Check enum via typedef resolution
    if enum_defs or typedef_map:
        base = member_type.replace("enum ", "").replace("const ", "").strip()
        if typedef_map:
            base = _resolve_type(base, typedef_map)
        if enum_defs and base in enum_defs and enum_defs[base]:
            return _enum_consumption(member_type.strip(), enum_defs[base], provider_var)

    if "char *" in t or "char*" in t:
        return "nullptr"
    if "float" in t:
        return f"{provider_var}.ConsumeFloatingPoint<float>()"
    if "double" in t:
        return f"{provider_var}.ConsumeFloatingPoint<double>()"
    if "bool" in t:
        return f"{provider_var}.ConsumeBool()"
    if "uint8_t" in t or "unsigned char" in t:
        return f"{provider_var}.ConsumeIntegral<uint8_t>()"
    if "uint16_t" in t or "unsigned short" in t:
        return f"{provider_var}.ConsumeIntegral<uint16_t>()"
    if "uint64_t" in t or "unsigned long long" in t:
        return f"{provider_var}.ConsumeIntegral<uint64_t>()"
    if "int64_t" in t or "long long" in t:
        return f"{provider_var}.ConsumeIntegral<int64_t>()"
    if "uint32_t" in t or "unsigned int" in t or "unsigned" in t:
        return f"{provider_var}.ConsumeIntegral<uint32_t>()"
    if "int32_t" in t or t == "int":
        return f"{provider_var}.ConsumeIntegral<int32_t>()"
    if "int16_t" in t or "short" in t:
        return f"{provider_var}.ConsumeIntegral<int16_t>()"
    if "size_t" in t:
        return f"{provider_var}.ConsumeIntegral<size_t>()"
    if "long" in t:
        return f"{provider_var}.ConsumeIntegral<long>()"
    if "int" in t:
        return f"{provider_var}.ConsumeIntegral<int>()"
    if "*" in member_type:
        return "nullptr"
    return f"{provider_var}.ConsumeIntegral<uint32_t>()"


def _is_complex_type(member_type: str) -> bool:
    """Return True for types that cannot be assigned from a FuzzedDataProvider scalar."""
    t = member_type.strip()
    t_lower = t.lower()
    if "[" in t:
        return True
    if ("struct " in t_lower or "union " in t_lower) and "*" not in t:
        return True
    return bool("(*" in t or "(* " in t)


def _parse_char_array(member_type: str) -> int | None:
    """Parse ``char [N]`` or ``char[N]`` and return N, or None if not a char array."""
    m = re.match(r"(?:const\s+)?char\s*\[\s*(\d+)\s*\]", member_type.strip())
    return int(m.group(1)) if m else None


def _generate_struct_init(
    struct_name: str,
    members: list[dict[str, str]] | list[str],
    var_name: str,
    enum_defs: dict[str, list[dict[str, str]]] | None = None,
    typedef_map: dict[str, str] | None = None,
) -> list[str]:
    """Generate zero-init + type-aware member population for a struct local variable."""
    lines = [
        f"  {struct_name} {var_name};",
        f"  memset(&{var_name}, 0, sizeof({var_name}));",
    ]
    for member in members:
        if isinstance(member, dict):
            mname = member.get("name", "")
            mtype = member.get("type", "uint32_t")
            if not mname:
                continue
            # Char array: fill with fuzzed data
            arr_size = _parse_char_array(mtype)
            if arr_size is not None and arr_size > 0:
                safe_size = arr_size - 1
                lines.append("  {")
                lines.append(f"    auto _tmp_{mname} = provider.ConsumeBytesAsString({safe_size});")
                lines.append(f"    memcpy({var_name}.{mname}, _tmp_{mname}.c_str(), _tmp_{mname}.size());")
                lines.append("  }")
                continue
            # Skip other complex types
            if _is_complex_type(mtype):
                continue
            consumption = _member_consumption(mtype, enum_defs=enum_defs, typedef_map=typedef_map)
        else:
            mname = member
            consumption = "provider.ConsumeIntegral<uint32_t>()"
        if mname and consumption != "nullptr":
            lines.append(f"  {var_name}.{mname} = {consumption};")
    return lines


def _param_to_consumption(
    param_type: str,
    param_name: str,
    provider_var: str = "provider",
    enum_defs: dict[str, list[dict[str, str]]] | None = None,
    typedef_map: dict[str, str] | None = None,
) -> str:
    """Map param type to FuzzedDataProvider consumption expression."""
    t = param_type.lower().strip()

    # Check enum via typedef resolution
    if enum_defs or typedef_map:
        base = _get_base_type(param_type)
        if typedef_map:
            base = _resolve_type(base, typedef_map)
        if enum_defs and base in enum_defs and enum_defs[base]:
            return _enum_consumption(base, enum_defs[base], provider_var)

    if "char *" in param_type or "char*" in param_type or "char * const" in t:
        return f"fuzz_str_{param_name}.c_str()"
    if "const char *" in param_type or "const char*" in param_type:
        return f"fuzz_str_{param_name}.c_str()"
    if "unsigned char *" in t or "uint8_t *" in t or "void *" in t:
        return f"fuzz_buf_{param_name}.data()"
    if "file *" in t or "file*" in t:
        return f"fuzz_fp_{param_name}"
    if "size_t" in t or "size_t *" in t:
        if "*" in param_type:
            return "&fuzz_size"
        return f"{provider_var}.ConsumeIntegral<size_t>()"
    if "float" in t and "*" not in param_type:
        return f"{provider_var}.ConsumeFloatingPoint<float>()"
    if "double" in t and "*" not in param_type:
        return f"{provider_var}.ConsumeFloatingPoint<double>()"
    if "int" in t and "*" not in param_type:
        return f"{provider_var}.ConsumeIntegral<int>()"
    if "long" in t:
        return f"{provider_var}.ConsumeIntegral<long>()"
    if "bool" in t:
        return f"{provider_var}.ConsumeBool()"
    if "*" in param_type:
        return "nullptr"
    return f"{provider_var}.ConsumeIntegral<uint32_t>()"


def _get_base_type(param_type: str) -> str:
    """Strip qualifiers to get base struct/class name."""
    return param_type.replace("const", "").replace("struct", "").replace("enum", "").replace("*", "").strip()


def _is_buffer_type(ptype: str) -> bool:
    """Check if type is a buffer pointer (char*, uint8_t*, void*, unsigned char*)."""
    t = ptype.lower()
    return any(tok in t for tok in ("char *", "uint8_t *", "void *", "unsigned char *"))


def _is_size_type(ptype: str) -> bool:
    """Check if type is a size parameter (size_t, not pointer)."""
    return "size_t" in ptype.lower() and "*" not in ptype


def _detect_buffer_size_pairs(params: list[dict]) -> dict[int, int]:
    """Detect (buffer, size) parameter pairs and return mapping buffer_idx -> size_idx.

    Heuristics:
    1. A size_t param immediately following a buffer pointer.
    2. A size_t param whose name suggests it's a length for a nearby buffer.
    """
    pairs: dict[int, int] = {}
    buffer_indices: list[int] = []

    for i, p in enumerate(params):
        ptype = p.get("type", "")
        if _is_buffer_type(ptype):
            buffer_indices.append(i)

    for buf_idx in buffer_indices:
        # Check the next param first (adjacent pattern)
        for offset in (1, 2):
            size_idx = buf_idx + offset
            if size_idx >= len(params):
                continue
            sp = params[size_idx]
            if _is_size_type(sp.get("type", "")) and size_idx not in pairs.values():
                pairs[buf_idx] = size_idx
                break
        if buf_idx in pairs:
            continue
        # Check by name heuristic
        for j, sp in enumerate(params):
            if j == buf_idx or j in pairs.values():
                continue
            if _is_size_type(sp.get("type", "")):
                sname = sp.get("name", "").lower()
                if sname in _SIZE_NAME_HINTS:
                    pairs[buf_idx] = j
                    break

    return pairs


def _build_extern_declaration(name: str, params: list[dict]) -> str:
    """Build an ``extern "C"`` forward declaration for a target function."""
    param_parts = []
    for p in params:
        ptype = p.get("type", "int")
        pname = p.get("name", "")
        param_parts.append(f"{ptype} {pname}".strip())
    params_str = ", ".join(param_parts) if param_parts else "void"
    return f'extern "C" void {name}({params_str});'


def generate_harness(
    finding_rule_id: str,
    finding_file: str,
    finding_line: int,
    target_context: dict,
    output_path: Path,
    repo_name: str,
    linkability: str = "unknown",
    source_root: str = "",
    file_has_main: bool = False,
) -> Path:
    """Generate one libFuzzer harness .cc file.

    target_context keys: name, file, params, includes, struct_defs, enum_defs, typedef_map.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    name = target_context.get("name", "target")
    params = target_context.get("params", [])
    includes = target_context.get("includes", [])
    struct_defs: dict[str, list] = target_context.get("struct_defs", {})
    enum_defs: dict[str, list[dict[str, str]]] = target_context.get("enum_defs", {})
    typedef_map: dict[str, str] = target_context.get("typedef_map", {})
    target_file = target_context.get("file", "")

    is_static_target = linkability == "static"

    # C++ standard headers first (before any project headers or #define workarounds)
    lines: list[str] = [
        "/* Fuzz harness generated for CodeQL finding */",
        "#include <cstdint>",
        "#include <cstdlib>",
        "#include <cstring>",
        "#include <cmath>",
        "#include <cstdio>",
        "#include <cerrno>",
        "#include <string>",
        "#include <vector>",
        "#include <fuzzer/FuzzedDataProvider.h>",
        "",
    ]

    if is_static_target and target_file:
        if file_has_main:
            lines.append("/* Stub out main() to avoid linker conflict */")
            lines.append("#define main __original_main_disabled")
            lines.append("")
        if source_root and target_file.startswith("/"):
            inc_path = target_file
        elif source_root:
            inc_path = str(Path(source_root) / target_file)
        else:
            inc_path = target_file
        lines.append(f'/* Include source to access static function "{name}" */')
        lines.append(f'#include "{inc_path}"')
        if file_has_main:
            lines.append("#undef main")
        lines.append("")
    else:
        for inc in includes:
            line = _include_line(inc)
            if line and line not in lines:
                lines.append(line)
        lines.append("")
        if linkability in ("library_exported", "object_global") and params:
            lines.append("/* Forward declaration for target function */")
            lines.append(_build_extern_declaration(name, params))
            lines.append("")

    lines.extend([
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {',
        "  if (size == 0) return 0;",
        "  FuzzedDataProvider provider(data, size);",
        "",
    ])

    # Detect buffer+size pairs for correlated generation
    buf_size_pairs = _detect_buffer_size_pairs(params)
    paired_size_indices = set(buf_size_pairs.values())

    # Pre-call setup lines and post-call cleanup lines
    setup_lines: list[str] = []
    cleanup_lines: list[str] = []
    args_list: list[str] = []
    string_locals: list[str] = []
    struct_init_lines: list[str] = []
    struct_vars: dict[str, str] = {}
    buffer_vars: dict[int, str] = {}  # buf_idx -> var_name

    for i, p in enumerate(params):
        ptype = p.get("type", "int")
        pname = p.get("name", f"arg{i}")
        base_type = _get_base_type(ptype)

        # Resolve typedef before struct/enum lookup
        resolved_base = _resolve_type(base_type, typedef_map) if typedef_map else base_type

        # Check struct
        lookup_base = resolved_base if resolved_base in struct_defs else base_type
        if lookup_base in struct_defs:
            var_name = f"fuzz_struct_{lookup_base}"
            if lookup_base not in struct_vars:
                struct_vars[lookup_base] = var_name
                struct_init_lines.extend(
                    _generate_struct_init(
                        lookup_base, struct_defs[lookup_base], var_name,
                        enum_defs=enum_defs, typedef_map=typedef_map,
                    )
                )
            expr = f"&{var_name}" if "*" in ptype else var_name
            args_list.append(expr)
            continue

        # Buffer+size correlated pair
        if i in buf_size_pairs:
            buf_var = f"fuzz_buf_{pname}"
            buffer_vars[i] = buf_var
            setup_lines.append(
                f"  auto {buf_var} = provider.ConsumeBytes<uint8_t>("
                f"provider.ConsumeIntegralInRange<size_t>(0, {_MAX_BUFFER_SIZE}));"
            )
            cast_type = ptype.strip()
            args_list.append(
                f"reinterpret_cast<{cast_type}>(const_cast<uint8_t*>({buf_var}.data()))"
                if "const" not in ptype.lower()
                else f"reinterpret_cast<{cast_type}>({buf_var}.data())"
            )
            continue

        # Paired size param — use the correlated buffer's .size()
        if i in paired_size_indices:
            buf_idx = next(bi for bi, si in buf_size_pairs.items() if si == i)
            buf_pname = params[buf_idx].get("name", f"arg{buf_idx}")
            buf_var = f"fuzz_buf_{buf_pname}"
            if "*" in ptype:
                setup_lines.append(f"  size_t fuzz_corr_size_{pname} = {buf_var}.size();")
                args_list.append(f"&fuzz_corr_size_{pname}")
            else:
                args_list.append(f"static_cast<{ptype.strip()}>({buf_var}.size())")
            continue

        # FILE* via fmemopen
        if "file *" in ptype.lower() or "file*" in ptype.lower():
            fp_var = f"fuzz_fp_{pname}"
            data_var = f"fuzz_fpdata_{pname}"
            setup_lines.append(f"  auto {data_var} = provider.ConsumeRandomLengthString({_MAX_BUFFER_SIZE});")
            setup_lines.append(f'  FILE *{fp_var} = fmemopen((void*){data_var}.data(), {data_var}.size(), "rb");')
            cleanup_lines.append(f"  if ({fp_var}) fclose({fp_var});")
            args_list.append(fp_var)
            continue

        # Standard type dispatch
        expr = _param_to_consumption(ptype, pname, enum_defs=enum_defs, typedef_map=typedef_map)
        if "fuzz_str_" in expr:
            string_locals.append(pname)
        elif "fuzz_buf_" in expr:
            # Non-paired buffer: bounded consumption (not ConsumeRemainingBytes)
            buf_var = f"fuzz_buf_{pname}"
            setup_lines.append(
                f"  auto {buf_var} = provider.ConsumeBytes<uint8_t>("
                f"provider.ConsumeIntegralInRange<size_t>(0, {_MAX_BUFFER_SIZE}));"
            )
            cast_type = ptype.strip()
            expr = f"reinterpret_cast<{cast_type}>({buf_var}.data())"
        args_list.append(expr)

    # Emit struct inits first (fixed-size consumption)
    lines.extend(struct_init_lines)

    # Emit setup lines (buffer allocations, FILE* creation)
    lines.extend(setup_lines)

    # Declare string locals with bounded size
    for pname in string_locals:
        lines.append(
            f"  std::string fuzz_str_{pname} = provider.ConsumeRandomLengthString(256);"
        )

    # Declare fuzz_size if needed
    if "&fuzz_size" in " ".join(args_list):
        lines.append("  size_t fuzz_size = provider.ConsumeIntegral<size_t>();")

    # Function call
    args_str = ", ".join(args_list)
    lines.append(f"  {name}({args_str});")

    # Cleanup (FILE* fclose, etc.)
    if cleanup_lines:
        lines.append("")
        lines.extend(cleanup_lines)

    lines.append("  return 0;")
    lines.append("}")
    lines.append("")

    text = "\n".join(lines)
    output_path.write_text(text, encoding="utf-8")
    return output_path
