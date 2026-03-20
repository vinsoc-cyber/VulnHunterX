"""
Stage 7.3: Generate libFuzzer harness source (.cc) from target and context.

Uses template-based generation; optional LLM can be added later.
"""

from __future__ import annotations

from pathlib import Path


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


def _member_consumption(member_type: str, provider_var: str = "provider") -> str:
    """Map a struct member's actual type to the correct FuzzedDataProvider call."""
    t = member_type.lower().strip()
    if "char *" in t or "char*" in t:
        # String member — can't easily fuzz a pointer member, use nullptr
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
    # Default fallback
    return f"{provider_var}.ConsumeIntegral<uint32_t>()"


def _is_complex_type(member_type: str) -> bool:
    """Return True for types that cannot be assigned from a FuzzedDataProvider scalar.

    Complex types include arrays, structs/unions by value, and function pointers.
    These are left zero-initialized from memset instead.
    """
    t = member_type.strip()
    t_lower = t.lower()
    # Arrays: int[256], char[64], ogg_int64_t[2], etc.
    if "[" in t:
        return True
    # Struct/union by value (not pointer)
    if ("struct " in t_lower or "union " in t_lower) and "*" not in t:
        return True
    # Function pointers: long **(*class)(...)
    return bool("(*" in t or "(* " in t)


def _generate_struct_init(
    struct_name: str,
    members: list[dict[str, str]] | list[str],
    var_name: str,
) -> list[str]:
    """Generate zero-init + type-aware member population for a struct local variable.

    *members* may be a list of dicts ``{"name": ..., "type": ...}`` (new format)
    or a plain list of member name strings (legacy format, defaults to uint32_t).

    Complex members (arrays, nested structs, function pointers) are left
    zero-initialized from memset rather than generating broken assignment code.
    """
    lines = [
        f"  {struct_name} {var_name};",
        f"  memset(&{var_name}, 0, sizeof({var_name}));",
    ]
    for member in members:
        if isinstance(member, dict):
            mname = member.get("name", "")
            mtype = member.get("type", "uint32_t")
            # Skip types that can't be assigned from a scalar
            if _is_complex_type(mtype):
                continue  # leave zero-initialized from memset
            consumption = _member_consumption(mtype)
        else:
            mname = member
            consumption = "provider.ConsumeIntegral<uint32_t>()"
        # Skip nullptr assignments — memset already zeroed the member
        if mname and consumption != "nullptr":
            lines.append(f"  {var_name}.{mname} = {consumption};")
    return lines


def _param_to_consumption(param_type: str, param_name: str, provider_var: str = "provider") -> str:
    """
    Heuristic: map param type to FuzzedDataProvider consumption.
    Returns C++ expression to produce a value for the parameter.
    """
    t = param_type.lower().strip()
    # Pointer + size patterns: prefer buffer then size
    if "char *" in param_type or "char*" in param_type or "char * const" in t:
        return f"fuzz_str_{param_name}.c_str()"  # caller must declare fuzz_str_* and consume
    if "const char *" in param_type or "const char*" in param_type:
        return f"fuzz_str_{param_name}.c_str()"
    if "unsigned char *" in t or "uint8_t *" in t or "void *" in t:
        # Buffer: need pointer + size; consume bytes and use data(), size()
        return f"reinterpret_cast<{param_type.strip()}>(const_cast<uint8_t*>({provider_var}.ConsumeRemainingBytes().data()))"
    if "file *" in t or "file*" in t:
        # Avoid tmpfile() here to prevent missing includes and FILE* lifetime issues.
        # Many APIs tolerate a nullptr FILE*; this is safer for generated harnesses.
        return "nullptr"
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
    # Default: try integral, else pass 0/null
    if "*" in param_type:
        return "nullptr"
    return f"{provider_var}.ConsumeIntegral<uint32_t>()"


def _get_base_type(param_type: str) -> str:
    """Strip qualifiers to get base struct/class name."""
    return param_type.replace("const", "").replace("struct", "").replace("*", "").strip()


def generate_harness(
    finding_rule_id: str,
    finding_file: str,
    finding_line: int,
    target_context: dict,
    output_path: Path,
    repo_name: str,
) -> Path:
    """
    Generate one libFuzzer harness .cc file.

    target_context: from get_target_context (name, file, params, includes).
    Writes output_path and returns it.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    name = target_context.get("name", "target")
    params = target_context.get("params", [])
    includes = target_context.get("includes", [])
    struct_defs: dict[str, list[str]] = target_context.get("struct_defs", {})

    # C++ standard headers MUST come first — before the #define class klass
    # workaround. This ensures C++ STL templates that use 'class' keyword are
    # fully processed. We also pre-include <cmath>/<cstdio>/<cerrno> so that
    # when project C headers transitively include <math.h> etc., the include
    # guards prevent re-processing inside the #define scope.
    lines: list[str] = [
        "/* Fuzz harness generated for CodeQL finding */",
        "#include <cstdint>",
        "#include <cstdlib>",
        "#include <cstring>",
        "#include <cmath>",
        "#include <cstdio>",
        "#include <cerrno>",
        "#include <string>",
        "#include <fuzzer/FuzzedDataProvider.h>",
        "",
    ]

    # Wrap project includes with #define class klass + extern "C".
    # Some C libraries use 'class' as an identifier (e.g. vorbis backends.h
    # line 94: long **(*class)(...)). The scoped #define renames it only for
    # project headers; C++ STL is already included above so won't be affected.
    project_includes: list[str] = []
    for inc in includes:
        line = _include_line(inc)
        if line and line not in lines:
            project_includes.append(line)
    if project_includes:
        lines.append("#define class klass")
        lines.append('extern "C" {')
        lines.extend(project_includes)
        lines.append("}")
        lines.append("#undef class")
    lines.append("")

    lines.extend(
        [
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {',
            "  if (size == 0) return 0;",
            "  FuzzedDataProvider provider(data, size);",
            "",
        ]
    )

    # Build argument expressions for the target call
    args_list: list[str] = []
    string_locals: list[str] = []  # param names that need a std::string local
    struct_init_lines: list[str] = []  # struct init blocks to emit before the call
    struct_vars: dict[str, str] = {}  # base_type -> var_name

    for i, p in enumerate(params):
        ptype = p.get("type", "int")
        pname = p.get("name", f"arg{i}")
        base_type = _get_base_type(ptype)

        if base_type in struct_defs:
            # Struct-aware: generate init block and pass by pointer or value
            var_name = f"fuzz_struct_{base_type}"
            if base_type not in struct_vars:
                struct_vars[base_type] = var_name
                struct_init_lines.extend(
                    _generate_struct_init(base_type, struct_defs[base_type], var_name)
                )
            expr = f"&{var_name}" if "*" in ptype else var_name
        else:
            expr = _param_to_consumption(ptype, pname)
            if "fuzz_str_" in expr:
                string_locals.append(pname)
        args_list.append(expr)

    # Emit struct inits
    lines.extend(struct_init_lines)
    # Declare string locals so .c_str() is valid during the call
    for pname in string_locals:
        lines.append(
            f"  std::string fuzz_str_{pname} = provider.ConsumeBytesAsString(provider.ConsumeIntegralInRange<size_t>(0, size));"
        )
    if "&fuzz_size" in " ".join(args_list):
        lines.append("  size_t fuzz_size = provider.ConsumeIntegral<size_t>();")
    args_str = ", ".join(args_list)
    lines.append(f"  {name}({args_str});")
    lines.append("  return 0;")
    lines.append("}")
    lines.append("")

    text = "\n".join(lines)
    output_path.write_text(text, encoding="utf-8")
    return output_path
