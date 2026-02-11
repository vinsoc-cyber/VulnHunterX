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


def _param_to_consumption(param_type: str, param_name: str, provider_var: str = "provider") -> str:
    """
    Heuristic: map param type to FuzzedDataProvider consumption.
    Returns C++ expression to produce a value for the parameter.
    """
    t = param_type.lower().strip()
    # Pointer + size patterns: prefer buffer then size
    if "char *" in param_type or "char*" in param_type or "char * const" in t:
        return f'fuzz_str_{param_name}.c_str()'  # caller must declare fuzz_str_* and consume
    if "const char *" in param_type or "const char*" in param_type:
        return f'fuzz_str_{param_name}.c_str()'
    if "unsigned char *" in t or "uint8_t *" in t or "void *" in t:
        # Buffer: need pointer + size; consume bytes and use data(), size()
        return f"reinterpret_cast<{param_type.strip()}>(const_cast<uint8_t*>({provider_var}.ConsumeRemainingBytes().data()))"
    if "size_t" in t or "size_t *" in t:
        if "*" in param_type:
            return "&fuzz_size"
        return f"{provider_var}.ConsumeIntegral<size_t>()"
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

    lines: list[str] = [
        "/* Fuzz harness generated for CodeQL finding */",
        "#include <cstdint>",
        "#include <cstdlib>",
        "#include <string>",
        "#include <fuzzer/FuzzedDataProvider.h>",
        "",
    ]

    for inc in includes:
        line = _include_line(inc)
        if line and line not in lines:
            lines.append(line)
    lines.append("")

    lines.extend([
        f"extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{",
        f"  if (size == 0) return 0;",
        f"  FuzzedDataProvider provider(data, size);",
        "",
    ])

    # Build argument expressions for the target call
    args_list: list[str] = []
    string_locals: list[str] = []  # param names that need a std::string local
    for i, p in enumerate(params):
        ptype = p.get("type", "int")
        pname = p.get("name", f"arg{i}")
        expr = _param_to_consumption(ptype, pname)
        if "fuzz_str_" in expr:
            string_locals.append(pname)
        args_list.append(expr)
    # Declare string locals so .c_str() is valid during the call
    for pname in string_locals:
        lines.append(f"  std::string fuzz_str_{pname} = provider.ConsumeBytesAsString(provider.ConsumeIntegralInRange(0u, static_cast<size_t>(size)));")
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


