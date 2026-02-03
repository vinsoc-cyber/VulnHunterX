# Python Version Policy

## Default Python Version
- **Default Python version is Python 3.12**
- When writing new code, use Python 3.12 as the target version
- Use Python 3.12 features and syntax when appropriate

## Compatibility Requirements
All tools must work correctly on the following Python versions:
- **Python 3.12** (default, required)
- **Python 3.13** (supported)

## Code Compatibility Guidelines

### When Writing Code
1. **Use Python 3.12+ features**
   - You can use features introduced in Python 3.12
   - Ensure compatibility with Python 3.13
   - If you must use newer features, provide fallbacks when necessary

2. **Use type hints compatible with target versions**
   - Use `from __future__ import annotations` for forward references when needed
   - Python 3.12+ typing features are available

3. **Test compatibility considerations**
   - When using new syntax or features, verify they work on Python 3.12 and 3.13
   - Use conditional imports or feature detection when necessary

4. **Dependency management**
   - Ensure all dependencies in `pyproject.toml` support Python 3.12-3.13
   - Set `requires-python = ">=3.12,<3.14"` in `pyproject.toml` files
   - `requirements.txt` files are auto-generated from `pyproject.toml` via `generate_requirements.py`
   - **Do NOT edit `requirements.txt` files directly** - they are auto-generated

### Common Compatibility Issues to Avoid
- **Pattern matching (match/case)**: Available from Python 3.10+, safe to use
- **Exception groups**: Python 3.11+ feature, safe to use
- **Self type**: Python 3.11+ feature, safe to use
- **Generic types**: PEP 585 generics (list[str]) are preferred over typing.List[str]

### Best Practices
- Prefer standard library features available in Python 3.12+
- Use `sys.version_info` checks only when absolutely necessary
- Document any version-specific behavior in code comments
- When in doubt, test the code on Python 3.12 (minimum supported version)

