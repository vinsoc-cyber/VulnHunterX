# Coding Conventions

## Python Style Guide
- **PEP 8 compliance**: Follow PEP 8 style guidelines for Python code
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters (preferred) or 120 characters (acceptable)
- Use meaningful variable and function names
- Follow naming conventions: `snake_case` for functions/variables, `PascalCase` for classes

## Type Hints
- **Required**: Use type hints for all function signatures and class attributes
- Use `from __future__ import annotations` at the top of files for forward references
- Prefer PEP 585 generics: `list[str]` over `typing.List[str]`
- Use `Optional[Type]` or `Type | None` for nullable types
- Examples:
  ```python
  from __future__ import annotations
  
  def process_urls(urls: list[str]) -> dict[str, int]:
      """Process a list of URLs."""
      return {"count": len(urls)}
  ```

## Async/Await Patterns
- Use `asyncio` for asynchronous operations, especially MCP communication
- Use `async def` for async functions, `await` for async calls
- Prefer `asyncio.create_subprocess_exec()` over `subprocess.run()` for async subprocess calls
- Handle async context managers properly with `async with`

## Dataclass Usage
- Use `@dataclass(frozen=True)` for immutable configuration objects
- Use dataclasses for structured data instead of dictionaries when possible
- Examples:
  ```python
  from dataclasses import dataclass
  
  @dataclass(frozen=True)
  class RunConfig:
      target_url: str
      mode: str
      reasoner: str
  ```

## Import Organization
- Organize imports in this order:
  1. Standard library imports
  2. Third-party imports
  3. Local application imports
- Use absolute imports when possible
- Group imports with blank lines between groups
- Example:
  ```python
  import asyncio
  from pathlib import Path
  from typing import Any
  
  from mcp.server import Server
  from mcp.types import Tool
  
  from core.utils import validate_url
  ```

## Docstring Conventions
- **Use Google-style docstrings** for all functions, classes, and modules
- Include: description, Args, Returns, Raises (if applicable)
- Example:
  ```python
  def validate_target_url(url: str) -> tuple[bool, str]:
      """Validate target URL for security testing.
      
      Args:
          url: The URL to validate.
      
      Returns:
          A tuple of (is_valid, error_message). If valid, error_message is empty.
      
      Raises:
          ValueError: If URL format is invalid.
      """
  ```

## Error Handling
- Use structured error returns from MCP tools (dictionaries with error keys)
- Use custom exception types in `core/` directories for domain-specific errors
- Always handle exceptions explicitly; avoid bare `except:` clauses
- Return error information in a consistent format:
  ```python
  return {"error": "Description", "server": "server_name", "tool": "tool_name"}
  ```

## Code Organization
- Follow the modular MCP server structure:
  - `server.py` - MCP server entry point, tool registration
  - `core/` - Core utilities, error types, validation
  - `lib/` - Shared libraries (payloads, outputs, wordlists)
  - `tools/` - Individual tool implementations
- Keep related functionality together
- Separate concerns: one module per responsibility

## File Size Limits
- **Maximum file size**: Python files (`.py`) must not exceed 1000 lines
- **Rationale**: Large files are harder to maintain, test, and understand
- **When a file exceeds the limit**:
  - Refactor by splitting into smaller modules
  - Extract classes/functions to separate files in appropriate directories (core/, lib/, tools/)
  - Use the existing modular architecture patterns
- **Examples**:
  - ✅ Good: Multiple focused files under 1000 lines each
  - ❌ Bad: Single file with 1010+ lines (must be refactored)
- **Current violations**: `mcp-servers/webrecon-mcp/tools/crawlers/zap_crawler.py` (1010 lines) needs refactoring

