# Security

## Input Validation Requirements
- **URL validation**: Use `SecurityTargetValidator` for all target URLs
  - Validate scheme (http/https only)
  - Validate network location
  - Check for dangerous patterns (file://, javascript:, etc.)
  - Maximum URL length: 2048 characters
- **Usage**: Always validate user input before processing

## Subprocess Safety
- **Never use `shell=True`**: Always use list format for subprocess commands
- **Always use list format**: `subprocess.run(["command", "arg1", "arg2"])`
- **Validate command arguments**: Ensure no shell injection in arguments
- **Example**:
  ```python
  # ✅ Good
  subprocess.run(["sqlmap", "-u", url, "--batch"], timeout=60)
  
  # ❌ Bad
  subprocess.run(f"sqlmap -u {url} --batch", shell=True)
  ```

## Path Traversal Protection
- **Validate file paths**: Ensure file paths are within allowed directories
- **Use `Path.resolve()`**: Resolve paths to prevent `../` traversal attacks
- **Check path containment**: Verify resolved path is within allowed directory
- **Example**:
  ```python
  from pathlib import Path
  
  def validate_file_path(file_path: str, allowed_dir: Path) -> Path:
      file_path_obj = Path(file_path).resolve()
      allowed_dir_resolved = allowed_dir.resolve()
      file_path_obj.relative_to(allowed_dir_resolved)  # Raises if outside
      return file_path_obj
  ```

## Timeout Validation
- **Bounds checking**: Validate timeout values with MIN/MAX constants
- **Default timeouts**: Use reasonable defaults (e.g., 60 seconds)
- **Maximum timeout**: Cap timeouts to prevent resource exhaustion (e.g., 600 seconds)
- **Example**:
  ```python
  MIN_TIMEOUT = 10
  MAX_TIMEOUT = 600
  DEFAULT_TIMEOUT = 60
  
  def validate_timeout(timeout: int | None) -> int:
      if timeout is None:
          return DEFAULT_TIMEOUT
      return max(MIN_TIMEOUT, min(timeout, MAX_TIMEOUT))
  ```

## Output Sanitization
- **Remove sensitive data**: Sanitize tool output before logging or returning
- **Pattern redaction**: Remove passwords, tokens, API keys from output
- **Limit output size**: Truncate large outputs to prevent resource issues

## Credential Handling
- **Never store credentials/secrets in config or code**: All credentials and secrets must be loaded from environment variables only
- **Environment variables**: Store credentials in environment variables, never hardcode
- **No hardcoded secrets**: Never commit API keys, passwords, or tokens to code or configuration files
- **No secrets in config files**: Do not store secrets in configuration files (e.g., `config.py`, `settings.py`, `config.yaml`, etc.)
- **Use `.env` files**: Store sensitive configuration in `.env` files (excluded from git) for local development only
- **Examples of secrets to never hardcode**:
  - `OPENAI_API_KEY`
  - `LANGFUSE_SECRET_KEY`
  - Database passwords
  - API tokens
  - Private keys
  - Any authentication credentials
- **Best practice**: Load all secrets from environment variables using `os.getenv()` or similar methods
- **Example**:
  ```python
  # ✅ Good
  api_key = os.getenv("OPENAI_API_KEY")
  if not api_key:
      raise ValueError("OPENAI_API_KEY environment variable is required")
  
  # ❌ Bad
  OPENAI_API_KEY = "sk-..."  # Never hardcode
  config = {"api_key": "sk-..."}  # Never in config dicts
  ```

## Security Testing Authorization
- **Only test authorized systems**: Only scan systems you own or have explicit permission to test
- **Document authorization**: Ensure users understand authorization requirements
- **Safe defaults**: Bruteforce disabled by default, requires explicit flag

## Safe Defaults

