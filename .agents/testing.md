# Testing

## Test File Organization
- Test files are located in `tests/` directory
- Naming convention: `test_*.py` (e.g., `test_all_modules.py`, `test_module_name.py`)

## Test Execution
- **Individual server tests**: Run specific server tests
  - `python tests/test_module_name.py`
  - `python tests/test_module_name.py --target repository_name`
- **Full suite**: Test all servers at once
  - `python tests/test_all_modules.py`
  - `python tests/test_all_modules.py --verbose`
- **Makefile commands**: Use Makefile for convenience
  - `make test-all` - Test all modules
  - `make test-module-name` - Test module-name

## Test Target Requirements
- **Safe defaults**: Tests should work without external targets
- **External targets optional**: Tests can accept custom targets via command-line arguments
- Example: `python tests/test_module_name.py repository_name`
- Tests should gracefully handle missing external tools

## Test Coverage Expectations
- Document current test coverage state
- Aim for improvement over time
- Focus on critical paths: tool execution, error handling, integration points
- Reference: `test/test_all_modules.py` for comprehensive test patterns

