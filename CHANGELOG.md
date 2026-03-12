# Changelog

All notable changes to VulnHunterX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CONTRIBUTING.md` with development workflow and PR guidelines
- `CHANGELOG.md` for tracking project changes
- `core/constants.py` centralizing all default values (models, timeouts, URLs)
- `core/validation.py` with input validation utilities (repo names, file paths, Ollama model normalization)
- Path traversal protection in `ContextProvider._read_lines()`
- Repository name validation in `RepositoryManager.clone_and_create_db()`
- Logging to 40+ previously silent `except Exception` blocks across the codebase
- XML-style tags wrapping code content in LLM prompts to mitigate prompt injection
- System prompt warning about untrusted code content

### Changed
- `build_sanitized.py`: replaced shell script generation with direct `subprocess.run(shell=True)` using `shlex.quote()` for path safety
- Hardcoded model names, timeouts, and URLs now reference `core/constants.py`
- Ollama model prefix logic (`ollama/` normalization) extracted to `core/validation.normalize_ollama_model()`

### Security
- Fixed shell injection risk in `fuzz/build_sanitized.py` (build commands from config)
- Added path traversal guards in `context/provider.py` using `Path.is_relative_to()`
- Added repository name validation to block `../` in path construction
- Hardened LLM prompts against injection via embedded code content
- Added Semgrep config validation to restrict to local paths and known registry rules

## [0.1.0] - 2025-01-01

### Added
- Initial release: 8-stage SAST + LLM verification pipeline
- CodeQL and Semgrep integration
- Multi-turn LLM verification with guided questions
- CSV-based context extraction (CodeQL and tree-sitter backends)
- Fuzz driver generation and execution (C/C++)
- CLI with subcommands: clone, analyze, extract-context, verify, build-sanitized, extract-fuzz-context, generate-fuzz-drivers, fuzz-run
- Support for C, C++, Python, JavaScript, PHP, Java
- LiteLLM-backed LLM client (OpenAI, Anthropic, Ollama)
