# Contributing to VulnHunterX

Thank you for your interest in contributing! This guide covers the development workflow and expectations.

## Development Setup

```bash
# Clone and set up the environment
git clone https://github.com/vinsoc-cyber/VulnHunterX.git
cd VulnHunterX
uv venv --python python3.12 .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Code Style

- **Formatter/Linter**: [ruff](https://docs.astral.sh/ruff/) (line-length 100)
- **Type checker**: mypy (Python 3.12)
- Run before committing:

```bash
ruff check src/
ruff format src/
mypy src/
```

## Testing

```bash
pytest tests/                              # all tests
pytest tests/test_specific.py::test_name   # single test
```

Tests use pytest with coverage reporting. Aim for unit tests on new functions and integration tests on new pipeline stages.

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Keep PRs focused: one logical change per PR.
3. Include tests for new functionality.
4. Ensure `ruff check`, `ruff format`, `mypy`, and `pytest` all pass.
5. Write a clear PR description explaining **what** and **why**.

## Commit Messages

Use concise, imperative-mood messages:

```
feat: add XML escaping for LLM code context
fix: prevent path traversal in ContextProvider
refactor: centralize model defaults into constants.py
docs: add CONTRIBUTING.md
```

Prefix with: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

## Security

If you discover a security vulnerability, please report it privately via GitHub Security Advisories rather than opening a public issue.
