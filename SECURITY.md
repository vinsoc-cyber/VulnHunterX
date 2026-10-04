# VulnHunterX security policy

VulnHunterX processes potentially sensitive source code and invokes external analyzers, target build systems, and configured LLM providers. Report vulnerabilities privately through the repository's GitHub Security Advisories workflow, as described in [CONTRIBUTING.md](CONTRIBUTING.md). If private reporting is unavailable, contact the maintainers privately; do not publish credentials or private source in a public issue.

## Security scope

Security issues include repository path traversal or symlink escapes, cross-repository evidence leakage, prompt injection that causes privileged actions, unsafe build-command execution, provider credential exposure, unauthorized source transmission, and sensitive data leakage through reports or conversation logs.

Use a minimal reproduction with synthetic source, redacted configuration, the affected version, and expected versus observed behavior. Omit API keys, `.env` files, private target code, and complete sensitive conversations.

## Contributor requirements

Follow [AGENTS.md](AGENTS.md), [security rules](docs/SECURITY_RULES.md), and [code standards](docs/CODE_STANDARDS.md). Changes to source access, subprocess execution, provider routing, evidence interpretation, or persistence should explain the changed boundary and include relevant regression coverage.

The repository documents a CLI and Python library. This policy does not claim a hardened execution sandbox, web authentication system, compliance certification, or implemented retention service. Operators must choose target build isolation, provider permissions, and artifact handling appropriate to their environment.
