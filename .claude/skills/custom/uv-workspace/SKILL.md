---
name: uv-workspace
description: Guide for managing the mcp-offsec uv workspace -- adding members, declaring workspace dependencies, syncing, running, building Docker images, and CI. Use when initializing new servers, adding dependencies, running workspace commands, or troubleshooting uv workspace issues.
---

# uv Workspace for mcp-offsec

This project uses a **uv workspace** monorepo. Each MCP server is an independent packaged application; shared libraries live under `libs/`. All members share one lockfile (`uv.lock`).

## Workspace Layout

```
mcp-offsec/                         # workspace root
├── pyproject.toml                  # members = ["servers/*", "libs/*"]
├── uv.lock                        # single lockfile for all members
├── servers/
│   ├── recon-<layer>/              # recon servers (--package)
│   │   ├── pyproject.toml
│   │   └── src/<pkg_name>/
│   └── exploit-<vuln>/             # exploit servers (--package)
│       ├── pyproject.toml
│       └── src/<pkg_name>/
└── libs/
    └── offsec-<purpose>/           # shared libraries (--lib)
        ├── pyproject.toml
        └── src/<pkg_name>/
```

Naming: `recon-*` for recon, `exploit-*` for attack, `offsec-*` for libs. Directories use hyphens; Python packages use underscores.

## Adding a New Server

```bash
# From workspace root:
uv init --package --name mcp-<name> servers/<name>
# uv auto-adds it to [tool.uv.workspace] members
```

This creates a `src/` layout with `[project.scripts]` entry point and `[build-system]`.

## Adding a New Library

```bash
# From workspace root:
uv init --lib --name <name> libs/<name>
# auto-discovered via libs/* glob in workspace members
```

Creates a `src/` layout with `py.typed` marker, suitable for importing from other members.

## Declaring a Workspace Dependency

To depend on a library from a server, use `uv add`:

```bash
cd servers/<server-name>
uv add <lib-name> --editable
```

This adds to the server's `pyproject.toml`:

```toml
[project]
dependencies = ["<lib-name>"]

[tool.uv.sources]
<lib-name> = { workspace = true }
```

All workspace member dependencies are editable by default.

## Adding External Dependencies

```bash
# Add to a specific member (from its directory)
cd servers/<server-name>
uv add "httpx>=0.27,<1.0"

# Or from root, targeting a member by package name
uv add --package <package-name> "httpx>=0.27,<1.0"

# Dev dependencies (for the root or a member)
uv add --dev pytest
```

Pin major versions, allow minor updates per project rules: `>=X.Y,<X+1.0`.

## Sync and Run

```bash
# Sync all members (install everything)
uv sync --all-packages

# Sync root only (default)
uv sync

# Sync a specific member
uv sync --package <package-name>

# Run a server entry point
uv run <entry-point>

# Run a command in a specific member's context
uv run --package <package-name> python -m <python_package>

# Run pytest for one member
uv run --package <package-name> pytest
```

## Lockfile

The workspace has a **single** `uv.lock` at the root. Commit it to git.

```bash
# Lock (resolve all members)
uv lock

# Check lockfile is up to date
uv lock --check

# Install from lockfile exactly (CI)
uv sync --frozen --all-packages

# Upgrade a specific dependency
uv lock --upgrade-package httpx
```

## Docker (Per-Server Image)

Each server has its own `Dockerfile`. Build context is the **repo root** so `COPY libs/` works.

```dockerfile
# servers/<server-name>/Dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY libs/ libs/
COPY servers/<server-name>/ servers/<server-name>/
RUN uv sync --frozen --package <package-name> --no-dev --no-editable

FROM python:3.12-slim-bookworm
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
CMD ["<entry-point>"]
```

Build from repo root:

```bash
docker build -f servers/<server-name>/Dockerfile -t <image-name> .
```

Key points:
- Copy `libs/` (all shared libraries) + the target server only (not other servers)
- Use `--frozen` to respect lockfile
- Use `--no-editable` for Docker (installs as regular packages)
- Multi-stage: builder installs, runtime only has `.venv`

## CI (GitHub Actions)

```yaml
- uses: astral-sh/setup-uv@v2
  with:
    enable-cache: true

- run: uv sync --frozen --all-packages
- run: uv run --package <package-name> pytest
```

## Key Commands Reference

| Task | Command |
|------|---------|
| Add server member | `uv init --package --name mcp-<n> servers/<n>` |
| Add library member | `uv init --lib --name <n> libs/<n>` |
| Add workspace dep | `uv add <lib-name> --editable` (from member dir) |
| Add external dep | `uv add "pkg>=X.Y,<X+1.0"` |
| Sync all | `uv sync --all-packages` |
| Sync one member | `uv sync --package <name>` |
| Run entry point | `uv run <script-name>` |
| Lock | `uv lock` |
| CI install | `uv sync --frozen --all-packages` |
| Build Docker | `docker build -f servers/<n>/Dockerfile -t <img> .` |

## Troubleshooting

- **"No such command" after sync**: Use `uv sync --all-packages` (default sync only installs root deps).
- **Import errors for libs**: Ensure the server's `pyproject.toml` has the lib in `dependencies` and `{ workspace = true }` in `[tool.uv.sources]`.
- **Lockfile drift**: Run `uv lock --check` in CI to catch it early.
- **Docker COPY fails**: Build context must be repo root (`docker build -f servers/.../Dockerfile .`).
- **New lib not discovered**: Libs under `libs/` are auto-discovered via the `libs/*` glob. Run `uv sync` after creating.
