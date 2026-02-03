# Project Structure

## Proposed Layout

```
FutagAssist/
├── src/futagassist/           # Main package
│   ├── cli.py                 # Click-based CLI entry point
│   ├── protocols/             # Abstract interfaces (Protocols)
│   ├── core/                  # Framework core (registry, pipeline, config)
│   ├── stages/                # Built-in pipeline stages
│   └── utils/                 # Shared utilities
│
├── plugins/                   # Plugin directory (auto-discovered)
│   ├── llm/                   # LLM provider plugins
│   ├── fuzzers/               # Fuzzer engine plugins
│   ├── languages/             # Language analyzer plugins
│   └── reporters/             # Reporter plugins
│
├── ql/                        # CodeQL queries (per language)
│   ├── cpp/
│   └── python/
│
├── config/                    # Configuration files
│   ├── default.yaml           # Default configuration
│   └── libs_projects.yaml     # Curated test projects
│
├── tests/                     # Test suite
├── docs/                      # Documentation
│   └── ARCHITECTURE.md        # Full architecture documentation
│
├── libs/                      # Downloaded sources (gitignored)
├── analyzing_result/          # Analysis output (gitignored)
│
├── pyproject.toml
├── Makefile
└── README.md
```

## Key Directories

- **src/futagassist/** — Main package with protocols, core framework, stages, and utilities
- **plugins/** — Auto-discovered plugins for LLM providers, fuzzers, languages, and reporters
- **ql/** — CodeQL queries organized by language
- **config/** — YAML configuration files
- **docs/** — Architecture and plugin documentation

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for complete architecture and implementation phases.
