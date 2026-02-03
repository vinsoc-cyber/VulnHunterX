# Project Architectures

FutagAssist is designed as an extensible Python framework for automated fuzz target generation.

## Core Architecture

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for the complete architecture documentation including:

- Protocol-based abstractions for all extensible components
- Plugin discovery system with auto-loading from `plugins/` directory
- Component registry pattern for runtime component selection
- Pipeline engine with stage skip/include support
- Configuration system (YAML + CLI overrides)

## Key Components

- **Protocols**: `LLMProvider`, `FuzzerEngine`, `LanguageAnalyzer`, `Reporter`, `PipelineStage`
- **Core**: `ComponentRegistry`, `PluginLoader`, `PipelineEngine`, `ConfigManager`
- **Stages**: Build, Analyze, Generate, Compile, Fuzz, Report
- **Plugins**: LLM providers, fuzzer engines, language analyzers, reporters
