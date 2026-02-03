# AI Coding Agent Instructions

This document provides comprehensive guidelines for AI coding agents working on the AutoRed MCP project. The documentation is organized into focused sections for easier navigation and maintenance.

## Quick Navigation

### Core Policies
- [Language Usage Policy](./language_policy.md) - Language requirements and tool language usage
- [Python Version Policy](./python_version.md) - Python version requirements and compatibility guidelines
- [Dependency Management Policy](./dependency_management.md) - Dependency management with pyproject.toml
- [File and Folder Naming Policy](./file_naming.md) - Naming conventions for files and directories

### Development Standards
- [Coding Conventions](./coding_conventions.md) - Python style guide, type hints, async patterns, file size limits
- [Development Environment](./development_environment.md) - Virtual environment, tools, Makefiles, Docker policy
- [Testing Guidelines](./testing.md) - Test organization, patterns, and execution

### Architecture & Integration
- [Project Architectures](./project_architectures.md) - System architecture, data flow, and component interaction

### Security & Usage
- [Security Policies](./security.md) - Input validation, subprocess safety, secure defaults
- [Project Structure](./project_structure.md) - Project organization overview

## Full Documentation

For complete details on any topic, see the [agents documentation directory](./).

## Quick Reference

### Most Important Policies
1. **Python Version**: Use Python 3.12 (3.13 supported)
2. **File Size**: Python files must not exceed 1000 lines
3. **Docker**: Always use fixed version tags (e.g., `python:3.12.7-slim`)
4. **Dependencies**: Edit `pyproject.toml`, not `requirements.txt` directly
5. **Security**: Never use `shell=True` in subprocess calls
6. **Credentials**: Never store credentials/secrets in config or code (e.g., `OPENAI_API_KEY`, `LANGFUSE_SECRET_KEY`)
7. **Naming**: Use lowercase with underscores (e.g., `long_name`, not `long`)
8. **Versioning**: X (MAJOR) manual, Y (MINOR) and Z (PATCH) automated via CI/CD
