# Development Environment

## Virtual Environment Setup
- Use a single `.venv` virtual environment at the repository root
- Create with: `uv venv --python python3.12 .venv`
- Activate with: `source .venv/bin/activate` (Linux/macOS) or `.venv\Scripts\activate` (Windows)

## Package Manager
- **Preferred**: Use `uv` package manager (10-100x faster than pip)
- **Fallback**: `pip` is acceptable if `uv` is not available
- Install dependencies: `uv pip install -r requirements.txt`
- Install in development mode: `uv pip install -e .`

## Python Version Requirements
- **Required**: Python 3.12 (default)
- **Supported**: Python 3.13
- All tools must work correctly on Python 3.12-3.13
- Set `requires-python = ">=3.12,<3.14"` in `pyproject.toml` files

## Environment Variables
- Store environment variables in `.env` file in `.` directory
- Common variables:
  - `OPENAI_API_KEY` - OpenAI API key for AI reasoning
  - `OPENAI_MODEL` - Model to use (default: `gpt-4.1-mini`)
  - `OPENAI_BASE_URL` - Base URL for OpenAI API
  - `LLM_PROVIDER` - Provider selection (`openai` or `ollama`)
  - `OLLAMA_MODEL` - Model for Ollama provider
  - `OLLAMA_API_BASE` - Ollama server URL (e.g. http://host:11434 for remote server)
- Load with: `python-dotenv` or via env file loading

## Makefile Usage
- `make install` - Install production dependencies
- `make dev` - Install development dependencies
- `make test` - Run test suite
- `make lint` - Run linting checks
- `make format` - Format code with black and isort

## Development Dependencies Installation
- Install in development mode: `uv pip install -e ./`
- Generate requirements.txt: `python generate_requirements.py`

## IDE/Editor Recommendations
- **VS Code**: Recommended with Python extension
- **PyCharm**: Full-featured Python IDE
- Configure to use the project's `.venv` as the Python interpreter
- Enable type checking and linting in the IDE

## Docker Policy
- **MANDATORY**: All Docker images MUST use fixed versions (tags), never floating versions
- **Rationale**: Ensures reproducible builds, prevents unexpected updates, improves security
- **Requirements**:
  - Use specific version tags: `python:3.12.7-slim` instead of `python:3.12-slim` or `python:3.12`
  - Use specific version tags: `nginx:1.26.0-alpine` instead of `nginx:1.26-alpine` or `nginx:latest`
  - When updating Docker images, explicitly update the version tag in the Dockerfile/docker-compose.yml
- **Examples**:
  - ✅ Good: `FROM python:3.12.7-slim`
  - ✅ Good: `image: nginx:1.26.0-alpine`
  - ❌ Bad: `FROM python:3.12-slim` (floating minor version)
  - ❌ Bad: `image: nginx:latest` (floating tag)
  - ❌ Bad: `image: nginx:1.26-alpine` (floating patch version)
- **Reference files**:
  - `docker/Dockerfile` - Docker image usage

