# Dependency Management Policy

## Primary Source: pyproject.toml
- **All dependencies must be defined in `pyproject.toml` files**
- `pyproject.toml` is the single source of truth for dependency management
- Each project has its own `pyproject.toml` file
- Root `pyproject.toml` contains consolidated dependencies for the entire suite

## Auto-Generated: requirements.txt
- **`requirements.txt` files are auto-generated and should NOT be edited manually**
- Generated via `generate_requirements.py` script
- Used for Docker builds and CI/CD pipelines that expect `requirements.txt`
- To update dependencies:
  1. Edit the relevant `pyproject.toml` file
  2. Run `python generate_requirements.py` to regenerate `requirements.txt`

## Generating requirements.txt
```bash
# Generate all requirements.txt files
python generate_requirements.py

```

