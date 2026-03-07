# Contributing to VulnHunterX

## Development Setup

```bash
uv venv --python python3.12 .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
.venv/bin/python -m pytest tests/ -v

# Single test
.venv/bin/python -m pytest tests/test_sarif_parser.py::TestSarifParserParsing -v
```

## Code Style

```bash
ruff check src/          # lint
ruff format src/         # format
mypy src/                # type check
```

All three must pass before submitting a PR.

---

## Adding Questions for a New CWE or Rule

1. Find the language file in `config/prompts/` (e.g., `cpp_questions.yaml`).
2. Add an entry keyed by the CodeQL/Semgrep rule ID.
3. Follow the format described in [config/prompts/README.md](config/prompts/README.md).
4. Test that the questions load correctly:
   ```bash
   .venv/bin/python -c "
   from vuln_hunter_x.questions.loader import QuestionsLoader
   l = QuestionsLoader()
   q = l.get_questions('cpp', 'cpp/my-new-rule')
   print(q.questions)
   "
   ```

---

## Supporting a New Language

1. **CodeQL queries** — add extraction queries under `config/queries/tools/<lang>/`:
   - `functions.ql` — extract function bodies
   - `callers.ql` — extract caller relationships
   - `classes.ql` or `structs.ql` — extract type definitions
2. **Question templates** — add `config/prompts/<lang>_questions.yaml` following the existing format.
3. **Language mapping** — add the new language to `LANG_MAP` in `src/vuln_hunter_x/core/config.py` and to CLI `--language` choices in `src/vuln_hunter_x/cli/main.py`.
4. **Tests** — add at least one test covering the new language's SARIF parsing and question loading.

---

## Adding a New Benchmark Dataset

1. Create an adapter in `benchmarks/adapters/<name>_adapter.py` implementing a `load(limit=0)` method that returns `list[GroundTruthEntry]`.
2. Register the dataset in `benchmarks/scripts/run_benchmark.py` under `_load_dataset()`.
3. Add a fixture file in `benchmarks/fixtures/<name>_sample.json` with 10 representative entries (5 TP, 5 FP).
4. Add tests in `tests/test_benchmark_adapters.py` covering load, label assignment, and CWE extraction.

---

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR.
- All existing tests must pass; add new tests for any new behaviour.
- Update `README.md` if you add new CLI flags or configuration options.
- Do not commit `.env`, `output/`, or benchmark result directories.
