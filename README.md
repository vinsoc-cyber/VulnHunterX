# VulnHunterX

VulnHunterX combines static analysis findings with repository context and guided verification. It produces JSON verdicts and Markdown reports. The supported pipeline is `prepare → analyze → verify → report`.

## Install

Use Python 3.12 or 3.13. Download the wheel, source distribution, and checksum file from the release. From the download directory, run:

```sh
sha256sum -c SHA256SUMS
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./vulnhunterx-1.0.2-py3-none-any.whl
vuln-hunter-x --help
```

To install from the verified source distribution, use `python -m pip install ./vulnhunterx-1.0.2.tar.gz` in the activated environment.

Install the CodeQL, Semgrep or OpenGrep executable appropriate to the selected scanner and add it to PATH. CodeQL and its language packs are external dependencies. OpenGrep uses the rule files included with the framework. Registry-based Semgrep profiles require network access.

## Analyze a local project

Run the CLI in a writable workspace. Set `SOURCE` to the absolute path of a Python project you are authorized to inspect.

```sh
vuln-hunter-x prepare --local-path "$SOURCE" --name app --lang python --skip-db --backend treesitter
vuln-hunter-x analyze --local-path "$SOURCE" --name app --lang python --tool opengrep
```

For verification, configure a provider and model using environment variables. For example, set `LLM_PROVIDER=openai`, `LLM_MODEL` to a model enabled for your account, and `OPENAI_API_KEY` through your environment. Run:

```sh
vuln-hunter-x verify --repo app --lang python
vuln-hunter-x report --repo app --lang python --lang-report en
```

For Ollama Cloud, set `OLLAMA_CLOUD_API_KEY` to one bearer token. When upgrading from 1.0.1, replace `OLLAMA_API_KEYS` with the singular variable.

Add `--translate-report` to verification for Vietnamese output. Translation uses a configured provider. Verification may send code excerpts to that provider. Use an isolated environment for builds from untrusted repositories.

The workspace holds checkouts or checkout links under `repos/` and results under `output/<language>/<repository>/`. Provide a repository list with `prepare --config`, or select a target with `--url` or `--local-path`. Run `vuln-hunter-x <command> --help` for scanner, configuration and output options.

## Python API

```python
from vuln_hunter_x import VerificationEngine

engine = VerificationEngine.from_config()
result = engine.verify_sarif("output/python/app/app.sarif", lang="python", repo_name="app")
for verdict in result.verdicts:
    print(verdict.finding.location, verdict.verdict)
```

## License

Required Notice: VulnHunterX by VinSOC

The first-party framework uses the [PolyForm Noncommercial License 1.0.0](LICENSE). The [vendored rules](config/opengrep-rules/NOTICE.md) have separate terms. See [NOTICE](NOTICE) and [security reporting](SECURITY.md).
