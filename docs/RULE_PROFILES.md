# Rule Profiles

`--profile` selects how much rule coverage a scan uses, trading breadth (and cost/time) against
focus. Profiles are defined in [config/rule_categories.yaml](../config/rule_categories.yaml); the
per-rule inventory is in [config/RULES.md](../config/RULES.md).

## The five profiles

From least to most coverage:

| Profile | CodeQL suite | Semgrep packs | Custom rules | Use when |
|---|---|---|---|---|
| `standard` *(default)* | `security-extended` (~200) | `auto` + per-language pack (`p/gosec`, `p/python`, …) | — | Fast baseline; most runs. |
| `extended` | `security-extended` | + `p/security-audit`, `p/secrets` | — | Audit + secret detection. |
| `maximum` | `security-and-quality` (~400) | + `p/owasp-top-ten` | — | Broad OWASP coverage. |
| `extended-registry` | `security-and-quality` | 8 universal + per-language packs (django/flask/nodejs/gosec/…) | — | Widest *public* rule set. |
| `full` | `security-and-quality` | extended-registry packs | **+ in-repo custom CodeQL & Semgrep** | Max coverage incl. project-specific rules; reliable offline. |

Coverage from `standard` → `full` grows roughly **5×–10×** more rules per scan.

## How to choose

- **Just triaging the obvious stuff, fast** → `standard`. The default ships a per-language pack so
  a bare `auto` never silently skips a language (a Go scan used to return 0 Semgrep results when
  no Go pack was applied).
- **Want secrets and a deeper audit** → `extended`.
- **Compliance / OWASP framing** → `maximum`.
- **Public registry breadth** → `extended-registry`.
- **Offline, or you maintain custom rules** → `full`. Registry `p/...` packs require semgrep.dev
  network access and yield nothing offline; `full` additionally loads the in-repo
  [config/semgrep-custom/](../config/semgrep-custom/) and
  [config/codeql-custom/](../config/codeql-custom/) rules, which work without a network.

`language_specific_configs` ensures per-language packs (e.g. `p/django`) are applied only to
matching repos, so cross-language scans aren't polluted.

## Cost implications

More rules → more findings → more LLM verification calls (~10K tokens each — see
[LLM_PROVIDERS.md](LLM_PROVIDERS.md)). The profile mostly affects **how many findings** reach the
LLM, not the per-finding cost. If a `full` scan produces too many findings to verify on your
budget, narrow with `--category` (e.g. `--category injection`) or `--limit`.

## Custom rules (the `full` profile)

`full` layers your own rules on top of the built-ins. To add one:

- **CodeQL** — drop `<name>.ql` into `config/codeql-custom/<lang>/src/` with `@id <lang>/<name>`
  matching a guided-question key so the verifier routes it correctly.
- **Semgrep** — append a rule to `config/semgrep-custom/<lang>.yaml` with
  `metadata.cwe: ["CWE-NNN"]` (Semgrep IDs can't contain `/`, so they route via the CWE map, not
  exact-id match).

Then verify the wiring:

```bash
python scripts/audit_rule_coverage.py --fail-on-gaps
```

This reports every rule × CWE × guided-question wire-up status and is CI-friendly. Currently the
repo ships **59 custom CodeQL queries** and **89 custom Semgrep rules** across the supported
languages; the routing map covers **124 CWE IDs**. See
[config/RULES.md](../config/RULES.md) for the authoritative per-rule list and
[METHODOLOGY.md](METHODOLOGY.md) for how routing to guided questions works.
