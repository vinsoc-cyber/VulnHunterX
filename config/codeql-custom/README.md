# Custom CodeQL Security Queries

This directory holds project-authored CodeQL security queries that supplement the built-in
`<lang>-security-extended.qls` suites. It exists separately from
`config/queries/tools/` (which holds context-extraction queries).

## Languages covered

| Pack | Path | Rule count |
|---|---|---|
| C/C++ | [cpp/](cpp/) | 21 |
| Java | [java/](java/) | 14 |
| JavaScript / TypeScript | [javascript/](javascript/) | 15 |
| Python | [python/](python/) | 12 |
| Go | [go/](go/) | 11 |

**Total: 73 custom queries.** Per-rule inventory with `@id` / CWE / severity / description
lives in [../RULES.md §3](../RULES.md#3-custom-codeql-queries).

Rules target patterns that built-in `security-extended` / `security-and-quality`
suites miss — typically inter-procedural taint with custom flow steps,
type-aware sinks, or framework-specific gadgets (Spring, Django, Express,
Log4j, JNDI, Mongoose, …). Structural / configuration patterns belong in
custom Semgrep rules at [../semgrep-custom/](../semgrep-custom/) instead.

## Layout

```
config/codeql-custom/
├── <lang>/
│   ├── qlpack.yml          — pack metadata
│   ├── suite.qls           — points to all .ql files in src/
│   └── src/
│       └── <rule-name>.ql  — one query per gap rule
```

Each `.ql` file must:

1. Set `@id <lang>/<name>` matching the guided-question rule_id exactly
   (e.g. `@id cpp/use-after-move`). The SARIF `ruleId` becomes this verbatim,
   giving the question loader the highest-priority `exact` match. When no
   exact match exists, routing falls back via [`cwe_question_map`](../rule_categories.yaml)
   to the question key derived from the CWE tag.
2. Set `@tags external/cwe/cwe-N security` so the SARIF parser tags the finding.
   Multiple CWE tags are allowed (e.g. CWE-805 + CWE-806).
3. Use `@kind problem` (single-point) or `@kind path-problem` (taint with
   source→sink trace).
4. Include `@security-severity` for prioritization (7.0–8.5 high impact,
   5.0–6.5 lower).

## Installation

Each language pack needs a one-time `codeql pack install` to resolve its
`codeql/<lang>-all` dependency:

```bash
for lang in cpp java javascript python go; do
  codeql pack install config/codeql-custom/$lang/
done
```

The `full` rule profile (in [`config/rule_categories.yaml`](../rule_categories.yaml))
sets `include_custom_codeql: true` to layer all five packs on top of the
built-in suite. Other profiles ignore this directory.

## Verifying coverage

```bash
python scripts/audit_rule_coverage.py --fail-on-gaps
```

Confirms every `@id` resolves to a guided question (exact tier) or to a
CWE-mapped fallback. Priority-B gaps (CWE-map entry missing) should stay at 0.
