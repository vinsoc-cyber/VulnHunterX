# Custom CodeQL Security Queries

This directory holds project-authored CodeQL security queries that supplement the built-in
`<lang>-security-extended.qls` suites. It exists separately from
`config/queries/tools/` (which holds context-extraction queries).

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
   giving the question loader the highest-priority `exact` match.
2. Set `@tags external/cwe/cwe-N security` so the SARIF parser tags the finding.
3. Use `@kind problem` or `@kind path-problem` for taint-tracking rules.
4. Include `@security-severity` for prioritization.

## Installation

Before analyze can use a custom pack:

```bash
codeql pack install config/codeql-custom/<lang>/
```

The `full` rule profile (in `config/rule_categories.yaml`) sets
`include_custom_codeql: true` to layer this on top of the built-in suite.
