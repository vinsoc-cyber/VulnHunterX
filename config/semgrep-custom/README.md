# Custom Semgrep / OpenGrep Rules

This directory holds project-authored Semgrep / OpenGrep rules to fill gaps
the public registry packs do not cover. One file per language. Loaded by the
`full` rule profile via `${LANG}` template expansion. Both `SemgrepAnalyzer`
and `OpenGrepAnalyzer` consume these files unchanged.

## Languages covered

| File | Rule count |
|---|---|
| [python.yaml](python.yaml) | 22 |
| [javascript.yaml](javascript.yaml) | 14 |
| [java.yaml](java.yaml) | 16 |
| [go.yaml](go.yaml) | 19 |
| [php.yaml](php.yaml) | 14 |
| [cpp.yaml](cpp.yaml) | 4 |
| [csharp.yaml](csharp.yaml) | 14 |

**Total: 103 custom rules.**

Rules target structural / configuration / dangerous-default patterns. Cross-
procedural taint flows are handled by custom CodeQL queries in
[../codeql-custom/](../codeql-custom/) and intentionally not duplicated here.

## Wiring contract

Semgrep rule IDs cannot use `/`, so they cannot exact-match guided-question
rule IDs like `php/type-juggling`. Instead, custom rules rely on the
CWE-based fallback in `vuln_hunter_x.questions.loader._match_by_cwe`:

1. Set `metadata.cwe` to one or more CWE IDs (e.g. `["CWE-1025"]`).
2. Ensure the CWE is in `config/rule_categories.yaml::cwe_question_map`
   (the audit script `scripts/audit_rule_coverage.py` verifies this).
3. The finding then receives the language-specific guided question for the
   mapped suffix — e.g. CWE-1025 → `type-juggling` → `php/type-juggling`.

## Required metadata fields

```yaml
rules:
  - id: vulnhunterx.<lang>.<rule-name>     # unique, namespaced
    languages: [<lang>]
    severity: WARNING | ERROR
    message: "<one-line description with CWE-N reference>"
    metadata:
      cwe: ["CWE-N"]                       # required — drives question selection
      category: security
      owasp: "A0X:2021"
      references:
        - https://cwe.mitre.org/data/definitions/N.html
    patterns:
      - ...
```

## Local linting

```bash
# Per file
opengrep --validate --config config/semgrep-custom/<lang>.yaml
# All files
for f in config/semgrep-custom/*.yaml; do opengrep --validate --config "$f"; done
# Wiring audit — every metadata.cwe must resolve via cwe_question_map
python scripts/audit_rule_coverage.py --fail-on-gaps
```
