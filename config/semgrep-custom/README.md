# Custom Semgrep / OpenGrep Rules

This directory holds project-authored Semgrep rules to fill gaps the public
registry packs do not cover. One file per language. Loaded by the `full`
rule profile via `${LANG}` template expansion.

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
semgrep --validate --config config/semgrep-custom/<lang>.yaml
```
