# Plan: Improve Guided Question Quality + Assessment Framework

## Context

VulnHunterX has 200+ guided question rules across 6 YAML files. Research revealed two interconnected problems:

1. **Quality gaps** — Several benchmark-critical rules have NO specific questions (falling back to generic), cross-language consistency is uneven, and modern vulnerability classes are missing entirely.
2. **No assessment infrastructure** — Benchmark results don't capture `rule_id`, there are no per-rule metrics, and no way to measure whether guided questions actually improve accuracy per rule.

External research (LLM4Vuln, SecLLMHolmes, CASTLE) confirms CWE-specific questions outperform generic prompts, but gains are strongly model- and CWE-dependent — making per-rule measurement critical.

See [guided_questions_research.md](../guided_questions_research.md) for full research findings.

---

## Part A: Question Quality Fixes

### A1. Add missing questions for benchmark-critical C/C++ rules

These 5 rules are exercised by the Juliet benchmark but fall back to generic questions:

| Rule | CWE | Juliet Impact |
|------|-----|---------------|
| `cpp/null-pointer-dereference` | CWE-476 | ~12.5% of findings |
| `cpp/overflow-destination` | CWE-787 | ~12.5% of findings |
| `cpp/overrunning-write` | CWE-787 | ~12.5% of findings |
| `cpp/out-of-bounds-read` | CWE-125 | ~12.5% of findings |
| `cpp/use-of-uninitialized-variable` | CWE-457 | ~12.5% of findings |

**File:** [config/prompts/cpp_questions.yaml](../../config/prompts/cpp_questions.yaml)

Example entry for `cpp/null-pointer-dereference`:
```yaml
cpp/null-pointer-dereference:
  short_description: "Null pointer dereferenced without NULL check"
  questions:
    - "Where is the pointer ASSIGNED — via malloc/calloc, function return, or parameter?"
    - "Is there a NULL check (if (ptr == NULL)) on ALL code paths BEFORE the flagged dereference?"
    - "Could the pointer legitimately be NULL at the flagged location (e.g., malloc failure, empty container)?"
    - "List ALL early returns or branches between the pointer assignment and the dereference."
    - "Is the pointer set to NULL explicitly anywhere between assignment and use?"
    - "Are there mitigating factors — internal-only API, assert() guarding, or test code?"
  context_hint: "Trace all paths from pointer assignment to dereference"
  additional_context: ["caller", "struct"]
```

For `cpp/overflow-destination` and `cpp/overrunning-write` (CWE-787 — out-of-bounds write):
```yaml
cpp/overflow-destination:
  short_description: "Write operation overflows the destination buffer"
  questions:
    - "What is the SIZE of the destination buffer — declared, computed, or heap-allocated?"
    - "What is the SIZE or maximum length of the data being written?"
    - "Is there a bounds check (if (len < sizeof(buf))) on ALL paths BEFORE the write?"
    - "Is the write length controlled by user input, a return value, or a computation that could overflow?"
    - "Is memcpy/strcpy/sprintf used instead of safer alternatives (memcpy_s, snprintf, strlcpy)?"
    - "Are there mitigating factors — ASLR, stack canaries, test code, or internal-only use?"
  context_hint: "Need buffer declaration and all callers that supply the write length"
  additional_context: ["caller", "struct"]
```

For `cpp/out-of-bounds-read` (CWE-125):
```yaml
cpp/out-of-bounds-read:
  short_description: "Read operation accesses memory beyond buffer bounds"
  questions:
    - "What is the SIZE of the source buffer being read?"
    - "What index or offset is used for the read — is it bounds-checked against the buffer size?"
    - "Could the index or offset be influenced by user input or a computation that could exceed the buffer size?"
    - "Is the read result used in a sensitive context (returned to user, written to file, network)?"
    - "Are safer read functions (fgets, strnlen, memcpy with explicit size) used instead of unbounded reads?"
    - "Are there mitigating factors — ASLR, test code, or sanitizer protection in production?"
  context_hint: "Need buffer declaration and all callers that supply the index"
  additional_context: ["caller", "struct"]
```

For `cpp/use-of-uninitialized-variable` (CWE-457):
```yaml
cpp/use-of-uninitialized-variable:
  short_description: "Variable used before being assigned a defined value"
  questions:
    - "On what code path is the variable DECLARED but NOT initialized before the flagged use?"
    - "Is initialization conditional (only happens in some branches) — list the branches that skip it?"
    - "What is the IMPACT if the variable holds stack garbage — could it affect control flow, memory, or output?"
    - "Is the variable a struct/array — if so, is only part of it uninitialized?"
    - "Does the calling code zero-initialize the containing structure before passing it?"
    - "Are there mitigating factors — is the use in a dead code branch or test path?"
  context_hint: "Trace all code paths from declaration to use"
  additional_context: ["caller", "struct"]
```

### A2. Add `java/jndi-injection` rule

**File:** [config/prompts/java_questions.yaml](../../config/prompts/java_questions.yaml)

```yaml
java/jndi-injection:
  short_description: "User-controlled JNDI lookup enables remote code execution"
  questions:
    - "Does InitialContext.lookup() or similar JNDI API receive user-controlled input?"
    - "Is the input validated against an allowlist of trusted JNDI providers?"
    - "Is the JVM com.sun.jndi.rmi.object.trustURLCodebase property set to false?"
    - "Is the application using Log4j 2.x where JNDI lookups in log messages are enabled?"
    - "What Java version and JNDI provider (RMI, LDAP, DNS) is in use?"
    - "Are there mitigating controls — WAF rules, network egress filtering, or serialization filters?"
  context_hint: "Check JVM system properties and framework JNDI configuration"
  additional_context: ["caller", "global"]
```

Also add alias for consistent naming:
```yaml
java/certificate-validation-disabled:
  short_description: "TLS certificate validation disabled — susceptible to MITM"
  # same questions as java/insecure-tls
```

### A3. Enhance `default_questions.yaml` with 3 new questions

**File:** [config/prompts/default_questions.yaml](../../config/prompts/default_questions.yaml)

Append after existing question 7:
```yaml
    - "Are there intermediate transformations (encoding, decoding, type conversion) between source and sink that could bypass sanitization?"
    - "Does the framework or library provide automatic protections at this point (e.g., ORM parameterization, auto-escaping templating engine)?"
    - "What privilege level or authentication state does an attacker need to trigger this code path?"
```

### A4. Enrich JavaScript SQL injection questions with ORM library names

**File:** [config/prompts/javascript_questions.yaml](../../config/prompts/javascript_questions.yaml)

Extend `js/sql-injection` questions:
```yaml
    - "If using Sequelize, is sequelize.query() called with raw SQL and user input, or with model methods (.findAll(), .findOne()) using where clauses?"
    - "If using Knex.js, is knex.raw() used with user input instead of the query builder API?"
    - "If using TypeORM, is getRepository().query() called with string concatenation instead of parameterized createQueryBuilder()?"
```

### A5. Add CWE-77 to rule map

**File:** [benchmarks/adapters/cwe_rule_map.py](../../benchmarks/adapters/cwe_rule_map.py)

```python
"CWE-77": ["cpp/command-line-injection", "py/command-injection",
           "js/command-injection", "php/command-injection", "java/command-injection"],
```

---

## Part B: Assessment Infrastructure

### B1. Persist `rule_id`, `cwe_id`, `lang` in checkpoint JSON

**File:** [benchmarks/approaches/base.py](../../benchmarks/approaches/base.py)

`to_dict()` (line 41-53) omits these but `from_dict()` already reads them. Add 3 fields:
```python
"cwe_id": self.entry.cwe_id,
"rule_id": self.entry.rule_id,
"lang": self.entry.lang,
```

Backward compatible — old checkpoints default gracefully in `from_dict()`.

### B2. Add `question_match_type` tracking

**File:** [benchmarks/approaches/base.py](../../benchmarks/approaches/base.py)

Add field to dataclass: `question_match_type: str = ""`

Serialize in `to_dict()`, read in `from_dict()`.

**File:** [src/vuln_hunter_x/questions/loader.py](../../src/vuln_hunter_x/questions/loader.py)

Add `get_questions_with_match_info(rule_id) -> tuple[GuidedQuestions, str]`. Returns questions + match type: `"exact"`, `"normalized"`, `"prefix"`, `"lang_prefix"`, `"default"`, or `"generic"`.

Refactor `get_questions()` to call this internally and discard the tag. No behavior change.

Match types map to the existing cascade at lines 95-130:
- Line 96-97: `"exact"` — direct key match
- Line 100-102: `"normalized"` — `-` → `/` substitution
- Line 105-107: `"prefix"` — bidirectional prefix match
- Line 116-118: `"lang_prefix"` — same language, partial name match
- Line 121-128: `"default"` — falls back to `default_questions.yaml`
- Line 130: `"generic"` — programmatic fallback

**Files:** [benchmarks/approaches/vulnhunterx.py](../../benchmarks/approaches/vulnhunterx.py) and [benchmarks/approaches/generic_questions.py](../../benchmarks/approaches/generic_questions.py)

After `entry_to_finding(entry)`, call `get_questions_with_match_info(finding.rule_id)` and record the match type in the returned `BenchmarkResult`.

### B3. Add `RuleMetrics` and per-language aggregation to evaluator

**File:** [benchmarks/metrics/evaluator.py](../../benchmarks/metrics/evaluator.py)

Add `RuleMetrics` dataclass (same structure as `CWEMetrics` + `lang: str` field).

Add to `ApproachMetrics`:
- `rule_metrics: dict[str, RuleMetrics]` — keyed by `rule_id`
- `lang_metrics: dict[str, CWEMetrics]` — reuse `CWEMetrics` structure, keyed by language
- `question_match_counts: dict[str, int]` — counts per match type

In `evaluate()`, after the CWE accumulation (lines 337-351), add parallel accumulation from `r.entry.rule_id`, `r.entry.lang`, and `getattr(r, 'question_match_type', '')`.

In `summary_dict()`, emit `per_rule`, `per_lang`, and `question_match_counts` sections.

### B4. Add 4 new report sections + 2 charts

**File:** [benchmarks/scripts/generate_report.py](../../benchmarks/scripts/generate_report.py)

**Section 1: Effectiveness Delta table** — per-CWE F1 delta (`vulnhunterx − generic-questions`), sorted descending. Shows where rule-specific questions help/hurt.

**Section 2: Question Coverage table**

| Language | Rules in YAML | Rules Exercised | Coverage % |
|----------|--------------|-----------------|-----------|

Plus list of unexercised rules and rules falling back to generic questions.

**Section 3: Per-Language breakdown**

| Approach | Language | Total | Precision | Recall | F1 |

**Section 4: Question Match Distribution** — fraction of findings using exact/prefix/default/generic questions per approach.

**Chart 6:** Effectiveness Delta horizontal bar chart (green=vulnhunterx better, red=generic better)

**Chart 7:** Question match distribution stacked bar chart (per approach)

---

## Part C: New Benchmark Approach — Ablation Study

**File to create:** [benchmarks/approaches/ablation.py](../../benchmarks/approaches/ablation.py)

New `--approach ablation` that runs the same finding through three question variants in a single pass, following the SecLLMHolmes methodology:

- **Variant A**: Rule-specific questions (vulnhunterx full YAML set)
- **Variant B**: Generic default questions only
- **Variant C**: Zero-shot (empty question list — no guided questions)

Records all three verdicts per finding. Enables measurement of isolated question contribution. Per-rule delta `A vs B vs C` shows exactly which rules benefit from specificity vs. which are unaffected.

---

## Critical Files Summary

| File | Change |
|------|--------|
| [config/prompts/cpp_questions.yaml](../../config/prompts/cpp_questions.yaml) | Add 5 missing benchmark-critical rules |
| [config/prompts/java_questions.yaml](../../config/prompts/java_questions.yaml) | Add `java/jndi-injection`, alias `certificate-validation-disabled` |
| [config/prompts/javascript_questions.yaml](../../config/prompts/javascript_questions.yaml) | Enrich SQL injection with ORM library names |
| [config/prompts/default_questions.yaml](../../config/prompts/default_questions.yaml) | Add 3 new questions |
| [benchmarks/adapters/cwe_rule_map.py](../../benchmarks/adapters/cwe_rule_map.py) | Add CWE-77 mapping |
| [benchmarks/approaches/base.py](../../benchmarks/approaches/base.py) | Add `question_match_type`; persist `cwe_id`/`rule_id`/`lang` in `to_dict()` |
| [src/vuln_hunter_x/questions/loader.py](../../src/vuln_hunter_x/questions/loader.py) | Add `get_questions_with_match_info()` |
| [benchmarks/approaches/vulnhunterx.py](../../benchmarks/approaches/vulnhunterx.py) | Record `question_match_type` |
| [benchmarks/approaches/generic_questions.py](../../benchmarks/approaches/generic_questions.py) | Record `question_match_type` |
| [benchmarks/metrics/evaluator.py](../../benchmarks/metrics/evaluator.py) | Add `RuleMetrics`, per-rule/per-lang aggregation |
| [benchmarks/scripts/generate_report.py](../../benchmarks/scripts/generate_report.py) | 4 new sections + 2 charts |
| [benchmarks/approaches/ablation.py](../../benchmarks/approaches/ablation.py) | New ablation study approach |

---

## Suggested Implementation Order

1. **Part A** — YAML quality fixes: small, high-impact, no code changes
2. **B1–B3** — data plumbing: no behavior change, prerequisite for B4
3. **B4** — report sections: depends on B3
4. **Part C** — ablation approach: independent, depends on B1–B2

---

## Verification

```bash
# Run tests
pytest tests/ -q -o "addopts="

# Verify new YAML rules are loaded
python -c "
from vuln_hunter_x.questions.loader import QuestionsLoader
from pathlib import Path
ql = QuestionsLoader(Path('config/prompts'))
for r in ['cpp/null-pointer-dereference', 'cpp/out-of-bounds-read',
          'java/jndi-injection', 'java/certificate-validation-disabled']:
    q, match = ql.get_questions_with_match_info(r)
    print(r, '->', q.short_description, '| match:', match)
"

# Dry-run benchmark to verify new fields in checkpoint JSON
python benchmarks/scripts/run_benchmark.py \
    --dataset juliet --approach vulnhunterx generic-questions \
    --limit 8 --dry-run

# Check REPORT.md has new sections
grep -c "Effectiveness Delta\|Question Coverage\|Per-Language\|Match Distribution" \
    benchmarks/results/*/REPORT.md
```
