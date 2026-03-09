# Guided Questions Research: Structure, Coverage & Quality Analysis

## Overview

VulnHunterX uses **200+ guided question rules** across 6 YAML files in `config/prompts/`. These rules provide rule-specific, language-tailored questions that the LLM must answer before issuing a verdict. This document captures findings from a deep analysis of their structure, quality gaps, external benchmark comparisons, and assessment methodology.

---

## File Inventory

| File | Language | Rules |
|------|----------|-------|
| `cpp_questions.yaml` | C/C++ | ~48 |
| `python_questions.yaml` | Python | ~58 |
| `javascript_questions.yaml` | JavaScript/TypeScript | ~56 |
| `php_questions.yaml` | PHP | ~36 |
| `java_questions.yaml` | Java | ~28 |
| `default_questions.yaml` | Generic fallback | 1 |
| `system_prompt.yaml` | LLM system prompt | — |

**Total: ~282 rules** (85% have no benchmark coverage yet)

---

## YAML Entry Structure

Every rule entry follows a consistent schema:

```yaml
rule_id:
  short_description: "Brief 1-line vulnerability description"
  questions:
    - "Question 1 (source: where does input originate?)"
    - "Question 2 (trace: is it sanitized through all assignments?)"
    - "Question 3 (sink: how is it used unsafely?)"
    - "Question 4 (constraints: are there bounds checks?)"
    - "Question 5 (mitigations: test code? dead code?)"
    - "Question 6 (alternative: would safer API X prevent this?)"
  context_hint: "Human-readable hint for what additional context helps"
  additional_context: ["caller", "struct", "global"]  # machine-readable
```

- **4–6 questions per rule** (mode: 6)
- `additional_context` drives multi-turn context expansion requests

---

## Universal Question Pattern

All languages follow an identical interrogation flow regardless of vulnerability class:

1. **SOURCE** — Where does the input originate?
2. **TRACE** — Is it sanitized/escaped through all assignments?
3. **SINK** — How is it used unsafely (concatenation, eval, file op)?
4. **CONSTRAINTS** — Are there bounds checks or validation?
5. **MITIGATING FACTORS** — Is this in test/legacy/dead code?
6. **ALTERNATIVE** — Would using safer API X prevent this?

---

## Language-Specific Threat Models

### C/C++ (Most Detailed, 48 rules)
- **Focus**: Memory safety (use-after-free, buffer overflow, off-by-one, stack exhaustion)
- Questions trace allocation/deallocation with extreme precision: "List ALL free() calls", "Are there ALIAS pointers"
- Unique rules: `cpp/use-after-free`, `cpp/alloca-in-loop`, RAII/exception/move semantics

### Python (Broadest Coverage, 58 rules)
- **Focus**: Web vulnerabilities (XSS, SSRF, CSRF, template injection, async race conditions)
- Questions ask about framework defaults and ORM methods
- Unique rules: `py/broken-authentication`, async race conditions, `defusedxml`

### JavaScript (Dual Client/Server, 56 rules)
- **Focus**: Browser DOM + Node.js server-side
- Includes DOM-specific attacks: prototype pollution, clobbering, postMessage
- Unique rules: `js/prototype-pollution`, Electron security (`nodeIntegration`), WebSocket/CORS

### PHP (Classic + Modern, 36 rules)
- **Focus**: Legacy PHP vulnerabilities + type coercion
- Unique rules: `php/type-juggling`, variable variables, `extract()` injection, stream wrappers, magic methods

### Java (Enterprise, 28 rules)
- **Focus**: JEE frameworks (Spring, servlet API), enterprise patterns
- Unique rules: `java/spring-actuator-exposed`, deserialization gadget chains, Spring EL injection
- **Smallest set** — significant gaps vs other languages (see below)

---

## Cross-Language Consistency

These vulnerabilities appear in 2+ languages with consistent source→trace→sink structure:

| Vulnerability | Languages |
|---|---|
| SQL Injection | C++, Python, Java, JS, PHP |
| Command Injection | C++, Python, Java, JS, PHP |
| XSS | Python, Java, JS, PHP |
| Path Injection | C++, Python, Java, JS, PHP |
| XXE | C++, Python, Java, JS, PHP |
| SSRF | Python, Java, JS, PHP |
| Hardcoded Credentials | C++, Python, Java, JS, PHP |
| Weak Crypto | C++, Python, Java, JS, PHP |
| Race Condition | C++, Python, Java, JS |

---

## Critical Quality Gaps Found

### Gap 1: Benchmark-Critical Rules Have NO Specific Questions

These rules are exercised by the **Juliet benchmark** but fall back to generic 7-question default — no rule-specific guidance:

| Rule | CWE | Juliet Impact |
|------|-----|---------------|
| `cpp/null-pointer-dereference` | CWE-476 | ~12.5% of all findings |
| `cpp/overflow-destination` | CWE-787 | ~12.5% of all findings |
| `cpp/overrunning-write` | CWE-787 | ~12.5% of all findings |
| `cpp/out-of-bounds-read` | CWE-125 | ~12.5% of all findings |
| `cpp/use-of-uninitialized-variable` | CWE-457 | ~12.5% of all findings |

**Impact**: ~62% of Juliet benchmark findings get generic questions instead of targeted guidance.

### Gap 2: Java Missing Critical Modern Rules

- **`java/jndi-injection`** — missing entirely (critical: CVE-2021-44228 Log4Shell pattern)
- **`java/cleartext-transmission`** — has `cleartext-storage` but not transmission
- **Inconsistent naming**: Java uses `insecure-tls` while all other languages use `certificate-validation-disabled`
- **CORS misconfiguration** — present in JS only, not Java or Python

### Gap 3: JavaScript Questions Lack ORM Specificity

SQL injection questions don't name popular Node.js libraries:
- No mention of **Sequelize** `sequelize.query()` vs model methods
- No mention of **Knex.js** `knex.raw()`
- No mention of **TypeORM** `getRepository().query()`

Compare to PHP/Java which explicitly name PDO, MySQLi, JPA/Hibernate — much more actionable.

### Gap 4: Default Questions Missing 3 Checks

Current 7-question fallback omits:
1. **Control flow bypass** — intermediate transformations (encoding/decoding) that can bypass sanitization
2. **Framework protections** — does the framework automatically protect here? (Django ORM, Spring Security)
3. **Privilege requirements** — what auth state does an attacker need to trigger this?

### Gap 5: CWE-77 Not Mapped

CWE-77 (Command Injection) appears in the **SecLLMHolmes** dataset but has no entry in `benchmarks/adapters/cwe_rule_map.py`, so findings cannot be matched to rules.

### Gap 6: 85% of Rules Have No Benchmark Coverage

Of ~282 defined question rules, only ~40 (~14%) are exercised by any current benchmark dataset. The remaining ~240 rules have no validation that their questions improve LLM accuracy.

---

## Additional Context Patterns

85% of rules request additional context via `additional_context`:

| Context Type | Frequency | When Needed |
|---|---|---|
| `caller` | ~75% of rules | Input comes from parameters; sizes from caller |
| `struct` | ~40% of rules | Buffer in struct; type definitions needed |
| `global` | ~20% of rules | Global state; race conditions on statics |
| `callees` | ~10% of rules | Callee may sanitize/allocate |
| `all_callers` | ~5% of rules | Multi-entry-point analysis |
| _(none)_ | ~15% of rules | Self-contained (hardcoded strings, weak algorithms) |

**Inconsistency found**: `cpp/type-confusion` requests only `["struct"]` but should also request `["macro", "caller"]` since type confusion often hides in macros.

---

## External Research Findings

### What Other Projects Do

| Project | Key Finding |
|---------|------------|
| **LLM4Vuln** (arXiv:2401.16185) | CWE-specific questions significantly outperform generic; gains are model- and CWE-dependent |
| **SecLLMHolmes** | Compares 8 LLMs × prompting strategies on 228 scenarios; role-oriented prompts outperform task-oriented |
| **CASTLE** (arXiv:2503.09433) | CWE-specific question templates vs. generalist approach — specialist wins on known CWEs |
| **SecVulEval** (arXiv:2505.19828) | 25,440 samples across 5,867 CVEs; enables statement-level evaluation beyond function-level |
| **NIST SARD / Juliet** | Juliet 1.3: 64,295 test cases covering 118 CWEs; both vulnerable ("bad") and secure ("good") variants |

### Key Research Insights

1. **CWE-specific questions outperform generic** — but gains depend strongly on model and CWE type
2. **Few-shot > zero-shot** — structured questions improve F1 significantly; but too many examples can degrade performance (retrieval-augmented selection is best)
3. **Chain-of-thought reduces ambiguity** — CoT reduces "needs more data" responses from 20.3% → 9.1% in controlled studies
4. **Role prompts outperform task prompts** — assigning expert role reduces hallucination
5. **FP reduction is measurable** — best configurations reduce CodeQL FP rate from 92%+ to 6.3%
6. **LLM consistency is measurable** — Claude shows κ=0.92 intra-rater consistency; inter-rater aggregation via majority voting improves accuracy
7. **Agentic multi-turn beats single-shot** — multi-turn context expansion is validated as superior in multiple studies

### Question Quality Metrics (From DeepEval/RAG Evaluation Literature)

| Metric | What It Measures | How to Apply |
|--------|-----------------|--------------|
| **Answer Relevancy** | Does LLM response address the question? | Run LLM-as-judge on reasoning text |
| **Context Precision** | Does each question request only necessary context? | Review `additional_context` fields |
| **Faithfulness** | Does verdict logically follow from the answers? | Check reasoning chain validity |
| **Discriminative Power** | Can questions distinguish TP from FP? | Measure Δ accuracy (with vs without questions) |
| **Ambiguity Rate** | What fraction return NMD? | Already tracked as `nmd_rate` |

---

## Code Flow: Questions → LLM

```
config/prompts/*_questions.yaml
    ↓ QuestionsLoader.load_from_directory()
    ↓ (cached in self.questions dict)
VerificationEngine._verify_single_finding()
    ↓ questions_loader.get_questions(finding.rule_id)
LLMClient.analyze(finding, context, questions)
    ↓ PromptBuilder.build_user_prompt()
    → Questions embedded as numbered list in prompt
    → LLM must answer all before verdict
```

### Question Selection Cascade (`loader.py:85-130`)

1. **Exact match** — `rule_id in self.questions`
2. **Normalized** — replace `-` with `/`
3. **Prefix match** — bidirectional prefix check
4. **Language-scoped** — same language prefix + partial rule name match
5. **Default** — `default_questions.yaml` content
6. **Generic fallback** — programmatically generated 5-question template

**Currently**: Match type is not tracked — no way to know which findings used exact questions vs fallback.

---

## Benchmark Approach Comparison

| Aspect | `generic-questions` | `vulnhunterx` |
|--------|--------------------|----------------|
| Questions source | Only `default_questions.yaml` | All language-specific YAMLs |
| Rule awareness | None (all identical) | Full (rule-specific) |
| Questions per finding | 7 generic questions | 4–6 targeted questions |
| Context hints | Generic `["caller", "struct", "global"]` | Rule-specific context needs |
| `force_decision` | False | True |
| Multi-turn | Yes | Yes |

The `generic-questions` approach is the benchmark **baseline** to isolate the contribution of rule-specific guidance from multi-turn context expansion.

---

## Proposed New Assessment Approaches

### 1. Ablation Study (`--approach ablation`)
Run the same finding through three question variants:
- **Variant A**: Rule-specific questions (vulnhunterx)
- **Variant B**: Generic default questions only
- **Variant C**: Zero-shot (no guided questions)

Measures isolated contribution of question specificity vs. zero guidance.

### 2. Question Match Type Tracking
Record whether each finding used `"exact"`, `"prefix"`, `"default"`, or `"generic"` questions. Enables per-match-type accuracy analysis.

### 3. Question Coverage Matrix

```
         | Juliet | SecLLMHolmes | CVEfixes |
---------|--------|--------------|----------|
CWE-416  |  YES   |     YES      |   YES    | cpp/use-after-free ✓ Questions ✓
CWE-476  |  YES   |     YES      |   NO     | cpp/null-deref ✗ Questions ✗ (FALLBACK)
CWE-787  |  YES   |     YES      |   NO     | cpp/overflow-* ✗ Questions ✗ (FALLBACK)
```

Green = dataset exercises CWE + questions available. Red = questions missing (fallback).

### 4. κ-Consistency Measurement
Run same finding twice with different question phrasings. Target κ ~0.5–0.6 (human-like variation) rather than perfect consistency. Identify rules where question phrasing causes high verdict variance.

---

## Related Files

- `config/prompts/` — all question YAML files
- `src/vuln_hunter_x/questions/loader.py` — `QuestionsLoader` class
- `src/vuln_hunter_x/llm/prompts.py` — `PromptBuilder.build_user_prompt()`
- `src/vuln_hunter_x/verification/engine.py` — `VerificationEngine`
- `benchmarks/approaches/vulnhunterx.py` — full approach
- `benchmarks/approaches/generic_questions.py` — baseline
- `benchmarks/adapters/cwe_rule_map.py` — CWE ↔ rule mapping
- `benchmarks/metrics/evaluator.py` — per-CWE metrics

## References

- LLM4Vuln: https://arxiv.org/abs/2401.16185
- SecVulEval: https://arxiv.org/abs/2505.19828
- CASTLE: https://arxiv.org/html/2503.09433
- SecLLMHolmes: https://github.com/ai4cloudops/SecLLMHolmes
- Sifting the Noise (FP reduction): https://arxiv.org/abs/2601.22952
- Chain-of-Thought for Vulnerabilities: https://arxiv.org/abs/2402.17230
- NIST SARD / Juliet: https://samate.nist.gov/SARD/test-suites/112
- LLM Consistency (Judge's Verdict): https://arxiv.org/abs/2510.09738
