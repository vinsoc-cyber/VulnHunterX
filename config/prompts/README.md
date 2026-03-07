# Guided Questions Templates

This directory contains YAML templates that drive the LLM's multi-turn verification of SAST findings. Each template defines the questions the LLM must answer before issuing a verdict, ensuring step-by-step reasoning rather than pattern-matching.

## File Naming Convention

| File | Language(s) |
|---|---|
| `cpp_questions.yaml` | C, C++ |
| `python_questions.yaml` | Python |
| `javascript_questions.yaml` | JavaScript, TypeScript |
| `php_questions.yaml` | PHP |
| `java_questions.yaml` | Java |
| `default_questions.yaml` | Fallback for any language / unknown rule |
| `system_prompt.yaml` | LLM system prompt template (not rule-specific) |

## YAML Structure

Each file is a mapping of `rule_id` → question template:

```yaml
cpp/use-after-free:
  short_description: "One-line description of the vulnerability type"
  questions:
    - "Question 1 the LLM must answer before giving a verdict"
    - "Question 2 ..."
    - "Question 3 ..."
  context_hint: "Human-readable hint about what extra context helps"
  additional_context:
    - "caller"      # fetch caller function code
    - "struct"      # fetch struct/class definition
    - "global"      # fetch global variable definition
    - "macro"       # fetch macro definition
```

### Fields

| Field | Required | Description |
|---|---|---|
| `short_description` | Yes | Shown in the LLM prompt as the rule description |
| `questions` | Yes | List of 4–6 questions the LLM must answer before giving a verdict |
| `context_hint` | No | Explains what context is most useful (informational only) |
| `additional_context` | No | Context types the LLM may request (`caller`, `struct`, `global`, `macro`) |

## Fallback Chain

When looking up a rule ID, the loader tries:

1. **Exact match** — `rule_id` exactly matches a key in the language file
2. **Prefix match** — e.g., `cpp/sql-injection-local` falls back to `cpp/sql-injection`
3. **Language generic** — first entry in the language file that loosely matches the rule category
4. **`default_questions.yaml`** — universal fallback used when no language-specific match is found

## Adding Questions for a New CWE or Rule

1. Find the appropriate language file (e.g., `cpp_questions.yaml` for C/C++).
2. Add a new entry using the rule ID as the key (e.g., `cpp/my-new-rule`).
3. Write 4–6 questions that force the LLM to trace:
   - Where variables are declared and their exact sizes/values
   - Whether sizes/values change through assignment or reallocation
   - What checks or constraints exist before the vulnerable operation
   - What other variables feed into the target
4. Optionally add `additional_context` types if the LLM often needs caller or struct info for this rule.

### Example: Adding a New Rule

```yaml
cpp/integer-truncation:
  short_description: "Integer value truncated when assigned to a smaller type"
  questions:
    - "What is the SOURCE type and its declared range or bit width?"
    - "What is the DESTINATION type and its maximum representable value?"
    - "Does the source value come from user input, a function parameter, or a fixed constant?"
    - "Is there a bounds check or cast guard BEFORE the assignment?"
    - "What happens if the truncated value is used downstream — does it affect memory sizes or indices?"
  context_hint: "Include the declaration of both variables and any upstream assignments."
  additional_context: ["caller"]
```

## Question Writing Guidelines

Good questions should:
- Force the LLM to examine **specific lines** of code, not reason abstractly
- Target the **root cause** of the vulnerability pattern (sizes, bounds, lifetime, ownership)
- Be answerable from the code context window alone, or explicitly ask for more context if needed
- Avoid yes/no questions — use "What is...", "Where is...", "Does X change...", "Are there checks..."

Poor questions to avoid:
- "Is this code vulnerable?" — too broad, defeats the purpose
- "Does this look safe?" — subjective, not analytical
- Generic questions that apply to all bugs equally
