# Family policy authoring

A **family policy** decides a finding by evidence closure instead of by the model's verdict string. The model fills fact slots and cites evidence for each value; only values backed by admissible evidence count; a declarative table then entails True Positive, False Positive, or Needs More Data. A finding that no family selects goes to the legacy route, where the model's verdict decides.

Policies are data. `load_policy_registry()` loads every `config/policies/*.yaml`, so adding a family needs no engine change. The engine lives in `src/vuln_hunter_x/verification/policy/`.

## Current coverage

Families that exist today, by class and language. `P` selects by CWE; `P*` selects only listed rule ids, so a finding from an unlisted rule stays on the legacy route. Everything else is on the legacy route.

| Class | CWE | c / cpp | csharp | go | java | javascript | php | python |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SQL injection | 89 (564 Java) | | P | P* | P | P* | P | P |
| OS command injection | 78, 77 | P | P | P* | P* | P* | P* | P |
| Path traversal / file access | 22, 23, 36 (73 Java, PHP; 98 PHP) | | P | P | P | P | P | P |
| SSRF | 918 | | | | P | | | P |
| Open redirect | 601 | | | | P | | | P |
| XSS | 79 | | | | P* | | | P* |
| Unsafe deserialization | 502 | | | | P | | | P |
| XXE | 611 | | | | P* | | | P |
| Code / expression / template-source injection | 94, 95 | | | | P* (95 by CWE) | | | P* |
| LDAP injection | 90 | | | | P* | | | P |
| XPath injection | 643 | | | | P | | | P |
| Log injection | 117 | P | P | P | P | P | P | P |
| Loose equality | 697 | P | P | P | P | P | P | P |
| Permissive CORS | 942, 346 | P | P | P | P | P | P | P |
| `sizeof` on pointer | 467 | P | P | P | P | P | P | P |
| TOCTOU race | 367 | P | P | P | P | P | P | P |

Language-agnostic families own a rule only where a scanner actually emits one; `tests/fixtures/policy_selector_audit/rule_inventory.json` is the per-rule truth.

**Validation status.** The per-language injection families are covered by deterministic tests with a mocked provider. They have not been measured against the legacy route on a benchmark (step 7 of the checklist); treat their verdict quality as unmeasured until that is done.

## How a family is selected

`PolicyRegistry._matches` (`loader.py`) applies, in order:

1. **Language gate.** A family that lists `selectors.languages` matches only findings whose stage language is in the list. `finding.lang` is one of `c, cpp, csharp, go, java, javascript, php, python`; TypeScript is analysed as `javascript`.
2. **CWE or alias.** The family matches when the finding shares any CWE with `selectors.cwes`, or its rule id matches any `selectors.rule_aliases` glob (`fnmatch`).

No match sends the finding to the legacy route. **More than one match fails closed to Needs More Data** (`PolicyOverlapError`). There is no negative selector: a CWE selector claims every rule in that language carrying the CWE.

Two facts make selectors easy to get wrong:

- **Rules carry several CWE tags.** `py/shell-command-constructed-from-input` is tagged CWE-73, CWE-78 and CWE-88, so a Python path family selecting CWE-73 and a Python command family selecting CWE-78 would both match it.
- **The same rule has different ids per scanner.** The vendored OpenGrep tree emits `config.opengrep-rules.<dirs>.<id>`; the semgrep.dev registry packs emit `<dirs>.<file>.<id>`; CodeQL emits `<lang>/<name>`. An exact alias written for one form does not match the others.

## Selector audit

`scripts/audit_policy_selectors.py` enumerates every rule the scanners can emit that carries a CWE tag (vendored OpenGrep rules in both id forms, custom Semgrep rules, custom CodeQL queries, and the installed CodeQL `security-and-quality` suite) and records the family the registry selects for it.

```bash
python scripts/audit_policy_selectors.py                        # regenerate (needs codeql)
python scripts/audit_policy_selectors.py --keep-codeql-builtin  # regenerate without codeql
python scripts/audit_policy_selectors.py --check                # exit 1 when stale
```

`tests/test_policy_selector_audit.py` re-resolves every row. After editing a selector, regenerate the inventory and review the diff: each changed line is one rule that moved between the legacy route and a family. A row whose owner starts with `OVERLAP:` fails the suite.

The built-in CodeQL list reflects the CodeQL version recorded in the inventory header; refresh it when the CodeQL bundle is upgraded.

### Why some families select by rule id

A CWE selector claims every rule in the language that carries the CWE, and the family's `sink_binding` slot would then dismiss a rule whose sink is something else as "not this sink". Where the inventory showed such a rule, the family lists rule ids instead and the odd rule stays on the legacy route:

| Family | Rule kept out, and why |
| --- | --- |
| `sql_injection_javascript` | `js/sql-injection` is tagged CWE-89, 90 and 943 and reports NoSQL injection too. |
| `sql_injection_go`, `command_injection_go` | `go/unsafe-quoting` is tagged CWE-78, 89 and 94 and is interpreter-agnostic. |
| `command_injection_java` | `java/relative-path-command`, `java/exec-tainted-environment` and the `java-reverse-shell` audit rule carry CWE-78 but do not report a tainted command. |
| `command_injection_javascript` | Three prototype-pollution rules carry CWE-78 next to 79, 94 and 915. |
| `xss_java`, `xss_python` | CWE-79 is carried by WebView rules, template-file rules and auto-escape configuration audits that do not locate a response write. |
| `xxe_java` | The `xml-decoder` rule is tagged CWE-611 but flags `java.beans.XMLDecoder`; `deserialization_java` owns it by alias. |
| `code_injection_java`, `code_injection_python` | CWE-94 is a catch-all tag (APK installation, `str.format` rules). |
| `ldap_injection_java` | `ldap-entry-poisoning` carries CWE-90 but has no filter or DN. |

Other selector facts recorded by the audit:

- `path_access_python` and `path_access_javascript` do not select CWE-73: `py/shell-command-constructed-from-input` carries CWE-73 with CWE-78, and `js/template-object-injection` carries it with CWE-94. The rules tagged only CWE-73 are claimed by alias.
- Zip-slip and tar-slip rules are tagged CWE-22 and therefore belong to the path families, which carry archive-entry guidance.

## Classes and per-language files

A class is implemented as **one file per language**, because its guidance must name language-specific sinks and defenses. The PHP families keep the bare class name (`sql_injection`); other languages use `<class>_<lang>` (`sql_injection_java`). `command_injection_cpp` covers both `c` and `cpp`. Family names must be unique; the loader does not check this.

The decision table (fact slots, decisive slots, entailment, admissibility) must be identical across the languages of a class. `tests/test_policy_family_parity.py` enforces it against the class reference: the bare-name family when one exists, otherwise the first member by name. Two classes deviate from their PHP reference on purpose, declared in that test:

- **Command injection.** The non-PHP families add `EXECUTABLE_CONTROL_PATH_FOUND` to `command_channel`, because those runtimes launch processes without a shell. Control of only an argument of a fixed program (argument injection) stays Needs More Data in every language.
- **Path access.** The non-PHP families have no handoff block, treat `NOT_PATH_ACCESS_SINK` as a False Positive, and accept local evidence for `defense_coverage: ALL_REACHING_PATHS`.

When a language's semantics force a different table, add the family and the differing sections to `_DEVIATIONS` in that test, with the reason; use `_REFERENCE` when several languages share the same deviation.

## Checklist for a new family

1. **Policy file.** `config/policies/<class>_<lang>.yaml`, modelled on `config/policies/sql_injection.yaml`. Required keys: `family`, `fact_slots`, `entailment.true_positive`. Admissibility must name a profile for every (slot, value); profiles are defined in `verification/policy/support.py`.
2. **Guidance.** `assessment_guidance` gathers facts. It must not command a verdict or name a benchmark. Say what establishes each slot value and what does not.
3. **Evidence.** Decide from the local slice, the scanner dataflow, and retrieved function, class, caller and callee bodies. Framework evidence does not satisfy the strong profiles. A fact that lives outside retrievable code must resolve to Needs More Data.
4. **Selectors.** Choose them from the inventory, regenerate it, and review every row that changed owner.
5. **Question bank.** The rule's guided questions are still rendered on the policy route. Remove verdict wording and answer labels from the covered rules in `config/prompts/<lang>_questions.yaml` (C# is `cs_questions.yaml`) and add them to `_COVERED_RULES` in `tests/test_prompt_policy_lint.py`.
6. **Tests.**
   - `tests/test_policy_<class>_families.py` (parametrized over the class's languages): selection, language gate, entailment truth table, missing slot gives Needs More Data. Model: `tests/test_policy_sql_injection.py`.
   - `tests/test_policy_acceptance_<class>_families.py`: mocked provider, synthetic True/False Positive panel, non-exhaustive and incomplete-index evidence give Needs More Data. Models: `tests/test_policy_acceptance_sqli.py`, `tests/test_policy_acceptance_cmdi.py`.
   - Add the family to the pinned list in `tests/test_policy_satisfiability.py`.
7. **Benchmark gate.** Compare `--approach-option route=legacy` with `route=auto` on the same entries (`benchmarks/README.md`). A family must not turn a legacy True Positive into a False Positive. This needs an authorised provider and dataset; state in the PR whether it was run.
8. **Docs.** Update the coverage table above and `CHANGELOG.md`.

## Behaviour to know before moving a class onto the policy route

- The policy route does not receive the legacy prefetched notes (framework detection, non-production path, scanner source kind) and does not run the legacy post-processing gates (test-only reachability, second opinion, confidence downgrades).
- When the assessment loop runs out of iterations the verdict is Needs More Data with `decision_source="policy"` and no `policy_decision`.
- Reports do not render `policy_decision`; the facts are in the saved verdict JSON only.
- Policies are read from `config/policies` in the source tree. They are not package data.
