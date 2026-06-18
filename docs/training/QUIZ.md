# Quiz — Self-Scan Your Code with VulnHunterX

20 multiple-choice questions covering [LESSON.md](LESSON.md) and
[WORKSHOP-cpp.md](WORKSHOP-cpp.md). Each question has one correct answer. The
answer key (with brief explanations) is at the bottom.

---

## Section 1 — SAST & DAST

**Q1. What is the defining difference between SAST and DAST?**
- A. SAST analyzes code at rest without running it; DAST tests a running application.
- B. SAST only works on compiled languages; DAST only works on interpreted ones.
- C. SAST is always more accurate than DAST.
- D. SAST is performed by humans; DAST is fully automated.

**Q2. Which weakness is SAST most associated with?**
- A. It cannot detect SQL injection.
- B. A high rate of false positives (it can't prove a path is reachable at runtime).
- C. It requires a deployed, running application.
- D. It only finds bugs in code that was actually executed.

**Q3. Where in the SDLC does SAST fit most naturally?**
- A. Only after the product is in production.
- B. Early — at commit / pull-request / IDE time ("shift left").
- C. Only during a penetration test of staging.
- D. Never — it has been replaced by DAST.

---

## Section 2 — CodeQL & Semgrep

**Q4. How does CodeQL fundamentally work?**
- A. It runs the program and watches for crashes.
- B. It builds a relational database of the program and runs `.ql` queries over it.
- C. It uses regular expressions on raw source text.
- D. It asks an LLM to read each file.

**Q5. Which statement about Semgrep is correct?**
- A. It requires compiling the project before it can scan.
- B. It matches syntactic/AST patterns on source files and needs no build.
- C. It can only scan Python.
- D. It performs whole-program cross-function taint analysis better than CodeQL.

**Q6. What is SARIF in the VulnHunterX pipeline?**
- A. A proprietary VulnHunterX-only binary format.
- B. The LLM's final verdict file.
- C. A standard JSON format for static-analysis results (ruleId, location, severity, dataflow).
- D. The name of the CodeQL query language.

---

## Section 3 — AST, Control Flow & Data Flow

**Q7. What is an Abstract Syntax Tree (AST)?**
- A. A list of every character in the source file.
- B. A structured tree of the code's syntax (nodes for expressions, statements, etc.).
- C. A runtime memory dump of the program.
- D. A graph of network connections the program makes.

**Q8. In taint analysis, the classic vulnerable pattern is:**
- A. sink → source → sanitizer with no loop.
- B. a flow from a source (untrusted input) to a sink (dangerous op) with no adequate sanitizer.
- C. any function that calls `malloc` twice.
- D. a variable that is declared but never used.

**Q9. How do CodeQL and tree-sitter differ as AST/context backends in VulnHunterX?**
- A. CodeQL is purely syntactic; tree-sitter is fully semantic.
- B. CodeQL builds a semantic model (AST+CFG+DFG, needs a build); tree-sitter is fast, syntactic, build-free.
- C. They are identical; the names are interchangeable.
- D. tree-sitter requires a CodeQL database to function.

---

## Section 4 — LLM Vulnerability Verification

**Q10. What is the LLM's role in VulnHunterX?**
- A. To detect new vulnerabilities the scanners never reported.
- B. To triage (verify) the candidates the SAST tools produced and label them TP/FP/NMD.
- C. To compile the source code.
- D. To replace the human reviewer entirely.

**Q11. Which is a genuine *risk* of LLM-based verification?**
- A. It is always 100% deterministic.
- B. Hallucination — it can assert a sanitizer or flow that doesn't exist.
- C. It cannot produce any explanation of its reasoning.
- D. It never costs tokens or time.

**Q12. Which of these is a mitigation VulnHunterX uses against LLM overconfidence/hallucination?**
- A. Setting temperature to 1.0 for creativity.
- B. Grounding answers in AST/CSV context and downgrading confidence on uncited reasoning.
- C. Hiding the source code from the model entirely.
- D. Accepting the first verdict on turn one for all findings.

---

## Section 5 — VulnHunterX Architecture & Stages

**Q13. What are pipeline Stages 1–4, in order?**
- A. verify → analyze → prepare → report
- B. prepare → analyze → verify → report
- C. analyze → verify → fuzz → report
- D. scan → build → fuzz → triage

**Q14. Which `--profile` loads the in-repo custom CodeQL and Semgrep rules (best for offline use)?**
- A. `standard`
- B. `extended`
- C. `full`
- D. `maximum`

**Q15. What is the purpose of "guided questions"?**
- A. To let the user chat with the repository.
- B. To force the LLM to answer evidence-anchored questions (with line citations) before giving a verdict.
- C. To generate new SARIF findings.
- D. To translate the report into Vietnamese.

**Q16. In the 3-tier question-routing logic, how does a custom Semgrep rule (ID like `vulnhunterx.cpp.weak-hash`) usually get its questions?**
- A. By exact `ruleId` match to a `<lang>/<name>` question key.
- B. Via the CWE-based fallback using the rule's `metadata.cwe`.
- C. It never gets guided questions.
- D. By matching the file extension.

**Q17. What happens in the multi-turn loop when the LLM returns `NEEDS_MORE_DATA` with a `context_needed` request?**
- A. The finding is immediately discarded as a false positive.
- B. The engine fetches the requested context (e.g. `free_sites`, caller) and re-asks, capped by `max_iterations`.
- C. The whole scan restarts from Stage 1.
- D. The LLM is replaced by a different provider.

---

## Section 6 — Using It & Workshop

**Q18. Which single command runs prepare → analyze → verify → report together?**
- A. `vuln-hunter-x check-env`
- B. `vuln-hunter-x scan`
- C. `vuln-hunter-x report`
- D. `vuln-hunter-x prepare`

**Q19. For Ollama Cloud, which environment variable holds the bearer key(s)?**
- A. `OLLAMA_API_KEY` (singular)
- B. `OLLAMA_API_KEYS` (plural, comma-separated pool)
- C. `OPENAI_API_KEY`
- D. `OLLAMA_TOKEN`

**Q20. According to the documented baselines, which class is VulnHunterX *expected to miss* on the `dvcp` / hard-tier targets?**
- A. Double-free and use-after-free.
- B. The integer-overflow chain, divide-by-zero, memory leak, and C++ lifetime/UB bugs.
- C. Stack buffer overflow via `gets`.
- D. Uncontrolled format string (`printf(argv[1], …)`).

---

## Answer Key

| Q | Answer | Why |
|---|---|---|
| 1 | **A** | SAST = static (code at rest); DAST = dynamic (running app). |
| 2 | **B** | SAST can't prove runtime reachability → false positives; the problem VulnHunterX targets. |
| 3 | **B** | SAST shifts left to commit/PR/IDE time. |
| 4 | **B** | CodeQL extracts a relational DB and runs `.ql` queries over it. |
| 5 | **B** | Semgrep matches AST/syntax patterns per file, no build needed. |
| 6 | **C** | SARIF is the standard JSON results format the scanners emit. |
| 7 | **B** | An AST is the structured syntax tree of the code. |
| 8 | **B** | A vuln = source → sink flow with no adequate sanitizer. |
| 9 | **B** | CodeQL = semantic (needs build); tree-sitter = fast, syntactic, build-free. |
| 10 | **B** | The LLM triages existing candidates; it does not detect new bugs or replace humans. |
| 11 | **B** | Hallucination is a real risk (also non-determinism, cost, prompt injection). |
| 12 | **B** | Grounding + confidence downgrades on uncited reasoning are the mitigations. |
| 13 | **B** | prepare → analyze → verify → report. |
| 14 | **C** | `full` loads the in-repo custom CodeQL + Semgrep rules (offline-reliable). |
| 15 | **B** | Guided questions force evidence-anchored, line-cited reasoning before a verdict. |
| 16 | **B** | Semgrep IDs use dots, never exact-match a question key → CWE fallback via `metadata.cwe`. |
| 17 | **B** | Engine fetches the requested context and re-asks, deduped and capped by `max_iterations`. |
| 18 | **B** | `scan` runs the full four-stage pipeline. |
| 19 | **B** | `OLLAMA_API_KEYS` (plural) is the comma-separated pool; singular is not read. |
| 20 | **B** | Integer-overflow chain, divide-by-zero, leak, and C++ lifetime/UB are the documented misses. |
