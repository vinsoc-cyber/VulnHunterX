# Context Extraction in the Verification Process

This document describes how source-code context is extracted and supplied to the
LLM during the verification stage of the VulnHunterX pipeline.

## Context Extraction Flow

```mermaid
flowchart TD
    Start([SARIF Finding]) --> Engine["VerificationEngine._verify_single_finding()<br/>engine.py:522"]

    Engine --> Q["QuestionsLoader.get_questions()<br/>→ questions + additional_context + min_iterations"]

    Q --> Code["ContextExtractor.get_context()<br/>extractor.py:67 — extract enclosing function"]

    Code --> FB{"Function bounds<br/>_find_function_bounds()"}
    FB -->|"Primary"| FCSV["Lookup functions.csv<br/>(CodeQL pre-extracted)"]
    FB -->|"Fallback"| Regex["Regex / indentation<br/>function detection"]
    FCSV --> CC[CodeContext: code + func_name + lines]
    Regex --> CC

    CC --> Sel{"Context CSVs exist?<br/>engine.py:546"}
    Sel -->|Yes| CP["ContextProvider<br/>(CSV-based lookup)"]
    Sel -->|No| SP["SnippetContextProvider<br/>(regex fallback)"]

    CP --> Pre["_build_prefetch_requests()<br/>engine.py:681<br/>pre-fetch caller / callees / all_callers"]
    SP --> Pre

    Pre --> LLM["LLMClient.analyze()<br/>client.py:313"]

    subgraph MT["Multi-turn loop (while iterations < max_iterations)"]
        LLM --> Call["_completion() → LLM"]
        Call --> Parse["_parse_response()<br/>verdict + context_needed"]
        Parse --> Vd{"Verdict?"}

        Vd -->|"TP / FP<br/>(min_iterations met)"| Done([Return Verdict])
        Vd -->|"Needs More Data<br/>+ context_needed[]"| Dedup{"New requests<br/>not yet fulfilled?"}

        Dedup -->|"No (all provided)"| Ask["Prompt LLM to decide<br/>with existing context"]
        Ask --> Call

        Dedup -->|Yes| Fetch["context_provider.get_additional_context()<br/>provider.py:58"]
        Fetch --> Dispatch["Dispatch by type →<br/>caller / all_callers / callees / struct /<br/>global / macro / typedef / enum /<br/>free_sites / destructor / field_writes"]
        Dispatch --> CSVRead["_load_csv() + _read_lines()<br/>(cached, path-traversal safe)"]
        CSVRead --> Follow["build_followup_prompt()<br/>append to message history"]
        Follow --> Call
    end

    Done --> Verdict([Verdict JSON:<br/>TP / FP / NMD + confidence])
```

## How CodeQL CSVs are pre-generated (Stage 2, upstream)

```mermaid
flowchart LR
    DB[("CodeQL database<br/>output/lang/repo/database")] --> CE["ContextExtractorDB.run_query()<br/>codeql/context_extractor.py:105"]
    CE --> Run["codeql query run → BQRS"]
    Run --> Decode["codeql bqrs decode → CSV"]
    Decode --> Out["output/lang/repo/context/<br/>functions.csv, callers.csv,<br/>structs.csv, globals.csv,<br/>macros.csv, free_sites.csv,<br/>destructors.csv, field_writes.csv"]
```

## Key points

- **Two-phase context model.** Some context is **pre-fetched** upfront (anything
  keyed off the function name: `caller`, `callees`, `all_callers` —
  `engine.py:681`). The rest is **reactive** — fetched only when the LLM asks for
  it via `context_needed` in a `Needs More Data` verdict.

- **Two providers.** `ContextProvider` does CSV lookups against CodeQL-extracted
  files; if those CSVs don't exist, the engine falls back to
  `SnippetContextProvider`, which regex-scans the snippet and returns an
  `<unavailable: out-of-snippet>` sentinel when data is outside scope.

- **The multi-turn loop** (`client.py:313`) deduplicates requests against
  already-fulfilled context, gates early TP/FP verdicts behind `min_iterations`,
  and can `_force_decision_turn()` if the LLM stalls on `Needs More Data`.

- **11 context types** are supported, with the C/C++-specific ones (`free_sites`,
  `destructor`, `field_writes`) targeting use-after-free / TOCTOU analysis.

## Reference: components and entry points

| Component | File | Methods |
|---|---|---|
| Heuristic context | `context/extractor.py` | `get_context()` (67), `_find_function_bounds()` (173) |
| CodeQL extraction | `codeql/context_extractor.py` | `run_query()` (105), `extract_for_database()` (180) |
| CSV provider | `context/provider.py` | `get_additional_context()` (58), `_load_csv()` (119) |
| Snippet fallback | `context/snippet_provider.py` | `get_additional_context()` (53) |
| Engine | `verification/engine.py` | `_verify_single_finding()` (522), `_build_prefetch_requests()` (681) |
| Questions | `questions/loader.py` | `get_questions()` (165) |
| LLM client | `llm/client.py` | `analyze()` (313), `_parse_response()` (1189) |
| Prompts | `llm/prompts.py` | `build_user_prompt()` (193), `build_followup_prompt()` (315) |
