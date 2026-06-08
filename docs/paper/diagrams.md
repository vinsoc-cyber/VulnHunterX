# VulnHunterX — Flow Charts

Mermaid sources.

**Preview tips**
- VS Code: install the extension **"Markdown Preview Mermaid Support"** (bierner.markdown-mermaid). The built-in preview does not render Mermaid by itself.
- GitHub: renders automatically in `.md` files.
- Export to SVG/PNG: `npx -p @mermaid-js/mermaid-cli mmdc -i docs/paper/diagrams.md -o docs/paper/diagram.svg`
- Online editor (paste a single fenced block): https://mermaid.live
- Draw.io: the `*.drawio.svg` files (`architecture.drawio.svg` §1d, `llm-verification.drawio.svg`
  §3d) are *editable* SVGs — they render inline here but also open for editing in draw.io / the
  VS Code **"Draw.io Integration"** extension.

---

## 1. Framework Architecture

```mermaid
flowchart TB
    subgraph UI["User Interface"]
        CLI["CLI (vuln-hunter-x)<br/>prepare · analyze · verify · report"]
        PyAPI["Python API<br/>VerificationEngine.from_config()"]
    end

    subgraph Config["Configuration — 3-tier: CLI > env > YAML"]
        EnvCfg[".env<br/>API keys, tool paths"]
        AppCfg["confirm_findings.yaml<br/>model, temperature, max_iterations"]
        Profiles["rule_categories.yaml<br/>profiles + CWE→question map"]
        Questions["prompts/*_questions.yaml<br/>342 per-rule guided questions"]
        CustomRules["codeql-custom/ + semgrep-custom/<br/>73 + 47 custom rules"]
    end

    subgraph SAST["SAST Engine Layer — SARIF is the only contract"]
        CodeQL["CodeQL adapter"]
        Semgrep["Semgrep adapter"]
        OpenGrep["OpenGrep adapter"]
    end

    subgraph Context["Context Extraction"]
        CtxCodeQL["CodeQL context queries<br/>(semantic)"]
        CtxTS["tree-sitter extractor<br/>(syntactic fallback)"]
        CSV[("Context CSVs<br/>functions, callers, structs,<br/>globals, macros, free_sites…")]
    end

    subgraph Core["Verification Core"]
        Parser["SarifParser<br/>(union + dedup)"]
        QLoader["QuestionsLoader<br/>(exact → prefix → CWE)"]
        CtxProv["ContextProvider<br/>(fixed-vocab broker)"]
        PromptB["PromptBuilder"]
        Engine["VerificationEngine<br/>(multi-turn loop)"]
    end

    subgraph LLM["LLM Layer"]
        Client["LLMClient (LiteLLM)"]
        KeyPool["Quota-aware<br/>multi-key pool<br/>(persistent cooldown)"]
        Providers["OpenAI · Anthropic ·<br/>DeepSeek · Qwen · Ollama"]
    end

    subgraph Out["Outputs"]
        Verdicts[("JSON verdicts<br/>+ reasoning")]
        Report["Markdown report<br/>(EN / VI)"]
    end

    CLI --> Engine
    PyAPI --> Engine
    Config -.-> Engine

    SAST -->|SARIF files| Parser
    CtxCodeQL --> CSV
    CtxTS --> CSV

    Parser --> Engine
    Engine --> QLoader
    Engine --> CtxProv
    CtxProv --> CSV
    Engine --> PromptB
    PromptB --> Client
    Client --> KeyPool
    KeyPool --> Providers
    Providers --> Client
    Client --> Engine

    Engine --> Verdicts
    Verdicts --> Report

    CustomRules -.->|layered by 'full' profile| SAST
    Questions -.-> QLoader
    Profiles -.-> QLoader
```

---

## 2. Full Pipeline Workflow (Stages 1–4, fuzzing excluded)

```mermaid
flowchart LR
    Start([Repo URL or local path]) --> S1

    subgraph S1["Stage 1 · prepare"]
        direction TB
        S1a["Clone source"] --> S1b["Build CodeQL DB"]
        S1b -->|success| S1c["Run CodeQL<br/>context queries"]
        S1b -->|build fails| S1d["tree-sitter<br/>fallback extractor"]
        S1c --> S1e[("Context CSVs")]
        S1d --> S1e
    end

    S1 --> S2

    subgraph S2["Stage 2 · analyze"]
        direction TB
        S2prof{"--profile<br/>standard / extended /<br/>maximum / extended-registry / full"}
        S2prof --> S2a["CodeQL<br/>(built-in + custom .ql)"]
        S2prof --> S2b["Semgrep<br/>(packs + custom YAML)"]
        S2prof --> S2c["OpenGrep<br/>(Semgrep fork)"]
        S2a --> S2out[("*.sarif files<br/>side-by-side")]
        S2b --> S2out
        S2c --> S2out
    end

    S2 --> S3

    subgraph S3["Stage 3 · verify"]
        direction TB
        S3a["SarifParser<br/>discover + dedup"] --> S3b["VerificationEngine<br/>(per finding)"]
        S3b --> S3c[/"Multi-turn LLM verification<br/>(see Diagram 3)"/]
        S3c --> S3d[("Verdict JSONs<br/>TP / FP / NMD<br/>+ confidence")]
    end

    S3 --> S4

    subgraph S4["Stage 4 · report"]
        S4a["Aggregate verdicts"] --> S4b["Markdown report<br/>EN / VI"]
    end

    S4 --> Done([Triaged findings<br/>ready for review])

    S1e -.->|consumed by| S3b
```

---

## 3. LLM Verification Process (per finding)

```mermaid
flowchart TB
    Start([Finding f from SARIF]) --> Init

    Init["Initialize<br/>• Load guided questions (exact → prefix → CWE fallback)<br/>• Extract code snippet (± window)<br/>• Build system prompt<br/>• turn ← 0, history ← []"]

    Init --> Call

    Call["LLM call via LiteLLM<br/>(key pool · prompt cache)"]

    Call --> Resp["Parse JSON response<br/>(answer-before-verdict schema)"]

    Resp --> Schema["answers[] → data_flow → verdict<br/>+ confidence + reasoning + context_needed[]"]

    Schema --> Decide{"verdict?"}

    Decide -->|True Positive| ChkCit{"Specific<br/>citations<br/>present?"}
    Decide -->|False Positive| ChkCit
    Decide -->|Needs More Data| ChkBudget

    ChkCit -->|yes| Return([Return verdict<br/>TP or FP])
    ChkCit -->|"no, High/Medium conf."| Downgrade["Downgrade<br/>confidence → Low"]
    Downgrade --> Return

    ChkBudget{"turn < max_iterations<br/>and min_iterations<br/>satisfied?"}

    ChkBudget -->|budget left| Fetch
    ChkBudget -->|exhausted| ReturnNMD([Return NMD<br/>queue for human review])

    Fetch["For each token in context_needed[]:<br/>caller: · struct: · global: · macro: ·<br/>callees: · all_callers: · typedef: ·<br/>enum: · free_sites: · destructor: ·<br/>field_writes:"]

    Fetch --> Broker[("ContextProvider<br/>CSV lookup<br/>(no live SAST re-run)")]

    Broker --> Append["Append CSV rows to history<br/>turn ← turn + 1"]

    Append --> Call

    classDef terminal fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef decision fill:#fff3e0,stroke:#e65100,color:#bf360c
    classDef store fill:#e3f2fd,stroke:#1565c0,color:#0d47a1
    class Return,ReturnNMD terminal
    class Decide,ChkCit,ChkBudget decision
    class Broker store
```

---

## Simplified Diagrams

Compact versions of the three diagrams above for use as paper figures.
Each subgraph from the detailed version is collapsed into a single node
whose label lists its members.

### 1s. Framework Architecture (simplified)

```mermaid
flowchart TB
    UI["User Interface<br/>CLI · Python API"]
    Config["Configuration (3-tier: CLI > env > YAML)<br/>.env · confirm_findings.yaml · rule_categories.yaml · prompts/*_questions.yaml"]
    CustomRules["Custom Rules<br/>codeql-custom/ · semgrep-custom/"]
    SAST["SAST Engine Layer (SARIF contract)<br/>CodeQL · Semgrep · OpenGrep"]
    Ctx["Context Extraction<br/>CodeQL queries · tree-sitter fallback → CSVs"]
    Core["Verification Core<br/>SarifParser · QuestionsLoader · ContextProvider · PromptBuilder · VerificationEngine"]
    LLM["LLM Layer (LiteLLM)<br/>Key-pool · OpenAI · Anthropic · DeepSeek · Qwen · Ollama"]
    Out["Outputs<br/>JSON verdicts · Markdown report (EN/VI)"]

    UI --> Core
    Config -.-> Core
    CustomRules -.->|"layered by 'full' profile"| SAST
    SAST -->|SARIF| Core
    Ctx --> Core
    Core --> LLM
    LLM --> Core
    Core --> Out
```

### 1d. Framework Architecture (draw.io)

A draw.io version of 1s — the same hub-and-spoke architecture (sources → **Verification Core** →
LLM / outputs, SARIF as the only contract). Like §3d, this is a standalone **editable SVG**: it
renders inline below *and* opens for editing in draw.io / the VS Code **"Draw.io Integration"**
extension (the editable model is embedded in the file's `content` attribute). The Mermaid sources
remain the source of truth for the paper figures.

![Framework Architecture (draw.io)](architecture.drawio.svg)

### 2s. Pipeline Workflow (simplified)

```mermaid
flowchart LR
    Start([Repo URL / local path])
    S1["Stage 1 · prepare<br/>Clone → CodeQL DB → context queries (tree-sitter fallback) → CSVs"]
    S2["Stage 2 · analyze (--profile)<br/>CodeQL · Semgrep · OpenGrep → *.sarif"]
    S3["Stage 3 · verify<br/>SarifParser → VerificationEngine → multi-turn LLM → verdict JSONs"]
    S4["Stage 4 · report<br/>Aggregate → Markdown (EN/VI)"]
    Done([Triaged findings])

    Start --> S1 --> S2 --> S3 --> S4 --> Done
    S1 -.->|context CSVs| S3
```

### 3s. LLM Verification (simplified)

```mermaid
flowchart TB
    Start([Finding f from SARIF])
    Init["Initialize & call LLM<br/>Load guided Qs · build prompt · LiteLLM call · parse JSON (answers · data_flow · verdict · confidence · context_needed)"]
    Decide{"verdict?"}
    ChkCit{"Specific citations present?"}
    Downgrade["Downgrade confidence → Low"]
    ChkBudget{"turn &lt; max_iterations &amp; min_iterations met?"}
    Fetch["Fetch context_needed[] via ContextProvider<br/>caller · struct · global · macro · callees · all_callers · typedef · enum · free_sites · destructor · field_writes"]
    Return([Return verdict — TP / FP])
    ReturnNMD([Return NMD — queue for human review])

    Start --> Init --> Decide
    Decide -->|TP or FP| ChkCit
    Decide -->|NMD| ChkBudget
    ChkCit -->|yes| Return
    ChkCit -->|"no & High/Med conf."| Downgrade --> Return
    ChkBudget -->|budget left| Fetch --> Init
    ChkBudget -->|exhausted| ReturnNMD

    classDef terminal fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef decision fill:#fff3e0,stroke:#e65100,color:#bf360c
    class Return,ReturnNMD terminal
    class Decide,ChkCit,ChkBudget decision
```

### 3d. LLM Verification (draw.io)

A draw.io version of 3s — same per-finding flow (verify the finding → decide the verdict → get
context), drawn in the classic draw.io style. Unlike the Mermaid blocks above, this is a standalone
**editable SVG**: it renders inline below *and* opens for editing in draw.io / the VS Code
**"Draw.io Integration"** extension (the editable model is embedded in the file's `content`
attribute). The Mermaid sources remain the source of truth for the paper figures.

![LLM Verification (draw.io)](llm-verification.drawio.svg)
