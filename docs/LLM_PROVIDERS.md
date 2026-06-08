# LLM Providers

VulnHunterX talks to LLMs through [LiteLLM](https://github.com/BerriAI/litellm), so OpenAI,
Anthropic, and Ollama (local or cloud) all work through one interface. Pick a provider in `.env`
(`LLM_PROVIDER` + `LLM_MODEL`) or override per-run with `verify --provider ... --model ...`.

Priority: **CLI args > env vars > `config/confirm_findings.yaml` > defaults.**

## Choosing a provider

| Provider | Setup | Cost | Notes |
|---|---|---|---|
| **Ollama (local)** | `OLLAMA_API_BASE=http://localhost:11434`, no key | **$0** | Cheapest; quality depends on the local model and your hardware. |
| **Ollama Cloud** | `OLLAMA_API_BASE=https://ollama.com` + `OLLAMA_API_KEYS=...` | $0–low | Large models (e.g. `qwen3-coder:480b-cloud`, `deepseek-v3.1:671b-cloud`) without local GPUs. |
| **OpenAI** | `OPENAI_API_KEY=sk-...` | ~$0.7–1.1 / 300 findings (gpt-4.1-mini) | Fast, predictable. Custom base URL via `OPENAI_BASE_URL` (Azure, Z.ai, …). |
| **Anthropic** | `ANTHROPIC_API_KEY=...` | varies by model | Claude models (`claude-sonnet-4-6`, `claude-opus-4-6`, `claude-haiku-4-5`). |

### `.env` examples

```bash
# OpenAI
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
OPENAI_API_KEY=sk-...

# Local Ollama
LLM_PROVIDER=ollama
LLM_MODEL=ollama/llama3.2
OLLAMA_API_BASE=http://localhost:11434

# Ollama Cloud
LLM_PROVIDER=ollama
LLM_MODEL=qwen3-coder:480b-cloud
OLLAMA_API_BASE=https://ollama.com
OLLAMA_API_KEYS=key1,key2,key3
```

## Ollama Cloud key pool

`OLLAMA_API_KEYS` (plural) takes a **comma-separated pool** of bearer tokens. With 2+ keys the
client round-robins across them and applies a per-key cooldown on HTTP 429 (rate limit), so a pool
of free-tier keys can sustain a long run. A key is parked on a longer cooldown when its quota is
exhausted. A pool is **required** when `OLLAMA_API_BASE` points at `ollama.com` or the model
carries a `:cloud` / `-cloud` tag. Note: the singular `OLLAMA_API_KEY` is **not** accepted, and
`OPENAI_API_KEY` is for plain OpenAI only — don't reuse it for Ollama Cloud.

## Cost & quality, grounded in the benchmarks

From the model-matrix runs (see [Results](../README.md#results) and
[benchmarks/results/](../benchmarks/results/)), the headline is **reasoning structure beats model
size**: a $0 model with the guided-question pipeline matches or beats paid frontier models.

| Model | Provider | OWASP-Python F1 | Cost (300 findings) |
|---|---|---|---|
| DeepSeek-v4-flash | pass-through / $0 | 92.4% | ~$0.40 |
| gpt-4.1-mini | OpenAI | 89.4% | ~$1.10 |
| Qwen3-Coder (local) | Ollama | 78.7% | $0 |
| GPT-5 | OpenAI | (SecLLMHolmes 82.0%) | ~$16.75 / 228 |

Budget rule of thumb: **~10K tokens per finding**. Multiply by your model's per-token price and the
number of findings. Local/pass-through models make full-dataset runs free but slower (higher p95
latency); paid APIs are faster but cost scales with finding count.

## Tuning knobs (`config/confirm_findings.yaml`)

```yaml
temperature: 0.2       # low = deterministic triage
max_tokens: 5000       # cap on each LLM response
max_iterations: 10     # max conversation rounds (CLI --max-iterations default is 3)
jobs: 4                # concurrent findings (verify -j N); raise carefully — providers have RPM/TPM limits
```

`max_iterations: 1` disables multi-turn (and most of the accuracy gain). Lower `jobs` if you hit
rate limits; raise it to speed up large runs on generous tiers.

## Debugging provider issues

| Symptom | Fix |
|---|---|
| `... API key not configured` | Set the matching key in `.env`; confirm `LLM_PROVIDER` matches. |
| HTTP 429 / rate limit | Lower `jobs`; for Ollama Cloud add more keys to `OLLAMA_API_KEYS`. |
| Empty / malformed verdicts | Raise `max_tokens`; some models truncate the JSON. Check `--log-file` output. |
| Wrong model name | OpenAI uses bare names (`gpt-4o`); Ollama uses `ollama/<model>` locally and `<model>:...-cloud` for cloud. |

Persist full conversations with `vuln-hunter-x verify --log-file output/llm_conversations.md` and
inspect the exact prompts and responses. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) and
[FAQ.md](FAQ.md).
