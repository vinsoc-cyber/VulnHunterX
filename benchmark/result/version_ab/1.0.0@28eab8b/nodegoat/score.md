# Score — 1.0.0@28eab8b

Model `gpt-5.5` · temp `0` · panel `sha256:1179d5607…` · 2026-07-12T12:21:06

precision **100%** · recall **94%** · TP 15 (real 15, false-alarm 0) · real 16 · not-real 1 · NMD 0 · err 0 · $2.5426
_resources:_ 346k in / 63k out · cache 69% · 1456.0s model-time · iters μ3.12

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| js/clear-text-cookie@server.js:78 | real | TP | CORRECT | High |
| js/code-injection@app/data/allocations-dao.js:78 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:32 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:33 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:34 | real | TP | CORRECT | High |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | FP | CORRECT | Low |
| js/log-injection@app/routes/session.js:64 | real | TP | CORRECT | High |
| js/missing-rate-limiting@app/routes/index.js:34 | real | TP | CORRECT | Medium |
| js/missing-token-validation@server.js:78 | real | FP | MISS | Low |
| js/polynomial-redos@app/routes/profile.js:61 | real | TP | CORRECT | High |
| js/polynomial-redos@app/routes/session.js:181 | real | TP | CORRECT | High |
| js/redos@app/routes/profile.js:59 | real | TP | CORRECT | High |
| js/request-forgery@app/routes/research.js:16 | real | TP | CORRECT | High |
| js/server-side-unvalidated-url-redirection@app/routes/index.js:72 | real | TP | CORRECT | High |
| js/session-fixation@app/routes/index.js:34 | real | TP | CORRECT | High |
| js/sql-injection@app/data/user-dao.js:104 | real | TP | CORRECT | Medium |
| js/sql-injection@app/data/user-dao.js:91 | real | TP | CORRECT | High |
