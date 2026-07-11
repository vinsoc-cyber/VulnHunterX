# Score — 1.0.0@b99ed57

Model `gpt-5.5` · temp `0` · panel `sha256:1179d5607…` · 2026-07-11T06:46:31

precision **100%** · recall **62%** · TP 10 (real 10, false-alarm 0) · real 16 · not-real 1 · NMD 1 · err 0 · $3.3324
_resources:_ 451k in / 83k out · cache 70% · 1820.5s model-time · iters μ3.82

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| js/clear-text-cookie@server.js:78 | real | TP | CORRECT | High |
| js/code-injection@app/data/allocations-dao.js:78 | real | FP | MISS | Low |
| js/code-injection@app/routes/contributions.js:32 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:33 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:34 | real | TP | CORRECT | High |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | FP | CORRECT | Low |
| js/log-injection@app/routes/session.js:64 | real | TP | CORRECT | High |
| js/missing-rate-limiting@app/routes/index.js:34 | real | NMD | abstain | High |
| js/missing-token-validation@server.js:78 | real | FP | MISS | Low |
| js/polynomial-redos@app/routes/profile.js:61 | real | TP | CORRECT | Medium |
| js/polynomial-redos@app/routes/session.js:181 | real | FP | MISS | Low |
| js/redos@app/routes/profile.js:59 | real | TP | CORRECT | High |
| js/request-forgery@app/routes/research.js:16 | real | TP | CORRECT | Medium |
| js/server-side-unvalidated-url-redirection@app/routes/index.js:72 | real | TP | CORRECT | High |
| js/session-fixation@app/routes/index.js:34 | real | TP | CORRECT | High |
| js/sql-injection@app/data/user-dao.js:104 | real | FP | MISS | Low |
| js/sql-injection@app/data/user-dao.js:91 | real | FP | MISS | Low |
