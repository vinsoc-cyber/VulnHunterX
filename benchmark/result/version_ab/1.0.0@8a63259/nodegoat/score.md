# Score — 1.0.0@8a63259

Model `gpt-5.5` · temp `0` · panel `sha256:1179d5607…` · 2026-07-08T21:16:47

precision **94%** · recall **100%** · TP 17 (real 16, false-alarm 1) · real 16 · not-real 1 · $3.3012

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| js/clear-text-cookie@server.js:78 | real | TP | CORRECT | High |
| js/code-injection@app/data/allocations-dao.js:78 | real | TP | CORRECT | Low |
| js/code-injection@app/routes/contributions.js:32 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:33 | real | TP | CORRECT | High |
| js/code-injection@app/routes/contributions.js:34 | real | TP | CORRECT | Medium |
| js/indirect-command-line-injection@Gruntfile.js:166 | not-real | TP | FALSE-ALARM | Low |
| js/log-injection@app/routes/session.js:64 | real | TP | CORRECT | High |
| js/missing-rate-limiting@app/routes/index.js:34 | real | TP | CORRECT | Medium |
| js/missing-token-validation@server.js:78 | real | TP | CORRECT | Low |
| js/polynomial-redos@app/routes/profile.js:61 | real | TP | CORRECT | Medium |
| js/polynomial-redos@app/routes/session.js:181 | real | TP | CORRECT | Low |
| js/redos@app/routes/profile.js:59 | real | TP | CORRECT | High |
| js/request-forgery@app/routes/research.js:16 | real | TP | CORRECT | High |
| js/server-side-unvalidated-url-redirection@app/routes/index.js:72 | real | TP | CORRECT | High |
| js/session-fixation@app/routes/index.js:34 | real | TP | CORRECT | High |
| js/sql-injection@app/data/user-dao.js:104 | real | TP | CORRECT | Low |
| js/sql-injection@app/data/user-dao.js:91 | real | TP | CORRECT | Low |
