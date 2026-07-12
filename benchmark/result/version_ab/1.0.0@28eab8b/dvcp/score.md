# Score — 1.0.0@28eab8b

Model `gpt-5.5` · temp `0` · panel `sha256:eebf118bd…` · 2026-07-12T12:21:06

precision **100%** · recall **100%** · TP 4 (real 4, false-alarm 0) · real 4 · not-real 1 · NMD 0 · err 0 · $0.3358
_resources:_ 27k in / 7k out · cache 21% · 169.9s model-time · iters μ1.2

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| cpp/double-free@imgRead.c:62 | real | TP | CORRECT | High |
| cpp/invalid-pointer-deref@imgRead.c:91 | real | TP | CORRECT | High |
| cpp/invalid-pointer-deref@imgRead.c:95 | real | TP | CORRECT | High |
| cpp/path-injection@imgRead.c:132 | not-real | FP | CORRECT | Medium |
| cpp/use-after-free@imgRead.c:67 | real | TP | CORRECT | High |
