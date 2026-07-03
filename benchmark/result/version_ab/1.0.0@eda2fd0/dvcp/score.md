# Score — 1.0.0@eda2fd0

Model `gpt-5.5` · temp `0` · panel `sha256:eebf118bd…` · 2026-07-01T02:56:44

precision **80%** · recall **100%** · TP 5 (real 4, false-alarm 1) · real 4 · not-real 1 · $0.2969

| finding | truth | verdict | grade | conf |
|---|---|---|---|---|
| cpp/double-free@imgRead.c:62 | real | TP | CORRECT | High |
| cpp/invalid-pointer-deref@imgRead.c:91 | real | TP | CORRECT | High |
| cpp/invalid-pointer-deref@imgRead.c:95 | real | TP | CORRECT | High |
| cpp/path-injection@imgRead.c:132 | not-real | TP | FALSE-ALARM | High |
| cpp/use-after-free@imgRead.c:67 | real | TP | CORRECT | High |
