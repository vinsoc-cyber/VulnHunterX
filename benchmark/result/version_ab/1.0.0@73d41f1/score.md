# Score — 1.0.0@73d41f1

Model `gpt-5.5` · temp `0` · 2026-06-30T08:11:34

precision **80%** · recall **100%** · TP 5 (real 4, false-alarm 1) · real 4 · not-real 1 · $0.3068

| target | finding | truth | verdict | grade | conf |
|---|---|---|---|---|---|
| dvcp | cpp/double-free@imgRead.c:62 | real | TP | CORRECT | High |
| dvcp | cpp/invalid-pointer-deref@imgRead.c:91 | real | TP | CORRECT | High |
| dvcp | cpp/invalid-pointer-deref@imgRead.c:95 | real | TP | CORRECT | High |
| dvcp | cpp/path-injection@imgRead.c:132 | not-real | TP | FALSE-ALARM | Low |
| dvcp | cpp/use-after-free@imgRead.c:67 | real | TP | CORRECT | High |

## Per target
| target | precision | recall | TP (real/FA) | real | not-real | cost | panel |
|---|---|---|---|---|---|---|---|
| dvcp | 80% | 100% | 5 (4/1) | 4 | 1 | $0.3068 | sha256:eebf118bd… |
