# Ground-Truth Vulnerability Baselines

Reference catalogue of the **known, intended** vulnerabilities in the
deliberately-vulnerable repositories used to benchmark VulnHunterX recall,
precision, and triage quality. Each repo is a fixed target with a knowable bug
set, so these tables are the *ground truth* a scan is scored against.

> Scope note: line numbers were read from the cloned sources at the time of
> writing (commit-pinned upstreams). If a repo is re-cloned and upstream moved,
> re-verify line numbers — the **classes/CWEs** are stable, the line numbers are
> not guaranteed.

Repos are registered in [config/repos.yaml](../../config/repos.yaml). Detection
difficulty tiers used below:

- **easy** — syntactic/pattern (unsafe function, `printf(user)`, double-free, infinite recursion)
- **medium** — needs data-flow / value-range (overflow→undersized alloc, tainted length, conditional UAF)
- **hard** — semantic / lifetime / compiler-behaviour (C++ temporaries, removed `memset`, RAII misuse, missing-`break` fall-through)

---

## 1. dvpwa — Damn Vulnerable Python Web App  (Python)

- **URL:** https://github.com/anxolerd/dvpwa
- **Stack:** aiohttp + aiohttp-jinja2 + aiopg (PostgreSQL) — *not* Django/Flask/FastAPI
- **Shape:** small web app under `sqli/`; bugs are realistic and reachable via routes

| # | Class | CWE | Location | Notes / difficulty |
|---|---|---|---|---|
| 1 | SQL injection | CWE-89 | `sqli/dao/student.py:42-45` (`Student.create`, `%`-format → `cur.execute`) | tainted `name` from POST; **medium** |
| 2 | Weak password hashing (MD5, unsalted) | CWE-327/328/916 | `sqli/dao/user.py:41` (`check_password`) | **easy** |
| 3 | Timing-unsafe comparison (pwd hash) | CWE-208 | `sqli/dao/user.py:41` | `==` on secret; **medium** |
| 4 | Timing-unsafe comparison (CSRF token) | CWE-208 | `sqli/middlewares.py:32` | **dead code** — in `csrf_middleware`, which is disabled (see #6) |
| 5 | Stored/Reflected XSS (autoescape off) | CWE-79 | root cause `sqli/app.py:34` (`setup_jinja(..., autoescape=False)`); sinks in `templates/course.jinja2` (`review_text`, `title`, `description`), `base.jinja2`, `students.jinja2` | taint flows through DB → template; **hard** for SAST taint, **easy** as config weakness |
| 6 | CSRF protection disabled | CWE-352 | `sqli/app.py:26` (`# csrf_middleware,` commented out of the middleware chain) | absence-of-control; not reliably SAST-detectable |
| 7 | Insecure session cookie (`httponly=False`) | CWE-1004/614 | `sqli/middlewares.py:20` (`RedisStorage(..., httponly=False)`) | **easy** (config) |
| 8 | Debug mode enabled | CWE-489 | `sqli/app.py:23` (`web.Application(debug=True)`) | **easy** (config) |
| 9 | Hardcoded DB credentials | CWE-798 | `config/dev.yaml` (`password: postgres`) | low-entropy → missed by gitleaks/p-secrets; **easy** with a literal rule |
| 10 | Missing authorization on POST endpoints | CWE-862 | `sqli/views.py` (students/courses/review/evaluate create handlers) | absence-of-control; not reliably SAST-detectable |

**Non-vuln noise to expect:** `py/unused-import` (`sqli/middlewares.py:4`) — a
quality-lint finding, correctly a False Positive for security.

**Observed VulnHunterX coverage:** SQLi and MD5 reliably detected; autoescape/
debug/httponly/hardcoded-creds detected only after the framework-aware custom
rules were added; CSRF-disabled and missing-authz are out of SAST reach (covered
by the report's Coverage-Limitations caveat).

---

## 2. dvcp — Damn Vulnerable C Program  (C)

- **URL:** https://github.com/hardik05/Damn_Vulnerable_C_Program
- **Build:** `gcc -g -o dvcp imgRead.c`
- **Shape:** one `ProcessImage()` path with all bugs stacked, gated by fields of a
  crafted input file. The repo ships **multiple identical copies** of the program
  (`dvcp.c`, `imgRead.c`, and `linux/ libAFL/ windows/` variants such as
  `imgRead_replication.c`, `imgReadlib.c`, `imgRead_libfuzzer.c`,
  `imgRead_socket.c`) — expect the same bug set repeated per file.

Ground truth (line numbers per `dvcp.c`; identical logic in the copies):

| # | Class | CWE | Line | Notes / difficulty |
|---|---|---|---|---|
| 1 | Integer overflow → undersized alloc | CWE-190 | `54` (`size1 = img.width + img.height`) then `malloc(size1)` `55` | **medium** (value-range) |
| 2 | Heap buffer overflow (`memcpy` fixed into undersized buf) | CWE-122/787 | `58` (`memcpy(buff1, img.data, sizeof(img.data))`) | depends on #1; **medium** |
| 3 | Double-free | CWE-415 | `59` + `62` (`free(buff1)` then `free(buff1)` if `size1%2==0`) | conditional; **medium** |
| 4 | Use-after-free | CWE-416 | `67` (`buff1[0]='a'` after free, if `size1%3==0`) | conditional; **medium** |
| 5 | Integer underflow → large alloc | CWE-191 | `74` (`size2 = width - height + 100`) | **medium** |
| 6 | Heap buffer overflow (second buffer) | CWE-122/787 | `79` (`memcpy(buff2, img.data, sizeof(img.data))`) | **medium** |
| 7 | Divide-by-zero | CWE-369 | `82` (`size3 = img.width / img.height`) | **easy**, *no rule currently fires* |
| 8 | Out-of-bounds read (stack) | CWE-125 | `90` (`buff3[size3]`, `buff3` is `char[10]`) | **medium** |
| 9 | Out-of-bounds read (heap) | CWE-125 | `91` (`buff4[size3]`) | **medium** |
| 10 | Out-of-bounds write (stack) | CWE-787 | `94` (`buff3[size3]='c'`) | **medium** |
| 11 | Out-of-bounds write (heap) | CWE-787 | `95` (`buff4[size3]='c'`) | **medium** |
| 12 | Memory leak | CWE-401 | `99` (`buff4=0` without `free`, if `size3>10`) | **medium** |
| 13 | Stack exhaustion (infinite recursion) | CWE-674 | `107` → `stack_operation()` (`22-27`) | **easy** |
| 14 | Heap exhaustion (unbounded `malloc` loop) | CWE-400/789 | `113-114` | **easy** |

Also note: `printf("%s", img.header)` (`48`) on a non-null-terminated `char[4]`
is a latent over-read.

**Observed VulnHunterX coverage:** double-free, UAF, and OOB read/write (CodeQL
`invalid-pointer-deref`) detected; **the integer-overflow chain, divide-by-zero,
leak, and exhaustion were missed** by CodeQL + custom cpp queries + Semgrep — the
primary recall gap for this target.

---

## 3. insecure-coding-examples  (C/C++)

- **URL:** https://github.com/patricia-gallardo/insecure-coding-examples
- **Build:** `cmake .. && make`
- **Shape:** one bug per file under `exploitable/`, each a minimal `main()`;
  the file name *is* the class, and CWE links are in the file header.

| File (`exploitable/`) | Class | CWE | Anchor | Tier |
|---|---|---|---|---|
| `stack_buffer_overflow.c` | stack overflow via `gets` | CWE-121/242 | `:13` `gets(buffer)` | easy |
| `stack_buffer_overflow_cwe.c` | stack overflow via `strcpy` | CWE-121 | `strcpy` larger input | easy |
| `heap_buffer_overflow.c` | heap overflow via `strcpy(malloc, argv[1])` | CWE-122 | `:14` `strcpy(buf, argv[1])` | easy |
| `heap_buffer_overflow_cwe.c` | heap overflow | CWE-122 | same pattern | easy |
| `global_buffer_overflow.c` | global OOB | CWE-119/125 | `return buffer[4]` on `int[4]` | easy |
| `buffer_underflow.c` | buffer underflow | CWE-124 | negative-index loop | medium |
| `container_overflow.cpp` | STL OOB (`vector.data()[6]`) | CWE-125 | beyond reserved capacity | medium |
| `signed_integer_overflow{,_ubsan,_unsafe}.c` | signed overflow (×3 variants) | CWE-190 | `INT_MAX + 256` | medium |
| `unsigned_integer_wraparound{,_ubsan,_unsafe}.c` | unsigned wraparound (×3) | CWE-190 | `UINT_MAX - 256 + 256` | medium |
| `numeric_truncation{,_ubsan,_unsafe}.c` | truncation (×3) | CWE-197 | wide→narrow conversion | medium |
| `double_free.c` | double-free | CWE-415 | `:13` + `:15` (`free` in error path, then unconditional) | easy |
| `use_after_free.c` | use-after-free | CWE-416 | `:15` free, then `strlen(buffer)` on error | medium |
| `uncontrolled_format_string.c` | format string | CWE-134 | `printf(argv[1], argv[2])` | easy |
| `incorrect_type_conversion.c` | bad cast | CWE-704 | `malloc(sizeof A)` cast to `struct B*` | medium |
| `disappearing_memset.c` | compiler-removed `memset` | CWE-14 | optimized-away scrub | hard |
| `dangling_pointer.cpp` | dangling `string_view` to temporary | CWE-416 | `sv = s + "World"` | hard |
| `temporary_capture.cpp` | lambda captures temporary by ref | (lifetime) | — | hard |
| `unnamed_lock_guard.cpp` | RAII misuse (lock released immediately) | (concurrency) | temporary `lock_guard` | hard |
| `infinite_loop.cpp` | infinite loop | CWE-835 | `while(true)` no exit | easy |
| `undefined_behavior.cpp` | UB | (various) | — | hard |

(~26 example files; `practice/` and `vulnerability/` dirs hold safe/heartbleed
extras.)

**Observed VulnHunterX coverage:** strong on the syntactic classes (unsafe
functions, format string, overflow, UAF, double-free, type-confusion); the C++
lifetime/UB classes (dangling string_view, removed memset, RAII) are largely
missed (expected — hard tier). The CodeQL `security-and-quality` suite also
emitted ~half the raw findings as **quality lint** (now filtered at parse time).

---

## 4. insecure-cpp-dojo  (C/C++)

- **URL:** https://github.com/patricia-gallardo/insecure-cplusplus-dojo
- **Build:** `cmake .. && make` (⚠ CodeQL+CMake build tracing fails in our env →
  CodeQL skipped; Semgrep-only → severe recall loss on this target)
- **Shape:** kata exercises by theme; each dir has `<name>.c/.cpp` + `.tests.cpp`.

| Dir | Class | CWE | Anchor | Tier |
|---|---|---|---|---|
| `check_bypass/` | unsigned overflow bypasses `<= 256` check | CWE-190 | `check_bypass.cpp:6` (`(first+second) <= max_sum`) | medium |
| `check_bypass/` | signed overflow bypass | CWE-190 | `:15` | medium |
| `check_bypass/` | truncation bypass (unsigned→int) | CWE-197 | later in file | medium |
| `signed_addition_overflow/` | buggy overflow check (`first+second < 0`) | CWE-190 | `signed_overflow.cpp:4` | medium |
| `heartbleed/` | OOB over-read: `payload` length from input drives copy | CWE-122/125 | `heartbleed.c`: `n2s(p, payload)` `:78` → `OPENSSL_malloc(... payload ...)` `:94` → copy-back of `payload` bytes | medium (taint on length field) |
| `free_use/` | UAF via missing `break` (fall-through) | CWE-416 | `free_use.cpp:13` `free(buffer)` (case 5) → `:15` `strlen(buffer)` (case 4) | hard (fall-through) |
| `string_length/` | stack/heap overflow + underflow | CWE-121/122/124 | `strcpy` w/o bounds; loop underflow | easy/medium |
| `type_conversion/` | pointer/integer confusion | CWE-704 | `uintptr_t`→`int` loses pointer | medium |
| `comparisons/` | signed/unsigned comparison semantics | CWE-704/697 | mismatch | medium |
| `yatzy/` | (game-logic stub; no heap bug in shipped code) | — | — | — |

**Observed VulnHunterX coverage:** with CodeQL unavailable (build failure),
Semgrep alone detected **1 of ~14** bugs — Heartbleed, the check-bypasses, the
missing-`break` UAF, and type-confusion were all missed. This target is the
clearest demonstration that a failed C/C++ build collapses memory-safety recall.

---

## Using these baselines

- Score a scan by mapping its findings' `(file, line, CWE)` to the rows above:
  **recall** = ground-truth rows detected by any tool; **precision** = verified
  TPs ÷ all verified; separate *detection misses* (no rule fired) from *triage
  misses* (fired but verified FP/NMD).
- dvcp's duplicate program copies and the kata `*.tests.cpp` files inflate raw
  counts — dedupe by basename when scoring per-class recall.
- These repos are the regression targets for the C/C++ improvements in
  [src/vuln_hunter_x/sarif/parser.py](../../src/vuln_hunter_x/sarif/parser.py)
  (non-security lint filter) and
  [src/vuln_hunter_x/verification/engine.py](../../src/vuln_hunter_x/verification/engine.py)
  (`_RECONCILE_SPECIFIC_CWES` memory-safety classes).
