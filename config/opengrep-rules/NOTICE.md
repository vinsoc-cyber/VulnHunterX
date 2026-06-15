# Vendored OpenGrep rules — provenance & license

This directory contains a **vendored, offline snapshot** of third-party Semgrep/
OpenGrep rules. It exists so the OpenGrep engine can run **without contacting
`registry.semgrep.dev`** (no `auto`, no `p/...` registry packs). See
[`../rule_categories.yaml`](../rule_categories.yaml) — every profile's
`opengrep_configs` points only at `config/opengrep-rules/${LANG}`.

## Source

| | |
|---|---|
| Upstream | https://github.com/opengrep/opengrep-rules |
| Commit | `f1d2b562b414783763fd02a6ed2736eaed622efa` |
| Imported | 2026-06-14 |
| Scope | rule `*.yaml` / `*.yml` only — test-target source files were **not** vendored |

Language directory mapping (project `${LANG}` key → upstream dir):

| `${LANG}` | upstream | files |
|---|---|---|
| `python` | `python/` | 334 |
| `javascript` | `javascript/` | 173 |
| `typescript` | `typescript/` | 30 |
| `java` | `java/` | 123 |
| `php` | `php/` | 61 |
| `go` | `go/` | 76 |
| `csharp` | `csharp/` | 52 |
| `c` | `c/` | 16 |
| `cpp` | `c/` (C/C++ rules share the upstream `c/` tree) | 16 |

## License — IMPORTANT, read before redistributing or selling

These rules are **NOT MIT** and are **NOT relicensed** by VulnHunterX. They retain
their upstream license, reproduced verbatim in [`LICENSE`](LICENSE):

> **LGPL 2.1 (GNU Lesser General Public License, Version 2.1)** with the
> **"Commons Clause" License Condition v1.0**.

The Commons Clause withholds the right to **"Sell"** the Software — i.e. to provide
to third parties, for a fee, a product or service whose value derives entirely or
substantially from the functionality of these rules. This makes the repository
**mixed-license**: VulnHunterX's own code remains MIT; everything under
`config/opengrep-rules/` is governed by `LICENSE` here.

Implications:
- Any distribution of VulnHunterX that bundles this directory must carry this
  Commons-Clause + LGPL-2.1 notice (this file + `LICENSE`).
- Offering VulnHunterX as a paid product/service whose value derives substantially
  from these rules requires legal review against the Commons Clause. If that is a
  concern, drop this directory and run OpenGrep with only the project's own
  `config/semgrep-custom/` rules (MIT-clean).

The OpenGrep **engine** itself is plain LGPL-2.1; the Commons Clause applies only to
this vendored *rule content*.

## Known limitations

These rules were authored for Semgrep, which has commercial-only capabilities the
OpenGrep OSS engine does not implement. Of the ~881 vendored rules, ~30 carry
`interfile:` / `interproc:` (cross-file/cross-function) flags that OpenGrep cannot
fully honor — OpenGrep runs them intra-file or skips them with a warning rather than
failing the scan. Intra-file taint rules (`mode: taint`, ~192 of them) run normally.
This is expected best-effort behavior; it does not abort an OpenGrep run.

## Refreshing

Upstream was archived (read-only) on 2025-11-28, so this snapshot will not receive
updates automatically. To re-pull / bump the pinned commit:

```bash
scripts/refresh_opengrep_rules.sh [<commit-ish>]
```
