# yaml.github-actions.security.run-shell-injection.run-shell-injection @ .github/workflows/docker-image.yml:29

**Verdict:** FP · **Confidence:** Medium (0.7) · **Truth:** not-real · **Grade:** CORRECT · **Iterations:** 5

## Reasoning

Although the risky pattern exists at the flagged `run: |` shell sink on line 29, the provided workflow only runs on manual dispatch and pushes to `master`, with no pull request or other untrusted trigger visible. The `push` path is explicitly branch-restricted on lines 5-7, and the other interpolated values shown are not demonstrated to be attacker-controlled by a lower-privileged user, so a clearly exploitable command-injection path is not established for this finding.

## Data flow

.github/workflows/docker-image.yml:33 `${{ github.ref }}` → direct interpolation into shell block started at line 29 → `VERSION=$(echo ... | sed ...)` at line 33 → conditional use on line 34 → possible normalization on line 35 → Docker tag use on line 42. Additional flows: line 31 `${{ github.repository_owner }}` → `IMAGE_ID` → lowercase transform on line 32 → Docker tags on lines 42-43; line 36 `${{ github.sha }}` → `COMMIT` via `cut` → Docker tag on line 43.

## Answers

1. Step 0 / flagged line: The flagged line is present at `.github/workflows/docker-image.yml:29`, exact text: `run: |`. This is a GitHub Actions YAML shell block in job `build`, step `Build and push multi-arch DVWA image` beginning at line 28; there is no PHP function involved.
2. Step 1 source: The data comes from GitHub Actions `github` context values used inside the shell block: `${{ github.repository_owner }}` on line 31, `${{ github.ref }}` on lines 33-34, and `${{ github.sha }}` on line 36. The workflow triggers are `workflow_dispatch` on line 4 and `push` only to `master` on lines 5-7.
3. Step 2 trace: `${{ github.repository_owner }}` is assigned to `IMAGE_ID` on line 31, lowercased via `tr` on line 32, and used in Docker tags on lines 42-43. `${{ github.ref }}` is inserted into an `echo | sed` command assigning `VERSION` on line 33, used again in a shell conditional on line 34, optionally normalized on lines 34-35, then used in a Docker tag on line 42. `${{ github.sha }}` is inserted into an `echo | cut` command assigning `COMMIT` on line 36, echoed on line 39, and used in a Docker tag on line 43.
4. Step 3 validation/sanitization: The workflow does not apply shell escaping. Line 32 lowercases `IMAGE_ID`, lines 33-34 use `sed`, line 35 maps `master` to `latest`, and line 36 truncates the SHA; these are not command-injection sanitizers. However, the visible trigger configuration constrains the `push` path to branch `master` only on lines 5-7, so `github.ref` for that path is not an attacker-chosen arbitrary branch name in this workflow.
5. Step 4 sink: The sink is shell execution of the multiline `run:` block starting at line 29. The potentially dangerous operation is pre-shell interpolation of `${{ github.* }}` values into shell commands on lines 31, 33, 34, and 36.
6. Step 5 framework/library protections: No automatic shell escaping is applied to direct `${{ ... }}` interpolation in `run:`. The relevant protection visible in this file is trigger restriction: `push` runs only for `master` on lines 5-7, and there are no pull request, issue, comment, or other untrusted-event triggers shown.
7. Step 6 attacker privilege: For the visible `push` path, an attacker would need permission to push to `master` because the workflow only runs on that branch per lines 5-7. For `workflow_dispatch` on line 4, the file shows no untrusted inputs; triggering it generally requires repository workflow permissions rather than unauthenticated external input. No pull-request-from-fork or unauthenticated trigger is visible.
8. Step 7 impact: If an attacker could control a shell-significant `github.ref`, impact would be command injection/RCE in the runner and possible tampering with the Docker build/push at lines 41-44. In the visible workflow, that lower-privileged attacker-controlled path is not established.
9. Step 8 weakest link: The weakest coding pattern is direct interpolation of `github.ref` into shell commands on lines 33-34. The defense preventing a clear exploit in the shown workflow is the absence of untrusted event triggers and the visible restriction of `push` to `master` on lines 5-7.
