# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic acceptance panel for the path-access (CWE-22 family) policies:
Java, Python, JavaScript, Go and C#.

Drives the full policy path — ``LLMClient.analyze()`` plus a real closure
controller — with a scripted (mocked) model, so every case is reproducible
without an LLM. The verdict is entailed by the fact table and admissibility,
NOT by the model's verdict string.

Every fixture is synthetic: a short, realistic snippet per language for an
unguarded traversal (True Positive), a canonicalise-then-containment guard, a
filename-only construction, a constant path, a non-file "sink" and an inert
outcome (False Positives), and an archive-extraction ("zip slip" / "tar slip")
pair. The evidence-shape cases show the fail-closed behaviour: a guard claimed
from a non-exhaustive retrieved helper, from the scanner data flow alone, or
from an incomplete index never dismisses, and "no guard seen" without a
concrete escaping path and a real effect never confirms.

Scripted tests prove policy/control correctness, NOT model semantic quality.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_REG = load_policy_registry()

TP = "True Positive"
FP = "False Positive"
NMD = "Needs More Data"


@dataclass(frozen=True)
class _Lang:
    lang: str
    file: str
    # (rule id, CWE tags) for the same unguarded traversal, in each id form.
    rules: tuple[tuple[str, tuple[str, ...]], ...]
    dataflow: str
    unguarded: str
    guarded: str  # canonicalise + containment on the only path
    filename_only: str  # construction that cannot change the directory
    constant: str  # no attacker value at all
    not_a_sink: str  # flagged expression is not a filesystem access
    inert: str  # path is built but nothing is done with it
    zip_rule: tuple[str, tuple[str, ...]]
    zip_dataflow: str
    zip_unguarded: str
    zip_guarded: str
    helper: str  # off-slice validator the model asks for
    prompt_tokens: tuple[str, ...]


_CASES = {
    "java": _Lang(
        lang="java",
        file="src/main/java/app/DownloadController.java",
        rules=(
            ("java/path-injection", ("CWE-22", "CWE-23", "CWE-36", "CWE-73")),
            ("config.opengrep-rules.java.lang.security.httpservlet-path-traversal", ("CWE-22",)),
            (
                "java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
                ("CWE-22",),
            ),
            ("java.spring.security.injection.tainted-file-path.tainted-file-path", ("CWE-23",)),
        ),
        dataflow='request.getParameter("name") -> new File(baseDir, name) -> Files.readAllBytes',
        unguarded=(
            'String name = request.getParameter("name");\n'
            "File target = new File(baseDir, name);\n"
            "response.getOutputStream().write(Files.readAllBytes(target.toPath()));"
        ),
        guarded=(
            'File target = new File(baseDir, request.getParameter("name"));\n'
            "String canonical = target.getCanonicalPath();\n"
            "if (!canonical.startsWith(baseDir.getCanonicalPath() + File.separator)) {\n"
            "    throw new SecurityException();\n"
            "}\n"
            "return Files.readAllBytes(target.toPath());"
        ),
        filename_only=(
            'String report = REPORTS.get(request.getParameter("kind"));  // constant Map\n'
            "if (report == null) { response.sendError(404); return; }\n"
            "return Files.readAllBytes(new File(baseDir, report).toPath());"
        ),
        constant='return Files.readAllBytes(Paths.get("/etc/app/banner.txt"));',
        not_a_sink='String label = "File(" + request.getParameter("name") + ")";',
        inert=(
            'File target = new File(baseDir, request.getParameter("name"));\n'
            'log.debug("resolved {}", target);  // never opened'
        ),
        zip_rule=("java/zipslip", ("CWE-22",)),
        zip_dataflow="entry.getName() -> new File(destDir, entry.getName()) -> FileOutputStream",
        zip_unguarded=(
            "ZipInputStream zis = new ZipInputStream(upload.getInputStream());\n"
            "ZipEntry entry;\n"
            "while ((entry = zis.getNextEntry()) != null) {\n"
            "    File out = new File(destDir, entry.getName());\n"
            "    try (FileOutputStream fos = new FileOutputStream(out)) { zis.transferTo(fos); }\n"
            "}"
        ),
        zip_guarded=(
            "File out = new File(destDir, entry.getName());\n"
            "if (!out.toPath().normalize().startsWith(destDir.toPath().normalize())) {\n"
            '    throw new IOException("entry outside target dir");\n'
            "}\n"
            "try (FileOutputStream fos = new FileOutputStream(out)) { zis.transferTo(fos); }"
        ),
        helper="PathGuard.resolveInside",
        prompt_tokens=("getCanonicalPath()", "File.separator", "ZipEntry.getName()"),
    ),
    "python": _Lang(
        lang="python",
        file="app/views.py",
        rules=(
            ("py/path-injection", ("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99")),
            (
                "config.opengrep-rules.python.flask.security.injection.path-traversal-open",
                ("CWE-22",),
            ),
            (
                "python.flask.security.injection.path-traversal-open.path-traversal-open",
                ("CWE-22",),
            ),
            (
                "python.flask.security.secure-static-file-serve."
                "avoid_send_file_without_path_sanitization",
                ("CWE-73",),
            ),
        ),
        dataflow='request.args["name"] -> os.path.join(BASE_DIR, name) -> send_file',
        unguarded=('name = request.args["name"]\nreturn send_file(os.path.join(BASE_DIR, name))'),
        guarded=(
            'candidate = os.path.realpath(os.path.join(BASE_DIR, request.args["name"]))\n'
            "if os.path.commonpath([BASE_DIR, candidate]) != BASE_DIR:\n"
            "    abort(404)\n"
            "return send_file(candidate)"
        ),
        filename_only=(
            'name = secure_filename(request.files["doc"].filename)\n'
            "if not name:\n"
            "    abort(400)\n"
            'request.files["doc"].save(os.path.join(UPLOAD_DIR, name))'
        ),
        constant='with open("/etc/app/banner.txt") as fh:\n    return fh.read()',
        not_a_sink='label = "open(%s)" % request.args["name"]',
        inert=(
            'candidate = os.path.join(BASE_DIR, request.args["name"])\n'
            'logger.debug("resolved %s", candidate)  # never opened'
        ),
        zip_rule=("py/tarslip", ("CWE-22",)),
        zip_dataflow="tarfile.open(fileobj=upload) -> tar.extractall(dest)",
        zip_unguarded=(
            'upload = request.files["bundle"]\n'
            "with tarfile.open(fileobj=upload.stream) as tar:\n"
            "    tar.extractall(dest)"
        ),
        zip_guarded=(
            "with tarfile.open(fileobj=upload.stream) as tar:\n"
            '    tar.extractall(dest, filter="data")'
        ),
        helper="resolve_inside",
        prompt_tokens=("os.path.commonpath", "werkzeug.utils.safe_join", "tarfile"),
    ),
    "javascript": _Lang(
        lang="javascript",
        file="routes/files.js",
        rules=(
            ("js/path-injection", ("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99")),
            (
                "config.opengrep-rules.javascript.lang.security.audit."
                "detect-non-literal-fs-filename",
                ("CWE-22",),
            ),
            (
                "javascript.express.security.audit.express-path-join-resolve-traversal."
                "express-path-join-resolve-traversal",
                ("CWE-22",),
            ),
            (
                "javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
                ("CWE-73",),
            ),
        ),
        dataflow="req.query.name -> path.join(BASE_DIR, name) -> res.sendFile",
        unguarded="res.sendFile(path.join(BASE_DIR, req.query.name));",
        guarded=(
            "const root = path.resolve(BASE_DIR);\n"
            "const candidate = path.resolve(root, req.query.name);\n"
            "if (!candidate.startsWith(root + path.sep)) return res.sendStatus(403);\n"
            "res.sendFile(candidate);"
        ),
        filename_only=(
            "const id = Number.parseInt(req.params.id, 10);\n"
            "if (!Number.isInteger(id)) return res.sendStatus(400);\n"
            "fs.createReadStream(path.join(BASE_DIR, `${id}.pdf`)).pipe(res);"
        ),
        constant="fs.readFileSync(path.join(__dirname, 'banner.txt'), 'utf8');",
        not_a_sink="const label = `readFile(${req.query.name})`;",
        inert=(
            "const candidate = path.join(BASE_DIR, req.query.name);\n"
            "logger.debug('resolved %s', candidate); // never opened"
        ),
        zip_rule=("js/zipslip", ("CWE-22",)),
        zip_dataflow="entry.path -> path.join(dest, entry.path) -> fs.createWriteStream",
        zip_unguarded=(
            "fs.createReadStream(req.file.path).pipe(unzipper.Parse()).on('entry', (entry) => {\n"
            "  entry.pipe(fs.createWriteStream(path.join(dest, entry.path)));\n"
            "});"
        ),
        zip_guarded=(
            "const target = path.resolve(dest, entry.path);\n"
            "if (!target.startsWith(path.resolve(dest) + path.sep)) return entry.autodrain();\n"
            "entry.pipe(fs.createWriteStream(target));"
        ),
        helper="resolveInside",
        prompt_tokens=("path.sep", "res.sendFile", "root option"),
    ),
    "go": _Lang(
        lang="go",
        file="internal/handlers/download.go",
        rules=(
            ("go/path-injection", ("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99")),
            ("config.opengrep-rules.go.lang.security.filepath-clean-misuse", ("CWE-22",)),
            ("go.lang.security.filepath-clean-misuse.filepath-clean-misuse", ("CWE-22",)),
        ),
        dataflow='r.URL.Query().Get("name") -> filepath.Join(baseDir, name) -> http.ServeFile',
        unguarded=(
            'name := r.URL.Query().Get("name")\nhttp.ServeFile(w, r, filepath.Join(baseDir, name))'
        ),
        guarded=(
            'abs := filepath.Join(baseDir, r.URL.Query().Get("name"))\n'
            "if !strings.HasPrefix(abs, baseDir+string(os.PathSeparator)) {\n"
            '    http.Error(w, "forbidden", http.StatusForbidden)\n'
            "    return\n"
            "}\n"
            "http.ServeFile(w, r, abs)"
        ),
        filename_only=(
            'id, err := strconv.Atoi(r.URL.Query().Get("id"))\n'
            'if err != nil { http.Error(w, "bad id", 400); return }\n'
            'http.ServeFile(w, r, filepath.Join(baseDir, fmt.Sprintf("%d.pdf", id)))'
        ),
        constant='data, err := os.ReadFile("/etc/app/banner.txt")',
        not_a_sink='label := "os.Open(" + r.URL.Query().Get("name") + ")"',
        inert=(
            'candidate := filepath.Join(baseDir, r.URL.Query().Get("name"))\n'
            'log.Printf("resolved %s", candidate) // never opened'
        ),
        zip_rule=("go/zipslip", ("CWE-22",)),
        zip_dataflow="f.Name -> filepath.Join(dest, f.Name) -> os.OpenFile",
        zip_unguarded=(
            "zr, _ := zip.NewReader(upload, size)\n"
            "for _, f := range zr.File {\n"
            "    out, _ := os.OpenFile(filepath.Join(dest, f.Name), os.O_CREATE|os.O_WRONLY, 0o644)\n"
            "    rc, _ := f.Open()\n"
            "    io.Copy(out, rc)\n"
            "}"
        ),
        zip_guarded=(
            "target := filepath.Join(dest, f.Name)\n"
            "if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {\n"
            '    return fmt.Errorf("illegal entry path: %s", f.Name)\n'
            "}\n"
            "out, _ := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)"
        ),
        helper="safeJoin",
        prompt_tokens=("filepath.IsLocal", "strings.HasPrefix", "http.ServeFile"),
    ),
    "csharp": _Lang(
        lang="csharp",
        file="Controllers/DownloadController.cs",
        rules=(
            ("cs/path-injection", ("CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99")),
            (
                "config.opengrep-rules.csharp.lang.security.filesystem.unsafe-path-combine",
                ("CWE-22",),
            ),
            (
                "csharp.lang.security.filesystem.unsafe-path-combine.unsafe-path-combine",
                ("CWE-22",),
            ),
        ),
        dataflow="[FromQuery] name -> Path.Combine(_baseDir, name) -> PhysicalFile",
        unguarded=(
            "public IActionResult Get([FromQuery] string name)\n"
            '    => PhysicalFile(Path.Combine(_baseDir, name), "application/octet-stream");'
        ),
        guarded=(
            "var full = Path.GetFullPath(Path.Combine(_baseDir, name));\n"
            "if (!full.StartsWith(_baseFull + Path.DirectorySeparatorChar, "
            "StringComparison.Ordinal))\n"
            "    return Forbid();\n"
            'return PhysicalFile(full, "application/octet-stream");'
        ),
        filename_only=(
            "if (!Guid.TryParse(id, out var docId)) return BadRequest();\n"
            'return PhysicalFile(Path.Combine(_baseDir, docId + ".pdf"), "application/pdf");'
        ),
        constant='var banner = System.IO.File.ReadAllText("/etc/app/banner.txt");',
        not_a_sink='var label = $"File.ReadAllText({name})";',
        inert=(
            "var candidate = Path.Combine(_baseDir, name);\n"
            '_logger.LogDebug("resolved {Path}", candidate); // never opened'
        ),
        zip_rule=("cs/zipslip", ("CWE-22",)),
        zip_dataflow="entry.FullName -> Path.Combine(dest, entry.FullName) -> ExtractToFile",
        zip_unguarded=(
            "using var archive = new ZipArchive(upload.OpenReadStream());\n"
            "foreach (var entry in archive.Entries)\n"
            "    entry.ExtractToFile(Path.Combine(dest, entry.FullName), overwrite: true);"
        ),
        zip_guarded=(
            "var target = Path.GetFullPath(Path.Combine(dest, entry.FullName));\n"
            "if (!target.StartsWith(destFull + Path.DirectorySeparatorChar, "
            "StringComparison.Ordinal))\n"
            '    throw new IOException("entry outside target dir");\n'
            "entry.ExtractToFile(target, overwrite: true);"
        ),
        helper="PathGuard.ResolveInside",
        prompt_tokens=("Path.GetFullPath", "Path.DirectorySeparatorChar", "Path.GetFileName"),
    ),
}

_LANGS = tuple(_CASES)

# A fully resolved True-Positive assessment (an external value is joined after a
# base, can leave it, meets no guard, and the file is served or written). Cases
# flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_PATH_ACCESS_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_path": {"value": "REACHES", "evidence": ["D1"]},
    "path_escape": {"value": "ESCAPE_PATH_FOUND", "evidence": ["L1"]},
    "defense_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
    "security_effect": {"value": "SECURITY_RELEVANT_EFFECT", "evidence": ["L1"]},
    "production_scope": {"value": "PROD", "evidence": ["L1"]},
}
_UNRESOLVED = {"value": "UNRESOLVED", "evidence": []}


def _policy(lang):
    return _REG.resolve_family(cwe_ids=["CWE-22"], rule_id="", lang=lang)


def _finding(case: _Lang, rule=None, *, line=20, dataflow=None):
    rule_id, cwes = rule or case.rules[0]
    return Finding(
        rule_id=rule_id,
        message="m",
        file=case.file,
        start_line=line,
        end_line=line,
        repo_name="synthetic",
        lang=case.lang,
        cwe_ids=list(cwes),
        dataflow_path=(dataflow or case.dataflow).split(" -> "),
    )


def _q(rule_id="path"):
    return GuidedQuestions(rule_id=rule_id, short_description="d", questions=["q?"])


def _seeded(case: _Lang, snippet: str, dataflow=None, *, line=20):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("synthetic", case.lang, case.file, line, line + snippet.count("\n")), snippet
    )
    led.add_scanner_dataflow(dataflow or case.dataflow)
    return led


def _assess(overrides=None, requests=None, **extra):
    slots = {k: dict(v) for k, v in _BASE.items()}
    slots.update(overrides or {})
    raw = {"fact_slots": slots, "reasoning": "assessed", **extra}
    if requests:
        raw["evidence_requests"] = requests
    return json.dumps(raw)


def _resp(content):
    choice = MagicMock()
    choice.message.content = content
    r = MagicMock()
    r.choices = [choice]
    return r


class _FakeProvider:
    def __init__(self, status, *, exhaustive=True, kind=EvidenceKind.FUNCTION):
        self._status, self._exhaustive, self._kind = status, exhaustive, kind

    def resolve_evidence(self, repo_name, lang, requests):
        out = {}
        for r in requests:
            out[r.raw_request] = EvidenceResult(
                request=r,
                status=self._status,
                prompt_content="// helper body",
                scope=EvidenceScope.REPOSITORY_INDEX,
                exhaustive=self._exhaustive,
            )
        return out


def _run(mock_completion, responses, case, snippet, *, finding=None, provider=None):
    mock_completion.side_effect = [_resp(r) for r in responses]
    finding = finding or _finding(case)
    controller = PolicyClosureController(
        policy=_REG.resolve_family(
            cwe_ids=finding.cwe_ids, rule_id=finding.rule_id, lang=finding.lang
        ),
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(case, snippet, " -> ".join(finding.dataflow_path)),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    verdict = client.analyze(
        finding=finding,
        context=snippet,
        questions=_q(finding.rule_id),
        func_name="handler",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=5,
        quiet=True,
    )
    return verdict, controller


def _override(slot, value, evidence=("L1",)):
    return {slot: {"value": value, "evidence": list(evidence)}}


# ── selection ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_selected_for_every_panel_rule(lang):
    case = _CASES[lang]
    for rule_id, cwes in (*case.rules, case.zip_rule):
        policy = _REG.resolve_family(cwe_ids=list(cwes), rule_id=rule_id, lang=lang)
        assert policy is not None and policy.family == f"path_access_{lang}", rule_id


# ── synthetic True/False Positive panel ───────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_unguarded_traversal_is_true_positive_for_each_rule_id_form(mc, lang):
    case = _CASES[lang]
    for rule in case.rules:
        verdict, controller = _run(
            mc, [_assess()], case, case.unguarded, finding=_finding(case, rule)
        )
        assert verdict.verdict == TP, rule
        assert controller.last_decision.family == f"path_access_{lang}"
        assert f"[policy:path_access_{lang} entailed]" in verdict.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_false_positive_panel(mc, lang):
    case = _CASES[lang]
    panel = [
        # canonicalise + containment test on the only path, visible in the slice
        (case.guarded, _override("defense_coverage", "ALL_REACHING_PATHS")),
        # the value can only select a fixed name / a typed id / one safe segment
        (case.filename_only, _override("path_escape", "CONFINED_ALL_PATHS")),
        # constant path: nothing external supplies it
        (case.constant, _override("attacker_control", "REFUTED")),
        # the flagged expression only builds a string
        (case.not_a_sink, _override("sink_binding", "NOT_PATH_ACCESS_SINK")),
        # the path is built and logged, never used for a file operation
        (case.inert, _override("security_effect", "NO_SECURITY_EFFECT")),
        # the value is overwritten by a constant before use on every path
        (case.constant, _override("flow_to_path", "NO_PATH_COMPLETE")),
    ]
    for snippet, override in panel:
        verdict, controller = _run(mc, [_assess(overrides=override)], case, snippet)
        slot = next(iter(override))
        assert verdict.verdict == FP, (slot, snippet)
        assert f"{slot}={override[slot]['value']}" in controller.last_decision.terminal_reason


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_single_safe_fact_dismisses_with_other_slots_unresolved(mc, lang):
    # A guard proven on every path dismisses even when the model could not
    # resolve the remaining positive slots.
    case = _CASES[lang]
    overrides = {
        "defense_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]},
        "path_escape": dict(_UNRESOLVED),
        "security_effect": dict(_UNRESOLVED),
    }
    verdict, _ = _run(mc, [_assess(overrides=overrides)], case, case.guarded)
    assert verdict.verdict == FP


# ── archive extraction ("zip slip" / "tar slip") ──────────────────────


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_archive_entry_written_outside_destination_is_true_positive(mc, lang):
    case = _CASES[lang]
    finding = _finding(case, case.zip_rule, dataflow=case.zip_dataflow)
    # The archive is an upload (visible in the slice), so control cites L1.
    overrides = _override("attacker_control", "PROVEN")
    verdict, controller = _run(
        mc, [_assess(overrides=overrides)], case, case.zip_unguarded, finding=finding
    )
    assert verdict.verdict == TP
    assert controller.last_decision.family == f"path_access_{lang}"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_archive_entry_confined_before_write_is_false_positive(mc, lang):
    case = _CASES[lang]
    finding = _finding(case, case.zip_rule, dataflow=case.zip_dataflow)
    verdict, _ = _run(
        mc,
        [_assess(overrides=_override("defense_coverage", "ALL_REACHING_PATHS"))],
        case,
        case.zip_guarded,
        finding=finding,
    )
    assert verdict.verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_archive_of_unknown_origin_is_needs_more_data(mc, lang):
    # The scanner flow starts at the entry name; where the archive comes from is
    # not in evidence, so attacker_control stays unresolved.
    case = _CASES[lang]
    finding = _finding(case, case.zip_rule, dataflow=case.zip_dataflow)
    verdict, controller = _run(
        mc,
        [_assess(overrides={"attacker_control": dict(_UNRESOLVED)})],
        case,
        case.zip_unguarded,
        finding=finding,
    )
    assert verdict.verdict == NMD
    assert controller.last_decision.terminal_reason == "unresolved: attacker_control"


# ── fail-closed evidence handling ─────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_no_guard_seen_without_escape_and_effect_is_needs_more_data(mc, lang):
    case = _CASES[lang]
    overrides = {"path_escape": dict(_UNRESOLVED), "security_effect": dict(_UNRESOLVED)}
    verdict, controller = _run(mc, [_assess(overrides=overrides)], case, case.unguarded)
    assert verdict.verdict == NMD
    assert controller.last_decision.terminal_reason == "unresolved: path_escape, security_effect"


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("slot", sorted(k for k in _BASE if k != "production_scope"))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_each_unresolved_decisive_slot_is_needs_more_data(mc, slot, lang):
    case = _CASES[lang]
    verdict, controller = _run(
        mc, [_assess(overrides={slot: dict(_UNRESOLVED)})], case, case.unguarded
    )
    assert verdict.verdict == NMD
    assert slot in verdict.reasoning
    assert controller.last_decision.terminal_reason == f"unresolved: {slot}"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_guard_from_non_exhaustive_retrieval_is_needs_more_data(mc, lang):
    # An ALL_REACHING_PATHS claim supported only by a non-exhaustive retrieved
    # helper is inadmissible, so the finding is not dismissed.
    case = _CASES[lang]
    responses = [
        _assess(
            overrides={"defense_coverage": dict(_UNRESOLVED)},
            requests=[{"kind": "function", "subject": case.helper, "for_slot": "defense_coverage"}],
        ),
        _assess(overrides=_override("defense_coverage", "ALL_REACHING_PATHS", ["R1"])),
    ]
    verdict, _ = _run(
        mc,
        responses,
        case,
        case.unguarded,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False),
    )
    assert verdict.verdict == NMD
    assert mc.call_count == 2  # the retrieval round really ran
    assert "defense_coverage" in verdict.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_guard_from_exhaustive_retrieval_dismisses(mc, lang):
    case = _CASES[lang]
    responses = [
        _assess(
            overrides={"defense_coverage": dict(_UNRESOLVED)},
            requests=[{"kind": "function", "subject": case.helper, "for_slot": "defense_coverage"}],
        ),
        _assess(overrides=_override("defense_coverage", "ALL_REACHING_PATHS", ["R1"])),
    ]
    verdict, _ = _run(
        mc,
        responses,
        case,
        case.unguarded,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert verdict.verdict == FP
    assert mc.call_count == 2  # the retrieval round really ran


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_framework_marker_retrieval_cannot_establish_the_guard(mc, lang):
    # Framework-sanitizer evidence is never valid all-paths coverage, even when
    # it is marked exhaustive.
    case = _CASES[lang]
    responses = [
        _assess(
            overrides={"defense_coverage": dict(_UNRESOLVED)},
            requests=[
                {
                    "kind": "framework_sanitizers",
                    "subject": "path",
                    "for_slot": "defense_coverage",
                }
            ],
        ),
        _assess(overrides=_override("defense_coverage", "ALL_REACHING_PATHS", ["R1"])),
    ]
    verdict, _ = _run(
        mc,
        responses,
        case,
        case.unguarded,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert verdict.verdict == NMD
    assert mc.call_count == 2  # the retrieval round really ran


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("defense_coverage", "ALL_REACHING_PATHS"),
        ("path_escape", "CONFINED_ALL_PATHS"),
        ("attacker_control", "REFUTED"),
        ("sink_binding", "NOT_PATH_ACCESS_SINK"),
        ("security_effect", "NO_SECURITY_EFFECT"),
    ],
)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_safe_value_cited_only_by_scanner_dataflow_does_not_dismiss(mc, slot, value, lang):
    # A dismissing value needs local proof; the scanner flow alone is not it.
    case = _CASES[lang]
    verdict, controller = _run(
        mc, [_assess(overrides=_override(slot, value, ["D1"]))], case, case.unguarded
    )
    assert verdict.verdict == NMD
    assert controller.last_decision.terminal_reason == f"unresolved: {slot}"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_needs_more_data_with_reason(mc, lang):
    case = _CASES[lang]
    responses = [
        _assess(
            overrides={"flow_to_path": dict(_UNRESOLVED)},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_path"}],
        ),
        _assess(overrides=_override("flow_to_path", "NO_PATH_COMPLETE", ["R1"])),
    ]
    verdict, _ = _run(
        mc, responses, case, case.unguarded, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX)
    )
    assert verdict.verdict == NMD
    assert mc.call_count == 2  # the retrieval round really ran
    assert "flow_to_path" in verdict.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, lang):
    case = _CASES[lang]
    # The model asserts a verdict that contradicts its own facts; the table decides.
    verdict, _ = _run(
        mc,
        [
            _assess(
                overrides=_override("defense_coverage", "ALL_REACHING_PATHS"),
                verdict="True Positive",
            )
        ],
        case,
        case.guarded,
    )
    assert verdict.verdict == FP
    verdict, _ = _run(
        mc,
        [_assess(overrides={"path_escape": dict(_UNRESOLVED)}, verdict="True Positive")],
        case,
        case.unguarded,
    )
    assert verdict.verdict == NMD


# ── rendered prompt ───────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:is\s+)?(?:a\s+)?(?:False|True)\s+Positive|the rule is likely correct",
    re.IGNORECASE,
)
_PAREN_LABEL = re.compile(r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)", re.IGNORECASE)
_BENCHMARK = re.compile(r"OWASP|Juliet|DVWA|WebGoat|NodeGoat|FP trap|FP case", re.IGNORECASE)


@pytest.mark.parametrize("lang", _LANGS)
def test_overlay_has_path_slots_guidance_and_no_verdict_command(lang):
    case = _CASES[lang]
    policy = _policy(lang)
    controller = PolicyClosureController(
        policy=policy,
        provider=MagicMock(),
        finding=_finding(case),
        model="gpt-4o",
        ledger=_seeded(case, case.unguarded),
    )
    instr = controller.initial_instructions()
    for slot in policy.fact_slots:
        assert slot in instr
    for entry in policy.assessment_guidance:
        assert entry in instr
    for token in case.prompt_tokens:
        assert token in instr, token
    assert "[L1]" in instr and "[D1]" in instr
    assert "Do NOT decide a free-text verdict" in instr
    assert not _VERDICT_CMD.search(instr)
    assert not _PAREN_LABEL.search(instr)
    assert not _BENCHMARK.search(instr)


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_prompt_sent_to_the_model_carries_the_family_guidance(mc, lang):
    case = _CASES[lang]
    _run(mc, [_assess()], case, case.unguarded)
    messages = mc.call_args.kwargs["messages"]
    sent = "\n".join(str(m["content"]) for m in messages)
    policy = _policy(lang)
    for entry in policy.assessment_guidance:
        assert entry in sent
    assert "Evidence-closure assessment (REQUIRED response format)" in sent
    assert not _VERDICT_CMD.search(sent)
    assert not _BENCHMARK.search(sent)
