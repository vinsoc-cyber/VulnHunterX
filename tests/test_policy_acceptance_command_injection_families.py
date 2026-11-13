# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic acceptance panel for the non-PHP OS command-injection families
(``command_injection_{java,python,javascript,go,csharp,cpp}``).

Drives the full policy path — ``analyze()`` + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

Every fixture is synthetic: a short, realistic snippet per language for each
branch of the table —

  shell text, no neutralizer                      -> True Positive
  attacker value in the program position          -> True Positive
  constant command (an audit rule firing)         -> False Positive
  fixed program, bounded data operand, no shell   -> False Positive
  shell text behind a strict allowlist            -> False Positive
  program chosen through a fixed allowlist        -> False Positive
  argument injection into a fixed program         -> Needs More Data

Scripted tests prove policy/control correctness, NOT model semantic quality.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.context.evidence import (
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

_SHELL = "SHELL_COMMAND_TEXT_PATH_FOUND"
_EXE = "EXECUTABLE_CONTROL_PATH_FOUND"
_FIXED = "FIXED_EXEC_DATA_OPERANDS_ONLY_ALL_PATHS"

# A fully-resolved True-Positive assessment (attacker value reaches shell command
# text with no effective neutralizer). Cases flip one or two slots.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_OS_COMMAND_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "command_channel": {"value": _SHELL, "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}

_EXE_CONTROL = {"command_channel": {"value": _EXE, "evidence": ["L1"]}}
_REFUTED = {"attacker_control": {"value": "REFUTED", "evidence": ["L1"]}}
_FIXED_EXEC = {"command_channel": {"value": _FIXED, "evidence": ["L1"]}}
_COVERED = {"neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]}}
_EXE_ALLOWLISTED = {**_EXE_CONTROL, **_COVERED}
# Argument injection: no channel value is established. The scripted model also
# claims "no shell, so everything is neutralized" — which must not dismiss.
_ARG_INJECTION = {"command_channel": {"value": "UNRESOLVED", "evidence": []}, **_COVERED}


@dataclass(frozen=True)
class _Lang:
    family: str
    lang: str
    rule_id: str
    cwes: tuple[str, ...]
    file: str
    dataflow: tuple[str, str]
    marker: str  # a language-specific phrase the rendered guidance must contain
    shell: str
    exe_control: str
    constant: str
    fixed_exec: str
    shell_allowlisted: str
    exe_allowlisted: str
    arg_injection: str


_LANGS = (
    _Lang(
        family="command_injection_java",
        lang="java",
        rule_id="java/command-line-injection",
        cwes=("CWE-78", "CWE-88"),
        file="src/main/java/app/PingController.java",
        dataflow=('request.getParameter("host")', "Runtime.exec"),
        marker="split on whitespace by StringTokenizer",
        shell=(
            'String host = request.getParameter("host");\n'
            'String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + host};\n'
            "Runtime.getRuntime().exec(cmd);"
        ),
        exe_control=(
            'String tool = request.getParameter("tool");\n'
            'new ProcessBuilder(tool, "--version").start();'
        ),
        constant='Runtime.getRuntime().exec(new String[] {"/usr/bin/uptime"});',
        fixed_exec=(
            'int count = Integer.parseInt(request.getParameter("count"));\n'
            'new ProcessBuilder("/bin/ping", "-c", Integer.toString(count), "127.0.0.1").start();'
        ),
        shell_allowlisted=(
            'String host = request.getParameter("host");\n'
            'if (!host.matches("[a-z0-9]+(\\\\.[a-z0-9]+)*")) { throw new BadRequest(); }\n'
            'Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping -c 1 " + host});'
        ),
        exe_allowlisted=(
            'String tool = request.getParameter("tool");\n'
            'if (!Set.of("/usr/bin/uptime", "/usr/bin/df").contains(tool)) { return; }\n'
            "new ProcessBuilder(tool).start();"
        ),
        arg_injection=(
            'String host = request.getParameter("host");\n'
            'Runtime.getRuntime().exec("ping -c 1 " + host);'
        ),
    ),
    _Lang(
        family="command_injection_python",
        lang="python",
        rule_id="py/command-line-injection",
        cwes=("CWE-78", "CWE-88"),
        file="app/views.py",
        dataflow=('request.args["host"]', "subprocess.run"),
        marker="os.system(s); os.popen(s)",
        shell=(
            'host = request.args["host"]\n'
            'subprocess.run(f"ping -c 1 {host}", shell=True, check=True)'
        ),
        exe_control=('tool = request.args["tool"]\nsubprocess.run([tool, "--version"])'),
        constant='subprocess.run("uptime", shell=True)',
        fixed_exec=(
            'count = int(request.args["count"])\n'
            'subprocess.run(["/bin/ping", "-c", str(count), "127.0.0.1"])'
        ),
        shell_allowlisted=(
            'host = request.args["host"]\n'
            'if not re.fullmatch(r"[a-z0-9]+(\\.[a-z0-9]+)*", host):\n'
            "    abort(400)\n"
            'os.system("ping -c 1 " + host)'
        ),
        exe_allowlisted=(
            'tool = request.args["tool"]\n'
            'if tool not in {"/usr/bin/uptime", "/usr/bin/df"}:\n'
            "    abort(400)\n"
            "subprocess.run([tool])"
        ),
        arg_injection=(
            'target = request.args["target"]\nsubprocess.run(["tar", "-czf", "out.tgz", target])'
        ),
    ),
    _Lang(
        family="command_injection_javascript",
        lang="javascript",
        rule_id="js/command-line-injection",
        cwes=("CWE-78", "CWE-88"),
        file="routes/ping.js",
        dataflow=("req.query.host", "child_process.exec"),
        marker="execFile / execFileSync(file, args) and spawn / spawnSync(command, args) run NO",
        shell=(
            "const host = req.query.host;\n"
            "child_process.exec(`ping -c 1 ${host}`, (err, out) => res.send(out));"
        ),
        exe_control=(
            "const tool = req.query.tool;\n"
            "child_process.execFile(tool, ['--version'], (err, out) => res.send(out));"
        ),
        constant="child_process.execSync('uptime');",
        fixed_exec=(
            "const count = parseInt(req.query.count, 10);\n"
            "if (Number.isNaN(count)) return res.sendStatus(400);\n"
            "child_process.execFile('/bin/ping', ['-c', String(count), '127.0.0.1'], cb);"
        ),
        shell_allowlisted=(
            "const host = req.query.host;\n"
            "if (!/^[a-z0-9]+(\\.[a-z0-9]+)*$/.test(host)) return res.sendStatus(400);\n"
            "child_process.exec('ping -c 1 ' + host, cb);"
        ),
        exe_allowlisted=(
            "const tool = req.query.tool;\n"
            "if (!['/usr/bin/uptime', '/usr/bin/df'].includes(tool)) return res.sendStatus(400);\n"
            "child_process.spawn(tool, []);"
        ),
        arg_injection=(
            "const ref = req.query.ref;\nchild_process.execFile('git', ['log', ref], cb);"
        ),
    ),
    _Lang(
        family="command_injection_go",
        lang="go",
        rule_id="go/command-injection",
        cwes=("CWE-78",),
        file="internal/handler/ping.go",
        dataflow=('r.URL.Query().Get("host")', "exec.Command"),
        marker="exec.CommandContext never invoke a shell",
        shell=(
            'host := r.URL.Query().Get("host")\n'
            'out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()'
        ),
        exe_control=(
            'tool := r.URL.Query().Get("tool")\nout, _ := exec.Command(tool, "--version").Output()'
        ),
        constant='out, _ := exec.Command("uptime").Output()',
        fixed_exec=(
            'count, err := strconv.Atoi(r.URL.Query().Get("count"))\n'
            'if err != nil { http.Error(w, "bad", 400); return }\n'
            'exec.Command("/bin/ping", "-c", strconv.Itoa(count), "127.0.0.1").Run()'
        ),
        shell_allowlisted=(
            'host := r.URL.Query().Get("host")\n'
            'if !hostRe.MatchString(host) { http.Error(w, "bad", 400); return } '
            "// hostRe = ^[a-z0-9]+(\\.[a-z0-9]+)*$\n"
            'exec.Command("sh", "-c", "ping -c 1 "+host).Run()'
        ),
        exe_allowlisted=(
            'tool := r.URL.Query().Get("tool")\n'
            'path, ok := map[string]string{"uptime": "/usr/bin/uptime"}[tool]\n'
            "if !ok { return }\n"
            "exec.Command(path).Run()"
        ),
        arg_injection=('ref := r.URL.Query().Get("ref")\nexec.Command("git", "log", ref).Run()'),
    ),
    _Lang(
        family="command_injection_csharp",
        lang="csharp",
        rule_id="cs/command-line-injection",
        cwes=("CWE-78", "CWE-88"),
        file="Controllers/PingController.cs",
        dataflow=('Request.Query["host"]', "Process.Start"),
        marker="Process.Start does not pass anything through a command interpreter by itself",
        shell=(
            'string host = Request.Query["host"];\n'
            'Process.Start("cmd.exe", "/c ping -n 1 " + host);'
        ),
        exe_control=(
            'string tool = Request.Query["tool"];\n'
            "Process.Start(new ProcessStartInfo { FileName = tool, UseShellExecute = false });"
        ),
        constant='Process.Start("ipconfig.exe", "/all");',
        fixed_exec=(
            'if (!int.TryParse(Request.Query["count"], out var count)) return BadRequest();\n'
            'var psi = new ProcessStartInfo("ping.exe") { UseShellExecute = false };\n'
            'psi.ArgumentList.Add("-n"); psi.ArgumentList.Add(count.ToString());\n'
            'psi.ArgumentList.Add("127.0.0.1");\n'
            "Process.Start(psi);"
        ),
        shell_allowlisted=(
            'string host = Request.Query["host"];\n'
            'if (!Regex.IsMatch(host, @"^[a-z0-9]+(\\.[a-z0-9]+)*\\z")) return BadRequest();\n'
            'Process.Start("cmd.exe", "/c ping -n 1 " + host);'
        ),
        exe_allowlisted=(
            'string tool = Request.Query["tool"];\n'
            'if (tool != "ipconfig.exe" && tool != "hostname.exe") return BadRequest();\n'
            "Process.Start(new ProcessStartInfo { FileName = tool, UseShellExecute = false });"
        ),
        arg_injection=(
            'string host = Request.Query["host"];\nProcess.Start("ping.exe", "-n 1 " + host);'
        ),
    ),
    _Lang(
        family="command_injection_cpp",
        lang="c",
        rule_id="cpp/command-line-injection",
        cwes=("CWE-78", "CWE-88"),
        file="src/netdiag.c",
        dataflow=("recv(sock, host, ...)", "system"),
        marker="system(s) runs '/bin/sh -c s' on POSIX",
        shell=(
            "recv(sock, host, sizeof(host) - 1, 0);\n"
            'snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);\n'
            "system(cmd);"
        ),
        exe_control=(
            'recv(sock, tool, sizeof(tool) - 1, 0);\nexecl(tool, tool, "--version", (char *)NULL);'
        ),
        constant='system("uptime");',
        fixed_exec=(
            "long count = strtol(buf, &end, 10);\n"
            "if (*end != '\\0' || count < 1 || count > 10) return -1;\n"
            'snprintf(num, sizeof(num), "%ld", count);\n'
            'execl("/bin/ping", "ping", "-c", num, "127.0.0.1", (char *)NULL);'
        ),
        shell_allowlisted=(
            "for (const char *p = host; *p; p++)\n"
            "    if (!islower((unsigned char)*p) && !isdigit((unsigned char)*p)) return -1;\n"
            'snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);\n'
            "system(cmd);"
        ),
        exe_allowlisted=(
            'if (strcmp(tool, "/usr/bin/uptime") != 0 && strcmp(tool, "/usr/bin/df") != 0)\n'
            "    return -1;\n"
            "execl(tool, tool, (char *)NULL);"
        ),
        arg_injection=(
            "recv(sock, target, sizeof(target) - 1, 0);\n"
            'execlp("tar", "tar", "-czf", "out.tgz", target, (char *)NULL);'
        ),
    ),
    # The C/C++ file is one family for both stage languages.
    _Lang(
        family="command_injection_cpp",
        lang="cpp",
        rule_id="cpp/command-injection",
        cwes=("CWE-77", "CWE-78"),
        file="src/netdiag.cpp",
        dataflow=("std::getline(conn, host)", "popen"),
        marker="popen(s, mode) passes s to the shell",
        shell=(
            "std::getline(conn, host);\n"
            'std::string cmd = "ping -c 1 " + host;\n'
            'FILE *p = popen(cmd.c_str(), "r");'
        ),
        exe_control=(
            "std::getline(conn, tool);\n"
            "char *argv[] = {const_cast<char *>(tool.c_str()), nullptr};\n"
            "posix_spawn(&pid, tool.c_str(), nullptr, nullptr, argv, environ);"
        ),
        constant='FILE *p = popen("uptime", "r");',
        fixed_exec=(
            "int count = std::stoi(text);\n"
            "std::string num = std::to_string(count);\n"
            'execl("/bin/ping", "ping", "-c", num.c_str(), "127.0.0.1", nullptr);'
        ),
        shell_allowlisted=(
            "if (!std::all_of(host.begin(), host.end(),\n"
            "        [](unsigned char c) { return std::islower(c) || std::isdigit(c); })) return;\n"
            'popen(("ping -c 1 " + host).c_str(), "r");'
        ),
        exe_allowlisted=(
            'static const std::set<std::string> kTools = {"/usr/bin/uptime", "/usr/bin/df"};\n'
            "if (!kTools.count(tool)) return;\n"
            "execl(tool.c_str(), tool.c_str(), nullptr);"
        ),
        arg_injection=(
            'std::getline(conn, ref);\nexeclp("git", "git", "log", ref.c_str(), nullptr);'
        ),
    ),
)

_IDS = [spec.lang for spec in _LANGS]
_SPEC = pytest.mark.parametrize("spec", _LANGS, ids=_IDS)

# (name, snippet attribute, slot overrides, expected verdict, attacker data flow?)
_PANEL = (
    ("shell_text_unguarded", "shell", {}, "True Positive", True),
    ("program_position_unrestricted", "exe_control", _EXE_CONTROL, "True Positive", True),
    ("constant_command", "constant", _REFUTED, "False Positive", False),
    ("fixed_program_bounded_operand", "fixed_exec", _FIXED_EXEC, "False Positive", True),
    ("shell_text_strict_allowlist", "shell_allowlisted", _COVERED, "False Positive", True),
    ("program_position_allowlisted", "exe_allowlisted", _EXE_ALLOWLISTED, "False Positive", True),
    ("argument_injection", "arg_injection", _ARG_INJECTION, "Needs More Data", True),
)


def _policy(spec: _Lang):
    return _REG.resolve_family(cwe_ids=list(spec.cwes), rule_id=spec.rule_id, lang=spec.lang)


def _finding(spec: _Lang, line: int = 12) -> Finding:
    return Finding(
        rule_id=spec.rule_id,
        message="m",
        file=spec.file,
        start_line=line,
        end_line=line,
        repo_name="synthetic",
        lang=spec.lang,
        cwe_ids=list(spec.cwes),
        dataflow_path=list(spec.dataflow),
    )


def _q() -> GuidedQuestions:
    return GuidedQuestions(rule_id="cmd", short_description="d", questions=["q?"])


def _seeded(spec: _Lang, snippet: str, *, with_dataflow: bool = True) -> EvidenceLedger:
    led = EvidenceLedger()
    led.add_local_slice(SourceRef("synthetic", spec.lang, spec.file, 12, 16), snippet)
    if with_dataflow:
        led.add_scanner_dataflow(" -> ".join(spec.dataflow))
    return led


def _assess(overrides=None, requests=None) -> str:
    slots = {k: dict(v) for k, v in _BASE.items()}
    for k, v in (overrides or {}).items():
        slots[k] = v
    raw = {"fact_slots": slots, "reasoning": "assessed"}
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
    def __init__(self, status, *, exhaustive=True):
        self._status, self._exhaustive = status, exhaustive

    def resolve_evidence(self, repo_name, lang, requests):
        out = {}
        for r in requests:
            out[r.raw_request] = EvidenceResult(
                request=r,
                status=self._status,
                prompt_content="// helper",
                scope=EvidenceScope.REPOSITORY_INDEX,
                exhaustive=self._exhaustive,
            )
        return out


def _run(mc, responses, spec: _Lang, snippet: str, *, provider=None, with_dataflow=True):
    mc.side_effect = [_resp(r) for r in responses]
    finding = _finding(spec)
    controller = PolicyClosureController(
        policy=_policy(spec),
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(spec, snippet, with_dataflow=with_dataflow),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    verdict = client.analyze(
        finding=finding,
        context=snippet,
        questions=_q(),
        func_name="handler",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=5,
        quiet=True,
    )
    return verdict, controller


# ── selection ────────────────────────────────────────────────────────────────


@_SPEC
def test_family_selected(spec):
    policy = _policy(spec)
    assert policy is not None and policy.family == spec.family


# ── the synthetic TP / FP / NMD panel ────────────────────────────────────────


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_synthetic_panel(mc, spec):
    verdicts = {}
    for name, attr, overrides, _expected, with_dataflow in _PANEL:
        if not with_dataflow:
            # A constant command has no attacker data flow: every claim is local.
            overrides = {
                **overrides,
                "flow_to_sink": {"value": "UNRESOLVED", "evidence": []},
            }
        v, controller = _run(
            mc, [_assess(overrides)], spec, getattr(spec, attr), with_dataflow=with_dataflow
        )
        verdicts[name] = v.verdict
        assert controller.last_decision is not None
        assert controller.last_decision.family == spec.family
    assert verdicts == {name: expected for name, _a, _o, expected, _d in _PANEL}
    counts = {v: sum(1 for x in verdicts.values() if x == v) for v in set(verdicts.values())}
    assert counts == {"True Positive": 2, "False Positive": 4, "Needs More Data": 1}


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_argument_injection_reason_names_the_unresolved_channel(mc, spec):
    v, controller = _run(mc, [_assess(_ARG_INJECTION)], spec, spec.arg_injection)
    assert v.verdict == "Needs More Data"
    assert controller.last_decision.terminal_reason == "unresolved: command_channel"
    assert "command_channel" in v.reasoning


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, spec):
    # The scripted model asserts a verdict the facts do not support; the table decides.
    raw = json.loads(_assess(_FIXED_EXEC))
    raw["verdict"] = "True Positive"
    v, _ = _run(mc, [json.dumps(raw)], spec, spec.fixed_exec)
    assert v.verdict == "False Positive"
    raw = json.loads(_assess())
    raw["verdict"] = "False Positive"
    v, _ = _run(mc, [json.dumps(raw)], spec, spec.shell)
    assert v.verdict == "True Positive"


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_uncited_bypass_claim_is_not_enough_for_tp(mc, spec):
    # "No sanitizer visible" asserted without any cited evidence is inadmissible.
    overrides = {"neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": []}}
    v, controller = _run(mc, [_assess(overrides)], spec, spec.shell)
    assert v.verdict == "Needs More Data"
    assert controller.last_decision.terminal_reason == "unresolved: neutralization_coverage"


# ── fail-closed evidence handling ────────────────────────────────────────────


@_SPEC
@pytest.mark.parametrize(
    ("slot", "value", "extra"),
    [
        ("neutralization_coverage", "ALL_REACHING_PATHS", {}),
        ("neutralization_coverage", "ALL_REACHING_PATHS", _EXE_CONTROL),
        ("command_channel", _FIXED, {}),
    ],
    ids=["shell-coverage", "program-allowlist", "fixed-exec"],
)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_non_exhaustive_all_paths_is_nmd(mc, slot, value, extra, spec):
    # An all-paths claim supported only by a non-exhaustive retrieved helper is
    # inadmissible -> the slot stays unresolved -> Needs More Data.
    responses = [
        _assess(
            overrides={**extra, slot: {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "validate_input", "for_slot": slot}],
        ),
        _assess(overrides={**extra, slot: {"value": value, "evidence": ["R1"]}}),
    ]
    v, controller = _run(
        mc,
        responses,
        spec,
        spec.shell_allowlisted,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False),
    )
    assert v.verdict == "Needs More Data"
    assert controller.last_decision.terminal_reason == f"unresolved: {slot}"


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_exhaustive_all_paths_is_fp(mc, spec):
    # The same claim backed by an exhaustive retrieval is admissible.
    slot = "neutralization_coverage"
    responses = [
        _assess(
            overrides={slot: {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "validate_input", "for_slot": slot}],
        ),
        _assess(overrides={slot: {"value": "ALL_REACHING_PATHS", "evidence": ["R1"]}}),
    ]
    v, _ = _run(
        mc,
        responses,
        spec,
        spec.shell_allowlisted,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert v.verdict == "False Positive"


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, spec):
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides={"flow_to_sink": {"value": "REACHES", "evidence": ["R1"]}}),
    ]
    v, _ = _run(
        mc, responses, spec, spec.shell, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX)
    )
    assert v.verdict == "Needs More Data"
    assert "flow_to_sink" in v.reasoning


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_cannot_prove_no_path(mc, spec):
    # An incomplete index is not a complete absence: NO_PATH_COMPLETE is refused.
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides={"flow_to_sink": {"value": "NO_PATH_COMPLETE", "evidence": ["R1"]}}),
    ]
    v, _ = _run(
        mc, responses, spec, spec.shell, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX)
    )
    assert v.verdict == "Needs More Data"


# ── the rendered prompt ──────────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct"
    r"|\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)",
    re.IGNORECASE,
)


@_SPEC
def test_overlay_has_family_slots_and_guidance_and_no_verdict_command(spec):
    policy = _policy(spec)
    controller = PolicyClosureController(
        policy=policy,
        provider=MagicMock(),
        finding=_finding(spec),
        model="gpt-4o",
        ledger=_seeded(spec, spec.shell),
    )
    instr = controller.initial_instructions()
    assert f"command_channel: {_SHELL}, {_EXE}, {_FIXED} | UNRESOLVED" in instr
    assert "neutralization_coverage: BYPASS_PATH_FOUND, ALL_REACHING_PATHS | UNRESOLVED" in instr
    assert "security_effect" not in instr
    assert "[L1]" in instr and "[D1]" in instr
    for guidance in policy.assessment_guidance:
        assert guidance in instr
    assert spec.marker in instr
    assert "argument injection, CWE-88" in instr
    assert not _VERDICT_CMD.search(instr), _VERDICT_CMD.search(instr)


@_SPEC
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_prompt_sent_to_the_model_carries_the_family_guidance(mc, spec):
    _run(mc, [_assess()], spec, spec.shell)
    messages = mc.call_args_list[0].kwargs["messages"]
    sent = "\n".join(str(m.get("content", "")) for m in messages)
    assert "Evidence-closure assessment (REQUIRED response format)" in sent
    assert spec.marker in sent
    assert _EXE in sent
    assert spec.shell.splitlines()[0] in sent
