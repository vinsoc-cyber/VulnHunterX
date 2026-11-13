# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic code-injection (CWE-94/95) acceptance panel — Java and Python.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

All fixtures are synthetic. Per language the panel covers: attacker text reaching
an evaluator (TP), a template SOURCE built from input (TP), an emptied-builtins /
blocklist "sandbox" (TP: a witnessed bypass), a fixed program with the value
bound as data (FP), a finite allowlist on the code-text path (FP), a constant
expression flagged by an audit rule (FP), a call that is not an evaluator (FP),
and a real restricted evaluator, which establishes neither coverage value and
therefore abstains (NMD).

Scripted tests prove policy/control correctness, NOT model semantic quality.
"""

from __future__ import annotations

import json
import re
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
_FAMILIES = {"java": "code_injection_java", "python": "code_injection_python"}

# A fully-resolved True-Positive assessment. Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_CODE_EVALUATION_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "interpreter_channel": {"value": "CODE_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}


def _flip(slot, value, evidence=("L1",)):
    return {slot: {"value": value, "evidence": list(evidence)}}


_UNRESOLVED_COVERAGE = {"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}}

# (id, lang, rule, cwes, snippet, dataflow, overrides, expected verdict)
_PANEL = [
    # ── Java ──────────────────────────────────────────────────────────
    (
        "java-spel-concat",
        "java",
        "java/spel-expression-injection",
        ["CWE-94"],
        'String expr = request.getParameter("expr");\n'
        "Object v = new SpelExpressionParser().parseExpression(expr).getValue();",
        'request.getParameter("expr") -> parseExpression',
        None,
        "True Positive",
    ),
    (
        "java-script-engine-concat",
        "java",
        "config.opengrep-rules.java.lang.security.audit.script-engine-injection",
        ["CWE-94"],
        'ScriptEngine js = new ScriptEngineManager().getEngineByName("js");\n'
        'js.eval("var total = " + request.getParameter("qty") + " * price;");',
        'request.getParameter("qty") -> ScriptEngine.eval',
        None,
        "True Positive",
    ),
    (
        "java-velocity-template-source",
        "java",
        "vulnhunterx.java.template-injection",
        ["CWE-917", "CWE-1336"],
        'String body = req.getParameter("template");\n'
        'Velocity.evaluate(context, writer, "mail", body);',
        'req.getParameter("template") -> Velocity.evaluate',
        None,
        "True Positive",
    ),
    (
        "java-mvel-keyword-blocklist",
        "java",
        "java/mvel-expression-injection",
        ["CWE-94"],
        'if (rule.contains("Runtime") || rule.contains("exec")) throw new BadRule();\n'
        "Object out = MVEL.eval(rule, vars);",
        "@RequestParam rule -> MVEL.eval",
        None,
        "True Positive",
    ),
    (
        "java-spel-bound-variable",
        "java",
        "java.spring.security.audit.spel-injection.spel-injection",
        ["CWE-94"],
        'ctx.setVariable("name", request.getParameter("name"));\n'
        'Object v = parser.parseExpression("#name.length() > 3").getValue(ctx);',
        'request.getParameter("name") -> EvaluationContext.setVariable',
        _flip("interpreter_channel", "DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "java-freemarker-fixed-template-model-value",
        "java",
        "java/server-side-template-injection",
        ["CWE-94", "CWE-1336"],
        'model.put("user", request.getParameter("user"));\n'
        'cfg.getTemplate("welcome.ftl").process(model, out);',
        'request.getParameter("user") -> Template.process',
        _flip("interpreter_channel", "DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "java-jexl-exact-match-allowlist",
        "java",
        "java/jexl-expression-injection",
        ["CWE-94"],
        'private static final Set<String> FORMULAS = Set.of("a + b", "a - b", "a * b");\n'
        "if (!FORMULAS.contains(formula)) throw new IllegalArgumentException();\n"
        "Object r = jexl.createExpression(formula).evaluate(ctx);",
        "@RequestParam formula -> createExpression",
        _flip("neutralization_coverage", "ALL_REACHING_PATHS"),
        "False Positive",
    ),
    (
        "java-groovy-constant-script",
        "java",
        "config.opengrep-rules.java.lang.security.audit.dangerous-groovy-shell",
        ["CWE-94"],
        'private static final String SCRIPT = "return 6 * 7";\n'
        "Object answer = new GroovyShell().evaluate(SCRIPT);",
        "SCRIPT -> GroovyShell.evaluate",
        _flip("attacker_control", "REFUTED"),
        "False Positive",
    ),
    (
        "java-regex-compile-is-not-an-evaluator",
        "java",
        "java.lang.security.audit.el-injection.el-injection",
        ["CWE-94"],
        'Pattern p = Pattern.compile(request.getParameter("q"));',
        'request.getParameter("q") -> Pattern.compile',
        _flip("sink_binding", "NOT_CODE_EVALUATION_SINK"),
        "False Positive",
    ),
    (
        "java-spel-simple-evaluation-context",
        "java",
        "java/spel-expression-injection",
        ["CWE-94"],
        "EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();\n"
        'Object v = parser.parseExpression(request.getParameter("f")).getValue(ctx, order);',
        'request.getParameter("f") -> parseExpression',
        _UNRESOLVED_COVERAGE,
        "Needs More Data",
    ),
    # ── Python ────────────────────────────────────────────────────────
    (
        "py-eval-request-arg",
        "python",
        "py/code-injection",
        ["CWE-94", "CWE-95", "CWE-116"],
        "expr = request.args['expr']\nresult = eval(expr)",
        "request.args['expr'] -> eval",
        None,
        "True Positive",
    ),
    (
        "py-exec-format-string",
        "python",
        "python.django.security.injection.code.user-exec-format-string.user-exec-format-string",
        ["CWE-95"],
        "code = 'result = compute(%s)' % request.POST['arg']\nexec(code, namespace)",
        "request.POST['arg'] -> exec",
        None,
        "True Positive",
    ),
    (
        "py-render-template-string-source",
        "python",
        "config.opengrep-rules.python.flask.security.audit.render-template-string",
        ["CWE-96"],
        "name = request.args.get('name', '')\n"
        "return render_template_string('<h1>Hello ' + name + '</h1>')",
        "request.args.get('name') -> render_template_string",
        None,
        "True Positive",
    ),
    (
        "py-eval-emptied-builtins",
        "python",
        "python.flask.security.injection.user-eval.eval-injection",
        ["CWE-95"],
        "value = eval(request.form['formula'], {'__builtins__': {}}, {})",
        "request.form['formula'] -> eval",
        None,
        "True Positive",
    ),
    (
        "py-render-template-context-value",
        "python",
        "py/template-injection",
        ["CWE-74"],
        "return render_template_string('<h1>Hello {{ name }}</h1>', name=request.args['name'])",
        "request.args['name'] -> render_template_string",
        _flip("interpreter_channel", "DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "py-literal-eval",
        "python",
        "py/code-injection",
        ["CWE-94", "CWE-95", "CWE-116"],
        "import ast\npoint = ast.literal_eval(request.args['point'])",
        "request.args['point'] -> ast.literal_eval",
        _flip("interpreter_channel", "DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "py-operator-allowlist",
        "python",
        "config.opengrep-rules.python.flask.security.injection.eval-injection",
        ["CWE-95"],
        "op = request.args['op']\n"
        "if op not in {'+', '-', '*'}:\n    abort(400)\n"
        "result = eval(f'{a!r} {op} {b!r}')",
        "request.args['op'] -> eval",
        _flip("neutralization_coverage", "ALL_REACHING_PATHS"),
        "False Positive",
    ),
    (
        "py-eval-detected-on-a-literal",
        "python",
        "python.lang.security.audit.eval-detected.eval-detected",
        ["CWE-95"],
        'DEFAULT_LIMITS = eval(\'{"cpu": 2, "mem": 512}\')',
        "literal -> eval",
        _flip("attacker_control", "REFUTED"),
        "False Positive",
    ),
    (
        "py-model-eval-is-not-an-evaluator",
        "python",
        "config.opengrep-rules.python.lang.security.audit.eval-detected",
        ["CWE-95"],
        "model = load_checkpoint(path)\nmodel.eval()",
        "path -> model.eval",
        _flip("sink_binding", "NOT_CODE_EVALUATION_SINK"),
        "False Positive",
    ),
    (
        "py-jinja-sandboxed-environment",
        "python",
        "vulnhunterx.python.template-injection",
        ["CWE-917", "CWE-1336"],
        "env = SandboxedEnvironment()\n"
        "return env.from_string(request.form['body']).render(user=user)",
        "request.form['body'] -> from_string",
        _UNRESOLVED_COVERAGE,
        "Needs More Data",
    ),
]

_SAMPLE = {
    "java": next(c for c in _PANEL if c[0] == "java-spel-concat"),
    "python": next(c for c in _PANEL if c[0] == "py-eval-request-arg"),
}
_EXT = {"java": "java", "python": "py"}


def _finding(lang, rule, cwes, dataflow):
    source, sink = dataflow.split(" -> ")
    return Finding(
        rule_id=rule,
        message="m",
        file=f"app/handler.{_EXT[lang]}",
        start_line=20,
        end_line=20,
        repo_name="synthetic",
        lang=lang,
        cwe_ids=list(cwes),
        dataflow_path=[source, sink],
    )


def _q(rule):
    return GuidedQuestions(rule_id=rule, short_description="d", questions=["q?"])


def _seeded(finding, snippet, dataflow):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("synthetic", finding.lang, finding.file, 18, 24),
        snippet,
    )
    led.add_scanner_dataflow(dataflow)
    return led


def _assess(overrides=None, requests=None):
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
    def __init__(self, status, *, exhaustive=True, kind=EvidenceKind.FUNCTION):
        self._status, self._exhaustive, self._kind = status, exhaustive, kind

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


def _controller(case, provider=None):
    _id, lang, rule, cwes, snippet, dataflow, _overrides, _expected = case
    finding = _finding(lang, rule, cwes, dataflow)
    policy = _REG.resolve_family(cwe_ids=finding.cwe_ids, rule_id=rule, lang=lang)
    assert policy is not None and policy.family == _FAMILIES[lang], rule
    controller = PolicyClosureController(
        policy=policy,
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(finding, snippet, dataflow),
        max_retrieval_rounds=2,
    )
    return finding, controller


def _run(mock_completion, responses, case, *, provider=None, max_iterations=5):
    mock_completion.side_effect = [_resp(r) for r in responses]
    finding, controller = _controller(case, provider)
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding,
        context=case[4],
        questions=_q(case[2]),
        func_name="h",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=max_iterations,
        quiet=True,
    )


# ── the synthetic panel ───────────────────────────────────────────────


@pytest.mark.parametrize("case", _PANEL, ids=[c[0] for c in _PANEL])
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_panel(mc, case):
    verdict = _run(mc, [_assess(overrides=case[6])], case)
    assert verdict.verdict == case[7]
    assert f"[policy:{_FAMILIES[case[1]]} " in verdict.reasoning


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_panel_has_every_outcome_per_language(lang):
    outcomes = {c[7] for c in _PANEL if c[1] == lang}
    assert outcomes == {"True Positive", "False Positive", "Needs More Data"}


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, lang):
    # The model asserts a verdict; only the fact table decides.
    raw = json.loads(_assess(overrides=_flip("interpreter_channel", "DATA_ONLY_ALL_PATHS")))
    raw["verdict"] = "True Positive"
    assert _run(mc, [json.dumps(raw)], _SAMPLE[lang]).verdict == "False Positive"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_coverage_claim_without_code_text_path_is_nmd(mc, lang):
    overrides = {
        "interpreter_channel": {"value": "UNRESOLVED", "evidence": []},
        **_flip("neutralization_coverage", "ALL_REACHING_PATHS"),
    }
    verdict = _run(mc, [_assess(overrides=overrides)] * 5, _SAMPLE[lang])
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_data_only_claim_cited_to_dataflow_only_is_nmd(mc, lang):
    # "Safe on all paths" needs the construction itself (local slice or an
    # exhaustive retrieval); the scanner dataflow witnesses one path only.
    overrides = _flip("interpreter_channel", "DATA_ONLY_ALL_PATHS", evidence=("D1",))
    verdict = _run(mc, [_assess(overrides=overrides)] * 5, _SAMPLE[lang])
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_allowlist_helper_non_exhaustive_is_nmd(mc, lang):
    # An ALL_REACHING_PATHS claim supported only by a non-exhaustive retrieved
    # helper is inadmissible -> stays Needs More Data.
    responses = [
        _assess(
            overrides=_UNRESOLVED_COVERAGE,
            requests=[
                {
                    "kind": "function",
                    "subject": "is_allowed_expression",
                    "for_slot": "neutralization_coverage",
                }
            ],
        ),
        _assess(overrides=_flip("neutralization_coverage", "ALL_REACHING_PATHS", ("R1",))),
    ]
    verdict = _run(
        mc,
        responses,
        _SAMPLE[lang],
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False),
    )
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_allowlist_helper_exhaustive_is_fp(mc, lang):
    responses = [
        _assess(
            overrides=_UNRESOLVED_COVERAGE,
            requests=[
                {
                    "kind": "function",
                    "subject": "is_allowed_expression",
                    "for_slot": "neutralization_coverage",
                }
            ],
        ),
        _assess(overrides=_flip("neutralization_coverage", "ALL_REACHING_PATHS", ("R1",))),
    ]
    verdict = _run(
        mc,
        responses,
        _SAMPLE[lang],
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert verdict.verdict == "False Positive"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, lang):
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides=_flip("flow_to_sink", "REACHES", ("R1",))),
    ]
    verdict = _run(
        mc, responses, _SAMPLE[lang], provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX)
    )
    assert verdict.verdict == "Needs More Data"
    assert "flow_to_sink" in verdict.reasoning


# ── rendered prompt ───────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct", re.IGNORECASE
)
_PAREN_LABEL = re.compile(r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)", re.IGNORECASE)
_BENCHMARK = re.compile(r"OWASP Benchmark|Juliet|BenchmarkTest|SecLLMHolmes|DVWA", re.IGNORECASE)
_LANGUAGE_MARKERS = {
    "java": ("ScriptEngine.eval", "SimpleEvaluationContext", "Velocity.evaluate"),
    "python": ("ast.literal_eval", "render_template_string", "SandboxedEnvironment"),
}


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_overlay_carries_the_family_guidance_and_no_verdict_command(lang):
    _finding_, controller = _controller(_SAMPLE[lang])
    instr = controller.initial_instructions()
    for slot in _BASE:
        assert slot in instr
    assert "production_scope" in instr
    assert "security_effect" not in instr
    assert "[L1]" in instr and "[D1]" in instr
    for marker in _LANGUAGE_MARKERS[lang]:
        assert marker in instr, marker
    for other in set(_LANGUAGE_MARKERS) - {lang}:
        assert _LANGUAGE_MARKERS[other][0] not in instr
    policy = _REG.resolve_family(cwe_ids=[], rule_id=_SAMPLE[lang][2], lang=lang)
    guidance = " ".join(policy.assessment_guidance)
    assert policy.assessment_guidance[0] in instr
    for text in (instr, guidance):
        assert not _VERDICT_CMD.search(text)
        assert not _PAREN_LABEL.search(text)
        assert not _BENCHMARK.search(text)
