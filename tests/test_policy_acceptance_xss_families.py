# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic acceptance panel for the cross-site scripting families
(``xss_java``, ``xss_python``).

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

Every fixture is synthetic: a short, realistic snippet seeded as the local
slice, with the fact values a careful reading of that snippet gives. The panel
covers, per language: reflected output with no encoder, an encoder that does not
match its output context, a context-appropriate encoder, a non-markup response,
a mislocated sink, a constant value, a stored value with no write path in
evidence, a helper or template that is not in evidence, and the evidence shapes
that must not dismiss (a non-exhaustive retrieval, a framework-sanitizer lookup,
an incomplete index).

Scripted tests prove policy/control correctness, NOT model semantic quality.
"""

from __future__ import annotations

import json
import re
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
_FAMILIES = {"java": "xss_java", "python": "xss_python"}
_LANGS = sorted(_FAMILIES)
_DEFAULT_RULE = {"java": "java/xss", "python": "py/reflective-xss"}
_DEFAULT_FILE = {"java": "src/main/java/app/GreetServlet.java", "python": "app/views.py"}
_DEFAULT_SNIPPET = {
    "java": (
        'String name = request.getParameter("name");\n'
        'response.setContentType("text/html");\n'
        'response.getWriter().println("<p>Hello " + name + "</p>");'
    ),
    "python": (
        '@app.route("/greet")\n'
        "def greet():\n"
        '    name = request.args.get("name", "")\n'
        '    return f"<p>Hello {name}</p>"'
    ),
}
_DEFAULT_FLOW = {
    "java": 'request.getParameter("name") -> PrintWriter.println',
    "python": "request.args.get -> return",
}

# A fully-resolved True-Positive assessment (an attacker value enters markup
# with no context-appropriate encoder). Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_HTML_OUTPUT_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "output_channel": {"value": "MARKUP_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "encoding_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}
_UNRESOLVED = {"value": "UNRESOLVED", "evidence": []}

_TP, _FP, _NMD = "True Positive", "False Positive", "Needs More Data"


def _local(slot, value):
    return {slot: {"value": value, "evidence": ["L1"]}}


# (case id, rule id, snippet, slot overrides, expected verdict)
_PANEL = {
    "java": [
        (
            "servlet_reflects_parameter_into_html",
            "java/xss",
            _DEFAULT_SNIPPET["java"],
            {},
            _TP,
        ),
        (
            "semgrep_servlet_writer_registry_id",
            "java.lang.security.servletresponse-writer-xss.servletresponse-writer-xss",
            'String q = req.getParameter("q");\nresp.getWriter().write("<b>" + q + "</b>");',
            {},
            _TP,
        ),
        (
            "spring_response_body_html_string_vendored_id",
            "config.opengrep-rules.java.spring.security.injection.tainted-html-string",
            '@GetMapping("/hi") @ResponseBody\n'
            "public String hi(@RequestParam String who) {\n"
            '    return "<h1>Hi " + who + "</h1>";\n}',
            {},
            _TP,
        ),
        (
            # escapeHtml4 leaves the single quote, and entity encoding does not
            # match a JavaScript-string context: the encoder is present but the
            # path is still a witnessed bypass.
            "html_escape_inside_single_quoted_js_string",
            "java/xss",
            'String q = request.getParameter("q");\n'
            'out.write("<script>var q = \'" + StringEscapeUtils.escapeHtml4(q) + "\';</script>");',
            {},
            _TP,
        ),
        (
            "encode_for_html_in_element_text",
            "java/xss",
            'String name = request.getParameter("name");\n'
            'response.getWriter().println("<p>Hello " + Encode.forHtml(name) + "</p>");',
            _local("encoding_coverage", "ALL_REACHING_PATHS"),
            _FP,
        ),
        (
            "integer_parsed_value_in_element_text",
            "java/xss",
            'int page = Integer.parseInt(request.getParameter("page"));\n'
            'response.getWriter().println("<span>Page " + page + "</span>");',
            _local("encoding_coverage", "ALL_REACHING_PATHS"),
            _FP,
        ),
        (
            "json_content_type_set_before_write",
            "java/xss",
            'response.setContentType("application/json");\n'
            'response.getWriter().write("{\\"echo\\": \\"" + request.getParameter("m") + "\\"}");',
            {
                **_local("output_channel", "NON_MARKUP_ONLY_ALL_PATHS"),
                "encoding_coverage": _UNRESOLVED,
            },
            _FP,
        ),
        (
            # The audit rule matches any PrintWriter by type.
            "print_writer_wraps_a_file_not_the_response",
            "java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer",
            'PrintWriter audit = new PrintWriter(new FileWriter("/var/log/app/audit.txt", true));\n'
            'audit.println(request.getParameter("user"));',
            {
                **_local("sink_binding", "NOT_HTML_OUTPUT_SINK"),
                "output_channel": _UNRESOLVED,
                "encoding_coverage": _UNRESOLVED,
            },
            _FP,
        ),
        (
            "value_replaced_by_constant_before_write",
            "java/xss",
            'String bar = request.getParameter("bar");\n'
            'bar = "fixed";\n'
            'response.getWriter().println("<p>" + bar + "</p>");',
            _local("attacker_control", "REFUTED"),
            _FP,
        ),
        (
            # Stored value: a repository read alone neither proves nor refutes
            # attacker control; the write path is not in evidence.
            "entity_field_read_without_write_path",
            "java/xss",
            "Comment c = commentRepository.findById(id).orElseThrow();\n"
            'response.getWriter().println("<li>" + c.getBody() + "</li>");',
            {"attacker_control": _UNRESOLVED},
            _NMD,
        ),
        (
            "helper_body_not_in_evidence",
            "java/xss",
            'String name = request.getParameter("name");\n'
            'response.getWriter().println("<p>" + HtmlHelper.clean(name) + "</p>");',
            {"encoding_coverage": _UNRESOLVED},
            _NMD,
        ),
        (
            "content_type_not_visible",
            "java/xss",
            "void render(PrintWriter out, String name) {\n"
            '    out.println("<p>" + name + "</p>");\n}',
            {"output_channel": _UNRESOLVED},
            _NMD,
        ),
    ],
    "python": [
        (
            "flask_view_returns_fstring",
            "py/reflective-xss",
            _DEFAULT_SNIPPET["python"],
            {},
            _TP,
        ),
        (
            "django_httpresponse_registry_id",
            "python.django.security.injection.reflected-data-httpresponse.reflected-data-httpresponse",
            'def search(request):\n    q = request.GET.get("q", "")\n'
            '    return HttpResponse("<h2>Results for " + q + "</h2>")',
            {},
            _TP,
        ),
        (
            "flask_raw_html_concat_registry_id",
            "python.flask.security.injection.raw-html-concat.raw-html-format",
            'who = request.args["who"]\nreturn "<div>" + who + "</div>"',
            {},
            _TP,
        ),
        (
            "markup_wraps_interpolated_fstring_vendored_id",
            "config.opengrep-rules.python.flask.security.xss.audit.explicit-unescape-with-markup",
            'name = request.args.get("name", "")\n'
            'banner = Markup(f"<b>{name}</b>")\n'
            'return render_template_string("{{ banner }}", banner=banner)',
            {},
            _TP,
        ),
        (
            # html.escape is entity encoding; it does not match a URL attribute
            # whose scheme the attacker chooses.
            "html_escape_in_href_attribute",
            "py/reflective-xss",
            'url = request.args.get("next", "")\n'
            "return f'<a href=\"{html.escape(url)}\">continue</a>'",
            {},
            _TP,
        ),
        (
            "html_escape_in_element_text",
            "py/reflective-xss",
            'name = request.args.get("name", "")\nreturn f"<p>Hello {html.escape(name)}</p>"',
            _local("encoding_coverage", "ALL_REACHING_PATHS"),
            _FP,
        ),
        (
            "format_html_static_format_string",
            "python.django.security.audit.avoid-mark-safe.avoid-mark-safe",
            'label = format_html("<b>{}</b>", request.GET.get("label", ""))\n'
            "return HttpResponse(label)",
            _local("encoding_coverage", "ALL_REACHING_PATHS"),
            _FP,
        ),
        (
            "plain_text_mimetype_on_this_response",
            "python.flask.security.audit.xss.make-response-with-unknown-content.make-response-with-unknown-content",
            'resp = make_response(request.args.get("msg", ""))\n'
            'resp.mimetype = "text/plain"\nreturn resp',
            {
                **_local("output_channel", "NON_MARKUP_ONLY_ALL_PATHS"),
                "encoding_coverage": _UNRESOLVED,
            },
            _FP,
        ),
        (
            "jsonify_is_not_an_html_output",
            "py/reflective-xss",
            'return jsonify({"echo": request.args.get("m", "")})',
            {
                **_local("sink_binding", "NOT_HTML_OUTPUT_SINK"),
                "output_channel": _UNRESOLVED,
                "encoding_coverage": _UNRESOLVED,
            },
            _FP,
        ),
        (
            "value_replaced_by_constant_before_return",
            "py/reflective-xss",
            'bar = request.args.get("bar", "")\nbar = "fixed"\nreturn f"<p>{bar}</p>"',
            _local("attacker_control", "REFUTED"),
            _FP,
        ),
        (
            # Auto-escaping is framework behaviour and the template text that
            # places the variable is not in evidence.
            "render_template_with_template_file_not_in_evidence",
            "py/xss",
            'name = request.args.get("name", "")\n'
            'return render_template("profile.html", name=name)',
            {"encoding_coverage": _UNRESOLVED},
            _NMD,
        ),
        (
            "model_field_read_without_write_path",
            "python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse",
            'comment = Comment.objects.get(pk=pk)\nreturn HttpResponse("<li>" + comment.body + "</li>")',
            {"attacker_control": _UNRESOLVED},
            _NMD,
        ),
        (
            "helper_body_not_in_evidence",
            "py/reflective-xss",
            'name = request.args.get("name", "")\nreturn "<p>" + clean_text(name) + "</p>"',
            {"encoding_coverage": _UNRESOLVED},
            _NMD,
        ),
    ],
}

_CASES = [
    pytest.param(lang, rule, snippet, overrides, expected, id=f"{lang}-{case_id}")
    for lang in _LANGS
    for case_id, rule, snippet, overrides, expected in _PANEL[lang]
]


def _policy(lang):
    return next(p for p in _REG._policies if p.family == _FAMILIES[lang])


def _finding(lang, rule=None):
    return Finding(
        rule_id=rule or _DEFAULT_RULE[lang],
        message="m",
        file=_DEFAULT_FILE[lang],
        start_line=12,
        end_line=12,
        repo_name="synthetic",
        lang=lang,
        cwe_ids=["CWE-79"],
        dataflow_path=["source", "sink"],
    )


def _q(lang):
    return GuidedQuestions(rule_id=_DEFAULT_RULE[lang], short_description="d", questions=["q?"])


def _seeded(lang, snippet=None):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("synthetic", lang, _DEFAULT_FILE[lang], 10, 14),
        snippet or _DEFAULT_SNIPPET[lang],
    )
    led.add_scanner_dataflow(_DEFAULT_FLOW[lang])
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
    """Answers every evidence request with one fixed status / exhaustiveness.
    The ledger takes the evidence KIND from the request the model made."""

    def __init__(self, status, *, exhaustive=True):
        self._status, self._exhaustive = status, exhaustive

    def resolve_evidence(self, repo_name, lang, requests):
        return {
            r.raw_request: EvidenceResult(
                request=r,
                status=self._status,
                prompt_content="// retrieved",
                scope=EvidenceScope.REPOSITORY_INDEX,
                exhaustive=self._exhaustive,
            )
            for r in requests
        }


def _run(mc, responses, lang, *, rule=None, snippet=None, provider=None):
    mc.side_effect = [_resp(r) for r in responses]
    finding = _finding(lang, rule)
    policy = _REG.resolve_family(
        cwe_ids=finding.cwe_ids, rule_id=finding.rule_id, lang=finding.lang
    )
    assert policy is not None and policy.family == _FAMILIES[lang]
    controller = PolicyClosureController(
        policy=policy,
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(lang, snippet),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    verdict = client.analyze(
        finding=finding,
        context=snippet or _DEFAULT_SNIPPET[lang],
        questions=_q(lang),
        func_name="handler",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=5,
        quiet=True,
    )
    return verdict, controller


# ── the synthetic panel ───────────────────────────────────────────────


@pytest.mark.parametrize(("lang", "rule", "snippet", "overrides", "expected"), _CASES)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_panel(mc, lang, rule, snippet, overrides, expected):
    verdict, controller = _run(mc, [_assess(overrides)], lang, rule=rule, snippet=snippet)
    assert verdict.verdict == expected
    assert controller.last_decision is not None
    assert controller.last_decision.family == _FAMILIES[lang]


@pytest.mark.parametrize("lang", _LANGS)
def test_panel_has_both_outcomes_and_abstentions(lang):
    outcomes = [expected for _, _, _, _, expected in _PANEL[lang]]
    assert outcomes.count(_TP) >= 3
    assert outcomes.count(_FP) >= 4
    assert outcomes.count(_NMD) >= 3


# ── a positive needs a witnessed path, not a missing encoder ──────────


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_bypass_claim_without_citation_is_nmd(mc, lang):
    # "No encoder visible" with nothing cited is not a witnessed bypass.
    verdict, controller = _run(
        mc,
        [_assess({"encoding_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": []}})],
        lang,
    )
    assert verdict.verdict == _NMD
    assert "encoding_coverage" in controller.last_decision.terminal_reason


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_coverage_with_unresolved_channel_is_nmd_not_fp(mc, lang):
    # An encoder cannot be matched to an unknown output context.
    verdict, controller = _run(
        mc,
        [
            _assess(
                {
                    "output_channel": _UNRESOLVED,
                    **_local("encoding_coverage", "ALL_REACHING_PATHS"),
                }
            )
        ],
        lang,
    )
    assert verdict.verdict == _NMD
    assert "output_channel" in controller.last_decision.terminal_reason


# ── evidence shapes that must not dismiss ─────────────────────────────

_COVERAGE_REQUEST = {
    "java": {"kind": "function", "subject": "clean", "for_slot": "encoding_coverage"},
    "python": {"kind": "function", "subject": "clean_text", "for_slot": "encoding_coverage"},
}


def _coverage_after_retrieval(request):
    return [
        _assess({"encoding_coverage": _UNRESOLVED}, requests=[request]),
        _assess({"encoding_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["R1"]}}),
    ]


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_exhaustive_retrieved_encoder_body_dismisses(mc, lang):
    # The helper's body was retrieved exhaustively: coverage is admissible.
    verdict, _ = _run(
        mc,
        _coverage_after_retrieval(_COVERAGE_REQUEST[lang]),
        lang,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert verdict.verdict == _FP


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_non_exhaustive_retrieved_encoder_is_nmd(mc, lang):
    verdict, controller = _run(
        mc,
        _coverage_after_retrieval(_COVERAGE_REQUEST[lang]),
        lang,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False),
    )
    assert verdict.verdict == _NMD
    assert "encoding_coverage" in controller.last_decision.terminal_reason


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("kind", ["framework_sanitizers", "framework_guards"])
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_framework_autoescape_claim_is_nmd(mc, lang, kind):
    # "The template engine / view layer escapes this" backed only by a framework
    # lookup — even an exhaustive FOUND — never establishes coverage.
    request = {"kind": kind, "subject": "autoescape", "for_slot": "encoding_coverage"}
    verdict, controller = _run(
        mc,
        _coverage_after_retrieval(request),
        lang,
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert verdict.verdict == _NMD
    assert "encoding_coverage" in controller.last_decision.terminal_reason


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_framework_content_type_claim_is_nmd(mc, lang):
    # A non-markup content type "set by a filter / middleware" is the same
    # shape: framework evidence does not establish NON_MARKUP_ONLY_ALL_PATHS.
    request = {"kind": "framework_guards", "subject": "content-type", "for_slot": "output_channel"}
    responses = [
        _assess({"output_channel": _UNRESOLVED}, requests=[request]),
        _assess({"output_channel": {"value": "NON_MARKUP_ONLY_ALL_PATHS", "evidence": ["R1"]}}),
    ]
    verdict, controller = _run(
        mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True)
    )
    assert verdict.verdict == _NMD
    assert "output_channel" in controller.last_decision.terminal_reason


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, lang):
    request = {"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}
    responses = [
        _assess({"flow_to_sink": _UNRESOLVED}, requests=[request]),
        _assess({"flow_to_sink": {"value": "REACHES", "evidence": ["R1"]}}),
    ]
    verdict, _ = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert verdict.verdict == _NMD
    assert "flow_to_sink" in verdict.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_cannot_prove_no_path(mc, lang):
    request = {"kind": "all_callers", "subject": "handler", "for_slot": "flow_to_sink"}
    responses = [
        _assess({"flow_to_sink": _UNRESOLVED}, requests=[request]),
        _assess({"flow_to_sink": {"value": "NO_PATH_COMPLETE", "evidence": ["R1"]}}),
    ]
    verdict, _ = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert verdict.verdict == _NMD


# ── rendered prompt ───────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct|"
    r"provide your final verdict|\((?:vulnerable|unsafe|safe)\)",
    re.IGNORECASE,
)


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_rendered_prompt_carries_guidance_and_no_verdict_command(mc, lang):
    _run(mc, [_assess()], lang)
    messages = mc.call_args_list[0].kwargs["messages"]
    user = messages[1]["content"]
    policy = _policy(lang)
    # the single response contract and every slot
    assert "fact_slots" in user
    for slot in policy.fact_slots:
        assert slot in user
    assert "security_effect" not in user
    # the family's guidance, verbatim
    for entry in policy.assessment_guidance:
        assert entry in user
    # the seeded evidence
    assert "[L1]" in user and "[D1]" in user
    # no verdict command anywhere in the user turn
    assert not _VERDICT_CMD.search(user)


@pytest.mark.parametrize("lang", _LANGS)
def test_overlay_names_language_specific_defenses(lang):
    controller = PolicyClosureController(
        policy=_policy(lang),
        provider=MagicMock(),
        finding=_finding(lang),
        model="gpt-4o",
        ledger=_seeded(lang),
    )
    instr = controller.initial_instructions()
    assert "output_channel" in instr and "encoding_coverage" in instr
    expected = {
        "java": ("Encode.forHtml", "HtmlUtils.htmlEscape", "<c:out>"),
        "python": ("html.escape(s)", "format_html", "render_template_string"),
    }[lang]
    for name in expected:
        assert name in instr
    other = {"java": "render_template_string", "python": "HttpServletResponse"}[lang]
    assert other not in instr
