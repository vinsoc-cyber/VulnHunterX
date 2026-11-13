# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic open-redirect (CWE-601) acceptance panel for the Java and
Python families.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

Every fixture is synthetic. Each case pairs a small realistic snippet with the
fact assessment that snippet supports:

* the value is the whole target with no check, or passes a check that admits
  ``//host`` / ``///host``                                -> True Positive
* a value appended to a fixed local path, a key into a constant map, a route
  reversal, a strict local-path test or host allowlist, a constant target, a
  server-side forward or a rendered link                  -> False Positive
* a context-path-only prefix, a host check that a backslash form may defeat,
  a validator whose body is not in evidence               -> Needs More Data

Scripted tests prove policy/control correctness, NOT model semantic quality
(that needs a real provider and is out of scope here).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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
_CWE = "CWE-601"
_LANGS = ("java", "python")
_FAMILY = {"java": "open_redirect_java", "python": "open_redirect_python"}

TP, FP, NMD = "True Positive", "False Positive", "Needs More Data"

# A fully-resolved True-Positive assessment (an attacker value selects an
# off-site target and reaches the redirect past no effective restriction). Cases
# flip slots.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_REDIRECT_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "target_control": {"value": "EXTERNAL_TARGET_PATH_FOUND", "evidence": ["L1"]},
    "target_restriction": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}
_UNRESOLVED = {"value": "UNRESOLVED", "evidence": []}


def _slot(value, evidence="L1"):
    return {"value": value, "evidence": [evidence]}


@dataclass(frozen=True)
class Case:
    name: str
    lang: str
    rule: str
    file: str
    snippet: str
    dataflow: str
    expected: str
    overrides: dict = field(default_factory=dict)


_JAVA = [
    Case(
        "whole-target-sendredirect",
        "java",
        "vulnhunterx.java.open-redirect",
        "src/main/java/app/LoginServlet.java",
        'response.sendRedirect(request.getParameter("next"));',
        'getParameter("next") -> sendRedirect',
        TP,
    ),
    Case(
        "spring-redirect-prefix",
        "java",
        "config.opengrep-rules.java.spring.security.audit.spring-unvalidated-redirect",
        "src/main/java/app/ReturnController.java",
        '@GetMapping("/return")\n'
        "public String back(@RequestParam String returnUrl) {\n"
        '    return "redirect:" + returnUrl;\n'
        "}",
        '@RequestParam returnUrl -> "redirect:" + returnUrl',
        TP,
    ),
    Case(
        "leading-slash-only-check-is-bypassable",
        "java",
        "java/unvalidated-url-redirection",
        "src/main/java/app/SsoController.java",
        'if (!target.startsWith("/")) { target = "/home"; }\nresponse.sendRedirect(target);',
        "@RequestParam target -> sendRedirect",
        TP,
    ),
    Case(
        "appended-to-fixed-local-path",
        "java",
        "java/unvalidated-url-redirection",
        "src/main/java/app/OrderController.java",
        'return "redirect:/orders/" + orderId;',
        '@PathVariable orderId -> "redirect:/orders/" + orderId',
        FP,
        {"target_control": _slot("LOCAL_TARGET_ONLY_ALL_PATHS")},
    ),
    Case(
        "key-into-constant-map",
        "java",
        "java.lang.security.audit.unvalidated-redirect.unvalidated-redirect",
        "src/main/java/app/LandingServlet.java",
        'private static final Map<String, String> PAGES = Map.of("home", "/home", "help", "/help");\n'
        'String url = PAGES.getOrDefault(page, "/home");\n'
        "response.sendRedirect(url);",
        'getParameter("page") -> PAGES.getOrDefault -> sendRedirect',
        FP,
        {"target_control": _slot("LOCAL_TARGET_ONLY_ALL_PATHS")},
    ),
    Case(
        "local-path-test-rejecting-slash-and-backslash",
        "java",
        "java/unvalidated-url-redirection",
        "src/main/java/app/AuthController.java",
        'if (!next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\\\")) {\n'
        '    next = "/";\n'
        "}\n"
        "response.sendRedirect(next);",
        "@RequestParam next -> sendRedirect",
        FP,
        {"target_restriction": _slot("ALL_REACHING_PATHS")},
    ),
    Case(
        "helper-parameter-with-constant-callers",
        "java",
        "config.opengrep-rules.java.lang.security.audit.unvalidated-redirect",
        "src/main/java/app/Redirects.java",
        "private void go(HttpServletResponse res, String url) throws IOException {\n"
        "    res.sendRedirect(url);\n"
        "}\n"
        'void toHome(HttpServletResponse res) throws IOException { go(res, "/home"); }',
        '"/home" -> go(res, url) -> sendRedirect',
        FP,
        {
            "attacker_control": _slot("REFUTED"),
            "flow_to_sink": _UNRESOLVED,
            "target_control": _UNRESOLVED,
            "target_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "server-side-forward",
        "java",
        "java/unvalidated-url-redirection",
        "src/main/java/app/Dispatcher.java",
        'request.getRequestDispatcher(request.getParameter("view")).forward(request, response);',
        'getParameter("view") -> getRequestDispatcher -> forward',
        FP,
        {
            "sink_binding": _slot("NOT_REDIRECT_SINK"),
            "target_control": _UNRESOLVED,
            "target_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "context-path-prefix-only",
        "java",
        "java/unvalidated-url-redirection",
        "src/main/java/app/LocaleServlet.java",
        'response.sendRedirect(request.getContextPath() + request.getParameter("page"));',
        'getParameter("page") -> getContextPath() + page -> sendRedirect',
        NMD,
        {"target_control": _UNRESOLVED, "target_restriction": _UNRESOLVED},
    ),
    Case(
        "java-net-url-host-check-without-backslash-rejection",
        "java",
        "java/unvalidated-url-redirection",
        "src/main/java/app/OAuthCallback.java",
        'if (!"app.example.com".equals(new URL(redirectUri).getHost())) {\n'
        "    throw new BadRequest();\n"
        "}\n"
        "response.sendRedirect(redirectUri);",
        "@RequestParam redirectUri -> sendRedirect",
        NMD,
        {"target_restriction": _UNRESOLVED},
    ),
]

_PYTHON = [
    Case(
        "whole-target-flask-redirect",
        "python",
        "config.opengrep-rules.python.flask.security.open-redirect",
        "app/auth.py",
        'return redirect(request.args.get("next"))',
        'request.args.get("next") -> redirect',
        TP,
    ),
    Case(
        "django-http-response-redirect",
        "python",
        "python.django.security.injection.open-redirect.open-redirect",
        "accounts/views.py",
        'target = request.GET.get("return_to", "/")\nreturn HttpResponseRedirect(target)',
        'request.GET.get("return_to") -> HttpResponseRedirect',
        TP,
    ),
    Case(
        "empty-netloc-check-is-bypassable",
        "python",
        "py/url-redirection",
        "app/login.py",
        'target = request.args.get("next", "")\n'
        'if urlparse(target).netloc != "":\n'
        '    target = url_for("index")\n'
        "return redirect(target)",
        'request.args.get("next") -> redirect',
        TP,
    ),
    Case(
        "appended-to-fixed-local-path",
        "python",
        "py/url-redirection",
        "app/orders.py",
        'return redirect(f"/orders/{order_id}")',
        "order_id -> f-string -> redirect",
        FP,
        {"target_control": _slot("LOCAL_TARGET_ONLY_ALL_PATHS")},
    ),
    Case(
        "route-reversal-with-value-as-argument",
        "python",
        "python.flask.security.open-redirect.open-redirect",
        "app/profile.py",
        'return redirect(url_for("profile.show", username=request.form["username"]))',
        'request.form["username"] -> url_for -> redirect',
        FP,
        {"target_control": _slot("LOCAL_TARGET_ONLY_ALL_PATHS")},
    ),
    Case(
        "django-url-has-allowed-host-and-scheme",
        "python",
        "py/url-redirection",
        "accounts/views.py",
        'target = request.POST.get("next", "")\n'
        "if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):\n"
        "    target = settings.LOGIN_REDIRECT_URL\n"
        "return HttpResponseRedirect(target)",
        'request.POST.get("next") -> HttpResponseRedirect',
        FP,
        {"target_restriction": _slot("ALL_REACHING_PATHS")},
    ),
    Case(
        "constant-view-name",
        "python",
        "config.opengrep-rules.python.django.security.injection.open-redirect",
        "shop/views.py",
        'return redirect("shop:cart")',
        '"shop:cart" -> redirect',
        FP,
        {
            "attacker_control": _slot("REFUTED"),
            "flow_to_sink": _UNRESOLVED,
            "target_control": _UNRESOLVED,
            "target_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "link-rendered-not-redirected",
        "python",
        "py/url-redirection",
        "app/share.py",
        'link = request.args.get("u")\nreturn render_template("share.html", link=link)',
        'request.args.get("u") -> render_template',
        FP,
        {
            "sink_binding": _slot("NOT_REDIRECT_SINK"),
            "target_control": _UNRESOLVED,
            "target_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "hostname-check-without-backslash-rejection",
        "python",
        "py/url-redirection",
        "app/oauth.py",
        'target = request.args["redirect_uri"]\n'
        'if urlsplit(target).hostname != "app.example.com":\n'
        "    abort(400)\n"
        "return redirect(target)",
        'request.args["redirect_uri"] -> redirect',
        NMD,
        {"target_restriction": _UNRESOLVED},
    ),
    Case(
        "validator-helper-not-in-evidence",
        "python",
        "py/url-redirection",
        "app/sso.py",
        'target = request.args.get("next")\n'
        "if not is_safe_redirect(target):\n"
        "    abort(400)\n"
        "return redirect(target)",
        'request.args.get("next") -> redirect',
        NMD,
        {"target_restriction": _UNRESOLVED},
    ),
]

_CASES = _JAVA + _PYTHON


def _policy(lang):
    return _REG.resolve_family(cwe_ids=[_CWE], rule_id="", lang=lang)


def _finding(case: Case, line=12):
    return Finding(
        rule_id=case.rule,
        message="m",
        file=case.file,
        start_line=line,
        end_line=line,
        repo_name="synthetic",
        lang=case.lang,
        cwe_ids=[_CWE],
        dataflow_path=case.dataflow.split(" -> "),
    )


def _q(rule):
    return GuidedQuestions(rule_id=rule, short_description="d", questions=["q?"])


def _seeded(case: Case, line=12):
    led = EvidenceLedger()
    led.add_local_slice(SourceRef("synthetic", case.lang, case.file, line, line + 4), case.snippet)
    led.add_scanner_dataflow(case.dataflow)
    return led


def _assess(overrides=None, requests=None):
    slots = {k: dict(v) for k, v in _BASE.items()}
    for k, v in (overrides or {}).items():
        slots[k] = dict(v)
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


def _run(mc, responses, case: Case, *, provider=None, max_iterations=5):
    mc.side_effect = [_resp(r) for r in responses]
    finding = _finding(case)
    policy = _REG.resolve_family(
        cwe_ids=finding.cwe_ids, rule_id=finding.rule_id, lang=finding.lang
    )
    controller = PolicyClosureController(
        policy=policy,
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(case),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding,
        context=case.snippet,
        questions=_q(case.rule),
        func_name="handler",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=max_iterations,
        quiet=True,
    )


def _first(lang):
    return next(c for c in _CASES if c.lang == lang and c.expected == TP)


# --- selection --------------------------------------------------------------
@pytest.mark.parametrize("case", _CASES, ids=lambda c: f"{c.lang}:{c.name}")
def test_every_panel_finding_routes_to_its_language_family(case):
    f = _finding(case)
    policy = _REG.resolve_family(cwe_ids=f.cwe_ids, rule_id=f.rule_id, lang=f.lang)
    assert policy is not None and policy.family == _FAMILY[case.lang]


# --- the synthetic panel ----------------------------------------------------
@pytest.mark.parametrize("case", _CASES, ids=lambda c: f"{c.lang}:{c.name}")
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_panel_case(mc, case):
    v = _run(mc, [_assess(overrides=case.overrides)], case)
    assert v.verdict == case.expected, (case.name, v.reasoning)
    assert f"[policy:{_FAMILY[case.lang]}" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
def test_panel_covers_tp_fp_and_nmd_per_language(lang):
    counts = {
        v: sum(1 for c in _CASES if c.lang == lang and c.expected == v) for v in (TP, FP, NMD)
    }
    assert counts[TP] >= 3 and counts[FP] >= 5 and counts[NMD] >= 2, counts


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_context_path_prefix_names_target_control_as_unresolved(mc):
    # request.getContextPath() is "" for a root deployment, so it is not a fixed
    # non-empty prefix: the channel stays unresolved instead of being dismissed.
    case = next(c for c in _CASES if c.name == "context-path-prefix-only")
    v = _run(mc, [_assess(overrides=case.overrides)], case)
    assert v.verdict == NMD
    assert "target_control" in v.reasoning


# --- fail-closed evidence handling -----------------------------------------
@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, lang):
    # The model appends its own verdict; the table decides from the facts.
    raw = json.loads(_assess(overrides={"target_restriction": _slot("ALL_REACHING_PATHS")}))
    raw["verdict"] = "True Positive"
    v = _run(mc, [json.dumps(raw)], _first(lang))
    assert v.verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_restriction_claim_cited_only_to_dataflow_is_nmd(mc, lang):
    # ALL_REACHING_PATHS needs the local construction or an exhaustive
    # retrieval; the scanner dataflow shows a path, not coverage of every path.
    v = _run(
        mc,
        [_assess(overrides={"target_restriction": _slot("ALL_REACHING_PATHS", "D1")})],
        _first(lang),
    )
    assert v.verdict == NMD
    assert "target_restriction" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_local_target_claim_cited_only_to_dataflow_is_nmd(mc, lang):
    v = _run(
        mc,
        [
            _assess(
                overrides={
                    "target_control": _slot("LOCAL_TARGET_ONLY_ALL_PATHS", "D1"),
                    "target_restriction": _UNRESOLVED,
                }
            )
        ],
        _first(lang),
    )
    assert v.verdict == NMD
    assert "target_control" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_validator_non_exhaustive_is_nmd(mc, lang):
    # The target check lives in a helper outside the slice. A non-exhaustive
    # retrieval of it cannot establish coverage of every reaching path.
    responses = [
        _assess(
            overrides={"target_restriction": _UNRESOLVED},
            requests=[
                {
                    "kind": "function",
                    "subject": "is_safe_redirect",
                    "for_slot": "target_restriction",
                }
            ],
        ),
        _assess(overrides={"target_restriction": _slot("ALL_REACHING_PATHS", "R1")}),
    ]
    v = _run(
        mc, responses, _first(lang), provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False)
    )
    assert v.verdict == NMD


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_validator_exhaustive_retrieval_dismisses(mc, lang):
    # The same helper, retrieved exhaustively, is admissible coverage evidence.
    responses = [
        _assess(
            overrides={"target_restriction": _UNRESOLVED},
            requests=[
                {
                    "kind": "function",
                    "subject": "is_safe_redirect",
                    "for_slot": "target_restriction",
                }
            ],
        ),
        _assess(overrides={"target_restriction": _slot("ALL_REACHING_PATHS", "R1")}),
    ]
    v = _run(
        mc, responses, _first(lang), provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True)
    )
    assert v.verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, lang):
    responses = [
        _assess(
            overrides={"flow_to_sink": _UNRESOLVED},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides={"flow_to_sink": _slot("NO_PATH_COMPLETE", "R1")}),
    ]
    v = _run(mc, responses, _first(lang), provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == NMD
    assert "flow_to_sink" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_unresolved_slot_without_a_request_is_nmd_not_a_guess(mc, lang):
    v = _run(mc, [_assess(overrides={"attacker_control": _UNRESOLVED})], _first(lang))
    assert v.verdict == NMD
    assert "attacker_control" in v.reasoning


# --- rendered prompt --------------------------------------------------------
_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct"
    r"|\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)",
    re.IGNORECASE,
)


@pytest.mark.parametrize("lang", _LANGS)
def test_overlay_has_slots_guidance_and_no_verdict_command(lang):
    case = _first(lang)
    controller = PolicyClosureController(
        policy=_policy(lang),
        provider=MagicMock(),
        finding=_finding(case),
        model="gpt-4o",
        ledger=_seeded(case),
    )
    instr = controller.initial_instructions()
    for slot in _BASE:
        assert slot in instr
    assert "EXTERNAL_TARGET_PATH_FOUND, LOCAL_TARGET_ONLY_ALL_PATHS | UNRESOLVED" in instr
    for entry in _policy(lang).assessment_guidance:
        assert entry in instr
    assert "[L1]" in instr and "[D1]" in instr
    assert not _VERDICT_CMD.search(instr), _VERDICT_CMD.search(instr)
    assert "Do NOT decide a free-text verdict" in instr


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_prompt_sent_to_the_model_carries_the_family_guidance(mc, lang):
    case = _first(lang)
    _run(mc, [_assess()], case)
    messages = mc.call_args_list[0].kwargs["messages"]
    sent = "\n".join(str(m.get("content", "")) for m in messages)
    assert "Evidence-closure assessment (REQUIRED response format)" in sent
    assert _policy(lang).assessment_guidance[3] in sent  # target_control
    assert _policy(lang).assessment_guidance[4] in sent  # target_restriction
