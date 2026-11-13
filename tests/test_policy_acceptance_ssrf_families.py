# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic SSRF (CWE-918) acceptance panel for the Java and Python
families.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

Every fixture is synthetic. Each case pairs a small realistic snippet with the
fact assessment that snippet supports:

* whole-URL / host control with no check, or with a bypassable raw-string
  check                                                   -> True Positive
* a value confined to the query of a fixed-origin request,
  a parsed-host allowlist on every path, a constant URL,
  a flagged value that is never requested                 -> False Positive
* a raw path segment on a fixed host (partial SSRF), a denylist of internal
  ranges, an allowlist claim with the channel unresolved  -> Needs More Data

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
_CWE = "CWE-918"
_LANGS = ("java", "python")
_FAMILY = {"java": "ssrf_java", "python": "ssrf_python"}

TP, FP, NMD = "True Positive", "False Positive", "Needs More Data"

# A fully-resolved True-Positive assessment (an attacker value selects the host
# and reaches the request past no effective restriction). Cases flip slots.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_OUTBOUND_REQUEST_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "destination_control": {"value": "HOST_OR_SCHEME_CONTROL_PATH_FOUND", "evidence": ["L1"]},
    "destination_restriction": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
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
        "whole-url-openconnection",
        "java",
        "java/ssrf",
        "src/main/java/app/PreviewController.java",
        'String target = request.getParameter("url");\n'
        "URL url = new URL(target);\n"
        "InputStream in = url.openConnection().getInputStream();",
        'getParameter("url") -> new URL(target) -> openConnection()',
        TP,
    ),
    Case(
        "host-format-resttemplate",
        "java",
        "config.opengrep-rules.java.spring.security.injection.tainted-url-host",
        "src/main/java/app/TenantClient.java",
        'String url = String.format("https://%s/api/status", tenantHost);\n'
        "return restTemplate.getForObject(url, String.class);",
        "@RequestParam tenantHost -> String.format -> getForObject",
        TP,
    ),
    Case(
        "raw-prefix-check-is-bypassable",
        "java",
        "java/ssrf-ext",
        "src/main/java/app/FetchService.java",
        'if (!target.startsWith("https://cdn.example.com")) { throw new BadRequest(); }\n'
        "HttpRequest req = HttpRequest.newBuilder(URI.create(target)).build();\n"
        "return client.send(req, BodyHandlers.ofString());",
        "@RequestParam target -> URI.create(target) -> HttpClient.send",
        TP,
    ),
    Case(
        "query-parameter-of-fixed-origin",
        "java",
        "java/ssrf",
        "src/main/java/app/GeoClient.java",
        'URI uri = UriComponentsBuilder.fromHttpUrl("https://geo.example.com/v1/lookup")\n'
        '    .queryParam("q", query).build().encode().toUri();\n'
        "return restTemplate.getForObject(uri, Geo.class);",
        "@RequestParam query -> queryParam -> getForObject",
        FP,
        {"destination_control": _slot("PATH_OR_QUERY_ONLY_ALL_PATHS")},
    ),
    Case(
        "parsed-host-allowlist",
        "java",
        "java.spring.security.injection.tainted-url-host.tainted-url-host",
        "src/main/java/app/WebhookSender.java",
        "URI uri = new URI(callback);\n"
        "if (!ALLOWED_HOSTS.contains(uri.getHost())) { throw new BadRequest(); }\n"
        "return client.send(HttpRequest.newBuilder(uri).build(), BodyHandlers.ofString());",
        "@RequestBody callback -> new URI(callback) -> HttpClient.send",
        FP,
        {"destination_restriction": _slot("ALL_REACHING_PATHS")},
    ),
    Case(
        "constant-url",
        "java",
        "java/ssrf",
        "src/main/java/app/HealthProbe.java",
        'private static final String STATUS_URL = "https://status.example.com/health";\n'
        "return restTemplate.getForObject(STATUS_URL, String.class);",
        "STATUS_URL -> getForObject",
        FP,
        {
            "attacker_control": _slot("REFUTED"),
            "flow_to_sink": _UNRESOLVED,
            "destination_control": _UNRESOLVED,
            "destination_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "url-only-parsed-never-requested",
        "java",
        "config.opengrep-rules.java.spring.security.injection.tainted-url-host",
        "src/main/java/app/LinkLabel.java",
        'String link = "https://" + host + "/profile";\n'
        'model.addAttribute("profileLink", link);\n'
        'return "profile";',
        "@RequestParam host -> link -> model.addAttribute",
        FP,
        {
            "sink_binding": _slot("NOT_OUTBOUND_REQUEST_SINK"),
            "destination_control": _UNRESOLVED,
            "destination_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "raw-path-segment-on-fixed-host",
        "java",
        "java/ssrf",
        "src/main/java/app/InventoryClient.java",
        'String url = "https://inventory.internal.example/api/items/" + itemId;\n'
        "return restTemplate.getForObject(url, Item.class);",
        "@PathVariable itemId -> url -> getForObject",
        NMD,
        {"destination_control": _UNRESOLVED, "destination_restriction": _UNRESOLVED},
    ),
    Case(
        "internal-range-denylist",
        "java",
        "java/ssrf",
        "src/main/java/app/Importer.java",
        "URL url = new URL(source);\n"
        'if (url.getHost().equals("localhost") || url.getHost().startsWith("10.")) {\n'
        "    throw new BadRequest();\n"
        "}\n"
        "return url.openStream();",
        "@RequestParam source -> new URL(source) -> openStream",
        NMD,
        {"destination_restriction": _UNRESOLVED},
    ),
]

_PYTHON = [
    Case(
        "whole-url-requests-get",
        "python",
        "py/full-ssrf",
        "app/views/preview.py",
        'target = request.args.get("url")\nresp = requests.get(target, timeout=5)',
        'request.args.get("url") -> requests.get',
        TP,
    ),
    Case(
        "host-fstring",
        "python",
        "config.opengrep-rules.python.flask.security.injection.tainted-url-host",
        "app/tenants.py",
        "url = f\"https://{request.args['tenant']}/api/status\"\n"
        "return requests.get(url, timeout=5).json()",
        "request.args['tenant'] -> url -> requests.get",
        TP,
    ),
    Case(
        "raw-prefix-check-is-bypassable",
        "python",
        "python.django.security.injection.ssrf.ssrf-injection-urllib.ssrf-injection-urllib",
        "shop/views.py",
        'target = request.GET["feed"]\n'
        'if not target.startswith("https://cdn.example.com"):\n'
        "    return HttpResponseBadRequest()\n"
        "body = urllib.request.urlopen(target).read()",
        'request.GET["feed"] -> urllib.request.urlopen',
        TP,
    ),
    Case(
        "route-variable-only-in-params",
        "python",
        "python.flask.security.injection.ssrf-requests.ssrf-requests",
        "app/geo.py",
        '@app.route("/lookup/<term>")\n'
        "def lookup(term):\n"
        '    r = requests.get("https://geo.example.com/v1/lookup", params={"q": term})\n'
        "    return r.json()",
        "term -> params -> requests.get",
        FP,
        {"destination_control": _slot("PATH_OR_QUERY_ONLY_ALL_PATHS")},
    ),
    Case(
        "integer-path-segment-of-fixed-origin",
        "python",
        "py/partial-ssrf",
        "app/orders.py",
        'order_id = int(request.args["order"])\n'
        'resp = requests.get(f"https://orders.example.com/api/orders/{order_id}")',
        'request.args["order"] -> f-string -> requests.get',
        FP,
        {"destination_control": _slot("PATH_OR_QUERY_ONLY_ALL_PATHS")},
    ),
    Case(
        "netloc-allowlist",
        "python",
        "py/full-ssrf",
        "app/webhooks.py",
        'target = request.json["callback"]\n'
        'if "\\\\" in target or urlsplit(target).netloc not in ALLOWED_HOSTS:\n'
        "    abort(400)\n"
        "httpx.post(target, json=payload)",
        'request.json["callback"] -> httpx.post',
        FP,
        {"destination_restriction": _slot("ALL_REACHING_PATHS")},
    ),
    Case(
        "constant-url",
        "python",
        "config.opengrep-rules.python.django.security.injection.ssrf.ssrf-injection-requests",
        "ops/health.py",
        'STATUS_URL = "https://status.example.com/health"\n'
        "resp = requests.get(STATUS_URL, timeout=2)",
        "STATUS_URL -> requests.get",
        FP,
        {
            "attacker_control": _slot("REFUTED"),
            "flow_to_sink": _UNRESOLVED,
            "destination_control": _UNRESOLVED,
            "destination_restriction": _UNRESOLVED,
        },
    ),
    Case(
        "raw-path-segment-on-fixed-host",
        "python",
        "py/partial-ssrf",
        "app/users.py",
        'name = request.args["user"]\n'
        'resp = requests.get(f"https://directory.internal.example/api/users/{name}")',
        'request.args["user"] -> f-string -> requests.get',
        NMD,
        {"destination_control": _UNRESOLVED, "destination_restriction": _UNRESOLVED},
    ),
    Case(
        "is-private-denylist",
        "python",
        "py/full-ssrf",
        "app/importer.py",
        "host = urlsplit(source).hostname\n"
        "if ipaddress.ip_address(socket.gethostbyname(host)).is_private:\n"
        "    abort(400)\n"
        "data = requests.get(source).content",
        'request.form["source"] -> requests.get',
        NMD,
        {"destination_restriction": _UNRESOLVED},
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
    assert counts[TP] >= 3 and counts[FP] >= 4 and counts[NMD] >= 2, counts


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_partial_ssrf_names_destination_control_as_unresolved(mc, lang):
    case = next(c for c in _CASES if c.lang == lang and c.name == "raw-path-segment-on-fixed-host")
    v = _run(mc, [_assess(overrides=case.overrides)], case)
    assert v.verdict == NMD
    assert "destination_control" in v.reasoning


# --- fail-closed evidence handling -----------------------------------------
@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, lang):
    # The model appends its own verdict; the table decides from the facts.
    raw = json.loads(_assess(overrides={"destination_restriction": _slot("ALL_REACHING_PATHS")}))
    raw["verdict"] = "True Positive"
    v = _run(mc, [json.dumps(raw)], _first(lang))
    assert v.verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_allowlist_claim_cited_only_to_dataflow_is_nmd(mc, lang):
    # ALL_REACHING_PATHS needs the local construction or an exhaustive
    # retrieval; the scanner dataflow shows a path, not coverage of every path.
    v = _run(
        mc,
        [_assess(overrides={"destination_restriction": _slot("ALL_REACHING_PATHS", "D1")})],
        _first(lang),
    )
    assert v.verdict == NMD
    assert "destination_restriction" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_fixed_origin_claim_cited_only_to_dataflow_is_nmd(mc, lang):
    v = _run(
        mc,
        [
            _assess(
                overrides={
                    "destination_control": _slot("PATH_OR_QUERY_ONLY_ALL_PATHS", "D1"),
                    "destination_restriction": _UNRESOLVED,
                }
            )
        ],
        _first(lang),
    )
    assert v.verdict == NMD
    assert "destination_control" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_validator_non_exhaustive_is_nmd(mc, lang):
    # The allowlist lives in a helper outside the slice. A non-exhaustive
    # retrieval of it cannot establish coverage of every reaching path.
    responses = [
        _assess(
            overrides={"destination_restriction": _UNRESOLVED},
            requests=[
                {
                    "kind": "function",
                    "subject": "validate_destination",
                    "for_slot": "destination_restriction",
                }
            ],
        ),
        _assess(overrides={"destination_restriction": _slot("ALL_REACHING_PATHS", "R1")}),
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
            overrides={"destination_restriction": _UNRESOLVED},
            requests=[
                {
                    "kind": "function",
                    "subject": "validate_destination",
                    "for_slot": "destination_restriction",
                }
            ],
        ),
        _assess(overrides={"destination_restriction": _slot("ALL_REACHING_PATHS", "R1")}),
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
    assert "HOST_OR_SCHEME_CONTROL_PATH_FOUND, PATH_OR_QUERY_ONLY_ALL_PATHS | UNRESOLVED" in instr
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
    assert _policy(lang).assessment_guidance[3] in sent  # destination_control
    assert _policy(lang).assessment_guidance[4] in sent  # destination_restriction
