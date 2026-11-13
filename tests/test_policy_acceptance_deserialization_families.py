# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic acceptance panel for the unsafe-deserialization (CWE-502)
families — Java and Python.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

All fixtures are synthetic. Each case pairs a realistic snippet with the facts a
careful reader derives from it; the panel covers the positive conjunction and
every dismissing fact (not a sink, authenticated payload, data-only decoder,
allowlisting stream filter), plus the fail-closed cases (off-slice helper with
non-exhaustive evidence, incomplete index, capability left unresolved).

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
_RULES = {"java": "java/unsafe-deserialization", "python": "py/unsafe-deserialization"}
_FAMILIES = {"java": "deserialization_java", "python": "deserialization_python"}
_POLICIES = {
    lang: _REG.resolve_family(cwe_ids=["CWE-502"], rule_id=rule, lang=lang)
    for lang, rule in _RULES.items()
}
_LANGS = sorted(_RULES)

# A fully-resolved True-Positive assessment (attacker bytes reach an unrestricted
# arbitrary-type decoder). Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_DESERIALIZATION_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "deserializer_capability": {"value": "ARBITRARY_TYPE_PATH_FOUND", "evidence": ["L1"]},
    "type_restriction": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}


def _flip(slot, value, evidence=("L1",)):
    return {slot: {"value": value, "evidence": list(evidence)}}


_NOT_SINK = _flip("sink_binding", "NOT_DESERIALIZATION_SINK")
_REFUTED = _flip("attacker_control", "REFUTED")
_DATA_ONLY = _flip("deserializer_capability", "DATA_ONLY_ALL_PATHS")
_RESTRICTED = _flip("type_restriction", "ALL_REACHING_PATHS")

# (case id, file, line, snippet, scanner dataflow, slot overrides, expected verdict)
_PANEL = {
    "java": [
        (
            "ois-readobject-request-body",
            "src/main/java/app/ImportController.java",
            41,
            "ObjectInputStream in = new ObjectInputStream(request.getInputStream());\n"
            "Object job = in.readObject();",
            "request.getInputStream() -> ObjectInputStream.readObject",
            None,
            "True Positive",
        ),
        (
            "ois-base64-cookie-cast-is-not-a-restriction",
            "src/main/java/app/SessionFilter.java",
            58,
            "byte[] raw = Base64.getDecoder().decode(cookie.getValue());\n"
            "UserState s = (UserState) new ObjectInputStream(new ByteArrayInputStream(raw))"
            ".readObject();",
            "cookie.getValue() -> ObjectInputStream.readObject",
            None,
            "True Positive",
        ),
        (
            "xmldecoder-upload",
            "src/main/java/app/LayoutService.java",
            27,
            "XMLDecoder decoder = new XMLDecoder(upload.getInputStream());\n"
            "Object layout = decoder.readObject();",
            "upload.getInputStream() -> XMLDecoder.readObject",
            None,
            "True Positive",
        ),
        (
            "jackson-default-typing",
            "src/main/java/app/EventResource.java",
            33,
            "ObjectMapper mapper = new ObjectMapper();\n"
            "mapper.enableDefaultTyping();\n"
            "Object evt = mapper.readValue(body, Object.class);",
            "@RequestBody body -> ObjectMapper.readValue",
            None,
            "True Positive",
        ),
        (
            "jackson-concrete-type-no-default-typing",
            "src/main/java/app/OrderResource.java",
            29,
            "ObjectMapper mapper = new ObjectMapper();\n"
            "OrderDto order = mapper.readValue(body, OrderDto.class);",
            "@RequestBody body -> ObjectMapper.readValue",
            _DATA_ONLY,
            "False Positive",
        ),
        (
            "snakeyaml-safeconstructor",
            "src/main/java/app/ConfigUpload.java",
            22,
            "Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));\n"
            "Map<String, Object> cfg = yaml.load(request.getReader());",
            "request.getReader() -> Yaml.load",
            _DATA_ONLY,
            "False Positive",
        ),
        (
            "ois-with-allowlisting-object-input-filter",
            "src/main/java/app/JobReceiver.java",
            47,
            "ObjectInputStream in = new ObjectInputStream(socket.getInputStream());\n"
            'in.setObjectInputFilter(ObjectInputFilter.Config.createFilter("app.Job;!*"));\n'
            "Job job = (Job) in.readObject();",
            "socket.getInputStream() -> ObjectInputStream.readObject",
            _RESTRICTED,
            "False Positive",
        ),
        (
            "hmac-verified-before-decoding-on-every-path",
            "src/main/java/app/TokenCodec.java",
            64,
            "if (!MessageDigest.isEqual(mac.doFinal(payload), sig)) { throw new "
            "SecurityException(); }\n"
            "Object state = new ObjectInputStream(new ByteArrayInputStream(payload)).readObject();",
            'request.getParameter("state") -> ObjectInputStream.readObject',
            _REFUTED,
            "False Positive",
        ),
        (
            "writeobject-is-not-a-decode",
            "src/main/java/app/Exporter.java",
            19,
            "new ObjectOutputStream(response.getOutputStream()).writeObject(report);",
            "report -> ObjectOutputStream.writeObject",
            _NOT_SINK,
            "False Positive",
        ),
    ],
    "python": [
        (
            "pickle-loads-request-body",
            "app/views.py",
            31,
            "job = pickle.loads(request.get_data())",
            "request.get_data() -> pickle.loads",
            None,
            "True Positive",
        ),
        (
            "pickle-loads-base64-cookie",
            "app/session.py",
            18,
            "state = pickle.loads(base64.b64decode(request.cookies['state']))",
            "request.cookies['state'] -> pickle.loads",
            None,
            "True Positive",
        ),
        (
            "yaml-load-unsafe-loader",
            "app/importer.py",
            44,
            "doc = yaml.load(request.files['spec'].read(), Loader=yaml.UnsafeLoader)",
            "request.files['spec'] -> yaml.load",
            None,
            "True Positive",
        ),
        (
            "jsonpickle-decode-post-field",
            "app/api.py",
            52,
            "obj = jsonpickle.decode(request.form['payload'])",
            "request.form['payload'] -> jsonpickle.decode",
            None,
            "True Positive",
        ),
        (
            "yaml-safe-load",
            "app/importer.py",
            61,
            "doc = yaml.safe_load(request.files['spec'].read())",
            "request.files['spec'] -> yaml.safe_load",
            _DATA_ONLY,
            "False Positive",
        ),
        (
            "yaml-load-explicit-safeloader",
            "app/importer.py",
            70,
            "doc = yaml.load(request.data, Loader=yaml.SafeLoader)",
            "request.data -> yaml.load",
            _DATA_ONLY,
            "False Positive",
        ),
        (
            "restricted-unpickler-find-class-allowlist",
            "app/rpc.py",
            25,
            "class _Safe(pickle.Unpickler):\n"
            "    def find_class(self, module, name):\n"
            "        if (module, name) in _ALLOWED:\n"
            "            return super().find_class(module, name)\n"
            "        raise pickle.UnpicklingError(name)\n"
            "msg = _Safe(io.BytesIO(request.get_data())).load()",
            "request.get_data() -> Unpickler.load",
            _RESTRICTED,
            "False Positive",
        ),
        (
            "hmac-verified-before-decoding-on-every-path",
            "app/tokens.py",
            37,
            "if not hmac.compare_digest(hmac.new(KEY, body, 'sha256').digest(), sig):\n"
            "    abort(403)\n"
            "state = pickle.loads(body)",
            "request.args['state'] -> pickle.loads",
            _REFUTED,
            "False Positive",
        ),
        (
            "pickle-dumps-is-not-a-decode",
            "app/cache.py",
            12,
            "blob = pickle.dumps(result)",
            "result -> pickle.dumps",
            _NOT_SINK,
            "False Positive",
        ),
    ],
}

_CASES = [(lang, *case) for lang in _LANGS for case in _PANEL[lang]]
_CASE_IDS = [f"{c[0]}:{c[1]}" for c in _CASES]


def _finding(lang, file=None, line=None, dataflow=None):
    case = _PANEL[lang][0]
    line = line or case[2]
    return Finding(
        rule_id=_RULES[lang],
        message="m",
        file=file or case[1],
        start_line=line,
        end_line=line,
        repo_name="synthetic",
        lang=lang,
        cwe_ids=["CWE-502"],
        dataflow_path=(dataflow or case[4]).split(" -> "),
    )


def _q(lang):
    return GuidedQuestions(rule_id=_RULES[lang], short_description="d", questions=["q?"])


def _seeded(lang, file=None, line=None, snippet=None, dataflow=None):
    case = _PANEL[lang][0]
    line = line or case[2]
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("synthetic", lang, file or case[1], line, line + 2), snippet or case[3]
    )
    led.add_scanner_dataflow(dataflow or case[4])
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


def _run(mock_completion, responses, lang, *, case=None, provider=None, max_iterations=5):
    mock_completion.side_effect = [_resp(r) for r in responses]
    _, file, line, snippet, dataflow, _, _ = case or _PANEL[lang][0]
    finding = _finding(lang, file, line, dataflow)
    controller = PolicyClosureController(
        policy=_POLICIES[lang],
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(lang, file, line, snippet, dataflow),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding,
        context=snippet,
        questions=_q(lang),
        func_name="handler",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=max_iterations,
        quiet=True,
    )


@pytest.mark.parametrize("lang", _LANGS)
def test_family_selected(lang):
    assert _POLICIES[lang] is not None and _POLICIES[lang].family == _FAMILIES[lang]


@pytest.mark.parametrize(
    ("lang", "name", "file", "line", "snippet", "dataflow", "overrides", "expected"),
    _CASES,
    ids=_CASE_IDS,
)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_synthetic_panel(mc, lang, name, file, line, snippet, dataflow, overrides, expected):
    case = (name, file, line, snippet, dataflow, overrides, expected)
    v = _run(mc, [_assess(overrides=overrides)], lang, case=case)
    assert v.verdict == expected, name


@pytest.mark.parametrize("lang", _LANGS)
def test_panel_has_both_outcomes(lang):
    expected = [case[6] for case in _PANEL[lang]]
    assert expected.count("True Positive") == 4
    assert expected.count("False Positive") == 5


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_does_not_decide(mc, lang):
    # The model asserts a verdict the facts do not support; the table decides.
    raw = json.loads(_assess(overrides=_DATA_ONLY))
    raw["verdict"] = "True Positive"
    v = _run(mc, [json.dumps(raw)], lang)
    assert v.verdict == "False Positive"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_unresolved_capability_is_nmd_even_with_a_claimed_restriction(mc, lang):
    # Version-dependent decoder (library version not in evidence): capability is
    # left unresolved, so a restriction claim cannot dismiss and nothing confirms.
    overrides = {
        "deserializer_capability": {"value": "UNRESOLVED", "evidence": []},
        **_RESTRICTED,
    }
    v = _run(mc, [_assess(overrides=overrides)] * 5, lang)
    assert v.verdict == "Needs More Data"
    assert "deserializer_capability" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_uncited_restriction_bypass_is_nmd(mc, lang):
    # "No filter was seen" with nothing cited is not a witnessed unrestricted path.
    overrides = {"type_restriction": {"value": "UNRESOLVED", "evidence": []}}
    v = _run(mc, [_assess(overrides=overrides)] * 5, lang)
    assert v.verdict == "Needs More Data"
    assert "type_restriction" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_non_exhaustive_restriction_is_nmd(mc, lang):
    # An ALL_REACHING_PATHS (allowlisted stream) claim supported only by a
    # non-exhaustive retrieved helper is inadmissible -> stays Needs More Data.
    responses = [
        _assess(
            overrides={"type_restriction": {"value": "UNRESOLVED", "evidence": []}},
            requests=[
                {"kind": "function", "subject": "open_stream", "for_slot": "type_restriction"}
            ],
        ),
        _assess(overrides=_flip("type_restriction", "ALL_REACHING_PATHS", ["R1"])),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_exhaustive_restriction_dismisses(mc, lang):
    responses = [
        _assess(
            overrides={"type_restriction": {"value": "UNRESOLVED", "evidence": []}},
            requests=[
                {"kind": "function", "subject": "open_stream", "for_slot": "type_restriction"}
            ],
        ),
        _assess(overrides=_flip("type_restriction", "ALL_REACHING_PATHS", ["R1"])),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True))
    assert v.verdict == "False Positive"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_non_exhaustive_data_only_claim_is_nmd(mc, lang):
    responses = [
        _assess(
            overrides={"deserializer_capability": {"value": "UNRESOLVED", "evidence": []}},
            requests=[
                {"kind": "function", "subject": "decode", "for_slot": "deserializer_capability"}
            ],
        ),
        _assess(overrides=_flip("deserializer_capability", "DATA_ONLY_ALL_PATHS", ["R1"])),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, lang):
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides=_flip("flow_to_sink", "REACHES", ["R1"])),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == "Needs More Data"
    assert "flow_to_sink" in v.reasoning


# --- rendered prompt --------------------------------------------------------

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct", re.IGNORECASE
)
_PAREN_LABEL = re.compile(r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)", re.IGNORECASE)
_BENCHMARK = re.compile(r"OWASP|Juliet|Benchmark|SecLLMHolmes|FP trap|FP case", re.IGNORECASE)

_GUIDANCE_TERMS = {
    "java": [
        "ObjectInputStream.readObject",
        "XMLDecoder",
        "XStream",
        "enableDefaultTyping",
        "SafeConstructor",
        "setObjectInputFilter",
        "resolveClass",
        "MessageDigest.isEqual",
    ],
    "python": [
        "pickle",
        "yaml.safe_load",
        "yaml.UnsafeLoader",
        "jsonpickle.decode",
        "weights_only",
        "allow_pickle",
        "find_class",
        "hmac.compare_digest",
    ],
}


@pytest.mark.parametrize("lang", _LANGS)
def test_overlay_has_family_slots_and_guidance_and_no_verdict_command(lang):
    policy = _POLICIES[lang]
    controller = PolicyClosureController(
        policy=policy,
        provider=MagicMock(),
        finding=_finding(lang),
        model="gpt-4o",
        ledger=_seeded(lang),
    )
    instr = controller.initial_instructions()
    assert "deserializer_capability" in instr
    assert "type_restriction" in instr
    assert "security_effect" not in instr
    assert "[L1]" in instr and "[D1]" in instr
    for guidance in policy.assessment_guidance:
        assert guidance in instr
    for term in _GUIDANCE_TERMS[lang]:
        assert term in instr, term
    guidance_text = "\n".join(policy.assessment_guidance)
    for pattern in (_VERDICT_CMD, _PAREN_LABEL, _BENCHMARK):
        assert not pattern.search(guidance_text), pattern.pattern
    assert not _VERDICT_CMD.search(instr)


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_prompt_sent_to_the_model_carries_the_guidance(mc, lang):
    _run(mc, [_assess()], lang)
    sent = "\n".join(str(m.get("content", "")) for m in mc.call_args_list[0].kwargs["messages"])
    assert _POLICIES[lang].assessment_guidance[3] in sent
    assert "deserializer_capability" in sent
    assert not _VERDICT_CMD.search(sent)
