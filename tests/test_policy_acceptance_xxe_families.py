# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic acceptance panel for the XML external entity (CWE-611)
families — Java and Python.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

All fixtures are synthetic. Each case pairs a realistic snippet with the facts a
careful reader derives from it. The deciding fact is the configuration of the
parser INSTANCE that parses the attacker document: the panel covers a visible
parser that resolves external entities, each dismissing fact (hardened on every
path, constant document, not an XML parse), and the fail-closed cases — a
factory/parser configured outside the cited code and a version-dependent
default both stay Needs More Data.

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
_RULES = {"java": "java/xxe", "python": "py/xxe"}
_CWES = {"java": ["CWE-611", "CWE-776", "CWE-827"], "python": ["CWE-611", "CWE-827"]}
_FAMILIES = {"java": "xxe_java", "python": "xxe_python"}
_POLICIES = {
    lang: _REG.resolve_family(cwe_ids=_CWES[lang], rule_id=rule, lang=lang)
    for lang, rule in _RULES.items()
}
_LANGS = sorted(_RULES)

# A fully-resolved True-Positive assessment (attacker document parsed by a visible
# parser instance that resolves external entities). Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_XML_PARSE_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "entity_resolution": {"value": "EXTERNAL_ENTITY_RESOLVING_PATH_FOUND", "evidence": ["L1"]},
}


def _flip(slot, value, evidence=("L1",)):
    return {slot: {"value": value, "evidence": list(evidence)}}


_NOT_SINK = _flip("sink_binding", "NOT_XML_PARSE_SINK")
_REFUTED = _flip("attacker_control", "REFUTED")
_DISABLED = _flip("entity_resolution", "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS")
_ENTITY_UNRESOLVED = {"entity_resolution": {"value": "UNRESOLVED", "evidence": []}}

# (case id, file, line, snippet, scanner dataflow, slot overrides, expected verdict)
_PANEL = {
    "java": [
        (
            "documentbuilder-default-factory-request-body",
            "src/main/java/app/InvoiceController.java",
            38,
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            "Document doc = dbf.newDocumentBuilder().parse(request.getInputStream());",
            "request.getInputStream() -> DocumentBuilder.parse",
            None,
            "True Positive",
        ),
        (
            "saxparser-secure-processing-only",
            "src/main/java/app/FeedImporter.java",
            52,
            "SAXParserFactory spf = SAXParserFactory.newInstance();\n"
            "spf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n"
            "spf.newSAXParser().parse(upload.getInputStream(), handler);",
            "upload.getInputStream() -> SAXParser.parse",
            # Secure-processing alone does not establish the disabled state; the
            # reader leaves the fact open and nothing confirms or dismisses.
            _ENTITY_UNRESOLVED,
            "Needs More Data",
        ),
        (
            "xmlinputfactory-external-entities-switched-on",
            "src/main/java/app/StaxReader.java",
            24,
            "XMLInputFactory xif = XMLInputFactory.newFactory();\n"
            "xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, true);\n"
            "XMLStreamReader r = xif.createXMLStreamReader(request.getReader());",
            "request.getReader() -> XMLInputFactory.createXMLStreamReader",
            None,
            "True Positive",
        ),
        (
            "transformer-default-factory-stream-source",
            "src/main/java/app/ReportRenderer.java",
            71,
            "Transformer t = TransformerFactory.newInstance().newTransformer();\n"
            "t.transform(new StreamSource(part.getInputStream()), result);",
            "part.getInputStream() -> Transformer.transform",
            None,
            "True Positive",
        ),
        (
            "documentbuilder-disallow-doctype-decl",
            "src/main/java/app/InvoiceController.java",
            64,
            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
            'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            "Document doc = dbf.newDocumentBuilder().parse(request.getInputStream());",
            "request.getInputStream() -> DocumentBuilder.parse",
            _DISABLED,
            "False Positive",
        ),
        (
            "xmlinputfactory-support-dtd-false",
            "src/main/java/app/StaxReader.java",
            40,
            "XMLInputFactory xif = XMLInputFactory.newFactory();\n"
            "xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n"
            "XMLStreamReader r = xif.createXMLStreamReader(request.getReader());",
            "request.getReader() -> XMLInputFactory.createXMLStreamReader",
            _DISABLED,
            "False Positive",
        ),
        (
            "constant-classpath-document",
            "src/main/java/app/Defaults.java",
            17,
            "Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder()\n"
            '    .parse(new InputSource(new StringReader("<defaults><page>20</page></defaults>")));',
            "literal -> DocumentBuilder.parse",
            _REFUTED,
            "False Positive",
        ),
        (
            "serializer-is-not-a-parse",
            "src/main/java/app/Exporter.java",
            29,
            "transformer.transform(new DOMSource(document), new StreamResult(response.getWriter()));",
            "document -> Transformer.transform",
            _NOT_SINK,
            "False Positive",
        ),
        (
            "factory-is-an-injected-field",
            "src/main/java/app/SoapEndpoint.java",
            45,
            "Document doc = this.documentBuilderFactory.newDocumentBuilder()\n"
            "    .parse(request.getInputStream());",
            "request.getInputStream() -> DocumentBuilder.parse",
            _ENTITY_UNRESOLVED,
            "Needs More Data",
        ),
    ],
    "python": [
        (
            "lxml-parser-resolve-entities-true",
            "app/views.py",
            27,
            "parser = etree.XMLParser(resolve_entities=True)\n"
            "root = etree.fromstring(request.data, parser)",
            "request.data -> lxml.etree.fromstring",
            None,
            "True Positive",
        ),
        (
            "lxml-parser-network-dtd",
            "app/importer.py",
            33,
            "parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)\n"
            "tree = etree.parse(request.files['feed'], parser)",
            "request.files['feed'] -> lxml.etree.parse",
            None,
            "True Positive",
        ),
        (
            "sax-external-general-entities-enabled",
            "app/sax_feed.py",
            19,
            "parser = xml.sax.make_parser()\n"
            "parser.setFeature(xml.sax.handler.feature_external_ges, True)\n"
            "parser.parse(io.BytesIO(request.get_data()))",
            "request.get_data() -> xml.sax.xmlreader.XMLReader.parse",
            None,
            "True Positive",
        ),
        (
            "lxml-parser-resolve-entities-false",
            "app/views.py",
            48,
            "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n"
            "root = etree.fromstring(request.data, parser)",
            "request.data -> lxml.etree.fromstring",
            _DISABLED,
            "False Positive",
        ),
        (
            "stdlib-elementtree-default-parser",
            "app/legacy.py",
            22,
            "import xml.etree.ElementTree as ET\nroot = ET.fromstring(request.data)",
            "request.data -> xml.etree.ElementTree.fromstring",
            _DISABLED,
            "False Positive",
        ),
        (
            "defusedxml-parse",
            "app/safe.py",
            14,
            "from defusedxml.ElementTree import fromstring\nroot = fromstring(request.data)",
            "request.data -> defusedxml.ElementTree.fromstring",
            _DISABLED,
            "False Positive",
        ),
        (
            "constant-document",
            "app/defaults.py",
            9,
            "root = etree.fromstring(b'<defaults><page>20</page></defaults>')",
            "literal -> lxml.etree.fromstring",
            _REFUTED,
            "False Positive",
        ),
        (
            "tostring-is-not-a-parse",
            "app/export.py",
            31,
            "return Response(etree.tostring(report_root), mimetype='application/xml')",
            "report_root -> lxml.etree.tostring",
            _NOT_SINK,
            "False Positive",
        ),
        (
            "lxml-default-parser-version-not-in-evidence",
            "app/webhook.py",
            16,
            "root = etree.fromstring(request.data)",
            "request.data -> lxml.etree.fromstring",
            # resolve_entities is not written and the lxml version is not in
            # evidence (True before 5.0, 'internal' from 5.0).
            _ENTITY_UNRESOLVED,
            "Needs More Data",
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
        cwe_ids=list(_CWES[lang]),
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


_FACTORY_REQUEST = [
    {"kind": "function", "subject": "newSecureParser", "for_slot": "entity_resolution"}
]


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
    # A case that leaves a fact open keeps answering the same way until the loop ends.
    v = _run(mc, [_assess(overrides=overrides)] * 5, lang, case=case)
    assert v.verdict == expected, name
    if expected == "Needs More Data":
        assert "entity_resolution" in v.reasoning


@pytest.mark.parametrize("lang", _LANGS)
def test_panel_has_all_three_outcomes(lang):
    expected = [case[6] for case in _PANEL[lang]]
    counts = tuple(
        expected.count(v) for v in ("True Positive", "False Positive", "Needs More Data")
    )
    assert counts == {"java": (3, 4, 2), "python": (3, 5, 1)}[lang]


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_does_not_decide(mc, lang):
    # The model asserts a verdict the facts do not support; the table decides.
    raw = json.loads(_assess(overrides=_DISABLED))
    raw["verdict"] = "True Positive"
    v = _run(mc, [json.dumps(raw)], lang)
    assert v.verdict == "False Positive"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_parser_factory_non_exhaustive_hardening_is_nmd(mc, lang):
    # The parser comes from a helper outside the cited code. A "disabled on every
    # path" claim supported only by a non-exhaustive retrieval is inadmissible.
    responses = [
        _assess(overrides=_ENTITY_UNRESOLVED, requests=_FACTORY_REQUEST),
        _assess(
            overrides=_flip("entity_resolution", "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS", ["R1"])
        ),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_parser_factory_exhaustive_hardening_dismisses(mc, lang):
    responses = [
        _assess(overrides=_ENTITY_UNRESOLVED, requests=_FACTORY_REQUEST),
        _assess(
            overrides=_flip("entity_resolution", "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS", ["R1"])
        ),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True))
    assert v.verdict == "False Positive"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_parser_factory_retrieved_unhardened_confirms(mc, lang):
    # The retrieved factory body shows the parser instance and no hardening: a
    # witnessed resolving path (CONCRETE_PATH admits a positive retrieval).
    responses = [
        _assess(overrides=_ENTITY_UNRESOLVED, requests=_FACTORY_REQUEST),
        _assess(
            overrides=_flip("entity_resolution", "EXTERNAL_ENTITY_RESOLVING_PATH_FOUND", ["R1"])
        ),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == "True Positive"


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_parser_factory_not_found_is_nmd(mc, lang):
    # The factory cannot be retrieved: its configuration is unknown either way.
    responses = [
        _assess(overrides=_ENTITY_UNRESOLVED, requests=_FACTORY_REQUEST),
        _assess(
            overrides=_flip("entity_resolution", "EXTERNAL_ENTITY_RESOLVING_PATH_FOUND", ["R1"])
        ),
    ]
    v = _run(mc, responses, lang, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == "Needs More Data"
    assert "entity_resolution" in v.reasoning


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
        "DocumentBuilderFactory",
        "SAXParserFactory",
        "XMLInputFactory",
        "TransformerFactory",
        "disallow-doctype-decl",
        "external-general-entities",
        "external-parameter-entities",
        "ACCESS_EXTERNAL_DTD",
        "FEATURE_SECURE_PROCESSING",
        "setExpandEntityReferences(false)",
        "SUPPORT_DTD",
    ],
    "python": [
        "lxml",
        "resolve_entities=True",
        "resolve_entities=False",
        "no_network",
        "defusedxml",
        "xml.etree.ElementTree",
        "xml.dom.minidom",
        "feature_external_ges",
        "set_default_parser",
        "lxml 5.0",
        "3.7.1",
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
    assert "entity_resolution" in instr
    assert "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS" in instr
    assert "neutralization_coverage" not in instr
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
def test_guidance_requires_the_same_parser_instance_and_excludes_entity_expansion(lang):
    text = _POLICIES[lang].assessment_guidance[3]
    assert text.startswith("entity_resolution:")
    assert "leave entity_resolution unresolved" in text
    assert "Internal entity expansion" in text


@pytest.mark.parametrize("lang", _LANGS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_prompt_sent_to_the_model_carries_the_guidance(mc, lang):
    _run(mc, [_assess()], lang)
    sent = "\n".join(str(m.get("content", "")) for m in mc.call_args_list[0].kwargs["messages"])
    assert _POLICIES[lang].assessment_guidance[3] in sent
    assert "entity_resolution" in sent
    assert not _VERDICT_CMD.search(sent)
