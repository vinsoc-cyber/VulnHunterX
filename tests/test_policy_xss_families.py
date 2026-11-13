# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Cross-site scripting (CWE-79/80) families for Java and Python: selection,
entailment and admissibility.

Both families select by rule alias only. CWE-79 is also carried by rules that do
not locate a response-output sink (Android WebView settings, template-engine
configuration audits, a header-injection rule), and a CWE selector would let
``sink_binding`` dismiss those as "not an HTML output sink". They stay on the
legacy route, and this module pins that.

The decision table is the same in both languages. Its two defensive facts —
``output_channel`` (markup vs a non-markup channel) and ``encoding_coverage``
(context-appropriate encoder on every reaching path) — are independent, and
coverage dismisses only a proven markup path.
"""

from __future__ import annotations

import re

import pytest

from vuln_hunter_x.context.evidence import EvidenceKind, EvidenceScope, EvidenceStatus
from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import is_admissible

_REG = load_policy_registry()
_FAMILIES = {"java": "xss_java", "python": "xss_python"}
_LANGS = sorted(_FAMILIES)

# Every id form a scanner emits for the rules each family owns.
_OWNED = {
    "java": [
        "java/xss",
        "config.opengrep-rules.java.lang.security.audit.xss.no-direct-response-writer",
        "java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer",
        "config.opengrep-rules.java.lang.security.servletresponse-writer-xss",
        "java.lang.security.servletresponse-writer-xss.servletresponse-writer-xss",
        "config.opengrep-rules.java.spring.security.injection.tainted-html-string",
        "java.spring.security.injection.tainted-html-string.tainted-html-string",
    ],
    "python": [
        "py/reflective-xss",
        "py/xss",
        "py/reflected-xss",
        "config.opengrep-rules.python.aws-lambda.security.tainted-html-response",
        "python.aws-lambda.security.tainted-html-response.tainted-html-response",
        "config.opengrep-rules.python.aws-lambda.security.tainted-html-string",
        "python.aws-lambda.security.tainted-html-string.tainted-html-string",
        "config.opengrep-rules.python.django.security.audit.avoid-mark-safe",
        "python.django.security.audit.avoid-mark-safe.avoid-mark-safe",
        "config.opengrep-rules.python.django.security.audit.xss.direct-use-of-httpresponse",
        "python.django.security.audit.xss.direct-use-of-httpresponse.direct-use-of-httpresponse",
        "config.opengrep-rules.python.django.security.audit.xss.formathtml-fstring-parameter",
        "python.django.security.audit.xss.formathtml-fstring-parameter.formathtml-fstring-parameter",
        "config.opengrep-rules.python.django.security.injection.raw-html-format",
        "python.django.security.injection.raw-html-format.raw-html-format",
        "config.opengrep-rules.python.django.security.injection.reflected-data-httpresponse",
        "python.django.security.injection.reflected-data-httpresponse.reflected-data-httpresponse",
        "config.opengrep-rules.python.django.security.injection.reflected-data-httpresponsebadrequest",
        "python.django.security.injection.reflected-data-httpresponsebadrequest.reflected-data-httpresponsebadrequest",
        "config.opengrep-rules.python.flask.security.audit.directly-returned-format-string",
        "python.flask.security.audit.directly-returned-format-string.directly-returned-format-string",
        "config.opengrep-rules.python.flask.security.audit.xss.make-response-with-unknown-content",
        "python.flask.security.audit.xss.make-response-with-unknown-content.make-response-with-unknown-content",
        "config.opengrep-rules.python.flask.security.injection.raw-html-format",
        "python.flask.security.injection.raw-html-concat.raw-html-format",
        "config.opengrep-rules.python.flask.security.response-contains-unsanitized-input",
        "python.flask.security.unsanitized-input.response-contains-unsanitized-input",
        "config.opengrep-rules.python.flask.security.xss.audit.explicit-unescape-with-markup",
        "python.flask.security.xss.audit.explicit-unescape-with-markup.explicit-unescape-with-markup",
        "config.opengrep-rules.python.pyramid.security.pyramid-direct-use-of-response",
        "python.pyramid.security.direct-use-of-response.pyramid-direct-use-of-response",
    ],
}

# Rules tagged CWE-79 that are deliberately NOT owned: (rule id, its CWE tags).
_LEFT_ON_LEGACY = {
    "java": [
        ("java/android/unsafe-android-webview-fetch", ["CWE-79", "CWE-749"]),
        ("java/android/websettings-javascript-enabled", ["CWE-79"]),
        ("java/android/webview-addjavascriptinterface", ["CWE-79"]),
        (
            "config.opengrep-rules.java.lang.security.audit.xssrequestwrapper-is-insecure",
            ["CWE-79"],
        ),
        (
            "java.lang.security.audit.xssrequestwrapper-is-insecure.xssrequestwrapper-is-insecure",
            ["CWE-79"],
        ),
        ("config.opengrep-rules.java.lang.security.audit.xss.jsp.use-escapexml", ["CWE-116"]),
    ],
    "python": [
        ("py/http-response-splitting", ["CWE-79", "CWE-113"]),
        ("py/jinja2/autoescape-false", ["CWE-79"]),
        ("py/jinja-autoescape-disabled", ["CWE-79"]),
        ("vulnhunterx.python.template-autoescape-disabled", ["CWE-79"]),
        (
            "config.opengrep-rules.python.django.security.audit.xss.global-autoescape-off",
            ["CWE-79"],
        ),
        (
            "config.opengrep-rules.python.django.security.audit.xss.context-autoescape-off",
            ["CWE-79"],
        ),
        (
            "config.opengrep-rules.python.django.security.audit.xss.class-extends-safestring",
            ["CWE-79"],
        ),
        ("config.opengrep-rules.python.django.security.audit.xss.html-magic-method", ["CWE-79"]),
        ("python.django.security.audit.xss.html-safe.html-safe", ["CWE-79"]),
        ("python.django.security.audit.xss.filter-with-is-safe.filter-with-is-safe", ["CWE-79"]),
        ("config.opengrep-rules.python.flask.security.unescaped-template-extension", ["CWE-79"]),
        ("python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2", ["CWE-79"]),
        (
            "python.flask.security.xss.audit.template-unescaped-with-safe.template-unescaped-with-safe",
            ["CWE-79"],
        ),
        ("config.opengrep-rules.python.lang.security.audit.mako-templates-detected", ["CWE-79"]),
        ("python.flask.security.audit.render-template-string.render-template-string", ["CWE-96"]),
    ],
}

_TP_FACTS = {
    "sink_binding": "QUALIFYING_HTML_OUTPUT_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "output_channel": "MARKUP_TEXT_PATH_FOUND",
    "encoding_coverage": "BYPASS_PATH_FOUND",
}
_DECISIVE = sorted(_TP_FACTS)


def _family(lang):
    return next(p for p in _REG._policies if p.family == _FAMILIES[lang])


def _resolve(lang, rule_id, cwes=("CWE-79",)):
    return _REG.resolve_family(cwe_ids=list(cwes), rule_id=rule_id, lang=lang)


# ── loading and selection ─────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_loads(lang):
    policy = _family(lang)
    assert _FAMILIES[lang] in _REG.families
    assert policy.languages == frozenset({lang})
    assert policy.version == "1"


@pytest.mark.parametrize("lang", _LANGS)
def test_selection_is_by_alias_not_cwe(lang):
    # No CWE selector: an unknown rule tagged CWE-79 or CWE-80 is not claimed.
    assert _family(lang).cwes == frozenset()
    assert _resolve(lang, "some/unknown-rule", ["CWE-79"]) is None
    assert _resolve(lang, "some/unknown-rule", ["CWE-80"]) is None


@pytest.mark.parametrize(
    ("lang", "rule_id"), [(lang, rule) for lang in _LANGS for rule in _OWNED[lang]]
)
def test_owned_rule_selects_family_in_every_id_form(lang, rule_id):
    for cwes in (["CWE-79"], ["CWE-80"], []):
        resolved = _resolve(lang, rule_id, cwes)
        assert resolved is not None and resolved.family == _FAMILIES[lang], (rule_id, cwes)


def test_py_reflective_xss_with_its_real_cwe_tags():
    # CodeQL tags the rule CWE-79 and CWE-116; no other family owns CWE-116.
    resolved = _resolve("python", "py/reflective-xss", ["CWE-79", "CWE-116"])
    assert resolved is not None and resolved.family == "xss_python"


@pytest.mark.parametrize(
    ("lang", "rule_id", "cwes"),
    [(lang, rule, cwes) for lang in _LANGS for rule, cwes in _LEFT_ON_LEGACY[lang]],
)
def test_config_and_audit_rules_stay_off_the_family(lang, rule_id, cwes):
    resolved = _resolve(lang, rule_id, cwes)
    assert resolved is None or not resolved.family.startswith("xss"), rule_id


@pytest.mark.parametrize("lang", _LANGS)
def test_language_gate(lang):
    other = "python" if lang == "java" else "java"
    for rule_id in _OWNED[lang]:
        resolved = _resolve(other, rule_id)
        assert resolved is None or resolved.family != _FAMILIES[lang], rule_id
    for foreign in ("javascript", "php", "go", "csharp"):
        resolved = _resolve(foreign, _OWNED[lang][0])
        assert resolved is None or not resolved.family.startswith("xss")
    assert _resolve("javascript", "js/xss") is None
    assert _resolve("php", "php/reflected-xss") is None


# ── decision table ────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_slots_and_decisive_set(lang):
    policy = _family(lang)
    assert policy.decisive_slots == frozenset(_DECISIVE)
    assert "production_scope" in policy.fact_slots
    assert "production_scope" not in policy.decisive_slots
    assert set(policy.admissibility["production_scope"].values()) == {"ANY_CITATION"}


@pytest.mark.parametrize("lang", _LANGS)
def test_entail_true_positive(lang):
    decision = entail(_family(lang), _TP_FACTS)
    assert decision.verdict == TP
    assert decision.terminal_reason is None


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_HTML_OUTPUT_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("output_channel", "NON_MARKUP_ONLY_ALL_PATHS"),
        ("encoding_coverage", "ALL_REACHING_PATHS"),
    ],
)
def test_each_safe_value_dominates(lang, slot, value):
    decision = entail(_family(lang), {**_TP_FACTS, slot: value})
    assert decision.verdict == FP
    assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_HTML_OUTPUT_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("output_channel", "NON_MARKUP_ONLY_ALL_PATHS"),
    ],
)
def test_single_safe_fact_is_sufficient_alone(lang, slot, value):
    assert entail(_family(lang), {slot: value}).verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("missing", _DECISIVE)
def test_each_missing_decisive_slot_is_nmd(lang, missing):
    facts = {k: v for k, v in _TP_FACTS.items() if k != missing}
    decision = entail(_family(lang), facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == f"unresolved: {missing}"


@pytest.mark.parametrize("lang", _LANGS)
def test_coverage_without_a_markup_channel_does_not_dismiss(lang):
    # An encoder can only be matched against a known output context. With
    # output_channel unresolved, coverage must not dismiss vacuously.
    policy = _family(lang)
    alone = entail(policy, {"encoding_coverage": "ALL_REACHING_PATHS"})
    assert alone.verdict == NMD
    facts = {k: v for k, v in _TP_FACTS.items() if k != "output_channel"}
    partial = entail(policy, {**facts, "encoding_coverage": "ALL_REACHING_PATHS"})
    assert partial.verdict == NMD
    assert "output_channel" in (partial.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
def test_no_facts_is_nmd_naming_every_decisive_slot(lang):
    decision = entail(_family(lang), {})
    assert decision.verdict == NMD
    for slot in _DECISIVE:
        assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
def test_production_scope_never_decides(lang):
    policy = _family(lang)
    for scope in policy.fact_slots["production_scope"]:
        assert entail(policy, {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(policy, {"production_scope": scope}).verdict == NMD


def test_decision_table_is_identical_across_languages():
    java, python = _family("java"), _family("python")
    assert dict(java.fact_slots) == dict(python.fact_slots)
    assert java.decisive_slots == python.decisive_slots
    assert dict(java.true_positive) == dict(python.true_positive)
    assert [dict(c) for c in java.false_positive_if_any] == [
        dict(c) for c in python.false_positive_if_any
    ]
    assert {s: dict(v) for s, v in java.admissibility.items()} == {
        s: dict(v) for s, v in python.admissibility.items()
    }


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


def _retrieved(kind=EvidenceKind.FUNCTION, *, status=EvidenceStatus.FOUND, exhaustive=True):
    return EvidenceEntry(
        id="R1",
        origin=EvidenceOrigin.RETRIEVED,
        summary="r",
        status=status,
        scope=EvidenceScope.REPOSITORY_INDEX,
        exhaustive=exhaustive,
        kind=kind,
    )


@pytest.mark.parametrize("lang", _LANGS)
def test_positive_values_admit_local_and_dataflow(lang):
    policy = _family(lang)
    assert is_admissible(policy, "sink_binding", "QUALIFYING_HTML_OUTPUT_SINK", [_LOCAL])
    assert is_admissible(policy, "attacker_control", "PROVEN", [_DATAFLOW])
    assert is_admissible(policy, "flow_to_sink", "REACHES", [_DATAFLOW])
    assert is_admissible(policy, "output_channel", "MARKUP_TEXT_PATH_FOUND", [_LOCAL])
    assert is_admissible(policy, "encoding_coverage", "BYPASS_PATH_FOUND", [_LOCAL])


@pytest.mark.parametrize("lang", _LANGS)
def test_dataflow_alone_cannot_establish_a_safe_value(lang):
    policy = _family(lang)
    assert not is_admissible(policy, "sink_binding", "NOT_HTML_OUTPUT_SINK", [_DATAFLOW])
    assert not is_admissible(policy, "attacker_control", "REFUTED", [_DATAFLOW])
    assert not is_admissible(policy, "flow_to_sink", "NO_PATH_COMPLETE", [_DATAFLOW])
    assert not is_admissible(policy, "output_channel", "NON_MARKUP_ONLY_ALL_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "encoding_coverage", "ALL_REACHING_PATHS", [_DATAFLOW])


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    "slot_value",
    [
        ("encoding_coverage", "ALL_REACHING_PATHS"),
        ("output_channel", "NON_MARKUP_ONLY_ALL_PATHS"),
    ],
)
def test_all_paths_values_need_local_or_exhaustive_non_framework_evidence(lang, slot_value):
    policy = _family(lang)
    slot, value = slot_value
    # A locally visible encoder call / content-type assignment is enough.
    assert is_admissible(policy, slot, value, [_LOCAL])
    # So is an exhaustive retrieval of real code.
    assert is_admissible(policy, slot, value, [_retrieved()])
    # A non-exhaustive retrieval is not.
    assert not is_admissible(policy, slot, value, [_retrieved(exhaustive=False)])
    # Framework evidence ("the template engine auto-escapes") never is, even
    # when the lookup reports an exhaustive FOUND.
    for kind in (EvidenceKind.FRAMEWORK_SANITIZERS, EvidenceKind.FRAMEWORK_GUARDS):
        assert not is_admissible(policy, slot, value, [_retrieved(kind)])
    # An incomplete index or a miss proves nothing.
    for status in (EvidenceStatus.INCOMPLETE_INDEX, EvidenceStatus.NOT_FOUND_COMPLETE):
        assert not is_admissible(policy, slot, value, [_retrieved(status=status)])


@pytest.mark.parametrize("lang", _LANGS)
def test_uncited_values_fail_closed(lang):
    policy = _family(lang)
    for slot, value in _TP_FACTS.items():
        assert not is_admissible(policy, slot, value, [])


# ── guidance ──────────────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct|"
    r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)|OWASP Benchmark|Juliet|"
    r"OWASP FP|FP trap|FP case",
    re.IGNORECASE,
)


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_has_one_entry_per_decisive_slot_and_no_verdict_command(lang):
    guidance = _family(lang).assessment_guidance
    assert sorted(g.split(":", 1)[0] for g in guidance) == _DECISIVE
    for entry in guidance:
        assert not _VERDICT_CMD.search(entry), entry[:80]


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_states_the_fail_closed_rules(lang):
    text = " ".join(_family(lang).assessment_guidance)
    # Context-appropriate encoding, not "an escape is present".
    assert "HTML entity encoding does NOT cover a JavaScript string" in text
    # A positive needs a witnessed path, not an unseen helper with no encoder.
    assert "BYPASS_PATH_FOUND requires a WITNESSED path" in text
    assert "not in evidence" in text
    # Framework / configuration behaviour is not evidence for coverage.
    assert "Framework or configuration behaviour is not evidence here" in text
    assert "leave encoding_coverage UNRESOLVED" in text
    # Stored values: a read alone does not establish control.
    assert "write path from request data" in text


def test_java_guidance_names_real_sinks_and_encoders():
    text = " ".join(_family("java").assessment_guidance)
    for name in (
        "HttpServletResponse.getWriter()",
        "ServletOutputStream",
        "<%= ... %>",
        "${...}",
        "@ResponseBody",
        "Encode.forHtml",
        "Encode.forJavaScript",
        "HtmlUtils.htmlEscape",
        "StringEscapeUtils.escapeHtml4",
        "<c:out>",
        "fn:escapeXml",
        "th:utext",
    ):
        assert name in text, name


def test_python_guidance_names_real_sinks_and_encoders():
    text = " ".join(_family("python").assessment_guidance)
    for name in (
        "flask.make_response(str)",
        "HttpResponse",
        "render_template_string",
        "markupsafe.Markup(x)",
        "mark_safe(x)",
        "format_html",
        "html.escape(s, quote=False)",
        "markupsafe.escape",
        "|safe",
        "flask.jsonify",
        "JsonResponse",
    ):
        assert name in text, name
    # Auto-escaping needs the template text in evidence.
    assert "If the template file or the engine configuration is not in evidence" in text
    assert "the absence of a visible |safe is not evidence" in text
