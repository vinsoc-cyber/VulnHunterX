# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Path-access (CWE-22 family) policies for Java, Python, JavaScript, Go and C#:
selection, language gate, entailment truth table and decision-table parity.

Each language has its own file (``path_access_<lang>``) because the guidance
names language-specific sinks and confinement idioms. The decision table is the
PHP ``path_access`` table with two documented differences, identical in all
five files:

1. no ``handoff_from`` / ``applicability`` block, so ``sink_binding:
   NOT_PATH_ACCESS_SINK`` is a False Positive condition (the family is the
   primary owner selected by CWE, like the SQL and command families) instead of
   PHP's not-applicable handoff outcome;
2. ``defense_coverage: ALL_REACHING_PATHS`` is admitted by
   ``LOCAL_OR_EXHAUSTIVE`` instead of ``EXHAUSTIVE_ENCODER``: a
   canonicalise-then-containment check is locally visible and is not an encoder.

Archive-extraction ("zip slip" / "tar slip") rules are tagged CWE-22, so they
are members of this family too.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.handoff import classify_applicability
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import PolicyOverlapError, load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import SELECTABLE_PROFILES, is_admissible

_ROOT = Path(__file__).resolve().parents[1]
_POLICIES = _ROOT / "config" / "policies"
_INVENTORY = _ROOT / "tests" / "fixtures" / "policy_selector_audit" / "rule_inventory.json"

_REG = load_policy_registry()
_LANGS = ("java", "python", "javascript", "go", "csharp")
_PATH_CWES = ("CWE-22", "CWE-23", "CWE-36")

# Real rule ids per language, in every id form that exists for the rule, with
# the CWE tags the scanner attaches (from the selector-audit inventory).
_RULES: dict[str, list[tuple[str, list[str]]]] = {
    "java": [
        ("java/path-injection", ["CWE-22", "CWE-23", "CWE-36", "CWE-73"]),
        ("java/partial-path-traversal", ["CWE-23"]),
        ("java/partial-path-traversal-from-remote", ["CWE-23"]),
        ("java/zipslip", ["CWE-22"]),
        ("java/zip-slip", ["CWE-22"]),
        ("config.opengrep-rules.java.lang.security.httpservlet-path-traversal", ["CWE-22"]),
        (
            "java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
            ["CWE-22"],
        ),
        ("config.opengrep-rules.java.jax-rs.security.jax-rs-path-traversal", ["CWE-22"]),
        ("java.jax-rs.security.jax-rs-path-traversal.jax-rs-path-traversal", ["CWE-22"]),
        ("config.opengrep-rules.java.spring.security.injection.tainted-file-path", ["CWE-23"]),
        ("java.spring.security.injection.tainted-file-path.tainted-file-path", ["CWE-23"]),
    ],
    "python": [
        ("py/path-injection", ["CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"]),
        ("py/tarslip", ["CWE-22"]),
        ("config.opengrep-rules.python.flask.security.injection.path-traversal-open", ["CWE-22"]),
        (
            "python.flask.security.injection.path-traversal-open.path-traversal-open",
            ["CWE-22"],
        ),
        (
            "config.opengrep-rules.python.django.security.injection.path-traversal."
            "path-traversal-join",
            ["CWE-22"],
        ),
        (
            "python.django.security.injection.path-traversal.path-traversal-join."
            "path-traversal-join",
            ["CWE-22"],
        ),
        (
            "config.opengrep-rules.python.django.security.injection.request-data-fileresponse",
            ["CWE-22"],
        ),
        # The one Flask rule tagged only CWE-73: claimed by the alias glob.
        (
            "config.opengrep-rules.python.flask.security.avoid_send_file_without_path_sanitization",
            ["CWE-73"],
        ),
        (
            "python.flask.security.secure-static-file-serve."
            "avoid_send_file_without_path_sanitization",
            ["CWE-73"],
        ),
    ],
    "javascript": [
        ("js/path-injection", ["CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"]),
        ("js/path-traversal", ["CWE-22"]),
        ("js/zipslip", ["CWE-22"]),
        (
            "config.opengrep-rules.javascript.lang.security.audit.detect-non-literal-fs-filename",
            ["CWE-22"],
        ),
        (
            "javascript.lang.security.audit.detect-non-literal-fs-filename."
            "detect-non-literal-fs-filename",
            ["CWE-22"],
        ),
        (
            "config.opengrep-rules.javascript.lang.security.audit.path-traversal."
            "path-join-resolve-traversal",
            ["CWE-22"],
        ),
        (
            "javascript.express.security.audit.express-path-join-resolve-traversal."
            "express-path-join-resolve-traversal",
            ["CWE-22"],
        ),
        # Tagged only CWE-73: claimed by the alias glob.
        (
            "config.opengrep-rules.javascript.express.security.audit.express-res-sendfile",
            ["CWE-73"],
        ),
        (
            "javascript.express.security.audit.express-res-sendfile.express-res-sendfile",
            ["CWE-73"],
        ),
    ],
    "go": [
        ("go/path-injection", ["CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"]),
        ("go/zipslip", ["CWE-22"]),
        ("go/unsafe-unzip-symlink", ["CWE-22"]),
        ("config.opengrep-rules.go.lang.security.filepath-clean-misuse", ["CWE-22"]),
        ("go.lang.security.filepath-clean-misuse.filepath-clean-misuse", ["CWE-22"]),
        (
            "config.opengrep-rules.go.lang.security.path-traversal-inside-zip-extraction",
            ["CWE-22"],
        ),
        ("go.lang.security.zip.path-traversal-inside-zip-extraction", ["CWE-22"]),
    ],
    "csharp": [
        ("cs/path-injection", ["CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"]),
        ("cs/zipslip", ["CWE-22"]),
        ("config.opengrep-rules.csharp.lang.security.filesystem.unsafe-path-combine", ["CWE-22"]),
        (
            "csharp.lang.security.filesystem.unsafe-path-combine.unsafe-path-combine",
            ["CWE-22"],
        ),
    ],
}

# CodeQL ids listed as aliases: they must route even when a result has no CWE tag.
_CODEQL_ALIASES = {
    "java": ["java/path-injection", "java/partial-path-traversal", "java/zipslip", "java/zip-slip"],
    "python": ["py/path-injection", "py/tarslip"],
    "javascript": ["js/path-injection", "js/path-traversal", "js/zipslip"],
    "go": ["go/path-injection", "go/zipslip", "go/unsafe-unzip-symlink"],
    "csharp": ["cs/path-injection", "cs/zipslip"],
}

_TP_FACTS = {
    "sink_binding": "QUALIFYING_PATH_ACCESS_SINK",
    "attacker_control": "PROVEN",
    "flow_to_path": "REACHES",
    "path_escape": "ESCAPE_PATH_FOUND",
    "defense_coverage": "BYPASS_PATH_FOUND",
    "security_effect": "SECURITY_RELEVANT_EFFECT",
}
_FP_VALUES = [
    ("sink_binding", "NOT_PATH_ACCESS_SINK"),
    ("attacker_control", "REFUTED"),
    ("flow_to_path", "NO_PATH_COMPLETE"),
    ("path_escape", "CONFINED_ALL_PATHS"),
    ("defense_coverage", "ALL_REACHING_PATHS"),
    ("security_effect", "NO_SECURITY_EFFECT"),
]


def _family(lang: str) -> str:
    return f"path_access_{lang}"


def _policy(lang: str):
    policy = _REG.resolve_family(cwe_ids=["CWE-22"], rule_id="", lang=lang)
    assert policy is not None
    return policy


def _raw(name: str) -> dict:
    return yaml.safe_load((_POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))


def _inventory() -> list[dict]:
    return json.loads(_INVENTORY.read_text(encoding="utf-8"))["rules"]


# ── loading and selection ─────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_loads_with_expected_name_and_language(lang):
    assert _family(lang) in _REG.families
    raw = _raw(_family(lang))
    assert raw["family"] == _family(lang)
    assert raw["version"] == "1"
    assert raw["selectors"]["languages"] == [lang]
    assert "path_access" in _REG.families  # the PHP family is untouched and coexists


@pytest.mark.parametrize("lang", _LANGS)
def test_policy_file_starts_with_the_licence_header(lang):
    lines = (_POLICIES / f"{_family(lang)}.yaml").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "# SPDX-License-Identifier: LGPL-2.1-only"
    assert lines[1] == "# Copyright (c) 2026 VinSOC Cyber"


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("cwe", _PATH_CWES)
def test_selected_by_each_path_cwe(lang, cwe):
    policy = _REG.resolve_family(cwe_ids=[cwe], rule_id="some/unlisted-rule", lang=lang)
    assert policy is not None and policy.family == _family(lang)


@pytest.mark.parametrize(
    ("lang", "rule_id", "cwes"),
    [(lang, rule, cwes) for lang, rules in _RULES.items() for rule, cwes in rules],
)
def test_selected_for_real_rule_ids_in_every_id_form(lang, rule_id, cwes):
    policy = _REG.resolve_family(cwe_ids=cwes, rule_id=rule_id, lang=lang)
    assert policy is not None and policy.family == _family(lang)


@pytest.mark.parametrize(
    ("lang", "rule_id"),
    [(lang, rule) for lang, rules in _CODEQL_ALIASES.items() for rule in rules],
)
def test_codeql_ids_route_by_alias_without_cwe_tags(lang, rule_id):
    policy = _REG.resolve_family(cwe_ids=[], rule_id=rule_id, lang=lang)
    assert policy is not None and policy.family == _family(lang)


@pytest.mark.parametrize("lang", _LANGS)
def test_every_inventory_rule_with_a_path_cwe_resolves_to_this_family(lang):
    selected = set(_raw(_family(lang))["selectors"]["cwes"])
    rows = [r for r in _inventory() if r["lang"] == lang and selected & set(r["cwes"])]
    assert rows, lang
    for row in rows:
        policy = _REG.resolve_family(cwe_ids=row["cwes"], rule_id=row["rule_id"], lang=lang)
        assert policy is not None and policy.family == _family(lang), row["rule_id"]


# ── selector boundaries ───────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_language_gate_keeps_other_languages_out(lang):
    for other in ("c", "cpp", "php", *_LANGS):
        if other == lang:
            continue
        policy = _REG.resolve_family(cwe_ids=["CWE-22"], rule_id="x/path", lang=other)
        assert policy is None or policy.family != _family(lang), (lang, other)


def test_php_cwe22_still_belongs_to_the_php_family():
    policy = _REG.resolve_family(cwe_ids=["CWE-22"], rule_id="php/path-injection", lang="php")
    assert policy is not None and policy.family == "path_access"


def test_cwe73_is_selected_for_java_only():
    selected = {lang: set(_raw(_family(lang))["selectors"]["cwes"]) for lang in _LANGS}
    assert selected["java"] == {"CWE-22", "CWE-23", "CWE-36", "CWE-73"}
    for lang in ("python", "javascript", "go", "csharp"):
        assert selected[lang] == {"CWE-22", "CWE-23", "CWE-36"}, lang
    # CWE-98 (file inclusion) stays PHP-only.
    assert all("CWE-98" not in cwes for cwes in selected.values())


def test_java_cwe73_selector_has_no_command_class_collision_in_the_inventory():
    # The condition under which Java may select CWE-73.
    command = {"CWE-77", "CWE-78", "CWE-88"}
    clash = [
        r["rule_id"]
        for r in _inventory()
        if r["lang"] == "java" and "CWE-73" in r["cwes"] and command & set(r["cwes"])
    ]
    assert clash == []
    policy = _REG.resolve_family(cwe_ids=["CWE-73"], rule_id="java/some-rule", lang="java")
    assert policy is not None and policy.family == "path_access_java"


def test_python_shell_command_rule_is_not_claimed_by_the_path_family():
    # CWE-73 + CWE-78 + CWE-88: a command-class rule. Selecting CWE-73 for Python
    # would make it match two families once a Python command family exists.
    policy = _REG.resolve_family(
        cwe_ids=["CWE-73", "CWE-78", "CWE-88"],
        rule_id="py/shell-command-constructed-from-input",
        lang="python",
    )
    assert policy is None or policy.family != "path_access_python"
    bare = _REG.resolve_family(cwe_ids=["CWE-73"], rule_id="py/other-rule", lang="python")
    assert bare is None or bare.family != "path_access_python"


def test_javascript_template_object_injection_is_not_claimed_by_the_path_family():
    # CWE-73 + CWE-94: a code-injection-class rule.
    policy = _REG.resolve_family(
        cwe_ids=["CWE-73", "CWE-94"], rule_id="js/template-object-injection", lang="javascript"
    )
    assert policy is None or policy.family != "path_access_javascript"


@pytest.mark.parametrize("lang", ("python", "javascript", "go", "csharp"))
def test_bare_cwe73_is_not_selected_outside_java(lang):
    policy = _REG.resolve_family(cwe_ids=["CWE-73"], rule_id="x/unlisted", lang=lang)
    assert policy is None or policy.family != _family(lang)


def test_alias_globs_do_not_reach_unrelated_rules():
    for lang, rule_id in (
        ("python", "python.flask.security.injection.os-system-injection.os-system-injection"),
        ("python", "python.flask.security.audit.render-template-string.render-template-string"),
        (
            "javascript",
            "javascript.express.security.audit.express-open-redirect.express-open-redirect",
        ),
        ("java", "java/relative-path-command"),
    ):
        policy = _REG.resolve_family(cwe_ids=[], rule_id=rule_id, lang=lang)
        assert policy is None or policy.family != _family(lang), rule_id


@pytest.mark.parametrize("lang", _LANGS)
def test_path_cwe_together_with_another_owned_cwe_fails_closed(lang):
    # CWE-117 is owned by the language-agnostic log_injection family.
    with pytest.raises(PolicyOverlapError):
        _REG.resolve_family(cwe_ids=["CWE-22", "CWE-117"], rule_id="x", lang=lang)


# ── entailment truth table ────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_full_conjunction_is_true_positive(lang):
    decision = entail(_policy(lang), _TP_FACTS)
    assert decision.verdict == TP
    assert decision.family == _family(lang)
    assert decision.terminal_reason is None


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(("slot", "value"), _FP_VALUES)
def test_each_safe_value_dominates_as_false_positive(lang, slot, value):
    decision = entail(_policy(lang), {**_TP_FACTS, slot: value})
    assert decision.verdict == FP
    assert f"{slot}={value}" in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(("slot", "value"), _FP_VALUES)
def test_a_single_safe_fact_dismisses_even_when_nothing_else_is_resolved(lang, slot, value):
    assert entail(_policy(lang), {slot: value}).verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("missing", sorted(_TP_FACTS))
def test_each_missing_decisive_slot_is_needs_more_data(lang, missing):
    facts = {k: v for k, v in _TP_FACTS.items() if k != missing}
    decision = entail(_policy(lang), facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == f"unresolved: {missing}"


@pytest.mark.parametrize("lang", _LANGS)
def test_no_guard_seen_alone_never_confirms(lang):
    # "No sanitizer visible" (BYPASS_PATH_FOUND) without a concrete escaping path
    # and a real effect is not a True Positive.
    policy = _policy(lang)
    facts = {
        "sink_binding": "QUALIFYING_PATH_ACCESS_SINK",
        "attacker_control": "PROVEN",
        "flow_to_path": "REACHES",
        "defense_coverage": "BYPASS_PATH_FOUND",
    }
    decision = entail(policy, facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == "unresolved: path_escape, security_effect"
    assert entail(policy, {"defense_coverage": "BYPASS_PATH_FOUND"}).verdict == NMD


@pytest.mark.parametrize("lang", _LANGS)
def test_production_scope_is_recorded_but_never_decisive(lang):
    policy = _policy(lang)
    assert "production_scope" in policy.fact_slots
    assert "production_scope" not in policy.decisive_slots
    for scope in policy.fact_slots["production_scope"]:
        assert entail(policy, {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(policy, {"production_scope": scope}).verdict == NMD


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


@pytest.mark.parametrize("lang", _LANGS)
def test_safe_on_all_paths_values_need_local_proof_not_just_dataflow(lang):
    policy = _policy(lang)
    for slot, value in (
        ("defense_coverage", "ALL_REACHING_PATHS"),
        ("path_escape", "CONFINED_ALL_PATHS"),
        ("attacker_control", "REFUTED"),
        ("sink_binding", "NOT_PATH_ACCESS_SINK"),
        ("security_effect", "NO_SECURITY_EFFECT"),
        ("flow_to_path", "NO_PATH_COMPLETE"),
    ):
        assert is_admissible(policy, slot, value, [_LOCAL]), (slot, value)
        assert not is_admissible(policy, slot, value, [_DATAFLOW]), (slot, value)
        assert not is_admissible(policy, slot, value, []), (slot, value)


@pytest.mark.parametrize("lang", _LANGS)
def test_positive_path_values_accept_the_scanner_dataflow(lang):
    policy = _policy(lang)
    for slot, value in (
        ("attacker_control", "PROVEN"),
        ("flow_to_path", "REACHES"),
        ("path_escape", "ESCAPE_PATH_FOUND"),
        ("defense_coverage", "BYPASS_PATH_FOUND"),
        ("security_effect", "SECURITY_RELEVANT_EFFECT"),
    ):
        assert is_admissible(policy, slot, value, [_DATAFLOW]), (slot, value)
    # The sink itself must be seen in the local slice.
    assert not is_admissible(policy, "sink_binding", "QUALIFYING_PATH_ACCESS_SINK", [_DATAFLOW])


@pytest.mark.parametrize("lang", _LANGS)
def test_every_slot_value_has_a_selectable_profile(lang):
    policy = _policy(lang)
    for slot, values in policy.fact_slots.items():
        for value in values:
            assert policy.admissibility[slot][value] in SELECTABLE_PROFILES, (slot, value)


# ── decision-table parity ─────────────────────────────────────────────

_TABLE_KEYS = ("fact_slots", "decisive_slots", "entailment", "admissibility")


@pytest.mark.parametrize("lang", _LANGS)
def test_decision_table_is_identical_across_the_five_languages(lang):
    reference = _raw("path_access_java")
    member = _raw(_family(lang))
    for key in _TABLE_KEYS:
        assert member[key] == reference[key], (lang, key)


@pytest.mark.parametrize("lang", _LANGS)
def test_table_differs_from_php_only_in_the_two_documented_points(lang):
    php = _raw("path_access")
    member = _raw(_family(lang))

    # Deviation 1: primary ownership — no handoff, no applicability gate, and the
    # not-a-path-sink value is a False Positive condition.
    assert "handoff_from" in php and "applicability" in php
    assert "handoff_from" not in member and "applicability" not in member
    assert {"sink_binding": "NOT_PATH_ACCESS_SINK"} not in php["entailment"][
        "false_positive_if_any"
    ]
    assert member["entailment"]["false_positive_if_any"] == [
        {"sink_binding": "NOT_PATH_ACCESS_SINK"},
        *php["entailment"]["false_positive_if_any"],
    ]

    # Deviation 2: the all-paths defense value is provable from the local slice.
    assert php["admissibility"]["defense_coverage"]["ALL_REACHING_PATHS"] == "EXHAUSTIVE_ENCODER"
    assert (
        member["admissibility"]["defense_coverage"]["ALL_REACHING_PATHS"] == "LOCAL_OR_EXHAUSTIVE"
    )
    expected_admissibility = json.loads(json.dumps(php["admissibility"]))
    expected_admissibility["defense_coverage"]["ALL_REACHING_PATHS"] = "LOCAL_OR_EXHAUSTIVE"
    assert member["admissibility"] == expected_admissibility

    # Everything else is the PHP table.
    assert member["fact_slots"] == php["fact_slots"]
    assert member["decisive_slots"] == php["decisive_slots"]
    assert member["entailment"]["true_positive"] == php["entailment"]["true_positive"]


@pytest.mark.parametrize("lang", _LANGS)
def test_not_a_path_sink_is_a_dismissal_here_and_a_handback_in_php(lang):
    facts = {"sink_binding": "NOT_PATH_ACCESS_SINK"}
    policy = _policy(lang)
    assert policy.handoff_from is None and policy.applicability is None
    assert classify_applicability(policy, facts) == "applicable"
    assert entail(policy, facts).verdict == FP

    php = _REG.resolve_family(cwe_ids=["CWE-22"], rule_id="php/path-injection", lang="php")
    assert classify_applicability(php, facts) == "not_applicable"
    assert entail(php, facts).verdict == NMD  # PHP never dismisses on this value


def test_local_canonicalise_and_prefix_check_is_admissible_here_but_not_in_php():
    php = _REG.resolve_family(cwe_ids=["CWE-22"], rule_id="php/path-injection", lang="php")
    assert not is_admissible(php, "defense_coverage", "ALL_REACHING_PATHS", [_LOCAL])
    for lang in _LANGS:
        assert is_admissible(_policy(lang), "defense_coverage", "ALL_REACHING_PATHS", [_LOCAL])


# ── guidance shape ────────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:is\s+)?(?:a\s+)?(?:False|True)\s+Positive|the rule is likely correct"
    r"|\b(?:True|False) Positive\b|Needs More Data",
    re.IGNORECASE,
)
_PAREN_LABEL = re.compile(r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)", re.IGNORECASE)
_BENCHMARK = re.compile(
    r"OWASP|Juliet|Benchmark|DVWA|WebGoat|NodeGoat|SecLLMHolmes|CVEfixes|FP trap|FP case",
    re.IGNORECASE,
)


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_has_one_neutral_entry_per_decisive_slot(lang):
    policy = _policy(lang)
    leading = [g.split(":", 1)[0] for g in policy.assessment_guidance]
    assert leading == list(_raw(_family(lang))["decisive_slots"])
    for entry in policy.assessment_guidance:
        assert not _VERDICT_CMD.search(entry), entry[:80]
        assert not _PAREN_LABEL.search(entry), entry[:80]
        assert not _BENCHMARK.search(entry), entry[:80]


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_names_both_values_of_each_decisive_slot_and_an_unresolved_exit(lang):
    policy = _policy(lang)
    by_slot = {g.split(":", 1)[0]: g for g in policy.assessment_guidance}
    for slot in policy.decisive_slots:
        for value in policy.fact_slots[slot]:
            assert value in by_slot[slot], (slot, value)
        assert "unresolved" in by_slot[slot], slot


# Language-specific sinks, defenses and API semantics the guidance must name.
_GUIDANCE_TOKENS = {
    "java": [
        "new File(",
        "Paths.get",
        "Files.*",
        "FileInputStream",
        "RandomAccessFile",
        "ServletContext.getResourceAsStream",
        "getCanonicalPath()",
        "toRealPath()",
        "toAbsolutePath().normalize()",
        "Path.startsWith(basePath), which compares whole name elements",
        "File.separator",
        "partial-path-traversal",
        "ZipEntry.getName()",
    ],
    "python": [
        "os.path.join(base, value) and pathlib base / value DISCARD the base",
        "os.path.realpath",
        "os.path.commonpath",
        "is_relative_to",
        "werkzeug.utils.safe_join",
        "flask.send_from_directory",
        "secure_filename",
        "flask.send_file",
        "FileResponse",
        "os.path.normpath",
        "tarfile",
    ],
    "javascript": [
        "createReadStream",
        "res.sendFile",
        "res.download",
        "path.resolve(base, value) restarts from value when value is absolute",
        "path.sep",
        "path.relative",
        "root option",
        "path.basename",
    ],
    "go": [
        "os.OpenFile",
        "http.ServeFile",
        "filepath.Join(base, value) concatenates and then applies filepath.Clean",
        "strings.HasPrefix",
        "filepath.Rel",
        "filepath.IsLocal",
        "os.Root",
        "http.Dir",
        "filepath.Base",
        "path.Clean('/' + value)",
        "tar.TypeSymlink",
    ],
    "csharp": [
        "FileStream",
        "StreamReader",
        "Path.Combine(base, value) RETURNS value alone when value is rooted",
        "Path.GetFullPath",
        "Path.DirectorySeparatorChar",
        "StringComparison.Ordinal",
        "Path.GetFileName",
        "PhysicalFile",
        "ZipArchiveEntry.FullName",
    ],
}


@pytest.mark.parametrize(
    ("lang", "token"),
    [(lang, token) for lang, tokens in _GUIDANCE_TOKENS.items() for token in tokens],
)
def test_guidance_names_language_specific_sinks_and_defenses(lang, token):
    assert token in " ".join(_policy(lang).assessment_guidance)


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_covers_archive_extraction(lang):
    by_slot = {g.split(":", 1)[0]: g for g in _policy(lang).assessment_guidance}
    assert "archive entry" in by_slot["sink_binding"].lower()
    assert "ARCHIVE is untrusted" in by_slot["attacker_control"]
    assert "archive" in by_slot["path_escape"].lower()
    assert (
        "archive extraction" in by_slot["defense_coverage"]
        or "tar extraction" in (by_slot["defense_coverage"])
    )
