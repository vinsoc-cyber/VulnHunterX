# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""OS command-injection (CWE-78/77) families beyond PHP: selection + entailment.

Six files share one decision table: ``command_injection_{java,python,javascript,
go,csharp}`` and ``command_injection_cpp`` (C and C++). The table is the PHP one
with a single deliberate change — ``command_channel`` has a second positive
value, ``EXECUTABLE_CONTROL_PATH_FOUND``, because these runtimes launch
processes without a shell — so ``true_positive.command_channel`` is a LIST
("any of"), and the coverage dismissal applies to either positive channel but
never to an unresolved one (argument injection stays Needs More Data).

Selectors differ per language and are pinned here: Python, C# and C/C++ select by
CWE; Java, JavaScript and Go select by rule alias because a CWE-78 selector would
claim rules that are not tainted-command sinks (or collide on a multi-CWE rule).
"""

from __future__ import annotations

import itertools
import re

import pytest

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import (
    PolicyError,
    PolicyOverlapError,
    load_policy_from_mapping,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import is_admissible

_REG = load_policy_registry()
_BY_FAMILY = {p.family: p for p in _REG._policies}

_SHELL = "SHELL_COMMAND_TEXT_PATH_FOUND"
_EXE = "EXECUTABLE_CONTROL_PATH_FOUND"
_FIXED = "FIXED_EXEC_DATA_OPERANDS_ONLY_ALL_PATHS"
_BYPASS = "BYPASS_PATH_FOUND"
_ALL = "ALL_REACHING_PATHS"

# family -> stage languages it is gated to.
_LANGS = {
    "command_injection_java": ("java",),
    "command_injection_python": ("python",),
    "command_injection_javascript": ("javascript",),
    "command_injection_go": ("go",),
    "command_injection_csharp": ("csharp",),
    "command_injection_cpp": ("c", "cpp"),
}
_FAMILIES = tuple(_LANGS)
_CWE_SELECTED = ("command_injection_python", "command_injection_csharp", "command_injection_cpp")
_ALIAS_ONLY = ("command_injection_java", "command_injection_javascript", "command_injection_go")

# family -> (rule id, CWE tags the scanner reports) for real rules, in every id
# form that exists: CodeQL `<lang>/<name>`, vendored OpenGrep
# `config.opengrep-rules.<dirs>.<id>`, semgrep.dev registry `<dirs>.<file>.<id>`.
_OWNED: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "command_injection_java": (
        ("java/command-line-injection", ("CWE-78", "CWE-88")),
        ("java/concatenated-command-line", ("CWE-78", "CWE-88")),
        (
            "config.opengrep-rules.java.lang.security.audit.command-injection-formatted-runtime-call",
            ("CWE-78",),
        ),
        (
            "java.lang.security.audit.command-injection-formatted-runtime-call"
            ".command-injection-formatted-runtime-call",
            ("CWE-78",),
        ),
        (
            "config.opengrep-rules.java.lang.security.audit.command-injection-process-builder",
            ("CWE-78",),
        ),
        (
            "java.lang.security.audit.command-injection-process-builder"
            ".command-injection-process-builder",
            ("CWE-78",),
        ),
        (
            "config.opengrep-rules.java.lang.security.audit.tainted-cmd-from-http-request",
            ("CWE-78",),
        ),
        (
            "java.lang.security.audit.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
            ("CWE-78",),
        ),
        (
            "config.opengrep-rules.java.spring.security.injection.tainted-system-command",
            ("CWE-78",),
        ),
        (
            "java.spring.security.injection.tainted-system-command.tainted-system-command",
            ("CWE-78",),
        ),
    ),
    "command_injection_python": (
        ("py/command-line-injection", ("CWE-78", "CWE-88")),
        # Also CWE-73: the Python path family deliberately does not select it.
        ("py/shell-command-constructed-from-input", ("CWE-73", "CWE-78", "CWE-88")),
        ("vulnhunterx.python.shell-true", ("CWE-78",)),
        ("config.opengrep-rules.python.lang.security.audit.subprocess-shell-true", ("CWE-78",)),
        (
            "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
            ("CWE-78",),
        ),
        (
            "config.opengrep-rules.python.lang.security.audit.paramiko.paramiko-exec-command",
            ("CWE-78",),
        ),
        (
            "python.flask.security.injection.os-system-injection.os-system-injection",
            ("CWE-78",),
        ),
        (
            "config.opengrep-rules.python.django.security.injection.command.subprocess-injection",
            ("CWE-78",),
        ),
        (
            "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args"
            ".dangerous-subprocess-use-tainted-env-args",
            ("CWE-78",),
        ),
        ("some/unknown-python-rule", ("CWE-77",)),
    ),
    "command_injection_javascript": (
        ("js/command-line-injection", ("CWE-78", "CWE-88")),
        ("js/indirect-command-line-injection", ("CWE-78", "CWE-88")),
        ("js/shell-command-constructed-from-input", ("CWE-78", "CWE-88")),
        ("js/shell-command-injection-from-environment", ("CWE-78", "CWE-88")),
        ("js/unnecessary-use-of-cat", ("CWE-78",)),
        ("js/command-injection", ("CWE-78",)),
        ("config.opengrep-rules.javascript.lang.security.detect-child-process", ("CWE-78",)),
        ("javascript.lang.security.detect-child-process.detect-child-process", ("CWE-78",)),
        (
            "config.opengrep-rules.javascript.aws-lambda.security.detect-child-process",
            ("CWE-78",),
        ),
        (
            "javascript.aws-lambda.security.detect-child-process.detect-child-process",
            ("CWE-78",),
        ),
        (
            "config.opengrep-rules.javascript.lang.security.audit.dangerous-spawn-shell",
            ("CWE-78",),
        ),
        (
            "javascript.lang.security.audit.dangerous-spawn-shell.dangerous-spawn-shell",
            ("CWE-78",),
        ),
        ("config.opengrep-rules.javascript.lang.security.audit.spawn-shell-true", ("CWE-78",)),
        ("javascript.lang.security.audit.spawn-shell-true.spawn-shell-true", ("CWE-78",)),
        (
            "config.opengrep-rules.javascript.shelljs.security.shelljs-exec-injection",
            ("CWE-78",),
        ),
        (
            "javascript.shelljs.security.shelljs-exec-injection.shelljs-exec-injection",
            ("CWE-78",),
        ),
        ("config.opengrep-rules.javascript.deno.security.audit.deno-dangerous-run", ("CWE-78",)),
        ("javascript.deno.security.audit.deno-dangerous-run.deno-dangerous-run", ("CWE-78",)),
    ),
    "command_injection_go": (
        ("go/command-injection", ("CWE-78",)),
        ("config.opengrep-rules.go.lang.security.audit.dangerous-command-write", ("CWE-78",)),
        (
            "go.lang.security.audit.dangerous-command-write.dangerous-command-write",
            ("CWE-78",),
        ),
    ),
    "command_injection_csharp": (
        ("cs/command-line-injection", ("CWE-78", "CWE-88")),
        (
            "config.opengrep-rules.csharp.lang.security.injections.os-command-injection",
            ("CWE-78",),
        ),
        ("csharp.lang.security.injections.os-command.os-command-injection", ("CWE-78",)),
        ("some/unknown-csharp-rule", ("CWE-77",)),
    ),
    "command_injection_cpp": (
        ("cpp/command-line-injection", ("CWE-78", "CWE-88")),
        ("cpp/command-injection", ("CWE-77", "CWE-78")),
        ("some/unknown-cpp-rule", ("CWE-77",)),
    ),
}

# Rules tagged CWE-78 that these families must NOT claim: (lang, rule id, CWEs).
_NOT_OURS = (
    # Java: not "attacker data reaches the command" — a constant command resolved
    # through PATH, attacker data in the child's environment, a backdoor pattern.
    ("java", "java/relative-path-command", ("CWE-78", "CWE-88")),
    ("java", "java/exec-tainted-environment", ("CWE-78", "CWE-88", "CWE-454")),
    (
        "java",
        "config.opengrep-rules.java.lang.security.audit.java-reverse-shell",
        ("CWE-78",),
    ),
    ("java", "java.lang.security.audit.java-reverse-shell.java-reverse-shell", ("CWE-78",)),
    # JavaScript: prototype pollution is tagged CWE-78 but is not a process launch.
    (
        "javascript",
        "js/prototype-pollution",
        ("CWE-78", "CWE-79", "CWE-94", "CWE-400", "CWE-471", "CWE-915"),
    ),
    (
        "javascript",
        "js/prototype-polluting-assignment",
        ("CWE-78", "CWE-79", "CWE-94", "CWE-400", "CWE-471", "CWE-915"),
    ),
    (
        "javascript",
        "js/prototype-pollution-utility",
        ("CWE-78", "CWE-79", "CWE-94", "CWE-400", "CWE-471", "CWE-915"),
    ),
    # JavaScript: argument injection into a fixed git/hg program — deferred class.
    ("javascript", "js/second-order-command-line-injection", ("CWE-78", "CWE-88")),
    ("javascript", "config.opengrep-rules.javascript.lang.security.spawn-git-clone", ("CWE-78",)),
    ("javascript", "javascript.lang.security.spawn-git-clone.spawn-git-clone", ("CWE-78",)),
    # Go: also CWE-89 and CWE-94; left to those classes' selectors.
    ("go", "go/unsafe-quoting", ("CWE-78", "CWE-89", "CWE-94")),
)

_TP_FACTS = {
    "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "command_channel": _SHELL,
    "neutralization_coverage": _BYPASS,
}
_DECISIVE = tuple(_TP_FACTS)


def _owner(rule_id: str, cwes: tuple[str, ...], lang: str) -> str | None:
    """Family name, ``None`` (legacy), or ``OVERLAP:<message>``."""
    try:
        policy = _REG.resolve_family(cwe_ids=list(cwes), rule_id=rule_id, lang=lang)
    except PolicyOverlapError as exc:
        return f"OVERLAP:{exc}"
    return policy.family if policy is not None else None


def _table(policy) -> tuple[object, ...]:
    return (
        {slot: tuple(values) for slot, values in policy.fact_slots.items()},
        policy.decisive_slots,
        dict(policy.true_positive),
        frozenset(frozenset(c.items()) for c in policy.false_positive_if_any),
        {slot: dict(values) for slot, values in policy.admissibility.items()},
    )


# ── loading and selection ────────────────────────────────────────────────────


@pytest.mark.parametrize("family", _FAMILIES)
def test_family_loads_with_expected_language_gate(family):
    policy = _BY_FAMILY[family]
    assert policy.version == "1"
    assert policy.languages == frozenset(_LANGS[family])


def test_php_reference_family_still_loads_beside_the_new_ones():
    assert "command_injection" in _BY_FAMILY
    assert _BY_FAMILY["command_injection"].languages == frozenset({"php"})


@pytest.mark.parametrize(
    ("family", "rule_id", "cwes"),
    [(family, rule, cwes) for family, rules in _OWNED.items() for rule, cwes in rules],
)
def test_real_rule_ids_resolve_to_the_family_in_every_id_form(family, rule_id, cwes):
    for lang in _LANGS[family]:
        assert _owner(rule_id, cwes, lang) == family, (rule_id, lang)


@pytest.mark.parametrize("family", _CWE_SELECTED)
def test_cwe_selected_families_select_cwe78_and_cwe77(family):
    assert _BY_FAMILY[family].cwes == frozenset({"CWE-78", "CWE-77"})
    for lang in _LANGS[family]:
        assert _owner("unknown/rule", ("CWE-78",), lang) == family
        assert _owner("unknown/rule", ("CWE-77",), lang) == family


@pytest.mark.parametrize("family", _ALIAS_ONLY)
def test_alias_only_families_do_not_select_by_cwe(family):
    # A CWE-78 selector in these languages would claim rules that are not
    # tainted-command sinks (see _NOT_OURS) — pinned so it is not reintroduced.
    assert _BY_FAMILY[family].cwes == frozenset()
    for lang in _LANGS[family]:
        assert _owner("unknown/rule", ("CWE-78",), lang) is None
        assert _owner("unknown/rule", ("CWE-77",), lang) is None


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), _NOT_OURS)
def test_cwe78_rules_that_are_not_tainted_command_sinks_are_not_claimed(lang, rule_id, cwes):
    # They may be legacy or belong to another class; they must never be routed to
    # a command family, alone or as one side of an overlap.
    owner = _owner(rule_id, cwes, lang)
    assert owner is None or "command_injection" not in owner, owner


@pytest.mark.parametrize("family", _FAMILIES)
def test_language_gate_same_rule_in_another_language_is_not_this_family(family):
    own = set(_LANGS[family])
    others = [lang for langs in _LANGS.values() for lang in langs if lang not in own] + ["php"]
    for rule_id, cwes in _OWNED[family]:
        for lang in others:
            assert _owner(rule_id, cwes, lang) != family, (rule_id, lang)


def test_cwe78_in_php_is_still_not_selected_by_cwe():
    # The PHP family stays alias-only; none of the new CWE selectors leaks into PHP.
    assert _owner("unknown/rule", ("CWE-78",), "php") is None


def test_python_multi_cwe_command_rule_does_not_overlap_the_path_class():
    # CWE-73 + CWE-78 + CWE-88 on one rule: exactly one family may match.
    owner = _owner(
        "py/shell-command-constructed-from-input", ("CWE-73", "CWE-78", "CWE-88"), "python"
    )
    assert owner == "command_injection_python"


# ── the PHP reference family: vendored OpenGrep id forms ─────────────────────

_PHP_VENDORED = (
    ("config.opengrep-rules.php.lang.security.injection.tainted-exec", ("CWE-78",)),
    ("config.opengrep-rules.php.lang.security.exec-use", ("CWE-94",)),
    ("config.opengrep-rules.php.lang.security.tainted-exec", ("CWE-94",)),
)
_PHP_REGISTRY = (
    ("php.lang.security.injection.tainted-exec.tainted-exec", ("CWE-78",)),
    ("php.lang.security.exec-use.exec-use", ("CWE-94",)),
    ("php.lang.security.tainted-exec.tainted-exec", ("CWE-94",)),
)


@pytest.mark.parametrize(("rule_id", "cwes"), _PHP_VENDORED + _PHP_REGISTRY)
def test_php_exec_rules_resolve_to_command_injection_in_both_semgrep_forms(rule_id, cwes):
    assert _owner(rule_id, cwes, "php") == "command_injection"
    # Selection is by alias: it holds with no CWE tag at all.
    assert _owner(rule_id, (), "php") == "command_injection"


@pytest.mark.parametrize(
    "rule_id",
    [
        "config.opengrep-rules.php.lang.security.eval-use",
        "php.lang.security.eval-use.eval-use",
        "config.opengrep-rules.php.wordpress-plugins.security.audit.wp-command-execution-audit",
        "php.wordpress-plugins.security.audit.wp-command-execution-audit"
        ".wp-command-execution-audit",
    ],
)
def test_php_aliases_are_exact_and_leave_other_cwe78_rules_unclaimed(rule_id):
    assert _owner(rule_id, ("CWE-78",), "php") is None


def test_php_aliases_are_exact_strings_not_globs():
    aliases = _BY_FAMILY["command_injection"].rule_aliases
    assert len(aliases) == 6
    assert not any(ch in alias for alias in aliases for ch in "*?[")
    assert _BY_FAMILY["command_injection"].cwes == frozenset()


def test_php_vendored_exec_rule_is_language_gated():
    assert _owner(_PHP_VENDORED[1][0], (), "go") is None


# ── decision-table parity ────────────────────────────────────────────────────


def test_decision_table_is_identical_in_all_six_files():
    reference = _table(_BY_FAMILY[_FAMILIES[0]])
    for family in _FAMILIES[1:]:
        assert _table(_BY_FAMILY[family]) == reference, family


def test_table_is_the_php_table_plus_exactly_one_positive_channel_value():
    php = _BY_FAMILY["command_injection"]
    new = _BY_FAMILY[_FAMILIES[0]]

    assert new.decisive_slots == php.decisive_slots
    assert set(new.fact_slots) == set(php.fact_slots)
    for slot in php.fact_slots:
        extra = set(new.fact_slots[slot]) - set(php.fact_slots[slot])
        assert extra == ({_EXE} if slot == "command_channel" else set()), slot
        assert set(php.fact_slots[slot]) <= set(new.fact_slots[slot])

    def without_exe(cond):
        return {slot: tuple(v for v in vals if v != _EXE) for slot, vals in cond.items()}

    assert without_exe(new.true_positive) == dict(php.true_positive)
    assert [without_exe(c) for c in new.false_positive_if_any] == [
        dict(c) for c in php.false_positive_if_any
    ]
    for slot, values in php.admissibility.items():
        for value, profile in values.items():
            assert new.admissibility[slot][value] == profile
    assert new.admissibility["command_channel"][_EXE] == "CONCRETE_PATH"


@pytest.mark.parametrize("family", _FAMILIES)
def test_list_valued_condition_is_parsed_as_any_of(family):
    policy = _BY_FAMILY[family]
    assert policy.true_positive["command_channel"] == (_SHELL, _EXE)
    coverage_fp = [c for c in policy.false_positive_if_any if "neutralization_coverage" in c]
    assert coverage_fp == [{"command_channel": (_SHELL, _EXE), "neutralization_coverage": (_ALL,)}]


def test_loader_rejects_an_undeclared_value_inside_a_list_condition():
    mapping = {
        "family": "toy",
        "fact_slots": {"channel": ["A", "B", "C"]},
        "entailment": {"true_positive": {"channel": ["A", "NOT_DECLARED"]}},
        "admissibility": {
            "channel": {"A": "CONCRETE_PATH", "B": "CONCRETE_PATH", "C": "LOCAL_OR_EXHAUSTIVE"}
        },
    }
    with pytest.raises(PolicyError, match="NOT_DECLARED"):
        load_policy_from_mapping(mapping)
    mapping["entailment"] = {"true_positive": {"channel": ["A", "B"]}}
    toy = load_policy_from_mapping(mapping)
    assert entail(toy, {"channel": "A"}).verdict == TP
    assert entail(toy, {"channel": "B"}).verdict == TP
    assert entail(toy, {"channel": "C"}).verdict == NMD


# ── entailment truth table ───────────────────────────────────────────────────


@pytest.mark.parametrize("family", _FAMILIES)
@pytest.mark.parametrize("channel", [_SHELL, _EXE])
def test_either_positive_channel_with_a_witnessed_bypass_is_tp(family, channel):
    decision = entail(_BY_FAMILY[family], {**_TP_FACTS, "command_channel": channel})
    assert decision.verdict == TP
    assert decision.terminal_reason is None


@pytest.mark.parametrize("family", _FAMILIES)
@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"sink_binding": "NOT_OS_COMMAND_SINK"}, "sink_binding=NOT_OS_COMMAND_SINK"),
        ({"attacker_control": "REFUTED"}, "attacker_control=REFUTED"),
        ({"flow_to_sink": "NO_PATH_COMPLETE"}, "flow_to_sink=NO_PATH_COMPLETE"),
        ({"command_channel": _FIXED}, f"command_channel={_FIXED}"),
        (
            {"command_channel": _SHELL, "neutralization_coverage": _ALL},
            f"command_channel={_SHELL}, neutralization_coverage={_ALL}",
        ),
        (
            {"command_channel": _EXE, "neutralization_coverage": _ALL},
            f"command_channel={_EXE}, neutralization_coverage={_ALL}",
        ),
    ],
)
def test_each_false_positive_condition_dominates(family, override, reason):
    decision = entail(_BY_FAMILY[family], {**_TP_FACTS, **override})
    assert decision.verdict == FP
    assert decision.terminal_reason == f"false_positive: {reason}"


@pytest.mark.parametrize("family", _FAMILIES)
@pytest.mark.parametrize("missing", _DECISIVE)
@pytest.mark.parametrize("channel", [_SHELL, _EXE])
def test_each_missing_decisive_slot_is_nmd_with_reason(family, missing, channel):
    facts = {**_TP_FACTS, "command_channel": channel}
    del facts[missing]
    decision = entail(_BY_FAMILY[family], facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == f"unresolved: {missing}"


@pytest.mark.parametrize("family", _FAMILIES)
@pytest.mark.parametrize("coverage", [_ALL, _BYPASS, None])
def test_argument_injection_with_unresolved_channel_is_never_dismissed(family, coverage):
    # CWE-88: the attacker controls only an option/argument of a fixed program and
    # no shell is involved, so no command_channel value is established. Whatever
    # is claimed for coverage ("no shell, so everything is neutralized"), the
    # finding stays Needs More Data — never a vacuous False Positive, never a TP.
    facts = {k: v for k, v in _TP_FACTS.items() if k != "command_channel"}
    if coverage is None:
        del facts["neutralization_coverage"]
    else:
        facts["neutralization_coverage"] = coverage
    decision = entail(_BY_FAMILY[family], facts)
    assert decision.verdict == NMD
    assert "command_channel" in (decision.terminal_reason or "")


@pytest.mark.parametrize("family", _FAMILIES)
def test_channel_by_coverage_grid_is_exactly_as_designed(family):
    policy = _BY_FAMILY[family]
    expected = {
        (_SHELL, _BYPASS): TP,
        (_EXE, _BYPASS): TP,
        (_SHELL, _ALL): FP,
        (_EXE, _ALL): FP,
        (_FIXED, _BYPASS): FP,  # the strong all-path channel state dominates
        (_FIXED, _ALL): FP,
        (_FIXED, None): FP,
        (_SHELL, None): NMD,
        (_EXE, None): NMD,
        (None, _BYPASS): NMD,
        (None, _ALL): NMD,
        (None, None): NMD,
    }
    channels = (*policy.fact_slots["command_channel"], None)
    coverages = (*policy.fact_slots["neutralization_coverage"], None)
    assert set(itertools.product(channels, coverages)) == set(expected)
    for (channel, coverage), verdict in expected.items():
        facts = {
            "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
            "attacker_control": "PROVEN",
            "flow_to_sink": "REACHES",
        }
        if channel is not None:
            facts["command_channel"] = channel
        if coverage is not None:
            facts["neutralization_coverage"] = coverage
        assert entail(policy, facts).verdict == verdict, (channel, coverage)


@pytest.mark.parametrize("family", _FAMILIES)
def test_production_scope_is_recorded_but_not_decisive(family):
    policy = _BY_FAMILY[family]
    assert "production_scope" in policy.fact_slots
    assert "production_scope" not in policy.decisive_slots
    assert set(policy.admissibility["production_scope"].values()) == {"ANY_CITATION"}
    for scope in policy.fact_slots["production_scope"]:
        assert entail(policy, {**_TP_FACTS, "production_scope": scope}).verdict == TP


# ── admissibility ────────────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="")
_FLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="")


@pytest.mark.parametrize("family", _FAMILIES)
def test_positive_values_need_a_concrete_path_and_all_path_values_need_local_proof(family):
    policy = _BY_FAMILY[family]
    for value in (_SHELL, _EXE):
        assert is_admissible(policy, "command_channel", value, [_LOCAL])
        assert is_admissible(policy, "command_channel", value, [_FLOW])
        assert not is_admissible(policy, "command_channel", value, [])
    assert is_admissible(policy, "neutralization_coverage", _BYPASS, [_FLOW])
    # "Safe on all paths" is never proven by the scanner data flow alone.
    assert is_admissible(policy, "command_channel", _FIXED, [_LOCAL])
    assert not is_admissible(policy, "command_channel", _FIXED, [_FLOW])
    assert is_admissible(policy, "neutralization_coverage", _ALL, [_LOCAL])
    assert not is_admissible(policy, "neutralization_coverage", _ALL, [_FLOW])
    # A dismissal by "not a sink" / "not attacker controlled" needs local proof.
    assert not is_admissible(policy, "sink_binding", "NOT_OS_COMMAND_SINK", [_FLOW])
    assert not is_admissible(policy, "attacker_control", "REFUTED", [_FLOW])


# ── guidance ─────────────────────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict|true positive|false positive|the rule is likely correct"
    r"|\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)",
    re.IGNORECASE,
)
_BENCHMARK = re.compile(
    r"owasp|juliet|benchmark|dvwa|nodegoat|webgoat|secllmholmes|cvefixes|realvuln|openvuln",
    re.IGNORECASE,
)

# A sink or semantic each language's guidance must name.
_LANGUAGE_MARKERS = {
    "command_injection_java": ("Runtime.exec(String)", "StringTokenizer", "ProcessBuilder"),
    "command_injection_python": ("shell=True", "shlex.quote", "os.system", "os.exec*"),
    "command_injection_javascript": ("child_process.exec", "execFile", "shell: true"),
    "command_injection_go": ("exec.Command(name, arg...)", '"-c"', "StdinPipe"),
    "command_injection_csharp": ("Process.Start", "UseShellExecute", "ArgumentList", "cmd.exe"),
    "command_injection_cpp": ("system(s)", "popen", "posix_spawn", "wordexp"),
}


@pytest.mark.parametrize("family", _FAMILIES)
def test_guidance_has_one_neutral_entry_per_decisive_slot(family):
    policy = _BY_FAMILY[family]
    guidance = policy.assessment_guidance
    assert [g.split(":", 1)[0] for g in guidance] == list(_DECISIVE)
    text = " ".join(guidance)
    assert not _VERDICT_CMD.search(text), _VERDICT_CMD.search(text)
    assert not _BENCHMARK.search(text), _BENCHMARK.search(text)
    for marker in _LANGUAGE_MARKERS[family]:
        assert marker in text, marker


@pytest.mark.parametrize("family", _FAMILIES)
def test_guidance_defines_both_channels_and_keeps_argument_injection_unresolved(family):
    by_slot = {g.split(":", 1)[0]: g for g in _BY_FAMILY[family].assessment_guidance}
    channel = by_slot["command_channel"]
    for value in (_SHELL, _EXE, _FIXED):
        assert value in channel
    assert "argument injection, CWE-88" in channel
    assert "leave command_channel UNRESOLVED" in channel
    coverage = by_slot["neutralization_coverage"]
    assert "(a) Shell-text path" in coverage and "(b) Program-position path" in coverage
    assert "The absence of a shell is NOT coverage" in coverage
    assert coverage.count(_BYPASS) >= 2 and coverage.count(_ALL) >= 2
