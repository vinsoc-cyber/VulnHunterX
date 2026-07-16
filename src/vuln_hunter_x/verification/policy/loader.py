# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Load family policies from YAML and select the policy for a finding.

Selection is by CWE membership or rule-id glob. Overlapping selectors (a
finding matching more than one family) fail closed — the caller must never
silently pick one. This mirrors the fail-closed repo-identity discipline from
P1: ambiguity is an error, not a guess.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from pathlib import Path

import yaml

from vuln_hunter_x.verification.policy.models import (
    Applicability,
    Condition,
    FamilyPolicy,
    HandoffSelector,
)
from vuln_hunter_x.verification.policy.support import PROFILE_NAMES


class PolicyError(ValueError):
    """A policy YAML is malformed or internally inconsistent."""


class PolicyOverlapError(RuntimeError):
    """A finding matched more than one family policy (fail closed)."""


def _normalize_condition(raw: Mapping[str, object]) -> dict[str, tuple[str, ...]]:
    out: dict[str, tuple[str, ...]] = {}
    for slot, value in raw.items():
        if isinstance(value, str):
            out[slot] = (value,)
        elif isinstance(value, (list, tuple)):
            out[slot] = tuple(str(v) for v in value)
        else:
            raise PolicyError(f"condition value for {slot!r} must be a string or list")
    return out


def _validate_condition(
    cond: Condition, fact_slots: Mapping[str, tuple[str, ...]], where: str
) -> None:
    for slot, values in cond.items():
        if slot not in fact_slots:
            raise PolicyError(f"{where}: slot {slot!r} is not declared in fact_slots")
        for v in values:
            if v not in fact_slots[slot]:
                raise PolicyError(
                    f"{where}: value {v!r} for slot {slot!r} is not a declared value"
                )


def _validate_admissibility(
    admissibility: Mapping[str, Mapping[str, str]],
    fact_slots: Mapping[str, tuple[str, ...]],
) -> None:
    for slot, value_map in admissibility.items():
        if slot not in fact_slots:
            raise PolicyError(f"admissibility: slot {slot!r} is not declared in fact_slots")
        for value, profile in value_map.items():
            if value not in fact_slots[slot]:
                raise PolicyError(
                    f"admissibility: value {value!r} for slot {slot!r} is not declared"
                )
            if profile not in PROFILE_NAMES:
                raise PolicyError(
                    f"admissibility: unknown profile {profile!r} for {slot}={value}"
                )


def load_policy_from_mapping(data: Mapping[str, object]) -> FamilyPolicy:
    """Build a :class:`FamilyPolicy` from a parsed YAML mapping (validated)."""
    try:
        family = str(data["family"])
        selectors = data.get("selectors", {}) or {}
        cwes = frozenset(str(c).upper() for c in selectors.get("cwes", []))
        rule_aliases = tuple(str(a) for a in selectors.get("rule_aliases", []))
        languages = frozenset(str(lang).lower() for lang in selectors.get("languages", []))
        raw_slots = data["fact_slots"]
        fact_slots = {str(k): tuple(str(v) for v in vals) for k, vals in raw_slots.items()}
        decisive = frozenset(
            str(s) for s in data.get("decisive_slots", list(fact_slots))
        )
        ent = data["entailment"]
        true_positive = _normalize_condition(ent["true_positive"])
        false_positive_if_any = tuple(
            _normalize_condition(c) for c in ent.get("false_positive_if_any", [])
        )
        raw_adm = data.get("admissibility", {}) or {}
        admissibility = {
            str(slot): {
                str(v): str(prof)
                for v, prof in (vals.items() if isinstance(vals, Mapping) else [])
            }
            for slot, vals in (raw_adm.items() if isinstance(raw_adm, Mapping) else [])
        }
        assessment_guidance = tuple(str(g) for g in data.get("assessment_guidance", []) or [])
        raw_handoff = data.get("handoff_from") or None
        handoff_from = None
        if raw_handoff is not None:
            handoff_from = HandoffSelector(
                languages=frozenset(str(x).lower() for x in raw_handoff.get("languages", [])),
                cwes=frozenset(str(c).upper() for c in raw_handoff.get("cwes", [])),
                rule_aliases=tuple(str(a) for a in raw_handoff.get("rule_aliases", [])),
            )
        raw_appl = data.get("applicability") or None
        applicability = None
        if raw_appl is not None:
            applicability = Applicability(
                slot=str(raw_appl["slot"]),
                applicable_values=frozenset(
                    str(v) for v in raw_appl.get("applicable_values", [])
                ),
                not_applicable_values=frozenset(
                    str(v) for v in raw_appl.get("not_applicable_values", [])
                ),
            )
    except (KeyError, TypeError) as exc:
        raise PolicyError(f"malformed policy: {exc}") from exc

    for slot in decisive:
        if slot not in fact_slots:
            raise PolicyError(f"decisive slot {slot!r} is not declared in fact_slots")
    _validate_condition(true_positive, fact_slots, "true_positive")
    for i, cond in enumerate(false_positive_if_any):
        _validate_condition(cond, fact_slots, f"false_positive_if_any[{i}]")
    _validate_admissibility(admissibility, fact_slots)
    if handoff_from is not None and applicability is None:
        raise PolicyError(f"family {family!r}: handoff_from requires applicability")
    if applicability is not None:
        if applicability.slot not in fact_slots:
            raise PolicyError(
                f"applicability: slot {applicability.slot!r} is not declared in fact_slots"
            )
        for v in (*applicability.applicable_values, *applicability.not_applicable_values):
            if v not in fact_slots[applicability.slot]:
                raise PolicyError(
                    f"applicability: value {v!r} for slot "
                    f"{applicability.slot!r} is not declared"
                )

    return FamilyPolicy(
        family=family,
        cwes=cwes,
        rule_aliases=rule_aliases,
        fact_slots=fact_slots,
        decisive_slots=decisive,
        true_positive=true_positive,
        false_positive_if_any=false_positive_if_any,
        languages=languages,
        admissibility=admissibility,
        assessment_guidance=assessment_guidance,
        handoff_from=handoff_from,
        applicability=applicability,
        version=str(data.get("version", "1")),
    )


class PolicyRegistry:
    """Holds the loaded policies and selects at most one per finding."""

    def __init__(self, policies: Iterable[FamilyPolicy]) -> None:
        self._policies = list(policies)

    @property
    def families(self) -> list[str]:
        return [p.family for p in self._policies]

    @staticmethod
    def _matches(policy: FamilyPolicy, cwe_set: set[str], rule_id: str, lang: str) -> bool:
        # Language gate: a policy that declares languages matches only findings in
        # those languages. An empty languages set is language-agnostic (CWE-117).
        if policy.languages and lang.lower() not in policy.languages:
            return False
        if cwe_set & policy.cwes:
            return True
        return any(fnmatch.fnmatch(rule_id, pat) for pat in policy.rule_aliases)

    def resolve_family(
        self, *, cwe_ids: Iterable[str], rule_id: str, lang: str = ""
    ) -> FamilyPolicy | None:
        """Return the single matching policy, ``None`` if none, error if >1."""
        cwe_set = {str(c).upper() for c in cwe_ids}
        matches = [
            p
            for p in self._policies
            if self._matches(p, cwe_set, rule_id or "", lang or "")
        ]
        if not matches:
            return None
        if len(matches) > 1:
            raise PolicyOverlapError(
                f"finding (cwes={sorted(cwe_set)}, rule={rule_id!r}) matched multiple "
                f"policy families: {[p.family for p in matches]}"
            )
        return matches[0]

    @staticmethod
    def _handoff_matches(
        h: HandoffSelector, cwe_set: set[str], rule_id: str, lang: str
    ) -> bool:
        if h.languages and lang.lower() not in h.languages:
            return False
        if h.cwes and (cwe_set & h.cwes):
            return True
        return any(fnmatch.fnmatch(rule_id, pat) for pat in h.rule_aliases)

    def resolve_handoff(
        self, *, cwe_ids: Iterable[str], rule_id: str, lang: str = ""
    ) -> FamilyPolicy | None:
        """Return the single family this finding can be handed off to, ``None`` if
        none, error if more than one distinct family matches (fail closed).

        A finding that a family PRIMARILY owns is not also that family's handoff
        candidate (dedup) — the primary path already covers it.
        """
        cwe_set = {str(c).upper() for c in cwe_ids}
        rid = rule_id or ""
        matches = [
            p
            for p in self._policies
            if p.handoff_from is not None
            and not self._matches(p, cwe_set, rid, lang or "")
            and self._handoff_matches(p.handoff_from, cwe_set, rid, lang or "")
        ]
        if not matches:
            return None
        if len(matches) > 1:
            raise PolicyOverlapError(
                f"finding (cwes={sorted(cwe_set)}, rule={rule_id!r}) matched multiple "
                f"handoff families: {[p.family for p in matches]}"
            )
        return matches[0]


def _bundled_policies_dir() -> Path:
    # config-relative bundled assets, resolved from __file__ (not cwd) so it
    # works from any working directory. This file is at
    # src/vuln_hunter_x/verification/policy/loader.py → parents[4] is repo root.
    return Path(__file__).resolve().parents[4] / "config" / "policies"


def load_policy_registry(policies_dir: Path | None = None) -> PolicyRegistry:
    """Load every ``*.yaml`` policy under ``policies_dir`` (bundled if None)."""
    directory = policies_dir or _bundled_policies_dir()
    policies: list[FamilyPolicy] = []
    if directory.is_dir():
        for yaml_file in sorted(directory.glob("*.yaml")):
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            policies.append(load_policy_from_mapping(data))
    return PolicyRegistry(policies)
