"""raw_response round-trips only behind the opt-in flag (#160).

Default output stays byte-identical (redaction); enabling persist_raw_response
restores an exact to_dict -> from_dict round-trip.
"""

import pytest

from vuln_hunter_x.core.config import Config
from vuln_hunter_x.core.types import Finding, Verdict, VerificationResult

RAW = "RAW-MODEL-TEXT"


def _finding() -> Finding:
    return Finding(
        rule_id="r",
        message="m",
        file="a.py",
        start_line=1,
        end_line=1,
        repo_name="repo",
        lang="python",
    )


@pytest.fixture()
def v() -> Verdict:
    return Verdict(
        finding=_finding(),
        verdict="True Positive",
        confidence="High",
        reasoning="because",
        answers=[],
        raw_response=RAW,
        model="test-model",
    )


@pytest.fixture()
def result(v) -> VerificationResult:
    return VerificationResult(verdicts=[v], stats={}, model="test-model", provider="test")


def test_default_output_omits_raw_response(v):
    assert "raw_response" not in v.to_dict()


def test_opt_in_round_trips_raw_response(v):
    d = v.to_dict(include_raw_response=True)
    assert d["raw_response"] == RAW
    assert Verdict.from_dict(d).raw_response == RAW


def test_result_forwards_flag(result):
    assert "raw_response" not in result.to_dict()["verdicts"][0]
    on = result.to_dict(include_raw_response=True)
    assert on["verdicts"][0]["raw_response"] == RAW


def test_output_config_flag_defaults_off():
    assert Config().output.persist_raw_response is False
    assert Config.from_dict({"persist_raw_response": True}).output.persist_raw_response is True
